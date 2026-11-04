"""Unit tests for the async query-log writer and retention job (FR-11, FR-12)."""

from __future__ import annotations

import asyncio
import ipaddress
import sqlite3
import time
from collections.abc import Callable

import pytest

from reqko.dns.acl import ClientACL
from reqko.dns.cache import DNSCache
from reqko.dns.pipeline import PipelineConfig, QueryEvent, process_query
from reqko.dns.protocol import TYPE_A, DNSHeader, DNSPacket, DNSQuestion
from reqko.dns.ratelimit import RateLimiter
from reqko.filtering.engine import FilterEngine, FilterSnapshot
from reqko.filtering.rules import RuleManager
from reqko.storage.migrations import init_database
from reqko.storage.retention import RetentionJob
from reqko.storage.writer import QueryLogWriter, anonymize_ip


def _event(
    status: str = "FORWARDED",
    client_ip: str = "192.168.1.45",
    name: str = "event.example.com",
    latency_ms: float = 10.0,
) -> QueryEvent:
    return QueryEvent(
        client_ip=client_ip,
        question_name=name,
        question_type="A",
        status=status,
        matched_rule=None,
        upstream="9.9.9.9:53" if status == "FORWARDED" else None,
        latency_ms=latency_ms,
        response_code=0,
    )


async def eventually(predicate: Callable[[], bool], timeout: float = 2.0) -> bool:
    """Polls a predicate on the event loop."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


def _start_writer(
    writer: QueryLogWriter, queue: asyncio.Queue[QueryEvent]
) -> asyncio.Task[None]:
    return asyncio.create_task(writer.run(queue))


async def _stop_writer(writer: QueryLogWriter, task: asyncio.Task[None]) -> None:
    await writer.stop()
    await task


def _count(conn: sqlite3.Connection, table: str) -> int:
    (n,) = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    return int(n)


# ── batching and flushing ──────────────────────────────────────────────────────


async def test_writer_batches_by_size() -> None:
    conn = init_database(":memory:")
    queue: asyncio.Queue[QueryEvent] = asyncio.Queue(maxsize=100)
    writer = QueryLogWriter(conn, batch_size=3, flush_interval=60.0)
    task = _start_writer(writer, queue)
    try:
        for i in range(3):
            queue.put_nowait(_event(name=f"batch{i}.example.com"))
        assert await eventually(lambda: _count(conn, "query_log") == 3)
        assert writer.flushed_events == 3
    finally:
        await _stop_writer(writer, task)


async def test_writer_flushes_on_interval() -> None:
    conn = init_database(":memory:")
    queue: asyncio.Queue[QueryEvent] = asyncio.Queue(maxsize=100)
    writer = QueryLogWriter(conn, batch_size=100, flush_interval=0.05)
    task = _start_writer(writer, queue)
    try:
        queue.put_nowait(_event(name="slow.example.com"))
        queue.put_nowait(_event(name="slow2.example.com"))
        assert await eventually(lambda: _count(conn, "query_log") == 2)
    finally:
        await _stop_writer(writer, task)


async def test_writer_flushes_queue_on_shutdown() -> None:
    conn = init_database(":memory:")
    queue: asyncio.Queue[QueryEvent] = asyncio.Queue(maxsize=100)
    writer = QueryLogWriter(conn, batch_size=100, flush_interval=60.0)
    task = _start_writer(writer, queue)
    queue.put_nowait(_event(name="shutdown1.example.com"))
    queue.put_nowait(_event(name="shutdown2.example.com", status="BLOCKED_BLACKLIST"))
    # Give the run loop a moment to pick the events into its buffer
    await asyncio.sleep(0.05)
    await _stop_writer(writer, task)
    assert _count(conn, "query_log") == 2
    assert writer.flushed_events == 2


async def test_writer_empty_run_stops_cleanly() -> None:
    conn = init_database(":memory:")
    queue: asyncio.Queue[QueryEvent] = asyncio.Queue(maxsize=10)
    writer = QueryLogWriter(conn, batch_size=10, flush_interval=0.02)
    task = _start_writer(writer, queue)
    await asyncio.sleep(0.05)
    await _stop_writer(writer, task)
    assert task.exception() is None
    assert _count(conn, "query_log") == 0


# ── stats_hourly UPSERT correctness ────────────────────────────────────────────


async def test_writer_upserts_stats_hourly() -> None:
    conn = init_database(":memory:")
    queue: asyncio.Queue[QueryEvent] = asyncio.Queue(maxsize=100)
    writer = QueryLogWriter(conn, batch_size=3, flush_interval=60.0)
    task = _start_writer(writer, queue)
    try:
        queue.put_nowait(_event(status="FORWARDED", latency_ms=10.0))
        queue.put_nowait(_event(status="BLOCKED_BLACKLIST", latency_ms=20.0))
        queue.put_nowait(_event(status="CACHED", latency_ms=30.0))
        assert await eventually(lambda: _count(conn, "query_log") == 3)

        queue.put_nowait(_event(status="FORWARDED", latency_ms=40.0))
        queue.put_nowait(_event(status="FORWARDED", latency_ms=50.0))
        queue.put_nowait(_event(status="REFUSED_ANY", latency_ms=1.0))
        assert await eventually(lambda: _count(conn, "query_log") == 6)
    finally:
        await _stop_writer(writer, task)

    rows = conn.execute("SELECT * FROM stats_hourly ORDER BY bucket_timestamp").fetchall()
    # Both batches land in the same hour bucket unless the test crosses an
    # hour boundary; in that case totals are checked summed over buckets.
    if len(rows) == 1:
        row = rows[0]
        assert row["total_queries"] == 6
        assert row["blocked_queries"] == 1
        assert row["cached_queries"] == 1
        assert row["forwarded_queries"] == 3
        assert row["allowed_queries"] == 0
        assert row["refused_queries"] == 1
        assert row["error_queries"] == 0
        assert row["latency_sum"] == 151.0
        assert row["latency_samples"] == 6
    else:
        assert sum(r["total_queries"] for r in rows) == 6
        assert sum(r["latency_samples"] for r in rows) == 6


# ── drop-when-full counter (pipeline side) ─────────────────────────────────────


async def test_pipeline_drops_events_when_queue_full() -> None:
    queue: asyncio.Queue[QueryEvent] = asyncio.Queue(maxsize=1)
    drop_counter = [0]
    snap = FilterSnapshot(
        exact_set=frozenset({"spam.example"}),
        wildcard_set=frozenset(),
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
    )
    cfg = PipelineConfig(
        acl=ClientACL([ipaddress.ip_network("127.0.0.0/8")]),
        rate_limiter=RateLimiter(rate_rps=1000.0, burst=2000.0),
        filter_engine=FilterEngine(snap),
        cache=DNSCache(),
        upstreams=[("127.0.0.1", 1)],
        upstream_timeout=0.1,
        block_mode="NULL",
        log_queue=queue,
        log_queue_drop_counter=drop_counter,
    )
    raw = DNSPacket(
        header=DNSHeader(id=1, qr=0, rd=1),
        questions=[DNSQuestion(name="spam.example", qtype=TYPE_A)],
    ).to_wire()

    await process_query(raw, "127.0.0.1", cfg)
    await process_query(raw, "127.0.0.1", cfg)  # queue is full now: dropped

    assert drop_counter[0] == 1
    assert queue.qsize() == 1


# ── IP privacy (FR-12) ─────────────────────────────────────────────────────────


def test_anonymize_ip_helper() -> None:
    assert anonymize_ip("192.168.1.45") == "192.168.1.0"
    assert anonymize_ip("10.0.0.7") == "10.0.0.0"
    # IPv6: the last 80 bits are masked, the /48 prefix survives
    assert anonymize_ip("2001:db8:1234:5678:9abc:def0:1234:5678") == "2001:db8:1234::"
    assert anonymize_ip("::1") == "::"
    assert anonymize_ip("not-an-ip") == ""


async def _flush_one_event_with_mode(mode: str, expected_ip: str) -> None:
    conn = init_database(":memory:")
    queue: asyncio.Queue[QueryEvent] = asyncio.Queue(maxsize=10)
    writer = QueryLogWriter(conn, batch_size=1, flush_interval=60.0, log_client_ip=mode)
    task = _start_writer(writer, queue)
    try:
        queue.put_nowait(_event(client_ip="192.168.1.45"))
        assert await eventually(lambda: _count(conn, "query_log") == 1)
    finally:
        await _stop_writer(writer, task)
    row = conn.execute("SELECT client_ip FROM query_log").fetchone()
    assert row is not None
    assert row[0] == expected_ip, f"mode={mode}"


async def test_writer_log_client_ip_modes() -> None:
    await _flush_one_event_with_mode("full", "192.168.1.45")
    await _flush_one_event_with_mode("anonymized", "192.168.1.0")
    await _flush_one_event_with_mode("off", "")


# ── retention (FR-12) ──────────────────────────────────────────────────────────


async def test_retention_deletes_only_old_rows() -> None:
    conn = init_database(":memory:")
    conn.execute(
        "INSERT INTO query_log (timestamp, client_ip, question_name, question_type, "
        "status, latency_ms, response_code) VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("2000-01-01 00:00:00", "192.168.1.1", "old.example.com", "A", "FORWARDED", 1.0, 0),
    )
    conn.execute(
        "INSERT INTO query_log (timestamp, client_ip, question_name, question_type, "
        "status, latency_ms, response_code) VALUES (CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?)",
        ("192.168.1.2", "fresh.example.com", "A", "FORWARDED", 1.0, 0),
    )
    conn.commit()

    job = RetentionJob(conn, retention_days=7)
    deleted = await job.run_once()
    assert deleted == 1

    names = {row[0] for row in conn.execute("SELECT question_name FROM query_log")}
    assert names == {"fresh.example.com"}


async def test_retention_run_forever_stops_promptly() -> None:
    conn = init_database(":memory:")
    job = RetentionJob(conn, retention_days=7, interval_seconds=3600.0)
    task = asyncio.create_task(job.run_forever())
    await asyncio.sleep(0.05)
    await job.stop()
    await asyncio.wait_for(task, timeout=2.0)
    assert task.done()


# ── RuleManager persistence and composition (FR-19) ───────────────────────────


def test_rule_manager_persists_across_restart() -> None:
    conn = init_database(":memory:")
    engine1 = FilterEngine()
    manager1 = RuleManager(engine1, conn)
    manager1.load_persisted()
    manager1.add_rule("blacklist", "block-me.example")
    manager1.add_rule("whitelist", "allow-me.example")

    # Simulate a restart: fresh engine + manager over the same database
    engine2 = FilterEngine()
    manager2 = RuleManager(engine2, conn)
    manager2.load_persisted()
    assert engine2.match("block-me.example").is_blocked
    assert engine2.match("sub.block-me.example").is_blocked is False  # exact rule
    assert engine2.match("allow-me.example").status == "ALLOWED"
    assert sorted(r["domain"] for r in manager2.list_rules()) == [
        "allow-me.example",
        "block-me.example",
    ]


def test_rule_manager_base_snapshot_and_validation() -> None:
    conn = init_database(":memory:")
    engine = FilterEngine()
    manager = RuleManager(engine, conn)
    manager.load_persisted()
    base = FilterSnapshot(
        exact_set=frozenset({"base-block.example"}),
        wildcard_set=frozenset(),
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
        version=5,
    )
    manager.set_base(base)
    assert engine.match("base-block.example").is_blocked

    manager.add_rule("whitelist", "base-block.example")
    assert engine.match("base-block.example").status == "ALLOWED"  # allow wins

    with pytest.raises(ValueError):
        manager.add_rule("blacklist", "not a domain!")

    assert manager.remove_rule("whitelist", "base-block.example") is True
    assert manager.remove_rule("whitelist", "base-block.example") is False
    assert engine.match("base-block.example").is_blocked
