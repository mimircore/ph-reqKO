"""Integration tests for the REST API (FR-15..FR-19) with aiohttp test client.

The app runs in-process against an in-memory database; the DNS integration
test drives the real pipeline in the same event loop.
"""

from __future__ import annotations

import asyncio
import ipaddress
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from unittest.mock import AsyncMock, patch

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from reqko.api.app import STATE_KEY, ApiState, create_app, utcnow_iso
from reqko.api.auth import AuthFailureLimiter, TokenStore, hash_token
from reqko.config import Config
from reqko.dns.acl import ClientACL
from reqko.dns.cache import DNSCache
from reqko.dns.pipeline import PipelineConfig, QueryEvent, process_query
from reqko.dns.protocol import (
    CLASS_IN,
    TYPE_A,
    DNSHeader,
    DNSPacket,
    DNSQuestion,
    DNSRecord,
    parse_wire,
)
from reqko.dns.ratelimit import RateLimiter
from reqko.filtering.engine import FilterEngine, FilterSnapshot
from reqko.filtering.rules import RuleManager
from reqko.storage.migrations import init_database

ADMIN_TOKEN = "admin-token-123"
READ_TOKEN = "read-token-456"


async def eventually(predicate: Callable[[], bool], timeout: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return predicate()


def _insert_event(
    conn: sqlite3.Connection,
    ts: str,
    ip: str,
    name: str,
    status: str,
    latency: float,
    qtype: str = "A",
    rule: str | None = None,
) -> None:
    conn.execute(
        "INSERT INTO query_log (timestamp, client_ip, question_name, question_type, "
        "status, matched_rule, upstream, latency_ms, response_code) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (ts, ip, name, qtype, status, rule, "9.9.9.9:53" if status == "FORWARDED" else None, latency, 0),
    )
    conn.commit()


def _state(
    conn: sqlite3.Connection,
    *,
    admin_token: str | None = ADMIN_TOKEN,
    read_token: str | None = None,
    auth_limit: int = 10,
    blocklist_files: tuple[str, ...] = (),
    blocklist_urls: tuple[str, ...] = (),
) -> ApiState:
    env = {
        "REQKO_ADMIN_TOKEN": admin_token or "unused",
        "REQKO_AUTH_FAILURE_LIMIT": str(auth_limit),
        "REQKO_UPSTREAM_DNS": "127.0.0.1:1",  # unreachable: probe returns False
    }
    if read_token:
        env["REQKO_READ_TOKEN"] = read_token
    if blocklist_files:
        env["REQKO_BLOCKLIST_FILES"] = ",".join(blocklist_files)
    if blocklist_urls:
        env["REQKO_BLOCKLIST_URLS"] = ",".join(blocklist_urls)
    cfg = Config.from_env(env)
    engine = FilterEngine()
    rule_manager = RuleManager(engine, conn)
    rule_manager.load_persisted()
    return ApiState(
        cfg=cfg,
        engine=engine,
        rule_manager=rule_manager,
        read_conn=conn,
        queue=asyncio.Queue(maxsize=100),
        drop_counter=[0],
        tokens=TokenStore(
            hash_token(admin_token) if admin_token else None,
            hash_token(read_token) if read_token else None,
        ),
        auth_limiter=AuthFailureLimiter(limit=auth_limit, window=60.0),
        probe_timeout=0.05,
        allowed_local_dirs=tuple({str(Path(p).resolve().parent) for p in blocklist_files}),
    )


async def _start(state: ApiState) -> TestClient[web.Request, web.Application]:
    client = TestClient(TestServer(create_app(state)))
    await client.start_server()
    return client


AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


# ── health (FR-16, public) ─────────────────────────────────────────────────────


async def test_health_is_public_and_reports_state() -> None:
    conn = init_database(":memory:")
    state = _state(conn)
    client = await _start(state)
    try:
        resp = await client.get("/health")
        assert resp.status == 200
        body = await resp.json()
        assert body["status"] == "ok"
        assert body["database"]["reachable"] is True
        assert body["upstream"]["reachable"] is False  # probe target refuses
        assert body["blocklist"]["domains"] == 0
        assert body["blocklist"]["last_update"] is None
        assert body["queue"]["depth"] == 0
        assert body["queue"]["dropped_events"] == 0
        assert body["uptime_seconds"] >= 0

        # Security headers on a public response
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Cache-Control"] == "no-store"
    finally:
        await client.close()


async def test_health_reports_blocklist_and_queue() -> None:
    conn = init_database(":memory:")
    state = _state(conn)
    state.rule_manager.add_rule("blacklist", "counted.example")
    state.queue.put_nowait(
        QueryEvent(
            client_ip="127.0.0.1",
            question_name="q.example",
            question_type="A",
            status="CACHED",
            matched_rule=None,
            upstream=None,
            latency_ms=1.0,
            response_code=0,
        )
    )
    state.drop_counter[0] = 7
    client = await _start(state)
    try:
        body = await (await client.get("/health")).json()
        assert body["blocklist"]["domains"] == 1
        assert body["queue"]["depth"] == 1
        assert body["queue"]["dropped_events"] == 7
    finally:
        await client.close()


async def test_health_503_when_db_unreachable() -> None:
    conn = init_database(":memory:")
    state = _state(conn)
    conn.close()
    client = await _start(state)
    try:
        resp = await client.get("/health")
        assert resp.status == 503
        body = await resp.json()
        assert body["status"] == "degraded"
        assert body["database"]["reachable"] is False
    finally:
        await client.close()


# ── authentication (FR-17) ─────────────────────────────────────────────────────


async def test_endpoints_require_bearer_token() -> None:
    conn = init_database(":memory:")
    client = await _start(_state(conn))
    try:
        # No header
        resp = await client.get("/api/v1/stats/summary")
        assert resp.status == 401
        assert resp.content_type == "application/problem+json"
        body = await resp.json()
        assert body["status"] == 401 and body["title"] == "Unauthorized"

        # Wrong token
        resp = await client.get(
            "/api/v1/stats/summary", headers={"Authorization": "Bearer nope"}
        )
        assert resp.status == 401

        # Non-Bearer scheme
        resp = await client.get(
            "/api/v1/stats/summary", headers={"Authorization": "Basic abc"}
        )
        assert resp.status == 401

        # Security headers are present on error responses too
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
    finally:
        await client.close()


async def test_read_token_scope_enforcement() -> None:
    conn = init_database(":memory:")
    client = await _start(_state(conn, read_token=READ_TOKEN))
    try:
        # Read scope can GET
        resp = await client.get(
            "/api/v1/queries", headers={"Authorization": f"Bearer {READ_TOKEN}"}
        )
        assert resp.status == 200

        # Read scope cannot POST
        resp = await client.post(
            "/api/v1/allowlist",
            json={"domain": "x.example"},
            headers={"Authorization": f"Bearer {READ_TOKEN}"},
        )
        assert resp.status == 403
        assert resp.content_type == "application/problem+json"
        body = await resp.json()
        assert body["status"] == 403 and body["title"] == "Forbidden"

        # Read scope cannot DELETE
        resp = await client.delete(
            "/api/v1/allowlist/x.example",
            headers={"Authorization": f"Bearer {READ_TOKEN}"},
        )
        assert resp.status == 403
    finally:
        await client.close()


async def test_failed_auth_rate_limited_429() -> None:
    conn = init_database(":memory:")
    client = await _start(_state(conn, auth_limit=2))
    try:
        statuses = []
        for _ in range(3):
            resp = await client.get(
                "/api/v1/stats/summary", headers={"Authorization": "Bearer bad"}
            )
            statuses.append(resp.status)
        assert statuses == [401, 401, 429]
    finally:
        await client.close()


# ── statistics endpoints ───────────────────────────────────────────────────────


def _seed_summary_data(conn: sqlite3.Connection) -> None:
    rows = [
        ("2026-11-04 10:00:00", "192.168.1.5", "news.example", "FORWARDED", 10.0),
        ("2026-11-04 10:00:01", "192.168.1.5", "docs.example", "FORWARDED", 10.0),
        ("2026-11-04 10:00:02", "192.168.1.5", "cdn.example", "FORWARDED", 10.0),
        ("2026-11-04 10:00:03", "192.168.1.5", "shop.example", "FORWARDED", 10.0),
        ("2026-11-04 10:01:00", "192.168.1.6", "ads.example", "BLOCKED_BLACKLIST", 20.0),
        ("2026-11-04 10:01:01", "192.168.1.6", "tracker.example", "BLOCKED_CNAME", 20.0),
        ("2026-11-04 10:02:00", "192.168.1.5", "news.example", "CACHED", 30.0),
        ("2026-11-04 10:02:01", "192.168.1.5", "docs.example", "CACHED", 30.0),
        ("2026-11-04 10:03:00", "192.168.1.9", "any.example", "REFUSED_ANY", 5.0),
        ("2026-11-04 10:04:00", "192.168.1.5", "dead.example", "ERROR_UPSTREAM", 50.0),
    ]
    for ts, ip, name, status, latency in rows:
        _insert_event(conn, ts, ip, name, status, latency)


async def test_stats_summary_totals_and_percentages() -> None:
    conn = init_database(":memory:")
    _seed_summary_data(conn)
    client = await _start(_state(conn))
    try:
        resp = await client.get("/api/v1/stats/summary", headers=AUTH)
        assert resp.status == 200
        body = await resp.json()
        assert body["total_queries"] == 10
        assert body["blocked_queries"] == 2
        assert body["blocked_percentage"] == 20.0
        assert body["cached_queries"] == 2
        assert body["cache_hit_percentage"] == 20.0
        assert body["forwarded_queries"] == 4
        assert body["allowed_queries"] == 0
        assert body["refused_queries"] == 1
        assert body["error_queries"] == 1
        assert body["avg_latency_ms"] == 19.5
        assert body["from"] is None and body["to"] is None

        # Range filter (date-only "to" covers the whole day)
        resp = await client.get(
            "/api/v1/stats/summary?from=2026-11-04 10:03:00", headers=AUTH
        )
        body = await resp.json()
        assert body["total_queries"] == 2
        assert body["refused_queries"] == 1
        assert body["error_queries"] == 1

        # Invalid input -> 400 problem
        resp = await client.get("/api/v1/stats/summary?from=not-a-date", headers=AUTH)
        assert resp.status == 400
        assert resp.content_type == "application/problem+json"
    finally:
        await client.close()


async def test_stats_timeseries_hour_and_day() -> None:
    conn = init_database(":memory:")
    conn.execute(
        "INSERT INTO stats_hourly (bucket_timestamp, total_queries, blocked_queries, "
        "cached_queries, latency_sum, latency_samples) VALUES (?,?,?,?,?,?)",
        ("2026-11-04 10:00:00", 6, 2, 2, 120.0, 6),
    )
    conn.commit()
    conn.execute(
        "INSERT INTO stats_hourly (bucket_timestamp, total_queries, blocked_queries, "
        "cached_queries, latency_sum, latency_samples) VALUES (?,?,?,?,?,?)",
        ("2026-11-04 11:00:00", 4, 0, 0, 40.0, 4),
    )
    conn.commit()
    client = await _start(_state(conn))
    try:
        resp = await client.get("/api/v1/stats/timeseries?bucket=hour", headers=AUTH)
        body = await resp.json()
        assert body["bucket"] == "hour"
        assert len(body["series"]) == 2
        assert body["series"][0]["total_queries"] == 6
        assert body["series"][0]["avg_latency_ms"] == 20.0

        resp = await client.get("/api/v1/stats/timeseries?bucket=day", headers=AUTH)
        body = await resp.json()
        assert len(body["series"]) == 1
        row = body["series"][0]
        assert row["bucket"] == "2026-11-04"
        assert row["total_queries"] == 10
        assert row["latency_samples"] == 10
        assert row["avg_latency_ms"] == 16.0

        resp = await client.get("/api/v1/stats/timeseries?bucket=week", headers=AUTH)
        assert resp.status == 400
    finally:
        await client.close()


async def test_stats_top_domains_and_clients() -> None:
    conn = init_database(":memory:")
    for _ in range(3):
        _insert_event(conn, "2026-11-04 10:00:00", "192.168.1.5", "ads.example", "BLOCKED_BLACKLIST", 1.0)
    for _ in range(2):
        _insert_event(conn, "2026-11-04 10:00:00", "192.168.1.5", "news.example", "FORWARDED", 1.0)
    _insert_event(conn, "2026-11-04 10:00:00", "192.168.1.6", "tracker.example", "BLOCKED_CNAME", 1.0)
    _insert_event(conn, "2026-11-04 10:00:00", "192.168.1.6", "", "REFUSED_ACL", 1.0)  # excluded
    client = await _start(_state(conn))
    try:
        resp = await client.get("/api/v1/stats/top-domains?status=blocked", headers=AUTH)
        body = await resp.json()
        assert [d["question_name"] for d in body["domains"]] == ["ads.example", "tracker.example"]

        resp = await client.get("/api/v1/stats/top-domains?status=allowed", headers=AUTH)
        body = await resp.json()
        assert [d["question_name"] for d in body["domains"]] == ["news.example"]

        resp = await client.get("/api/v1/stats/top-domains?status=all&limit=1", headers=AUTH)
        body = await resp.json()
        assert len(body["domains"]) == 1
        assert body["domains"][0]["question_name"] == "ads.example"

        resp = await client.get("/api/v1/stats/top-domains?status=weird", headers=AUTH)
        assert resp.status == 400

        resp = await client.get("/api/v1/stats/top-clients", headers=AUTH)
        body = await resp.json()
        assert body["clients"][0] == {"client_ip": "192.168.1.5", "hits": 5}
        assert body["clients"][1] == {"client_ip": "192.168.1.6", "hits": 2}
    finally:
        await client.close()


async def test_queries_pagination_filters_and_injection_safety() -> None:
    conn = init_database(":memory:")
    for i in range(12):
        _insert_event(
            conn,
            f"2026-11-04 10:{i:02d}:00",
            "192.168.1.5",
            f"page{i}.example",
            "FORWARDED",
            1.0,
        )
    _insert_event(conn, "2026-11-04 10:59:00", "192.168.1.6", "blockme.example", "BLOCKED_BLACKLIST", 2.0, rule="blockme.example")
    client = await _start(_state(conn))
    try:
        resp = await client.get("/api/v1/queries?limit=5", headers=AUTH)
        body = await resp.json()
        assert body["total"] == 13 and body["limit"] == 5 and body["offset"] == 0
        assert len(body["queries"]) == 5

        resp = await client.get("/api/v1/queries?limit=5&offset=10", headers=AUTH)
        body = await resp.json()
        assert len(body["queries"]) == 3

        # Newest first (DESC by timestamp)
        resp = await client.get("/api/v1/queries?limit=1", headers=AUTH)
        body = await resp.json()
        assert body["queries"][0]["question_name"] == "blockme.example"

        # Filters
        resp = await client.get(
            "/api/v1/queries?status=BLOCKED_BLACKLIST", headers=AUTH
        )
        body = await resp.json()
        assert body["total"] == 1 and body["queries"][0]["question_name"] == "blockme.example"

        resp = await client.get("/api/v1/queries?client=192.168.1.6", headers=AUTH)
        body = await resp.json()
        assert body["total"] == 1

        resp = await client.get("/api/v1/queries?domain=page1", headers=AUTH)
        body = await resp.json()
        assert body["total"] == 3  # page1, page10, page11

        # Invalid inputs -> 400
        for query in ("limit=501", "limit=0", "limit=abc", "offset=-1", "status=HACKED"):
            resp = await client.get(f"/api/v1/queries?{query}", headers=AUTH)
            assert resp.status == 400, query

        # SQL injection attempt: executed as a bound value, table survives
        resp = await client.get(
            "/api/v1/queries?domain=" + "%27%3B%20DROP%20TABLE%20query_log%3B--",
            headers=AUTH,
        )
        assert resp.status == 200
        remaining = conn.execute("SELECT COUNT(*) FROM query_log").fetchone()[0]
        assert remaining == 13
    finally:
        await client.close()


# ── custom rules (FR-19) ───────────────────────────────────────────────────────


async def test_allowlist_and_blocklist_custom_crud() -> None:
    conn = init_database(":memory:")
    client = await _start(_state(conn))
    try:
        # Create
        resp = await client.post(
            "/api/v1/allowlist", json={"domain": "OK-Example.COM"}, headers=AUTH
        )
        assert resp.status == 201
        body = await resp.json()
        assert body["rule"] == {"type": "whitelist", "domain": "ok-example.com"}

        resp = await client.post(
            "/api/v1/blocklist/custom", json={"domain": "banned.example"}, headers=AUTH
        )
        assert resp.status == 201

        # List
        resp = await client.get("/api/v1/allowlist", headers=AUTH)
        assert [r["domain"] for r in (await resp.json())["rules"]] == ["ok-example.com"]
        resp = await client.get("/api/v1/blocklist/custom", headers=AUTH)
        assert [r["domain"] for r in (await resp.json())["rules"]] == ["banned.example"]

        # Validation errors
        resp = await client.post("/api/v1/allowlist", json={"domain": "bad domain!"}, headers=AUTH)
        assert resp.status == 400
        resp = await client.post("/api/v1/allowlist", json={"domain": 123}, headers=AUTH)
        assert resp.status == 400
        resp = await client.post("/api/v1/allowlist", data="not-json", headers=AUTH)
        assert resp.status == 400

        # Delete
        resp = await client.delete("/api/v1/allowlist/ok-example.com", headers=AUTH)
        assert resp.status == 200
        resp = await client.delete("/api/v1/allowlist/ok-example.com", headers=AUTH)
        assert resp.status == 404
        assert resp.content_type == "application/problem+json"

        # Persistence: a fresh manager over the same DB still has the rule
        fresh_engine = FilterEngine()
        fresh = RuleManager(fresh_engine, conn)
        fresh.load_persisted()
        assert fresh_engine.match("banned.example").is_blocked

        state: ApiState = client.app[STATE_KEY]
        assert state.engine.match("banned.example").is_blocked
    finally:
        await client.close()


async def test_allowlist_change_takes_effect_on_next_dns_query() -> None:
    """FR-19 acceptance: adding an allowlist rule unblocks the very next query."""
    conn = init_database(":memory:")
    state = _state(conn)
    client = await _start(state)

    acl = ClientACL([ipaddress.ip_network("127.0.0.0/8")])
    pipeline_cfg = PipelineConfig(
        acl=acl,
        rate_limiter=RateLimiter(rate_rps=1000.0, burst=2000.0),
        filter_engine=state.engine,
        cache=DNSCache(),
        upstreams=[("127.0.0.1", 1)],
        upstream_timeout=0.1,
        block_mode="NULL",
    )

    def _query(name: str, qid: int) -> bytes:
        return DNSPacket(
            header=DNSHeader(id=qid, qr=0, rd=1),
            questions=[DNSQuestion(name=name, qtype=TYPE_A)],
        ).to_wire()

    fake_resp = DNSPacket(
        header=DNSHeader(id=2, qr=1, ra=1),
        questions=[DNSQuestion(name="dual.test", qtype=TYPE_A)],
        answers=[DNSRecord("dual.test", TYPE_A, CLASS_IN, 300, "6.6.6.6")],
    )
    mock = AsyncMock(return_value=(fake_resp, "127.0.0.1:53"))

    try:
        # 1. Block via API
        resp = await client.post(
            "/api/v1/blocklist/custom", json={"domain": "dual.test"}, headers=AUTH
        )
        assert resp.status == 201

        blocked = parse_wire(await process_query(_query("dual.test", 1), "127.0.0.1", pipeline_cfg))
        assert blocked.answers[0].rdata == "0.0.0.0"

        # 2. Allow via API; the change applies to the engine immediately
        resp = await client.post(
            "/api/v1/allowlist", json={"domain": "dual.test"}, headers=AUTH
        )
        assert resp.status == 201
        assert await eventually(lambda: state.engine.match("dual.test").status == "ALLOWED")

        # 3. The next DNS query is served, not blocked
        with patch("reqko.dns.pipeline.query_upstream", new=mock):
            allowed = parse_wire(
                await process_query(_query("dual.test", 2), "127.0.0.1", pipeline_cfg)
            )
        assert allowed.answers[0].rdata == "6.6.6.6"
    finally:
        await client.close()


# ── blocklist refresh (FR-10/FR-15) ───────────────────────────────────────────


async def test_blocklists_update_endpoint(tmp_path: Path) -> None:
    list_file = tmp_path / "lists" / "more.txt"
    list_file.parent.mkdir()
    list_file.write_text("||new-block.example^\n", encoding="utf-8")

    conn = init_database(":memory:")
    state = _state(conn, blocklist_files=(str(list_file),))
    client = await _start(state)
    try:
        resp = await client.post("/api/v1/blocklists/update", headers=AUTH)
        assert resp.status == 202
        body = await resp.json()
        assert body["status"] == "update_started"

        assert await eventually(
            lambda: state.engine.match("new-block.example").is_blocked
        )
        assert await eventually(lambda: state.rule_manager.last_update is not None)

        # Concurrent update while one is running -> 409 (locked), but a
        # sequential retry succeeds
        resp = await client.post("/api/v1/blocklists/update", headers=AUTH)
        assert resp.status in (202, 409)
    finally:
        await client.close()


async def test_blocklists_update_without_sources_400() -> None:
    conn = init_database(":memory:")
    client = await _start(_state(conn))
    try:
        resp = await client.post("/api/v1/blocklists/update", headers=AUTH)
        assert resp.status == 400
        assert resp.content_type == "application/problem+json"
    finally:
        await client.close()


# ── misc ───────────────────────────────────────────────────────────────────────


async def test_unknown_route_returns_problem_json() -> None:
    conn = init_database(":memory:")
    client = await _start(_state(conn))
    try:
        resp = await client.get("/api/v1/does-not-exist", headers=AUTH)
        assert resp.status == 404
        assert resp.content_type == "application/problem+json"
        body = await resp.json()
        assert body["status"] == 404
    finally:
        await client.close()


def test_utcnow_iso_format() -> None:
    value = utcnow_iso()
    assert len(value) == 19 and value[10] == " " and value[4] == "-"


async def test_json_body_must_be_object() -> None:
    conn = init_database(":memory:")
    client = await _start(_state(conn))
    try:
        resp = await client.post("/api/v1/allowlist", json=[1, 2], headers=AUTH)
        assert resp.status == 400
        body = await resp.json()
        assert body["title"] == "Bad Request"
    finally:
        await client.close()


async def test_top_domains_limit_cap() -> None:
    conn = init_database(":memory:")
    client = await _start(_state(conn))
    try:
        resp = await client.get("/api/v1/stats/top-domains?limit=101", headers=AUTH)
        assert resp.status == 400
    finally:
        await client.close()


async def test_rule_delete_invalid_domain_400() -> None:
    conn = init_database(":memory:")
    client = await _start(_state(conn))
    try:
        resp = await client.delete("/api/v1/allowlist/not%20a%20domain!", headers=AUTH)
        assert resp.status == 400
        assert resp.content_type == "application/problem+json"
    finally:
        await client.close()


async def test_health_probe_cache_second_call() -> None:
    conn = init_database(":memory:")
    client = await _start(_state(conn))
    try:
        first = await (await client.get("/health")).json()
        second = await (await client.get("/health")).json()
        assert first["upstream"]["reachable"] == second["upstream"]["reachable"]
        assert first["status"] == second["status"] == "ok"
    finally:
        await client.close()


async def test_ready_is_public_and_reflects_rules() -> None:
    conn = init_database(":memory:")
    client = await _start(_state(conn))
    try:
        # No rules loaded -> not ready (503), no auth required
        resp = await client.get("/ready")
        assert resp.status == 503
        body = await resp.json()
        assert body["status"] == "not_ready" and body["rules_loaded"] == 0

        # Load a rule -> ready (200)
        state: ApiState = client.app[STATE_KEY]
        state.rule_manager.add_rule("blacklist", "ready.example")
        resp = await client.get("/ready")
        assert resp.status == 200
        body = await resp.json()
        assert body["status"] == "ready" and body["rules_loaded"] == 1
    finally:
        await client.close()


# ── browser extension (client scope) ───────────────────────────────────────────

CLIENT_TOKEN = "client-token-789"
CLIENT_AUTH = {"Authorization": f"Bearer {CLIENT_TOKEN}"}


async def _client_app(conn: sqlite3.Connection) -> tuple[ApiState, TestClient[web.Request, web.Application]]:
    """Builds a state with a client token and returns (state, client)."""
    state = _state(conn)
    state.tokens = TokenStore(
        hash_token(ADMIN_TOKEN), None, hash_token(CLIENT_TOKEN)
    )
    client = await _start(state)
    return state, client


async def test_client_scope_can_fetch_rules_but_nothing_else() -> None:
    conn = init_database(":memory:")
    _, client = await _client_app(conn)
    try:
        # The two allowed endpoints
        resp = await client.get("/api/v1/extension/rules", headers=CLIENT_AUTH)
        assert resp.status == 200
        resp = await client.post(
            "/api/v1/extension/report",
            json={"events": [{"domain": "x.test", "count": 1, "ts": 1}]},
            headers=CLIENT_AUTH,
        )
        # ts=1 is far older than 24h -> 400 proves the endpoint is reachable
        # (validation happens after auth); the 403 test is below.
        assert resp.status == 400

        # Everything else must be 403 for the client scope
        for method, path in (
            ("GET", "/api/v1/stats/summary"),
            ("GET", "/api/v1/queries"),
            ("GET", "/api/v1/allowlist"),
            ("GET", "/api/v1/stats/top-domains"),
            ("POST", "/api/v1/allowlist"),
            ("POST", "/api/v1/blocklist/custom"),
            ("POST", "/api/v1/blocklists/update"),
            ("DELETE", "/api/v1/allowlist/x.test"),
            ("GET", "/health/other"),  # not the real /health
        ):
            resp = await client.request(
                method, path, headers=CLIENT_AUTH,
                json={"domain": "x.test"} if method == "POST" else None,
            )
            assert resp.status == 403, f"{method} {path}: {resp.status}"
    finally:
        await client.close()


async def test_read_and_admin_tokens_keep_working() -> None:
    conn = init_database(":memory:")
    state = _state(conn, read_token=READ_TOKEN)
    client = await _start(state)
    try:
        resp = await client.get(
            "/api/v1/stats/summary", headers={"Authorization": f"Bearer {READ_TOKEN}"}
        )
        assert resp.status == 200
        resp = await client.get("/api/v1/extension/rules", headers=AUTH)
        assert resp.status == 200
        resp = await client.post(
            "/api/v1/extension/report",
            json={"events": [{"domain": "x.test", "count": 1,
                              "ts": __import__("time").time()}]},
            headers=AUTH,
        )
        assert resp.status == 202
    finally:
        await client.close()


async def test_extension_rules_content_allowlist_priority_and_deterministic_order() -> None:
    conn = init_database(":memory:")
    state, client = await _client_app(conn)
    # base blocklist: b.test, a.test, wildcard w.test; allowlist: keep.test, a.test
    state.engine.update_snapshot(
        FilterSnapshot(
            exact_set=frozenset({"a.test", "b.test"}),
            wildcard_set=frozenset({"w.test"}),
            allow_exact_set=frozenset({"keep.test", "a.test"}),
            allow_wildcard_set=frozenset(),
        )
    )
    client = await _start(state)
    try:
        resp = await client.get("/api/v1/extension/rules", headers=CLIENT_AUTH)
        assert resp.status == 200
        body = await resp.json()
        # allowlisted a.test is excluded; deterministic sorted order
        assert body["domains"] == ["b.test", "w.test"]
        assert body["count"] == 2
        assert body["truncated"] is False
        assert body["skipped"] == 0
        assert isinstance(body["version"], int)
        assert "ETag" in resp.headers
    finally:
        await client.close()


async def test_extension_rules_etag_304_and_limit_truncation() -> None:
    conn = init_database(":memory:")
    state, client = await _client_app(conn)
    state.engine.update_snapshot(
        FilterSnapshot(
            exact_set=frozenset({f"d{i}.test" for i in range(5)}),
            wildcard_set=frozenset(),
            allow_exact_set=frozenset(),
            allow_wildcard_set=frozenset(),
        )
    )
    client = await _start(state)
    try:
        resp1 = await client.get("/api/v1/extension/rules?limit=3", headers=CLIENT_AUTH)
        body1 = await resp1.json()
        assert body1["count"] == 5
        assert body1["truncated"] is True
        assert len(body1["domains"]) == 3
        # deterministic truncation: sorted order
        assert body1["domains"] == sorted(body1["domains"])

        etag = resp1.headers["ETag"]
        resp2 = await client.get(
            "/api/v1/extension/rules?limit=3",
            headers={**CLIENT_AUTH, "If-None-Match": etag},
        )
        assert resp2.status == 304
        assert await resp2.read() == b""

        # changed content -> new ETag, 200
        state.engine.update_snapshot(
            FilterSnapshot(
                exact_set=frozenset({f"d{i}.test" for i in range(6)}),
                wildcard_set=frozenset(),
                allow_exact_set=frozenset(),
                allow_wildcard_set=frozenset(),
            )
        )
        resp3 = await client.get(
            "/api/v1/extension/rules?limit=3",
            headers={**CLIENT_AUTH, "If-None-Match": etag},
        )
        assert resp3.status == 200
        assert resp3.headers["ETag"] != etag

        # limit validation
        for query in ("limit=0", "limit=30001", "limit=abc"):
            resp = await client.get(f"/api/v1/extension/rules?{query}", headers=CLIENT_AUTH)
            assert resp.status == 400, query
    finally:
        await client.close()


async def test_extension_rules_skips_unrepresentable_entries() -> None:
    conn = init_database(":memory:")
    state, client = await _client_app(conn)
    # A rule that is not a valid plain domain (simulates future rule kinds):
    # inserted directly, bypassing add_rule validation
    def _insert() -> None:
        conn.execute(
            "INSERT INTO custom_rules (rule_type, syntax_type, domain, enabled) "
            "VALUES ('blacklist', 'exact', 'not a domain!', 1)"
        )
        conn.commit()

    import asyncio as _asyncio

    await _asyncio.get_running_loop().run_in_executor(None, _insert)
    # Reload the engine from the DB so the invalid domain is in the snapshot
    def _reload() -> None:
        from reqko.filtering.rules import RuleManager as _RM
        fresh = _RM(state.engine, conn)
        fresh.load_persisted()

    await _asyncio.get_running_loop().run_in_executor(None, _reload)

    client = await _start(state)
    try:
        resp = await client.get("/api/v1/extension/rules", headers=CLIENT_AUTH)
        body = await resp.json()
        assert body["skipped"] >= 1
        assert "not a domain!" not in body["domains"]
    finally:
        await client.close()


async def test_extension_report_stores_browser_events() -> None:
    conn = init_database(":memory:")
    state, client = await _client_app(conn)
    # Run the REAL query-log writer against the same DB so the queue is drained
    from reqko.storage.writer import QueryLogWriter as _Writer
    writer = _Writer(conn, batch_size=1, flush_interval=60.0)
    writer_task = asyncio.create_task(writer.run(state.queue))
    try:
        now = __import__("time").time()
        resp = await client.post(
            "/api/v1/extension/report",
            json={"events": [
                {"domain": "ads.test", "count": 3, "ts": now},
                {"domain": "trackers.test", "count": 1, "ts": now},
            ]},
            headers=CLIENT_AUTH,
        )
        assert resp.status == 202
        body = await resp.json()
        assert body["queued"] == 4

        # rows are stored through the writer path (batch flush) - wait for it
        import asyncio as _asyncio
        await _asyncio.sleep(0.3)

        def _rows() -> list[sqlite3.Row]:
            return conn.execute(
                "SELECT question_name, status, source, occurrences FROM query_log "
                "WHERE source = 'browser' ORDER BY question_name"
            ).fetchall()

        await writer.stop()
        await writer_task
        rows = await _asyncio.get_running_loop().run_in_executor(None, _rows)
        assert len(rows) == 2
        assert rows[0]["question_name"] == "ads.test"
        assert rows[0]["status"] == "BLOCKED"
        assert rows[0]["source"] == "browser"
        assert rows[0]["occurrences"] == 3

        # summary exposes browser_blocked
        resp = await client.get("/api/v1/stats/summary", headers=AUTH)
        summary = await resp.json()
        assert summary["browser_blocked"] == 4
    finally:
        await client.close()


async def test_extension_report_validation_errors() -> None:
    conn = init_database(":memory:")
    _, client = await _client_app(conn)
    now = __import__("time").time()
    try:
        bad_bodies = [
            {"events": "not-a-list"},
            {"events": []},
            {"events": [{"domain": "x.test"}]},                       # no count/ts
            {"events": [{"domain": 5, "count": 1, "ts": now}]},       # domain not str
            {"events": [{"domain": "bad domain!", "count": 1, "ts": now}]},
            {"events": [{"domain": "x.test", "count": 0, "ts": now}]},
            {"events": [{"domain": "x.test", "count": 10001, "ts": now}]},
            {"events": [{"domain": "x.test", "count": True, "ts": now}]},
            {"events": [{"domain": "x.test", "count": 1, "ts": "now"}]},
            {"events": [{"domain": "x.test", "count": 1, "ts": now - 90000}]},  # >24h
            {"events": [{"domain": "x.test", "count": 1, "ts": now + 500}]},    # future
            {"events": [{"domain": f"e{i}.test", "count": 40, "ts": now}
                        for i in range(501)]},                        # >500 events
        ]
        for body in bad_bodies:
            resp = await client.post(
                "/api/v1/extension/report", json=body, headers=CLIENT_AUTH
            )
            assert resp.status == 400, body
    finally:
        await client.close()


async def test_extension_report_rate_limited() -> None:
    conn = init_database(":memory:")
    state = _state(conn)
    state.tokens = TokenStore(
        hash_token(ADMIN_TOKEN), None, hash_token(CLIENT_TOKEN)
    )
    # small limiter for the test: burst 3
    from reqko.dns.ratelimit import RateLimiter as _RL
    state.report_limiter = _RL(rate_rps=0.1, burst=3.0)
    client = await _start(state)
    now = __import__("time").time()
    try:
        statuses = []
        for _ in range(5):
            resp = await client.post(
                "/api/v1/extension/report",
                json={"events": [{"domain": "x.test", "count": 1, "ts": now}]},
                headers=CLIENT_AUTH,
            )
            statuses.append(resp.status)
        assert statuses == [202, 202, 202, 429, 429]
    finally:
        await client.close()
