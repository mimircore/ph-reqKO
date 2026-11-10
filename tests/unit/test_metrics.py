"""Tests for the Prometheus metrics exporter (NFR-07) and its isolation (NFR-03)."""

from __future__ import annotations

import asyncio
import ipaddress
import platform
from unittest.mock import AsyncMock, patch

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from reqko.dns.acl import ClientACL
from reqko.dns.cache import DNSCache
from reqko.dns.pipeline import PipelineConfig, QueryEvent, process_query
from reqko.dns.protocol import (
    CLASS_IN,
    TYPE_A,
    TYPE_CNAME,
    DNSHeader,
    DNSPacket,
    DNSQuestion,
    DNSRecord,
    parse_wire,
)
from reqko.dns.ratelimit import RateLimiter
from reqko.dns.upstream import UpstreamResult
from reqko.filtering.engine import FilterEngine, FilterSnapshot
from reqko.metrics.exporter import DURATION_BUCKETS, MetricsRegistry, qtype_label

TYPE_UNKNOWN = 65280  # not in the known-qtype set


def _query(name: str, qtype: int = TYPE_A, qid: int = 1) -> bytes:
    return DNSPacket(
        header=DNSHeader(id=qid, qr=0, rd=1),
        questions=[DNSQuestion(name=name, qtype=qtype)],
    ).to_wire()


def _a_response(request_id: int, name: str, ip: str = "1.2.3.4") -> DNSPacket:
    return DNSPacket(
        header=DNSHeader(id=request_id, qr=1, ra=1),
        questions=[DNSQuestion(name=name, qtype=TYPE_A)],
        answers=[DNSRecord(name, TYPE_A, CLASS_IN, 300, ip)],
    )


def _make_cfg(
    metrics: MetricsRegistry | None,
    engine: FilterEngine | None = None,
    queue: asyncio.Queue[QueryEvent] | None = None,
) -> PipelineConfig:
    return PipelineConfig(
        acl=ClientACL([ipaddress.ip_network("127.0.0.0/8")]),
        rate_limiter=RateLimiter(rate_rps=10000.0, burst=20000.0),
        filter_engine=engine if engine is not None else FilterEngine(),
        cache=DNSCache(),
        upstreams=[("127.0.0.1", 1)],
        upstream_timeout=0.1,
        block_mode="NULL",
        metrics=metrics,
        log_queue=queue,
        log_queue_drop_counter=[0],
    )


# ── registry unit behaviour ────────────────────────────────────────────────────


def test_qtype_label_bounds_cardinality() -> None:
    assert qtype_label("A") == "A"
    assert qtype_label("AAAA") == "AAAA"
    assert qtype_label("TOTALLY-UNKNOWN") == "OTHER"
    assert qtype_label("SOMETHING-ELSE") == qtype_label("TOTALLY-UNKNOWN")


def test_exposition_format_contains_all_families() -> None:
    registry = MetricsRegistry()
    registry.inc_dns_queries("udp", "A")
    registry.inc_blocked("blacklist")
    registry.observe_duration("cache", 0.0002)
    registry.inc_cache_hit()
    registry.inc_cache_miss()
    registry.set_active_rules(1234)
    registry.inc_dropped_logs()

    text = registry.render()
    # HELP/TYPE lines use the metric FAMILY name (the histogram's _bucket/
    # _sum/_count series share one family header)
    for name in (
        "dns_queries_total",
        "dns_blocked_queries_total",
        "dns_query_duration_seconds",
        "dns_cache_hits_total",
        "dns_cache_misses_total",
        "dns_active_rules_count",
        "dns_dropped_logs_total",
    ):
        assert f"# HELP {name} " in text, name
        assert f"# TYPE {name} " in text, name
    assert "# HELP dns_query_duration_seconds_bucket " not in text
    assert "# TYPE dns_query_duration_seconds histogram" in text

    assert 'dns_queries_total{protocol="udp",qtype="A"} 1' in text
    assert 'dns_blocked_queries_total{reason="blacklist"} 1' in text
    assert "dns_active_rules_count 1234" in text
    assert "dns_dropped_logs_total 1" in text


def test_histogram_buckets_are_cumulative_and_counted() -> None:
    registry = MetricsRegistry()
    registry.observe_duration("upstream", 0.0004)  # le=0.0005
    registry.observe_duration("upstream", 0.02)  # le=0.025
    registry.observe_duration("upstream", 9.0)  # +Inf only

    text = registry.render()
    values = dict(
        (parts[0], parts[1])
        for parts in (line.rsplit(" ", 1) for line in text.splitlines() if " " in line)
    )
    b_0005 = 'dns_query_duration_seconds_bucket{class="upstream",le="0.0005"}'
    b_0025 = 'dns_query_duration_seconds_bucket{class="upstream",le="0.025"}'
    b_inf = 'dns_query_duration_seconds_bucket{class="upstream",le="+Inf"}'
    count = 'dns_query_duration_seconds_count{class="upstream"}'

    assert values[b_0005] == "1"
    assert values[b_0025] == "2"  # cumulative
    assert values[b_inf] == "3"
    assert values[count] == "3"
    assert len(DURATION_BUCKETS) >= 10  # sub-millisecond .. seconds range


def test_resident_memory_metric_is_linux_only() -> None:
    registry = MetricsRegistry()
    text = registry.render()
    # On Linux /proc/self/status exists; on Windows the metric is omitted.
    if platform.system() == "Linux":
        assert "process_resident_memory_bytes" in text
    else:
        assert "process_resident_memory_bytes" not in text


# ── hot-path integration: every metric increments on the right event ──────────


async def test_counters_increment_on_the_right_events() -> None:
    registry = MetricsRegistry()
    engine = FilterEngine()
    cfg = _make_cfg(registry, engine)

    fake = _a_response(1, "live.test", "9.9.9.10")
    with patch(
        "reqko.dns.pipeline.query_upstream",
        new=AsyncMock(return_value=UpstreamResult(response=fake, upstream="127.0.0.1:53", attempts=1)),
    ):
        await process_query(_query("live.test"), "127.0.0.1", cfg, protocol="udp")
        await process_query(_query("live.test", qid=2), "127.0.0.1", cfg, protocol="udp")  # cached
        await process_query(_query("live.test", qid=3), "127.0.0.1", cfg, protocol="tcp")  # cached

    # blocked query (blacklist)
    engine.update_snapshot(
        FilterSnapshot(
            exact_set=frozenset({"ads.test"}),
            wildcard_set=frozenset(),
            allow_exact_set=frozenset(),
            allow_wildcard_set=frozenset(),
        )
    )
    await process_query(_query("ads.test", qid=4), "127.0.0.1", cfg, protocol="udp")

    text = registry.render()
    assert 'dns_queries_total{protocol="udp",qtype="A"} 3' in text
    assert 'dns_queries_total{protocol="tcp",qtype="A"} 1' in text
    assert "dns_cache_hits_total 2" in text
    assert "dns_cache_misses_total 1" in text
    assert 'dns_blocked_queries_total{reason="blacklist"} 1' in text
    # duration observed for cache (2), blocked (1), upstream (1)
    for cls in ("cache", "blocked", "upstream"):
        assert f'dns_query_duration_seconds_count{{class="{cls}"}} ' in text


async def test_blocked_cname_reason_and_unknown_qtype_mapped() -> None:
    registry = MetricsRegistry()
    engine = FilterEngine()
    cfg = _make_cfg(registry, engine)

    # CNAME to a blocked target
    cname_response = DNSPacket(
        header=DNSHeader(id=1, qr=1, ra=1),
        questions=[DNSQuestion(name="portal.test", qtype=TYPE_A)],
        answers=[
            DNSRecord("portal.test", TYPE_CNAME, CLASS_IN, 300, "ads.test"),
            DNSRecord("ads.test", TYPE_A, CLASS_IN, 300, "7.7.7.7"),
        ],
    )
    engine.update_snapshot(
        FilterSnapshot(
            exact_set=frozenset(),
            wildcard_set=frozenset({"ads.test"}),
            allow_exact_set=frozenset(),
            allow_wildcard_set=frozenset(),
        )
    )
    with patch(
        "reqko.dns.pipeline.query_upstream",
        new=AsyncMock(return_value=UpstreamResult(response=cname_response, upstream="127.0.0.1:53", attempts=1)),
    ):
        await process_query(_query("portal.test"), "127.0.0.1", cfg)

    # unknown qtype collapses to OTHER
    await process_query(_query("whatever.test", qtype=TYPE_UNKNOWN), "127.0.0.1", cfg)

    text = registry.render()
    assert 'dns_blocked_queries_total{reason="cname"} 1' in text
    assert 'dns_queries_total{protocol="udp",qtype="OTHER"} 1' in text


async def test_dropped_logs_counter_increments_when_queue_full() -> None:
    registry = MetricsRegistry()
    queue: asyncio.Queue[QueryEvent] = asyncio.Queue(maxsize=1)
    engine = FilterEngine(
        FilterSnapshot(
            exact_set=frozenset({"spam.test"}),
            wildcard_set=frozenset(),
            allow_exact_set=frozenset(),
            allow_wildcard_set=frozenset(),
        )
    )
    cfg = _make_cfg(registry, engine, queue=queue)
    await process_query(_query("spam.test"), "127.0.0.1", cfg)
    await process_query(_query("spam.test"), "127.0.0.1", cfg)  # queue full: dropped

    assert "dns_dropped_logs_total 1" in registry.render()


async def test_active_rules_gauge_tracks_snapshot_changes() -> None:
    """In production every snapshot change flows through RuleManager, whose
    on_rules_changed callback feeds the gauge."""
    from reqko.filtering.rules import RuleManager
    from reqko.storage.migrations import init_database

    registry = MetricsRegistry()
    engine = FilterEngine()
    manager = RuleManager(engine, init_database(":memory:"))
    manager.on_rules_changed = registry.set_active_rules
    manager.load_persisted()
    assert "dns_active_rules_count 0" in registry.render()

    manager.add_rule("blacklist", "a.test")
    manager.add_rule("blacklist", "b.test")
    assert "dns_active_rules_count 2" in registry.render()

    # Snapshot changes that bypass the manager (raw engine swaps) are not
    # the gauge's concern in production, but the DNS path keeps working.
    cfg = _make_cfg(registry, engine)
    fake = _a_response(1, "gauge.test")
    with patch(
        "reqko.dns.pipeline.query_upstream",
        new=AsyncMock(return_value=UpstreamResult(response=fake, upstream="127.0.0.1:53", attempts=1)),
    ):
        wire = parse_wire(await process_query(_query("gauge.test"), "127.0.0.1", cfg))
    assert wire.answers[0].rdata == "1.2.3.4"


# ── hot-path isolation (NFR-03): a broken registry must not affect resolving ──


class _RaisingRegistry(MetricsRegistry):
    def inc_dns_queries(self, protocol: str, qtype_name: str) -> None:
        raise RuntimeError("registry exploded")

    def inc_blocked(self, reason: str) -> None:
        raise RuntimeError("registry exploded")

    def observe_duration(self, query_class: str, seconds: float) -> None:
        raise RuntimeError("registry exploded")

    def inc_cache_hit(self) -> None:
        raise RuntimeError("registry exploded")

    def inc_cache_miss(self) -> None:
        raise RuntimeError("registry exploded")

    def inc_dropped_logs(self) -> None:
        raise RuntimeError("registry exploded")


async def test_resolver_answers_when_registry_raises() -> None:
    cfg = _make_cfg(_RaisingRegistry())
    fake = _a_response(1, "still-works.test")

    with patch(
        "reqko.dns.pipeline.query_upstream",
        new=AsyncMock(return_value=UpstreamResult(response=fake, upstream="127.0.0.1:53", attempts=1)),
    ):
        wire = parse_wire(await process_query(_query("still-works.test"), "127.0.0.1", cfg))

    assert wire.answers[0].rdata == "1.2.3.4"


async def test_resolver_answers_without_metrics_at_all() -> None:
    cfg = _make_cfg(None)
    fake = _a_response(1, "no-metrics.test")
    with patch(
        "reqko.dns.pipeline.query_upstream",
        new=AsyncMock(return_value=UpstreamResult(response=fake, upstream="127.0.0.1:53", attempts=1)),
    ):
        wire = parse_wire(await process_query(_query("no-metrics.test"), "127.0.0.1", cfg))
    assert wire.answers[0].rdata == "1.2.3.4"


# ── the standalone metrics site: ACL, format, isolation from the API app ──────


async def _metrics_client(
    registry: MetricsRegistry, allowed: list[str]
) -> TestClient[web.Request, web.Application]:
    from reqko.metrics.exporter import create_metrics_app

    acl = ClientACL([ipaddress.ip_network(net) for net in allowed])
    app = create_metrics_app(registry, acl)
    client = TestClient(TestServer(app))
    await client.start_server()
    return client


async def test_metrics_site_serves_exposition() -> None:
    registry = MetricsRegistry()
    registry.inc_dns_queries("udp", "A")
    client = await _metrics_client(registry, ["127.0.0.1/32"])
    try:
        resp = await client.get("/metrics")
        assert resp.status == 200
        assert resp.content_type == "text/plain"
        assert "version=0.0.4" in resp.headers["Content-Type"]
        assert "dns_queries_total" in await resp.text()

        # Only GET /metrics exists
        assert (await client.get("/")).status == 404
        assert (await client.post("/metrics")).status == 405
    finally:
        await client.close()


async def test_metrics_site_acl_403_for_outside_client() -> None:
    registry = MetricsRegistry()
    # 127.0.0.1 (the test client's address) is NOT in the allowed set
    client = await _metrics_client(registry, ["10.0.0.0/8"])
    try:
        resp = await client.get("/metrics")
        assert resp.status == 403
        body = await resp.text()
        assert "dns_" not in body  # no metric data leaks
    finally:
        await client.close()


async def test_metrics_site_failure_does_not_break_dns_server() -> None:
    """The metrics site is a separate app; a stopped/dead metrics server
    cannot affect the resolver (NFR-03)."""
    registry = MetricsRegistry()
    client = await _metrics_client(registry, ["127.0.0.1/32"])
    await client.close()  # metrics server "dead"

    cfg = _make_cfg(registry)
    fake = _a_response(1, "independent.test")
    with patch(
        "reqko.dns.pipeline.query_upstream",
        new=AsyncMock(return_value=UpstreamResult(response=fake, upstream="127.0.0.1:53", attempts=1)),
    ):
        wire = parse_wire(await process_query(_query("independent.test"), "127.0.0.1", cfg))
    assert wire.answers[0].rdata == "1.2.3.4"


def test_no_high_cardinality_labels_in_render() -> None:
    registry = MetricsRegistry()
    for name in ("a.test", "client-x.test", "many-labels.test"):
        registry.inc_dns_queries("udp", name)  # qtype names that do not exist
    text = registry.render()
    assert 'qtype="OTHER"' in text
    assert "a.test" not in text and "client-x.test" not in text
