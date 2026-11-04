"""Integration tests for the DNS pipeline (FR-01 through FR-14).

Uses an in-process fake upstream: no real network access required.
"""

from __future__ import annotations

import asyncio
import ipaddress
from unittest.mock import AsyncMock, patch

from reqko.dns.acl import ClientACL
from reqko.dns.cache import DNSCache
from reqko.dns.pipeline import PipelineConfig, QueryEvent, process_query
from reqko.dns.protocol import (
    CLASS_IN,
    RCODE_FORMERR,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    RCODE_REFUSED,
    RCODE_SERVFAIL,
    TYPE_A,
    TYPE_ANY,
    TYPE_CNAME,
    TYPE_OPT,
    DNSHeader,
    DNSPacket,
    DNSQuestion,
    DNSRecord,
    make_opt_record,
    parse_wire,
)
from reqko.dns.ratelimit import RateLimiter
from reqko.dns.upstream import UpstreamError
from reqko.filtering.engine import FilterEngine, FilterSnapshot

# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_a_query(name: str, qid: int = 1) -> bytes:
    pkt = DNSPacket(
        header=DNSHeader(id=qid, qr=0, rd=1),
        questions=[DNSQuestion(name=name, qtype=TYPE_A)],
    )
    return pkt.to_wire()


def _make_a_query_edns(name: str, qid: int = 1, do_flag: bool = False) -> bytes:
    """Builds an A query carrying an EDNS0 OPT pseudo-RR in ADDITIONAL."""
    pkt = DNSPacket(
        header=DNSHeader(id=qid, qr=0, rd=1),
        questions=[DNSQuestion(name=name, qtype=TYPE_A)],
        additionals=[make_opt_record(do_flag=do_flag)],
    )
    return pkt.to_wire()


def _make_any_query(name: str, qid: int = 1) -> bytes:
    pkt = DNSPacket(
        header=DNSHeader(id=qid, qr=0, rd=1),
        questions=[DNSQuestion(name=name, qtype=TYPE_ANY)],
    )
    return pkt.to_wire()


def _make_upstream_response(
    request_id: int,
    name: str,
    ip: str = "1.2.3.4",
    ttl: int = 300,
) -> DNSPacket:
    return DNSPacket(
        header=DNSHeader(id=request_id, qr=1, ra=1, rcode=RCODE_NOERROR),
        questions=[DNSQuestion(name=name, qtype=TYPE_A)],
        answers=[
            DNSRecord(
                name=name, rtype=TYPE_A, rclass=CLASS_IN, ttl=ttl, rdata=ip
            )
        ],
    )


def _make_cname_upstream_response(
    request_id: int, name: str, cname_target: str, ip: str, ttl: int = 300
) -> DNSPacket:
    return DNSPacket(
        header=DNSHeader(id=request_id, qr=1, ra=1, rcode=RCODE_NOERROR),
        questions=[DNSQuestion(name=name, qtype=TYPE_A)],
        answers=[
            DNSRecord(name=name, rtype=TYPE_CNAME, rclass=CLASS_IN, ttl=ttl, rdata=cname_target),
            DNSRecord(name=cname_target, rtype=TYPE_A, rclass=CLASS_IN, ttl=ttl, rdata=ip),
        ],
    )


def _default_acl() -> ClientACL:
    return ClientACL([
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("10.0.0.0/8"),
    ])


def _make_cfg(
    filter_engine: FilterEngine | None = None,
    cache: DNSCache | None = None,
    rate_limiter: RateLimiter | None = None,
    log_queue: asyncio.Queue[QueryEvent] | None = None,
) -> PipelineConfig:
    return PipelineConfig(
        acl=_default_acl(),
        # NOTE: DNSCache defines __len__, so an empty cache is falsy - never
        # use `cache or DNSCache()` here, it would silently swap in a
        # different (real-clock) cache instance.
        rate_limiter=rate_limiter if rate_limiter is not None else RateLimiter(rate_rps=1000.0, burst=2000.0),
        filter_engine=filter_engine if filter_engine is not None else FilterEngine(),
        cache=cache if cache is not None else DNSCache(),
        upstreams=[("127.0.0.1", 65533)],  # fake — will be mocked
        upstream_timeout=2.0,
        block_mode="NULL",
        log_queue=log_queue,
    )


# ── ACL Tests ──────────────────────────────────────────────────────────────────

async def test_acl_refuses_external_ip() -> None:
    """FR-13: Queries from outside allowed networks are REFUSED."""
    cfg = _make_cfg()
    raw = _make_a_query("example.com")

    resp_bytes = await process_query(raw, "8.8.8.8", cfg)
    resp = parse_wire(resp_bytes)
    assert resp.header.rcode == RCODE_REFUSED


async def test_acl_allows_lan_ip() -> None:
    """FR-13: Queries from RFC 1918 LAN are processed."""
    cfg = _make_cfg()
    raw = _make_a_query("example.com")

    fake_response = _make_upstream_response(
        parse_wire(raw).header.id, "example.com"
    )

    with patch("reqko.dns.pipeline.query_upstream", new=AsyncMock(return_value=(fake_response, "127.0.0.1:65533"))):
        resp_bytes = await process_query(raw, "192.168.1.100", cfg)

    resp = parse_wire(resp_bytes)
    assert resp.header.rcode == RCODE_NOERROR


# ── Rate Limit Tests ──────────────────────────────────────────────────────────

async def test_rate_limit_drops_excessive_requests() -> None:
    """FR-14: Excessive requests from single IP are rate-limited."""
    # Rate 2 rps, burst 2 — exhausted after 2 requests
    rl = RateLimiter(rate_rps=2.0, burst=2.0)
    cfg = _make_cfg(rate_limiter=rl)
    raw = _make_a_query("example.com")

    fake_response = _make_upstream_response(parse_wire(raw).header.id, "example.com")

    with patch("reqko.dns.pipeline.query_upstream", new=AsyncMock(return_value=(fake_response, "127.0.0.1:65533"))):
        resp1 = parse_wire(await process_query(raw, "10.0.0.1", cfg))
        resp2 = parse_wire(await process_query(raw, "10.0.0.1", cfg))
        resp3 = parse_wire(await process_query(raw, "10.0.0.1", cfg))

    # First 2 allowed
    assert resp1.header.rcode in (RCODE_NOERROR, RCODE_REFUSED)
    assert resp2.header.rcode in (RCODE_NOERROR, RCODE_REFUSED)
    # 3rd must be refused (rate limited)
    assert resp3.header.rcode == RCODE_REFUSED


# ── FORMERR Tests ─────────────────────────────────────────────────────────────

async def test_formerr_on_malformed_packet() -> None:
    """NFR-10: Malformed packets get FORMERR without crashing."""
    cfg = _make_cfg()
    resp_bytes = await process_query(b"\x00\x01\x00\x00", "127.0.0.1", cfg)
    resp = parse_wire(resp_bytes)
    assert resp.header.rcode == RCODE_FORMERR


# ── ANY Tests ─────────────────────────────────────────────────────────────────

async def test_any_query_refused() -> None:
    """FR-13: QTYPE=ANY is refused (anti-amplification)."""
    cfg = _make_cfg()
    raw = _make_any_query("example.com")
    resp_bytes = await process_query(raw, "127.0.0.1", cfg)
    resp = parse_wire(resp_bytes)
    assert resp.header.rcode == RCODE_REFUSED


# ── Blocklist Tests ───────────────────────────────────────────────────────────

async def test_blocked_domain_null_mode() -> None:
    """FR-04, FR-07, FR-08: Blocked domain returns 0.0.0.0 in NULL mode."""
    snap = FilterSnapshot(
        exact_set=frozenset(),
        wildcard_set=frozenset({"adserver.com"}),
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
    )
    engine = FilterEngine(snap)
    cfg = _make_cfg(filter_engine=engine)

    raw = _make_a_query("ads.adserver.com")
    resp_bytes = await process_query(raw, "127.0.0.1", cfg)
    resp = parse_wire(resp_bytes)
    assert resp.header.rcode == RCODE_NOERROR
    assert len(resp.answers) == 1
    assert resp.answers[0].rdata == "0.0.0.0"


async def test_blocked_domain_nxdomain_mode() -> None:
    """FR-08: NXDOMAIN block mode returns RCODE=3 with no answers."""
    snap = FilterSnapshot(
        exact_set=frozenset({"tracker.net"}),
        wildcard_set=frozenset(),
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
    )
    engine = FilterEngine(snap)
    cfg = _make_cfg(filter_engine=engine)
    cfg = PipelineConfig(
        acl=cfg.acl,
        rate_limiter=cfg.rate_limiter,
        filter_engine=engine,
        cache=cfg.cache,
        upstreams=cfg.upstreams,
        upstream_timeout=cfg.upstream_timeout,
        block_mode="NXDOMAIN",
    )

    raw = _make_a_query("tracker.net")
    resp_bytes = await process_query(raw, "127.0.0.1", cfg)
    resp = parse_wire(resp_bytes)
    assert resp.header.rcode == RCODE_NXDOMAIN
    assert len(resp.answers) == 0


# ── Allowlist Precedence ──────────────────────────────────────────────────────

async def test_allowlist_overrides_blocklist() -> None:
    """FR-06: Allowlist takes priority over blocklist."""
    snap = FilterSnapshot(
        exact_set=frozenset(),
        wildcard_set=frozenset({"adserver.com"}),
        allow_exact_set=frozenset({"safe.adserver.com"}),
        allow_wildcard_set=frozenset(),
    )
    engine = FilterEngine(snap)
    cfg = _make_cfg(filter_engine=engine)

    raw = _make_a_query("safe.adserver.com")
    req_pkt = parse_wire(raw)

    fake_response = _make_upstream_response(req_pkt.header.id, "safe.adserver.com", "5.5.5.5")

    with patch("reqko.dns.pipeline.query_upstream", new=AsyncMock(return_value=(fake_response, "127.0.0.1:65533"))):
        resp_bytes = await process_query(raw, "127.0.0.1", cfg)

    resp = parse_wire(resp_bytes)
    assert resp.header.rcode == RCODE_NOERROR
    assert resp.answers[0].rdata == "5.5.5.5"


# ── Cache Tests ───────────────────────────────────────────────────────────────

async def test_cache_hit_on_second_request() -> None:
    """FR-03: Second identical query is served from cache."""
    cfg = _make_cfg()
    raw = _make_a_query("cached.example.com")
    req_pkt = parse_wire(raw)

    fake_response = _make_upstream_response(req_pkt.header.id, "cached.example.com", "9.9.9.9", ttl=300)
    call_count = 0

    async def fake_upstream(
        pkt: DNSPacket, upstreams: list[tuple[str, int]], timeout: float = 2.0
    ) -> tuple[DNSPacket, str]:
        nonlocal call_count
        call_count += 1
        return fake_response, "127.0.0.1:65533"

    with patch("reqko.dns.pipeline.query_upstream", side_effect=fake_upstream):
        await process_query(raw, "127.0.0.1", cfg)
        # Same query second time
        raw2 = _make_a_query("cached.example.com", qid=2)
        await process_query(raw2, "127.0.0.1", cfg)

    # Upstream should have been called only once
    assert call_count == 1


async def test_cache_hit_blocked_by_new_rule() -> None:
    """FR-04: On cache hit, re-validate queried name with current rules."""
    engine = FilterEngine()  # initially no rules
    cache = DNSCache()
    cfg = _make_cfg(filter_engine=engine, cache=cache)

    raw = _make_a_query("newblock.com")
    req_pkt = parse_wire(raw)
    fake_resp = _make_upstream_response(req_pkt.header.id, "newblock.com", "1.1.1.1", ttl=3600)

    # First request: forwarded and cached
    with patch("reqko.dns.pipeline.query_upstream", new=AsyncMock(return_value=(fake_resp, "127.0.0.1:65533"))):
        resp1_bytes = await process_query(raw, "127.0.0.1", cfg)
    resp1 = parse_wire(resp1_bytes)
    assert resp1.header.rcode == RCODE_NOERROR

    # Now add a blocking rule
    new_snap = FilterSnapshot(
        exact_set=frozenset({"newblock.com"}),
        wildcard_set=frozenset(),
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
        version=2,
    )
    engine.update_snapshot(new_snap)

    # Second request: cache hit but re-validated -> should now be blocked
    raw2 = _make_a_query("newblock.com", qid=2)
    resp2_bytes = await process_query(raw2, "127.0.0.1", cfg)
    resp2 = parse_wire(resp2_bytes)
    assert resp2.header.rcode == RCODE_NOERROR
    assert len(resp2.answers) == 1
    assert resp2.answers[0].rdata == "0.0.0.0"


# ── CNAME Uncloaking ──────────────────────────────────────────────────────────

async def test_cname_uncloaking_upstream() -> None:
    """FR-09: CNAME target blocked -> block the whole response from upstream."""
    snap = FilterSnapshot(
        exact_set=frozenset(),
        wildcard_set=frozenset({"hidden-tracker.com"}),
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
    )
    engine = FilterEngine(snap)
    cfg = _make_cfg(filter_engine=engine)

    raw = _make_a_query("legit-site.com")
    req_pkt = parse_wire(raw)

    cname_resp = _make_cname_upstream_response(
        req_pkt.header.id, "legit-site.com", "sub.hidden-tracker.com", "1.2.3.4"
    )

    with patch("reqko.dns.pipeline.query_upstream", new=AsyncMock(return_value=(cname_resp, "127.0.0.1:65533"))):
        resp_bytes = await process_query(raw, "127.0.0.1", cfg)

    resp = parse_wire(resp_bytes)
    # Should be blocked due to CNAME pointing to hidden-tracker.com
    assert resp.header.rcode == RCODE_NOERROR
    assert len(resp.answers) == 1
    assert resp.answers[0].rdata == "0.0.0.0"


async def test_cname_uncloaking_from_cache() -> None:
    """FR-09: Cached CNAME targets are re-validated on cache hit."""
    engine = FilterEngine()  # no rules initially
    cache = DNSCache()
    cfg = _make_cfg(filter_engine=engine, cache=cache)

    raw = _make_a_query("portal.com")
    req_pkt = parse_wire(raw)

    cname_resp = _make_cname_upstream_response(
        req_pkt.header.id, "portal.com", "cdn.tracker.com", "1.1.1.1", ttl=3600
    )

    # First request: forwarded and cached (no rules)
    with patch("reqko.dns.pipeline.query_upstream", new=AsyncMock(return_value=(cname_resp, "127.0.0.1:65533"))):
        resp1_bytes = await process_query(raw, "127.0.0.1", cfg)
    resp1 = parse_wire(resp1_bytes)
    assert resp1.header.rcode == RCODE_NOERROR

    # Add blocking rule for the CNAME target
    new_snap = FilterSnapshot(
        exact_set=frozenset(),
        wildcard_set=frozenset({"tracker.com"}),
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
        version=2,
    )
    engine.update_snapshot(new_snap)

    # Second request: cache hit, but CNAME target now blocked
    raw2 = _make_a_query("portal.com", qid=2)
    resp2_bytes = await process_query(raw2, "127.0.0.1", cfg)
    resp2 = parse_wire(resp2_bytes)
    assert resp2.header.rcode == RCODE_NOERROR
    assert len(resp2.answers) == 1
    assert resp2.answers[0].rdata == "0.0.0.0"


# ── Upstream Failures ─────────────────────────────────────────────────────────

async def test_all_upstreams_fail_returns_servfail() -> None:
    """FR-02: SERVFAIL when all upstreams are unavailable."""
    cfg = _make_cfg()
    raw = _make_a_query("upstream-failure.com")

    with patch("reqko.dns.pipeline.query_upstream", new=AsyncMock(side_effect=UpstreamError("All down"))):
        resp_bytes = await process_query(raw, "127.0.0.1", cfg)

    resp = parse_wire(resp_bytes)
    assert resp.header.rcode == RCODE_SERVFAIL


# ── Log Queue ─────────────────────────────────────────────────────────────────

async def test_events_logged_to_queue() -> None:
    """NFR-03: Query events are dispatched to the async log queue without blocking."""
    q: asyncio.Queue[QueryEvent] = asyncio.Queue(maxsize=100)
    cfg = _make_cfg(log_queue=q)

    # Blocked domain
    snap = FilterSnapshot(
        exact_set=frozenset({"spam.com"}),
        wildcard_set=frozenset(),
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
    )
    cfg.filter_engine.update_snapshot(snap)

    raw = _make_a_query("spam.com")
    await process_query(raw, "127.0.0.1", cfg)

    assert not q.empty()
    event = q.get_nowait()
    assert event.status == "BLOCKED_BLACKLIST"
    assert event.question_name == "spam.com"


# ── STEP 2a: TTL consistency between forwarded response and cache ─────────────

async def test_first_response_ttl_matches_cached_ttl() -> None:
    """The first (forwarded) response must carry the clamped cache TTL, not the raw upstream TTL.

    Upstream TTL 50 is below REQKO_CACHE_MIN_TTL=60: the cache stores 60 s, so the
    client must see 60 s immediately, then a decreasing remaining TTL on cache hits.
    """
    current_time = 1000.0

    def mock_clock() -> float:
        return current_time

    cache = DNSCache(clock=mock_clock, min_ttl=60, max_ttl=3600)
    cfg = _make_cfg(cache=cache)
    # Guard: the pipeline must use the same mocked-clock cache instance
    assert cfg.cache._clock is mock_clock

    raw = _make_a_query("ttl.example.com")
    req_pkt = parse_wire(raw)
    fake_resp = _make_upstream_response(req_pkt.header.id, "ttl.example.com", "1.2.3.4", ttl=50)

    with patch(
        "reqko.dns.pipeline.query_upstream",
        new=AsyncMock(return_value=(fake_resp, "upstream.test:53")),
    ):
        resp1 = parse_wire(await process_query(raw, "127.0.0.1", cfg))

    assert resp1.answers[0].ttl == 60  # clamped cache TTL, not upstream 50

    entry = cache.get("ttl.example.com", TYPE_A)
    assert entry is not None
    assert entry.expires_at - entry.created_at == 60

    # Advance the mock clock: the cache hit TTL must decrease
    current_time += 10.0
    raw2 = _make_a_query("ttl.example.com", qid=2)
    resp2 = parse_wire(await process_query(raw2, "127.0.0.1", cfg))
    assert resp2.answers[0].ttl == 50


# ── STEP 2b: allowlist priority regressions (FR-06 vs FR-04/FR-09) ────────────

async def test_allowlisted_name_in_blocklist_queried_twice_stays_allowed() -> None:
    """A name in both blocklist and allowlist stays ALLOWED, then CACHED."""
    snap = FilterSnapshot(
        exact_set=frozenset({"dual.com"}),
        wildcard_set=frozenset(),
        allow_exact_set=frozenset({"dual.com"}),
        allow_wildcard_set=frozenset(),
    )
    q: asyncio.Queue[QueryEvent] = asyncio.Queue()
    cfg = _make_cfg(filter_engine=FilterEngine(snap), log_queue=q)
    fake_resp = _make_upstream_response(1, "dual.com", "6.6.6.6", ttl=300)

    with patch(
        "reqko.dns.pipeline.query_upstream",
        new=AsyncMock(return_value=(fake_resp, "127.0.0.1:65533")),
    ):
        resp1 = parse_wire(await process_query(_make_a_query("dual.com", qid=1), "127.0.0.1", cfg))
        resp2 = parse_wire(await process_query(_make_a_query("dual.com", qid=2), "127.0.0.1", cfg))

    assert resp1.answers[0].rdata == "6.6.6.6"
    assert resp2.answers[0].rdata == "6.6.6.6"

    ev1 = q.get_nowait()
    ev2 = q.get_nowait()
    assert ev1.status == "ALLOWED"
    assert ev2.status == "CACHED"


async def test_rule_added_after_cache_blocks_cached_name_with_event() -> None:
    """FR-04: a rule added after caching blocks a non-allowlisted cached name.

    The log-queue event must be BLOCKED_BLACKLIST and the answer 0.0.0.0.
    """
    engine = FilterEngine()
    cache = DNSCache()
    q: asyncio.Queue[QueryEvent] = asyncio.Queue()
    cfg = _make_cfg(filter_engine=engine, cache=cache, log_queue=q)

    raw = _make_a_query("newblock.com")
    req_pkt = parse_wire(raw)
    fake_resp = _make_upstream_response(req_pkt.header.id, "newblock.com", "1.1.1.1", ttl=3600)

    with patch(
        "reqko.dns.pipeline.query_upstream",
        new=AsyncMock(return_value=(fake_resp, "127.0.0.1:65533")),
    ):
        await process_query(raw, "127.0.0.1", cfg)

    engine.update_snapshot(
        FilterSnapshot(
            exact_set=frozenset({"newblock.com"}),
            wildcard_set=frozenset(),
            allow_exact_set=frozenset(),
            allow_wildcard_set=frozenset(),
            version=2,
        )
    )

    resp2 = parse_wire(await process_query(_make_a_query("newblock.com", qid=2), "127.0.0.1", cfg))
    assert resp2.header.rcode == RCODE_NOERROR
    assert len(resp2.answers) == 1
    assert resp2.answers[0].rdata == "0.0.0.0"

    ev1 = q.get_nowait()
    ev2 = q.get_nowait()
    assert ev1.status == "FORWARDED"
    assert ev2.status == "BLOCKED_BLACKLIST"
    assert ev2.matched_rule == "newblock.com"


async def test_allowlisted_cname_to_blocked_target_not_blocked() -> None:
    """FR-06 vs FR-09: an allowlisted name is served even if its CNAME target is blocked."""
    snap = FilterSnapshot(
        exact_set=frozenset(),
        wildcard_set=frozenset({"tracker.net"}),
        allow_exact_set=frozenset({"safe.site.com"}),
        allow_wildcard_set=frozenset(),
    )
    engine = FilterEngine(snap)
    cache = DNSCache()
    cfg = _make_cfg(filter_engine=engine, cache=cache)

    cname_resp = _make_cname_upstream_response(1, "safe.site.com", "ads.tracker.net", "7.7.7.7")

    with patch(
        "reqko.dns.pipeline.query_upstream",
        new=AsyncMock(return_value=(cname_resp, "127.0.0.1:65533")),
    ):
        resp1 = parse_wire(await process_query(_make_a_query("safe.site.com", qid=1), "127.0.0.1", cfg))
        resp2 = parse_wire(await process_query(_make_a_query("safe.site.com", qid=2), "127.0.0.1", cfg))

    # Both the fresh and the cached answer must be the real IP, not 0.0.0.0
    assert resp1.answers[-1].rdata == "7.7.7.7"
    assert resp2.answers[-1].rdata == "7.7.7.7"


# ── STEP 2c: EDNS0 OPT handling ────────────────────────────────────────────────

async def test_cached_response_with_edns_gets_fresh_opt() -> None:
    """A cached response served to an EDNS client carries exactly one fresh OPT."""
    cfg = _make_cfg()
    fake_resp = _make_upstream_response(1, "edns.example.com", "4.4.4.4", ttl=300)

    with patch(
        "reqko.dns.pipeline.query_upstream",
        new=AsyncMock(return_value=(fake_resp, "127.0.0.1:65533")),
    ):
        resp1 = parse_wire(await process_query(_make_a_query_edns("edns.example.com", qid=1), "127.0.0.1", cfg))
        resp2 = parse_wire(await process_query(_make_a_query_edns("edns.example.com", qid=2, do_flag=True), "127.0.0.1", cfg))

    # Forwarded response: exactly one OPT, fresh (TTL field 0 = no DO flag)
    opts1 = [rr for rr in resp1.additionals if rr.rtype == TYPE_OPT]
    assert len(opts1) == 1
    assert opts1[0].ttl == 0

    # Cached response: exactly one OPT, DO flag preserved from the request
    opts2 = [rr for rr in resp2.additionals if rr.rtype == TYPE_OPT]
    assert len(opts2) == 1
    assert opts2[0].ttl == 0x8000

    # The OPT pseudo-RR is never stored in the cache
    assert cfg.cache.get("edns.example.com", TYPE_A) is not None
    entry = cfg.cache.get("edns.example.com", TYPE_A)
    assert entry is not None
    assert all(rr.rtype != TYPE_OPT for rr in entry.additionals)


async def test_cached_response_without_edns_has_no_opt() -> None:
    """A response to a non-EDNS client must never contain an OPT record."""
    cfg = _make_cfg()
    fake_resp = _make_upstream_response(1, "noedns.example.com", "4.4.4.4", ttl=300)

    with patch(
        "reqko.dns.pipeline.query_upstream",
        new=AsyncMock(return_value=(fake_resp, "127.0.0.1:65533")),
    ):
        resp1 = parse_wire(await process_query(_make_a_query("noedns.example.com", qid=1), "127.0.0.1", cfg))
        resp2 = parse_wire(await process_query(_make_a_query("noedns.example.com", qid=2), "127.0.0.1", cfg))

    assert all(rr.rtype != TYPE_OPT for rr in resp1.additionals)
    assert all(rr.rtype != TYPE_OPT for rr in resp2.additionals)


# ── STEP 2d: the event records the upstream server that answered ──────────────

async def test_event_records_answering_upstream_server() -> None:
    """The pipeline must log the server that actually answered, not upstreams[0]."""
    q: asyncio.Queue[QueryEvent] = asyncio.Queue()
    cfg = _make_cfg(log_queue=q)
    fake_resp = _make_upstream_response(1, "who-answered.com", "8.8.4.4")

    with patch(
        "reqko.dns.pipeline.query_upstream",
        new=AsyncMock(return_value=(fake_resp, "10.9.9.2:5353")),
    ):
        await process_query(_make_a_query("who-answered.com"), "127.0.0.1", cfg)

    event = q.get_nowait()
    assert event.status == "FORWARDED"
    assert event.upstream == "10.9.9.2:5353"


# ── STEP 2f: malformed packets are logged as ERROR_FORMAT ─────────────────────

async def test_formerr_event_status_is_error_format() -> None:
    """FORMERR responses carry their own status ERROR_FORMAT, not REFUSED_ACL."""
    q: asyncio.Queue[QueryEvent] = asyncio.Queue()
    cfg = _make_cfg(log_queue=q)

    await process_query(b"\x00\x01\x00\x00", "127.0.0.1", cfg)

    event = q.get_nowait()
    assert event.status == "ERROR_FORMAT"
    assert event.response_code == RCODE_FORMERR
