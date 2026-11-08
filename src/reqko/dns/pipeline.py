"""DNS query processing pipeline (FR-01 through FR-14, NFR-03).

Pipeline order (per docs/03-architecture.md section 3):
  ACL -> Rate Limit -> Wire Parse (FORMERR) -> ANY Check ->
  Allowlist/Blocklist -> Cache Lookup -> Cache-hit re-validation ->
  Upstream -> CNAME Uncloaking -> Cache Store -> Response -> Async Log
"""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from dataclasses import dataclass

from reqko.dns.acl import ClientACL
from reqko.dns.cache import DNSCache
from reqko.dns.protocol import (
    INT_TO_TYPE_NAME,
    RCODE_FORMERR,
    RCODE_REFUSED,
    TYPE_ANY,
    TYPE_CNAME,
    TYPE_OPT,
    DNSFormatError,
    DNSHeader,
    DNSPacket,
    find_request_opt,
    make_blocking_response,
    make_opt_record,
    make_response,
    parse_wire,
)
from reqko.dns.ratelimit import RateLimiter
from reqko.dns.upstream import UpstreamError, make_servfail, query_upstream
from reqko.filtering.engine import FilterEngine

logger = logging.getLogger(__name__)

# Fixed name used by the UDP self-probe watchdog (dns.server.DnsUdpWatchdog).
# The pipeline answers it locally with REFUSED — no upstream query, no
# query_log event — so the watchdog never pollutes statistics (dns/server.py).
SELF_PROBE_NAME = "selfprobe.reqko.internal"


@dataclass
class QueryEvent:
    """Query log event dispatched to the async queue (no blocking)."""

    client_ip: str
    question_name: str
    question_type: str
    status: str
    matched_rule: str | None
    upstream: str | None
    latency_ms: float
    response_code: int
    # Where the event came from: "dns" (real query) or "browser"
    # (aggregated report from the browser extension).
    source: str = "dns"
    # Aggregated occurrence count (browser reports may batch counts);
    # DNS events always carry 1.
    occurrences: int = 1


@dataclass
class PipelineConfig:
    """Configuration bundle for the resolver pipeline."""

    acl: ClientACL
    rate_limiter: RateLimiter
    filter_engine: FilterEngine
    cache: DNSCache
    upstreams: list[tuple[str, int]]
    upstream_timeout: float
    block_mode: str
    blocking_ipv4: str = "0.0.0.0"
    blocking_ipv6: str = "::"
    block_ttl: int = 300
    log_queue: asyncio.Queue[QueryEvent] | None = None
    log_queue_drop_counter: list[int] | None = None  # [0] = mutable int


def _qtype_name(qtype: int) -> str:
    return INT_TO_TYPE_NAME.get(qtype, str(qtype))


def _make_early_response(raw_data: bytes, rcode: int) -> DNSPacket:
    """Builds a minimal REFUSED/FORMERR response keeping the client packet ID.

    Used while the packet cannot be parsed yet (ACL, rate limit, wire errors).
    """
    pkt_id = 0
    if len(raw_data) >= 2:
        try:
            (pkt_id,) = struct.unpack_from("!H", raw_data, 0)
        except struct.error:
            pkt_id = 0
    return DNSPacket(header=DNSHeader(id=pkt_id, qr=1, rcode=rcode))


def _clamp_response_ttls(packet: DNSPacket, ttl: int) -> None:
    """Rewrites answer and authority record TTLs to the cached clamped TTL.

    Keeps the response shown to the client consistent with what the cache
    stores (the forwarded response would otherwise carry the raw upstream
    TTL while the cache serves a clamped one). OPT records (type 41) are
    never touched: their TTL field carries EDNS flags, not a time-to-live.
    """
    for rr in packet.answers:
        if rr.rtype != TYPE_OPT:
            rr.ttl = ttl
    for rr in packet.authorities:
        if rr.rtype != TYPE_OPT:
            rr.ttl = ttl


def _sanitize_edns(request: DNSPacket, response: DNSPacket) -> None:
    """Makes the forwarded response EDNS-consistent with the client (RFC 6891).

    The response gets exactly one fresh OPT record when the client sent an
    OPT, and no OPT record at all when it did not.
    """
    additionals = [rr for rr in response.additionals if rr.rtype != TYPE_OPT]
    client_opt = find_request_opt(request)
    if client_opt is not None:
        additionals.append(make_opt_record(do_flag=bool(client_opt.ttl & 0x8000)))
    response.additionals = additionals


async def process_query(
    raw_data: bytes,
    client_ip: str,
    cfg: PipelineConfig,
) -> bytes:
    """Processes a raw DNS packet through the full pipeline.

    Returns raw DNS response bytes. Never raises (returns SERVFAIL on unexpected errors).
    """
    # perf_counter is the highest-resolution monotonic clock on every platform
    # (time.monotonic has ~15 ms granularity on Windows and would round
    # short latencies down to 0).
    start_time = time.perf_counter()

    def _make_event(
        pkt: DNSPacket | None,
        status: str,
        matched_rule: str | None = None,
        upstream: str | None = None,
    ) -> QueryEvent:
        name = pkt.questions[0].name if pkt and pkt.questions else ""
        qtype = _qtype_name(pkt.questions[0].qtype) if pkt and pkt.questions else "?"
        rcode = pkt.header.rcode if pkt else 2
        return QueryEvent(
            client_ip=client_ip,
            question_name=name,
            question_type=qtype,
            status=status,
            matched_rule=matched_rule,
            upstream=upstream,
            latency_ms=(time.perf_counter() - start_time) * 1000,
            response_code=rcode,
        )

    def _dispatch(event: QueryEvent) -> None:
        # The persistent query_log writer arrives with objective 5; until then
        # the event is emitted to the log and buffered in the in-memory queue.
        logger.info(
            "query_log: status=%s name=%s type=%s client=%s upstream=%s latency=%.1fms rcode=%d",
            event.status,
            event.question_name,
            event.question_type,
            event.client_ip,
            event.upstream or "-",
            event.latency_ms,
            event.response_code,
        )
        if cfg.log_queue is None:
            return
        try:
            cfg.log_queue.put_nowait(event)
        except asyncio.QueueFull:
            if cfg.log_queue_drop_counter is not None:
                cfg.log_queue_drop_counter[0] += 1
            logger.warning("Log queue full, dropping event for %s", client_ip)

    def _respond(pkt: DNSPacket) -> bytes:
        try:
            return pkt.to_wire()
        except Exception as e:
            logger.error("Failed to serialize response: %s: %s", type(e).__name__, e)
            return b""

    def _blocked(
        request: DNSPacket,
        matched_rule: str | None,
        status: str,
        upstream: str | None = None,
    ) -> bytes:
        """Builds, logs and serializes a blocking response (FR-08)."""
        block_resp = make_blocking_response(
            request,
            block_mode=cfg.block_mode,
            blocking_ipv4=cfg.blocking_ipv4,
            blocking_ipv6=cfg.blocking_ipv6,
            ttl=cfg.block_ttl,
        )
        _dispatch(_make_event(block_resp, status, matched_rule=matched_rule, upstream=upstream))
        return _respond(block_resp)

    # ── Step 1: ACL ──────────────────────────────────────────────────────────
    if not cfg.acl.is_allowed(client_ip):
        refused = _make_early_response(raw_data, RCODE_REFUSED)
        _dispatch(
            QueryEvent(
                client_ip=client_ip,
                question_name="",
                question_type="?",
                status="REFUSED_ACL",
                matched_rule=None,
                upstream=None,
                latency_ms=(time.perf_counter() - start_time) * 1000,
                response_code=RCODE_REFUSED,
            )
        )
        return _respond(refused)

    # ── Step 2: Rate Limit ────────────────────────────────────────────────────
    if not cfg.rate_limiter.is_allowed(client_ip):
        refused = _make_early_response(raw_data, RCODE_REFUSED)
        _dispatch(
            QueryEvent(
                client_ip=client_ip,
                question_name="",
                question_type="?",
                status="REFUSED_RATE_LIMIT",
                matched_rule=None,
                upstream=None,
                latency_ms=(time.perf_counter() - start_time) * 1000,
                response_code=RCODE_REFUSED,
            )
        )
        return _respond(refused)

    # ── Step 3: Wire Parse (FORMERR) ──────────────────────────────────────────
    try:
        request = parse_wire(raw_data)
    except DNSFormatError as e:
        formerr = _make_early_response(raw_data, RCODE_FORMERR)
        logger.debug("FORMERR from %s: %s: %s", client_ip, type(e).__name__, e)
        _dispatch(
            QueryEvent(
                client_ip=client_ip,
                question_name="",
                question_type="?",
                status="ERROR_FORMAT",
                matched_rule=None,
                upstream=None,
                latency_ms=(time.perf_counter() - start_time) * 1000,
                response_code=RCODE_FORMERR,
            )
        )
        return _respond(formerr)

    if not request.questions:
        formerr = make_response(request, rcode=RCODE_FORMERR)
        _dispatch(_make_event(formerr, "ERROR_FORMAT"))
        return _respond(formerr)

    question = request.questions[0]
    qname = question.name.strip(".").lower()
    qtype = question.qtype

    # ── Step 3.5: UDP self-probe (watchdog liveness, never logged) ────────────
    # Any reply at all proves the UDP path is alive; REFUSED is synthetic and
    # the event is intentionally not dispatched (no query_log/stats noise).
    if qname == SELF_PROBE_NAME:
        return _respond(make_response(request, rcode=RCODE_REFUSED))

    # ── Step 4: ANY Check ─────────────────────────────────────────────────────
    if qtype == TYPE_ANY:
        refused_resp = make_response(request, rcode=RCODE_REFUSED)
        _dispatch(_make_event(refused_resp, "REFUSED_ANY"))
        return _respond(refused_resp)

    # ── Steps 5+6: Allowlist priority + Blocklist Check (FR-04, FR-06, FR-07) ─
    # match() checks the allowlist first, so one call covers both steps.
    match_result = cfg.filter_engine.match(qname)
    if match_result.is_blocked:
        return _blocked(request, match_result.matched_rule, "BLOCKED_BLACKLIST")
    is_whitelisted = match_result.status == "ALLOWED"

    # ── Step 7: Cache Lookup ──────────────────────────────────────────────────
    cache_entry = cfg.cache.get(qname, qtype)
    if cache_entry is not None:
        # ── Step 7a: Cache-hit re-validation (FR-04, FR-09) ──────────────────
        # Re-check against the snapshot current at this moment, so rules added
        # after caching still block immediately.
        recheck = cfg.filter_engine.match(qname)
        if recheck.is_blocked:
            return _blocked(request, recheck.matched_rule, "BLOCKED_BLACKLIST")

        # Re-check CNAME targets (FR-09) unless the queried name is allowlisted
        if recheck.status != "ALLOWED" and cache_entry.cname_targets:
            for cname_target in cache_entry.cname_targets:
                cname_result = cfg.filter_engine.match(cname_target, is_cname=True)
                if cname_result.is_blocked:
                    return _blocked(request, cname_result.matched_rule, "BLOCKED_CNAME")

        # Serve from cache
        cached_resp = cfg.cache.build_response(request, cache_entry)
        _dispatch(_make_event(cached_resp, "CACHED"))
        return _respond(cached_resp)

    # ── Step 8: Upstream Query ────────────────────────────────────────────────
    try:
        upstream_resp, upstream_used = await query_upstream(
            request, cfg.upstreams, timeout=cfg.upstream_timeout
        )
    except UpstreamError as e:
        logger.warning("All upstreams failed for %s: %s", qname, e)
        servfail = make_servfail(request)
        _dispatch(_make_event(servfail, "ERROR_UPSTREAM"))
        return _respond(servfail)

    # ── Step 9: CNAME Uncloaking (FR-09) ─────────────────────────────────────
    if not is_whitelisted:
        for rr in upstream_resp.answers:
            if rr.rtype == TYPE_CNAME and isinstance(rr.rdata, str):
                cname_result = cfg.filter_engine.match(
                    rr.rdata.strip(".").lower(), is_cname=True
                )
                if cname_result.is_blocked:
                    return _blocked(
                        request,
                        cname_result.matched_rule,
                        "BLOCKED_CNAME",
                        upstream=upstream_used,
                    )

    # ── Step 10: Cache Store (FR-03) + TTL consistency ────────────────────────
    _sanitize_edns(request, upstream_resp)
    entry = cfg.cache.set(qname, qtype, upstream_resp)
    if entry is not None:
        _clamp_response_ttls(upstream_resp, entry.ttl)

    # ── Step 11: Respond ──────────────────────────────────────────────────────
    status = "ALLOWED" if is_whitelisted else "FORWARDED"
    _dispatch(_make_event(upstream_resp, status, upstream=upstream_used))
    return _respond(upstream_resp)
