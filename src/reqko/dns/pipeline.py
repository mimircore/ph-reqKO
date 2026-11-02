"""DNS query processing pipeline (FR-01 through FR-14, NFR-03).

Pipeline order (per docs/03-architecture.md section 3):
  ACL -> Rate Limit -> Wire Parse (FORMERR) -> ANY Check ->
  Allowlist -> Blocklist -> Cache Lookup -> Cache-hit re-validation ->
  Upstream -> CNAME Uncloaking -> Cache Store -> Response -> Async Log
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

from reqko.dns.acl import ClientACL
from reqko.dns.cache import DNSCache
from reqko.dns.protocol import (
    RCODE_FORMERR,
    RCODE_REFUSED,
    TYPE_ANY,
    DNSFormatError,
    DNSPacket,
    make_blocking_response,
    make_response,
    parse_wire,
)
from reqko.dns.ratelimit import RateLimiter
from reqko.dns.upstream import UpstreamError, make_servfail, query_upstream
from reqko.filtering.engine import FilterEngine

logger = logging.getLogger(__name__)


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
    from reqko.dns.protocol import INT_TO_TYPE_NAME

    return INT_TO_TYPE_NAME.get(qtype, str(qtype))


async def process_query(
    raw_data: bytes,
    client_ip: str,
    cfg: PipelineConfig,
) -> bytes:
    """Processes a raw DNS packet through the full pipeline.

    Returns raw DNS response bytes. Never raises (returns SERVFAIL on unexpected errors).
    """
    start_time = time.monotonic()

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
            latency_ms=(time.monotonic() - start_time) * 1000,
            response_code=rcode,
        )

    def _dispatch(event: QueryEvent) -> None:
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
            logger.error("Failed to serialize response: %s", e)
            return b""

    # ── Step 1: ACL ──────────────────────────────────────────────────────────
    if not cfg.acl.is_allowed(client_ip):
        # We have no parsed packet yet - build minimal REFUSED with no questions
        refused = DNSPacket(
            header=__import__("reqko.dns.protocol", fromlist=["DNSHeader"]).DNSHeader(
                id=0, qr=1, rcode=RCODE_REFUSED
            )
        )
        # Can't build a proper question response without parsing, so try to extract ID
        try:
            import struct

            pkt_id = struct.unpack_from("!H", raw_data, 0)[0] if len(raw_data) >= 2 else 0
            refused.header.id = pkt_id
        except Exception:
            pass
        _dispatch(
            QueryEvent(
                client_ip=client_ip,
                question_name="",
                question_type="?",
                status="REFUSED_ACL",
                matched_rule=None,
                upstream=None,
                latency_ms=(time.monotonic() - start_time) * 1000,
                response_code=RCODE_REFUSED,
            )
        )
        return _respond(refused)

    # ── Step 2: Rate Limit ────────────────────────────────────────────────────
    if not cfg.rate_limiter.is_allowed(client_ip):
        try:
            import struct

            pkt_id = struct.unpack_from("!H", raw_data, 0)[0] if len(raw_data) >= 2 else 0
        except Exception:
            pkt_id = 0
        from reqko.dns.protocol import DNSHeader

        refused = DNSPacket(header=DNSHeader(id=pkt_id, qr=1, rcode=RCODE_REFUSED))
        _dispatch(
            QueryEvent(
                client_ip=client_ip,
                question_name="",
                question_type="?",
                status="REFUSED_RATE_LIMIT",
                matched_rule=None,
                upstream=None,
                latency_ms=(time.monotonic() - start_time) * 1000,
                response_code=RCODE_REFUSED,
            )
        )
        return _respond(refused)

    # ── Step 3: Wire Parse (FORMERR) ──────────────────────────────────────────
    try:
        request = parse_wire(raw_data)
    except DNSFormatError as e:
        from reqko.dns.protocol import DNSHeader

        try:
            import struct

            pkt_id = struct.unpack_from("!H", raw_data, 0)[0] if len(raw_data) >= 2 else 0
        except Exception:
            pkt_id = 0
        formerr = DNSPacket(header=DNSHeader(id=pkt_id, qr=1, rcode=RCODE_FORMERR))
        logger.debug("FORMERR from %s: %s", client_ip, e)
        _dispatch(
            QueryEvent(
                client_ip=client_ip,
                question_name="",
                question_type="?",
                status="ERROR_FORMAT",
                matched_rule=None,
                upstream=None,
                latency_ms=(time.monotonic() - start_time) * 1000,
                response_code=RCODE_FORMERR,
            )
        )
        return _respond(formerr)

    if not request.questions:
        from reqko.dns.protocol import DNSHeader

        formerr = DNSPacket(header=DNSHeader(id=request.header.id, qr=1, rcode=RCODE_FORMERR))
        _dispatch(_make_event(request, "ERROR_FORMAT"))
        return _respond(formerr)

    question = request.questions[0]
    qname = question.name.strip(".").lower()
    qtype = question.qtype

    # ── Step 4: ANY Check ─────────────────────────────────────────────────────
    if qtype == TYPE_ANY:
        refused_resp = make_response(request, rcode=RCODE_REFUSED)
        _dispatch(_make_event(refused_resp, "REFUSED_ANY"))
        return _respond(refused_resp)

    # ── Step 5: Allowlist Check ───────────────────────────────────────────────
    is_whitelisted, _whitelist_rule = cfg.filter_engine.is_allowlisted(qname)

    # ── Step 6: Blocklist Check ───────────────────────────────────────────────
    if not is_whitelisted:
        block_result = cfg.filter_engine.match(qname)
        if block_result.is_blocked:
            block_resp = make_blocking_response(
                request,
                block_mode=cfg.block_mode,
                blocking_ipv4=cfg.blocking_ipv4,
                blocking_ipv6=cfg.blocking_ipv6,
                ttl=cfg.block_ttl,
            )
            _dispatch(
                _make_event(block_resp, "BLOCKED_BLACKLIST", matched_rule=block_result.matched_rule)
            )
            return _respond(block_resp)

    # ── Step 7: Cache Lookup ──────────────────────────────────────────────────
    cache_entry = cfg.cache.get(qname, qtype)
    if cache_entry is not None:
        # ── Step 7a: Cache-hit re-validation (FR-04, FR-09) ──────────────────
        # Re-check the queried name against current rules (new rules apply immediately)
        recheck = cfg.filter_engine.match(qname)
        if recheck.is_blocked:
            block_resp = make_blocking_response(
                request,
                block_mode=cfg.block_mode,
                blocking_ipv4=cfg.blocking_ipv4,
                blocking_ipv6=cfg.blocking_ipv6,
                ttl=cfg.block_ttl,
            )
            _dispatch(
                _make_event(block_resp, "BLOCKED_BLACKLIST", matched_rule=recheck.matched_rule)
            )
            return _respond(block_resp)

        # Re-check CNAME targets (FR-09) unless the queried name is whitelisted
        if not is_whitelisted and cache_entry.cname_targets:
            for cname_target in cache_entry.cname_targets:
                cname_result = cfg.filter_engine.match(cname_target, is_cname=True)
                if cname_result.is_blocked:
                    block_resp = make_blocking_response(
                        request,
                        block_mode=cfg.block_mode,
                        blocking_ipv4=cfg.blocking_ipv4,
                        blocking_ipv6=cfg.blocking_ipv6,
                        ttl=cfg.block_ttl,
                    )
                    _dispatch(
                        _make_event(
                            block_resp, "BLOCKED_CNAME", matched_rule=cname_result.matched_rule
                        )
                    )
                    return _respond(block_resp)

        # Serve from cache
        cached_resp = cfg.cache.build_response(request, cache_entry)
        _dispatch(_make_event(cached_resp, "CACHED"))
        return _respond(cached_resp)

    # ── Step 8: Upstream Query ────────────────────────────────────────────────
    try:
        upstream_resp = await query_upstream(
            request, cfg.upstreams, timeout=cfg.upstream_timeout
        )
        upstream_used = f"{cfg.upstreams[0][0]}:{cfg.upstreams[0][1]}"
    except UpstreamError as e:
        logger.warning("All upstreams failed for %s: %s", qname, e)
        servfail = make_servfail(request)
        _dispatch(_make_event(servfail, "ERROR_UPSTREAM"))
        return _respond(servfail)

    # ── Step 9: CNAME Uncloaking (FR-09) ─────────────────────────────────────
    if not is_whitelisted:
        cname_targets_from_upstream: list[str] = []
        for rr in upstream_resp.answers:
            from reqko.dns.protocol import TYPE_CNAME

            if rr.rtype == TYPE_CNAME and isinstance(rr.rdata, str):
                cname_targets_from_upstream.append(rr.rdata.strip(".").lower())

        for cname_target in cname_targets_from_upstream:
            cname_result = cfg.filter_engine.match(cname_target, is_cname=True)
            if cname_result.is_blocked:
                block_resp = make_blocking_response(
                    request,
                    block_mode=cfg.block_mode,
                    blocking_ipv4=cfg.blocking_ipv4,
                    blocking_ipv6=cfg.blocking_ipv6,
                    ttl=cfg.block_ttl,
                )
                _dispatch(
                    _make_event(
                        block_resp,
                        "BLOCKED_CNAME",
                        matched_rule=cname_result.matched_rule,
                        upstream=upstream_used,
                    )
                )
                return _respond(block_resp)

    # ── Step 10: Cache Store ──────────────────────────────────────────────────
    cfg.cache.set(qname, qtype, upstream_resp)

    # ── Step 11: Respond ──────────────────────────────────────────────────────
    status = "ALLOWED" if is_whitelisted else "FORWARDED"
    _dispatch(_make_event(upstream_resp, status, upstream=upstream_used))
    return _respond(upstream_resp)
