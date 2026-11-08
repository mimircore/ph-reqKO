"""Async upstream DNS client (FR-02).

Sends queries to upstream DNS servers over UDP with TCP fallback (TC=1).
All upstreams are queried RACE-style: the first valid answer wins, the rest
are cancelled — a dead/black-holed first upstream no longer adds its full
timeout to every query (perf-latency: p95 2040 ms -> ~10 ms in the bench).
A tiny circuit breaker (UpstreamHealth) marks an upstream unhealthy for a
cooldown after repeated failures so healthy upstreams are preferred.
"""

from __future__ import annotations

import asyncio
import logging
import random
import struct
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from reqko.dns.protocol import (
    RCODE_SERVFAIL,
    TYPE_NS,
    DNSHeader,
    DNSPacket,
    DNSQuestion,
    make_response,
    parse_wire,
)

logger = logging.getLogger(__name__)

MAX_UDP_PAYLOAD = 512

DEFAULT_UPSTREAM_TIMEOUT = 1.5
BREAKER_COOLDOWN_SECONDS = 30.0
BREAKER_FAILURE_THRESHOLD = 2


class UpstreamError(OSError):
    """Raised when all configured upstream servers are unavailable."""

    def __init__(self, message: str, attempts: int = 0) -> None:
        super().__init__(message)
        self.attempts = attempts


@dataclass
class UpstreamResult:
    """Successful upstream round trip."""

    response: DNSPacket
    upstream: str  # "host:port" of the server that answered
    attempts: int  # how many upstreams were queried in the winning race


@dataclass
class UpstreamHealth:
    """Tiny circuit breaker: after ``threshold`` consecutive failures an
    upstream is skipped for ``cooldown_seconds`` (measured with ``clock``,
    monotonic by default). When EVERY upstream is unhealthy the breaker is
    ignored — a total blackout must not become permanent.
    """

    cooldown_seconds: float = BREAKER_COOLDOWN_SECONDS
    threshold: int = BREAKER_FAILURE_THRESHOLD
    clock: Callable[[], float] = time.monotonic
    _failures: dict[tuple[str, int], int] = field(default_factory=dict)
    _blocked_until: dict[tuple[str, int], float] = field(default_factory=dict)

    def is_healthy(self, upstream: tuple[str, int]) -> bool:
        return self.clock() >= self._blocked_until.get(upstream, 0.0)

    def record_success(self, upstream: tuple[str, int]) -> None:
        self._failures.pop(upstream, None)
        self._blocked_until.pop(upstream, None)

    def record_failure(self, upstream: tuple[str, int]) -> None:
        failures = self._failures.get(upstream, 0) + 1
        self._failures[upstream] = failures
        if failures >= self.threshold:
            self._blocked_until[upstream] = self.clock() + self.cooldown_seconds
            self._failures[upstream] = 0
            logger.warning(
                "Upstream %s:%d marked unhealthy for %ss after %d failures",
                upstream[0],
                upstream[1],
                self.cooldown_seconds,
                failures,
            )


async def _send_udp_query(
    wire: bytes,
    host: str,
    port: int,
    timeout: float,
) -> bytes:
    """Sends a DNS query over UDP and returns raw response bytes."""
    loop = asyncio.get_running_loop()

    # Ephemeral socket per query: measured cost is ~1 ms (bench_dns.py), not
    # a latency factor compared to network RTT; a persistent multiplexed
    # client would need per-upstream ID demux for no measured benefit.
    transport: asyncio.DatagramTransport | None = None
    recv_future: asyncio.Future[bytes] = loop.create_future()

    class _Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: object) -> None:
            if not recv_future.done():
                recv_future.set_result(data)

        def error_received(self, exc: Exception) -> None:
            if not recv_future.done():
                recv_future.set_exception(exc)

        def connection_lost(self, exc: Exception | None) -> None:
            if not recv_future.done():
                recv_future.set_exception(OSError("Connection lost"))

    transport, _ = await loop.create_datagram_endpoint(
        _Proto,
        remote_addr=(host, port),
    )
    try:
        transport.sendto(wire)
        return await asyncio.wait_for(recv_future, timeout=timeout)
    finally:
        transport.close()


async def _send_tcp_query(
    wire: bytes,
    host: str,
    port: int,
    timeout: float,
) -> bytes:
    """Sends a DNS query over TCP (2-byte length prefix per RFC 1035)."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=timeout
    )
    try:
        length_prefix = struct.pack("!H", len(wire))
        writer.write(length_prefix + wire)
        await writer.drain()

        resp_len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        (resp_len,) = struct.unpack("!H", resp_len_bytes)
        resp_data = await asyncio.wait_for(reader.readexactly(resp_len), timeout=timeout)
        return resp_data
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _validate_response(request: DNSPacket, response: DNSPacket, host: str, port: int) -> bool:
    """Transaction-ID and echoed-question checks shared by UDP and TCP."""
    if response.header.id != request.header.id:
        logger.warning(
            "Upstream %s:%d returned mismatched ID %d (expected %d)",
            host,
            port,
            response.header.id,
            request.header.id,
        )
        return False
    if response.questions and request.questions:
        req_q = request.questions[0]
        resp_q = response.questions[0]
        if req_q.name.lower() != resp_q.name.lower() or req_q.qtype != resp_q.qtype:
            logger.warning(
                "Upstream %s:%d returned different question: %s/%d (expected %s/%d)",
                host,
                port,
                resp_q.name,
                resp_q.qtype,
                req_q.name,
                req_q.qtype,
            )
            return False
    return True


async def _query_one(
    wire: bytes,
    request: DNSPacket,
    host: str,
    port: int,
    timeout: float,
) -> DNSPacket:
    """One upstream round trip: UDP, validation, TC=1 TCP retry.

    Raises on any failure so the race can pick another upstream.
    """
    raw = await _send_udp_query(wire, host, port, timeout)
    response = parse_wire(raw)
    if not _validate_response(request, response, host, port):
        raise UpstreamError(f"Upstream {host}:{port} returned an invalid response")

    # TC=1 -> retry over TCP
    if response.header.tc:
        logger.debug("Upstream %s:%d returned TC=1, retrying over TCP", host, port)
        raw_tcp = await _send_tcp_query(wire, host, port, timeout)
        response = parse_wire(raw_tcp)
        if not _validate_response(request, response, host, port):
            raise UpstreamError(f"Upstream {host}:{port} TCP fallback invalid")

    return response


async def query_upstream(
    request: DNSPacket,
    upstreams: Sequence[tuple[str, int]],
    timeout: float = DEFAULT_UPSTREAM_TIMEOUT,
    *,
    health: UpstreamHealth | None = None,
) -> UpstreamResult:
    """Queries upstream DNS servers RACE-style (UDP + TC=1 TCP fallback).

    Every healthy upstream is queried simultaneously; the first VALID
    response wins and the remaining attempts are cancelled (a black-holed
    first upstream therefore costs nothing). Failures feed the optional
    ``health`` breaker. Raises UpstreamError (with .attempts) if all fail.
    """
    if not request.questions:
        raise UpstreamError("Request has no questions")

    wire = request.to_wire()

    candidates = [u for u in upstreams if health is None or health.is_healthy(u)]
    if not candidates:
        # Breaker excluded everything: never allow a permanent blackout.
        logger.warning("All upstreams marked unhealthy — retrying all")
        candidates = list(upstreams)

    tasks = {
        asyncio.ensure_future(_query_one(wire, request, host, port, timeout)): (host, port)
        for host, port in candidates
    }
    pending = set(tasks)
    last_exc: Exception = UpstreamError("No upstreams configured")
    try:
        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
            for done_task in done:
                upstream = tasks[done_task]
                try:
                    response = done_task.result()
                except Exception as exc:
                    last_exc = exc
                    if health is not None:
                        health.record_failure(upstream)
                    continue
                if health is not None:
                    health.record_success(upstream)
                for still_pending in pending:
                    still_pending.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                return UpstreamResult(
                    response=response,
                    upstream=f"{upstream[0]}:{upstream[1]}",
                    attempts=len(candidates),
                )
    finally:
        for still_pending in pending:
            still_pending.cancel()

    raise UpstreamError(
        f"All upstreams failed: {last_exc}", attempts=len(candidates)
    ) from last_exc


def make_servfail(request: DNSPacket) -> DNSPacket:
    """Creates a SERVFAIL response for when all upstreams are unavailable."""
    return make_response(request, rcode=RCODE_SERVFAIL)


async def probe_upstream(
    upstreams: Sequence[tuple[str, int]],
    timeout: float = 1.0,
) -> bool:
    """Lightweight reachability probe for GET /health (FR-16).

    Sends a root NS query to the first upstream that answers; returns True
    on any response and False when all upstreams are unreachable.
    """
    if not upstreams:
        return False
    query = DNSPacket(
        header=DNSHeader(id=random.getrandbits(16), qr=0, rd=0),
        questions=[DNSQuestion(name="", qtype=TYPE_NS)],
    )
    wire = query.to_wire()
    for host, port in upstreams:
        try:
            await _send_udp_query(wire, host, port, timeout)
            return True
        except Exception:
            continue
    return False
