"""Async upstream DNS client (FR-02).

Sends queries to upstream DNS servers over UDP with TCP fallback (TC=1).
Supports timeout, fallback upstream list, and per-query source validation.
"""

from __future__ import annotations

import asyncio
import logging
import struct
from collections.abc import Sequence

from reqko.dns.protocol import (
    RCODE_SERVFAIL,
    DNSPacket,
    make_response,
    parse_wire,
)

logger = logging.getLogger(__name__)

MAX_UDP_PAYLOAD = 512


class UpstreamError(OSError):
    """Raised when all configured upstream servers are unavailable."""


async def _send_udp_query(
    wire: bytes,
    host: str,
    port: int,
    timeout: float,
) -> bytes:
    """Sends a DNS query over UDP and returns raw response bytes."""
    loop = asyncio.get_event_loop()

    # Create ephemeral socket for each query
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


async def query_upstream(
    request: DNSPacket,
    upstreams: Sequence[tuple[str, int]],
    timeout: float = 2.0,
) -> DNSPacket:
    """Queries upstream DNS servers with UDP + TC=1 TCP fallback.

    Tries each upstream in order. Returns first successful response.
    Raises UpstreamError if all fail.
    """
    if not request.questions:
        raise UpstreamError("Request has no questions")

    wire = request.to_wire()

    last_exc: Exception = UpstreamError("No upstreams configured")

    for host, port in upstreams:
        try:
            raw = await _send_udp_query(wire, host, port, timeout)
            response = parse_wire(raw)

            # Validate transaction ID matches
            if response.header.id != request.header.id:
                logger.warning(
                    "Upstream %s:%d returned mismatched ID %d (expected %d)",
                    host,
                    port,
                    response.header.id,
                    request.header.id,
                )
                continue

            # Validate question echoed back
            if response.questions and request.questions:
                req_q = request.questions[0]
                resp_q = response.questions[0]
                if (
                    req_q.name.lower() != resp_q.name.lower()
                    or req_q.qtype != resp_q.qtype
                ):
                    logger.warning(
                        "Upstream %s:%d returned different question: %s/%d (expected %s/%d)",
                        host,
                        port,
                        resp_q.name,
                        resp_q.qtype,
                        req_q.name,
                        req_q.qtype,
                    )
                    continue

            # TC=1 -> retry over TCP
            if response.header.tc:
                logger.debug("Upstream %s:%d returned TC=1, retrying over TCP", host, port)
                try:
                    raw_tcp = await _send_tcp_query(wire, host, port, timeout)
                    response = parse_wire(raw_tcp)
                    if response.header.id != request.header.id:
                        continue
                except Exception as e:
                    logger.warning("TCP fallback to %s:%d failed: %s", host, port, e)
                    last_exc = e if isinstance(e, Exception) else OSError(str(e))
                    continue

            return response

        except Exception as e:
            logger.warning("Upstream %s:%d failed: %s", host, port, e)
            last_exc = e

    raise UpstreamError(f"All upstreams failed: {last_exc}") from last_exc


def make_servfail(request: DNSPacket) -> DNSPacket:
    """Creates a SERVFAIL response for when all upstreams are unavailable."""
    return make_response(request, rcode=RCODE_SERVFAIL)
