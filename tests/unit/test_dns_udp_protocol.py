"""Unit tests: the UDP protocol never stops serving after socket errors.

Regression for the Windows WinError 10054 bug: after error_received
(ConnectionResetError from an ICMP port-unreachable) the protocol must keep
receiving and answering datagrams.
"""

from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, cast

from reqko.dns.acl import ClientACL
from reqko.dns.cache import DNSCache
from reqko.dns.pipeline import PipelineConfig
from reqko.dns.protocol import TYPE_A, DNSHeader, DNSPacket, DNSQuestion
from reqko.dns.ratelimit import RateLimiter
from reqko.dns.server import _UDPDNSProtocol
from reqko.filtering.engine import FilterEngine, FilterSnapshot


class _RecordingTransport:
    """Minimal transport stub recording sendto calls."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    def sendto(self, data: bytes, addr: tuple[str, int] | None = None) -> None:
        self.sent.append(data)

    def is_closing(self) -> bool:
        return False

    def close(self) -> None:
        pass

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        return default


def _blocked_cfg() -> PipelineConfig:
    snapshot = FilterSnapshot(
        exact_set=frozenset({"ads.test"}),
        wildcard_set=frozenset(),
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
        version=1,
    )
    return PipelineConfig(
        acl=ClientACL([ipaddress.ip_network("127.0.0.0/8")]),
        rate_limiter=RateLimiter(rate_rps=10000.0, burst=20000.0),
        filter_engine=FilterEngine(snapshot),
        cache=DNSCache(),
        upstreams=[("127.0.0.1", 1)],  # never reached: query is blocked locally
        upstream_timeout=0.1,
        block_mode="NULL",
    )


def _blocked_query(qid: int) -> bytes:
    return DNSPacket(
        header=DNSHeader(id=qid, qr=0, rd=1),
        questions=[DNSQuestion(name="ads.test", qtype=TYPE_A)],
    ).to_wire()


async def _answered_after_error(exc: Exception) -> list[bytes]:
    """error_received(exc), then one query -> the sent responses."""
    protocol = _UDPDNSProtocol(_blocked_cfg())
    transport = _RecordingTransport()
    protocol.connection_made(cast(asyncio.BaseTransport, transport))

    protocol.error_received(exc)  # must not raise or close the transport
    assert transport.is_closing() is False

    protocol.datagram_received(_blocked_query(0x1234), ("127.0.0.1", 54321))
    for _ in range(200):
        if transport.sent:
            break
        await asyncio.sleep(0.005)
    return transport.sent


async def test_connection_reset_error_does_not_stop_serving() -> None:
    """Exactly the Windows ICMP port-unreachable error (WinError 10054)."""
    sent = await _answered_after_error(
        ConnectionResetError(10054, "Connection reset by peer")
    )
    assert sent, "protocol stopped answering after ConnectionResetError"
    header, _ = DNSHeader.from_wire(sent[0])
    assert header.id == 0x1234
    assert header.qr == 1  # a response


async def test_generic_socket_error_does_not_stop_serving() -> None:
    sent = await _answered_after_error(OSError("generic socket error"))
    assert sent, "protocol stopped answering after a generic socket error"


async def test_several_resets_in_a_row_still_serving() -> None:
    """Repeated resets (a churning client) must not accumulate into a stop."""
    protocol = _UDPDNSProtocol(_blocked_cfg())
    transport = _RecordingTransport()
    protocol.connection_made(cast(asyncio.BaseTransport, transport))
    for _ in range(5):
        protocol.error_received(ConnectionResetError(10054, "reset"))
    protocol.datagram_received(_blocked_query(0x4321), ("127.0.0.1", 54321))
    for _ in range(200):
        if transport.sent:
            break
        await asyncio.sleep(0.005)
    assert transport.sent
    header, _ = DNSHeader.from_wire(transport.sent[0])
    assert header.id == 0x4321
