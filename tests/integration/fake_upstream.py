"""In-process fake upstream DNS server (UDP + TCP) for integration tests.

Uses dnspython to build responses. Fully configurable per-test:
- answer map: qname -> list of (rtype, rdata, ttl)
- canned wire responses sent verbatim (for wrong ID / wrong question tests)
- UDP answer delay (to trigger resolver-side timeouts)
- TC=1 responses (to force TCP fallback)
- query log for assertions
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field

import dns.flags
import dns.message
import dns.rcode
import dns.rrset
from dns.rdatatype import RdataType

# Default payload returned by the fake upstream for A queries
DEFAULT_A_TTL = 300


@dataclass
class FakeUpstreamConfig:
    """Per-server behaviour knobs."""

    # qname (lowercase) -> list of (owner, ttl, rdatatype_name, rdata) tuples;
    # owner may differ from qname for CNAME chains
    answers: dict[str, list[tuple[str, int, str, str]]] = field(default_factory=dict)
    # qname -> raw wire bytes sent verbatim instead of a built message
    canned_wire: dict[str, bytes] = field(default_factory=dict)
    # qname -> delay in seconds before the UDP answer is sent
    udp_delay: dict[str, float] = field(default_factory=dict)
    # qnames answered with TC=1 over UDP (forces resolver TCP retry)
    truncated: set[str] = field(default_factory=set)
    # if True, never answer at all (read timeout on the resolver side)
    silent: bool = False


class FakeUpstreamServer:
    """A fake authoritative/recursive upstream listening on UDP and TCP."""

    def __init__(self, config: FakeUpstreamConfig | None = None) -> None:
        self.config = config or FakeUpstreamConfig()
        self.udp_port: int = 0
        self.tcp_port: int = 0
        self.queries: list[tuple[str, str]] = []  # (protocol, qname)
        self._udp_transport: asyncio.DatagramTransport | None = None
        self._tcp_server: asyncio.Server | None = None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._udp_transport, _ = await loop.create_datagram_endpoint(
            lambda: _FakeUDPProtocol(self), local_addr=("127.0.0.1", 0)
        )
        sock = self._udp_transport.get_extra_info("socket")
        assert sock is not None
        self.udp_port = sock.getsockname()[1]

        # Real upstream DNS servers serve UDP and TCP on the SAME port;
        # the resolver's TC=1 TCP fallback connects to the UDP port.
        self._tcp_server = await asyncio.start_server(
            lambda r, w: self._handle_tcp(r, w), "127.0.0.1", self.udp_port
        )
        self.tcp_port = self.udp_port

    async def stop(self) -> None:
        if self._udp_transport is not None:
            self._udp_transport.close()
        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()

    @property
    def address(self) -> tuple[str, int]:
        return "127.0.0.1", self.udp_port

    # ── response building ─────────────────────────────────────────────────────

    def _build_response(self, query: dns.message.Message, truncate: bool = True) -> dns.message.Message:
        qname = str(query.question[0].name).rstrip(".").lower()
        qtype = query.question[0].rdtype
        response = dns.message.make_response(query)

        if qname in self.config.canned_wire:
            # Cannot mix canned wire into a built message; caller handles this.
            raise RuntimeError("canned_wire handled separately")

        records = self.config.answers.get(qname, [])
        for owner, ttl, rtype_name, rdata in records:
            response.answer.append(
                dns.rrset.from_text(owner, ttl, "IN", rtype_name, rdata)
            )

        # Only the UDP transport truncates; the TCP answer must be complete.
        if truncate and qname in self.config.truncated:
            response.flags |= dns.flags.TC

        if not records and qtype != RdataType.ANY:
            # NXDOMAIN with an SOA in authority for negative caching scenarios
            response.set_rcode(dns.rcode.NXDOMAIN)
        return response

    def _answer_udp(self, data: bytes) -> bytes | None:
        if self.config.silent:
            return None
        try:
            query = dns.message.from_wire(data)
        except Exception:
            return None
        qname = str(query.question[0].name).rstrip(".").lower()
        self.queries.append(("udp", qname))
        if qname in self.config.canned_wire:
            return self.config.canned_wire[qname]
        response = self._build_response(query)
        return response.to_wire()

    # ── transports ────────────────────────────────────────────────────────────

    async def _handle_udp(self, data: bytes, addr: tuple[str, int]) -> None:
        assert self._udp_transport is not None
        delay = 0.0
        try:
            query = dns.message.from_wire(data)
            delay = self.config.udp_delay.get(
                str(query.question[0].name).rstrip(".").lower(), 0.0
            )
        except Exception:
            pass
        if delay:
            await asyncio.sleep(delay)
        wire = self._answer_udp(data)
        if wire is not None:
            self._udp_transport.sendto(wire, addr)

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                try:
                    len_data = await asyncio.wait_for(reader.readexactly(2), timeout=5.0)
                except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                    break
                (msg_len,) = struct.unpack("!H", len_data)
                data = await reader.readexactly(msg_len)

                if self.config.silent:
                    # Hold the connection without answering
                    continue
                try:
                    query = dns.message.from_wire(data)
                except Exception:
                    break
                qname = str(query.question[0].name).rstrip(".").lower()
                self.queries.append(("tcp", qname))
                wire = self.config.canned_wire.get(qname)
                if wire is None:
                    wire = self._build_response(query, truncate=False).to_wire()
                writer.write(struct.pack("!H", len(wire)) + wire)
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


class _FakeUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, server: FakeUpstreamServer) -> None:
        self._server = server
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        # asyncio guarantees DatagramProtocol.connection_made receives a DatagramTransport
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        task = asyncio.ensure_future(self._server._handle_udp(data, addr))
        task.add_done_callback(lambda _t: None)

    def error_received(self, exc: Exception) -> None:  # pragma: no cover
        pass
