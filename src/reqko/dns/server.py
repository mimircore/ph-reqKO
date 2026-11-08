"""UDP and TCP DNS server (FR-01, NFR-03, NFR-10).

Windows UDP reset hardening (WinError 10054). A client that closes its UDP
socket right after sending makes Windows deliver an ICMP port-unreachable;
the next recvfrom then raises ConnectionResetError. On the default
ProactorEventLoop, _ProactorDatagramTransport._loop_reading does NOT re-arm
the read future after an OSError — the transport stays open ("listening")
but never receives again. Three independent defenses:

  1. the UDP socket is created by reqko with SIO_UDP_CONNRESET (and, when
     available, SIO_UDP_NETRESET) disabled, so client resets never surface
     as receive errors in the first place;
  2. the entrypoint (reqko.__main__) selects
     asyncio.WindowsSelectorEventLoopPolicy, whose selector transport
     re-arms reads after error_received();
  3. DnsUdpWatchdog self-probes UDP liveness every 30 s and REBINDS the
     endpoint after two consecutive failures (see docs/04-implementation.md,
     known Windows pitfall).
"""

from __future__ import annotations

import asyncio
import ctypes
import datetime
import logging
import socket
import struct
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from reqko.dns.pipeline import SELF_PROBE_NAME, PipelineConfig, process_query
from reqko.dns.protocol import TYPE_A, DNSHeader, DNSPacket, DNSQuestion

logger = logging.getLogger(__name__)

# WSAIoctl control codes (Windows): disable ICMP-triggered connection reset
# reporting on UDP sockets. SIO_UDP_NETRESET exists only on newer Windows.
SIO_UDP_CONNRESET = 0x9800000C
SIO_UDP_NETRESET = 0x9800000F

PROBE_INTERVAL_SECONDS = 30.0
PROBE_TIMEOUT_SECONDS = 2.0
PROBE_FAILURES_BEFORE_REBIND = 2


class _UDPDNSProtocol(asyncio.DatagramProtocol):
    """UDP protocol that answers via the RAW socket when one is provided.

    Why raw-socket replies: after a reply hits a closed client port, Windows
    delivers a ONE-SHOT WSAECONNRESET to the socket. asyncio's datagram
    transports (proactor AND selector) treat that as a fatal write error:
    they silently latch _conn_lost and drop every subsequent sendto — the
    server keeps 'listening' but never answers again. A raw socket sendto
    raises once per ICMP event and succeeds again afterwards, so replies
    keep flowing (a dropped reply is normal for UDP; clients retry).
    """

    def __init__(
        self, cfg: PipelineConfig, sock: socket.socket | None = None
    ) -> None:
        self._cfg = cfg
        self._sock = sock  # raw send path; transport used only for receiving
        self._transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        # asyncio guarantees DatagramProtocol.connection_made receives a DatagramTransport
        self._transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        client_ip = addr[0]
        task = asyncio.ensure_future(self._handle(data, client_ip, addr))
        # Keep a reference to avoid GC of the task before it completes
        task.add_done_callback(lambda _t: None)

    async def _handle(
        self, data: bytes, client_ip: str, addr: tuple[str, int]
    ) -> None:
        try:
            response = await process_query(data, client_ip, self._cfg)
            if not response:
                return
            if self._sock is not None:
                try:
                    self._sock.sendto(response, addr)
                except BlockingIOError:
                    pass  # kernel buffer momentarily full: UDP clients retry
                except OSError as exc:
                    # One-shot WSAECONNRESET and friends: this reply is lost,
                    # the next one goes through — never fatal.
                    logger.debug("UDP reply to %s dropped: %s", addr, exc)
            else:
                transport = self._transport
                if transport is not None:
                    transport.sendto(response, addr)
        except Exception as e:
            logger.error("Unhandled error in UDP handler for %s: %s", client_ip, e)

    def error_received(self, exc: Exception) -> None:
        # Must NEVER stop serving: with the selector loop the read is re-armed
        # after this callback; the proactor + raw socket would be the dead
        # combination this file defends against (see module docstring).
        if isinstance(exc, ConnectionResetError):
            logger.debug("UDP peer reset (expected on Windows), continuing: %s", exc)
        else:
            logger.warning("UDP socket error: %s", exc)


def _disable_windows_udp_reset(sock: socket.socket) -> None:
    """Best-effort: silence ICMP-triggered resets on a UDP socket (Windows).

    Calls WSAIoctl directly — Python's socket.ioctl accepts only a fixed set
    of commands and raises ValueError for SIO_UDP_CONNRESET.
    """
    for control_code in (SIO_UDP_CONNRESET, SIO_UDP_NETRESET):
        flag = ctypes.c_ulong(0)  # FALSE: reset reporting off
        returned = ctypes.c_ulong(0)
        result = ctypes.windll.ws2_32.WSAIoctl(
            sock.fileno(),
            control_code,
            ctypes.byref(flag),
            ctypes.sizeof(flag),
            None,
            0,
            ctypes.byref(returned),
            None,
            None,
        )
        if result != 0:
            # SIO_UDP_NETRESET is missing on older Windows; CONRESET failing
            # leaves defenses #2 (selector loop) and #3 (watchdog) active.
            wsa_error = ctypes.windll.ws2_32.WSAGetLastError()
            logger.debug(
                "WSAIoctl(0x%08X) failed (WSA error %d) — continuing",
                control_code,
                wsa_error,
            )


def _create_udp_socket(host: str, port: int) -> socket.socket:
    """Creates and binds the UDP socket with Windows reset handling disabled.

    Defense #1 against WinError 10054: without SIO_UDP_CONNRESET=FALSE, a
    client closing its socket right after sending makes the next recvfrom
    raise ConnectionResetError, which permanently kills the proactor
    transport's read loop.
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
        if sys.platform == "win32":
            _disable_windows_udp_reset(sock)
    except Exception:
        sock.close()
        raise
    return sock


class UdpDnsServer:
    """Owns the UDP DNS endpoint; can rebind it after a watchdog-detected death."""

    def __init__(self, cfg: PipelineConfig, host: str, port: int) -> None:
        self._cfg = cfg
        self._host = host
        self._requested_port = port
        self.transport: asyncio.DatagramTransport | None = None
        self.port: int = port

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        sock = _create_udp_socket(self._host, self._requested_port)
        try:
            # The real port (requested_port may be 0 = ephemeral, tests)
            self.port = sock.getsockname()[1]
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPDNSProtocol(self._cfg, sock), sock=sock
            )
        except Exception:
            sock.close()
            raise
        self.transport = transport

    async def rebind(self) -> None:
        """Closes the current (possibly dead) endpoint and binds a fresh one."""
        old = self.transport
        if old is not None:
            old.close()
        self.transport = None
        # transport.close() releases the underlying socket asynchronously; on
        # Windows the port can still report "in use" for a few ticks — retry.
        last_exc: OSError | None = None
        for _ in range(10):
            try:
                await self.start()
                logger.warning(
                    "UDP DNS endpoint rebound on %s:%d", self._host, self.port
                )
                return
            except OSError as exc:
                last_exc = exc
                await asyncio.sleep(0.05)
        raise OSError(
            f"UDP rebind on {self._host}:{self._requested_port} failed"
        ) from last_exc


@dataclass
class DnsProbeStatus:
    """UDP self-probe watchdog state, exposed via GET /health (self_probe)."""

    last_probe_ok: str | None = None
    consecutive_failures: int = 0
    event_loop_lag_ms: float | None = None


class ProbeTarget(Protocol):
    """What the watchdog needs from the UDP server (structural)."""

    port: int

    async def rebind(self) -> None: ...


class DnsUdpWatchdog:
    """Self-probe watchdog: 'is UDP actually answering?' every interval.

    Sends a UDP query for SELF_PROBE_NAME to 127.0.0.1:<port> (answered by
    the pipeline locally with REFUSED, never logged). Two consecutive
    timeouts mean the UDP path is dead although the socket may still look
    open: an ERROR is logged and the UDP endpoint is rebound. The measured
    overrun of each cycle is reported as event_loop_lag_ms (health).
    """

    def __init__(
        self,
        server: ProbeTarget,
        status: DnsProbeStatus,
        rebind: Callable[[], Awaitable[None]] | None = None,
        *,
        interval: float = PROBE_INTERVAL_SECONDS,
        timeout: float = PROBE_TIMEOUT_SECONDS,
        threshold: int = PROBE_FAILURES_BEFORE_REBIND,
    ) -> None:
        self._server = server
        self._status = status
        self._rebind: Callable[[], Awaitable[None]] = (
            server.rebind if rebind is None else rebind
        )
        self._interval = interval
        self._timeout = timeout
        self._threshold = threshold

    async def run(self, stop_event: asyncio.Event) -> None:
        while not stop_event.is_set():
            started = time.monotonic()
            if await self._probe_once():
                self._status.consecutive_failures = 0
                self._status.last_probe_ok = datetime.datetime.now(
                    datetime.timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S")
            else:
                self._status.consecutive_failures += 1
                if self._status.consecutive_failures >= self._threshold:
                    logger.error(
                        "UDP self-probe failed %d time(s) in a row "
                        "(last OK: %s) — rebinding the UDP endpoint",
                        self._status.consecutive_failures,
                        self._status.last_probe_ok,
                    )
                    try:
                        await self._rebind()
                    except Exception:
                        logger.exception("UDP endpoint rebind failed")
            delay = max(0.0, self._interval - (time.monotonic() - started))
            await asyncio.sleep(delay)
            # Loop-lag probe: by how much did the cycle overrun its interval?
            self._status.event_loop_lag_ms = round(
                max(0.0, (time.monotonic() - started - self._interval) * 1000.0), 1
            )

    async def _probe_once(self) -> bool:
        query_id = 0x524B  # "RK"
        query = DNSPacket(
            header=DNSHeader(id=query_id, qr=0, rd=1),
            questions=[DNSQuestion(name=SELF_PROBE_NAME, qtype=TYPE_A)],
        ).to_wire()
        port = self._server.port
        timeout = self._timeout
        loop = asyncio.get_running_loop()

        def _exchange() -> bytes | None:
            """Blocking one-shot exchange on an ephemeral socket (executor)."""
            probe_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                probe_sock.settimeout(timeout)
                probe_sock.sendto(query, ("127.0.0.1", port))
                data, _addr = probe_sock.recvfrom(512)
                return data
            except OSError:
                # TimeoutError is an OSError alias (socket.timeout), and
                # ConnectionResetError (WinError 10054) arrives when a dead
                # listener answers the probe with ICMP port-unreachable.
                return None
            finally:
                probe_sock.close()

        data = await loop.run_in_executor(None, _exchange)
        if data is None or len(data) < 12:
            return False
        response_id, flags = struct.unpack_from("!HH", data, 0)
        return response_id == query_id and bool(flags & 0x8000)  # QR set


async def _handle_tcp_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    cfg: PipelineConfig,
    idle_timeout: float = 5.0,
) -> None:
    """Handles a single TCP DNS connection (RFC 1035 2-byte length prefix)."""
    peer = writer.get_extra_info("peername")
    client_ip = peer[0] if peer else "unknown"
    try:
        while True:
            try:
                len_data = await asyncio.wait_for(reader.readexactly(2), timeout=idle_timeout)
            except asyncio.TimeoutError:
                break
            except asyncio.IncompleteReadError:
                break

            (msg_len,) = struct.unpack("!H", len_data)
            if msg_len == 0:
                break

            try:
                data = await asyncio.wait_for(reader.readexactly(msg_len), timeout=idle_timeout)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError):
                break

            response = await process_query(data, client_ip, cfg)
            if response:
                writer.write(struct.pack("!H", len(response)) + response)
                await writer.drain()
    except Exception as e:
        logger.error("Unhandled error in TCP handler for %s: %s", client_ip, e)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


@dataclass
class DnsServerHandles:
    """DNS listener handles for the caller (supervision and shutdown)."""

    udp: UdpDnsServer
    tcp: asyncio.Server

    @property
    def port(self) -> int:
        """The actual UDP/TCP port (requested port may have been 0)."""
        return self.udp.port

    @property
    def udp_transport(self) -> asyncio.DatagramTransport:
        assert self.udp.transport is not None
        return self.udp.transport


async def start_dns_servers(
    cfg: PipelineConfig,
    dns_host: str = "0.0.0.0",
    dns_port: int = 53,
    tcp_max_connections: int = 100,
    tcp_idle_timeout: float = 5.0,
) -> DnsServerHandles:
    """Creates the UDP endpoint (reset-hardened) and the TCP DNS server."""
    udp = UdpDnsServer(cfg, dns_host, dns_port)
    await udp.start()

    # RFC 1035: UDP and TCP listen on the SAME port. With port 0 (ephemeral,
    # used by tests) the actual assigned port comes from the UDP socket.
    semaphore = asyncio.Semaphore(tcp_max_connections)

    async def _limited_tcp_handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        async with semaphore:
            await _handle_tcp_client(reader, writer, cfg, idle_timeout=tcp_idle_timeout)

    try:
        tcp_server = await asyncio.start_server(
            _limited_tcp_handler,
            dns_host,
            udp.port,
        )
    except Exception:
        # Do not leak the already-bound UDP transport when TCP cannot bind
        if udp.transport is not None:
            udp.transport.close()
        raise

    logger.info("DNS UDP+TCP listening on %s:%d", dns_host, udp.port)
    return DnsServerHandles(udp=udp, tcp=tcp_server)


async def run_dns_servers(
    cfg: PipelineConfig,
    dns_host: str = "0.0.0.0",
    dns_port: int = 53,
    tcp_max_connections: int = 100,
    tcp_idle_timeout: float = 5.0,
) -> tuple[asyncio.DatagramTransport, asyncio.Server]:
    """Creates and returns UDP and TCP DNS server handles (compat wrapper)."""
    handles = await start_dns_servers(
        cfg,
        dns_host=dns_host,
        dns_port=dns_port,
        tcp_max_connections=tcp_max_connections,
        tcp_idle_timeout=tcp_idle_timeout,
    )
    return handles.udp_transport, handles.tcp
