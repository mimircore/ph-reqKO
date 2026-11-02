"""UDP and TCP DNS server (FR-01, NFR-03, NFR-10)."""

from __future__ import annotations

import asyncio
import logging
import struct

from reqko.dns.pipeline import PipelineConfig, process_query

logger = logging.getLogger(__name__)


class _UDPDNSProtocol(asyncio.DatagramProtocol):
    def __init__(self, cfg: PipelineConfig) -> None:
        self._cfg = cfg
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
            transport = self._transport
            if response and transport is not None:
                transport.sendto(response, addr)
        except Exception as e:
            logger.error("Unhandled error in UDP handler for %s: %s", client_ip, e)

    def error_received(self, exc: Exception) -> None:
        logger.warning("UDP socket error: %s", exc)


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


async def run_dns_servers(
    cfg: PipelineConfig,
    dns_host: str = "0.0.0.0",
    dns_port: int = 53,
    tcp_max_connections: int = 100,
    tcp_idle_timeout: float = 5.0,
) -> tuple[asyncio.DatagramTransport, asyncio.Server]:
    """Creates and returns UDP and TCP DNS server handles."""
    loop = asyncio.get_event_loop()

    # UDP
    udp_transport, _ = await loop.create_datagram_endpoint(
        lambda: _UDPDNSProtocol(cfg),
        local_addr=(dns_host, dns_port),
    )

    # TCP with connection semaphore
    semaphore = asyncio.Semaphore(tcp_max_connections)

    async def _limited_tcp_handler(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        async with semaphore:
            await _handle_tcp_client(reader, writer, cfg, idle_timeout=tcp_idle_timeout)

    tcp_server = await asyncio.start_server(
        _limited_tcp_handler,
        dns_host,
        dns_port,
    )

    logger.info("DNS UDP+TCP listening on %s:%d", dns_host, dns_port)
    return udp_transport, tcp_server
