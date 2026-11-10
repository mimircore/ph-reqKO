"""Runtime tests for the real entrypoint (src/reqko/__main__.py, FR-01..FR-19).

Runs the full `_run()` stack in-process on high ports (no port 53, no signal
handlers — the shutdown is triggered through an injected event) and verifies:
startup wiring (DNS UDP+TCP, REST API, metrics site), query answering through
the real sockets, and graceful shutdown with the final log flush.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import urllib.request
from collections.abc import Generator
from pathlib import Path

import dns.message
import pytest

from reqko.__main__ import _run
from reqko.config import Config
from reqko.dns.protocol import parse_wire
from reqko.storage.migrations import init_database


def _free_port() -> int:
    """A free high port (bound and released; the resolver binds it next)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _make_config(tmp_path: Path, **extra: str) -> Config:
    """Config on free HIGH ports (never 53); upstream 127.0.0.1:1 fails fast."""
    env = {
        "REQKO_ADMIN_TOKEN": "runtime-admin-token",
        "REQKO_READ_TOKEN": "runtime-read-token",
        "REQKO_DB_PATH": str(tmp_path / "runtime.db"),
        "REQKO_DNS_HOST": "127.0.0.1",
        "REQKO_DNS_PORT": str(_free_port()),
        "REQKO_API_HOST": "127.0.0.1",
        "REQKO_API_PORT": str(_free_port()),
        "REQKO_METRICS_HOST": "127.0.0.1",
        "REQKO_METRICS_PORT": str(_free_port()),
        "REQKO_UPSTREAM_DNS": "127.0.0.1:1",  # dead: fast-fail, no external DNS
        "REQKO_SUGGEST_INTERVAL_MINUTES": "0",
        "REQKO_BLOCKLIST_REFRESH_HOURS": "0",
        "REQKO_LOG_LEVEL": "WARNING",
        **extra,
    }
    return Config.from_env(env)


def _a_query(name: str) -> bytes:
    return dns.message.make_query(name, "A").to_wire()


class _UdpClient(asyncio.DatagramProtocol):
    def __init__(self, fut: asyncio.Future[bytes]) -> None:
        self.fut = fut

    def datagram_received(self, data: bytes, addr: object) -> None:
        if not self.fut.done():
            self.fut.set_result(data)


async def _udp_ask(port: int, wire: bytes, timeout: float = 3.0) -> bytes:
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[bytes] = loop.create_future()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _UdpClient(fut), remote_addr=("127.0.0.1", port)
    )
    try:
        transport.sendto(wire)
        return await asyncio.wait_for(fut, timeout=timeout)
    finally:
        transport.close()


@pytest.fixture()
def capture_logs(monkeypatch: pytest.MonkeyPatch) -> Generator[list[str], None, None]:
    """Captures reqko log messages (startup lines carry the ephemeral ports)."""
    lines: list[str] = []

    class _List(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(record.getMessage())

    handler = _List()
    loggers = [logging.getLogger("reqko.dns.server"), logging.getLogger("reqko")]
    for logger in loggers:
        logger.addHandler(handler)
        monkeypatch.setattr(logger, "level", logging.INFO)
    yield lines
    for logger in loggers:
        logger.removeHandler(handler)
        monkeypatch.undo()


def _port_from_log(log_lines: list[str], marker: str) -> int:
    import re

    for line in log_lines:
        if marker in line:
            match = re.search(r"127\.0\.0\.1:(\d+)", line)
            assert match is not None, line
            return int(match.group(1))
    raise AssertionError(f"'{marker}' not found in startup log: {log_lines!r}")


async def test_full_runtime_start_serve_shutdown_final_flush(
    tmp_path: Path, capture_logs: list[str]
) -> None:
    """Startup wiring + serving + graceful shutdown with a final flush."""
    config = _make_config(tmp_path)
    shutdown = asyncio.Event()
    runtime = asyncio.create_task(_run(config, shutdown_event=shutdown))

    # ── startup wiring: DNS, API and metrics sites all came up ───────────────
    for _ in range(200):
        if len(capture_logs) >= 3:
            break
        await asyncio.sleep(0.05)
    dns_port = _port_from_log(capture_logs, "DNS UDP+TCP listening on 127.0.0.1:")
    api_port = _port_from_log(capture_logs, "REST API listening on 127.0.0.1:")
    metrics_port = _port_from_log(
        capture_logs, "Metrics endpoint listening on 127.0.0.1:"
    )
    assert dns_port > 0 and api_port > 0 and metrics_port > 0

    # ── real UDP query answered through the running stack ────────────────────
    # upstream 127.0.0.1:1 fails fast -> ERROR_UPSTREAM; either way a reply
    response = parse_wire(await _udp_ask(dns_port, _a_query("runtime.test")))
    assert response.header.qr == 1
    assert response.header.rcode == 2  # SERVFAIL: all upstreams failed

    # self-probe: answered locally with REFUSED, no upstream involvement
    probe = parse_wire(await _udp_ask(dns_port, _a_query("selfprobe.reqko.internal")))
    assert probe.header.rcode == 5

    # ── the real metrics site exposes Prometheus text ────────────────────────
    # blocking urlopen must run in the executor: the site lives on this loop
    loop = asyncio.get_running_loop()
    metrics_body = await loop.run_in_executor(
        None,
        lambda: urllib.request.urlopen(
            f"http://127.0.0.1:{metrics_port}/metrics", timeout=5
        ).read().decode(),
    )
    assert "dns_queries_total" in metrics_body
    assert 'qtype="A"' in metrics_body

    # ── graceful shutdown: final flush must land the query in SQLite ─────────
    shutdown.set()
    await asyncio.wait_for(runtime, timeout=15.0)

    conn = init_database(str(tmp_path / "runtime.db"))
    rows = conn.execute(
        "SELECT status FROM query_log WHERE question_name = 'runtime.test'"
    ).fetchall()
    assert rows, "query_log missing the runtime.test row after graceful shutdown"
    assert rows[0][0] == "ERROR_UPSTREAM"
    probe_rows = conn.execute(
        "SELECT COUNT(*) FROM query_log WHERE question_name = 'selfprobe.reqko.internal'"
    ).fetchone()
    assert probe_rows[0] == 0  # watchdog probes never logged
    conn.close()


async def test_runtime_blocklist_loads_and_blocks(
    tmp_path: Path, capture_logs: list[str]
) -> None:
    """A configured blocklist file is loaded at startup and blocks queries."""
    list_file = tmp_path / "o8_block.txt"
    list_file.write_text("||blocked-runtime.test^\n", encoding="utf-8")
    config = _make_config(tmp_path, REQKO_BLOCKLIST_FILES=str(list_file))
    shutdown = asyncio.Event()
    runtime = asyncio.create_task(_run(config, shutdown_event=shutdown))
    try:
        for _ in range(200):
            if any("DNS UDP+TCP listening" in line for line in capture_logs):
                break
            await asyncio.sleep(0.05)
        dns_port = _port_from_log(capture_logs, "DNS UDP+TCP listening on 127.0.0.1:")

        # Blocked name: 0.0.0.0, no upstream needed
        blocked = parse_wire(await _udp_ask(dns_port, _a_query("blocked-runtime.test")))
        assert blocked.answers[0].rdata == "0.0.0.0"

        # Self-probe still answered locally
        assert parse_wire(
            await _udp_ask(dns_port, _a_query("selfprobe.reqko.internal"))
        ).header.rcode == 5
    finally:
        shutdown.set()
        await asyncio.wait_for(runtime, timeout=15.0)


async def test_runtime_shutdown_with_empty_queue_completes_cleanly(
    tmp_path: Path,
) -> None:
    """Shutdown without traffic completes cleanly and leaves a closed DB."""
    config = _make_config(tmp_path)
    shutdown = asyncio.Event()
    runtime = asyncio.create_task(_run(config, shutdown_event=shutdown))
    await asyncio.sleep(0.5)  # let the stack come up
    shutdown.set()
    await asyncio.wait_for(runtime, timeout=15.0)  # no hang, no exception
    conn = init_database(str(tmp_path / "runtime.db"))
    assert conn.execute("SELECT COUNT(*) FROM query_log").fetchone()[0] == 0
    conn.close()
