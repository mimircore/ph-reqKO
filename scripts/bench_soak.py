"""Objective-8 soak: steady DNS load + server RSS sampling with trend.

Generates a mixed query load (blocked/forwarded/cached) against a running
server for --duration seconds while sampling the server's resident memory
every --interval seconds. Prints per-sample lines and a linear trend (RSS
delta between the averages of the first and last quarter of the run).

stdlib only. RSS via psapi GetProcessMemoryInfo (Windows) or /proc (Linux).
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import random
import socket
import sys
import time
from pathlib import Path


def rss_bytes(pid: int) -> int | None:
    """Resident set size of a process, or None if unavailable."""
    if sys.platform != "win32":
        return None
    psapi = ctypes.windll.psapi
    kernel32 = ctypes.windll.kernel32

    class _PMC(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    pmc = _PMC()
    pmc.cb = ctypes.sizeof(_PMC)
    handle = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)  # QUERY_INFO|VM_READ
    if not handle:
        return None
    try:
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
            return None
        return int(pmc.WorkingSetSize)
    finally:
        kernel32.CloseHandle(handle)
    proc = Path(f"/proc/{pid}/status")
    try:
        for line in proc.read_text(encoding="utf-8").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except OSError:
        return None
    return None  # pragma: no cover - non-win32 non-linux


async def one_query(sock: socket.socket, name: str, server: tuple[str, int]) -> float:
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[bytes] = loop.create_future()

    class _P(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: object) -> None:
            if not fut.done():
                fut.set_result(data)

    import dns.message

    wire = dns.message.make_query(name, "A").to_wire()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _P(), remote_addr=server
    )
    try:
        started = time.perf_counter()
        transport.sendto(wire)
        await asyncio.wait_for(fut, timeout=10.0)
        return (time.perf_counter() - started) * 1000.0
    finally:
        transport.close()


async def main() -> int:
    parser = argparse.ArgumentParser(description="ph-reqKO soak + RSS trend")
    parser.add_argument("--pid", type=int, required=True, help="server process id")
    parser.add_argument("--port", type=int, default=15353)
    parser.add_argument("--duration", type=float, default=600.0)
    parser.add_argument("--interval", type=float, default=10.0, help="RSS sample interval")
    parser.add_argument("--qps", type=float, default=20.0, help="target load")
    parser.add_argument("--blocklist-file", type=Path, required=True)
    args = parser.parse_args()

    blocked = []
    for line in args.blocklist_file.read_text(encoding="utf-8", errors="replace").splitlines()[:5000]:
        parts = line.split()
        if len(parts) == 2 and parts[0] == "0.0.0.0" and len(parts[1]) > 6:
            blocked.append(parts[1])
    random.seed(8)

    server = ("127.0.0.1", args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    samples: list[tuple[float, int]] = []
    queries = 0
    errors = 0
    started = time.monotonic()
    next_sample = started
    next_query = started
    delay = 1.0 / args.qps

    while time.monotonic() - started < args.duration:
        now = time.monotonic()
        if now >= next_sample:
            rss = rss_bytes(args.pid)
            elapsed = now - started
            if rss is not None:
                samples.append((elapsed, rss))
                print(f"t={elapsed:7.1f}s RSS={rss / 1024 / 1024:8.2f} MiB "
                      f"queries={queries} errors={errors}", flush=True)
            next_sample = now + args.interval
        if now >= next_query:
            kind = random.random()
            if kind < 0.45:
                name = random.choice(blocked)
            elif kind < 0.9:
                name = f"soak-{queries}.bench.example"
            else:
                name = "cached-bench.o8.example"
            try:
                await one_query(sock, name, server)
                queries += 1
            except (asyncio.TimeoutError, OSError):
                errors += 1
            next_query = now + delay
        await asyncio.sleep(0.002)

    if len(samples) >= 4:
        quarter = max(1, len(samples) // 4)
        first = sum(r for _, r in samples[:quarter]) / quarter
        last = sum(r for _, r in samples[-quarter:]) / quarter
        print(f"SOAK TREND: first-quarter avg RSS={first / 1024 / 1024:.2f} MiB, "
              f"last-quarter avg RSS={last / 1024 / 1024:.2f} MiB, "
              f"delta={(last - first) / 1024 / 1024:+.2f} MiB over "
              f"{args.duration:.0f}s, total queries={queries}, errors={errors}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
