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


def memory_snapshot(pid: int) -> dict[str, int] | None:
    """Detailed memory footprint of a process, or None if unavailable.

    Windows: GetProcessMemoryInfo with PROCESS_MEMORY_COUNTERS_EX —
    WorkingSetSize (resident, trimmed when idle), PeakWorkingSetSize and
    PrivateUsage (private commit charge — the credible "how much heap does
    the process actually hold" number).
    Linux: VmRSS (resident) and VmHWM (peak resident) from /proc/<pid>/status.
    """
    if sys.platform == "win32":
        psapi = ctypes.windll.psapi
        kernel32 = ctypes.windll.kernel32

        class _PMCEX(ctypes.Structure):
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
                ("PrivateUsage", ctypes.c_size_t),
            ]

        pmc = _PMCEX()
        pmc.cb = ctypes.sizeof(_PMCEX)
        handle = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)  # QUERY_INFO|VM_READ
        if not handle:
            return None
        try:
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb):
                return None
            return {
                "working_set": int(pmc.WorkingSetSize),
                "peak_working_set": int(pmc.PeakWorkingSetSize),
                "private_usage": int(pmc.PrivateUsage),
            }
        finally:
            kernel32.CloseHandle(handle)
    fields: dict[str, int] = {}
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            if line.startswith(("VmRSS:", "VmHWM:")):
                key, value, _unit = line.split()
                fields["vm_rss" if key == "VmRSS:" else "vm_hwm"] = int(value) * 1024
    except OSError:
        return None
    return fields or None


def rss_bytes(pid: int) -> int | None:
    """Resident set size of a process, or None if unavailable."""
    snap = memory_snapshot(pid)
    if snap is None:
        return None
    return snap.get("working_set", snap.get("vm_rss"))


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
    samples: list[tuple[float, dict[str, int]]] = []
    queries = 0
    errors = 0
    started = time.monotonic()
    next_sample = started
    next_query = started
    delay = 1.0 / args.qps

    while time.monotonic() - started < args.duration:
        now = time.monotonic()
        if now >= next_sample:
            snap = memory_snapshot(args.pid)
            elapsed = now - started
            if snap is not None:
                samples.append((elapsed, snap))
                parts = " ".join(f"{k}={v / 1048576:8.2f}MiB" for k, v in sorted(snap.items()))
                print(f"t={elapsed:7.1f}s {parts} queries={queries} errors={errors}",
                      flush=True)
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
        first = samples[:quarter]
        last = samples[-quarter:]
        for key in sorted(samples[0][1]):
            first_avg = sum(s[1][key] for s in first) / len(first)
            last_avg = sum(s[1][key] for s in last) / len(last)
            print(f"SOAK TREND {key}: first-quarter avg={first_avg / 1048576:.2f} MiB, "
                  f"last-quarter avg={last_avg / 1048576:.2f} MiB, "
                  f"delta={(last_avg - first_avg) / 1048576:+.2f} MiB")
        print(f"SOAK TOTAL: {args.duration:.0f}s, queries={queries}, errors={errors}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
