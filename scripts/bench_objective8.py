"""Objective-8 benchmark: latency/throughput per query class and concurrency.

Queries a RUNNING ph-reqKO server (UDP) and measures, per concurrency level
(1/10/50) and per class (cached / forwarded / blocked), throughput (qps) and
latency p50/p95/p99/max. Also: amplification ratio (response/request bytes).

stdlib + dnspython only. Names:
  cached    -- one fixed name asked repeatedly (served from cache after #1)
  forwarded -- unique names guaranteed NOT in the blocklist (upstream RTT)
  blocked   -- names taken verbatim from the loaded blocklist file

Usage:
  python scripts/bench_objective8.py --port 15353 --blocklist-file hosts.txt \
      --per-scenario 100 --concurrencies 1,10,50
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import random
import sys
import time
from pathlib import Path

import dns.message  # dnspython (declared dependency)

random.seed(20261110)


def percentile(sorted_values: list[float], p: float) -> float:
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * p / 100.0
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return sorted_values[int(k)]
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


def _query_wire(name: str, qid: int) -> bytes:
    return dns.message.make_query(name, "A").to_wire()


class _Client(asyncio.DatagramProtocol):
    def __init__(self, fut: asyncio.Future[bytes]) -> None:
        self.fut = fut

    def datagram_received(self, data: bytes, addr: object) -> None:
        if not self.fut.done():
            self.fut.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.fut.done():
            self.fut.set_exception(exc)


async def one_exchange(
    host: str, port: int, name: str, qid: int, timeout: float
) -> tuple[float, int, int]:
    """One UDP exchange; returns (latency_ms, request_bytes, response_bytes)."""
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[bytes] = loop.create_future()
    wire = _query_wire(name, qid)
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _Client(fut), remote_addr=(host, port)
    )
    try:
        started = time.perf_counter()
        transport.sendto(wire)
        response = await asyncio.wait_for(fut, timeout=timeout)
        return (time.perf_counter() - started) * 1000.0, len(wire), len(response)
    finally:
        transport.close()


async def bench_scenario(
    host: str,
    port: int,
    names: list[str],
    concurrency: int,
    timeout: float,
) -> dict[str, float | int]:
    """Runs len(names) queries with the given concurrency; returns stats."""
    semaphore = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    amplification: list[float] = []
    failures = 0
    qid_counter = iter(range(1, 1_000_000))

    async def worker(name: str) -> None:
        nonlocal failures
        async with semaphore:
            try:
                ms, req_len, resp_len = await one_exchange(
                    host, port, name, next(qid_counter), timeout
                )
                latencies.append(ms)
                amplification.append(resp_len / max(req_len, 1))
            except (asyncio.TimeoutError, OSError):
                failures += 1

    started = time.perf_counter()
    await asyncio.gather(*(worker(n) for n in names))
    wall = time.perf_counter() - started

    latencies.sort()
    return {
        "queries": len(names),
        "answered": len(latencies),
        "failures": failures,
        "qps": round(len(names) / wall, 1) if wall > 0 else 0.0,
        "p50": round(percentile(latencies, 50), 2),
        "p95": round(percentile(latencies, 95), 2),
        "p99": round(percentile(latencies, 99), 2),
        "max": round(latencies[-1], 2) if latencies else 0.0,
        "amplification_mean": round(sum(amplification) / len(amplification), 3)
        if amplification
        else 0.0,
    }


def load_blocked_names(list_file: Path, count: int) -> list[str]:
    """Extracts blocked domains from a hosts-format file (0.0.0.0 name)."""
    names: list[str] = []
    for line in list_file.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            names.append(parts[1])
        elif line.startswith("||") and line.endswith("^"):
            names.append(line[2:-1])
    # dedupe deterministically, drop very short entries
    seen: set[str] = set()
    unique = []
    for name in names:
        if len(name) > 6 and name not in seen:
            seen.add(name)
            unique.append(name)
    random.shuffle(unique)
    return unique[:count]


async def main() -> int:
    parser = argparse.ArgumentParser(description="ph-reqKO objective-8 benchmark")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=15353)
    parser.add_argument("--blocklist-file", type=Path, required=True)
    parser.add_argument("--per-scenario", type=int, default=100)
    parser.add_argument("--concurrencies", default="1,10,50")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--prefix", default="o8",
                        help="unique-name prefix: forwarded queries must never repeat")
    parser.add_argument("--skip-kinds", default="",
                        help="comma-separated kinds to skip (cached,forwarded,blocked)")
    args = parser.parse_args()
    skip = {k.strip() for k in args.skip_kinds.split(",") if k.strip()}

    blocked_names = load_blocked_names(args.blocklist_file, args.per_scenario)
    cached_name = "cached-bench.o8.example"
    forwarded_counter = iter(range(1, 1_000_000_000))

    def forwarded_names(count: int) -> list[str]:
        # EVERY forwarded query must use a fresh name: repeats would be served
        # from the cache and silently degrade the scenario into "cached".
        return [f"{args.prefix}-f{next(forwarded_counter)}.bench.example"
                for _ in range(count)]

    results: dict[str, object] = {}
    for concurrency in (int(c) for c in args.concurrencies.split(",")):
        # Warm the cache entry once so "cached" really measures the cache path
        await one_exchange(args.host, args.port, cached_name, 99999, args.timeout)

        for kind, names in (
            ("cached", [cached_name] * args.per_scenario),
            ("forwarded", forwarded_names(args.per_scenario)),
            ("blocked", blocked_names),
        ):
            if kind in skip:
                continue
            stats = await bench_scenario(
                args.host, args.port, names, concurrency, args.timeout
            )
            results[f"{kind}@c{concurrency}"] = stats
            print(
                f"{kind:<10} c={concurrency:<3} "
                f"qps={stats['qps']:>8} p50={stats['p50']:>9} p95={stats['p95']:>9} "
                f"p99={stats['p99']:>9} max={stats['max']:>10} "
                f"answered={stats['answered']}/{stats['queries']} "
                f"amp={stats['amplification_mean']}",
                flush=True,
            )

    print("JSON_BEGIN")
    print(json.dumps(results, indent=2))
    print("JSON_END")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
