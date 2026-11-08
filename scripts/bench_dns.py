"""DNS latency benchmark for ph-reqKO (N concurrent queries -> p50/p95/p99).

Two modes:
  client (default):  bench against an already-running server:
        python scripts/bench_dns.py --port 53 --n 200 --concurrency 20
  --selfhosted:      starts the full reqko resolver in-process with a fake
        second upstream (answers every A query after a configurable delay);
        the FIRST upstream is a dead port, so uncached queries exercise the
        dead-upstream fallback path — the scenario that skews real-world
        averages when a resolver dies.

Every query uses a unique name, so answers come from the upstream, not the
cache (--cached reuses one name to measure the cache instead).
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import math
import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from reqko.dns.acl import ClientACL
from reqko.dns.cache import DNSCache
from reqko.dns.pipeline import PipelineConfig
from reqko.dns.protocol import TYPE_A, DNSHeader, DNSPacket, DNSQuestion
from reqko.dns.ratelimit import RateLimiter
from reqko.dns.server import start_dns_servers
from reqko.filtering.engine import FilterEngine


def build_query(name: str, qid: int) -> bytes:
    return DNSPacket(
        header=DNSHeader(id=qid & 0xFFFF, qr=0, rd=1),
        questions=[DNSQuestion(name=name, qtype=TYPE_A)],
    ).to_wire()


def percentile(sorted_values: list[float], p: float) -> float:
    """Linear-interpolated percentile (numpy-style) of an ascending list."""
    if not sorted_values:
        return 0.0
    k = (len(sorted_values) - 1) * p / 100.0
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return sorted_values[int(k)]
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


async def one_query(
    host: str, port: int, name: str, qid: int, timeout: float
) -> float:
    """One UDP exchange; returns latency in ms (raises on failure)."""
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[bytes] = loop.create_future()

    class _Client(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: object) -> None:
            if not fut.done():
                fut.set_result(data)

        def error_received(self, exc: Exception) -> None:
            if not fut.done():
                fut.set_exception(exc)

    wire = build_query(name, qid)
    transport, _ = await loop.create_datagram_endpoint(
        _Client, remote_addr=(host, port)
    )
    try:
        started = time.perf_counter()
        transport.sendto(wire)
        await asyncio.wait_for(fut, timeout=timeout)
        return (time.perf_counter() - started) * 1000.0
    finally:
        transport.close()


async def run_bench(
    host: str, port: int, total: int, concurrency: int, timeout: float, cached: bool
) -> None:
    semaphore = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    answered = 0

    async def worker(i: int) -> None:
        nonlocal answered
        async with semaphore:
            name = "cached-bench.example" if cached else f"bench-{i}.example"
            try:
                ms = await one_query(host, port, name, i, timeout)
                latencies.append(ms)
                answered += 1
            except (asyncio.TimeoutError, OSError):
                pass

    started = time.perf_counter()
    await asyncio.gather(*(worker(i) for i in range(total)))
    wall = time.perf_counter() - started

    latencies.sort()
    print(f"queries={total} answered={answered} concurrency={concurrency} "
          f"wall={wall:.2f}s ({total / wall:.0f} qps)")
    if latencies:
        print(f"latency ms: p50={percentile(latencies, 50):.1f} "
              f"p95={percentile(latencies, 95):.1f} "
              f"p99={percentile(latencies, 99):.1f} "
              f"max={latencies[-1]:.1f} mean={sum(latencies) / len(latencies):.1f}")
    else:
        print("latency ms: no answers at all")


class _FakeUpstream(asyncio.DatagramProtocol):
    """Answers every A query with 203.0.113.1 after an artificial delay."""

    def __init__(self, delay_ms: int) -> None:
        self._delay_ms = delay_ms
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        task = asyncio.ensure_future(self._answer(data, addr))
        task.add_done_callback(lambda _t: None)

    async def _answer(self, data: bytes, addr: tuple[str, int]) -> None:
        if self._delay_ms:
            await asyncio.sleep(self._delay_ms / 1000.0)
        transport = self.transport
        if transport is None:
            return
        try:
            import struct as _struct

            (qid,) = _struct.unpack_from("!H", data, 0)
            # minimal valid NOERROR answer with one A record
            question_tail = data[12:]
            response = (
                _struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
                + question_tail
                + b"\xc0\x0c"
                + _struct.pack("!HHIH", 1, 1, 30, 4)
                + bytes((203, 0, 113, 1))
            )
            transport.sendto(response, addr)
        except Exception:
            pass


async def selfhosted(args: argparse.Namespace) -> None:
    """Starts a fake upstream + the real resolver (black-hole first upstream)."""
    loop = asyncio.get_running_loop()
    fake_transport, _ = await loop.create_datagram_endpoint(
        lambda: _FakeUpstream(args.fake_delay_ms), local_addr=("127.0.0.1", 0)
    )
    fake_port = fake_transport.get_extra_info("socket").getsockname()[1]

    # Black-hole upstream: bound, never answers, never refuses — the model of
    # a real dead resolver (a plain closed port would fast-fail on loopback).
    blackhole = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    blackhole.bind(("127.0.0.1", 0))
    blackhole_port = blackhole.getsockname()[1]

    cfg = PipelineConfig(
        acl=ClientACL([ipaddress.ip_network("127.0.0.0/8")]),
        rate_limiter=RateLimiter(rate_rps=100000.0, burst=200000.0),
        filter_engine=FilterEngine(),
        cache=DNSCache(),
        upstreams=[("127.0.0.1", blackhole_port), ("127.0.0.1", fake_port)],
        upstream_timeout=args.upstream_timeout,
        block_mode="NULL",
    )
    handles = await start_dns_servers(cfg, "127.0.0.1", 0)
    port = handles.port
    print(f"selfhosted resolver on 127.0.0.1:{port} "
          f"(upstream 1 = black-hole 127.0.0.1:{blackhole_port}, "
          f"upstream 2 = fake 127.0.0.1:{fake_port} "
          f"delay={args.fake_delay_ms}ms, upstream_timeout={args.upstream_timeout}s)")
    try:
        await run_bench("127.0.0.1", port, args.n, args.concurrency,
                        args.timeout, args.cached)
    finally:
        if handles.udp.transport is not None:
            handles.udp.transport.close()
        handles.tcp.close()
        fake_transport.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="ph-reqKO DNS latency benchmark")
    parser.add_argument("--host", default="127.0.0.1", help="server host (client mode)")
    parser.add_argument("--port", type=int, default=53, help="server DNS/UDP port")
    parser.add_argument("--n", type=int, default=200, help="number of queries")
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="per-query client timeout, seconds")
    parser.add_argument("--cached", action="store_true",
                        help="send the same name: measures the cache, not upstream")
    parser.add_argument("--selfhosted", action="store_true",
                        help="start the resolver in-process (dead first upstream)")
    parser.add_argument("--fake-delay-ms", type=int, default=5,
                        help="artificial answer delay of the fake upstream")
    parser.add_argument("--upstream-timeout", type=float, default=None,
                        help="override the resolver's upstream timeout (selfhosted)")
    args = parser.parse_args()

    if args.selfhosted:
        if args.upstream_timeout is None:
            from reqko.config import Config

            args.upstream_timeout = Config.from_env(
                {"REQKO_ADMIN_TOKEN": "bench"}
            ).upstream_timeout
        asyncio.run(selfhosted(args))
    else:
        asyncio.run(run_bench(args.host, args.port, args.n, args.concurrency,
                              args.timeout, args.cached))
    return 0


if __name__ == "__main__":
    sys.exit(main())
