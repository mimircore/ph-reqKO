"""End-to-end integration tests through the real UDP/TCP DNS servers (FR-01..FR-14).

The resolver runs in-process on ephemeral ports; upstreams are the in-process
FakeUpstreamServer; the client side is dnspython. No internet access needed.
"""

from __future__ import annotations

import asyncio
import ipaddress
import struct

import dns.message
import dns.rcode

from integration.fake_upstream import FakeUpstreamConfig, FakeUpstreamServer
from reqko.dns.acl import ClientACL
from reqko.dns.cache import DNSCache
from reqko.dns.pipeline import PipelineConfig, QueryEvent
from reqko.dns.protocol import DNSHeader
from reqko.dns.ratelimit import RateLimiter
from reqko.dns.server import run_dns_servers
from reqko.filtering.engine import FilterEngine, FilterSnapshot

# ── helpers ────────────────────────────────────────────────────────────────────


async def _start_resolver(
    fake: FakeUpstreamServer,
    *,
    allowed_networks: list[str] | None = None,
    rate_limiter: RateLimiter | None = None,
    filter_engine: FilterEngine | None = None,
    cache: DNSCache | None = None,
    block_mode: str = "NULL",
    tcp_max_connections: int = 100,
    tcp_idle_timeout: float = 5.0,
    upstream_timeout: float = 2.0,
) -> tuple[PipelineConfig, int, asyncio.DatagramTransport, asyncio.Server]:
    acl = ClientACL(
        [
            ipaddress.ip_network(net)
            for net in (allowed_networks if allowed_networks is not None else ["127.0.0.1/32"])
        ]
    )
    cfg = PipelineConfig(
        acl=acl,
        rate_limiter=rate_limiter if rate_limiter is not None else RateLimiter(rate_rps=10000.0, burst=20000.0),
        filter_engine=filter_engine if filter_engine is not None else FilterEngine(),
        cache=cache if cache is not None else DNSCache(),
        upstreams=[fake.address],
        upstream_timeout=upstream_timeout,
        block_mode=block_mode,
    )
    udp_transport, tcp_server = await run_dns_servers(
        cfg,
        "127.0.0.1",
        0,
        tcp_max_connections=tcp_max_connections,
        tcp_idle_timeout=tcp_idle_timeout,
    )
    sock = udp_transport.get_extra_info("socket")
    assert sock is not None
    port = sock.getsockname()[1]
    return cfg, port, udp_transport, tcp_server


async def _stop_resolver(
    udp_transport: asyncio.DatagramTransport, tcp_server: asyncio.Server
) -> None:
    udp_transport.close()
    tcp_server.close()
    await tcp_server.wait_closed()


async def _udp_exchange(port: int, wire: bytes, timeout: float = 2.0) -> bytes:
    """Sends one UDP query and returns the raw response bytes."""
    loop = asyncio.get_running_loop()
    fut: asyncio.Future[bytes] = loop.create_future()

    class _Client(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: object) -> None:
            if not fut.done():
                fut.set_result(data)

        def error_received(self, exc: Exception) -> None:
            if not fut.done():
                fut.set_exception(exc)

    transport, _ = await loop.create_datagram_endpoint(
        _Client, remote_addr=("127.0.0.1", port)
    )
    try:
        transport.sendto(wire)
        return await asyncio.wait_for(fut, timeout)
    finally:
        transport.close()


async def _udp_query(port: int, name: str, qtype: str = "A") -> dns.message.Message:
    query = dns.message.make_query(name, qtype)
    raw = await _udp_exchange(port, query.to_wire())
    return dns.message.from_wire(raw)


async def _tcp_read_response(
    reader: asyncio.StreamReader, timeout: float = 3.0
) -> bytes:
    len_data = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
    (n,) = struct.unpack("!H", len_data)
    return await asyncio.wait_for(reader.readexactly(n), timeout=timeout)


async def _tcp_query(port: int, name: str, qtype: str = "A") -> dns.message.Message:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        query = dns.message.make_query(name, qtype)
        wire = query.to_wire()
        writer.write(struct.pack("!H", len(wire)) + wire)
        await writer.drain()
        raw = await _tcp_read_response(reader)
        return dns.message.from_wire(raw)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


def _snapshot(exact: frozenset[str], wildcard: frozenset[str]) -> FilterSnapshot:
    return FilterSnapshot(
        exact_set=exact,
        wildcard_set=wildcard,
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
    )


# ── forwarding and caching through the real server ─────────────────────────────


async def test_udp_forward_then_cached_with_ttl_consistency() -> None:
    """FR-02/FR-03: first query forwarded, second cached; client TTL == cached TTL."""
    current_time = 5000.0

    def mock_clock() -> float:
        return current_time

    fake = FakeUpstreamServer(
        FakeUpstreamConfig(
            answers={"ttl.srv.com": [("ttl.srv.com.", 50, "A", "203.0.113.10")]}
        )
    )
    await fake.start()
    cache = DNSCache(clock=mock_clock, min_ttl=60, max_ttl=3600)
    _, port, udp_t, tcp_s = await _start_resolver(fake, cache=cache)
    try:
        resp1 = await _udp_query(port, "ttl.srv.com.")
        assert resp1.rcode() == dns.rcode.NOERROR
        assert resp1.answer[0].to_text() == "ttl.srv.com. 60 IN A 203.0.113.10"
        assert len(fake.queries) == 1

        # Advance the mock clock: cache hit with a decreased TTL, no new upstream hit
        current_time += 10.0
        resp2 = await _udp_query(port, "ttl.srv.com.")
        assert resp2.rcode() == dns.rcode.NOERROR
        assert resp2.answer[0].to_text() == "ttl.srv.com. 50 IN A 203.0.113.10"
        assert len(fake.queries) == 1  # still only the first query reached upstream
    finally:
        await _stop_resolver(udp_t, tcp_s)
        await fake.stop()


async def test_blocked_domain_returns_null_ip() -> None:
    """FR-04/FR-08: a blocklisted name is answered with 0.0.0.0, upstream not queried."""
    fake = FakeUpstreamServer(FakeUpstreamConfig())
    await fake.start()
    engine = FilterEngine(_snapshot(frozenset({"ads.srv.com"}), frozenset()))
    _, port, udp_t, tcp_s = await _start_resolver(fake, filter_engine=engine)
    try:
        resp = await _udp_query(port, "ads.srv.com.")
        assert resp.rcode() == dns.rcode.NOERROR
        assert resp.answer[0].to_text() == "ads.srv.com. 300 IN A 0.0.0.0"
        assert len(fake.queries) == 0  # never forwarded
    finally:
        await _stop_resolver(udp_t, tcp_s)
        await fake.stop()


async def test_wildcard_rule_blocks_subdomain() -> None:
    """FR-07: ||wild.srv.com^ blocks the domain and its subdomains, not others."""
    fake = FakeUpstreamServer(
        FakeUpstreamConfig(answers={"ok.srv.com": [("ok.srv.com.", 300, "A", "1.2.3.4")]})
    )
    await fake.start()
    engine = FilterEngine(_snapshot(frozenset(), frozenset({"wild.srv.com"})))
    _, port, udp_t, tcp_s = await _start_resolver(fake, filter_engine=engine)
    try:
        blocked = await _udp_query(port, "a.b.wild.srv.com.")
        assert blocked.answer[0].to_text() == "a.b.wild.srv.com. 300 IN A 0.0.0.0"

        clean = await _udp_query(port, "ok.srv.com.")
        assert clean.answer[0].to_text() == "ok.srv.com. 300 IN A 1.2.3.4"

        # "notwild.srv.com" must NOT match the ||wild.srv.com^ rule: it is
        # forwarded (the fake answers NXDOMAIN for unknown names).
        not_wildcard = await _udp_query(port, "notwild.srv.com.")
        assert not_wildcard.rcode() == dns.rcode.NXDOMAIN
        assert ("udp", "notwild.srv.com") in fake.queries
    finally:
        await _stop_resolver(udp_t, tcp_s)
        await fake.stop()


async def test_block_mode_nxdomain_and_nodata() -> None:
    """FR-08: NXDOMAIN and NODATA block modes produce the right responses."""
    fake = FakeUpstreamServer(FakeUpstreamConfig())
    await fake.start()
    engine = FilterEngine(_snapshot(frozenset({"nx.srv.com", "nd.srv.com"}), frozenset()))
    try:
        for block_mode, expected_rcode, has_answer in (
            ("NXDOMAIN", dns.rcode.NXDOMAIN, False),
            ("NODATA", dns.rcode.NOERROR, False),
        ):
            _, port, udp_t, tcp_s = await _start_resolver(
                fake, filter_engine=engine, block_mode=block_mode
            )
            try:
                resp = await _udp_query(port, "nx.srv.com.")
                assert resp.rcode() == expected_rcode
                assert len(resp.answer) == (1 if has_answer else 0)
            finally:
                await _stop_resolver(udp_t, tcp_s)
    finally:
        await fake.stop()


# ── FR-04 / FR-09 through the real server ──────────────────────────────────────


async def test_fr04_rule_added_after_caching_blocks_via_server() -> None:
    """FR-04: a rule added after caching blocks the cached name immediately."""
    fake = FakeUpstreamServer(
        FakeUpstreamConfig(answers={"portal4.com": [("portal4.com.", 300, "A", "10.1.1.5")]})
    )
    await fake.start()
    engine = FilterEngine()
    _, port, udp_t, tcp_s = await _start_resolver(fake, filter_engine=engine)
    try:
        resp1 = await _udp_query(port, "portal4.com.")
        assert resp1.answer[0][0].to_text() == "10.1.1.5"
        assert len(fake.queries) == 1

        engine.update_snapshot(_snapshot(frozenset({"portal4.com"}), frozenset()))

        resp2 = await _udp_query(port, "portal4.com.")
        assert resp2.answer[0][0].to_text() == "0.0.0.0"
        assert len(fake.queries) == 1  # served from cache, not re-forwarded
    finally:
        await _stop_resolver(udp_t, tcp_s)
        await fake.stop()


async def test_fr09_cname_block_fresh_and_from_cache() -> None:
    """FR-09: blocked CNAME target blocks a fresh answer AND a cached one."""
    fake = FakeUpstreamServer(
        FakeUpstreamConfig(
            answers={
                "fresh9.com": [
                    ("fresh9.com.", 300, "CNAME", "cdn.tracker9.com."),
                    ("cdn.tracker9.com.", 300, "A", "1.2.3.4"),
                ],
                "alias9.com": [
                    ("alias9.com.", 300, "CNAME", "cdn.alias9.net."),
                    ("cdn.alias9.net.", 300, "A", "5.6.7.8"),
                ],
            }
        )
    )
    await fake.start()
    engine = FilterEngine(_snapshot(frozenset(), frozenset({"tracker9.com"})))
    _, port, udp_t, tcp_s = await _start_resolver(fake, filter_engine=engine)
    try:
        # Fresh answer: CNAME target blocked at upstream-response stage
        resp1 = await _udp_query(port, "fresh9.com.")
        assert resp1.answer[0][0].to_text() == "0.0.0.0"

        # Cache first, then add a rule for the cached CNAME target
        resp2 = await _udp_query(port, "alias9.com.")
        assert resp2.answer[-1][0].to_text() == "5.6.7.8"

        engine.update_snapshot(_snapshot(frozenset(), frozenset({"alias9.net"})))

        resp3 = await _udp_query(port, "alias9.com.")
        assert resp3.answer[0][0].to_text() == "0.0.0.0"
    finally:
        await _stop_resolver(udp_t, tcp_s)
        await fake.stop()


# ── refusal paths through the real server ──────────────────────────────────────


async def test_any_query_refused_via_server() -> None:
    """FR-13: QTYPE=ANY is REFUSED through the real UDP server."""
    fake = FakeUpstreamServer(FakeUpstreamConfig())
    await fake.start()
    _, port, udp_t, tcp_s = await _start_resolver(fake)
    try:
        resp = await _udp_query(port, "any.srv.com.", qtype="ANY")
        assert resp.rcode() == dns.rcode.REFUSED
    finally:
        await _stop_resolver(udp_t, tcp_s)
        await fake.stop()


async def test_malformed_packet_gets_formerr_via_server() -> None:
    """NFR-10: a truncated packet gets FORMERR keeping the request ID."""
    fake = FakeUpstreamServer(FakeUpstreamConfig())
    await fake.start()
    _, port, udp_t, tcp_s = await _start_resolver(fake)
    try:
        raw = await _udp_exchange(port, b"\xab\xcd\x00\x00")
        header, _ = DNSHeader.from_wire(raw)
        assert header.id == 0xABCD
        assert header.rcode == 1  # FORMERR
    finally:
        await _stop_resolver(udp_t, tcp_s)
        await fake.stop()


async def test_acl_refuses_disallowed_client_via_server() -> None:
    """FR-13: queries from a client outside REQKO_ALLOWED_NETWORKS get REFUSED."""
    fake = FakeUpstreamServer(FakeUpstreamConfig())
    await fake.start()
    _, port, udp_t, tcp_s = await _start_resolver(
        fake, allowed_networks=["10.0.0.0/8"]
    )
    try:
        raw = await _udp_exchange(port, dns.message.make_query("acl.srv.com.", "A").to_wire())
        header, _ = DNSHeader.from_wire(raw)
        assert header.rcode == 5  # REFUSED
        assert len(fake.queries) == 0
    finally:
        await _stop_resolver(udp_t, tcp_s)
        await fake.stop()


async def test_rate_limit_via_server() -> None:
    """FR-14: burst exhaustion through the real UDP server leads to REFUSED."""
    fake = FakeUpstreamServer(
        FakeUpstreamConfig(answers={"rl.srv.com": [("rl.srv.com.", 300, "A", "9.9.9.9")]})
    )
    await fake.start()
    rl = RateLimiter(rate_rps=1.0, burst=2.0)
    _, port, udp_t, tcp_s = await _start_resolver(fake, rate_limiter=rl)
    try:
        rcodes = []
        for _ in range(6):
            resp = await _udp_query(port, "rl.srv.com.")
            rcodes.append(resp.rcode())
        assert rcodes.count(dns.rcode.NOERROR) >= 2  # burst tokens were available
        assert rcodes.count(dns.rcode.REFUSED) >= 1  # excess requests refused
    finally:
        await _stop_resolver(udp_t, tcp_s)
        await fake.stop()


# ── TCP behaviour ──────────────────────────────────────────────────────────────


async def test_tcp_query_forwarded_via_server() -> None:
    """FR-01: TCP queries are answered through the real TCP server."""
    fake = FakeUpstreamServer(
        FakeUpstreamConfig(answers={"tcp.srv.com": [("tcp.srv.com.", 300, "A", "10.0.0.77")]})
    )
    await fake.start()
    _, port, udp_t, tcp_s = await _start_resolver(fake)
    try:
        resp = await _tcp_query(port, "tcp.srv.com.")
        assert resp.rcode() == dns.rcode.NOERROR
        assert resp.answer[0][0].to_text() == "10.0.0.77"
        assert ("udp", "tcp.srv.com") in fake.queries  # upstream used UDP
    finally:
        await _stop_resolver(udp_t, tcp_s)
        await fake.stop()


async def test_tcp_idle_timeout_closes_connection() -> None:
    """An idle TCP client is disconnected after REQKO_TCP_IDLE_TIMEOUT."""
    fake = FakeUpstreamServer(FakeUpstreamConfig())
    await fake.start()
    _, port, udp_t, tcp_s = await _start_resolver(fake, tcp_idle_timeout=0.3)
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            await asyncio.sleep(0.7)
            data = await asyncio.wait_for(reader.read(2), timeout=2.0)
            assert data == b""  # EOF: the server closed the idle connection
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    finally:
        await _stop_resolver(udp_t, tcp_s)
        await fake.stop()


async def test_tcp_max_connections_limit() -> None:
    """REQKO_MAX_TCP_CONNECTIONS=1: the second connection is served only after the first finishes."""
    fake = FakeUpstreamServer(
        FakeUpstreamConfig(
            answers={
                "slow.srv.com": [("slow.srv.com.", 300, "A", "10.0.0.1")],
                "fast.srv.com": [("fast.srv.com.", 300, "A", "10.0.0.2")],
            },
            udp_delay={"slow.srv.com": 1.0},
        )
    )
    await fake.start()
    _, port, udp_t, tcp_s = await _start_resolver(
        fake, tcp_max_connections=1, upstream_timeout=3.0
    )
    writer_a: asyncio.StreamWriter | None = None
    writer_b: asyncio.StreamWriter | None = None
    try:
        # Connection A holds the only slot while its upstream answer is delayed
        _reader_a, writer_a = await asyncio.open_connection("127.0.0.1", port)
        q_slow = dns.message.make_query("slow.srv.com.", "A").to_wire()
        writer_a.write(struct.pack("!H", len(q_slow)) + q_slow)
        await writer_a.drain()

        # Connection B connects but must not be answered while A holds the slot
        reader_b, writer_b = await asyncio.open_connection("127.0.0.1", port)
        q_fast = dns.message.make_query("fast.srv.com.", "A").to_wire()
        writer_b.write(struct.pack("!H", len(q_fast)) + q_fast)
        await writer_b.drain()

        got_early = True
        try:
            await asyncio.wait_for(reader_b.readexactly(2), timeout=0.4)
        except asyncio.TimeoutError:
            got_early = False
        assert got_early is False

        # Closing A releases the only connection slot; B is then served
        writer_a.close()
        await writer_a.wait_closed()
        resp_b = dns.message.from_wire(await _tcp_read_response(reader_b, timeout=3.0))
        assert resp_b.answer[0][0].to_text() == "10.0.0.2"

        # Both queries did reach the upstream (A over its delayed UDP exchange)
        assert ("udp", "slow.srv.com") in fake.queries
        assert ("udp", "fast.srv.com") in fake.queries
    finally:
        if writer_a is not None:
            writer_a.close()
        if writer_b is not None:
            writer_b.close()
        await _stop_resolver(udp_t, tcp_s)
        await fake.stop()


# ── EDNS through the real server ───────────────────────────────────────────────


async def test_edns_opt_presence_matches_client() -> None:
    """RFC 6891: an OPT in the response iff the client sent one (fresh and cached)."""
    fake = FakeUpstreamServer(
        FakeUpstreamConfig(answers={"edns.srv.com": [("edns.srv.com.", 300, "A", "10.0.0.9")]})
    )
    await fake.start()
    _, port, udp_t, tcp_s = await _start_resolver(fake)
    try:
        # EDNS client (fresh + cached response)
        q_edns = dns.message.make_query("edns.srv.com.", "A", use_edns=0, payload=4096)
        raw1 = await _udp_exchange(port, q_edns.to_wire())
        raw2 = await _udp_exchange(port, q_edns.to_wire())
        resp1 = dns.message.from_wire(raw1)
        resp2 = dns.message.from_wire(raw2)
        assert resp1.edns == 0
        assert resp1.payload == 1232  # our EDNS_PAYLOAD_SIZE, not the client's 4096
        assert resp2.edns == 0
        assert resp2.payload == 1232

        # Non-EDNS client (fresh + cached response)
        q_plain = dns.message.make_query("edns.srv.com.", "A")
        raw3 = await _udp_exchange(port, q_plain.to_wire())
        raw4 = await _udp_exchange(port, q_plain.to_wire())
        resp3 = dns.message.from_wire(raw3)
        resp4 = dns.message.from_wire(raw4)
        assert resp3.edns == -1
        assert resp4.edns == -1
    finally:
        await _stop_resolver(udp_t, tcp_s)
        await fake.stop()


# ── log queue through the real server ─────────────────────────────────────────


async def test_log_queue_receives_statuses_via_server() -> None:
    """The pipeline dispatches FORWARDED / CACHED / BLOCKED_* events to the queue."""
    fake = FakeUpstreamServer(
        FakeUpstreamConfig(
            answers={"logq.srv.com": [("logq.srv.com.", 300, "A", "10.0.0.42")]},
        )
    )
    await fake.start()
    engine = FilterEngine(_snapshot(frozenset({"spam.srv.com"}), frozenset()))

    log_queue: asyncio.Queue[QueryEvent] = asyncio.Queue()
    cfg = PipelineConfig(
        acl=ClientACL([ipaddress.ip_network("127.0.0.1/32")]),
        rate_limiter=RateLimiter(rate_rps=10000.0, burst=20000.0),
        filter_engine=engine,
        cache=DNSCache(),
        upstreams=[fake.address],
        upstream_timeout=2.0,
        block_mode="NULL",
        log_queue=log_queue,
    )
    udp_transport, tcp_server = await run_dns_servers(cfg, "127.0.0.1", 0)
    sock = udp_transport.get_extra_info("socket")
    assert sock is not None
    port = sock.getsockname()[1]
    try:
        await _udp_query(port, "logq.srv.com.")  # FORWARDED
        await _udp_query(port, "logq.srv.com.")  # CACHED
        await _udp_query(port, "spam.srv.com.")  # BLOCKED_BLACKLIST

        statuses = [log_queue.get_nowait().status for _ in range(3)]
        assert statuses == ["FORWARDED", "CACHED", "BLOCKED_BLACKLIST"]
    finally:
        await _stop_resolver(udp_transport, tcp_server)
        await fake.stop()
