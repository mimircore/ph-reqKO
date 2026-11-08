"""Integration tests for the async upstream client (FR-02) against in-process fake servers.

No real network access: the fake upstream UDP+TCP servers live in this test process.
"""

from __future__ import annotations

import struct
import time

import dns.message
import dns.rrset
import pytest

from integration.fake_upstream import FakeUpstreamConfig, FakeUpstreamServer
from reqko.dns.protocol import parse_wire
from reqko.dns.upstream import (
    UpstreamError,
    UpstreamHealth,
    query_upstream,
)


def _a_query(name: str, qid: int = 4242) -> dns.message.Message:
    return dns.message.make_query(name, "A")


async def test_first_upstream_timeout_second_answers() -> None:
    """FR-02 fallback: a timing-out first upstream is skipped; the second answers."""
    dead = FakeUpstreamServer(FakeUpstreamConfig(silent=True))
    alive = FakeUpstreamServer(
        FakeUpstreamConfig(answers={"fallback.com": [("fallback.com.", 300, "A", "9.9.9.9")]})
    )
    await dead.start()
    await alive.start()
    try:
        pkt = parse_wire(_a_query("fallback.com.").to_wire())
        result = await query_upstream(pkt, [dead.address, alive.address], timeout=0.4)

        assert result.attempts == 2  # raced both, winner was the second
        assert result.response.header.rcode == 0
        assert result.upstream == f"127.0.0.1:{alive.udp_port}"
        assert ("udp", "fallback.com") in alive.queries
    finally:
        await dead.stop()
        await alive.stop()


async def test_tc1_over_udp_retries_over_tcp() -> None:
    """A TC=1 UDP answer forces a TCP retry to the same upstream."""
    server = FakeUpstreamServer(
        FakeUpstreamConfig(
            answers={"big.example.com": [("big.example.com.", 300, "A", "203.0.113.7")]},
            truncated={"big.example.com"},
        )
    )
    await server.start()
    try:
        pkt = parse_wire(_a_query("big.example.com.").to_wire())
        result = await query_upstream(pkt, [server.address], timeout=1.0)

        assert result.response.header.tc == 0
        assert result.response.header.rcode == 0
        assert result.upstream == f"127.0.0.1:{server.udp_port}"
        assert ("udp", "big.example.com") in server.queries
        assert ("tcp", "big.example.com") in server.queries
    finally:
        await server.stop()


async def test_wrong_id_response_is_rejected() -> None:
    """A response whose transaction ID does not match the request is discarded."""
    bad = FakeUpstreamServer(FakeUpstreamConfig())
    good = FakeUpstreamServer(
        FakeUpstreamConfig(answers={"idcheck.com": [("idcheck.com.", 300, "A", "1.1.1.1")]})
    )
    await bad.start()
    await good.start()
    try:
        query = _a_query("idcheck.com.")
        response = dns.message.make_response(query)
        response.answer.append(
            dns.rrset.from_text("idcheck.com.", 300, "IN", "A", "6.6.6.6")
        )
        wire = response.to_wire()
        wrong_id_wire = struct.pack("!H", (query.id + 1) & 0xFFFF) + wire[2:]
        bad.config.canned_wire["idcheck.com"] = wrong_id_wire

        pkt = parse_wire(query.to_wire())
        result = await query_upstream(pkt, [bad.address, good.address], timeout=0.5)

        assert result.response.header.rcode == 0
        assert result.upstream == f"127.0.0.1:{good.udp_port}"
    finally:
        await bad.stop()
        await good.stop()


async def test_wrong_question_response_is_rejected() -> None:
    """A response echoing a different question is discarded (cache-poisoning guard)."""
    bad = FakeUpstreamServer(FakeUpstreamConfig())
    await bad.start()
    try:
        query = _a_query("asked.com.")
        other = dns.message.make_query("other.com.", "A")
        forged = dns.message.make_response(other)
        bad.config.canned_wire["asked.com"] = forged.to_wire()

        pkt = parse_wire(query.to_wire())
        with pytest.raises(UpstreamError):
            await query_upstream(pkt, [bad.address], timeout=0.5)
    finally:
        await bad.stop()


async def test_all_upstreams_down_raises() -> None:
    """When no upstream answers, UpstreamError is raised (resolver returns SERVFAIL)."""
    dead1 = FakeUpstreamServer(FakeUpstreamConfig(silent=True))
    dead2 = FakeUpstreamServer(FakeUpstreamConfig(silent=True))
    await dead1.start()
    await dead2.start()
    try:
        pkt = parse_wire(_a_query("nothing.com.").to_wire())
        with pytest.raises(UpstreamError):
            await query_upstream(pkt, [dead1.address, dead2.address], timeout=0.3)
    finally:
        await dead1.stop()
        await dead2.stop()


async def test_race_answers_from_second_while_first_black_holes() -> None:
    """perf-latency: upstreams are raced — the answer arrives from the healthy
    second upstream WITHIN the first one's timeout, not after it expires."""
    dead = FakeUpstreamServer(FakeUpstreamConfig(silent=True))
    alive = FakeUpstreamServer(
        FakeUpstreamConfig(answers={"race.com": [("race.com.", 300, "A", "7.7.7.7")]})
    )
    await dead.start()
    await alive.start()
    try:
        pkt = parse_wire(_a_query("race.com.").to_wire())
        started = time.monotonic()
        result = await query_upstream(pkt, [dead.address, alive.address], timeout=2.0)
        elapsed = time.monotonic() - started
        # Sequential fallback would have waited the full 2 s first
        assert elapsed < 1.0, f"race took {elapsed:.2f}s — sequential walk?"
        assert result.upstream == f"127.0.0.1:{alive.udp_port}"
        assert result.attempts == 2
    finally:
        await dead.stop()
        await alive.stop()


async def test_circuit_breaker_trips_and_skips_dead_upstream() -> None:
    """After `threshold` consecutive FAILURES (completed timeouts) an upstream
    is skipped for the cooldown. Race losers cancelled by a faster winner are
    NOT failures — a slow-but-working upstream must stay available."""
    now = [1000.0]
    health = UpstreamHealth(
        clock=lambda: now[0], threshold=2, cooldown_seconds=30.0
    )
    dead = FakeUpstreamServer(FakeUpstreamConfig(silent=True))
    alive = FakeUpstreamServer(
        FakeUpstreamConfig(answers={"br.com": [("br.com.", 300, "A", "7.7.7.8")]})
    )
    await dead.start()
    await alive.start()
    try:
        pkt = parse_wire(_a_query("br.com.").to_wire())

        # Two all-fail rounds on the dead upstream alone -> breaker trips
        with pytest.raises(UpstreamError):
            await query_upstream(pkt, [dead.address], timeout=0.2, health=health)
        assert health.is_healthy(dead.address)
        with pytest.raises(UpstreamError):
            await query_upstream(pkt, [dead.address], timeout=0.2, health=health)
        assert not health.is_healthy(dead.address)

        # With a healthy second upstream configured, the dead one is skipped
        result = await query_upstream(
            pkt, [dead.address, alive.address], timeout=0.4, health=health
        )
        assert result.upstream == f"127.0.0.1:{alive.udp_port}"
        assert result.attempts == 1  # only the healthy candidate raced

        # Cooldown expiry brings it back
        now[0] += 31.0
        assert health.is_healthy(dead.address)
    finally:
        await dead.stop()
        await alive.stop()


async def test_circuit_breaker_total_blackout_is_not_permanent() -> None:
    """When every upstream is marked unhealthy, all are retried anyway."""
    now = [2000.0]
    health = UpstreamHealth(
        clock=lambda: now[0], threshold=1, cooldown_seconds=3600.0
    )
    dead1 = FakeUpstreamServer(FakeUpstreamConfig(silent=True))
    dead2 = FakeUpstreamServer(FakeUpstreamConfig(silent=True))
    await dead1.start()
    await dead2.start()
    try:
        pkt = parse_wire(_a_query(" blackout.com.").to_wire())
        with pytest.raises(UpstreamError):
            await query_upstream(pkt, [dead1.address, dead2.address], timeout=0.2, health=health)
        # threshold=1: both are now blocked...
        assert not health.is_healthy(dead1.address)
        assert not health.is_healthy(dead2.address)
        # ...but the next query still races both (blackout escape hatch):
        # the error reports attempts=2, i.e. both candidates were tried.
        with pytest.raises(UpstreamError) as exc_info:
            await query_upstream(pkt, [dead1.address, dead2.address], timeout=0.2, health=health)
        assert exc_info.value.attempts == 2
    finally:
        await dead1.stop()
        await dead2.stop()
