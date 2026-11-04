"""Integration tests for the async upstream client (FR-02) against in-process fake servers.

No real network access: the fake upstream UDP+TCP servers live in this test process.
"""

from __future__ import annotations

import struct

import dns.message
import dns.rrset
import pytest

from integration.fake_upstream import FakeUpstreamConfig, FakeUpstreamServer
from reqko.dns.protocol import parse_wire
from reqko.dns.upstream import UpstreamError, query_upstream


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
        resp, used = await query_upstream(
            pkt, [dead.address, alive.address], timeout=0.4
        )

        assert resp.header.rcode == 0
        assert used == f"127.0.0.1:{alive.udp_port}"
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
        resp, used = await query_upstream(pkt, [server.address], timeout=1.0)

        assert resp.header.tc == 0
        assert resp.header.rcode == 0
        assert used == f"127.0.0.1:{server.udp_port}"
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
        resp, used = await query_upstream(pkt, [bad.address, good.address], timeout=0.5)

        assert resp.header.rcode == 0
        assert used == f"127.0.0.1:{good.udp_port}"
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
