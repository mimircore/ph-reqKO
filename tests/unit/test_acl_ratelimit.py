"""Unit tests for ClientACL (FR-13) and RateLimiter (FR-14)."""

import ipaddress

from reqko.dns.acl import ClientACL
from reqko.dns.ratelimit import RateLimiter


def test_acl_rfc1918_and_loopback() -> None:
    allowed = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("::1/128"),
    ]
    acl = ClientACL(allowed)

    # Allowed LAN & loopback IPs
    assert acl.is_allowed("127.0.0.1") is True
    assert acl.is_allowed("192.168.1.100") is True
    assert acl.is_allowed("10.20.30.40") is True
    assert acl.is_allowed("::1") is True

    # Disallowed WAN IPs
    assert acl.is_allowed("8.8.8.8") is False
    assert acl.is_allowed("1.1.1.1") is False
    assert acl.is_allowed("2001:db8::1") is False

    # Invalid IPs
    assert acl.is_allowed("not-an-ip") is False
    assert acl.is_allowed("") is False


def test_rate_limiter_token_bucket() -> None:
    current_time = 1000.0

    def mock_clock() -> float:
        return current_time

    # Rate 5 rps, burst 5
    limiter = RateLimiter(rate_rps=5.0, burst=5.0, clock=mock_clock)

    ip = "192.168.1.50"

    # Consume all 5 burst tokens
    for _ in range(5):
        assert limiter.is_allowed(ip) is True

    # 6th request should be rejected immediately
    assert limiter.is_allowed(ip) is False

    # Advance time by 0.2s (1 token regenerated: 5 rps * 0.2s = 1.0)
    current_time += 0.2
    assert limiter.is_allowed(ip) is True
    assert limiter.is_allowed(ip) is False

    # Advance time by 1.0s (5 tokens regenerated, capped at burst)
    current_time += 1.0
    for _ in range(5):
        assert limiter.is_allowed(ip) is True
    assert limiter.is_allowed(ip) is False


def test_rate_limiter_cleanup() -> None:
    current_time = 1000.0

    def mock_clock() -> float:
        return current_time

    limiter = RateLimiter(rate_rps=10.0, clock=mock_clock)
    limiter.is_allowed("10.0.0.1")
    limiter.is_allowed("10.0.0.2")

    # Advance time by 70s
    current_time += 70.0
    # Add new activity for 10.0.0.2
    limiter.is_allowed("10.0.0.2")

    # Cleanup with 60s idle threshold -> 10.0.0.1 removed, 10.0.0.2 kept
    removed = limiter.cleanup(max_idle_seconds=60.0)
    assert removed == 1
    assert "10.0.0.1" not in limiter._buckets
    assert "10.0.0.2" in limiter._buckets
