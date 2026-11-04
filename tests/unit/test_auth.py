"""Unit tests for token hashing, scopes, and the auth failure limiter (FR-17)."""

from reqko.api.auth import AuthFailureLimiter, TokenStore, constant_time_equals, hash_token


def test_hash_token_is_sha256_hex() -> None:
    digest = hash_token("secret-token")
    assert len(digest) == 64
    int(digest, 16)  # valid hex
    assert hash_token("secret-token") == digest
    assert hash_token("other-token") != digest


def test_constant_time_equals() -> None:
    assert constant_time_equals("abc", "abc") is True
    assert constant_time_equals("abc", "abd") is False
    assert constant_time_equals("", "") is True


def test_token_store_scopes() -> None:
    admin = hash_token("admin-token")
    read = hash_token("read-token")
    store = TokenStore(admin, read)

    assert store.scope_for("admin-token") == "admin"
    assert store.scope_for("read-token") == "read"
    assert store.scope_for("wrong-token") is None
    assert store.scope_for("") is None
    assert store.scope_for(None) is None

    # A read token must never be mistaken for the admin scope
    admin_only = TokenStore(admin, None)
    assert admin_only.scope_for("read-token") is None


def test_auth_failure_limiter_blocks_after_limit() -> None:
    now = 1000.0
    clock = lambda: now  # noqa: E731 (test clock)

    limiter = AuthFailureLimiter(limit=3, window=60.0, clock=clock)
    ip = "203.0.113.9"

    assert limiter.is_blocked(ip) is False
    limiter.record_failure(ip)
    limiter.record_failure(ip)
    assert limiter.is_blocked(ip) is False
    assert limiter.failures_in_window(ip) == 2

    limiter.record_failure(ip)
    assert limiter.is_blocked(ip) is True
    assert limiter.failures_in_window(ip) == 3


def test_auth_failure_limiter_window_expiry() -> None:
    now = 1000.0
    clock = lambda: now  # noqa: E731 (test clock)

    limiter = AuthFailureLimiter(limit=2, window=30.0, clock=clock)
    ip = "198.51.100.4"

    limiter.record_failure(ip)
    limiter.record_failure(ip)
    assert limiter.is_blocked(ip) is True

    now += 31.0  # failures leave the window
    assert limiter.is_blocked(ip) is False
    assert limiter.failures_in_window(ip) == 0


def test_auth_failure_limiter_is_per_ip() -> None:
    limiter = AuthFailureLimiter(limit=2, window=60.0, clock=lambda: 0.0)
    limiter.record_failure("10.0.0.1")
    limiter.record_failure("10.0.0.1")
    assert limiter.is_blocked("10.0.0.1") is True
    assert limiter.is_blocked("10.0.0.2") is False
