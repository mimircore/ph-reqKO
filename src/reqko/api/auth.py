"""Bearer token authentication for the REST API (FR-16, FR-17).

Tokens are never stored in plain text: only their SHA-256 hashes are kept,
and comparison uses hmac.compare_digest (timing-safe). Scopes: "admin"
(ALL methods) and "read" (GET only). /health is public.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from collections import defaultdict, deque
from collections.abc import Callable


def hash_token(token: str) -> str:
    """SHA-256 hex digest of a token - the only form ever persisted."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


class TokenStore:
    """Holds token hashes and resolves a presented token to its scope."""

    def __init__(
        self,
        admin_token_hash: str | None,
        read_token_hash: str | None = None,
    ) -> None:
        self._admin_hash = admin_token_hash
        self._read_hash = read_token_hash

    def scope_for(self, token: str | None) -> str | None:
        """Returns "admin", "read", or None when the token is unknown."""
        if not token:
            return None
        digest = hash_token(token)
        if self._admin_hash and constant_time_equals(digest, self._admin_hash):
            return "admin"
        if self._read_hash and constant_time_equals(digest, self._read_hash):
            return "read"
        return None


class AuthFailureLimiter:
    """Per-IP rate limit on failed authentication attempts.

    Keeps a sliding window of failure timestamps per client IP; once an IP
    accumulates ``limit`` failures within ``window`` seconds it is blocked
    until the oldest failure leaves the window.
    """

    def __init__(
        self,
        limit: int,
        window: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = limit
        self._window = window
        self._clock = clock
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, ip: str, now: float) -> None:
        bucket = self._failures[ip]
        while bucket and (now - bucket[0]) > self._window:
            bucket.popleft()
        if not bucket:
            del self._failures[ip]

    def is_blocked(self, ip: str) -> bool:
        now = self._clock()
        self._prune(ip, now)
        return len(self._failures[ip]) >= self._limit

    def record_failure(self, ip: str) -> None:
        now = self._clock()
        self._failures[ip].append(now)
        self._prune(ip, now)

    def failures_in_window(self, ip: str) -> int:
        now = self._clock()
        self._prune(ip, now)
        return len(self._failures[ip])
