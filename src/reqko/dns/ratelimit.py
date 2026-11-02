"""Per-client Token Bucket rate limiter (FR-14).

Protects against DNS amplification, reflection, and client flooding.
Supports injectable clock and periodic idle client pruning.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class _ClientBucket:
    tokens: float
    last_updated: float


class RateLimiter:
    """Token bucket rate limiter keyed by client IP."""

    def __init__(
        self,
        rate_rps: float,
        burst: float | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.rate = float(rate_rps)
        self.burst = float(burst if burst is not None else rate_rps)
        self._clock = clock
        self._buckets: dict[str, _ClientBucket] = {}

    def is_allowed(self, client_ip: str) -> bool:
        """Checks if a request from client_ip is permitted under rate limits."""
        if self.rate <= 0:
            return True  # Rate limiting disabled

        now = self._clock()
        bucket = self._buckets.get(client_ip)

        if bucket is None:
            if self.burst >= 1.0:
                self._buckets[client_ip] = _ClientBucket(
                    tokens=self.burst - 1.0, last_updated=now
                )
                return True
            return False

        # Refill tokens based on elapsed time
        elapsed = max(0.0, now - bucket.last_updated)
        bucket.tokens = min(self.burst, bucket.tokens + elapsed * self.rate)
        bucket.last_updated = now

        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            return True

        return False

    def cleanup(self, max_idle_seconds: float = 60.0) -> int:
        """Removes inactive client buckets to prevent memory leak."""
        now = self._clock()
        keys_to_delete = [
            ip
            for ip, b in self._buckets.items()
            if now - b.last_updated > max_idle_seconds
        ]
        for ip in keys_to_delete:
            del self._buckets[ip]
        return len(keys_to_delete)
