"""In-memory DNS filtering engine using frozenset and Label Walk.

Implements FR-04, FR-05, FR-06, FR-07, FR-09, FR-10.
Supports atomic snapshot swapping and lock-free concurrency.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple

from reqko.filtering.parser import ParsedFilterRules


class MatchResult(NamedTuple):
    is_blocked: bool
    status: str  # "ALLOWED", "BLOCKED_BLACKLIST", "BLOCKED_CNAME", or "CLEAN"
    matched_rule: str | None


class FilterSnapshot:
    """Immutable snapshot of in-memory filter rules."""

    __slots__ = (
        "allow_exact_set",
        "allow_wildcard_set",
        "exact_set",
        "rules_count",
        "version",
        "wildcard_set",
    )

    def __init__(
        self,
        exact_set: frozenset[str],
        wildcard_set: frozenset[str],
        allow_exact_set: frozenset[str],
        allow_wildcard_set: frozenset[str],
        version: int = 1,
        rules_count: int = 0,
    ) -> None:
        self.exact_set: frozenset[str] = exact_set
        self.wildcard_set: frozenset[str] = wildcard_set
        self.allow_exact_set: frozenset[str] = allow_exact_set
        self.allow_wildcard_set: frozenset[str] = allow_wildcard_set
        self.version: int = version
        self.rules_count: int = (
            rules_count
            if rules_count > 0
            else (
                len(exact_set)
                + len(wildcard_set)
                + len(allow_exact_set)
                + len(allow_wildcard_set)
            )
        )

    @classmethod
    def from_parsed(cls, parsed: ParsedFilterRules, version: int = 1) -> FilterSnapshot:
        return cls(
            exact_set=frozenset(parsed.exact_blocks),
            wildcard_set=frozenset(parsed.wildcard_blocks),
            allow_exact_set=frozenset(parsed.exact_allows),
            allow_wildcard_set=frozenset(parsed.wildcard_allows),
            version=version,
            rules_count=parsed.total_count,
        )


@dataclass
class FilterEngine:
    """Thread-safe and async-safe filtering engine with atomic snapshot swap."""

    _snapshot: FilterSnapshot

    def __init__(self, snapshot: FilterSnapshot | None = None) -> None:
        if snapshot is None:
            self._snapshot = FilterSnapshot(
                exact_set=frozenset(),
                wildcard_set=frozenset(),
                allow_exact_set=frozenset(),
                allow_wildcard_set=frozenset(),
                version=0,
                rules_count=0,
            )
        else:
            self._snapshot = snapshot

    @property
    def snapshot(self) -> FilterSnapshot:
        return self._snapshot

    def update_snapshot(self, new_snapshot: FilterSnapshot) -> None:
        """Atomic reference swap (FR-10)."""
        self._snapshot = new_snapshot

    def is_allowlisted(self, domain: str) -> tuple[bool, str | None]:
        """Checks if a domain matches allowlist exact or wildcard rules (FR-06)."""
        snap = self._snapshot
        norm_domain = domain.strip(".").lower()

        # 1. Exact allow
        if norm_domain in snap.allow_exact_set:
            return True, norm_domain

        # 2. Wildcard allow via Label Walk
        labels = norm_domain.split(".")
        for i in range(len(labels)):
            suffix = ".".join(labels[i:])
            if suffix in snap.allow_wildcard_set:
                return True, f"@@||{suffix}^"

        return False, None

    def match(self, domain: str, is_cname: bool = False) -> MatchResult:
        """Evaluates domain against the current filter snapshot.

        Checks:
        1. Allowlist exact & wildcard -> returns ALLOWED
        2. Blocklist exact -> returns BLOCKED_BLACKLIST / BLOCKED_CNAME
        3. Blocklist wildcard via Label Walk -> returns BLOCKED_BLACKLIST / BLOCKED_CNAME
        4. If clean -> returns CLEAN
        """
        snap = self._snapshot
        norm_domain = domain.strip(".").lower()

        # Step 1: Whitelist check (FR-06)
        is_allowed, matched_allow = self.is_allowlisted(norm_domain)
        if is_allowed:
            return MatchResult(is_blocked=False, status="ALLOWED", matched_rule=matched_allow)

        # Step 2: Blocklist exact check (FR-05)
        if norm_domain in snap.exact_set:
            status = "BLOCKED_CNAME" if is_cname else "BLOCKED_BLACKLIST"
            return MatchResult(is_blocked=True, status=status, matched_rule=norm_domain)

        # Step 3: Blocklist wildcard check via Label Walk (FR-07)
        labels = norm_domain.split(".")
        for i in range(len(labels)):
            suffix = ".".join(labels[i:])
            if suffix in snap.wildcard_set:
                status = "BLOCKED_CNAME" if is_cname else "BLOCKED_BLACKLIST"
                return MatchResult(
                    is_blocked=True, status=status, matched_rule=f"||{suffix}^"
                )

        return MatchResult(is_blocked=False, status="CLEAN", matched_rule=None)
