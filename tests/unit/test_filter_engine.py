"""Unit tests for FilterEngine and FilterSnapshot (FR-04, FR-05, FR-06, FR-07, FR-09, FR-10)."""

from reqko.filtering.engine import FilterEngine, FilterSnapshot


def test_exact_block_does_not_block_subdomain() -> None:
    snap = FilterSnapshot(
        exact_set=frozenset({"tracker.com"}),
        wildcard_set=frozenset(),
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
    )
    engine = FilterEngine(snap)

    res_exact = engine.match("tracker.com")
    assert res_exact.is_blocked is True
    assert res_exact.status == "BLOCKED_BLACKLIST"
    assert res_exact.matched_rule == "tracker.com"

    # Subdomain must NOT be blocked by exact match (FR-05)
    res_sub = engine.match("sub.tracker.com")
    assert res_sub.is_blocked is False
    assert res_sub.status == "CLEAN"


def test_wildcard_block_blocks_domain_and_subdomains() -> None:
    snap = FilterSnapshot(
        exact_set=frozenset(),
        wildcard_set=frozenset({"adnetwork.com"}),
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
    )
    engine = FilterEngine(snap)

    # Base domain
    res_base = engine.match("adnetwork.com")
    assert res_base.is_blocked is True
    assert res_base.status == "BLOCKED_BLACKLIST"
    assert res_base.matched_rule == "||adnetwork.com^"

    # Deep subdomain
    res_sub = engine.match("deep.sub.adnetwork.com")
    assert res_sub.is_blocked is True
    assert res_sub.status == "BLOCKED_BLACKLIST"
    assert res_sub.matched_rule == "||adnetwork.com^"

    # Unrelated domain
    res_unrelated = engine.match("example.com")
    assert res_unrelated.is_blocked is False
    assert res_unrelated.status == "CLEAN"


def test_allowlist_precedence_over_blocklist() -> None:
    # tracker.com is blocked by wildcard, but exception.tracker.com is whitelisted (FR-06)
    snap = FilterSnapshot(
        exact_set=frozenset(),
        wildcard_set=frozenset({"tracker.com"}),
        allow_exact_set=frozenset({"exception.tracker.com"}),
        allow_wildcard_set=frozenset({"allowed-subtree.tracker.com"}),
    )
    engine = FilterEngine(snap)

    # General subdomain blocked
    assert engine.match("ads.tracker.com").is_blocked is True

    # Exact allowlist exception
    res_allowed_exact = engine.match("exception.tracker.com")
    assert res_allowed_exact.is_blocked is False
    assert res_allowed_exact.status == "ALLOWED"
    assert res_allowed_exact.matched_rule == "exception.tracker.com"

    # Wildcard allowlist exception
    res_allowed_wildcard = engine.match("sub.allowed-subtree.tracker.com")
    assert res_allowed_wildcard.is_blocked is False
    assert res_allowed_wildcard.status == "ALLOWED"
    assert res_allowed_wildcard.matched_rule == "@@||allowed-subtree.tracker.com^"


def test_cname_blocking_status() -> None:
    snap = FilterSnapshot(
        exact_set=frozenset({"cloaked-tracker.net"}),
        wildcard_set=frozenset(),
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
    )
    engine = FilterEngine(snap)

    res = engine.match("cloaked-tracker.net", is_cname=True)
    assert res.is_blocked is True
    assert res.status == "BLOCKED_CNAME"
    assert res.matched_rule == "cloaked-tracker.net"


def test_atomic_snapshot_swap() -> None:
    engine = FilterEngine()
    # Initially clean
    assert engine.match("badsite.com").is_blocked is False
    assert engine.snapshot.version == 0

    # Atomic swap to v1 with badsite blocked
    new_snap = FilterSnapshot(
        exact_set=frozenset({"badsite.com"}),
        wildcard_set=frozenset(),
        allow_exact_set=frozenset(),
        allow_wildcard_set=frozenset(),
        version=1,
    )
    engine.update_snapshot(new_snap)

    # Immediately blocked
    assert engine.match("badsite.com").is_blocked is True
    assert engine.snapshot.version == 1
