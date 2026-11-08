"""Tests for the adaptive ad-domain suggestion engine (query-log analysis)."""

from __future__ import annotations

import asyncio
import sqlite3
import time

import pytest

from reqko.filtering.engine import FilterEngine
from reqko.filtering.suggester import (
    LogRow,
    Suggestion,
    _is_protected,
    _iso,
    _parse_ts,
    analyze_rows,
    fetch_suggestions,
    has_keyword,
    keyword_reasons,
    registrable_base,
    rejected_domains,
    run_analysis_once,
    run_suggestion_scheduler,
    save_suggestions,
    set_suggestion_status,
)
from reqko.storage.migrations import init_database


def _rows(*events: tuple[float, str, str, str]) -> list[LogRow]:
    """events: (timestamp, client_ip, question_name, status)."""
    return [LogRow(timestamp=ts, client_ip=ip, question_name=qn, status=st)
            for ts, ip, qn, st in events]


def test_keyword_label_exact_match() -> None:
    assert has_keyword("ads.example.com") is True
    assert has_keyword("doubleclick.net") is True
    assert has_keyword("metrics.example.com") is True


def test_keyword_substring_does_not_match() -> None:
    # 'ads' must NOT match inside 'loads', 'uploads', 'gadsden'
    assert has_keyword("loads.example.com") is False
    assert has_keyword("uploads.example.com") is False
    assert has_keyword("gadsden.com") is False
    assert has_keyword("download.example.com") is False  # 'load' not 'ads'


def test_keyword_token_split_by_hyphen_and_digits() -> None:
    # label tokens split by '-' and digits
    assert has_keyword("ad-server.example.com") is True       # '-' -> [ad, server]
    assert has_keyword("ad2.example.com") is True              # digit -> [ad]
    assert has_keyword("sdk-events.example.com") is True       # '-' -> [events]
    assert has_keyword("rtb-west.example.com") is True         # '-' -> [rtb]
    # non-keyword tokens after split
    assert has_keyword("adversary.example.com") is False       # 'adversary' != 'ad'


def test_keyword_reasons_lists_tokens() -> None:
    reasons = keyword_reasons("ads.adserver.example.com")
    assert "keyword:ads" in reasons
    assert "keyword:adserver" in reasons
    assert len(reasons) == 2


def test_registrable_base_multi_part_suffixes() -> None:
    assert registrable_base("metrics.ads.yahoo.co.uk") == "yahoo.co.uk"
    assert registrable_base("x.y.com.au") == "y.com.au"
    assert registrable_base("a.b.c.co.jp") == "c.co.jp"
    assert registrable_base("simple.com") == "simple.com"
    assert registrable_base("deep.sub.simple.com") == "simple.com"


def test_protected_bases_never_suggested() -> None:
    """googleapis/facebook/gstatic bases are NEVER suggested even with
    matching keyword labels."""
    rows = _rows(
        (1000.0, "192.168.1.5", "metrics.googleapis.com", "FORWARDED"),
        (1001.0, "192.168.1.5", "metrics.googleapis.com", "FORWARDED"),
        (1002.0, "192.168.1.5", "graph.facebook.com", "FORWARDED"),
        (1003.0, "192.168.1.5", "graph.facebook.com", "FORWARDED"),
        (1004.0, "192.168.1.5", "firestore.googleapis.com", "FORWARDED"),
        (1005.0, "192.168.1.5", "firestore.googleapis.com", "FORWARDED"),
        (1006.0, "192.168.1.5", "connectivitycheck.gstatic.com", "FORWARDED"),
        (1007.0, "192.168.1.5", "connectivitycheck.gstatic.com", "FORWARDED"),
        (1008.0, "192.168.1.5", "ads.real-tracker.example", "FORWARDED"),
        (1009.0, "192.168.1.5", "ads.real-tracker.example", "FORWARDED"),
    )
    suggestions = analyze_rows(rows, blocked=frozenset(), allowlisted=frozenset(),
                               rejected=frozenset())
    domains = [s.domain for s in suggestions]
    assert "metrics.googleapis.com" not in domains
    assert "graph.facebook.com" not in domains
    assert "firestore.googleapis.com" not in domains
    assert "connectivitycheck.gstatic.com" not in domains
    assert "ads.real-tracker.example" in domains


def test_fallback_pattern_real_fixture() -> None:
    """Real sequence: d.applovin.com BLOCKED at t, d.applvn.com FORWARDED
    at t+2s -> suggested with reason 'fallback after blocked'."""
    rows = _rows(
        (1000.0, "10.0.0.5", "d.applovin.com", "BLOCKED_BLACKLIST"),
        (1002.0, "10.0.0.5", "d.applvn.com", "FORWARDED"),
    )
    suggestions = analyze_rows(rows, blocked=frozenset(), allowlisted=frozenset(),
                               rejected=frozenset(), min_hits=1)
    matches = [s for s in suggestions if s.domain == "d.applvn.com"]
    assert len(matches) == 1
    assert "fallback after blocked" in matches[0].reasons
    assert matches[0].score >= 3


def test_fallback_not_triggered_when_queried_alone_later() -> None:
    """Same domain queried alone minutes later by many clients is NOT enough."""
    rows = _rows(
        (1000.0, "10.0.0.5", "d.applovin.com", "BLOCKED_BLACKLIST"),
        (1002.0, "10.0.0.5", "d.applvn.com", "FORWARDED"),
        # minutes later, other clients, no blocked event nearby
        (1600.0, "10.0.0.9", "d.applvn.com", "FORWARDED"),
        (3200.0, "10.0.0.8", "d.applvn.com", "FORWARDED"),
    )
    suggestions = analyze_rows(rows, blocked=frozenset(), allowlisted=frozenset(),
                               rejected=frozenset(), min_hits=1)
    # Score 0 (no keyword, not all queries in fallback windows): NOT suggested
    matches = [s for s in suggestions if s.domain == "d.applvn.com"]
    assert matches == []


def test_sibling_burst_two_distinct_networks() -> None:
    rows = _rows(
        (1000.0, "10.0.0.5", "net1.one-ad.example", "BLOCKED_BLACKLIST"),
        (1000.5, "10.0.0.5", "net2.two-ad.example", "BLOCKED_BLACKLIST"),
        (1001.0, "10.0.0.5", "target.example.com", "FORWARDED"),
    )
    suggestions = analyze_rows(rows, blocked=frozenset(), allowlisted=frozenset(),
                               rejected=frozenset(), min_hits=1)
    matches = [s for s in suggestions if s.domain == "target.example.com"]
    assert len(matches) == 1
    assert "sibling burst" in matches[0].reasons


def test_min_hits_filters_singletons() -> None:
    rows = _rows(
        (1000.0, "10.0.0.5", "single.test", "FORWARDED"),
    )
    suggestions = analyze_rows(rows, blocked=frozenset(), allowlisted=frozenset(),
                               rejected=frozenset(), min_hits=2)
    assert all(s.domain != "single.test" for s in suggestions)


def test_already_blocked_and_allowlisted_never_suggested() -> None:
    rows = _rows(
        (1000.0, "10.0.0.5", "ads.test", "FORWARDED"),
        (1001.0, "10.0.0.5", "ads.test", "FORWARDED"),
        (1002.0, "10.0.0.5", "safe.test", "FORWARDED"),
        (1003.0, "10.0.0.5", "safe.test", "FORWARDED"),
    )
    blocked = frozenset({"ads.test"})
    allowlisted = frozenset({"safe.test"})
    suggestions = analyze_rows(rows, blocked=blocked, allowlisted=allowlisted,
                               rejected=frozenset())
    assert all(s.domain not in ("ads.test", "safe.test") for s in suggestions)


def test_suggestions_sorted_by_score_desc() -> None:
    rows = _rows(
        # score 4 (keyword + fallback)
        (1000.0, "10.0.0.5", "d.applovin.com", "BLOCKED_BLACKLIST"),
        (1001.0, "10.0.0.5", "ad2.applvn.com", "FORWARDED"),
        (1002.0, "10.0.0.5", "ad2.applvn.com", "FORWARDED"),
        # score 2 (keyword only)
        (1010.0, "10.0.0.5", "pixel.test", "FORWARDED"),
        (1011.0, "10.0.0.5", "pixel.test", "FORWARDED"),
    )
    suggestions = analyze_rows(rows, blocked=frozenset(), allowlisted=frozenset(),
                               rejected=frozenset(), min_hits=1)
    scores = [s.score for s in suggestions]
    assert scores == sorted(scores, reverse=True)
    assert suggestions[0].domain == "ad2.applvn.com"


# ── protected-base exception and timestamps ────────────────────────────────────


def test_is_protected_xiaomi_ad_host_exception() -> None:
    """xiaomi/miui bases are protected EXCEPT for keyword-labelled ad hosts."""
    assert _is_protected("ad.intl.xiaomi.com") is False
    assert _is_protected("sdk-events.miui.com") is False
    assert _is_protected("api.intl.xiaomi.com") is True
    # every other protected base is never exempted
    assert _is_protected("metrics.googleapis.com") is True


def test_parse_ts_iso_roundtrip() -> None:
    assert _parse_ts(_iso(1700000000.0)) == 1700000000.0


# ── persistence (domain_suggestions table) ─────────────────────────────────────


def test_suggestion_persistence_roundtrip() -> None:
    conn = init_database(":memory:")
    suggestions = [
        Suggestion(
            domain="ads-x.example", base="ads-x.example", score=5,
            reasons=["keyword:ads"], hits=3, first_seen=1000.0, last_seen=2000.0,
        )
    ]
    assert save_suggestions(conn, suggestions) == 1

    rows = fetch_suggestions(conn, "pending", 10)
    assert len(rows) == 1
    row = rows[0]
    assert row["domain"] == "ads-x.example"
    assert row["base"] == "ads-x.example"
    assert row["score"] == 5
    assert row["reasons"] == ["keyword:ads"]
    assert row["hits"] == 3
    assert row["first_seen"] == "1970-01-01 00:16:40"
    assert row["last_seen"] == "1970-01-01 00:33:20"
    assert row["auto"] is False

    # Re-analysis refreshes pending rows
    suggestions[0].score = 9
    save_suggestions(conn, suggestions)
    assert fetch_suggestions(conn, "pending", 10)[0]["score"] == 9

    # A decision is never reset by later saves
    assert set_suggestion_status(conn, "ads-x.example", "approved") is True
    suggestions[0].score = 1
    save_suggestions(conn, suggestions)
    assert fetch_suggestions(conn, "approved", 10)[0]["score"] == 9
    assert fetch_suggestions(conn, "pending", 10) == []

    # Unknown domain: no-op
    assert set_suggestion_status(conn, "ghost.example", "rejected") is False

    # Rejected domains are remembered for the analyzer
    assert set_suggestion_status(conn, "ads-x.example", "rejected") is True
    assert rejected_domains(conn) == frozenset({"ads-x.example"})


# ── scheduler ──────────────────────────────────────────────────────────────────


class _FakeRules:
    """Minimal RuleManager stand-in recording add_rule calls."""

    def __init__(self) -> None:
        self.added: list[tuple[str, str, str]] = []

    def add_rule(self, rule_type: str, domain: str, syntax: str = "exact") -> None:
        self.added.append((rule_type, domain, syntax))


def _seed_log(conn: sqlite3.Connection, name: str, count: int = 2) -> None:
    """Inserts `count` recent FORWARDED queries for one domain (min_hits=2)."""
    ts = _iso(time.time() - 60.0)
    with conn:
        for _ in range(count):
            conn.execute(
                "INSERT INTO query_log (timestamp, client_ip, question_name, "
                "question_type, status, latency_ms, response_code) "
                "VALUES (?, '10.0.0.1', ?, 'A', 'FORWARDED', 1.0, 0)",
                (ts, name),
            )


def _seed_fallback(conn: sqlite3.Connection, name: str) -> None:
    """Fallback fixture: blocked source at t, two queries of `name` at t+2s."""
    now = time.time()
    t0 = _iso(now - 60.0)
    t1 = _iso(now - 58.0)
    with conn:
        conn.execute(
            "INSERT INTO query_log (timestamp, client_ip, question_name, "
            "question_type, status, latency_ms, response_code) "
            "VALUES (?, '10.0.0.9', 'blocked-src.example', 'A', "
            "'BLOCKED_BLACKLIST', 0.0, 0)",
            (t0,),
        )
        for _ in range(2):
            conn.execute(
                "INSERT INTO query_log (timestamp, client_ip, question_name, "
                "question_type, status, latency_ms, response_code) "
                "VALUES (?, '10.0.0.9', ?, 'A', 'FORWARDED', 1.0, 0)",
                (t1, name),
            )


async def test_scheduler_disabled_at_zero_interval() -> None:
    conn = init_database(":memory:")
    stop = asyncio.Event()
    written = await run_suggestion_scheduler(
        conn, FilterEngine(), _FakeRules(),
        window_hours=24, min_hits=2, interval_minutes=0,
        auto_approve_score=None, stop_event=stop,
    )
    assert written == 0


async def test_scheduler_analyzes_then_stops_gracefully() -> None:
    conn = init_database(":memory:")
    _seed_log(conn, "sdk-events.example")  # keyword token 'events' -> score 2
    stop = asyncio.Event()
    task = asyncio.create_task(
        run_suggestion_scheduler(
            conn, FilterEngine(), _FakeRules(),
            window_hours=24, min_hits=2, interval_minutes=1,
            auto_approve_score=None, stop_event=stop,
        )
    )
    try:
        for _ in range(200):
            if fetch_suggestions(conn, "pending", 10):
                break
            await asyncio.sleep(0.01)
        rows = fetch_suggestions(conn, "pending", 10)
        assert [r["domain"] for r in rows] == ["sdk-events.example"]
    finally:
        stop.set()
        written = await asyncio.wait_for(task, timeout=5.0)
    assert written == 1


async def test_scheduler_survives_a_failing_iteration() -> None:
    """A broken DB iteration is logged and skipped, the scheduler keeps going."""
    conn = init_database(":memory:")
    conn.execute("DROP TABLE query_log")
    conn.commit()
    stop = asyncio.Event()
    task = asyncio.create_task(
        run_suggestion_scheduler(
            conn, FilterEngine(), _FakeRules(),
            window_hours=24, min_hits=2, interval_minutes=1,
            auto_approve_score=None, stop_event=stop,
        )
    )
    await asyncio.sleep(0.1)  # first iteration fails; the loop keeps running
    stop.set()
    written = await asyncio.wait_for(task, timeout=5.0)
    assert written == 0


async def test_scheduler_auto_approve_wildcard_and_exact_rules() -> None:
    """Auto mode: score >= threshold adds rules (wildcard when the base itself
    carries a keyword, exact otherwise) and marks the row auto=1."""
    conn = init_database(":memory:")
    _seed_log(conn, "x.ads.example")               # base 'ads.example' has keyword
    _seed_log(conn, "ads.adserver.example.com")    # base 'example.com' has none
    _seed_fallback(conn, "cdn-x.example")          # score 3 (fallback), no keyword
    fake = _FakeRules()
    stop = asyncio.Event()
    task = asyncio.create_task(
        run_suggestion_scheduler(
            conn, FilterEngine(), fake,
            window_hours=24, min_hits=2, interval_minutes=1,
            auto_approve_score=2, stop_event=stop,
        )
    )
    try:
        for _ in range(200):
            if fetch_suggestions(conn, "approved", 10):
                break
            await asyncio.sleep(0.01)
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=5.0)

    assert ("blacklist", "ads.example", "wildcard") in fake.added
    assert ("blacklist", "ads.adserver.example.com", "exact") in fake.added
    assert ("blacklist", "cdn-x.example", "exact") in fake.added
    approved = {r["domain"] for r in fetch_suggestions(conn, "approved", 10)}
    assert approved == {"x.ads.example", "ads.adserver.example.com", "cdn-x.example"}
    assert all(r["auto"] for r in fetch_suggestions(conn, "approved", 10))
    assert fetch_suggestions(conn, "pending", 10) == []


# ── run_analysis_once (POST /suggestions/analyze) ──────────────────────────────


async def test_run_analysis_once_writes_and_auto_approves_wildcard() -> None:
    conn = init_database(":memory:")
    _seed_log(conn, "ad-server.example")
    fake = _FakeRules()
    written = await run_analysis_once(
        conn, FilterEngine(), fake, asyncio.get_running_loop(),
        window_hours=24, min_hits=2, auto_approve_score=2,
    )
    assert written == 1
    assert fake.added == [("blacklist", "ad-server.example", "wildcard")]
    rows = fetch_suggestions(conn, "approved", 10)
    assert rows[0]["domain"] == "ad-server.example"
    assert rows[0]["auto"] is True


async def test_run_analysis_once_auto_exact_rule_without_keyword_base() -> None:
    conn = init_database(":memory:")
    _seed_fallback(conn, "cdn-x.example")
    fake = _FakeRules()
    written = await run_analysis_once(
        conn, FilterEngine(), fake, asyncio.get_running_loop(),
        window_hours=24, min_hits=2, auto_approve_score=3,
    )
    assert written == 1
    assert fake.added == [("blacklist", "cdn-x.example", "exact")]


async def test_run_analysis_once_auto_skips_protected_base(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defense-in-depth guard: even if a protected domain ever reached the
    suggestion list, the auto-approve loop re-checks protection and skips it.
    Simulated with a flag flip because analyze_rows already filters protected
    domains, so the guard is unreachable with consistent inputs."""
    import reqko.filtering.suggester as suggester_module

    calls = {"n": 0}

    def _protected_after_analyze(domain: str) -> bool:
        calls["n"] += 1
        return calls["n"] > 1  # suggestible during analyze, protected at decide

    monkeypatch.setattr(suggester_module, "_is_protected", _protected_after_analyze)
    conn = init_database(":memory:")
    _seed_log(conn, "pixel.test")
    fake = _FakeRules()
    written = await run_analysis_once(
        conn, FilterEngine(), fake, asyncio.get_running_loop(),
        window_hours=24, min_hits=2, auto_approve_score=2,
    )
    # Saved as pending, never auto-approved, no rule installed
    assert written == 1
    assert fake.added == []
    assert [r["domain"] for r in fetch_suggestions(conn, "pending", 10)] == [
        "pixel.test"
    ]


async def test_run_analysis_once_below_threshold_stays_pending() -> None:
    conn = init_database(":memory:")
    _seed_log(conn, "pixel.test")
    fake = _FakeRules()
    written = await run_analysis_once(
        conn, FilterEngine(), fake, asyncio.get_running_loop(),
        window_hours=24, min_hits=2, auto_approve_score=100,
    )
    assert written == 1
    assert fake.added == []
    assert [r["domain"] for r in fetch_suggestions(conn, "pending", 10)] == [
        "pixel.test"
    ]
