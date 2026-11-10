"""Adaptive ad-domain suggestion engine (query-log analysis).

Analyzes query_log rows from the last REQKO_SUGGEST_WINDOW_HOURS and scores
FORWARDED/CACHED domains that look like ad/tracker infrastructure. Never
suggests: already-blocked domains, allowlisted domains, previously rejected
domains, or domains whose registrable base is PROTECTED (see
filtering/data/protected_bases.txt).

Signals (each adds to the score, reasons stored as strings):
  a) keyword label match: whole labels or label tokens split by '-' and
     digits ("ad2" -> "ad", "sdk-events" -> "events"). Exact token matching
     only — "ads" must NOT match "loads"/"uploads"/"gadsden";
  b) fallback pattern: the same client queried this domain within 3 seconds
     AFTER a BLOCKED_* domain, and the domain was never queried outside such
     windows;
  c) sibling burst: queried in the same 2 s burst as >= 2 blocked domains
     from different ad networks (distinct registrable bases);
  d) minimum hits: REQKO_SUGGEST_MIN_HITS (default 2).

Pure functions over in-memory row lists: no browser, no I/O — the caller
(SQL scheduler task) loads rows and persists results.
"""

from __future__ import annotations

import asyncio
import datetime
import fnmatch
import json
import logging
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reqko.filtering.engine import FilterEngine

logger = logging.getLogger(__name__)

DATA_FILE = Path(__file__).resolve().parent / "data" / "protected_bases.txt"

# Whole-label keywords (exact label match after lowercasing)
KEYWORDS: frozenset[str] = frozenset(
    {
        "ad",
        "ads",
        "adserver",
        "adservice",
        "adx",
        "adsystem",
        "doubleclick",
        "track",
        "tracker",
        "tracking",
        "telemetry",
        "metrics",
        "analytics",
        "attribution",
        "mediation",
        "rtb",
        "ssp",
        "dsp",
        "pixel",
        "beacon",
        "banner",
        "offerwall",
        "rewarded",
        "events",
    }
)

# Multi-part public suffixes handled by the registrable-base helper
MULTI_PART_SUFFIXES: frozenset[str] = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.au", "net.au", "org.au",
        "co.jp", "ne.jp", "or.jp",
        "com.br", "com.mx", "com.ar",
        "co.nz", "net.nz", "org.nz",
        "co.in", "co.za", "co.kr", "co.id",
        "com.cn", "com.tw", "com.hk", "com.sg",
        "com.tr", "com.ua", "com.pl", "com.my",
    }
)

FALLBACK_WINDOW_SECONDS = 3.0
BURST_WINDOW_SECONDS = 2.0
BURST_MIN_BLOCKED_NETWORKS = 2

SCORE_KEYWORD = 2
SCORE_FALLBACK = 3
SCORE_SIBLING_BURST = 2


def _load_protected_bases(data_file: Path = DATA_FILE) -> tuple[frozenset[str], list[str]]:
    exact: set[str] = set()
    wildcards: list[str] = []
    for line in data_file.read_text(encoding="utf-8").splitlines():
        entry = line.strip().lower()
        if not entry or entry.startswith("#"):
            continue
        if "*" in entry:
            wildcards.append(entry)
        else:
            exact.add(entry)
    return frozenset(exact), wildcards


PROTECTED_EXACT, PROTECTED_WILDCARDS = _load_protected_bases()


def registrable_base(domain: str) -> str:
    """Small public-suffix helper (no dependencies).

    Handles common multi-part suffixes (co.uk, com.au, ...): a domain whose
    last two labels form a known multi-part suffix keeps three labels as its
    base; otherwise the base is the last two labels.
    """
    labels = domain.strip(".").lower().split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    suffix2 = ".".join(labels[-2:])
    if suffix2 in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return suffix2


def _is_protected(domain: str) -> bool:
    """Protected = registrable base is protected AND the host itself is not
    an ad host (keyword-labelled hosts like ad.intl.xiaomi.com stay
    suggestible)."""
    base = registrable_base(domain)
    protected = base in PROTECTED_EXACT or any(
        fnmatch.fnmatch(base, pattern) for pattern in PROTECTED_WILDCARDS
    )
    if not protected:
        return False
    # Exception: ad.intl.xiaomi.com-style ad hosts on the xiaomi/miui bases
    # stay suggestible; every other protected base is never exempted.
    if "xiaomi" in base or "miui" in base:
        return not has_keyword(domain)
    return True


def _split_tokens(label: str) -> list[str]:
    """Splits a label into tokens on '-' and digit runs: ad2 -> [ad],
    sdk-events -> [sdk, events]. Digits act as separators and are dropped
    as tokens."""
    return [tok for tok in re.split(r"[-0-9]+", label) if tok]


def has_keyword(domain: str) -> bool:
    """True when any label equals a keyword, or any hyphen/digit token of a
    label equals a keyword. Exact token matching only: 'ads' does not match
    'loads', 'uploads' or 'gadsden'."""
    for label in domain.strip(".").lower().split("."):
        if label in KEYWORDS:
            return True
        for token in _split_tokens(label):
            if token in KEYWORDS:
                return True
    return False


def keyword_reasons(domain: str) -> list[str]:
    """Returns 'keyword:<token>' reason strings for matched labels/tokens."""
    reasons: list[str] = []
    for label in domain.strip(".").lower().split("."):
        if label in KEYWORDS:
            reasons.append(f"keyword:{label}")
            continue
        for token in _split_tokens(label):
            if token in KEYWORDS:
                reasons.append(f"keyword:{token}")
                break
    return reasons


@dataclass
class Suggestion:
    domain: str
    base: str
    score: int
    reasons: list[str] = field(default_factory=list)
    hits: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass(frozen=True)
class LogRow:
    """One query_log row relevant to the analysis."""

    timestamp: float  # unix seconds
    client_ip: str
    question_name: str
    status: str


def analyze_rows(
    rows: list[LogRow],
    *,
    blocked: frozenset[str],
    allowlisted: frozenset[str],
    rejected: frozenset[str],
    min_hits: int = 2,
) -> list[Suggestion]:
    """Scores FORWARDED/CACHED domains from the given log rows.

    rows must be sorted by timestamp. blocked/allowlisted/rejected are the
    domains that must never be suggested. Returns suggestions sorted by
    (score desc, domain).
    """
    allowed_statuses = ("FORWARDED", "CACHED")
    blocked_by_client: dict[str, list[tuple[float, str]]] = {}
    queries_by_domain: dict[str, list[tuple[float, str]]] = {}
    first_seen: dict[str, float] = {}
    last_seen: dict[str, float] = {}

    for row in rows:
        domain = row.question_name
        if row.status.startswith("BLOCKED"):
            blocked_by_client.setdefault(row.client_ip, []).append(
                (row.timestamp, domain)
            )
        if row.status in allowed_statuses:
            queries_by_domain.setdefault(domain, []).append(
                (row.timestamp, row.client_ip)
            )
            first_seen[domain] = min(first_seen.get(domain, row.timestamp), row.timestamp)
            last_seen[domain] = max(last_seen.get(domain, row.timestamp), row.timestamp)

    # Per-client blocked event timestamps, for window checks
    blocked_ts_by_client: dict[str, list[float]] = {
        client: [ts for ts, _domain in events]
        for client, events in blocked_by_client.items()
    }

    def _in_fallback_window(ts: float, client: str) -> bool:
        return any(
            0 <= ts - blocked_ts <= FALLBACK_WINDOW_SECONDS
            for blocked_ts in blocked_ts_by_client.get(client, ())
        )

    def _sibling_bursts(ts: float, client: str) -> int:
        """Distinct registrable bases of blocked domains in the same 2 s
        burst around this query."""
        bases: set[str] = set()
        for blocked_ts, blocked_domain in blocked_by_client.get(client, ()):
            if abs(ts - blocked_ts) <= BURST_WINDOW_SECONDS:
                bases.add(registrable_base(blocked_domain))
        return len(bases)

    suggestions: list[Suggestion] = []
    for domain, queries in sorted(queries_by_domain.items()):
        if domain in blocked or domain in allowlisted or domain in rejected:
            continue
        if _is_protected(domain):
            continue
        hits = len(queries)
        if hits < min_hits:
            continue

        reasons: list[str] = []
        score = 0
        kw = keyword_reasons(domain)
        if kw:
            reasons.extend(kw)
            score += SCORE_KEYWORD * len(kw)

        # b) fallback pattern: every query of this domain falls within 3 s
        #    after a blocked query by the same client
        in_window = [_in_fallback_window(ts, client) for ts, client in queries]
        if in_window and all(in_window):
            reasons.append("fallback after blocked")
            score += SCORE_FALLBACK

        # c) sibling burst: any query within 2 s of >= 2 blocked domains
        #    from different registrable bases
        if any(_sibling_bursts(ts, client) >= BURST_MIN_BLOCKED_NETWORKS
               for ts, client in queries):
            reasons.append("sibling burst")
            score += SCORE_SIBLING_BURST

        if score > 0:
            suggestions.append(
                Suggestion(
                    domain=domain,
                    base=registrable_base(domain),
                    score=score,
                    reasons=reasons,
                    hits=hits,
                    first_seen=first_seen[domain],
                    last_seen=last_seen[domain],
                )
            )

    suggestions.sort(key=lambda s: (-s.score, s.domain))
    return suggestions
# ── persistence (domain_suggestions table) ─────────────────────────────────────


def _parse_ts(raw: str) -> float:
    """Parses a SQLite TIMESTAMP string ('YYYY-MM-DD HH:MM:SS') to unix seconds."""
    import datetime

    return datetime.datetime.strptime(
        str(raw), "%Y-%m-%d %H:%M:%S"
    ).replace(tzinfo=datetime.timezone.utc).timestamp()


def _iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S"
    )


def save_suggestions(conn: sqlite3.Connection, suggestions: list[Suggestion]) -> int:
    """Inserts new suggestions / refreshes existing pending ones.

    Already decided (approved/rejected) domains are never reset to pending.
    Returns the number of rows written.
    """
    written = 0
    for s in suggestions:
        conn.execute(
            """
            INSERT INTO domain_suggestions (
                domain, base, score, reasons_json, hits, first_seen, last_seen, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
            ON CONFLICT(domain) DO UPDATE SET
                score = excluded.score,
                reasons_json = excluded.reasons_json,
                hits = excluded.hits,
                last_seen = excluded.last_seen
            WHERE domain_suggestions.status = 'pending'
            """,
            (
                s.domain,
                s.base,
                s.score,
                json.dumps(s.reasons),
                s.hits,
                _iso(s.first_seen) if s.first_seen else "",
                _iso(s.last_seen) if s.last_seen else "",
            ),
        )
        written += 1
    conn.commit()
    return written


def fetch_suggestions(
    conn: sqlite3.Connection, status: str, limit: int
) -> list[dict[str, Any]]:
    cur = conn.execute(
        "SELECT domain, base, score, reasons_json, hits, first_seen, last_seen, auto "
        "FROM domain_suggestions WHERE status = ? "
        "ORDER BY score DESC, domain LIMIT ?",
        (status, limit),
    )
    rows: list[dict[str, Any]] = []
    for domain, base, score, reasons_json, hits, first_seen, last_seen, auto in cur.fetchall():
        rows.append(
            {
                "domain": str(domain),
                "base": str(base),
                "score": int(score),
                "reasons": json.loads(str(reasons_json)),
                "hits": int(hits),
                "first_seen": str(first_seen),
                "last_seen": str(last_seen),
                "auto": bool(auto),
            }
        )
    return rows


def set_suggestion_status(
    conn: sqlite3.Connection, domain: str, status: str, auto: bool = False
) -> bool:
    cur = conn.execute(
        "UPDATE domain_suggestions SET status = ?, auto = ?, decided_at = CURRENT_TIMESTAMP "
        "WHERE domain = ?",
        (status, int(auto), domain),
    )
    conn.commit()
    return bool(cur.rowcount)


def rejected_domains(conn: sqlite3.Connection) -> frozenset[str]:
    return frozenset(
        str(row[0])
        for row in conn.execute(
            "SELECT domain FROM domain_suggestions WHERE status = 'rejected'"
        )
    )


# ── scheduler (never blocks the DNS path; graceful shutdown) ──────────────────


async def run_suggestion_scheduler(
    conn: sqlite3.Connection,
    engine: FilterEngine,
    rule_manager: Any,
    *,
    window_hours: int,
    min_hits: int,
    interval_minutes: int,
    auto_approve_score: int | None,
    stop_event: asyncio.Event,
) -> int:
    """Background task: analyze query_log every interval_minutes.

    interval_minutes == 0 disables the scheduler entirely. Runs the
    (blocking) SQL analysis in the executor so the DNS path is never
    delayed; honors graceful shutdown via stop_event. Auto-approves
    suggestions when auto_approve_score is set (PROTECTED bases and the
    allowlist are always respected). Returns the total number of rows
    written across the task's lifetime.
    """
    if interval_minutes <= 0:
        return 0
    loop = asyncio.get_running_loop()
    stop = stop_event
    total_written = 0
    while not stop.is_set():
        try:
            cutoff = _iso(time.time() - window_hours * 3600)

            def _load_rows(cutoff: str = cutoff) -> list[LogRow]:
                cur = conn.execute(
                    "SELECT timestamp, client_ip, question_name, status "
                    "FROM query_log WHERE timestamp >= ? AND source = 'dns' "
                    "ORDER BY timestamp",
                    (cutoff,),
                )
                return [
                    LogRow(timestamp=_parse_ts(ts), client_ip=ip,
                           question_name=qn, status=st)
                    for ts, ip, qn, st in cur.fetchall()
                ]

            rows = await loop.run_in_executor(None, _load_rows)
            rejected = frozenset(
                await loop.run_in_executor(None, rejected_domains, conn)
            )
            suggestions = analyze_rows(
                rows,
                blocked=frozenset(engine.snapshot.exact_set)
                | frozenset(engine.snapshot.wildcard_set),
                allowlisted=frozenset(engine.snapshot.allow_exact_set)
                | frozenset(engine.snapshot.allow_wildcard_set),
                rejected=rejected,
                min_hits=min_hits,
            )
            written = await loop.run_in_executor(
                None, save_suggestions, conn, suggestions
            )
            total_written += written

            if auto_approve_score is not None:
                for suggestion in suggestions:
                    if suggestion.score < auto_approve_score:
                        continue
                    if _is_protected(suggestion.domain):
                        logger.info(
                            "auto-approve skipped (protected): %s", suggestion.domain
                        )
                        continue
                    if has_keyword(suggestion.base):
                        await loop.run_in_executor(
                            None,
                            rule_manager.add_rule,
                            "blacklist",
                            suggestion.base,
                            "wildcard",
                        )
                    else:
                        await loop.run_in_executor(
                            None,
                            rule_manager.add_rule,
                            "blacklist",
                            suggestion.domain,
                            "exact",
                        )
                    await loop.run_in_executor(
                        None,
                        set_suggestion_status,
                        conn,
                        suggestion.domain,
                        "approved",
                        True,
                    )
                    logger.info(
                        "auto-approved suggestion %s (score %d): %s",
                        suggestion.domain,
                        suggestion.score,
                        ", ".join(suggestion.reasons),
                    )
        except Exception:
            logger.exception("suggestion scheduler iteration failed")
        slept = 0.0
        interval_seconds = interval_minutes * 60.0
        while slept < interval_seconds and not stop.is_set():
            delay = min(1.0, interval_seconds - slept)
            await asyncio.sleep(delay)
            slept += delay
    return total_written


async def run_analysis_once(
    conn: sqlite3.Connection,
    engine: FilterEngine,
    rule_manager: Any,
    loop: asyncio.AbstractEventLoop,
    *,
    window_hours: int,
    min_hits: int,
    auto_approve_score: int | None,
) -> int:
    """Single-shot analysis (POST /api/v1/suggestions/analyze).

    Returns the number of suggestion rows written."""
    cutoff = _iso(time.time() - window_hours * 3600)

    def _load_rows() -> list[LogRow]:
        cur = conn.execute(
            "SELECT timestamp, client_ip, question_name, status "
            "FROM query_log WHERE timestamp >= ? AND source = 'dns' "
            "ORDER BY timestamp",
            (cutoff,),
        )
        return [
            LogRow(timestamp=_parse_ts(ts), client_ip=ip,
                   question_name=qn, status=st)
            for ts, ip, qn, st in cur.fetchall()
        ]

    rows = await loop.run_in_executor(None, _load_rows)
    rejected = frozenset(await loop.run_in_executor(None, rejected_domains, conn))
    suggestions = analyze_rows(
        rows,
        blocked=frozenset(engine.snapshot.exact_set)
        | frozenset(engine.snapshot.wildcard_set),
        allowlisted=frozenset(engine.snapshot.allow_exact_set)
        | frozenset(engine.snapshot.allow_wildcard_set),
        rejected=rejected,
        min_hits=min_hits,
    )
    written = await loop.run_in_executor(None, save_suggestions, conn, suggestions)

    if auto_approve_score is not None:
        for suggestion in suggestions:
            if suggestion.score < auto_approve_score:
                continue
            if _is_protected(suggestion.domain):
                logger.info("auto-approve skipped (protected): %s", suggestion.domain)
                continue
            if has_keyword(suggestion.base):
                await loop.run_in_executor(
                    None,
                    rule_manager.add_rule,
                    "blacklist",
                    suggestion.base,
                    "wildcard",
                )
            else:
                await loop.run_in_executor(
                    None,
                    rule_manager.add_rule,
                    "blacklist",
                    suggestion.domain,
                    "exact",
                )
            await loop.run_in_executor(
                None,
                set_suggestion_status,
                conn,
                suggestion.domain,
                "approved",
                True,
            )
            logger.info(
                "auto-approved suggestion %s (score %d): %s",
                suggestion.domain,
                suggestion.score,
                ", ".join(suggestion.reasons),
            )
    return written
