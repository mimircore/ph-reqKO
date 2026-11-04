"""Custom rule management: persisted allow/block domains (FR-19).

Custom domains are stored in the custom_rules table and merged into the
FilterSnapshot on every change via an atomic reference swap, so the DNS
hot path never locks and never restarts. Blocklist refreshes replace the
base snapshot; custom rules survive them.
"""

from __future__ import annotations

import logging
import sqlite3

from reqko.filtering.engine import FilterEngine, FilterSnapshot
from reqko.filtering.parser import normalize_domain

logger = logging.getLogger(__name__)

LAST_UPDATE_KEY = "blocklists_last_update"


class RuleManager:
    """Keeps the effective FilterSnapshot = base lists + persisted custom rules."""

    def __init__(self, engine: FilterEngine, conn: sqlite3.Connection) -> None:
        self._engine = engine
        self._conn = conn
        self._base = engine.snapshot
        self._custom_allows: set[str] = set()
        self._custom_blocks: set[str] = set()
        self._version = engine.snapshot.version
        self.last_update: str | None = None

    # ── startup / persistence ─────────────────────────────────────────────────

    def load_persisted(self) -> None:
        """Loads enabled custom rules and the last update marker from the DB."""
        cur = self._conn.execute(
            "SELECT domain, rule_type FROM custom_rules WHERE enabled = 1"
        )
        for domain, rule_type in cur.fetchall():
            if rule_type == "whitelist":
                self._custom_allows.add(str(domain))
            elif rule_type == "blacklist":
                self._custom_blocks.add(str(domain))
        self.last_update = self._read_last_update()
        self._apply()

    def _read_last_update(self) -> str | None:
        cur = self._conn.execute(
            "SELECT value FROM system_settings WHERE key = ?", (LAST_UPDATE_KEY,)
        )
        row = cur.fetchone()
        return str(row[0]) if row is not None else None

    def save_last_update(self, iso_timestamp: str) -> None:
        self._conn.execute(
            """
            INSERT INTO system_settings (key, value, updated_at)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value, updated_at = CURRENT_TIMESTAMP
            """,
            (LAST_UPDATE_KEY, iso_timestamp),
        )
        self._conn.commit()
        self.last_update = iso_timestamp

    # ── snapshot composition ──────────────────────────────────────────────────

    def set_base(self, base: FilterSnapshot) -> None:
        """Installs a new base snapshot (after a list refresh) and re-applies
        the custom rules with an atomic swap."""
        self._base = base
        self._apply()

    def _apply(self) -> None:
        self._version += 1
        snapshot = FilterSnapshot(
            exact_set=self._base.exact_set | self._custom_blocks,
            wildcard_set=self._base.wildcard_set,
            allow_exact_set=self._base.allow_exact_set | self._custom_allows,
            allow_wildcard_set=self._base.allow_wildcard_set,
            version=self._version,
            rules_count=0,  # auto-computed from the merged sets
        )
        self._engine.update_snapshot(snapshot)
        logger.info(
            "Filter rules v%d: %d rules (%d base + %d custom)",
            snapshot.version,
            snapshot.rules_count,
            self._base.rules_count,
            len(self._custom_allows) + len(self._custom_blocks),
        )

    # ── CRUD (synchronous; API handlers call these via the executor) ─────────

    def add_rule(self, rule_type: str, domain: str) -> str:
        """Adds a custom rule; returns the normalized domain.

        Raises ValueError for an invalid domain.
        """
        normalized = normalize_domain(domain)
        if normalized is None:
            raise ValueError(f"Invalid domain: {domain!r}")
        self._conn.execute(
            """
            INSERT INTO custom_rules (rule_type, syntax_type, domain, enabled)
            VALUES (?, 'exact', ?, 1)
            ON CONFLICT(rule_type, domain) DO UPDATE SET enabled = 1
            """,
            (rule_type, normalized),
        )
        self._conn.commit()
        if rule_type == "whitelist":
            self._custom_allows.add(normalized)
        else:
            self._custom_blocks.add(normalized)
        self._apply()
        return normalized

    def remove_rule(self, rule_type: str, domain: str) -> bool:
        """Removes a custom rule; returns True if it existed."""
        normalized = normalize_domain(domain)
        if normalized is None:
            raise ValueError(f"Invalid domain: {domain!r}")
        cur = self._conn.execute(
            "DELETE FROM custom_rules WHERE rule_type = ? AND domain = ?",
            (rule_type, normalized),
        )
        self._conn.commit()
        existed = bool(cur.rowcount)
        if rule_type == "whitelist":
            self._custom_allows.discard(normalized)
        else:
            self._custom_blocks.discard(normalized)
        if existed:
            self._apply()
        return existed

    def list_rules(self, rule_type: str | None = None) -> list[dict[str, str]]:
        """Returns enabled custom rules, optionally filtered by rule_type."""
        if rule_type is None:
            cur = self._conn.execute(
                "SELECT rule_type, domain FROM custom_rules WHERE enabled = 1 "
                "ORDER BY rule_type, domain"
            )
        else:
            cur = self._conn.execute(
                "SELECT rule_type, domain FROM custom_rules WHERE enabled = 1 "
                "AND rule_type = ? ORDER BY domain",
                (rule_type,),
            )
        return [
            {"type": str(rtype), "domain": str(domain)}
            for rtype, domain in cur.fetchall()
        ]
