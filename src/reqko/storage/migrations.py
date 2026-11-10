"""Database migrations and connection management for reqko.

Implements idempotent schema creation and WAL mode configuration.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

CURRENT_SCHEMA_VERSION = 4
SCHEMA_SQL_PATH = Path(__file__).parent / "schema.sql"

# Forward-only migrations for databases created by older schema versions.
# Applied after the (idempotent) base schema, only when the recorded
# schema version is lower than the migration's target version.
MIGRATIONS: dict[int, tuple[str, str]] = {
    2: (
        "v2: stats_hourly latency aggregates (latency_sum, latency_samples)",
        """
        ALTER TABLE stats_hourly ADD COLUMN latency_sum REAL NOT NULL DEFAULT 0;
        ALTER TABLE stats_hourly ADD COLUMN latency_samples INTEGER NOT NULL DEFAULT 0;
        """,
    ),
    4: (
        "v4: domain_suggestions table for adaptive ad-domain discovery",
        """
        CREATE TABLE IF NOT EXISTS domain_suggestions (
            domain TEXT PRIMARY KEY,
            base TEXT NOT NULL,
            score INTEGER NOT NULL,
            reasons_json TEXT NOT NULL,
            hits INTEGER NOT NULL,
            first_seen TIMESTAMP NOT NULL,
            last_seen TIMESTAMP NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending'
                CHECK(status IN ('pending', 'approved', 'rejected')),
            auto INTEGER NOT NULL DEFAULT 0,
            decided_at TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_domain_suggestions_status
            ON domain_suggestions(status);
        """,
    ),
    3: (
        "v3: query_log source (dns|browser) and occurrences for browser-extension reports",
        """
        CREATE TABLE query_log_v3 (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT NOT NULL,
            question_name TEXT NOT NULL,
            question_type TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN (
                'ALLOWED',
                'FORWARDED',
                'BLOCKED',
                'BLOCKED_BLACKLIST',
                'BLOCKED_CNAME',
                'CACHED',
                'REFUSED_ACL',
                'REFUSED_RATE_LIMIT',
                'REFUSED_ANY',
                'ERROR_UPSTREAM',
                'ERROR_FORMAT'
            )),
            matched_rule TEXT,
            upstream TEXT,
            latency_ms REAL NOT NULL,
            response_code INTEGER NOT NULL,
            source TEXT NOT NULL DEFAULT 'dns' CHECK(source IN ('dns', 'browser')),
            occurrences INTEGER NOT NULL DEFAULT 1
        );
        INSERT INTO query_log_v3 (
            id, timestamp, client_ip, question_name, question_type, status,
            matched_rule, upstream, latency_ms, response_code, source, occurrences
        )
        SELECT id, timestamp, client_ip, question_name, question_type, status,
               matched_rule, upstream, latency_ms, response_code, 'dns', 1
        FROM query_log;
        DROP TABLE query_log;
        ALTER TABLE query_log_v3 RENAME TO query_log;
        CREATE INDEX IF NOT EXISTS idx_query_log_timestamp ON query_log(timestamp);
        CREATE INDEX IF NOT EXISTS idx_query_log_client_ip ON query_log(client_ip);
        CREATE INDEX IF NOT EXISTS idx_query_log_question_name ON query_log(question_name);
        CREATE INDEX IF NOT EXISTS idx_query_log_status ON query_log(status);
        CREATE INDEX IF NOT EXISTS idx_query_log_source ON query_log(source);
        """,
    ),
}


def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Create a configured SQLite connection with WAL pragmas.

    check_same_thread=False: connections are used from the executor threads
    (writer, retention, API reads). Write connections are single-owner per
    component; SQLite's serialized mode plus busy_timeout cover the rest.
    """
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON;")
    # In :memory: databases WAL mode returns 'memory'
    if db_path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.row_factory = sqlite3.Row
    return conn


def apply_migrations(conn: sqlite3.Connection) -> None:
    """Apply database schema and record migration status idempotently."""
    # 1. Read schema SQL (fresh installs get the full current schema)
    if not SCHEMA_SQL_PATH.is_file():
        raise FileNotFoundError(f"Schema SQL file not found at: {SCHEMA_SQL_PATH}")
    sql_script = SCHEMA_SQL_PATH.read_text(encoding="utf-8")

    with conn:
        # Execute schema DDL
        conn.executescript(sql_script)

        # Check the recorded schema version (0 for a fresh database)
        cur = conn.cursor()
        cur.execute(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
        )
        (db_version,) = cur.fetchone()

        # 2. Apply forward migrations for databases created by older versions.
        # A database with no recorded version was just created from the base
        # schema, which already matches CURRENT_SCHEMA_VERSION.
        for target_version in sorted(MIGRATIONS):
            if db_version == 0 or db_version >= target_version:
                continue
            description, sql = MIGRATIONS[target_version]
            cur.executescript(sql)
            cur.execute(
                "INSERT INTO schema_migrations (version, description) VALUES (?, ?)",
                (target_version, description),
            )
            logger.info("Applied schema migration version %d", target_version)

        # 3. Record the current version for a fresh database
        cur.execute(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations"
        )
        (db_version,) = cur.fetchone()
        if db_version < CURRENT_SCHEMA_VERSION:
            cur.execute(
                "INSERT INTO schema_migrations (version, description) VALUES (?, ?)",
                (
                    CURRENT_SCHEMA_VERSION,
                    "Initial schema v1: blocklist, rules, query_log, stats_hourly",
                ),
            )
            logger.info("Recorded schema migration version %d", CURRENT_SCHEMA_VERSION)
        else:
            logger.debug("Schema migration version %d already applied", CURRENT_SCHEMA_VERSION)


def init_database(db_path: str) -> sqlite3.Connection:
    """Convenience function to get connection and apply migrations."""
    conn = get_db_connection(db_path)
    apply_migrations(conn)
    return conn
