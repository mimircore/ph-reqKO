"""Database migrations and connection management for reqko.

Implements idempotent schema creation and WAL mode configuration.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)

CURRENT_SCHEMA_VERSION = 1
SCHEMA_SQL_PATH = Path(__file__).parent / "schema.sql"


def get_db_connection(db_path: str) -> sqlite3.Connection:
    """Create a configured SQLite connection with WAL pragmas."""
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
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
    # 1. Read schema SQL
    if not SCHEMA_SQL_PATH.is_file():
        raise FileNotFoundError(f"Schema SQL file not found at: {SCHEMA_SQL_PATH}")
    sql_script = SCHEMA_SQL_PATH.read_text(encoding="utf-8")

    with conn:
        # Execute schema DDL
        conn.executescript(sql_script)

        # Check if version is already recorded
        cur = conn.cursor()
        cur.execute(
            "SELECT version FROM schema_migrations WHERE version = ?",
            (CURRENT_SCHEMA_VERSION,),
        )
        row = cur.fetchone()
        if not row:
            cur.execute(
                "INSERT INTO schema_migrations (version, description) VALUES (?, ?)",
                (CURRENT_SCHEMA_VERSION, "Initial schema v1: blocklist, rules, query_log, stats_hourly"),
            )
            logger.info("Recorded schema migration version %d", CURRENT_SCHEMA_VERSION)
        else:
            logger.debug("Schema migration version %d already applied", CURRENT_SCHEMA_VERSION)


def init_database(db_path: str) -> sqlite3.Connection:
    """Convenience function to get connection and apply migrations."""
    conn = get_db_connection(db_path)
    apply_migrations(conn)
    return conn
