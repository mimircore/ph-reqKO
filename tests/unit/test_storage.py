"""Unit tests for storage schema, migrations, and SQLite queries."""

import sqlite3

import pytest

from reqko.storage.migrations import (
    CURRENT_SCHEMA_VERSION,
    apply_migrations,
    get_db_connection,
    init_database,
)

ALL_VALID_STATUSES = [
    "ALLOWED",
    "FORWARDED",
    "BLOCKED_BLACKLIST",
    "BLOCKED_CNAME",
    "CACHED",
    "REFUSED_ACL",
    "REFUSED_RATE_LIMIT",
    "REFUSED_ANY",
    "ERROR_UPSTREAM",
    "ERROR_FORMAT",
]


def test_migrations_create_tables_and_version() -> None:
    conn = get_db_connection(":memory:")
    apply_migrations(conn)

    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = {row[0] for row in cur.fetchall()}
    expected = {
        "schema_migrations",
        "blocklist_sources",
        "custom_rules",
        "query_log",
        "stats_hourly",
        "system_settings",
    }
    assert expected.issubset(tables)

    cur.execute("SELECT version, description FROM schema_migrations;")
    migrations = cur.fetchall()
    assert len(migrations) == 1
    assert migrations[0]["version"] == CURRENT_SCHEMA_VERSION


def test_migrations_are_idempotent() -> None:
    conn = get_db_connection(":memory:")
    apply_migrations(conn)
    apply_migrations(conn)
    apply_migrations(conn)

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM schema_migrations;")
    count = cur.fetchone()[0]
    assert count == 1


def test_migration_v1_to_v2_adds_latency_columns() -> None:
    """A database created by schema v1 is upgraded in place, keeping its data."""
    conn = get_db_connection(":memory:")
    # Recreate the OLD v1 stats_hourly shape (no latency columns)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            description TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS stats_hourly (
            bucket_timestamp TIMESTAMP NOT NULL PRIMARY KEY,
            total_queries INTEGER NOT NULL DEFAULT 0,
            blocked_queries INTEGER NOT NULL DEFAULT 0,
            cached_queries INTEGER NOT NULL DEFAULT 0,
            forwarded_queries INTEGER NOT NULL DEFAULT 0,
            allowed_queries INTEGER NOT NULL DEFAULT 0,
            refused_queries INTEGER NOT NULL DEFAULT 0,
            error_queries INTEGER NOT NULL DEFAULT 0
        );
        INSERT INTO schema_migrations (version, description) VALUES (1, 'v1');
        INSERT INTO stats_hourly (bucket_timestamp, total_queries, blocked_queries)
            VALUES ('2026-01-01 10:00:00', 42, 7);
        """
    )
    conn.commit()

    apply_migrations(conn)

    cols = {row[1] for row in conn.execute("PRAGMA table_info(stats_hourly)")}
    assert "latency_sum" in cols
    assert "latency_samples" in cols

    versions = [
        row[0] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")
    ]
    # v1 databases migrate forward through ALL later versions (2 and 3)
    assert versions == [1, 2, 3]

    # Existing aggregates survive the migration
    row = conn.execute(
        "SELECT total_queries, blocked_queries, latency_sum, latency_samples "
        "FROM stats_hourly WHERE bucket_timestamp = '2026-01-01 10:00:00'"
    ).fetchone()
    assert row is not None
    assert row["total_queries"] == 42
    assert row["blocked_queries"] == 7
    assert row["latency_sum"] == 0
    assert row["latency_samples"] == 0

    # The writer's UPSERT works against the migrated table
    conn.execute(
        """
        INSERT INTO stats_hourly (
            bucket_timestamp, total_queries, blocked_queries, cached_queries,
            forwarded_queries, allowed_queries, refused_queries, error_queries,
            latency_sum, latency_samples
        ) VALUES ('2026-01-01 10:00:00', 8, 0, 8, 0, 0, 0, 0, 12.5, 8)
        ON CONFLICT(bucket_timestamp) DO UPDATE SET
            total_queries = total_queries + excluded.total_queries,
            latency_sum = latency_sum + excluded.latency_sum,
            latency_samples = latency_samples + excluded.latency_samples
        """,
    )
    conn.commit()
    row = conn.execute(
        "SELECT total_queries, latency_sum, latency_samples FROM stats_hourly "
        "WHERE bucket_timestamp = '2026-01-01 10:00:00'"
    ).fetchone()
    assert row is not None
    assert row["total_queries"] == 50
    assert row["latency_sum"] == 12.5
    assert row["latency_samples"] == 8


def test_query_log_accepts_all_valid_statuses() -> None:
    conn = init_database(":memory:")
    with conn:
        for idx, status in enumerate(ALL_VALID_STATUSES):
            conn.execute(
                """
                INSERT INTO query_log (
                    client_ip, question_name, question_type, status,
                    matched_rule, upstream, latency_ms, response_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"192.168.1.{10 + idx}",
                    f"test{idx}.example.com",
                    "A",
                    status,
                    "rule-1" if "BLOCKED" in status else None,
                    "9.9.9.9:53" if status == "FORWARDED" else None,
                    1.23,
                    0,
                ),
            )

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM query_log;")
    assert cur.fetchone()[0] == len(ALL_VALID_STATUSES)


def test_query_log_rejects_invalid_status() -> None:
    conn = init_database(":memory:")
    with pytest.raises(sqlite3.IntegrityError):
        with conn:
            conn.execute(
                """
                INSERT INTO query_log (
                    client_ip, question_name, question_type, status,
                    matched_rule, upstream, latency_ms, response_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ("192.168.1.1", "bad.com", "A", "INVALID_STATUS_XYZ", None, None, 1.0, 0),
            )


def test_stats_hourly_upsert_sums_correctly() -> None:
    conn = init_database(":memory:")
    upsert_sql = """
    INSERT INTO stats_hourly (
        bucket_timestamp, total_queries, blocked_queries, cached_queries,
        forwarded_queries, allowed_queries, refused_queries, error_queries
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(bucket_timestamp) DO UPDATE SET
        total_queries = total_queries + excluded.total_queries,
        blocked_queries = blocked_queries + excluded.blocked_queries,
        cached_queries = cached_queries + excluded.cached_queries,
        forwarded_queries = forwarded_queries + excluded.forwarded_queries,
        allowed_queries = allowed_queries + excluded.allowed_queries,
        refused_queries = refused_queries + excluded.refused_queries,
        error_queries = error_queries + excluded.error_queries;
    """

    bucket = "2026-11-02 12:00:00"
    with conn:
        # Batch 1: 10 queries (4 forwarded, 3 blocked, 2 cached, 1 allowed)
        conn.execute(upsert_sql, (bucket, 10, 3, 2, 4, 1, 0, 0))
        # Batch 2: 6 queries (2 blocked, 1 error, 1 refused, 1 forwarded, 1 cached)
        conn.execute(upsert_sql, (bucket, 6, 2, 1, 1, 0, 1, 1))

    cur = conn.cursor()
    cur.execute("SELECT * FROM stats_hourly WHERE bucket_timestamp = ?", (bucket,))
    row = cur.fetchone()
    assert row is not None

    total = row["total_queries"]
    assert total == 16

    sub_sum = (
        row["blocked_queries"]
        + row["cached_queries"]
        + row["forwarded_queries"]
        + row["allowed_queries"]
        + row["refused_queries"]
        + row["error_queries"]
    )
    assert total == sub_sum
    assert row["blocked_queries"] == 5
    assert row["cached_queries"] == 3
    assert row["forwarded_queries"] == 5
    assert row["allowed_queries"] == 1
    assert row["refused_queries"] == 1
    assert row["error_queries"] == 1


def test_migration_v2_to_v3_adds_source_and_blocked_status() -> None:
    """A v2 database (query_log without source/occurrences) is upgraded in
    place: existing rows keep their data with source='dns', and the new
    'BLOCKED' status (browser-extension reports) becomes valid."""
    conn = get_db_connection(":memory:")
    # Recreate the OLD v2 query_log shape (no source/occurrences, no BLOCKED)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            description TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS query_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            client_ip TEXT NOT NULL,
            question_name TEXT NOT NULL,
            question_type TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN (
                'ALLOWED', 'FORWARDED', 'BLOCKED_BLACKLIST', 'BLOCKED_CNAME',
                'CACHED', 'REFUSED_ACL', 'REFUSED_RATE_LIMIT', 'REFUSED_ANY',
                'ERROR_UPSTREAM', 'ERROR_FORMAT'
            )),
            matched_rule TEXT,
            upstream TEXT,
            latency_ms REAL NOT NULL,
            response_code INTEGER NOT NULL
        );
        INSERT INTO schema_migrations (version, description) VALUES (1, 'v1');
        INSERT INTO schema_migrations (version, description) VALUES (2, 'v2');
        INSERT INTO query_log (client_ip, question_name, question_type, status, latency_ms, response_code)
            VALUES ('192.168.1.5', 'old.example.com', 'A', 'FORWARDED', 1.5, 0);
        """
    )
    conn.commit()

    apply_migrations(conn)

    cols = {row[1] for row in conn.execute("PRAGMA table_info(query_log)")}
    assert "source" in cols
    assert "occurrences" in cols

    versions = [
        row[0] for row in conn.execute("SELECT version FROM schema_migrations ORDER BY version")
    ]
    assert versions == [1, 2, 3]

    # Existing v2 data survives with source='dns', occurrences=1
    row = conn.execute(
        "SELECT client_ip, question_name, status, source, occurrences FROM query_log"
    ).fetchone()
    assert row is not None
    assert row["question_name"] == "old.example.com"
    assert row["source"] == "dns"
    assert row["occurrences"] == 1

    # The new BLOCKED status (browser reports) is now accepted
    conn.execute(
        """
        INSERT INTO query_log (client_ip, question_name, question_type, status,
                               latency_ms, response_code, source, occurrences)
        VALUES ('browser', 'ads.example.com', 'A', 'BLOCKED', 0.0, 0, 'browser', 5)
        """
    )
    conn.commit()
    row = conn.execute(
        "SELECT source, occurrences FROM query_log WHERE status = 'BLOCKED'"
    ).fetchone()
    assert row is not None
    assert row["source"] == "browser"
    assert row["occurrences"] == 5

    # source CHECK still rejects unknown sources
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            """
            INSERT INTO query_log (client_ip, question_name, question_type, status,
                                   latency_ms, response_code, source)
            VALUES ('x', 'y', 'A', 'BLOCKED', 0.0, 0, 'smtp')
            """
        )
