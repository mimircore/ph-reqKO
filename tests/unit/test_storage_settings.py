"""Unit tests for the system_settings key/value store."""

import sqlite3

import pytest

from reqko.storage.migrations import init_database
from reqko.storage.settings import get_setting, set_setting


def test_get_missing_setting_returns_none() -> None:
    conn = init_database(":memory:")
    assert get_setting(conn, "no-such-key") is None


def test_set_and_get_setting_roundtrip() -> None:
    conn = init_database(":memory:")
    set_setting(conn, "admin_token_hash", "abc123")
    assert get_setting(conn, "admin_token_hash") == "abc123"


def test_set_setting_overwrites() -> None:
    conn = init_database(":memory:")
    set_setting(conn, "key", "first")
    set_setting(conn, "key", "second")
    assert get_setting(conn, "key") == "second"
    # Still exactly one row for the key
    (count,) = conn.execute(
        "SELECT COUNT(*) FROM system_settings WHERE key = ?", ("key",)
    ).fetchone()
    assert count == 1


def test_set_setting_rejects_wrong_type() -> None:
    conn = init_database(":memory:")
    with pytest.raises(sqlite3.IntegrityError):
        set_setting(conn, "key", None)  # type: ignore[arg-type]
