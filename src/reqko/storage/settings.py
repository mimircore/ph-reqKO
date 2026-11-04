"""Key/value access to the system_settings table.

Synchronous helpers meant to be called from the executor (or during
startup before the event loop serves traffic).
"""

from __future__ import annotations

import sqlite3


def get_setting(conn: sqlite3.Connection, key: str) -> str | None:
    cur = conn.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
    row = cur.fetchone()
    return str(row[0]) if row is not None else None


def set_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        """
        INSERT INTO system_settings (key, value, updated_at)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = CURRENT_TIMESTAMP
        """,
        (key, value),
    )
    conn.commit()
