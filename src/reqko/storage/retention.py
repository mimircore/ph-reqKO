"""Retention job: deletes query_log rows older than the configured days (FR-12).

Runs once at startup and then once per hour. The DELETE uses SQLite's own
clock (UTC) with a bound parameter, so it is injection-safe.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3

logger = logging.getLogger(__name__)


class RetentionJob:
    """Periodically prunes expired rows from query_log."""

    def __init__(
        self,
        conn: sqlite3.Connection,
        retention_days: int,
        interval_seconds: float = 3600.0,
    ) -> None:
        self._conn = conn
        self._retention_days = retention_days
        self._interval = interval_seconds
        self._stop_event = asyncio.Event()

    async def run_once(self) -> int:
        """Deletes expired rows once; returns the number of deleted rows."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._run_once_sync)

    def _run_once_sync(self) -> int:
        cur = self._conn.execute(
            "DELETE FROM query_log WHERE timestamp < datetime('now', '-' || ? || ' days')",
            (self._retention_days,),
        )
        self._conn.commit()
        deleted = cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
        if deleted:
            logger.info(
                "Retention: deleted %d query_log rows older than %d days",
                deleted,
                self._retention_days,
            )
        return deleted

    async def run_forever(self) -> None:
        """Runs once immediately, then once per interval until stopped."""
        while not self._stop_event.is_set():
            try:
                await self.run_once()
            except Exception:
                logger.exception("Retention job failed")
            # Sleep in short slices so stop() is prompt
            slept = 0.0
            while slept < self._interval and not self._stop_event.is_set():
                delay = min(1.0, self._interval - slept)
                await asyncio.sleep(delay)
                slept += delay

    async def stop(self) -> None:
        self._stop_event.set()
