"""Async query-log writer: event queue -> batched SQLite inserts (FR-11, FR-12).

Consumes QueryEvents produced by the DNS pipeline and writes them in batches:
a single transaction inserts the rows into query_log and UPSERTs the hourly
aggregates into stats_hourly. Flushes run in the default executor so the
event loop (and the DNS hot path) is never blocked by SQLite (NFR-03).
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import sqlite3
import time
from collections.abc import Callable

from reqko.dns.pipeline import QueryEvent

logger = logging.getLogger(__name__)

# Status -> stats_hourly category mapping (docs/03-architecture.md, section 7.3).
# "BLOCKED" is the aggregated status reported by the browser extension.
STATUS_CATEGORY: dict[str, str] = {
    "BLOCKED": "blocked",
    "BLOCKED_BLACKLIST": "blocked",
    "BLOCKED_CNAME": "blocked",
    "CACHED": "cached",
    "FORWARDED": "forwarded",
    "ALLOWED": "allowed",
    "REFUSED_ACL": "refused",
    "REFUSED_RATE_LIMIT": "refused",
    "REFUSED_ANY": "refused",
    "ERROR_UPSTREAM": "error",
    "ERROR_FORMAT": "error",
}

_QUERY_LOG_INSERT = """
INSERT INTO query_log (
    timestamp, client_ip, question_name, question_type,
    status, matched_rule, upstream, latency_ms, response_code,
    source, occurrences
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""

_STATS_HOURLY_UPSERT = """
INSERT INTO stats_hourly (
    bucket_timestamp, total_queries, blocked_queries, cached_queries,
    forwarded_queries, allowed_queries, refused_queries, error_queries,
    latency_sum, latency_samples
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(bucket_timestamp) DO UPDATE SET
    total_queries = total_queries + excluded.total_queries,
    blocked_queries = blocked_queries + excluded.blocked_queries,
    cached_queries = cached_queries + excluded.cached_queries,
    forwarded_queries = forwarded_queries + excluded.forwarded_queries,
    allowed_queries = allowed_queries + excluded.allowed_queries,
    refused_queries = refused_queries + excluded.refused_queries,
    error_queries = error_queries + excluded.error_queries,
    latency_sum = latency_sum + excluded.latency_sum,
    latency_samples = latency_samples + excluded.latency_samples
"""


def anonymize_ip(ip: str) -> str:
    """Masks the last IPv4 octet / the last 80 bits of an IPv6 address (FR-12).

    Unparseable values are reduced to an empty string.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return ""
    if addr.version == 4:
        return str(ipaddress.IPv4Address(int(addr) & 0xFFFFFF00))
    # IPv6: keep the first 48 bits (mask the last 80 bits)
    mask = (2**128 - 1) ^ (2**80 - 1)
    return str(ipaddress.IPv6Address(int(addr) & mask))


class QueryLogWriter:
    """Consumes QueryEvents from the pipeline queue and persists them.

    Batching: a flush happens after ``batch_size`` buffered events or once
    ``flush_interval`` seconds have passed with a non-empty buffer, whichever
    comes first. ``stop()`` drains the queue and performs a final flush, so
    no accepted event is lost on graceful shutdown.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        *,
        batch_size: int = 100,
        flush_interval: float = 2.0,
        log_client_ip: str = "full",
        clock: Callable[[], float] = time.monotonic,
        wall_time: Callable[[], float] = time.time,
    ) -> None:
        self._conn = conn
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._log_client_ip = log_client_ip
        self._clock = clock
        self._wall_time = wall_time
        self._stop_event = asyncio.Event()
        self.flushed_events = 0

    async def run(self, queue: asyncio.Queue[QueryEvent]) -> None:
        """Consumes the queue until stopped; performs a final flush on exit."""
        buffer: list[QueryEvent] = []
        last_flush = self._clock()
        while not self._stop_event.is_set():
            getter = asyncio.ensure_future(queue.get())
            stopper = asyncio.ensure_future(self._stop_event.wait())
            done, pending = await asyncio.wait(
                {getter, stopper},
                timeout=self._flush_interval,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            if getter in done and not getter.cancelled():
                buffer.append(getter.result())
            # Opportunistically drain without blocking
            while len(buffer) < self._batch_size:
                try:
                    buffer.append(queue.get_nowait())
                except asyncio.QueueEmpty:
                    break

            now = self._clock()
            if buffer and (
                len(buffer) >= self._batch_size
                or (now - last_flush) >= self._flush_interval
            ):
                await self._flush(buffer)
                buffer = []
                last_flush = now

        # Graceful shutdown: drain whatever is left and flush it
        while True:
            try:
                buffer.append(queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        await self._flush(buffer)

    async def stop(self) -> None:
        """Signals the run loop to finish; awaits happen in the caller."""
        self._stop_event.set()

    async def _flush(self, buffer: list[QueryEvent]) -> None:
        if not buffer:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._flush_sync, buffer)

    def _flush_sync(self, events: list[QueryEvent]) -> None:
        wall = self._wall_time()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(wall))
        bucket = time.strftime("%Y-%m-%d %H:00:00", time.gmtime(wall))

        rows: list[tuple[object, ...]] = []
        total = blocked = cached = forwarded = allowed = refused = errors = 0
        latency_sum = 0.0
        for event in events:
            rows.append(
                (
                    timestamp,
                    self._client_ip_for_log(event.client_ip),
                    event.question_name,
                    event.question_type,
                    event.status,
                    event.matched_rule,
                    event.upstream,
                    event.latency_ms,
                    event.response_code,
                    event.source,
                    event.occurrences,
                )
            )
            total += event.occurrences
            category = STATUS_CATEGORY.get(event.status)
            if category == "blocked":
                blocked += event.occurrences
            elif category == "cached":
                cached += event.occurrences
            elif category == "forwarded":
                forwarded += event.occurrences
            elif category == "allowed":
                allowed += event.occurrences
            elif category == "refused":
                refused += event.occurrences
            elif category == "error":
                errors += event.occurrences
            # Latency is measured for real DNS queries only; browser reports
            # carry aggregated counts without a per-query latency.
            if event.source == "dns":
                latency_sum += event.latency_ms

        try:
            self._conn.execute("BEGIN")
            self._conn.executemany(_QUERY_LOG_INSERT, rows)
            self._conn.execute(
                _STATS_HOURLY_UPSERT,
                (
                    bucket,
                    total,
                    blocked,
                    cached,
                    forwarded,
                    allowed,
                    refused,
                    errors,
                    latency_sum,
                    # latency samples: only real DNS-measured queries
                    sum(1 for e in events if e.source == "dns"),
                ),
            )
            self._conn.commit()
            self.flushed_events += len(events)
            logger.debug("Flushed %d query log events (bucket %s)", len(events), bucket)
        except Exception:
            self._conn.rollback()
            raise

    def _client_ip_for_log(self, client_ip: str) -> str:
        if self._log_client_ip == "off":
            return ""
        if self._log_client_ip == "anonymized":
            return anonymize_ip(client_ip)
        return client_ip
