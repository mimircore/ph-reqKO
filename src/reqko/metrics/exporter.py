"""Prometheus metrics for ph-reqKO (NFR-07).

The exposition text format is written BY HAND instead of using the
prometheus_client library. Justification:

- the project needs exactly 8 metric families (NFR-07 list); the library
  pulls in a dependency and an API surface that would be wrapped anyway;
- hand-rolled counters are plain dict increments: O(1), lock-free within
  the single asyncio event loop, and trivially provable as non-blocking
  for the DNS hot path (NFR-03);
- the text exposition format (text/plain; version=0.0.4) for counters,
  a gauge and one histogram is small and stable.

Cardinality policy (NFR-07): NO domain or client labels. qtype is mapped
to a fixed set with unknown types collapsed to "OTHER"; the histogram
label separates bounded query classes (cache/blocked/upstream/error).
"""

from __future__ import annotations

import time

from aiohttp import web

from reqko.dns.acl import ClientACL

# Bucket edges in seconds: sub-millisecond (cache hits) up to seconds
# (slow upstreams). PromQL quantiles are computed by Prometheus.
DURATION_BUCKETS: tuple[float, ...] = (
    0.0005,
    0.001,
    0.0025,
    0.005,
    0.01,
    0.025,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
)

# Bounded label values
KNOWN_QTYPES: frozenset[str] = frozenset({"A", "AAAA", "CNAME", "NS", "SOA", "PTR", "MX", "TXT"})
OTHER_QTYPE = "OTHER"
DURATION_CLASSES = ("cache", "blocked", "upstream", "error")


def qtype_label(qtype_name: str) -> str:
    """Collapses unknown qtypes to OTHER (bounded cardinality)."""
    return qtype_name if qtype_name in KNOWN_QTYPES else OTHER_QTYPE


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _read_resident_memory_bytes() -> int | None:
    """Resident set size in bytes (Linux /proc only; None elsewhere)."""
    try:
        with open("/proc/self/status", encoding="ascii") as status:
            for line in status:
                if line.startswith("VmRSS:"):
                    # "VmRSS:    12345 kB"
                    parts = line.split()
                    return int(parts[1]) * 1024
    except OSError:
        return None
    return None


class MetricsRegistry:
    """In-memory Prometheus registry with O(1), non-raising updates.

    All update methods are plain in-memory operations (dict increments and
    assignments): they never await I/O and are safe to call from the DNS
    hot path. Rendering happens only when /metrics is scraped.
    """

    def __init__(self, started_at: float | None = None) -> None:
        self._started_at = started_at if started_at is not None else time.time()
        self._queries: dict[tuple[str, str], int] = {}
        self._blocked: dict[str, int] = {}
        self._duration_buckets: dict[str, list[int]] = {
            cls: [0] * len(DURATION_BUCKETS) for cls in DURATION_CLASSES
        }
        self._duration_sum: dict[str, float] = {cls: 0.0 for cls in DURATION_CLASSES}
        self._duration_count: dict[str, int] = {cls: 0 for cls in DURATION_CLASSES}
        self._cache_hits = 0
        self._cache_misses = 0
        self._active_rules = 0
        self._dropped_logs = 0

    # ── hot-path updates (O(1), no I/O) ────────────────────────────────────

    def inc_dns_queries(self, protocol: str, qtype_name: str) -> None:
        key = (protocol, qtype_label(qtype_name))
        self._queries[key] = self._queries.get(key, 0) + 1

    def inc_blocked(self, reason: str) -> None:
        self._blocked[reason] = self._blocked.get(reason, 0) + 1

    def observe_duration(self, query_class: str, seconds: float) -> None:
        bucket_list = self._duration_buckets[query_class]
        for i, edge in enumerate(DURATION_BUCKETS):
            if seconds <= edge:
                bucket_list[i] += 1
                break
        else:
            bucket_list[-1] += 1
        self._duration_sum[query_class] += seconds
        self._duration_count[query_class] += 1

    def inc_cache_hit(self) -> None:
        self._cache_hits += 1

    def inc_cache_miss(self) -> None:
        self._cache_misses += 1

    def set_active_rules(self, count: int) -> None:
        self._active_rules = count

    def inc_dropped_logs(self) -> None:
        self._dropped_logs += 1

    # ── exposition ─────────────────────────────────────────────────────────

    def render(self) -> str:
        """Renders the text exposition format (version 0.0.4)."""
        lines: list[str] = []

        # dns_queries_total
        lines.append("# HELP dns_queries_total Total parsed DNS queries by protocol and qtype.")
        lines.append("# TYPE dns_queries_total counter")
        for (protocol, qtype), value in sorted(self._queries.items()):
            lines.append(f'dns_queries_total{{protocol="{protocol}",qtype="{qtype}"}} {value}')

        # dns_blocked_queries_total
        lines.append("# HELP dns_blocked_queries_total Blocked queries by reason (blacklist/cname).")
        lines.append("# TYPE dns_blocked_queries_total counter")
        for reason, value in sorted(self._blocked.items()):
            lines.append(f'dns_blocked_queries_total{{reason="{reason}"}} {value}')

        # dns_query_duration_seconds histogram
        lines.append("# HELP dns_query_duration_seconds DNS query duration by query class.")
        lines.append("# TYPE dns_query_duration_seconds histogram")
        for cls in DURATION_CLASSES:
            for i, edge in enumerate(DURATION_BUCKETS):
                cumulative = sum(self._duration_buckets[cls][: i + 1])
                lines.append(
                    f'dns_query_duration_seconds_bucket{{class="{cls}",le="{_format_float(edge)}"}} {cumulative}'
                )
            inf_total = self._duration_count[cls]
            lines.append(f'dns_query_duration_seconds_bucket{{class="{cls}",le="+Inf"}} {inf_total}')
            lines.append(f'dns_query_duration_seconds_sum{{class="{cls}"}} {_format_float(self._duration_sum[cls])}')
            lines.append(f'dns_query_duration_seconds_count{{class="{cls}"}} {inf_total}')

        # simple counters and gauge
        lines.append("# HELP dns_cache_hits_total Cache hits (served from the in-memory cache).")
        lines.append("# TYPE dns_cache_hits_total counter")
        lines.append(f"dns_cache_hits_total {self._cache_hits}")

        lines.append("# HELP dns_cache_misses_total Cache misses (resolved via an upstream).")
        lines.append("# TYPE dns_cache_misses_total counter")
        lines.append(f"dns_cache_misses_total {self._cache_misses}")

        lines.append("# HELP dns_active_rules_count Currently loaded filter rules.")
        lines.append("# TYPE dns_active_rules_count gauge")
        lines.append(f"dns_active_rules_count {self._active_rules}")

        lines.append("# HELP dns_dropped_logs_total Query-log events dropped when the queue was full.")
        lines.append("# TYPE dns_dropped_logs_total counter")
        lines.append(f"dns_dropped_logs_total {self._dropped_logs}")

        rss = _read_resident_memory_bytes()
        if rss is not None:
            lines.append("# HELP process_resident_memory_bytes Resident memory size of the process.")
            lines.append("# TYPE process_resident_memory_bytes gauge")
            lines.append(f"process_resident_memory_bytes {rss}")

        return "\n".join(lines) + "\n"


def _format_float(value: float) -> str:
    return str(int(value)) if value == int(value) else str(value)


def create_metrics_app(registry: MetricsRegistry, acl: ClientACL) -> web.Application:
    """Standalone metrics site (NOT the main API app): GET /metrics only.

    Client IP must be in REQKO_ALLOWED_NETWORKS, otherwise 403 (NFR-04).
    """

    async def handle_metrics(request: web.Request) -> web.Response:
        peer = request.remote or ""
        if not acl.is_allowed(peer):
            return web.Response(status=403, text="Forbidden\n")
        return web.Response(
            text=registry.render(),
            headers={
                "Content-Type": "text/plain; version=0.0.4; charset=utf-8",
                "Cache-Control": "no-store",
            },
        )

    app = web.Application()
    app.router.add_get("/metrics", handle_metrics)
    return app
