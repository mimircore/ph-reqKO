"""REST API route handlers (FR-15, FR-16, FR-19).

All SQL uses bound parameters only - user input never enters the SQL text.
Errors are returned as RFC 7807 problem documents.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import time
from collections.abc import Callable
from typing import Any, TypeVar

from aiohttp import web

from reqko.api.app import (
    PROBE_CACHE_TTL,
    STATE_KEY,
    ApiProblem,
    ApiState,
    utcnow_iso,
)
from reqko.dns.upstream import probe_upstream
from reqko.filtering.updater import update_filter_engine

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

VALID_STATUSES: frozenset[str] = frozenset(
    {
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
    }
)

_BLOCKED_STATUSES = ("BLOCKED_BLACKLIST", "BLOCKED_CNAME")
_ALLOWED_STATUSES = ("ALLOWED", "FORWARDED", "CACHED")

MAX_QUERIES_LIMIT = 500
MAX_TOP_LIMIT = 100


async def _in_executor(fn: Callable[[], _T]) -> _T:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, fn)


async def _json_body(request: web.Request) -> dict[str, Any]:
    try:
        data = await request.json()
    except Exception:
        raise ApiProblem(
            400, "Bad Request", detail="Request body must be valid JSON."
        ) from None
    if not isinstance(data, dict):
        raise ApiProblem(400, "Bad Request", detail="Request body must be a JSON object.")
    return data


def _parse_limit(
    request: web.Request,
    name: str = "limit",
    default: int = 50,
    maximum: int = MAX_QUERIES_LIMIT,
) -> int:
    raw = request.query.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ApiProblem(400, "Bad Request", detail=f"Invalid {name}: must be an integer.") from None
    if value < 1 or value > maximum:
        raise ApiProblem(
            400,
            "Bad Request",
            detail=f"Invalid {name}: must be between 1 and {maximum}.",
        )
    return value


def _parse_offset(request: web.Request) -> int:
    raw = request.query.get("offset")
    if raw is None:
        return 0
    try:
        value = int(raw)
    except ValueError:
        raise ApiProblem(400, "Bad Request", detail="Invalid offset: must be an integer.") from None
    if value < 0:
        raise ApiProblem(400, "Bad Request", detail="Invalid offset: must be >= 0.")
    return value


def _parse_timestamp(value: str, name: str, end_of_day: bool) -> str:
    try:
        parsed = datetime.datetime.fromisoformat(value)
    except ValueError:
        raise ApiProblem(
            400,
            "Bad Request",
            detail=f"Invalid {name}: must be an ISO 8601 date or datetime.",
        ) from None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    if end_of_day and (parsed.hour, parsed.minute, parsed.second) == (0, 0, 0):
        parsed = parsed.replace(hour=23, minute=59, second=59)
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def _parse_range(request: web.Request) -> tuple[str | None, str | None]:
    from_raw = request.query.get("from")
    to_raw = request.query.get("to")
    from_ts = _parse_timestamp(from_raw, "from", end_of_day=False) if from_raw else None
    to_ts = _parse_timestamp(to_raw, "to", end_of_day=True) if to_raw else None
    return from_ts, to_ts


def _range_clause(from_ts: str | None, to_ts: str | None, column: str) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if from_ts is not None:
        clauses.append(f"{column} >= ?")
        params.append(from_ts)
    if to_ts is not None:
        clauses.append(f"{column} <= ?")
        params.append(to_ts)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


# ── health (FR-16, public) ─────────────────────────────────────────────────────


async def _db_reachable(state: ApiState) -> bool:
    def _check() -> bool:
        try:
            state.read_conn.execute("SELECT 1").fetchone()
            return True
        except Exception:
            return False

    return await _in_executor(_check)


async def _upstream_reachable(state: ApiState) -> bool:
    now = time.monotonic()
    cache = state.probe_cache
    if now - float(cache["checked_at"]) <= PROBE_CACHE_TTL:
        return bool(cache["ok"])
    ok = await probe_upstream(state.cfg.upstream_dns, timeout=state.probe_timeout)
    cache["ok"] = ok
    cache["checked_at"] = now
    return ok


async def handle_health(request: web.Request) -> web.Response:
    state: ApiState = request.app[STATE_KEY]
    db_ok = await _db_reachable(state)
    upstream_ok = await _upstream_reachable(state)
    snapshot = state.engine.snapshot
    body = {
        "status": "ok" if db_ok else "degraded",
        "uptime_seconds": round(time.monotonic() - state.started_at, 3),
        "database": {"reachable": db_ok},
        "upstream": {"reachable": upstream_ok},
        "blocklist": {
            "domains": snapshot.rules_count,
            "version": snapshot.version,
            "last_update": state.rule_manager.last_update,
        },
        "queue": {
            "depth": state.queue.qsize(),
            "dropped_events": state.drop_counter[0],
        },
    }
    return web.json_response(body, status=200 if db_ok else 503)


async def handle_ready(request: web.Request) -> web.Response:
    """Readiness probe (FR-16): rules are loaded in memory and the DB is reachable."""
    state: ApiState = request.app[STATE_KEY]
    db_ok = await _db_reachable(state)
    ready = db_ok and state.engine.snapshot.rules_count > 0
    body = {
        "status": "ready" if ready else "not_ready",
        "rules_loaded": state.engine.snapshot.rules_count,
        "database": {"reachable": db_ok},
    }
    return web.json_response(body, status=200 if ready else 503)


# ── statistics (FR-11/FR-15) ───────────────────────────────────────────────────


async def handle_stats_summary(request: web.Request) -> web.Response:
    state: ApiState = request.app[STATE_KEY]
    from_ts, to_ts = _parse_range(request)
    where, params = _range_clause(from_ts, to_ts, "timestamp")

    sql = f"""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN status IN (?, ?) THEN 1 ELSE 0 END) AS blocked,
            SUM(CASE WHEN status = 'CACHED' THEN 1 ELSE 0 END) AS cached,
            SUM(CASE WHEN status = 'FORWARDED' THEN 1 ELSE 0 END) AS forwarded,
            SUM(CASE WHEN status = 'ALLOWED' THEN 1 ELSE 0 END) AS allowed,
            SUM(CASE WHEN status LIKE 'REFUSED%' THEN 1 ELSE 0 END) AS refused,
            SUM(CASE WHEN status LIKE 'ERROR%' THEN 1 ELSE 0 END) AS errors,
            AVG(latency_ms) AS avg_latency
        FROM query_log {where}
    """
    sql_params: list[Any] = [*_BLOCKED_STATUSES, *params]

    def _query() -> dict[str, Any]:
        row = state.read_conn.execute(sql, sql_params).fetchone()
        return dict(row) if row is not None else {}

    row = await _in_executor(_query)
    total = int(row.get("total") or 0)
    blocked = int(row.get("blocked") or 0)
    cached = int(row.get("cached") or 0)
    avg_latency = row.get("avg_latency")
    body = {
        "from": from_ts,
        "to": to_ts,
        "total_queries": total,
        "blocked_queries": blocked,
        "blocked_percentage": round(blocked * 100.0 / total, 2) if total else 0.0,
        "cached_queries": cached,
        "cache_hit_percentage": round(cached * 100.0 / total, 2) if total else 0.0,
        "forwarded_queries": int(row.get("forwarded") or 0),
        "allowed_queries": int(row.get("allowed") or 0),
        "refused_queries": int(row.get("refused") or 0),
        "error_queries": int(row.get("errors") or 0),
        "avg_latency_ms": round(float(avg_latency), 3) if avg_latency is not None else None,
    }
    return web.json_response(body)


async def handle_stats_timeseries(request: web.Request) -> web.Response:
    state: ApiState = request.app[STATE_KEY]
    bucket = request.query.get("bucket", "hour")
    if bucket not in ("hour", "day"):
        raise ApiProblem(400, "Bad Request", detail="Invalid bucket: must be 'hour' or 'day'.")
    from_ts, to_ts = _parse_range(request)
    where, params = _range_clause(from_ts, to_ts, "bucket_timestamp")

    agg_cols = (
        "SUM(total_queries) AS total_queries, "
        "SUM(blocked_queries) AS blocked_queries, "
        "SUM(cached_queries) AS cached_queries, "
        "SUM(forwarded_queries) AS forwarded_queries, "
        "SUM(allowed_queries) AS allowed_queries, "
        "SUM(refused_queries) AS refused_queries, "
        "SUM(error_queries) AS error_queries, "
        "SUM(latency_sum) AS latency_sum, "
        "SUM(latency_samples) AS latency_samples"
    )
    if bucket == "hour":
        sql = (
            f"SELECT bucket_timestamp AS bucket, total_queries, blocked_queries, "
            f"cached_queries, forwarded_queries, allowed_queries, refused_queries, "
            f"error_queries, latency_sum, latency_samples "
            f"FROM stats_hourly {where} ORDER BY bucket_timestamp"
        )
    else:
        sql = (
            f"SELECT date(bucket_timestamp) AS bucket, {agg_cols} "
            f"FROM stats_hourly {where} "
            f"GROUP BY date(bucket_timestamp) ORDER BY date(bucket_timestamp)"
        )

    def _query() -> list[dict[str, Any]]:
        rows = state.read_conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    rows = await _in_executor(_query)
    for row in rows:
        samples = row.get("latency_samples") or 0
        latency_sum = row.get("latency_sum") or 0.0
        row["avg_latency_ms"] = (
            round(float(latency_sum) / int(samples), 3) if samples else None
        )
    return web.json_response({"bucket": bucket, "series": rows})


async def handle_stats_top_domains(request: web.Request) -> web.Response:
    state: ApiState = request.app[STATE_KEY]
    status_filter = request.query.get("status", "all")
    if status_filter not in ("blocked", "allowed", "all"):
        raise ApiProblem(400, "Bad Request", detail="Invalid status: must be blocked, allowed, or all.")
    limit = _parse_limit(request, default=10, maximum=MAX_TOP_LIMIT)

    clauses: list[str] = ["question_name != ''"]
    params: list[Any] = []
    if status_filter == "blocked":
        clauses.append(f"status IN ({', '.join('?' for _ in _BLOCKED_STATUSES)})")
        params.extend(_BLOCKED_STATUSES)
    elif status_filter == "allowed":
        clauses.append(f"status IN ({', '.join('?' for _ in _ALLOWED_STATUSES)})")
        params.extend(_ALLOWED_STATUSES)
    where = f"WHERE {' AND '.join(clauses)}"

    sql = (
        f"SELECT question_name, COUNT(*) AS hits FROM query_log {where} "
        f"GROUP BY question_name ORDER BY hits DESC, question_name LIMIT ?"
    )
    params.append(limit)

    def _query() -> list[dict[str, Any]]:
        rows = state.read_conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    rows = await _in_executor(_query)
    return web.json_response({"status": status_filter, "domains": rows})


async def handle_stats_top_clients(request: web.Request) -> web.Response:
    state: ApiState = request.app[STATE_KEY]
    limit = _parse_limit(request, default=10, maximum=MAX_TOP_LIMIT)
    sql = (
        "SELECT client_ip, COUNT(*) AS hits FROM query_log "
        "WHERE client_ip != '' GROUP BY client_ip ORDER BY hits DESC, client_ip LIMIT ?"
    )

    def _query() -> list[dict[str, Any]]:
        rows = state.read_conn.execute(sql, (limit,)).fetchall()
        return [dict(row) for row in rows]

    rows = await _in_executor(_query)
    return web.json_response({"clients": rows})


# ── query log (FR-11/FR-15) ────────────────────────────────────────────────────


async def handle_queries(request: web.Request) -> web.Response:
    state: ApiState = request.app[STATE_KEY]
    limit = _parse_limit(request)
    offset = _parse_offset(request)

    status = request.query.get("status")
    if status is not None and status not in VALID_STATUSES:
        raise ApiProblem(
            400,
            "Bad Request",
            detail=f"Invalid status: must be one of {', '.join(sorted(VALID_STATUSES))}.",
        )
    client = request.query.get("client")
    domain = request.query.get("domain")

    clauses: list[str] = []
    params: list[Any] = []
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    if client is not None:
        clauses.append("client_ip = ?")
        params.append(client)
    if domain is not None:
        clauses.append("question_name LIKE ?")
        params.append(f"%{domain}%")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    count_sql = f"SELECT COUNT(*) FROM query_log {where}"
    rows_sql = (
        f"SELECT id, timestamp, client_ip, question_name, question_type, status, "
        f"matched_rule, upstream, latency_ms, response_code "
        f"FROM query_log {where} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
    )
    rows_params = [*params, limit, offset]

    def _query() -> tuple[int, list[dict[str, Any]]]:
        (total,) = state.read_conn.execute(count_sql, params).fetchone()
        rows = state.read_conn.execute(rows_sql, rows_params).fetchall()
        return int(total), [dict(row) for row in rows]

    total, rows = await _in_executor(_query)
    return web.json_response({"total": total, "limit": limit, "offset": offset, "queries": rows})


# ── custom rules (FR-19) ───────────────────────────────────────────────────────


def _rule_type_for(request: web.Request) -> str:
    if request.path.startswith("/api/v1/allowlist"):
        return "whitelist"
    return "blacklist"


async def _handle_rules_get(request: web.Request) -> web.Response:
    state: ApiState = request.app[STATE_KEY]
    rule_type = _rule_type_for(request)
    rules = await _in_executor(lambda: state.rule_manager.list_rules(rule_type))
    return web.json_response({"rules": rules})


async def _handle_rules_post(request: web.Request) -> web.Response:
    state: ApiState = request.app[STATE_KEY]
    rule_type = _rule_type_for(request)
    body = await _json_body(request)
    domain = body.get("domain")
    if not isinstance(domain, str) or not domain.strip():
        raise ApiProblem(400, "Bad Request", detail="Field 'domain' is required and must be a string.")
    try:
        normalized = await _in_executor(
            lambda: state.rule_manager.add_rule(rule_type, domain)
        )
    except ValueError as exc:
        raise ApiProblem(400, "Bad Request", detail=str(exc)) from None
    return web.json_response(
        {"status": "created", "rule": {"type": rule_type, "domain": normalized}},
        status=201,
    )


async def _handle_rules_delete(request: web.Request) -> web.Response:
    state: ApiState = request.app[STATE_KEY]
    rule_type = _rule_type_for(request)
    domain = request.match_info["domain"]
    try:
        existed = await _in_executor(
            lambda: state.rule_manager.remove_rule(rule_type, domain)
        )
    except ValueError as exc:
        raise ApiProblem(400, "Bad Request", detail=str(exc)) from None
    if not existed:
        raise ApiProblem(404, "Not Found", detail=f"No {rule_type} rule for '{domain}'.")
    return web.json_response(
        {"status": "deleted", "rule": {"type": rule_type, "domain": domain}}
    )


async def handle_allowlist_get(request: web.Request) -> web.Response:
    return await _handle_rules_get(request)


async def handle_allowlist_post(request: web.Request) -> web.Response:
    return await _handle_rules_post(request)


async def handle_allowlist_delete(request: web.Request) -> web.Response:
    return await _handle_rules_delete(request)


async def handle_blocklist_get(request: web.Request) -> web.Response:
    return await _handle_rules_get(request)


async def handle_blocklist_post(request: web.Request) -> web.Response:
    return await _handle_rules_post(request)


async def handle_blocklist_delete(request: web.Request) -> web.Response:
    return await _handle_rules_delete(request)


# ── blocklist refresh (FR-10/FR-15) ───────────────────────────────────────────


async def handle_blocklists_update(request: web.Request) -> web.Response:
    state: ApiState = request.app[STATE_KEY]
    sources: list[str] = [*state.cfg.blocklist_files, *state.cfg.blocklist_urls]
    if not sources:
        raise ApiProblem(
            400,
            "Bad Request",
            detail="No blocklist sources configured "
            "(set REQKO_BLOCKLIST_FILES and/or REQKO_BLOCKLIST_URLS).",
        )
    if state.update_lock.locked():
        raise ApiProblem(409, "Conflict", detail="A blocklist update is already running.")

    success = {"value": False}

    def _on_success(version: int, rules_count: int) -> None:
        success["value"] = True

    async def _update() -> None:
        async with state.update_lock:
            try:
                snapshot = await update_filter_engine(
                    state.engine,
                    sources,
                    version=state.engine.snapshot.version + 1,
                    on_success=_on_success,
                    allowed_local_dirs=state.allowed_local_dirs,
                )
                state.rule_manager.set_base(snapshot)
                if success["value"]:
                    state.rule_manager.save_last_update(utcnow_iso())
            except Exception:
                logger.exception("Background blocklist update failed")

    state.update_task = asyncio.ensure_future(_update())
    return web.json_response(
        {"status": "update_started", "sources": len(sources)}, status=202
    )


# ── registration ───────────────────────────────────────────────────────────────


def register_routes(app: web.Application) -> None:
    app.router.add_get("/health", handle_health)
    app.router.add_get("/ready", handle_ready)
    app.router.add_get("/api/v1/stats/summary", handle_stats_summary)
    app.router.add_get("/api/v1/stats/timeseries", handle_stats_timeseries)
    app.router.add_get("/api/v1/stats/top-domains", handle_stats_top_domains)
    app.router.add_get("/api/v1/stats/top-clients", handle_stats_top_clients)
    app.router.add_get("/api/v1/queries", handle_queries)
    app.router.add_get("/api/v1/allowlist", handle_allowlist_get)
    app.router.add_post("/api/v1/allowlist", handle_allowlist_post)
    app.router.add_delete("/api/v1/allowlist/{domain}", handle_allowlist_delete)
    app.router.add_get("/api/v1/blocklist/custom", handle_blocklist_get)
    app.router.add_post("/api/v1/blocklist/custom", handle_blocklist_post)
    app.router.add_delete("/api/v1/blocklist/custom/{domain}", handle_blocklist_delete)
    app.router.add_post("/api/v1/blocklists/update", handle_blocklists_update)


__all__ = ["register_routes"]
