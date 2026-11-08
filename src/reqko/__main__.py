"""Entry point for python -m reqko."""

from __future__ import annotations

import asyncio
import logging
import secrets
import signal
import sqlite3
import sys
from pathlib import Path

from aiohttp import web

from reqko.api.app import ApiState, create_app, utcnow_iso
from reqko.api.auth import AuthFailureLimiter, TokenStore, hash_token
from reqko.config import Config, ConfigError
from reqko.dns.acl import ClientACL
from reqko.dns.cache import DNSCache
from reqko.dns.pipeline import PipelineConfig, QueryEvent
from reqko.dns.ratelimit import RateLimiter
from reqko.dns.server import run_dns_servers
from reqko.filtering.engine import FilterEngine
from reqko.filtering.rules import RuleManager
from reqko.filtering.suggester import run_suggestion_scheduler
from reqko.filtering.updater import run_blocklist_refresh, update_filter_engine
from reqko.storage.migrations import get_db_connection, init_database
from reqko.storage.retention import RetentionJob
from reqko.storage.settings import get_setting, set_setting
from reqko.storage.writer import QueryLogWriter

logger = logging.getLogger("reqko")

QUERY_QUEUE_SIZE = 10000
ADMIN_TOKEN_HASH_KEY = "admin_token_hash"


async def _bootstrap_tokens(config: Config, conn: sqlite3.Connection) -> tuple[TokenStore, str | None]:
    """Resolves the admin token (FR-17).

    With REQKO_ADMIN_TOKEN set, its hash is used directly. Otherwise the
    hash persisted in system_settings is reused; if none exists, a token is
    generated once, returned for a single print, and only its hash is stored.
    """
    loop = asyncio.get_running_loop()

    def _sync() -> tuple[TokenStore, str | None]:
        generated: str | None = None
        if config.admin_token:
            admin_hash = hash_token(config.admin_token)
        else:
            stored = get_setting(conn, ADMIN_TOKEN_HASH_KEY)
            if stored:
                admin_hash = stored
            else:
                generated = secrets.token_urlsafe(32)
                admin_hash = hash_token(generated)
                set_setting(conn, ADMIN_TOKEN_HASH_KEY, admin_hash)
        read_hash = hash_token(config.read_token) if config.read_token else None
        client_hash = hash_token(config.client_token) if config.client_token else None
        return TokenStore(admin_hash, read_hash, client_hash), generated

    return await loop.run_in_executor(None, _sync)


async def _run(config: Config) -> None:
    """Main async entrypoint: DNS servers and REST API in the same loop."""
    # ── Database ────────────────────────────────────────────────────────────
    conn = init_database(config.db_path)  # writer connection (single owner)
    read_conn = get_db_connection(config.db_path)  # API read connection (WAL)
    retention_conn = get_db_connection(config.db_path)  # retention connection

    # ── Auth bootstrap (FR-17) ──────────────────────────────────────────────
    tokens, generated_token = await _bootstrap_tokens(config, conn)
    if generated_token is not None:
        # Printed exactly once; only the SHA-256 hash is persisted.
        print(
            f"Generated admin API token (shown once; store it now): {generated_token}",
            file=sys.stdout,
            flush=True,
        )

    # ── Filter engine, custom rules, blocklists ────────────────────────────
    engine = FilterEngine()
    rule_manager = RuleManager(engine, conn)
    await asyncio.get_running_loop().run_in_executor(None, rule_manager.load_persisted)

    allowed_dirs = tuple(
        sorted({str(Path(p).resolve().parent) for p in config.blocklist_files})
    )
    sources = [*config.blocklist_files, *config.blocklist_urls]
    if sources:
        logger.info(
            "Loading %d blocklist source(s): %s",
            len(sources),
            ", ".join(sources),
        )
        snapshot = await update_filter_engine(
            engine, sources, allowed_local_dirs=allowed_dirs
        )
        rule_manager.set_base(snapshot)
        await asyncio.get_running_loop().run_in_executor(
            None, rule_manager.save_last_update, utcnow_iso()
        )
        logger.info(
            "Filter rules loaded: %d rules (version %d)",
            engine.snapshot.rules_count,
            engine.snapshot.version,
        )
    else:
        logger.info(
            "No blocklist sources configured (REQKO_BLOCKLIST_FILES / REQKO_BLOCKLIST_URLS); "
            "filter engine starts with custom rules only"
        )

    # ── Query log writer + retention (FR-11, FR-12) ─────────────────────────
    queue: asyncio.Queue[QueryEvent] = asyncio.Queue(maxsize=QUERY_QUEUE_SIZE)
    log_drop_counter = [0]
    writer = QueryLogWriter(
        conn,
        batch_size=config.log_batch_size,
        flush_interval=config.log_flush_interval,
        log_client_ip=config.log_client_ip,
    )
    writer_task = asyncio.create_task(writer.run(queue), name="query-log-writer")
    retention = RetentionJob(retention_conn, retention_days=config.log_retention_days)
    retention_task = asyncio.create_task(retention.run_forever(), name="retention")
    stop_event = asyncio.Event()
    suggest_stop = asyncio.Event()
    suggest_task: asyncio.Task[int] | None = None
    if config.suggest_interval_minutes > 0:
        suggest_task = asyncio.create_task(
            run_suggestion_scheduler(
                conn,
                engine,
                rule_manager,
                window_hours=config.suggest_window_hours,
                min_hits=config.suggest_min_hits,
                interval_minutes=config.suggest_interval_minutes,
                auto_approve_score=config.suggest_auto_approve_score,
                stop_event=suggest_stop,
            ),
            name="domain-suggestions",
        )
    refresh_stop = asyncio.Event()
    refresh_task: asyncio.Task[None] | None = None
    if config.blocklist_refresh_hours > 0 and config.blocklist_urls:
        refresh_task = asyncio.create_task(
            run_blocklist_refresh(
                config, engine, rule_manager, refresh_stop, allowed_dirs
            ),
            name="blocklist-refresh",
        )

    # ── DNS servers ─────────────────────────────────────────────────────────
    acl = ClientACL(config.allowed_networks)
    rate_limiter = RateLimiter(
        rate_rps=float(config.rate_limit_rps),
        burst=float(config.rate_limit_burst),
    )
    cache = DNSCache(
        max_size=config.cache_size,
        min_ttl=config.cache_min_ttl,
        max_ttl=config.cache_max_ttl,
    )
    pipeline_cfg = PipelineConfig(
        acl=acl,
        rate_limiter=rate_limiter,
        filter_engine=engine,
        cache=cache,
        upstreams=config.upstream_dns,
        upstream_timeout=config.upstream_timeout,
        block_mode=config.block_mode,
        log_queue=queue,
        log_queue_drop_counter=log_drop_counter,
    )

    udp_transport, tcp_server = await run_dns_servers(
        pipeline_cfg,
        dns_host=config.dns_host,
        dns_port=config.dns_port,
        tcp_max_connections=config.max_tcp_connections,
        tcp_idle_timeout=config.tcp_idle_timeout,
    )
    logger.info(
        "ph-reqKO DNS resolver ready on %s:%d (UDP+TCP, block_mode=%s)",
        config.dns_host,
        config.dns_port,
        config.block_mode,
    )

    # ── REST API (same event loop) ──────────────────────────────────────────
    state = ApiState(
        cfg=config,
        engine=engine,
        rule_manager=rule_manager,
        read_conn=read_conn,
        queue=queue,
        drop_counter=log_drop_counter,
        tokens=tokens,
        auth_limiter=AuthFailureLimiter(
            limit=config.auth_failure_limit,
            window=config.auth_failure_window,
        ),
        # Browser-extension report rate limit: bursts up to 60 reports,
        # sustained 2/s per client IP
        report_limiter=RateLimiter(rate_rps=2.0, burst=60.0),
        allowed_local_dirs=allowed_dirs,
    )
    app = create_app(state)
    access_log = logging.getLogger("reqko.access") if logger.isEnabledFor(logging.DEBUG) else None
    runner = web.AppRunner(app, access_log=access_log)
    await runner.setup()
    site = web.TCPSite(runner, config.api_host, config.api_port)
    await site.start()
    logger.info(
        "REST API listening on %s:%d (auth: Bearer token; /health is public)",
        config.api_host,
        config.api_port,
    )
    # The Prometheus metrics exporter is still not implemented.
    logger.info(
        "Metrics exporter (%s:%d) is not implemented yet (objective 7)",
        config.metrics_host,
        config.metrics_port,
    )

    # ── Graceful shutdown on SIGINT/SIGTERM ─────────────────────────────────
    # loop.add_signal_handler is not supported on Windows (ProactorEventLoop)
    # - fall back to signal.signal.
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _shutdown() -> None:
        logger.info("Shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _shutdown)
        except NotImplementedError:
            try:
                signal.signal(sig, lambda _sig, _frame: _shutdown())
            except (ValueError, OSError):
                pass

    await stop_event.wait()

    logger.info("Shutting down...")
    await runner.cleanup()
    udp_transport.close()
    tcp_server.close()
    await tcp_server.wait_closed()

    # Flush the accepted query events before closing the DB
    suggest_stop.set()
    if suggest_task is not None:
        await suggest_task
    refresh_stop.set()
    if refresh_task is not None:
        await refresh_task
    await writer.stop()
    await writer_task
    await retention.stop()
    await retention_task

    conn.close()
    read_conn.close()
    retention_conn.close()
    logger.info("ph-reqKO stopped")


def main() -> int:
    """Run the reqko server."""
    try:
        config = Config.from_env()
    except ConfigError as err:
        sys.stderr.write(f"Configuration error: {err}\n")
        return 1

    logging.basicConfig(
        level=getattr(logging, config.log_level, logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logger.info("Starting ph-reqKO DNS resolver + REST API v0.1.0")
    logger.info(
        "DNS listeners: %s:%d (UDP+TCP) | REST API: %s:%d",
        config.dns_host,
        config.dns_port,
        config.api_host,
        config.api_port,
    )
    logger.info(
        "Block mode: %s | Upstreams: %s | Log client IPs: %s",
        config.block_mode,
        config.upstream_dns,
        config.log_client_ip,
    )

    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
