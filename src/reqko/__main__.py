"""Entry point for python -m reqko."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from pathlib import Path

from reqko.config import Config, ConfigError
from reqko.dns.acl import ClientACL
from reqko.dns.cache import DNSCache
from reqko.dns.pipeline import PipelineConfig
from reqko.dns.ratelimit import RateLimiter
from reqko.dns.server import run_dns_servers
from reqko.filtering.engine import FilterEngine
from reqko.filtering.updater import update_filter_engine

logger = logging.getLogger("reqko")


async def _run(config: Config) -> None:
    """Main async entrypoint."""
    # Build pipeline components
    acl = ClientACL(config.allowed_networks)
    rate_limiter = RateLimiter(
        rate_rps=float(config.rate_limit_rps),
        burst=float(config.rate_limit_burst),
    )
    filter_engine = FilterEngine()
    cache = DNSCache(
        max_size=config.cache_size,
        min_ttl=config.cache_min_ttl,
        max_ttl=config.cache_max_ttl,
    )

    log_queue: asyncio.Queue[object] = asyncio.Queue(maxsize=10000)
    log_drop_counter = [0]

    pipeline_cfg = PipelineConfig(
        acl=acl,
        rate_limiter=rate_limiter,
        filter_engine=filter_engine,
        cache=cache,
        upstreams=config.upstream_dns,
        upstream_timeout=config.upstream_timeout,
        block_mode=config.block_mode,
        log_queue=log_queue,  # type: ignore[arg-type]
        log_queue_drop_counter=log_drop_counter,
    )

    # Load local blocklist files into the filter engine before going ready.
    # The REST API list manager and scheduled remote updates are objective 5.
    if config.blocklist_files:
        allowed_dirs = sorted(
            {str(Path(p).resolve().parent) for p in config.blocklist_files}
        )
        logger.info(
            "Loading %d local blocklist file(s): %s",
            len(config.blocklist_files),
            ", ".join(config.blocklist_files),
        )
        snapshot = await update_filter_engine(
            filter_engine,
            config.blocklist_files,
            version=1,
            allowed_local_dirs=allowed_dirs,
        )
        logger.info("Filter rules loaded: %d rules (version %d)", snapshot.rules_count, snapshot.version)
    else:
        logger.info("No blocklist files configured (REQKO_BLOCKLIST_FILES); filter engine starts empty")

    # Start DNS servers
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

    # Graceful shutdown on SIGINT/SIGTERM. loop.add_signal_handler is not
    # supported on Windows (ProactorEventLoop) - fall back to signal.signal.
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
    udp_transport.close()
    tcp_server.close()
    await tcp_server.wait_closed()
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
    logger.info("Starting ph-reqKO DNS resolver v0.1.0")
    logger.info(
        "DNS listeners: %s:%d (UDP+TCP)",
        config.dns_host,
        config.dns_port,
    )
    # The REST API and the Prometheus metrics exporter are NOT started:
    # they are objective 5 and not implemented yet.
    logger.info(
        "REST API (%s:%d) and metrics exporter (%s:%d) are not implemented yet (objective 5)",
        config.http_host,
        config.http_port,
        config.metrics_host,
        config.metrics_port,
    )
    logger.info("Block mode: %s | Upstreams: %s", config.block_mode, config.upstream_dns)

    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
