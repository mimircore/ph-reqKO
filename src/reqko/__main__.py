"""Entry point for python -m reqko."""

from __future__ import annotations

import asyncio
import logging
import signal
import sys

from reqko.config import Config, ConfigError
from reqko.dns.acl import ClientACL
from reqko.dns.cache import DNSCache
from reqko.dns.pipeline import PipelineConfig
from reqko.dns.ratelimit import RateLimiter
from reqko.dns.server import run_dns_servers
from reqko.filtering.engine import FilterEngine

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

    # Start DNS servers
    udp_transport, tcp_server = await run_dns_servers(
        pipeline_cfg,
        dns_host=config.dns_host,
        dns_port=config.dns_port,
        tcp_max_connections=config.max_tcp_connections,
        tcp_idle_timeout=config.tcp_idle_timeout,
    )

    logger.info(
        "ph-reqKO DNS resolver ready on %s:%d (block_mode=%s)",
        config.dns_host,
        config.dns_port,
        config.block_mode,
    )

    # Graceful shutdown on SIGINT/SIGTERM
    loop = asyncio.get_event_loop()
    stop_event = asyncio.Event()

    def _shutdown() -> None:
        logger.info("Shutdown signal received")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _shutdown)

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
    logger.info("DNS: %s:%d | API: %s:%d | Metrics: %s:%d",
                config.dns_host, config.dns_port,
                config.http_host, config.http_port,
                config.metrics_host, config.metrics_port)
    logger.info("Block mode: %s | Upstreams: %s", config.block_mode, config.upstream_dns)

    try:
        asyncio.run(_run(config))
    except KeyboardInterrupt:
        pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
