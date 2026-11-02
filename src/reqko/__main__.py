"""Entry point for python -m reqko."""

from __future__ import annotations

import logging
import sys

from reqko.config import Config, ConfigError


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
    logger = logging.getLogger("reqko")
    logger.info("Initializing ph-reqKO DNS resolver (version 0.1.0)")
    logger.info("DNS listener configured on %s:%d", config.dns_host, config.dns_port)
    logger.info("HTTP API configured on %s:%d", config.http_host, config.http_port)
    logger.info("Metrics site configured on %s:%d", config.metrics_host, config.metrics_port)
    logger.info("Block mode: %s | Upstreams: %s", config.block_mode, config.upstream_dns)
    return 0


if __name__ == "__main__":
    sys.exit(main())
