"""Configuration module for reqko.

Loads and validates all REQKO_* environment variables according to docs/03-architecture.md.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from typing import Literal

BlockMode = Literal["NULL", "NXDOMAIN", "NODATA"]
LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR"]

VALID_BLOCK_MODES: set[str] = {"NULL", "NXDOMAIN", "NODATA"}
VALID_LOG_LEVELS: set[str] = {"DEBUG", "INFO", "WARNING", "ERROR"}

DEFAULT_ALLOWED_NETWORKS = (
    "127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1/128,fe80::/10"
)
DEFAULT_UPSTREAMS = "9.9.9.9:53,149.112.112.112:53"


class ConfigError(ValueError):
    """Raised when configuration validation fails."""


@dataclass(frozen=True)
class Config:
    """Strongly typed application configuration."""

    api_key: str
    dns_host: str = "0.0.0.0"
    dns_port: int = 53
    http_host: str = "0.0.0.0"
    http_port: int = 8080
    metrics_host: str = "127.0.0.1"
    metrics_port: int = 9100
    upstream_dns: list[tuple[str, int]] = field(
        default_factory=lambda: [("9.9.9.9", 53), ("149.112.112.112", 53)]
    )
    upstream_timeout: float = 2.0
    block_mode: BlockMode = "NULL"
    allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        default_factory=lambda: [
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("::1/128"),
            ipaddress.ip_network("fe80::/10"),
        ]
    )
    rate_limit_rps: int = 100
    rate_limit_burst: int = 150
    max_tcp_connections: int = 100
    tcp_idle_timeout: float = 5.0
    cache_size: int = 10000
    cache_min_ttl: int = 60
    cache_max_ttl: int = 86400
    anonymize_ips: bool = False
    log_retention_days: int = 30
    db_path: str = "/data/reqko.db"
    log_level: LogLevel = "INFO"

    @classmethod
    def from_env(cls, environ: dict[str, str] | None = None) -> Config:
        """Create and validate Config from environment variables."""
        env = os.environ if environ is None else environ

        # 1. API key is mandatory
        api_key = env.get("REQKO_API_KEY", "").strip()
        if not api_key:
            raise ConfigError(
                "REQKO_API_KEY is required and cannot be empty. "
                "Refusing to start without an API key."
            )

        # 2. Host and ports
        dns_host = env.get("REQKO_DNS_HOST", "0.0.0.0").strip()
        dns_port = _parse_port(env.get("REQKO_DNS_PORT", "53"), "REQKO_DNS_PORT")

        http_host = env.get("REQKO_HTTP_HOST", "0.0.0.0").strip()
        http_port = _parse_port(env.get("REQKO_HTTP_PORT", "8080"), "REQKO_HTTP_PORT")

        metrics_host = env.get("REQKO_METRICS_HOST", "127.0.0.1").strip()
        metrics_port = _parse_port(
            env.get("REQKO_METRICS_PORT", "9100"), "REQKO_METRICS_PORT"
        )

        # 3. Upstream DNS
        raw_upstreams = env.get("REQKO_UPSTREAM_DNS", DEFAULT_UPSTREAMS)
        upstream_dns = _parse_upstreams(raw_upstreams)

        # 4. Upstream timeout
        try:
            upstream_timeout = float(env.get("REQKO_UPSTREAM_TIMEOUT", "2.0"))
            if upstream_timeout <= 0:
                raise ValueError
        except ValueError as err:
            raise ConfigError(
                f"Invalid REQKO_UPSTREAM_TIMEOUT: {env.get('REQKO_UPSTREAM_TIMEOUT')}. Must be positive float."
            ) from err

        # 5. Block mode
        raw_block_mode = env.get("REQKO_BLOCK_MODE", "NULL").strip().upper()
        if raw_block_mode not in VALID_BLOCK_MODES:
            raise ConfigError(
                f"Invalid REQKO_BLOCK_MODE: '{raw_block_mode}'. Expected one of: NULL, NXDOMAIN, NODATA."
            )
        block_mode: BlockMode = raw_block_mode  # type: ignore[assignment]

        # 6. Allowed networks
        raw_networks = env.get("REQKO_ALLOWED_NETWORKS", DEFAULT_ALLOWED_NETWORKS)
        allowed_networks = _parse_networks(raw_networks)

        # 7. Rate limits
        rate_limit_rps = _parse_positive_int(
            env.get("REQKO_RATE_LIMIT_RPS", "100"), "REQKO_RATE_LIMIT_RPS"
        )
        rate_limit_burst = _parse_positive_int(
            env.get("REQKO_RATE_LIMIT_BURST", "150"), "REQKO_RATE_LIMIT_BURST"
        )
        if rate_limit_burst < rate_limit_rps:
            raise ConfigError(
                f"REQKO_RATE_LIMIT_BURST ({rate_limit_burst}) must be >= REQKO_RATE_LIMIT_RPS ({rate_limit_rps})."
            )

        # 8. TCP limits
        max_tcp_connections = _parse_positive_int(
            env.get("REQKO_MAX_TCP_CONNECTIONS", "100"), "REQKO_MAX_TCP_CONNECTIONS"
        )
        try:
            tcp_idle_timeout = float(env.get("REQKO_TCP_IDLE_TIMEOUT", "5.0"))
            if tcp_idle_timeout <= 0:
                raise ValueError
        except ValueError as err:
            raise ConfigError(
                f"Invalid REQKO_TCP_IDLE_TIMEOUT: {env.get('REQKO_TCP_IDLE_TIMEOUT')}. Must be positive float."
            ) from err

        # 9. Cache settings
        cache_size = _parse_positive_int(
            env.get("REQKO_CACHE_SIZE", "10000"), "REQKO_CACHE_SIZE"
        )
        cache_min_ttl = _parse_positive_int(
            env.get("REQKO_CACHE_MIN_TTL", "60"), "REQKO_CACHE_MIN_TTL"
        )
        cache_max_ttl = _parse_positive_int(
            env.get("REQKO_CACHE_MAX_TTL", "86400"), "REQKO_CACHE_MAX_TTL"
        )
        if cache_max_ttl < cache_min_ttl:
            raise ConfigError(
                f"REQKO_CACHE_MAX_TTL ({cache_max_ttl}) must be >= REQKO_CACHE_MIN_TTL ({cache_min_ttl})."
            )

        # 10. Privacy & retention
        anonymize_ips = _parse_bool(env.get("REQKO_ANONYMIZE_IPS", "false"))
        log_retention_days = _parse_positive_int(
            env.get("REQKO_LOG_RETENTION_DAYS", "30"), "REQKO_LOG_RETENTION_DAYS"
        )

        # 11. Storage & Logging
        db_path = env.get("REQKO_DB_PATH", "/data/reqko.db").strip()
        if not db_path:
            raise ConfigError("REQKO_DB_PATH cannot be empty.")

        raw_log_level = env.get("REQKO_LOG_LEVEL", "INFO").strip().upper()
        if raw_log_level not in VALID_LOG_LEVELS:
            raise ConfigError(
                f"Invalid REQKO_LOG_LEVEL: '{raw_log_level}'. Expected DEBUG, INFO, WARNING, or ERROR."
            )
        log_level: LogLevel = raw_log_level  # type: ignore[assignment]

        return cls(
            api_key=api_key,
            dns_host=dns_host,
            dns_port=dns_port,
            http_host=http_host,
            http_port=http_port,
            metrics_host=metrics_host,
            metrics_port=metrics_port,
            upstream_dns=upstream_dns,
            upstream_timeout=upstream_timeout,
            block_mode=block_mode,
            allowed_networks=allowed_networks,
            rate_limit_rps=rate_limit_rps,
            rate_limit_burst=rate_limit_burst,
            max_tcp_connections=max_tcp_connections,
            tcp_idle_timeout=tcp_idle_timeout,
            cache_size=cache_size,
            cache_min_ttl=cache_min_ttl,
            cache_max_ttl=cache_max_ttl,
            anonymize_ips=anonymize_ips,
            log_retention_days=log_retention_days,
            db_path=db_path,
            log_level=log_level,
        )


def _parse_port(val: str, name: str) -> int:
    try:
        port = int(val.strip())
        if not (1 <= port <= 65535):
            raise ValueError
        return port
    except ValueError as err:
        raise ConfigError(f"Invalid {name}: '{val}'. Must be integer between 1 and 65535.") from err


def _parse_positive_int(val: str, name: str) -> int:
    try:
        res = int(val.strip())
        if res <= 0:
            raise ValueError
        return res
    except ValueError as err:
        raise ConfigError(f"Invalid {name}: '{val}'. Must be positive integer.") from err


def _parse_bool(val: str) -> bool:
    clean = val.strip().lower()
    if clean in {"true", "1", "yes", "on"}:
        return True
    if clean in {"false", "0", "no", "off", ""}:
        return False
    raise ConfigError(f"Invalid boolean value: '{val}'. Expected true/false.")


def _parse_upstreams(raw: str) -> list[tuple[str, int]]:
    items = [item.strip() for item in raw.split(",") if item.strip()]
    if not items:
        raise ConfigError("REQKO_UPSTREAM_DNS cannot be empty.")
    result: list[tuple[str, int]] = []
    for item in items:
        if ":" in item:
            host, port_str = item.rsplit(":", 1)
            port = _parse_port(port_str, "upstream port in REQKO_UPSTREAM_DNS")
        else:
            host = item
            port = 53
        # validate host is IP or hostname
        if not host:
            raise ConfigError(f"Invalid upstream format: '{item}'")
        result.append((host, port))
    return result


def _parse_networks(
    raw: str,
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    items = [item.strip() for item in raw.split(",") if item.strip()]
    if not items:
        raise ConfigError("REQKO_ALLOWED_NETWORKS cannot be empty.")
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for item in items:
        try:
            net = ipaddress.ip_network(item, strict=False)
            nets.append(net)
        except ValueError as err:
            raise ConfigError(f"Invalid network in REQKO_ALLOWED_NETWORKS: '{item}'") from err
    return nets
