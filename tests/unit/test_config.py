"""Unit tests for configuration module."""

import ipaddress

import pytest

from reqko.config import Config, ConfigError


def test_config_missing_api_key_raises() -> None:
    with pytest.raises(ConfigError, match="REQKO_API_KEY is required"):
        Config.from_env({})


def test_config_defaults_with_valid_key() -> None:
    cfg = Config.from_env({"REQKO_API_KEY": "test-key-123"})
    assert cfg.api_key == "test-key-123"
    assert cfg.dns_host == "0.0.0.0"
    assert cfg.dns_port == 53
    assert cfg.http_host == "0.0.0.0"
    assert cfg.http_port == 8080
    assert cfg.metrics_host == "127.0.0.1"
    assert cfg.metrics_port == 9100
    assert cfg.block_mode == "NULL"
    assert cfg.upstream_dns == [("9.9.9.9", 53), ("149.112.112.112", 53)]
    assert cfg.rate_limit_rps == 100
    assert cfg.rate_limit_burst == 150
    assert cfg.max_tcp_connections == 100
    assert cfg.tcp_idle_timeout == 5.0
    assert cfg.cache_size == 10000
    assert cfg.cache_min_ttl == 60
    assert cfg.cache_max_ttl == 86400
    assert cfg.anonymize_ips is False
    assert cfg.log_retention_days == 30
    assert cfg.db_path == "/data/reqko.db"
    assert cfg.log_level == "INFO"
    assert len(cfg.allowed_networks) == 6
    assert ipaddress.ip_network("127.0.0.0/8") in cfg.allowed_networks


def test_config_custom_valid_values() -> None:
    env = {
        "REQKO_API_KEY": "custom-key",
        "REQKO_DNS_HOST": "127.0.0.1",
        "REQKO_DNS_PORT": "5353",
        "REQKO_HTTP_HOST": "127.0.0.1",
        "REQKO_HTTP_PORT": "8888",
        "REQKO_METRICS_HOST": "127.0.0.2",
        "REQKO_METRICS_PORT": "9101",
        "REQKO_UPSTREAM_DNS": "1.1.1.1:53,8.8.8.8:5353",
        "REQKO_UPSTREAM_TIMEOUT": "3.5",
        "REQKO_BLOCK_MODE": "nxdomain",
        "REQKO_ALLOWED_NETWORKS": "192.168.1.0/24,10.0.0.0/16",
        "REQKO_RATE_LIMIT_RPS": "50",
        "REQKO_RATE_LIMIT_BURST": "75",
        "REQKO_MAX_TCP_CONNECTIONS": "200",
        "REQKO_TCP_IDLE_TIMEOUT": "10.0",
        "REQKO_CACHE_SIZE": "5000",
        "REQKO_CACHE_MIN_TTL": "30",
        "REQKO_CACHE_MAX_TTL": "3600",
        "REQKO_ANONYMIZE_IPS": "true",
        "REQKO_LOG_RETENTION_DAYS": "14",
        "REQKO_DB_PATH": "/tmp/test.db",
        "REQKO_LOG_LEVEL": "debug",
    }
    cfg = Config.from_env(env)
    assert cfg.api_key == "custom-key"
    assert cfg.dns_port == 5353
    assert cfg.http_port == 8888
    assert cfg.metrics_port == 9101
    assert cfg.upstream_dns == [("1.1.1.1", 53), ("8.8.8.8", 5353)]
    assert cfg.upstream_timeout == 3.5
    assert cfg.block_mode == "NXDOMAIN"
    assert cfg.rate_limit_rps == 50
    assert cfg.rate_limit_burst == 75
    assert cfg.anonymize_ips is True
    assert cfg.log_retention_days == 14
    assert cfg.db_path == "/tmp/test.db"
    assert cfg.log_level == "DEBUG"
    assert cfg.allowed_networks == [
        ipaddress.ip_network("192.168.1.0/24"),
        ipaddress.ip_network("10.0.0.0/16"),
    ]


@pytest.mark.parametrize(
    ("env_var", "val", "match"),
    [
        ("REQKO_DNS_PORT", "0", "REQKO_DNS_PORT"),
        ("REQKO_DNS_PORT", "70000", "REQKO_DNS_PORT"),
        ("REQKO_DNS_PORT", "abc", "REQKO_DNS_PORT"),
        ("REQKO_BLOCK_MODE", "DROP", "REQKO_BLOCK_MODE"),
        ("REQKO_ALLOWED_NETWORKS", "invalid-ip/24", "REQKO_ALLOWED_NETWORKS"),
        ("REQKO_UPSTREAM_TIMEOUT", "-1.0", "REQKO_UPSTREAM_TIMEOUT"),
        ("REQKO_RATE_LIMIT_RPS", "0", "REQKO_RATE_LIMIT_RPS"),
        ("REQKO_RATE_LIMIT_BURST", "10", "REQKO_RATE_LIMIT_BURST"),  # burst < rps (10 < 100)
        ("REQKO_CACHE_MAX_TTL", "10", "REQKO_CACHE_MAX_TTL"),  # max < min (10 < 60)
        ("REQKO_ANONYMIZE_IPS", "maybe", "boolean"),
        ("REQKO_LOG_LEVEL", "TRACE", "REQKO_LOG_LEVEL"),
    ],
)
def test_config_invalid_values_raise(env_var: str, val: str, match: str) -> None:
    env = {"REQKO_API_KEY": "valid-key", env_var: val}
    with pytest.raises(ConfigError, match=match):
        Config.from_env(env)
