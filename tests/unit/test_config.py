"""Unit tests for configuration module."""

import ipaddress

import pytest

from reqko.config import Config, ConfigError


def test_config_tokens_are_optional() -> None:
    """Without token env vars the config is valid: the entry point generates
    an admin token at first start (FR-17 bootstrap alternative)."""
    cfg = Config.from_env({})
    assert cfg.admin_token is None
    assert cfg.read_token is None


def test_config_defaults() -> None:
    cfg = Config.from_env({"REQKO_ADMIN_TOKEN": "test-key-123"})
    assert cfg.admin_token == "test-key-123"
    assert cfg.dns_host == "0.0.0.0"
    assert cfg.dns_port == 53
    assert cfg.api_host == "127.0.0.1"
    assert cfg.api_port == 8080
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
    assert cfg.log_retention_days == 7
    assert cfg.db_path == "/data/reqko.db"
    assert cfg.log_level == "INFO"
    assert cfg.log_client_ip == "full"
    assert cfg.log_batch_size == 100
    assert cfg.log_flush_interval == 2.0
    assert cfg.auth_failure_limit == 10
    assert cfg.auth_failure_window == 60.0
    assert cfg.blocklist_files == []
    assert cfg.blocklist_urls == []
    assert len(cfg.allowed_networks) == 6
    assert ipaddress.ip_network("127.0.0.0/8") in cfg.allowed_networks


def test_config_legacy_env_aliases() -> None:
    """REQKO_API_KEY and REQKO_HTTP_HOST/PORT still work as aliases."""
    cfg = Config.from_env({"REQKO_API_KEY": "legacy-key"})
    assert cfg.admin_token == "legacy-key"

    cfg = Config.from_env(
        {"REQKO_ADMIN_TOKEN": "k", "REQKO_HTTP_HOST": "0.0.0.0", "REQKO_HTTP_PORT": "8888"}
    )
    assert cfg.api_host == "0.0.0.0"
    assert cfg.api_port == 8888


def test_config_custom_valid_values() -> None:
    env = {
        "REQKO_ADMIN_TOKEN": "custom-key",
        "REQKO_READ_TOKEN": "read-only-token",
        "REQKO_DNS_HOST": "127.0.0.1",
        "REQKO_DNS_PORT": "5353",
        "REQKO_API_HOST": "127.0.0.1",
        "REQKO_API_PORT": "8888",
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
        "REQKO_LOG_RETENTION_DAYS": "14",
        "REQKO_DB_PATH": "/tmp/test.db",
        "REQKO_LOG_LEVEL": "debug",
        "REQKO_LOG_CLIENT_IP": "anonymized",
        "REQKO_LOG_BATCH_SIZE": "25",
        "REQKO_LOG_FLUSH_INTERVAL": "0.5",
        "REQKO_AUTH_FAILURE_LIMIT": "5",
        "REQKO_AUTH_FAILURE_WINDOW": "30.0",
        "REQKO_BLOCKLIST_FILES": "C:/lists/a.txt, C:/lists/b.txt",
        "REQKO_BLOCKLIST_URLS": "https://example.com/list.txt",
    }
    cfg = Config.from_env(env)
    assert cfg.admin_token == "custom-key"
    assert cfg.read_token == "read-only-token"
    assert cfg.dns_port == 5353
    assert cfg.api_port == 8888
    assert cfg.metrics_port == 9101
    assert cfg.upstream_dns == [("1.1.1.1", 53), ("8.8.8.8", 5353)]
    assert cfg.upstream_timeout == 3.5
    assert cfg.block_mode == "NXDOMAIN"
    assert cfg.rate_limit_rps == 50
    assert cfg.rate_limit_burst == 75
    assert cfg.log_retention_days == 14
    assert cfg.db_path == "/tmp/test.db"
    assert cfg.log_level == "DEBUG"
    assert cfg.log_client_ip == "anonymized"
    assert cfg.log_batch_size == 25
    assert cfg.log_flush_interval == 0.5
    assert cfg.auth_failure_limit == 5
    assert cfg.auth_failure_window == 30.0
    assert cfg.blocklist_files == ["C:/lists/a.txt", "C:/lists/b.txt"]
    assert cfg.blocklist_urls == ["https://example.com/list.txt"]
    assert cfg.allowed_networks == [
        ipaddress.ip_network("192.168.1.0/24"),
        ipaddress.ip_network("10.0.0.0/16"),
    ]


def test_config_legacy_anonymize_ips_maps_to_anonymized() -> None:
    cfg = Config.from_env({"REQKO_ANONYMIZE_IPS": "true"})
    assert cfg.log_client_ip == "anonymized"

    # Explicit REQKO_LOG_CLIENT_IP wins over the legacy flag
    cfg = Config.from_env({"REQKO_ANONYMIZE_IPS": "true", "REQKO_LOG_CLIENT_IP": "off"})
    assert cfg.log_client_ip == "off"


@pytest.mark.parametrize(
    ("env_var", "val", "match"),
    [
        ("REQKO_DNS_PORT", "0", "REQKO_DNS_PORT"),
        ("REQKO_DNS_PORT", "70000", "REQKO_DNS_PORT"),
        ("REQKO_DNS_PORT", "abc", "REQKO_DNS_PORT"),
        ("REQKO_API_PORT", "70000", "REQKO_API_PORT"),
        ("REQKO_BLOCK_MODE", "DROP", "REQKO_BLOCK_MODE"),
        ("REQKO_ALLOWED_NETWORKS", "invalid-ip/24", "REQKO_ALLOWED_NETWORKS"),
        ("REQKO_UPSTREAM_TIMEOUT", "-1.0", "REQKO_UPSTREAM_TIMEOUT"),
        ("REQKO_RATE_LIMIT_RPS", "0", "REQKO_RATE_LIMIT_RPS"),
        ("REQKO_RATE_LIMIT_BURST", "10", "REQKO_RATE_LIMIT_BURST"),  # burst < rps (10 < 100)
        ("REQKO_CACHE_MAX_TTL", "10", "REQKO_CACHE_MAX_TTL"),  # max < min (10 < 60)
        ("REQKO_LOG_LEVEL", "TRACE", "REQKO_LOG_LEVEL"),
        ("REQKO_LOG_CLIENT_IP", "sometimes", "REQKO_LOG_CLIENT_IP"),
        ("REQKO_LOG_BATCH_SIZE", "0", "REQKO_LOG_BATCH_SIZE"),
        ("REQKO_LOG_FLUSH_INTERVAL", "-1", "REQKO_LOG_FLUSH_INTERVAL"),
        ("REQKO_AUTH_FAILURE_LIMIT", "0", "REQKO_AUTH_FAILURE_LIMIT"),
        ("REQKO_AUTH_FAILURE_WINDOW", "0", "REQKO_AUTH_FAILURE_WINDOW"),
    ],
)
def test_config_invalid_values_raise(env_var: str, val: str, match: str) -> None:
    env = {"REQKO_ADMIN_TOKEN": "valid-key", env_var: val}
    with pytest.raises(ConfigError, match=match):
        Config.from_env(env)
