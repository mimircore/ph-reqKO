"""Static deployment checks for Dockerfile and docker-compose.yml (NFR-04, NFR-08).

These tests need no Docker: they parse the files and assert the security
properties that the container runtime would enforce. Runtime behaviour
(build, ports, TLS, read-only filesystem) is verified separately with real
Docker commands and marked NOT VERIFIED in the docs when Docker is absent.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = yaml.safe_load((_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
_DOCKERFILE = (_ROOT / "Dockerfile").read_text(encoding="utf-8")
_ENV_EXAMPLE = (_ROOT / ".env.example").read_text(encoding="utf-8")
_CONFIG = (_ROOT / "src" / "reqko" / "config.py").read_text(encoding="utf-8")


# ── compose: reqko service hardening ───────────────────────────────────────────


def test_reqko_service_is_read_only_with_tmpfs() -> None:
    reqko = _COMPOSE["services"]["reqko"]
    assert reqko["read_only"] is True
    assert any(t.startswith("/tmp") for t in reqko["tmpfs"])


def test_cap_drop_all_and_no_new_privileges_on_both_services() -> None:
    for name in ("reqko", "proxy"):
        service = _COMPOSE["services"][name]
        assert "ALL" in service["cap_drop"], name
        assert "no-new-privileges:true" in service["security_opt"], name


def test_resource_limits_present() -> None:
    reqko = _COMPOSE["services"]["reqko"]
    assert reqko["pids_limit"] > 0
    assert reqko["mem_limit"].endswith("m")
    assert float(reqko["cpus"]) > 0
    assert reqko["restart"] == "unless-stopped"


def test_api_port_is_not_published() -> None:
    """The REST API (container 8080) must be reachable only via the proxy."""
    ports = _COMPOSE["services"]["reqko"].get("ports", [])
    assert ports, "DNS ports must be published"
    for port in ports:
        assert ":8080" not in port, f"API port published to host: {port}"
        assert port.endswith(":5353/udp") or port.endswith(":5353/tcp"), port


def test_dns_bind_defaults_to_localhost_and_maps_to_5353() -> None:
    ports = _COMPOSE["services"]["reqko"]["ports"]
    for port in ports:
        assert port.startswith("${REQKO_DNS_BIND:-127.0.0.1}:53:5353"), port
    protocols = {port.rsplit("/", 1)[1] for port in ports}
    assert protocols == {"udp", "tcp"}


def test_required_tokens_use_error_syntax() -> None:
    env = _COMPOSE["services"]["reqko"]["environment"]
    for token in ("REQKO_ADMIN_TOKEN", "REQKO_READ_TOKEN"):
        assert ":?" in env[token], f"{token} must use ${{{token}:?message}}"


def test_proxy_publishes_only_https_and_internal_network() -> None:
    proxy = _COMPOSE["services"]["proxy"]
    assert proxy["ports"] == ["${REQKO_HTTPS_BIND:-127.0.0.1}:443:443"]
    assert set(proxy["networks"]) == {"backend"}
    assert _COMPOSE["networks"]["backend"]["internal"] is True


def test_reqko_has_egress_network_for_upstreams() -> None:
    """backend is internal (proxy<->reqko); reqko needs a second network
    with egress for upstream DNS and blocklist URL refresh."""
    networks = _COMPOSE["services"]["reqko"]["networks"]
    assert "backend" in networks
    assert "upstream" in networks
    assert "internal" not in _COMPOSE["networks"].get("upstream", {})


def test_volume_persists_data() -> None:
    volumes = _COMPOSE["services"]["reqko"]["volumes"]
    assert "reqko-data:/data" in volumes
    assert "reqko-data" in _COMPOSE["volumes"]


def test_wireguard_only_under_vpn_profile() -> None:
    wireguard = _COMPOSE["services"]["wireguard"]
    assert "vpn" in wireguard["profiles"]
    # Not started by a plain `docker compose up -d`
    assert "profiles" in wireguard


def test_no_latest_tags_anywhere() -> None:
    for name, service in _COMPOSE["services"].items():
        image: str = service["image"]
        assert not image.endswith(":latest"), f"{name}: unpinned image {image}"


# ── env file cross-checks ──────────────────────────────────────────────────────


def _referenced_env_vars() -> set[str]:
    compose_text = (_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    return set(re.findall(r"REQKO_[A-Z_]+", compose_text))


def test_all_compose_reqko_vars_exist_in_config() -> None:
    """Every app-consumed REQKO_* variable referenced by compose must be
    understood by config.py. Host-side-only variables are consumed by
    compose itself (port bindings, TZ) and never reach the container."""
    compose_only = {"REQKO_DNS_BIND", "REQKO_HTTPS_BIND", "REQKO_WG_BIND", "TZ"}
    for var in sorted(_referenced_env_vars()):
        if var in compose_only:
            continue
        assert var in _CONFIG, f"{var} referenced in compose but not in config.py"


def test_env_example_covers_required_tokens() -> None:
    assert "REQKO_ADMIN_TOKEN=" in _ENV_EXAMPLE
    assert "REQKO_READ_TOKEN=" in _ENV_EXAMPLE
    # .env must never be committed
    gitignore = (_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert re.search(r"^\.env$", gitignore, flags=re.MULTILINE)


# ── Dockerfile checks ──────────────────────────────────────────────────────────


def test_dockerfile_base_image_pinned() -> None:
    from_lines = re.findall(r"^FROM (\S+)", _DOCKERFILE, flags=re.MULTILINE)
    assert from_lines, "no FROM instruction found"
    for image in from_lines:
        assert image == "python:3.11.9-slim", f"unexpected base image: {image}"
        assert "latest" not in image


def test_dockerfile_runs_as_non_root() -> None:
    user_lines = re.findall(r"^USER (\S+)", _DOCKERFILE, flags=re.MULTILINE)
    assert user_lines, "no USER instruction found"
    assert user_lines[-1] == "10001:10001"


def test_dockerfile_has_healthcheck_using_python() -> None:
    assert "HEALTHCHECK" in _DOCKERFILE
    healthcheck_block = _DOCKERFILE.split("HEALTHCHECK", 1)[1]
    assert "curl" not in healthcheck_block
    assert '"python", "-c"' in healthcheck_block


def test_dockerfile_entrypoint_and_volume() -> None:
    assert 'ENTRYPOINT ["python", "-m", "reqko"]' in _DOCKERFILE
    assert 'VOLUME ["/data"]' in _DOCKERFILE


def test_dockerfile_container_listens_on_unprivileged_ports() -> None:
    assert "EXPOSE 5353/tcp 5353/udp 8080/tcp" in _DOCKERFILE


def test_dockerfile_oci_labels() -> None:
    assert "org.opencontainers.image.source=" in _DOCKERFILE
    assert "org.opencontainers.image.version=" in _DOCKERFILE


# ── proxy configuration ────────────────────────────────────────────────────────


def test_caddyfile_tls_internal_and_security_headers() -> None:
    caddyfile = (_ROOT / "docker" / "Caddyfile").read_text(encoding="utf-8")
    assert "tls internal" in caddyfile
    assert "Strict-Transport-Security" in caddyfile
    assert "X-Content-Type-Options nosniff" in caddyfile
    assert "X-Frame-Options DENY" in caddyfile
    assert "max_size 1MB" in caddyfile
    assert "reverse_proxy reqko:8080" in caddyfile


def test_wireguard_image_pinned() -> None:
    image = _COMPOSE["services"]["wireguard"]["image"]
    assert image == "linuxserver/wireguard:1.0.20260223"
