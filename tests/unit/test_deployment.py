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
        assert port.endswith(":53/udp") or port.endswith(":53/tcp"), port


def test_dns_bind_defaults_to_localhost_and_maps_to_53() -> None:
    ports = _COMPOSE["services"]["reqko"]["ports"]
    for port in ports:
        assert port.startswith("${REQKO_DNS_BIND:-127.0.0.1}:53:53"), port
    protocols = {port.rsplit("/", 1)[1] for port in ports}
    assert protocols == {"udp", "tcp"}


def test_reqko_binds_53_without_root() -> None:
    """Port 53 is bound directly via the unprivileged-port sysctl: no root,
    no CAP_NET_BIND_SERVICE."""
    reqko = _COMPOSE["services"]["reqko"]
    assert reqko["sysctls"]["net.ipv4.ip_unprivileged_port_start"] == 0
    assert reqko["environment"]["REQKO_DNS_PORT"] == "53"
    assert "ALL" in reqko["cap_drop"]  # still no capabilities at all


def test_reqko_has_fixed_ip_for_vpn_clients() -> None:
    """VPN clients use the fixed backend address 172.28.0.10 as DNS."""
    reqko_networks = _COMPOSE["services"]["reqko"]["networks"]
    assert reqko_networks["backend"]["ipv4_address"] == "172.28.0.10"
    backend = _COMPOSE["networks"]["backend"]
    assert backend["internal"] is True
    assert backend["ipam"]["config"][0]["subnet"] == "172.28.0.0/24"


def test_published_services_are_on_edge_network() -> None:
    """internal networks cannot publish ports: proxy and wireguard must
    also sit on a non-internal `edge` network."""
    edge = _COMPOSE["networks"]["edge"]
    assert "internal" not in edge
    proxy_networks = _COMPOSE["services"]["proxy"]["networks"]
    assert "edge" in proxy_networks and "backend" in proxy_networks
    wg_networks = _COMPOSE["services"]["wireguard"]["networks"]
    assert "edge" in wg_networks and "backend" in wg_networks
    # reqko itself needs no published API: it stays off `edge`
    assert "edge" not in _COMPOSE["services"]["reqko"]["networks"]


def test_required_tokens_use_error_syntax() -> None:
    env = _COMPOSE["services"]["reqko"]["environment"]
    for token in ("REQKO_ADMIN_TOKEN", "REQKO_READ_TOKEN"):
        assert ":?" in env[token], f"{token} must use ${{{token}:?message}}"


def test_proxy_publishes_only_https() -> None:
    proxy = _COMPOSE["services"]["proxy"]
    # Caddy listens on unprivileged 8443 inside the container (it runs with
    # cap_drop: ALL and its file capability is stripped at build time)
    assert proxy["ports"] == ["${REQKO_HTTPS_BIND:-127.0.0.1}:443:8443"]
    assert _COMPOSE["networks"]["backend"]["internal"] is True


def test_caddy_image_strips_file_capability() -> None:
    """The stock caddy image sets cap_net_bind_service on its binary; with
    cap_drop: ALL that execve fails (EPERM). The custom build strips it."""
    caddy_dockerfile = (_ROOT / "docker" / "caddy" / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM caddy:2.8.4" in caddy_dockerfile
    assert "setcap -r /usr/bin/caddy" in caddy_dockerfile
    proxy = _COMPOSE["services"]["proxy"]
    assert proxy["build"]["context"].endswith("docker/caddy")


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


def test_dockerfile_container_listens_on_dns_53_and_api_8080() -> None:
    assert "EXPOSE 53/tcp 53/udp 8080/tcp" in _DOCKERFILE


def test_dockerfile_oci_labels() -> None:
    assert "org.opencontainers.image.source=" in _DOCKERFILE
    assert "org.opencontainers.image.version=" in _DOCKERFILE


# ── proxy configuration ────────────────────────────────────────────────────────


def test_caddyfile_tls_internal_and_security_headers() -> None:
    caddyfile = (_ROOT / "docker" / "Caddyfile").read_text(encoding="utf-8")
    assert "localhost:8443" in caddyfile
    assert "tls internal" in caddyfile
    assert "Strict-Transport-Security" in caddyfile
    assert "X-Content-Type-Options nosniff" in caddyfile
    assert "X-Frame-Options DENY" in caddyfile
    assert "max_size 1MB" in caddyfile
    assert "reverse_proxy reqko:8080" in caddyfile


def test_wireguard_image_pinned() -> None:
    image = _COMPOSE["services"]["wireguard"]["image"]
    assert image == "linuxserver/wireguard:1.0.20260223"
