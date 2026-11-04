# ph-reqKO

A DNS server that blocks ad and tracker domains for your devices — a Pi-hole-style DNS filter written in Python.

> **Status:** the resolver core (objective 4), statistics + REST API (objective 5), the charts-only web panel, and containerization (objective 6, runtime-verified on Docker Desktop) are implemented and tested. Objective 7 adds Prometheus metrics (hand-written exposition, NFR-07), a provisioned Prometheus + Grafana stack in compose, and a GitHub Actions CI workflow (NFR-09 — written and actionlint-validated, but never run on GitHub: pushing is out of scope for now). Objective 8 (performance/security validation) is pending.

## Goal

Build a DNS server in Python that:

- blocks advertising and tracker domains using domain blocklists;
- caches upstream answers and keeps query statistics;
- is managed through a REST API;
- ships with a minimal web panel showing what was blocked (charts only);
- is deployed in a container with secure remote access, monitoring, and CI.

## Planned stack

Python (`asyncio`), SQLite, REST API, Docker / Docker Compose, Prometheus, Grafana, GitHub Actions.

## Roadmap

- [x] 1. Study how DNS works and existing solutions (Pi-hole, AdGuard Home)
- [x] 2. Define functional and non-functional requirements
- [x] 3. Design the architecture and the database schema
- [x] 4. Build the resolver with caching and blocklist filtering
- [x] 5. Add statistics collection and a REST API (incl. the charts-only web panel)
- [x] 6. Containerize the application and set up secure remote access (runtime-verified on Docker Desktop)
- [x] 7. Set up monitoring (Prometheus, Grafana) and automated tests (CI written and lint-validated; first GitHub run pending push)
- [ ] 8. Test performance and security, document limitations and improvements

## Development

Python 3.11+ is required.

### Windows (PowerShell)

```powershell
# Create virtual environment and install dependencies
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"

# Lint, type check, and test
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy src tests
.\.venv\Scripts\python.exe -m pytest -q

# Run server: DNS on 5454, REST API on 127.0.0.1:8080
$env:REQKO_ADMIN_TOKEN='changeme-admin-token'
$env:REQKO_DNS_PORT='5454'; $env:REQKO_DNS_HOST='127.0.0.1'
$env:REQKO_API_PORT='8080'
$env:REQKO_BLOCKLIST_FILES='C:\path\to\blocklist.txt'
$env:REQKO_DB_PATH='C:\path\to\reqko.db'
.\.venv\Scripts\python.exe -m reqko

# Query the API (admin token: read + write; GET /health needs no token)
curl.exe -s -H "Authorization: Bearer changeme-admin-token" http://127.0.0.1:8080/api/v1/stats/summary

# Open the charts-only web panel (reads a token in the browser, sessionStorage)
#   http://127.0.0.1:8080/panel
# Enter the admin or read token when prompted; the panel refreshes every 10 s.
```

### Linux (bash)

```bash
# Create virtual environment and install dependencies
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Lint, type check, and test
.venv/bin/ruff check .
.venv/bin/mypy src tests
.venv/bin/pytest -q

# Run server
REQKO_ADMIN_TOKEN=changeme-admin-token REQKO_DNS_PORT=5454 REQKO_DNS_HOST=127.0.0.1 \
  REQKO_DB_PATH=/tmp/reqko.db REQKO_BLOCKLIST_FILES=/path/to/blocklist.txt \
  .venv/bin/python -m reqko
```

### Configuration (REQKO_* environment variables)

| Variable | Default | Description |
|---|---|---|
| `REQKO_ADMIN_TOKEN` | *(generated once, printed to stdout)* | Admin API token (all endpoints) |
| `REQKO_READ_TOKEN` | *(none)* | Optional read-only API token (GET only) |
| `REQKO_DNS_HOST` / `REQKO_DNS_PORT` | `0.0.0.0` / `53` | DNS listeners (UDP+TCP) |
| `REQKO_API_HOST` / `REQKO_API_PORT` | `127.0.0.1` / `8080` | REST API bind address |
| `REQKO_DB_PATH` | `/data/reqko.db` | SQLite database file (WAL) |
| `REQKO_BLOCKLIST_FILES` | *(none)* | Comma-separated local blocklist files loaded at startup |
| `REQKO_BLOCKLIST_URLS` | *(none)* | Comma-separated http(s) blocklist URLs (refresh via `POST /api/v1/blocklists/update`) |
| `REQKO_BLOCK_MODE` | `NULL` | Blocking answer: `NULL` (0.0.0.0), `NXDOMAIN`, `NODATA` |
| `REQKO_LOG_CLIENT_IP` | `full` | Query-log privacy: `full` / `anonymized` (mask last IPv4 octet / last 80 IPv6 bits) / `off` |
| `REQKO_LOG_RETENTION_DAYS` | `7` | `query_log` retention (deleted at startup and hourly) |
| `REQKO_LOG_BATCH_SIZE` / `REQKO_LOG_FLUSH_INTERVAL` | `100` / `2.0` | Log writer batching |
| `REQKO_AUTH_FAILURE_LIMIT` / `REQKO_AUTH_FAILURE_WINDOW` | `10` / `60.0` | Failed-auth rate limit per IP (429) |
| `REQKO_UPSTREAM_DNS` | `9.9.9.9:53,149.112.112.112:53` | Upstream resolvers (fallback list) |
| `REQKO_ALLOWED_NETWORKS` | RFC 1918 + loopback | ACL for DNS clients |
| `REQKO_RATE_LIMIT_RPS` / `REQKO_RATE_LIMIT_BURST` | `100` / `150` | Per-client DNS rate limiting |
| `REQKO_LOG_LEVEL` | `INFO` | Process log level |

The full variable list lives in [docs/03-architecture.md](docs/03-architecture.md) (section 9); the API surface is documented in [docs/05-implementation.md](docs/05-implementation.md).

## Docker quick start

> **Note:** the container setup was written and statically tested, but never executed on the
> development machine (Docker is not installed there) — runtime behaviour is marked NOT VERIFIED
> in [docs/06-implementation.md](docs/06-implementation.md).

```powershell
# 1. Copy the example env and generate tokens (never commit .env)
Copy-Item .env.example .env
# PowerShell token generator:
-join ((48..57) + (97..122) | Get-Random -Count 32 | ForEach-Object {[char]$_})
# put the result into REQKO_ADMIN_TOKEN and REQKO_READ_TOKEN in .env

# 2. Build and start (DNS on 127.0.0.1:53 -> container 5353, HTTPS on 127.0.0.1:443)
docker compose up -d
docker compose ps
```

```bash
# 1. Copy the example env and generate tokens (never commit .env)
cp .env.example .env
# bash token generator:
openssl rand -hex 32
# put the result into REQKO_ADMIN_TOKEN and REQKO_READ_TOKEN in .env

# 2. Build and start
docker compose up -d
docker compose ps
```

- **Panel/API:** open `https://localhost/panel` and accept (or trust) the Caddy internal-CA
  certificate: the proxy uses `tls internal` so it works fully offline. To install the root CA
  instead, export it from the proxy container; for a real domain + Let's Encrypt see
  [docs/06-remote-access.md](docs/06-remote-access.md).
- **DNS:** point a LAN client at the host's port 53 (default bind is `127.0.0.1` — change
  `REQKO_DNS_BIND` in `.env` to your LAN IP to serve the network; keep the ACL and rate limit on).
- **Blocklist (first start):** the fresh volume is empty, so seed it once and reload:
  `docker compose exec reqko sh -c "printf 'ads.example.com\ndoubleclick.net\n' > /data/blocklist.txt"`
  then `POST https://localhost/api/v1/blocklists/update` with the admin token (or restart).
- **Remote access:** the intended path is the optional WireGuard profile
  (`docker compose --profile vpn up -d`) — nothing exposed publicly; VPN clients use
  `172.28.0.10:53` (fixed address) as their DNS. **All three bind variables default to
  `127.0.0.1`** (`REQKO_DNS_BIND`, `REQKO_HTTPS_BIND`, `REQKO_WG_BIND`) and must be changed
  in `.env` for real remote access — see
  [docs/06-remote-access.md](docs/06-remote-access.md) (threat model and peer setup).
- **Monitoring (objective 7):** Grafana runs at `http://127.0.0.1:3000` (login `admin`,
  password = `GRAFANA_ADMIN_PASSWORD` from `.env`) with a provisioned `ph-reqKO overview`
  dashboard; Prometheus scrapes the resolver internally and is **not** published to the host —
  raw metrics are visible from inside the compose network at `http://reqko:9100/metrics`, e.g.
  `docker compose exec reqko python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:9100/metrics').read().decode())"`.
  See [docs/07-implementation.md](docs/07-implementation.md).

## Demo

One-command demo on Windows PowerShell (uses demo-only tokens, see the script header):

```powershell
# Terminal 1: create the demo blocklist (if missing), start DNS on 5454 + API on 8080
powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1

# Terminal 2: send the demo query list and see per-query results + a summary
.\.venv\Scripts\python.exe scripts\send_queries.py
```

Then open **http://127.0.0.1:8080/panel** and enter the read token printed by the
launcher (`read-secret-456`). The panel tiles, charts and top lists fill in as
queries arrive.

## Documentation

- [Goal 1 — Research: DNS, Pi-hole, AdGuard Home](docs/01-research.md) (in Russian)
- [Goal 2 — Requirements: functional and non-functional requirements](docs/02-requirements.md) (in Russian)
- [Goal 3 — Architecture and Database Design](docs/03-architecture.md) (in Russian)
- [Goal 4 — Implementation: resolver, filtering, cache, pipeline](docs/04-implementation.md) (in Russian)
- [Goal 5 — Implementation: statistics storage and REST API](docs/05-implementation.md) (in Russian)
- [Goal 6 — Implementation: containerization and secure remote access](docs/06-implementation.md) (in Russian)
- [Goal 6 — Remote access guide: threat model, VPN setup](docs/06-remote-access.md) (in Russian)
- [Goal 7 — Implementation: Prometheus metrics, Grafana, CI](docs/07-implementation.md) (in Russian)

## License

Not chosen yet.
