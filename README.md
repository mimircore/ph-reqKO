# ph-reqKO

A DNS server that blocks ad and tracker domains for your devices — a Pi-hole-style DNS filter written in Python.

> **Status:** the resolver core (objective 4) and the statistics storage + REST API (objective 5) are implemented and tested: UDP/TCP DNS forwarding, caching with TTL, blocklist filtering with allowlist priority, CNAME uncloaking, ACL, rate limiting; batched SQLite query-log writer with hourly aggregates and retention; a token-authenticated REST API (`/health`, `/ready`, stats, query log, custom rules, blocklist refresh); a charts-only web panel at `/panel` (canvas, no CDN). Prometheus metrics and Docker deployment are not implemented yet (objectives 6–8).

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
- [ ] 6. Containerize the application and set up secure remote access
- [ ] 7. Set up monitoring (Prometheus, Grafana) and automated tests (CI)
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

## Browser extension

A Manifest V3 extension (Chrome/Edge/Firefox 113+) blocks ad and tracker
domains **inside the browser** using the same lists as your ph-reqKO server -
no system DNS change needed. The server exposes a dedicated, least-privilege
client scope for it: `REQKO_CLIENT_TOKEN` may only call
`GET /api/v1/extension/rules` and `POST /api/v1/extension/report`.

Load it unpacked (`chrome://extensions` -> Developer mode) from the
`extension/` directory, then set the server URL and the client token in the
extension options. Full install steps, limits and security notes:
[docs/06-browser-extension.md](docs/06-browser-extension.md).

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

## License

Not chosen yet.
