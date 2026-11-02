# ph-reqKO

A DNS server that blocks ad and tracker domains for your devices — a Pi-hole-style DNS filter written in Python.

> **Status:** work in progress.

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
- [ ] 5. Add statistics collection and a REST API
- [ ] 6. Containerize the application and set up secure remote access
- [ ] 7. Set up monitoring (Prometheus, Grafana) and automated tests (CI)
- [ ] 8. Test performance and security, document limitations and improvements

## Development

```bash
# Create virtual environment and install dependencies
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"

# Run server (port 5454, API key required)
REQKO_API_KEY=changeme REQKO_DNS_PORT=5454 REQKO_DNS_HOST=127.0.0.1 \
  .venv/bin/python -m reqko

# Lint, type check, and test
.venv/bin/ruff check .
.venv/bin/mypy src tests
.venv/bin/pytest -q
```

## Documentation

- [Goal 1 — Research: DNS, Pi-hole, AdGuard Home](docs/01-research.md) (in Russian)
- [Goal 2 — Requirements: functional and non-functional requirements](docs/02-requirements.md) (in Russian)
- [Goal 3 — Architecture and Database Design](docs/03-architecture.md) (in Russian)
- [Goal 4 — Implementation: resolver, filtering, cache, pipeline](docs/04-implementation.md) (in Russian)

## License

Not chosen yet.
