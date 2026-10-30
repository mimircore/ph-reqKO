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
- [ ] 3. Design the architecture and the database schema
- [ ] 4. Build the resolver with caching and blocklist filtering
- [ ] 5. Add statistics collection and a REST API
- [ ] 6. Containerize the application and set up secure remote access
- [ ] 7. Set up monitoring (Prometheus, Grafana) and automated tests (CI)
- [ ] 8. Test performance and security, document limitations and improvements

## Documentation

- [Goal 1 — Research: DNS, Pi-hole, AdGuard Home](docs/01-research.md) (in Russian)
- [Goal 2 — Requirements: functional and non-functional requirements](docs/02-requirements.md) (in Russian)

## License

Not chosen yet.
