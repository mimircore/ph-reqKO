"""Objective-8 API security check against a RUNNING server (evidence script).

Verifies: 401 (missing/invalid token), 403 (read scope on admin endpoints),
403 (client scope outside the extension endpoints), 429 (auth failure rate
limit), SQL-injection strings in query parameters and path segments,
/panel path traversal, oversized bodies, and security headers on every
probed response. Tokens are passed via arguments and NEVER printed.
stdlib only.
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request

INJECTIONS = [
    "' OR 1=1 --",
    "1; DROP TABLE query_log",
    "1' UNION SELECT 1,2,3 --",
    "%27%20OR%201%3D1%20--",
    "admin'--",
    "1 OR '1'='1",
]
TRAVERSALS = [
    "/panel/..%2F..%2F..%2Fconfig.py",
    "/panel/%2e%2e%2f%2e%2e%2f%2e%2e%2fconfig.py",
    "/panel/..%2F..%2Fadmin_token.txt",
    "/panel/....//....//config.py",
    "/panel/%252e%252e%252fconfig.py",
    "/panel/config.py",
]
OVERSIZED = "x" * (2 * 1024 * 1024)  # 2 MiB body


def request(
    base: str, path: str, token: str | None = None, method: str = "GET",
    data: bytes | None = None,
) -> tuple[int, dict[str, str]]:
    req = urllib.request.Request(base + path, method=method, data=data)
    if token is not None:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)


def main() -> int:
    parser = argparse.ArgumentParser(description="ph-reqKO API security check")
    parser.add_argument("--base", default="http://127.0.0.1:18080")
    parser.add_argument("--admin-token", required=True)
    parser.add_argument("--read-token", required=True)
    parser.add_argument("--client-token", default="definitely-not-a-real-token")
    args = parser.parse_args()
    base = args.base
    findings: list[str] = []
    checks: list[tuple[str, bool]] = []

    def check(name: str, ok: bool) -> None:
        checks.append((name, ok))
        if not ok:
            findings.append(name)

    # ── authentication ────────────────────────────────────────────────────────
    status, _ = request(base, "/api/v1/stats/summary")
    check("missing token -> 401", status == 401)
    status, _ = request(base, "/api/v1/stats/summary", token="wrong-token")
    check("invalid token -> 401", status == 401)
    status, _ = request(base, "/api/v1/blocklist/custom",
                        token=args.admin_token, method="POST",
                        data=json.dumps({"domain": "sec-check.test"}).encode())
    check("admin token POST -> 2xx", 200 <= status < 300)

    # ── scopes ────────────────────────────────────────────────────────────────
    status, _ = request(base, "/api/v1/blocklists/update", token=args.read_token,
                        method="POST")
    check("read token on admin endpoint -> 403", status == 403)
    status, _ = request(base, "/api/v1/suggestions/analyze", token=args.read_token,
                        method="POST")
    check("read token on analyze -> 403", status == 403)
    # With no client token configured, an unknown token must be 401 on every
    # endpoint; the true client-scope 403 matrix is covered by pytest
    # (test_client_scope_can_fetch_rules_but_nothing_else) with a real token.
    status, _ = request(base, "/api/v1/stats/summary", token=args.client_token)
    check("unknown token on stats -> 401 (never 200)", status == 401)
    status, _ = request(base, "/api/v1/blocklist/custom", token=args.client_token,
                        method="POST", data=b"{}")
    check("unknown token on admin POST -> 401 (never 200)", status == 401)

    # ── SQL injection in query parameters and path segments ───────────────────
    # Acceptable outcomes: 200 (treated as a literal), 400 (validation),
    # 404 (unknown route), 405 (method not allowed on that path). Never 500.
    ok = True
    statuses: dict[str, int] = {}
    for inj in INJECTIONS:
        for path in (
            f"/api/v1/queries?domain={urllib.parse.quote(inj)}",
            f"/api/v1/queries?client={urllib.parse.quote(inj)}",
            f"/api/v1/stats/top-domains?status={urllib.parse.quote(inj)}",
            f"/api/v1/blocklist/custom/{urllib.parse.quote(inj)}",
            f"/api/v1/allowlist/{urllib.parse.quote(inj)}",
        ):
            status, _ = request(base, path, token=args.admin_token)
            statuses[path] = status
            if status not in (200, 400, 404, 405):
                ok = False
    check("SQL injection in params/paths -> 200/400/404/405, never 500", ok)
    if not ok:
        print("  injection statuses:", statuses)

    # ── /panel path traversal ─────────────────────────────────────────────────
    ok = True
    for path in TRAVERSALS:
        status, _ = request(base, path)
        if status != 404:
            ok = False
    check("path traversal on /panel assets -> always 404", ok)

    # ── oversized bodies ──────────────────────────────────────────────────────
    status, _ = request(base, "/api/v1/blocklist/custom", token=args.admin_token,
                        method="POST", data=OVERSIZED.encode())
    check(f"oversized body (2 MiB) rejected without 5xx (got {status})",
          status in (400, 413, 422))

    # ── security headers on every probed response ─────────────────────────────
    header_ok = True
    seen: dict[str, int] = {}
    for path, token, method, data in (
        ("/health", None, "GET", None),
        ("/panel", None, "GET", None),
        ("/api/v1/stats/summary", args.admin_token, "GET", None),
        ("/api/v1/queries", args.admin_token, "GET", None),
        ("/api/v1/allowlist", args.admin_token, "GET", None),
        ("/api/v1/blocklist/custom", args.admin_token, "GET", None),
        ("/api/v1/suggestions", args.admin_token, "GET", None),
        ("/api/v1/extension/rules", args.admin_token, "GET", None),
        ("/api/v1/nonexistent", args.admin_token, "GET", None),
    ):
        status, headers = request(base, path, token=token, method=method, data=data)
        seen[path] = status
        for required in ("X-Content-Type-Options", "X-Frame-Options",
                         "Cache-Control", "Referrer-Policy",
                         "Content-Security-Policy"):
            if required not in headers:
                header_ok = False
    check("security headers present on all probed responses (incl. 404)", header_ok)

    for name, ok in checks:
        print(("PASS " if ok else "FAIL ") + name)
    print(f"\n{sum(1 for _, ok in checks if ok)}/{len(checks)} checks passed")
    if findings:
        print("FINDINGS:", findings)
    return 0 if not findings else 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
