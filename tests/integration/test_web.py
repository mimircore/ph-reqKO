"""Integration tests for the web panel (FR-18): static serving, CSP, security.

The panel is public static content with no data inside; the JS fetches the
API with a Bearer token. API endpoints must still require tokens.
"""

from __future__ import annotations

import asyncio

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from reqko.api.app import ApiState, create_app
from reqko.api.auth import AuthFailureLimiter, TokenStore, hash_token
from reqko.config import Config
from reqko.filtering.engine import FilterEngine
from reqko.filtering.rules import RuleManager
from reqko.storage.migrations import init_database

ADMIN_TOKEN = "admin-token-123"
AUTH = {"Authorization": f"Bearer {ADMIN_TOKEN}"}

PANEL_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; frame-ancestors 'none'"
)
API_CSP = "default-src 'none'; frame-ancestors 'none'"


async def _start() -> TestClient[web.Request, web.Application]:
    conn = init_database(":memory:")
    cfg = Config.from_env({"REQKO_ADMIN_TOKEN": ADMIN_TOKEN})
    engine = FilterEngine()
    rule_manager = RuleManager(engine, conn)
    rule_manager.load_persisted()
    state = ApiState(
        cfg=cfg,
        engine=engine,
        rule_manager=rule_manager,
        read_conn=conn,
        queue=asyncio.Queue(maxsize=100),
        drop_counter=[0],
        tokens=TokenStore(hash_token(ADMIN_TOKEN), None),
        auth_limiter=AuthFailureLimiter(limit=10, window=60.0),
        probe_timeout=0.05,
    )
    client = TestClient(TestServer(create_app(state)))
    await client.start_server()
    return client


def _no_inline_script(html: str) -> bool:
    """Every <script ...> occurrence must reference an external src file."""
    index = 0
    found_script = False
    while True:
        index = html.find("<script", index)
        if index == -1:
            return found_script  # at least one script tag expected (src=)
        found_script = True
        tag_end = html.find(">", index)
        assert tag_end != -1
        tag = html[index : tag_end + 1]
        assert "src=" in tag, f"inline script found: {tag!r}"
        index = tag_end


async def test_panel_index_served_with_strict_csp() -> None:
    client = await _start()
    try:
        resp = await client.get("/panel")
        assert resp.status == 200
        assert resp.content_type == "text/html"
        assert resp.headers["Content-Security-Policy"] == PANEL_CSP
        html = await resp.text()
        assert "chart-timeseries" in html
        assert "chart-top-domains" in html
        assert "chart-top-clients" in html
        assert _no_inline_script(html)
    finally:
        await client.close()


async def test_panel_assets_content_types_and_csp() -> None:
    client = await _start()
    try:
        js = await client.get("/panel/panel.js")
        assert js.status == 200
        assert js.content_type in ("application/javascript", "text/javascript")
        assert js.headers["Content-Security-Policy"] == PANEL_CSP
        js_text = await js.text()
        assert "sessionStorage" in js_text
        assert "apiFetch" in js_text

        css = await client.get("/panel/panel.css")
        assert css.status == 200
        assert css.content_type == "text/css"
        assert css.headers["Content-Security-Policy"] == PANEL_CSP
    finally:
        await client.close()


async def test_panel_unknown_asset_and_traversal_404() -> None:
    client = await _start()
    try:
        resp = await client.get("/panel/nope.js")
        assert resp.status == 404
        assert resp.content_type == "application/problem+json"

        # Path traversal attempts must never reach the filesystem. (Plain
        # "/panel/.." is normalized client-side by yarl and never sent.)
        for path in (
            "/panel/..%2F..%2Fconfig.py",
            "/panel/%2e%2e%2f%2e%2e%2fconfig.py",
            "/panel/config.py",
            "/panel/panel.js%2F",
        ):
            resp = await client.get(path)
            assert resp.status == 404, path
    finally:
        await client.close()


async def test_api_still_requires_token_and_keeps_own_csp() -> None:
    client = await _start()
    try:
        resp = await client.get("/api/v1/stats/summary")
        assert resp.status == 401
        assert resp.headers["Content-Security-Policy"] == API_CSP

        resp = await client.get("/api/v1/stats/summary", headers=AUTH)
        assert resp.status == 200
        assert resp.headers["Content-Security-Policy"] == API_CSP

        # /health stays public
        assert (await client.get("/health")).status == 200
    finally:
        await client.close()


async def test_panel_assets_are_loadable_from_package() -> None:
    """The whitelist maps only to files that actually exist in reqko/web."""
    from reqko.api.routes import PANEL_ASSETS, PANEL_DIR

    assert PANEL_DIR.is_dir()
    assert (PANEL_DIR / "index.html").is_file()
    for name in PANEL_ASSETS:
        assert (PANEL_DIR / name).is_file(), name
