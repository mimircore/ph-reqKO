"""Integration tests for the blocklist updater (FR-10).

Uses a local aiohttp test server for HTTP sources (no external network) and
temporary files for local list sources.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from reqko.config import Config
from reqko.filtering.engine import FilterEngine, FilterSnapshot
from reqko.filtering.updater import (
    UpdaterError,
    _refresh_once,
    fetch_list,
    run_blocklist_refresh,
    update_filter_engine,
)


def _engine_with(rule: str) -> FilterEngine:
    return FilterEngine(
        FilterSnapshot(
            exact_set=frozenset({rule}),
            wildcard_set=frozenset(),
            allow_exact_set=frozenset(),
            allow_wildcard_set=frozenset(),
            version=1,
        )
    )


async def test_successful_local_update_swaps_rules(tmp_path: Path) -> None:
    """A successful update replaces the whole rule set atomically."""
    list_file = tmp_path / "lists" / "block.txt"
    list_file.parent.mkdir()
    list_file.write_text(
        "# comment line\n||ads-new.com^\nplain-new.com\n0.0.0.0 host-new.com\n",
        encoding="utf-8",
    )
    engine = _engine_with("old-rule.com")

    snapshot = await update_filter_engine(
        engine,
        [str(list_file)],
        version=2,
        allowed_local_dirs=[str(tmp_path / "lists")],
    )

    assert snapshot.version == 2
    assert snapshot.rules_count == 3
    assert engine.match("ads-new.com").is_blocked
    assert engine.match("sub.ads-new.com").is_blocked  # wildcard
    assert engine.match("plain-new.com").is_blocked
    assert engine.match("host-new.com").is_blocked
    # Old rules are gone: the update swaps, not merges
    assert not engine.match("old-rule.com").is_blocked


async def test_http_500_keeps_old_snapshot(tmp_path: Path) -> None:
    """FR-10: an HTTP 500 from a list source keeps the last working rules."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response(status=500, text="internal error")

    app = web.Application()
    app.router.add_get("/list", handler)
    server = TestServer(app)
    await server.start_server()
    try:
        url = str(server.make_url("/list"))
        engine = _engine_with("old-rule.com")

        snapshot = await update_filter_engine(engine, [url], version=2)

        assert snapshot.version == 1
        assert engine.match("old-rule.com").is_blocked
        assert not engine.match("ads-new.com").is_blocked
    finally:
        await server.close()


async def test_connection_error_keeps_old_snapshot(tmp_path: Path) -> None:
    """FR-10: a connection error (refused TCP) keeps the last working rules."""
    engine = _engine_with("old-rule.com")

    # Port 1 on loopback: connection refused, no listener
    snapshot = await update_filter_engine(
        engine, ["http://127.0.0.1:1/blocklist.txt"], version=2
    )

    assert snapshot.version == 1
    assert engine.match("old-rule.com").is_blocked


async def test_corrupt_list_keeps_old_snapshot(tmp_path: Path) -> None:
    """FR-10: a list that yields zero valid rules is treated as corrupt."""
    list_file = tmp_path / "lists" / "corrupt.txt"
    list_file.parent.mkdir()
    list_file.write_text(
        "\x00\xff\xfe garbage \x01\n### not a list ###\n???\n",
        encoding="utf-8",
    )
    engine = _engine_with("old-rule.com")

    snapshot = await update_filter_engine(
        engine,
        [str(list_file)],
        version=2,
        allowed_local_dirs=[str(tmp_path / "lists")],
    )

    assert snapshot.version == 1
    assert engine.match("old-rule.com").is_blocked


async def test_local_path_outside_allowed_dir_rejected(tmp_path: Path) -> None:
    """Path traversal guard: local lists outside the allowed directory are rejected."""
    allowed_dir = tmp_path / "lists"
    allowed_dir.mkdir()
    outside_file = tmp_path / "secrets" / "hosts.txt"
    outside_file.parent.mkdir()
    outside_file.write_text("||evil.com^\n", encoding="utf-8")

    # fetch_list itself raises
    with pytest.raises(UpdaterError):
        await fetch_list(str(outside_file), allowed_local_dirs=[str(allowed_dir)])

    # update_filter_engine keeps the old snapshot and logs the rejection
    engine = _engine_with("old-rule.com")
    snapshot = await update_filter_engine(
        engine,
        [str(outside_file)],
        version=2,
        allowed_local_dirs=[str(allowed_dir)],
    )
    assert snapshot.version == 1
    assert engine.match("old-rule.com").is_blocked
    assert not engine.match("evil.com").is_blocked


async def test_valid_list_inside_allowed_dir_is_readable(tmp_path: Path) -> None:
    """A local list inside the allowed directory loads normally."""
    allowed_dir = tmp_path / "lists"
    allowed_dir.mkdir()
    list_file = allowed_dir / "ok.txt"
    list_file.write_text("||inside.com^\n", encoding="utf-8")

    content, etag = await fetch_list(
        str(list_file), allowed_local_dirs=[str(allowed_dir)]
    )
    assert content is not None
    assert "inside.com" in content
    assert etag is None  # local files carry no ETag


async def test_empty_url_list_is_noop(tmp_path: Path) -> None:
    """No URLs configured: the snapshot is left untouched."""
    engine = _engine_with("old-rule.com")
    snapshot = await update_filter_engine(engine, [], version=5)
    assert snapshot.version == 1
    assert engine.match("old-rule.com").is_blocked


async def test_partial_failure_still_loads_good_sources(tmp_path: Path) -> None:
    """FR-10: one failing source does not prevent other sources from loading."""

    async def handler(request: web.Request) -> web.Response:
        return web.Response(status=500, text="down")

    app = web.Application()
    app.router.add_get("/dead", handler)
    server = TestServer(app)
    await server.start_server()
    try:
        list_file = tmp_path / "lists" / "good.txt"
        list_file.parent.mkdir()
        list_file.write_text("||good-source.com^\n", encoding="utf-8")

        engine = _engine_with("old-rule.com")
        snapshot = await update_filter_engine(
            engine,
            [str(server.make_url("/dead")), str(list_file)],
            version=3,
            allowed_local_dirs=[str(tmp_path / "lists")],
        )

        assert snapshot.version == 3
        assert engine.match("good-source.com").is_blocked
        # The update swaps the whole snapshot: old rules are replaced
        assert not engine.match("old-rule.com").is_blocked
    finally:
        await server.close()


async def test_http_etag_round_trip_304_keeps_rules() -> None:
    """FR-10 refresh: the ETag from the first fetch is replayed as
    If-None-Match; a 304 answer keeps the last good rules and the etag."""
    served: list[str] = []

    async def handler(request: web.Request) -> web.Response:
        if request.headers.get("If-None-Match") == '"v1"':
            return web.Response(status=304)
        served.append("hit")
        return web.Response(text="||etag-list.com^\n", headers={"ETag": '"v1"'})

    app = web.Application()
    app.router.add_get("/list", handler)
    server = TestServer(app)
    await server.start_server()
    try:
        url = str(server.make_url("/list"))
        engine = _engine_with("old-rule.com")
        etags: dict[str, str] = {}

        snapshot = await update_filter_engine(engine, [url], version=2, etags=etags)
        assert snapshot.version == 2
        assert engine.match("etag-list.com").is_blocked
        assert etags == {url: '"v1"'}

        # Second refresh: the server answers 304 -> rules stay untouched and
        # the engine snapshot is NOT swapped (version stays 2)
        snapshot = await update_filter_engine(engine, [url], version=3, etags=etags)
        assert snapshot.version == 2
        assert engine.match("etag-list.com").is_blocked
        assert etags == {url: '"v1"'}
        assert served == ["hit"]  # second fetch was conditional (304)
    finally:
        await server.close()


async def test_fetch_list_unsupported_scheme_rejected() -> None:
    with pytest.raises(UpdaterError):
        await fetch_list("ftp://example.com/list.txt")


class _FakeRuleManager:
    """Minimal RuleManager stand-in recording set_base calls."""

    def __init__(self) -> None:
        self.bases: list[FilterSnapshot] = []

    def set_base(self, base: FilterSnapshot) -> None:
        self.bases.append(base)


class _FakeEtagStore:
    """get/set callables persisted via system_settings in production."""

    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self.data.get(key)

    def set(self, key: str, value: str) -> None:
        self.data[key] = value


def _refresh_config(url: str) -> Config:
    return Config.from_env(
        {
            "REQKO_ADMIN_TOKEN": "x",
            "REQKO_BLOCKLIST_URLS": url,
            "REQKO_BLOCKLIST_REFRESH_HOURS": "1",
        }
    )


async def test_run_blocklist_refresh_disabled() -> None:
    """hours=0 or no URLs: the task returns immediately, nothing changes."""
    engine = _engine_with("old-rule.com")
    stop = asyncio.Event()
    await run_blocklist_refresh(
        Config.from_env(
            {"REQKO_ADMIN_TOKEN": "x", "REQKO_BLOCKLIST_REFRESH_HOURS": "0"}
        ),
        engine, _FakeRuleManager(), stop, (),
    )
    await run_blocklist_refresh(
        Config.from_env({"REQKO_ADMIN_TOKEN": "x"}),  # no URLs configured
        engine, _FakeRuleManager(), stop, (),
    )
    assert engine.snapshot.version == 1


async def test_run_blocklist_refresh_stops_gracefully_before_interval() -> None:
    engine = _engine_with("old-rule.com")
    rules = _FakeRuleManager()
    stop = asyncio.Event()
    task = asyncio.create_task(
        run_blocklist_refresh(
            _refresh_config("http://127.0.0.1:1/x"),  # never reached
            engine, rules, stop, (), etags_store=_FakeEtagStore(),
        )
    )
    await asyncio.sleep(0.1)  # inside the interval sleep loop
    stop.set()
    await asyncio.wait_for(task, timeout=5.0)
    assert rules.bases == []  # the interval never elapsed


async def test_refresh_once_swaps_base_and_persists_etags() -> None:
    async def handler(request: web.Request) -> web.Response:
        return web.Response(text="||refresh-list.com^\n", headers={"ETag": '"r1"'})

    app = web.Application()
    app.router.add_get("/list", handler)
    server = TestServer(app)
    await server.start_server()
    try:
        url = str(server.make_url("/list"))
        engine = _engine_with("old-rule.com")
        rules = _FakeRuleManager()
        store = _FakeEtagStore()
        etags: dict[str, str] = {}

        await _refresh_once(
            _refresh_config(url), engine, rules, asyncio.get_running_loop(),
            (), etags, store,
        )

        assert engine.match("refresh-list.com").is_blocked
        assert rules.bases and rules.bases[-1].version == 2
        assert etags == {url: '"r1"'}
        assert store.data["blocklist_etags"] == json.dumps({url: '"r1"'})
    finally:
        await server.close()


async def test_refresh_once_failure_is_contained() -> None:
    """A dead source keeps the old rules (FR-10): the engine falls back to its
    previous snapshot, which set_base re-installs unchanged. Never raises."""
    engine = _engine_with("old-rule.com")
    rules = _FakeRuleManager()

    await _refresh_once(
        _refresh_config("http://127.0.0.1:1/dead"), engine, rules,
        asyncio.get_running_loop(), (), {}, _FakeEtagStore(),
    )

    # The old snapshot is re-set as the base (idempotent, still version 1)
    assert len(rules.bases) == 1
    assert rules.bases[0].version == 1
    assert engine.match("old-rule.com").is_blocked
