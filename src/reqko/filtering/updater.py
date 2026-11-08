"""Blocklist updater: download, parse, and atomically swap filter snapshot (FR-10)."""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.parse
import urllib.request
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import aiohttp

from reqko.filtering.engine import FilterEngine, FilterSnapshot
from reqko.filtering.parser import parse_filter_lines

logger = logging.getLogger(__name__)

# Local list files are only read from these directories by default (FR-10,
# path traversal protection, docs/03-architecture.md section 11).
DEFAULT_ALLOWED_LIST_DIRS: tuple[str, ...] = ("/data/lists",)


class UpdaterError(Exception):
    """Raised when list update fails and no fallback is available."""


async def _download_url(
    url: str, timeout: float = 30.0, etag: str | None = None
) -> tuple[str | None, str | None]:
    """Downloads text content from HTTP/HTTPS URL.

    Sends If-None-Match when an etag is given. Returns (content, etag);
    content is None on HTTP 304 (unchanged) so callers keep last good lists.
    """
    headers = {"If-None-Match": etag} if etag else {}
    async with aiohttp.ClientSession() as session:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=timeout), headers=headers
        ) as resp:
            if resp.status == 304:
                return None, etag
            resp.raise_for_status()
            content = await resp.text(encoding="utf-8", errors="replace")
            return content, resp.headers.get("ETag")


def _read_local_file(path: str, allowed_dirs: Sequence[str]) -> str:
    """Reads a local list file, rejecting paths outside allowed directories."""
    abs_path = Path(path).resolve()
    for raw_dir in allowed_dirs:
        allowed_dir = Path(raw_dir).resolve()
        if abs_path.is_relative_to(allowed_dir):
            break
    else:
        raise UpdaterError(
            f"Local list path {abs_path} is outside the allowed directories "
            f"({', '.join(str(Path(d).resolve()) for d in allowed_dirs)})"
        )
    with open(abs_path, encoding="utf-8", errors="replace") as f:
        return f.read()


async def fetch_list(
    url: str,
    allowed_local_dirs: Sequence[str] = DEFAULT_ALLOWED_LIST_DIRS,
    etag: str | None = None,
) -> tuple[str | None, str | None]:
    """Fetches a blocklist by URL or file path.

    Returns (content, etag); content is None when the server reports 304
    Not Modified (remote URL sources only).
    """
    parsed = urllib.parse.urlparse(url)
    scheme = parsed.scheme.lower()
    if scheme in ("http", "https"):
        return await _download_url(url, etag=etag)
    if scheme in ("file", "") or len(scheme) == 1:
        # len(scheme) == 1 covers Windows drive letters: urlparse("C:\\x")
        # reports scheme "c". For the file scheme, convert the URL path part
        # back to a platform path (e.g. "file:///C:/x" -> "C:\\x").
        if scheme == "file":
            path = urllib.request.url2pathname(parsed.path)
        else:
            path = url
        loop = asyncio.get_running_loop()
        content = await loop.run_in_executor(
            None, _read_local_file, path, allowed_local_dirs
        )
        return content, None
    raise UpdaterError(f"Unsupported URL scheme: {parsed.scheme}")


def _parse_in_executor_sync(content: str) -> FilterSnapshot:
    lines = content.splitlines()
    parsed = parse_filter_lines(lines)
    return FilterSnapshot.from_parsed(parsed)


async def update_filter_engine(
    engine: FilterEngine,
    list_urls: list[str],
    version: int = 1,
    on_success: Callable[[int, int], None] | None = None,
    allowed_local_dirs: Sequence[str] = DEFAULT_ALLOWED_LIST_DIRS,
    etags: dict[str, str] | None = None,
) -> FilterSnapshot:
    """Downloads all lists, merges rules, and atomically swaps the engine snapshot.

    Falls back to the existing snapshot on failure (FR-10). ``etags`` is an
    optional mutable {url: etag} map read/updated in place for ETag-based
    conditional fetches (If-None-Match; 304 keeps last good lists).
    """
    if not list_urls:
        logger.warning("No blocklist URLs configured, skipping update")
        return engine.snapshot
    etag_map = etags if etags is not None else {}

    loop = asyncio.get_running_loop()
    merged_lines: list[str] = []
    new_etags: dict[str, str | None] = {}
    failures = 0
    unchanged = 0

    for url in list_urls:
        try:
            content, etag = await fetch_list(
                url, allowed_local_dirs=allowed_local_dirs, etag=etag_map.get(url)
            )
            if content is None:
                # 304 Not Modified: last good list stays
                new_etags[url] = etag or ""
                unchanged += 1
                logger.info("Blocklist %s unchanged (304), keeping current rules", url)
                continue
            if etag:
                new_etags[url] = etag
            merged_lines.extend(content.splitlines())
            logger.info("Loaded blocklist: %s (%d lines)", url, len(content.splitlines()))
        except Exception as e:
            failures += 1
            # Log the exception type and HTTP status (if any) instead of
            # formatting the exception object: some aiohttp exceptions crash
            # when interpolated into a message.
            logger.error(
                "Failed to fetch blocklist %s: %s (status=%s)",
                url,
                type(e).__name__,
                getattr(e, "status", None),
            )
            # Continue with other sources

    if etags is not None:
        etags.clear()
        etags.update({k: v for k, v in new_etags.items() if v})

    if not merged_lines:
        if unchanged == len(list_urls):
            logger.info("All blocklist sources unchanged (304), keeping current rules")
            return engine.snapshot
        logger.error("All blocklist sources failed, keeping existing rules (FR-10 fallback)")
        return engine.snapshot

    # Parse in thread executor to avoid blocking the event loop
    try:
        parsed_snapshot = await loop.run_in_executor(
            None, _parse_in_executor_sync, "\n".join(merged_lines)
        )
        if parsed_snapshot.rules_count == 0:
            # Content was fetched but no valid rule parsed out of it: most
            # likely a corrupt or foreign list - keep the last working rules.
            logger.error(
                "Parsed 0 valid rules from the blocklist sources — keeping existing rules (FR-10)"
            )
            return engine.snapshot
        new_snapshot = FilterSnapshot(
            exact_set=parsed_snapshot.exact_set,
            wildcard_set=parsed_snapshot.wildcard_set,
            allow_exact_set=parsed_snapshot.allow_exact_set,
            allow_wildcard_set=parsed_snapshot.allow_wildcard_set,
            version=version,
            rules_count=parsed_snapshot.rules_count,
        )
    except Exception as e:
        logger.error(
            "Failed to parse blocklist rules: %s: %s — keeping existing (FR-10)",
            type(e).__name__,
            e,
        )
        return engine.snapshot

    # Atomic swap (FR-10)
    engine.update_snapshot(new_snapshot)
    logger.info(
        "Filter rules updated to v%d: %d total rules", version, new_snapshot.rules_count
    )

    if on_success is not None:
        on_success(version, new_snapshot.rules_count)

    return new_snapshot


async def run_blocklist_refresh(
    config: Any,
    engine: FilterEngine,
    rule_manager: Any,
    stop_event: asyncio.Event,
    allowed_local_dirs: Sequence[str],
    etags_store: Any = None,
) -> None:
    """Periodic blocklist URL refresh (REQKO_BLOCKLIST_REFRESH_HOURS).

    0 disables. Uses ETag/If-None-Match (etags persisted via etags_store
    get/set callables) and keeps last good lists on any failure (FR-10).
    """
    if config.blocklist_refresh_hours <= 0 or not config.blocklist_urls:
        return
    loop = asyncio.get_running_loop()
    interval_seconds = config.blocklist_refresh_hours * 3600.0
    etags: dict[str, str] = {}
    if etags_store is not None:
        try:
            stored = await loop.run_in_executor(None, etags_store.get, "blocklist_etags")
            if stored:
                etags.update(json.loads(stored))
        except Exception:
            logger.debug("could not load stored blocklist etags", exc_info=True)

    while not stop_event.is_set():
        slept = 0.0
        while slept < interval_seconds and not stop_event.is_set():
            delay = min(1.0, interval_seconds - slept)
            await asyncio.sleep(delay)
            slept += delay
        if stop_event.is_set():
            return
        await _refresh_once(
            config, engine, rule_manager, loop, allowed_local_dirs, etags, etags_store
        )


async def _refresh_once(
    config: Any,
    engine: FilterEngine,
    rule_manager: Any,
    loop: asyncio.AbstractEventLoop,
    allowed_local_dirs: Sequence[str],
    etags: dict[str, str],
    etags_store: Any,
) -> None:
    """One refresh iteration: reload the URLs, swap the base snapshot and
    persist the etag map (kept separate so the interval loop stays thin)."""
    try:
        version = engine.snapshot.version + 1
        snapshot = await update_filter_engine(
            engine,
            config.blocklist_urls,
            version=version,
            allowed_local_dirs=allowed_local_dirs,
            etags=etags,
        )
        rule_manager.set_base(snapshot)
        if etags_store is not None and etags:
            await loop.run_in_executor(
                None,
                etags_store.set,
                "blocklist_etags",
                json.dumps(etags),
            )
    except Exception:
        logger.exception("blocklist refresh iteration failed")
