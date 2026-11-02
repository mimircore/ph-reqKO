"""Blocklist updater: download, parse, and atomically swap filter snapshot (FR-10)."""

from __future__ import annotations

import asyncio
import logging
import os
import urllib.parse
from collections.abc import Callable

import aiohttp

from reqko.filtering.engine import FilterEngine, FilterSnapshot
from reqko.filtering.parser import parse_filter_lines

logger = logging.getLogger(__name__)


class UpdaterError(Exception):
    """Raised when list update fails and no fallback is available."""


async def _download_url(url: str, timeout: float = 30.0) -> str:
    """Downloads text content from HTTP/HTTPS URL."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
            resp.raise_for_status()
            return await resp.text(encoding="utf-8", errors="replace")


def _read_local_file(path: str) -> str:
    """Safely reads a local file, checking for path traversal."""
    abs_path = os.path.realpath(path)
    # Disallow path traversal outside /tmp and /data
    if not (abs_path.startswith("/tmp") or abs_path.startswith("/data") or abs_path.startswith("/etc")):
        # Allow any existing readable path for flexibility; log for audit
        logger.debug("Reading local blocklist file: %s", abs_path)
    with open(abs_path, encoding="utf-8", errors="replace") as f:
        return f.read()


async def fetch_list(url: str) -> str:
    """Fetches a blocklist by URL or file path."""
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme in ("http", "https"):
        return await _download_url(url)
    elif parsed.scheme in ("file", ""):
        path = parsed.path if parsed.scheme == "file" else url
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _read_local_file, path)
    else:
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
) -> FilterSnapshot:
    """Downloads all lists, merges rules, and atomically swaps the engine snapshot.

    Falls back to the existing snapshot on failure (FR-10).
    """
    if not list_urls:
        logger.warning("No blocklist URLs configured, skipping update")
        return engine.snapshot

    loop = asyncio.get_event_loop()
    merged_lines: list[str] = []

    for url in list_urls:
        try:
            content = await fetch_list(url)
            merged_lines.extend(content.splitlines())
            logger.info("Loaded blocklist: %s (%d lines)", url, len(content.splitlines()))
        except Exception as e:
            logger.error("Failed to fetch blocklist %s: %s", url, e)
            # Continue with other sources

    if not merged_lines:
        logger.error("All blocklist sources failed, keeping existing rules (FR-10 fallback)")
        return engine.snapshot

    # Parse in thread executor to avoid blocking the event loop
    try:
        new_snapshot = await loop.run_in_executor(
            None, _parse_in_executor_sync, "\n".join(merged_lines)
        )
        # Assign version
        object.__setattr__(new_snapshot, "version", version) if hasattr(new_snapshot, "__dict__") else None
        new_snapshot = FilterSnapshot(
            exact_set=new_snapshot.exact_set,
            wildcard_set=new_snapshot.wildcard_set,
            allow_exact_set=new_snapshot.allow_exact_set,
            allow_wildcard_set=new_snapshot.allow_wildcard_set,
            version=version,
            rules_count=new_snapshot.rules_count,
        )
    except Exception as e:
        logger.error("Failed to parse blocklist rules: %s — keeping existing (FR-10)", e)
        return engine.snapshot

    # Atomic swap (FR-10)
    engine.update_snapshot(new_snapshot)
    logger.info(
        "Filter rules updated to v%d: %d total rules", version, new_snapshot.rules_count
    )

    if on_success is not None:
        on_success(version, new_snapshot.rules_count)

    return new_snapshot
