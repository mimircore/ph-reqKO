"""Cosmetic-filtering selector data: load, validate, and version (objective 7 ext).

The selector file ships with the server (src/reqko/api/data/) and is edited
in-repo only — no external scraping. Both the server and the extension
validate every selector defensively: anything that could smuggle code or
break the injected <style> is rejected.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parent / "data" / "cosmetic_selectors.txt"

# Substrings that must never appear in a selector: CSS escape hatches,
# injection vectors, and at-rule constructs.
FORBIDDEN_SUBSTRINGS: tuple[str, ...] = (
    "{",
    "}",
    "<",
    ">",
    "@import",
    "url(",
    "expression",
    "javascript:",
    "behavior",
    "-moz-binding",
)
MAX_SELECTOR_LENGTH = 256
MAX_SELECTORS = 1000


def validate_selector(selector: str) -> str | None:
    """Returns the cleaned selector, or None when it must be rejected."""
    cleaned = selector.strip()
    if not cleaned or cleaned.startswith("#"):
        return None
    if len(cleaned) > MAX_SELECTOR_LENGTH:
        return None
    lowered = cleaned.lower()
    for forbidden in FORBIDDEN_SUBSTRINGS:
        if forbidden in lowered:
            return None
    return cleaned


def load_selectors(data_file: Path = DATA_FILE) -> tuple[list[str], str]:
    """Returns (validated selectors, content version hash).

    Lines starting with '#' are comments; blank lines are skipped; any line
    failing validate_selector is dropped (the shipped file is curated, so
    this is a defensive backstop, not an expected path).
    """
    selectors: list[str] = []
    for line in data_file.read_text(encoding="utf-8").splitlines():
        selector = validate_selector(line)
        if selector is not None:
            selectors.append(selector)
    version = hashlib.sha256("\n".join(selectors).encode("utf-8")).hexdigest()[:16]
    return selectors, version
