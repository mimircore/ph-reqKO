"""Build and validate the ph-reqKO browser extension.

Usage:
    python scripts/build_extension.py          # validate + zip to dist/
    python scripts/build_extension.py --check-only

The validator enforces the security contract of extension/manifest.json:
required fields, the exact permission set, the strict extension_pages CSP,
no remote code vectors, that every referenced file exists, and that every
ES-module import in extension/**/*.js resolves to a real export (via
extension_check).
"""

from __future__ import annotations

import argparse
import json
import sys
import types
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
EXTENSION_DIR = ROOT / "extension"
DIST_DIR = ROOT / "dist"
ZIP_PATH = DIST_DIR / "ph-reqko-extension.zip"

REQUIRED_PERMISSIONS = frozenset(
    {
        "declarativeNetRequest",
        "declarativeNetRequestFeedback",
        "activeTab",  # popup reads the active tab URL (pause/resume, counts)
        "storage",
        "alarms",
    }
)
FORBIDDEN_PERMISSIONS = frozenset(
    {
        "webRequest",
        "webRequestBlocking",
        "scripting",
        "nativeMessaging",
        "proxy",
        "management",
        "history",
        "cookies",
    }
)
REQUIRED_BACKGROUND_KEYS = {"scripts", "service_worker"}
REQUIRED_CSP_TOKENS = ("script-src 'self'", "object-src 'none'")
FORBIDDEN_CSP_TOKENS = ("unsafe-inline", "unsafe-eval", "http://", "https://")

MAX_MANIFEST_BYTES = 64 * 1024


class ValidationIssue(Exception):
    """Raised with a human-readable description of a manifest problem."""


def validate_manifest(manifest: dict[str, Any], raw_bytes: bytes) -> list[str]:
    """Returns the list of extension files referenced by the manifest.

    Raises ValidationIssue on any violated rule.
    """
    if len(raw_bytes) > MAX_MANIFEST_BYTES:
        raise ValidationIssue("manifest.json is suspiciously large")

    for key in ("manifest_version", "name", "version", "description"):
        if key not in manifest:
            raise ValidationIssue(f"manifest.json: missing required key '{key}'")
    if manifest["manifest_version"] != 3:
        raise ValidationIssue("manifest_version must be 3")
    if not isinstance(manifest["name"], str) or not manifest["name"].strip():
        raise ValidationIssue("manifest name must be a non-empty string")

    permissions = set(manifest.get("permissions", []))
    missing = REQUIRED_PERMISSIONS - permissions
    if missing:
        raise ValidationIssue(f"manifest.json: missing permissions: {sorted(missing)}")
    forbidden = permissions & FORBIDDEN_PERMISSIONS
    if forbidden:
        raise ValidationIssue(f"manifest.json: over-broad permissions: {sorted(forbidden)}")

    optional_hosts = manifest.get("optional_host_permissions", [])
    if "http://*/*" not in optional_hosts or "https://*/*" not in optional_hosts:
        raise ValidationIssue(
            "manifest.json: optional_host_permissions must include http://*/* "
            "and https://*/* (user-configured server origin)"
        )

    background = manifest.get("background", {})
    if not REQUIRED_BACKGROUND_KEYS.issubset(background):
        raise ValidationIssue(
            "manifest.json: background must declare both scripts (Firefox "
            "event pages) and service_worker (Chrome) - the documented "
            "cross-browser pattern"
        )

    csp = manifest.get("content_security_policy", {}).get("extension_pages", "")
    for token in REQUIRED_CSP_TOKENS:
        if token not in csp:
            raise ValidationIssue(f"manifest.json CSP missing '{token}'")
    for token in FORBIDDEN_CSP_TOKENS:
        if token in csp:
            raise ValidationIssue(f"manifest.json CSP must not contain '{token}'")

    if "web_accessible_resources" in manifest:
        raise ValidationIssue(
            "manifest.json: web_accessible_resources must not be present "
            "(no data is shared with web pages)"
        )

    referenced: list[str] = [background["service_worker"], *background["scripts"]]
    action = manifest.get("action", {})
    if "default_popup" in action:
        referenced.append(action["default_popup"])
    options_ui = manifest.get("options_ui", {})
    if "page" in options_ui:
        referenced.append(options_ui["page"])

    for name in referenced:
        if ".." in name or name.startswith("/"):
            raise ValidationIssue(f"manifest.json references path outside the bundle: {name}")
        if not (EXTENSION_DIR / name).is_file():
            raise ValidationIssue(f"manifest.json references missing file: {name}")

    return referenced


def collect_bundle_files(referenced: list[str]) -> list[Path]:
    """Every file that goes into the zip: manifest + referenced files +
    lib/ modules + icons, ignoring tests and metadata."""
    files: list[Path] = [EXTENSION_DIR / "manifest.json"]
    files.extend(EXTENSION_DIR / name for name in referenced)
    files.extend((EXTENSION_DIR / "lib").glob("*.js"))
    files.extend((EXTENSION_DIR / "icons").glob("*") if (EXTENSION_DIR / "icons").is_dir() else [])
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in files:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    missing = [p for p in unique if not p.is_file()]
    if missing:
        raise ValidationIssue(f"bundle files missing: {[str(m) for m in missing]}")
    return unique


def _load_extension_check() -> Any:
    """Loads the sibling extension_check.py as a module (scripts/ is not a
    package, and the repo root must not become importable from scripts)."""
    import importlib.util

    checker_path = Path(__file__).resolve().parent / "extension_check.py"
    spec = importlib.util.spec_from_file_location("extension_check", checker_path)
    assert spec is not None and spec.loader is not None
    module: Any = types.ModuleType(spec.name)
    module.__file__ = str(checker_path)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build(check_only: bool) -> None:
    manifest_path = EXTENSION_DIR / "manifest.json"
    raw = manifest_path.read_bytes()
    manifest = json.loads(raw.decode("utf-8"))
    referenced = validate_manifest(manifest, raw)

    # Static import/export, messaging and permission-usage checks: the build
    # fails if any named import does not resolve (e.g. Firefox failing with
    # "doesn't provide an export named ...").
    extension_check = _load_extension_check()
    problems = extension_check.check_extension(EXTENSION_DIR)
    if problems:
        for problem in problems:
            print(f"PROBLEM: {problem}", file=sys.stderr)
        raise ValidationIssue(
            f"extension static checks failed: {len(problems)} problem(s)"
        )
    for path in collect_bundle_files(referenced):
        if path.suffix == ".html":
            html = path.read_text(encoding="utf-8")
            idx = html.find("<script")
            while idx != -1:
                end = html.find(">", idx)
                tag = html[idx : end + 1]
                if "src=" not in tag:
                    raise ValidationIssue(
                        f"{path.name}: inline <script> tag (CSP forbids it)"
                    )
                idx = html.find("<script", end)

    if check_only:
        print("validation OK (check-only)")
        return

    DIST_DIR.mkdir(parents=True, exist_ok=True)
    files = collect_bundle_files(referenced)
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as bundle:
        for path in files:
            bundle.write(path, f"ph-reqko-extension/{path.relative_to(EXTENSION_DIR)}")
    print(f"validation OK; wrote {ZIP_PATH} ({ZIP_PATH.stat().st_size} bytes, {len(files)} files)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate and zip the browser extension")
    parser.add_argument("--check-only", action="store_true", help="validate without zipping")
    args = parser.parse_args(argv)
    try:
        build(check_only=args.check_only)
    except (ValidationIssue, json.JSONDecodeError) as exc:
        print(f"VALIDATION FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
