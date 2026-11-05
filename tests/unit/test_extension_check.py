"""Tests for scripts/extension_check.py (static import/export + messaging checks).

Includes a negative test reproducing the exact Firefox bug this checker was
built for: background.js importing a non-existent 'buildDnrRule' export.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "extension_check.py"


def _load() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("extension_check", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = types.ModuleType(spec.name)
    module.__file__ = str(_SCRIPT)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def checker() -> types.ModuleType:
    return _load()


def _make_extension(tmp_path: Path, background_js: str, popup_js: str = "",
                    manifest_permissions: list[str] | None = None) -> Path:
    ext = tmp_path / "extension"
    (ext / "lib").mkdir(parents=True)
    (ext / "lib" / "rules.js").write_text(
        "export function buildDnrRules(domains) { return []; }\n"
        "export function sanitizeDomain(d) { return d; }\n",
        encoding="utf-8",
    )
    (ext / "background.js").write_text(background_js, encoding="utf-8")
    if popup_js:
        (ext / "popup.js").write_text(popup_js, encoding="utf-8")
    permissions = manifest_permissions if manifest_permissions is not None else [
        "declarativeNetRequest", "storage", "alarms",
    ]
    manifest = {
        "manifest_version": 3,
        "name": "t",
        "version": "0.1.0",
        "permissions": permissions,
        "background": {"scripts": ["background.js"], "service_worker": "background.js"},
    }
    (ext / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return ext


def test_real_extension_passes(checker: types.ModuleType) -> None:
    """The actual extension in the repo must pass all static checks."""
    real_ext = _SCRIPT.parents[1] / "extension"
    assert checker.check_extension(real_ext) == []


def test_nonexistent_named_import_is_reported(
    checker: types.ModuleType, tmp_path: Path
) -> None:
    """Negative test reproducing the exact Firefox bug: background.js imports
    'buildDnrRule' (singular) which lib/rules.js never exported."""
    ext = _make_extension(
        tmp_path,
        background_js=(
            "import {\n"
            "  buildDnrRules,\n"
            "  buildDnrRule,\n"  # <-- does not exist (the reported bug)
            "} from \"./lib/rules.js\";\n"
            "console.log(buildDnrRules, buildDnrRule);\n"
        ),
    )
    problems = checker.check_extension(ext)
    assert any(
        "buildDnrRule" in p and "does not resolve to an export" in p for p in problems
    ), problems


def test_missing_import_path_is_reported(checker: types.ModuleType, tmp_path: Path) -> None:
    ext = _make_extension(
        tmp_path,
        background_js='import { x } from "./lib/missing.js";\nconsole.log(x);\n',
    )
    problems = checker.check_extension(ext)
    assert any("does not exist" in p for p in problems)


def test_default_import_without_default_export_is_reported(
    checker: types.ModuleType, tmp_path: Path
) -> None:
    ext = _make_extension(
        tmp_path,
        background_js='import rules from "./lib/rules.js";\nconsole.log(rules);\n',
    )
    problems = checker.check_extension(ext)
    assert any("default import" in p for p in problems)


def test_valid_imports_pass(checker: types.ModuleType, tmp_path: Path) -> None:
    ext = _make_extension(
        tmp_path,
        background_js=(
            'import { buildDnrRules, sanitizeDomain } from "./lib/rules.js";\n'
            "console.log(buildDnrRules, sanitizeDomain);\n"
        ),
    )
    assert checker.check_extension(ext) == []


def test_sent_message_without_handler_is_reported(
    checker: types.ModuleType, tmp_path: Path
) -> None:
    ext = _make_extension(
        tmp_path,
        background_js=(
            'import { buildDnrRules } from "./lib/rules.js";\n'
            'browser.runtime.onMessage.addListener((m, s, r) => {\n'
            '  switch (m && m.type) {\n'
            '    case "getStatus":\n'
            '      return true;\n'
            '  }\n'
            '});\n'
            "console.log(buildDnrRules);\n"
        ),
        popup_js=(
            'browser.runtime.sendMessage({ type: "getStatus" });\n'
            'browser.runtime.sendMessage({ type: "bogusType" });\n'
        ),
        manifest_permissions=["declarativeNetRequest", "storage", "activeTab"],
    )
    problems = checker.check_extension(ext)
    assert any("bogusType" in p and "no handler" in p for p in problems)


def test_every_sent_message_has_a_handler_in_the_real_extension(
    checker: types.ModuleType,
) -> None:
    """Message-name consistency between popup/options and background."""
    real_ext = _SCRIPT.parents[1] / "extension"
    problems = [p for p in checker.check_extension(real_ext) if "message" in p]
    assert problems == []


def test_browser_api_without_permission_is_reported(
    checker: types.ModuleType, tmp_path: Path
) -> None:
    ext = _make_extension(
        tmp_path,
        background_js=(
            'import { buildDnrRules } from "./lib/rules.js";\n'
            "browser.alarms.create(\"x\", { periodInMinutes: 1 });\n"
            "console.log(buildDnrRules);\n"
        ),
        manifest_permissions=["declarativeNetRequest"],  # alarms missing
    )
    problems = checker.check_extension(ext)
    assert any("browser.alarms" in p and "alarms" in p for p in problems)


def test_active_tab_satisfies_tabs_usage(checker: types.ModuleType, tmp_path: Path) -> None:
    ext = _make_extension(
        tmp_path,
        background_js=(
            'import { buildDnrRules } from "./lib/rules.js";\n'
            "browser.tabs.query({});\n"
            "console.log(buildDnrRules);\n"
        ),
        manifest_permissions=["declarativeNetRequest", "activeTab"],
    )
    problems = [p for p in checker.check_extension(ext) if "browser.tabs" in p]
    assert problems == []
