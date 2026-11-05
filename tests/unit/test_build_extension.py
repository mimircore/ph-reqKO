"""Unit tests for scripts/build_extension.py (manifest validator + zip)."""

from __future__ import annotations

import importlib.util
import json
import sys
import types
import zipfile
from pathlib import Path
from typing import Any

import pytest

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "build_extension.py"


def _load() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("build_extension", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = types.ModuleType(spec.name)
    module.__file__ = str(_SCRIPT)
    module.__dict__["__name__"] = "build_extension"
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


builder: types.ModuleType = _load()


def _base_manifest() -> dict[str, Any]:
    manifest_path = Path(__file__).resolve().parents[2] / "extension" / "manifest.json"
    manifest: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    return manifest


def test_real_manifest_passes_validation() -> None:
    manifest = _base_manifest()
    raw = json.dumps(manifest).encode("utf-8")
    referenced = builder.validate_manifest(manifest, raw)
    assert "background.js" in referenced
    assert "popup.html" in referenced
    assert "options.html" in referenced


def test_missing_permission_fails() -> None:
    manifest = _base_manifest()
    manifest["permissions"] = ["storage"]
    with pytest.raises(builder.ValidationIssue, match="missing permissions"):
        builder.validate_manifest(manifest, b"{}")


def test_overbroad_permission_fails() -> None:
    manifest = _base_manifest()
    manifest["permissions"] = sorted(
        {"declarativeNetRequest", "declarativeNetRequestFeedback", "storage",
         "alarms", "tabs"}
    )
    with pytest.raises(builder.ValidationIssue, match="over-broad permissions"):
        builder.validate_manifest(manifest, b"{}")


def test_missing_csp_token_fails() -> None:
    manifest = _base_manifest()
    manifest["content_security_policy"]["extension_pages"] = "script-src 'self'"
    with pytest.raises(builder.ValidationIssue, match="object-src 'none'"):
        builder.validate_manifest(manifest, b"{}")


def test_unsafe_csp_token_fails() -> None:
    manifest = _base_manifest()
    manifest["content_security_policy"]["extension_pages"] = (
        "script-src 'self' 'unsafe-eval'; object-src 'none'"
    )
    with pytest.raises(builder.ValidationIssue, match="unsafe-eval"):
        builder.validate_manifest(manifest, b"{}")


def test_missing_version_fails() -> None:
    manifest = _base_manifest()
    del manifest["version"]
    with pytest.raises(builder.ValidationIssue, match="version"):
        builder.validate_manifest(manifest, b"{}")


def test_web_accessible_resources_fails() -> None:
    manifest = _base_manifest()
    manifest["web_accessible_resources"] = []
    with pytest.raises(builder.ValidationIssue, match="web_accessible_resources"):
        builder.validate_manifest(manifest, b"{}")


def test_background_needs_both_keys() -> None:
    manifest = _base_manifest()
    del manifest["background"]["scripts"]
    with pytest.raises(builder.ValidationIssue, match="scripts"):
        builder.validate_manifest(manifest, b"{}")


def test_referenced_files_exist_on_disk() -> None:
    """The real bundle: every manifest-referenced file must exist."""
    manifest = _base_manifest()
    raw = json.dumps(manifest).encode("utf-8")
    referenced = builder.validate_manifest(manifest, raw)
    files = builder.collect_bundle_files(referenced)
    assert len(files) >= 6  # manifest + background + popup + options + 3 lib


def test_build_creates_zip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(builder, "DIST_DIR", tmp_path)
    monkeypatch.setattr(builder, "ZIP_PATH", tmp_path / "ph-reqko-extension.zip")
    builder.build(check_only=False)
    zip_path = tmp_path / "ph-reqko-extension.zip"
    assert zip_path.is_file()
    with zipfile.ZipFile(zip_path) as bundle:
        names = bundle.namelist()
    assert "ph-reqko-extension/manifest.json" in names
    assert "ph-reqko-extension/background.js" in names
    assert any("lib/rules.js" in name for name in names)
    assert not any("test" in name for name in names)  # tests are not shipped
