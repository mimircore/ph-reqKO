"""Static import/export + messaging analysis for the browser extension.

Run standalone:  python scripts/extension_check.py
(Also invoked from scripts/build_extension.py during build/check.)

AST-free but robust parsing of the ES module subset used by the extension:
multi-line named/default/namespace imports, `export function/const/class`,
`export { a as b }`, and `export default`. Verifies:
  1. every imported path exists (relative to the importing file);
  2. every named import resolves to a real export in the target module;
  3. runtime.sendMessage type names in UI pages match background handlers;
  4. every browser.*/chrome.* API namespace used in JS is covered by the
     manifest permissions.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# Statement-level regexes (DOTALL so multi-line import clauses are caught).
_IMPORT_FROM_RE = re.compile(
    r"^\s*import\s+(?P<clause>[^'\"]+?)\s+from\s+['\"](?P<path>[^'\"]+)['\"]",
    re.MULTILINE | re.DOTALL,
)
_IMPORT_SIDE_EFFECT_RE = re.compile(r"^\s*import\s+['\"](?P<path>[^'\"]+)['\"]", re.MULTILINE)
_EXPORT_NAMED_RE = re.compile(r"^\s*export\s+\{(?P<names>[^}]*)\}", re.MULTILINE)
_EXPORT_DECL_RE = re.compile(
    r"^\s*export\s+(?:default\s+)?(?:async\s+)?(?:function\s*\*?|const|let|class|var)\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)",
    re.MULTILINE,
)
_EXPORT_DEFAULT_RE = re.compile(r"^\s*export\s+default\b", re.MULTILINE)
_SENDMSG_RE = re.compile(r"\.sendMessage\(\s*\{\s*type:\s*\"(?P<type>\w+)\"")
_HANDLER_RE = re.compile(r"case\s+\"(?P<type>\w+)\":")
_API_USE_RE = re.compile(r"\b(?:browser|chrome)\.(?P<ns>\w+)\.")

# browser.*/chrome.* namespace -> set of acceptable manifest permission keys
# (any one satisfies the usage), or None for keys that need no permission.
# "tabs" usage from an action popup is covered by activeTab (granted when the
# user invokes the extension's button).
API_NAMESPACE_REQUIREMENTS: dict[str, set[str] | None] = {
    "declarativeNetRequest": {"declarativeNetRequest"},
    "storage": {"storage"},
    "alarms": {"alarms"},
    "action": None,
    "runtime": None,
    "permissions": None,
    "tabs": {"tabs", "activeTab"},
}

_CLAUSE_NAMED_RE = re.compile(r"\{(?P<named>[^}]*)\}")
_CLAUSE_DEFAULT_RE = re.compile(r"^(?P<default>\w+)\s*,?\s*")
_CLAUSE_NS_RE = re.compile(r"\*\s+as\s+(?P<ns>\w+)")


def parse_imports(text: str) -> list[tuple[str, list[tuple[str, str | None]], str | None]]:
    """Returns [(module_path, [(imported, alias_or_None), ...], default_or_None)]."""
    imports: list[tuple[str, list[tuple[str, str | None]], str | None]] = []
    for match in _IMPORT_FROM_RE.finditer(text):
        clause, module_path = match.group("clause"), match.group("path")
        named: list[tuple[str, str | None]] = []
        default: str | None = None
        rest = clause
        named_match = _CLAUSE_NAMED_RE.search(rest)
        if named_match:
            rest = rest[: named_match.start()] + rest[named_match.end() :]
            for part in named_match.group("named").split(","):
                part = part.strip()
                if not part:
                    continue
                if " as " in part:
                    imported, alias = (p.strip() for p in part.split(" as ", 1))
                    named.append((imported, alias))
                else:
                    named.append((part, None))
        ns_match = _CLAUSE_NS_RE.search(rest)
        if ns_match:
            named.append((ns_match.group("ns"), None))
            rest = rest[: ns_match.start()] + rest[ns_match.end() :]
        default_match = _CLAUSE_DEFAULT_RE.search(rest.strip())
        if default_match:
            default = default_match.group("default")
        imports.append((module_path, named, default))
    for match in _IMPORT_SIDE_EFFECT_RE.finditer(text):
        imports.append((match.group("path"), [], None))
    return imports


def parse_exports(text: str) -> tuple[set[str], bool]:
    names: set[str] = set()
    has_default = False
    for match in _EXPORT_DECL_RE.finditer(text):
        names.add(match.group("name"))
    for match in _EXPORT_NAMED_RE.finditer(text):
        for part in match.group("names").split(","):
            part = part.strip()
            if not part:
                continue
            names.add(part.split(" as ")[-1].strip())
    if _EXPORT_DEFAULT_RE.search(text):
        has_default = True
    return names, has_default


def check_extension(extension_dir: Path) -> list[str]:
    """Runs all static checks; returns a list of human-readable problems."""
    problems: list[str] = []
    js_files = sorted(extension_dir.rglob("*.js"))
    exports_by_file: dict[Path, tuple[set[str], bool]] = {}
    for path in js_files:
        exports_by_file[path] = parse_exports(path.read_text(encoding="utf-8"))

    # 1+2: import path existence and named-import resolution
    for path in js_files:
        text = path.read_text(encoding="utf-8")
        for module_path, named, default in parse_imports(text):
            if not module_path.startswith("."):
                problems.append(
                    f"{path.name}: bare-specifier import '{module_path}' is not allowed "
                    "(no bundler, no node_modules)"
                )
                continue
            target = (path.parent / module_path).resolve()
            if not target.is_file():
                problems.append(f"{path.name}: import path does not exist: {module_path}")
                continue
            target_exports, target_has_default = exports_by_file.setdefault(
                target, parse_exports(target.read_text(encoding="utf-8"))
            )
            for imported, _alias in named:
                if imported not in target_exports:
                    problems.append(
                        f"{path.name}: import '{imported}' from '{module_path}' does not "
                        f"resolve to an export of {target.name} (has: "
                        f"{', '.join(sorted(target_exports)) or 'none'})"
                    )
            if default is not None and not target_has_default:
                problems.append(
                    f"{path.name}: default import from '{module_path}' but "
                    f"{target.name} has no default export"
                )

    # 3: message-name consistency between UI pages and the background
    bg = extension_dir / "background.js"
    sent: set[str] = set()
    handled: set[str] = set()
    for path in js_files:
        text = path.read_text(encoding="utf-8")
        sent.update(m.group("type") for m in _SENDMSG_RE.finditer(text))
        if path == bg:
            handled.update(m.group("type") for m in _HANDLER_RE.finditer(text))
    for name in sorted(sent - handled):
        problems.append(
            f"message '{name}' is sent but background.js has no handler case for it"
        )
    for name in sorted(handled - sent):
        problems.append(f"background.js handles message '{name}' but no page sends it")

    # 4: browser API namespaces vs manifest permissions
    manifest = json.loads((extension_dir / "manifest.json").read_text(encoding="utf-8"))
    permissions = set(manifest.get("permissions", []))
    if "activeTab" in permissions:
        permissions.add("tabs")  # activeTab grants tabs-query access on invoke
    for path in js_files:
        text = path.read_text(encoding="utf-8")
        for namespace in sorted(set(m.group("ns") for m in _API_USE_RE.finditer(text))):
            required = API_NAMESPACE_REQUIREMENTS.get(namespace)
            if required is None:
                continue
            if not (required & permissions):
                problems.append(
                    f"{path.name}: browser.{namespace}.* used but manifest permissions "
                    f"lack any of {sorted(required)}"
                )
    return problems


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent / "extension"
    found = check_extension(root)
    if found:
        for problem in found:
            print("PROBLEM:", problem)
        raise SystemExit(1)
    print("extension static checks OK")
