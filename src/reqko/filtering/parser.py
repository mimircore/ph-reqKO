"""Filter list parser for /etc/hosts, plain domain lists, and Adblock syntax.

Implements FR-05, FR-06, and FR-07 parsing specifications:
- Comments (#, !) stripped
- Normalization: lowercase, trailing dot removed, whitespace stripped
- /etc/hosts and plain domain lists produce exact match rules
- Adblock syntax: ||domain^ produces wildcard block, @@||domain^ produces wildcard allow
- Loopback domains (localhost, ip6-loopback, etc.) are excluded
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class RuleAction(str, Enum):
    BLOCK = "BLOCK"
    ALLOW = "ALLOW"


class RuleSyntax(str, Enum):
    EXACT = "EXACT"
    WILDCARD = "WILDCARD"


@dataclass
class FilterRule:
    domain: str
    action: RuleAction
    syntax: RuleSyntax


@dataclass
class ParsedFilterRules:
    exact_blocks: set[str] = field(default_factory=set)
    wildcard_blocks: set[str] = field(default_factory=set)
    exact_allows: set[str] = field(default_factory=set)
    wildcard_allows: set[str] = field(default_factory=set)

    @property
    def total_count(self) -> int:
        return (
            len(self.exact_blocks)
            + len(self.wildcard_blocks)
            + len(self.exact_allows)
            + len(self.wildcard_allows)
        )

    def merge(self, other: ParsedFilterRules) -> None:
        self.exact_blocks.update(other.exact_blocks)
        self.wildcard_blocks.update(other.wildcard_blocks)
        self.exact_allows.update(other.exact_allows)
        self.wildcard_allows.update(other.wildcard_allows)


# Standard loopback and system domains to ignore in hosts files
IGNORED_HOSTS_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "local",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "0.0.0.0",
        "127.0.0.1",
        "::1",
        "loopback",
    }
)

# Regex to validate valid domain names (RFC 1035 / RFC 1123)
_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9\-_]{0,61}[a-zA-Z0-9]$"
)


def normalize_domain(domain: str) -> str | None:
    """Normalizes and validates a domain name."""
    norm = domain.strip().lower().rstrip(".")
    if not norm or norm in IGNORED_HOSTS_NAMES:
        return None

    # Strip port if present
    if ":" in norm:
        norm = norm.split(":")[0]

    # Quick check for invalid characters
    if "/" in norm or "\\" in norm or "@" in norm or "?" in norm or "#" in norm:
        return None

    if not _DOMAIN_PATTERN.match(norm):
        return None

    return norm


def parse_line(raw_line: str) -> list[FilterRule]:
    """Parses a single line from a filter list.

    Returns a list of FilterRule (or empty if comment/empty/ignored).
    """
    line = raw_line.strip()
    if not line:
        return []

    # Comment line
    if line.startswith("#") or line.startswith("!"):
        return []

    # Strip inline comment (e.g. "domain.com # comment" or "domain.com ! comment")
    for sep in ("#", "!"):
        if sep in line:
            # Be careful with Adblock @@||domain^!comment
            # If line starts with @@|| or ||, strip inline comment after trailing separator
            idx = line.find(sep)
            if idx > 0 and line[idx - 1].isspace():
                line = line[:idx].strip()

    if not line:
        return []

    # 1. Adblock syntax: @@||domain^ (wildcard allow) or @@||domain (allow)
    if line.startswith("@@||"):
        content = line[4:]
        # Strip trailing ^ or $ modifiers (we support domain subset)
        domain_part = content.rstrip("^").split("$")[0]
        norm = normalize_domain(domain_part)
        if norm:
            return [FilterRule(domain=norm, action=RuleAction.ALLOW, syntax=RuleSyntax.WILDCARD)]
        return []

    # 2. Adblock syntax: ||domain^ (wildcard block)
    if line.startswith("||"):
        content = line[2:]
        domain_part = content.rstrip("^").split("$")[0]
        norm = normalize_domain(domain_part)
        if norm:
            return [FilterRule(domain=norm, action=RuleAction.BLOCK, syntax=RuleSyntax.WILDCARD)]
        return []

    # 3. /etc/hosts format: IP domain [domain2 domain3...]
    tokens = line.split()
    if len(tokens) >= 2 and (
        tokens[0] in ("0.0.0.0", "127.0.0.1", "::1", "::")
        or _looks_like_ip(tokens[0])
    ):
        results: list[FilterRule] = []
        for d in tokens[1:]:
            norm = normalize_domain(d)
            if norm:
                results.append(
                    FilterRule(domain=norm, action=RuleAction.BLOCK, syntax=RuleSyntax.EXACT)
                )
        return results

    # 4. Plain domain format (single domain per line)
    norm = normalize_domain(tokens[0])
    if norm:
        return [FilterRule(domain=norm, action=RuleAction.BLOCK, syntax=RuleSyntax.EXACT)]

    return []


def _looks_like_ip(token: str) -> bool:
    """Fast heuristic to check if a token looks like an IPv4 address."""
    parts = token.split(".")
    if len(parts) == 4:
        return all(p.isdigit() for p in parts)
    return False


def parse_filter_lines(lines: list[str]) -> ParsedFilterRules:
    """Parses an iterable of filter list lines into a structured ParsedFilterRules."""
    rules = ParsedFilterRules()
    for line in lines:
        for rule in parse_line(line):
            if rule.action == RuleAction.ALLOW:
                if rule.syntax == RuleSyntax.WILDCARD:
                    rules.wildcard_allows.add(rule.domain)
                else:
                    rules.exact_allows.add(rule.domain)
            else:
                if rule.syntax == RuleSyntax.WILDCARD:
                    rules.wildcard_blocks.add(rule.domain)
                else:
                    rules.exact_blocks.add(rule.domain)
    return rules
