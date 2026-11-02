"""Unit tests for filter rules parser (FR-05, FR-06, FR-07)."""

from reqko.filtering.parser import (
    RuleAction,
    RuleSyntax,
    normalize_domain,
    parse_filter_lines,
    parse_line,
)


def test_normalize_domain() -> None:
    assert normalize_domain("EXAMPLE.COM.") == "example.com"
    assert normalize_domain("  sub.domain.org  ") == "sub.domain.org"
    # Ignored system domains
    assert normalize_domain("localhost") is None
    assert normalize_domain("127.0.0.1") is None
    assert normalize_domain("0.0.0.0") is None
    assert normalize_domain("::1") is None
    # Invalid domain names
    assert normalize_domain("invalid/path") is None
    assert normalize_domain("user@domain.com") is None
    assert normalize_domain("") is None


def test_parse_hosts_format() -> None:
    line1 = "0.0.0.0 track.adserver.com"
    rules = parse_line(line1)
    assert len(rules) == 1
    assert rules[0].domain == "track.adserver.com"
    assert rules[0].action == RuleAction.BLOCK
    assert rules[0].syntax == RuleSyntax.EXACT

    # Multiple domains per line, including localhost
    line2 = "127.0.0.1 localhost ad1.com ad2.com"
    rules2 = parse_line(line2)
    assert len(rules2) == 2
    domains = [r.domain for r in rules2]
    assert "ad1.com" in domains
    assert "ad2.com" in domains
    assert "localhost" not in domains


def test_parse_plain_domain() -> None:
    line = "telemetry.badcorp.com"
    rules = parse_line(line)
    assert len(rules) == 1
    assert rules[0].domain == "telemetry.badcorp.com"
    assert rules[0].syntax == RuleSyntax.EXACT
    assert rules[0].action == RuleAction.BLOCK


def test_parse_adblock_syntax() -> None:
    # Wildcard block
    block_rule = parse_line("||doubleclick.net^")
    assert len(block_rule) == 1
    assert block_rule[0].domain == "doubleclick.net"
    assert block_rule[0].syntax == RuleSyntax.WILDCARD
    assert block_rule[0].action == RuleAction.BLOCK

    # Wildcard allow
    allow_rule = parse_line("@@||analytics.google.com^")
    assert len(allow_rule) == 1
    assert allow_rule[0].domain == "analytics.google.com"
    assert allow_rule[0].syntax == RuleSyntax.WILDCARD
    assert allow_rule[0].action == RuleAction.ALLOW


def test_comments_and_blank_lines() -> None:
    assert parse_line("") == []
    assert parse_line("   ") == []
    assert parse_line("# This is a comment") == []
    assert parse_line("! Another Adblock comment") == []

    # Inline comment
    inline = parse_line("0.0.0.0 bad.com # inline comment")
    assert len(inline) == 1
    assert inline[0].domain == "bad.com"


def test_parse_filter_lines_aggregation() -> None:
    content = [
        "# Header comment",
        "0.0.0.0 hosts-bad.com",
        "plain-bad.com",
        "||wildcard-bad.com^",
        "@@||whitelist-wildcard.com^",
        "! Footer comment",
    ]
    parsed = parse_filter_lines(content)
    assert "hosts-bad.com" in parsed.exact_blocks
    assert "plain-bad.com" in parsed.exact_blocks
    assert "wildcard-bad.com" in parsed.wildcard_blocks
    assert "whitelist-wildcard.com" in parsed.wildcard_allows
    assert parsed.total_count == 4
