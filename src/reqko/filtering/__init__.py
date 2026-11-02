"""Domain filtering and rule evaluation engine."""

from reqko.filtering.engine import FilterEngine, FilterSnapshot, MatchResult
from reqko.filtering.parser import (
    FilterRule,
    ParsedFilterRules,
    RuleAction,
    RuleSyntax,
    normalize_domain,
    parse_filter_lines,
    parse_line,
)

__all__ = [
    "FilterEngine",
    "FilterRule",
    "FilterSnapshot",
    "MatchResult",
    "ParsedFilterRules",
    "RuleAction",
    "RuleSyntax",
    "normalize_domain",
    "parse_filter_lines",
    "parse_line",
]
