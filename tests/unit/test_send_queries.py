"""Unit tests for scripts/send_queries.py (argument parsing and summary logic).

The module is loaded directly from the scripts folder; the network function
is not exercised here, so no DNS server is needed.
"""

from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

_SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "send_queries.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("send_queries", _SCRIPT_PATH)
    assert spec is not None and spec.loader is not None
    module = types.ModuleType(spec.name)
    # dataclasses resolves the KW_ONLY sentinel via sys.modules[cls.__module__],
    # so the module must be registered before it is executed.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_default_names_and_query_list() -> None:
    module = _load_module()
    names = module.DEFAULT_NAMES
    assert len(names) == 10
    assert names.count("example.com") == 2
    assert names.count("ads.example.com") == 2
    assert names.count("doubleclick.net") == 3
    assert names[-1] == "tracker.example.net"

    # One repetition keeps the list as-is
    once = module.build_query_list(names, 1)
    assert once == list(names)

    # Two repetitions double it and preserve the order
    twice = module.build_query_list(names, 2)
    assert len(twice) == 20
    assert twice[:10] == list(names)
    assert twice[10:] == list(names)


def test_parse_args_defaults() -> None:
    module = _load_module()
    args = module.parse_args([])
    assert args.host == "127.0.0.1"
    assert args.port == 5454
    assert args.count == 1
    assert tuple(args.names) == tuple(module.DEFAULT_NAMES)


def test_parse_args_custom_values() -> None:
    module = _load_module()
    args = module.parse_args(
        ["--host", "0.0.0.0", "--port", "6000", "--count", "3",
         "--names", "a.test", "b.test"]
    )
    assert args.host == "0.0.0.0"
    assert args.port == 6000
    assert args.count == 3
    assert args.names == ["a.test", "b.test"]

    query_list = module.build_query_list(args.names, args.count)
    assert query_list == ["a.test", "b.test"] * 3


def test_summarize_counts_blocked_and_errors() -> None:
    module = _load_module()
    QueryResult = module.QueryResult
    results = [
        QueryResult(name="ads.test", error=None, rcode="NOERROR",
                    answer="0.0.0.0", blocked=True, latency_ms=1.0),
        QueryResult(name="ok.test", error=None, rcode="NOERROR",
                    answer="1.2.3.4", blocked=False, latency_ms=2.0),
        QueryResult(name="nx.test", error=None, rcode="NXDOMAIN",
                    answer=None, blocked=False, latency_ms=3.0),
        QueryResult(name="dead.test", error="TimeoutError: timed out",
                    rcode="?", answer=None, blocked=False, latency_ms=5000.0),
    ]
    summary = module.summarize(results)
    assert summary.total == 4
    assert summary.blocked == 1
    assert summary.errors == 1


def test_format_result_and_blocked_detection() -> None:
    module = _load_module()
    QueryResult = module.QueryResult

    blocked = QueryResult(name="ads.test", error=None, rcode="NOERROR",
                          answer="0.0.0.0", blocked=True, latency_ms=1.3)
    line = module.format_result(7, blocked)
    assert "ads.test A -> 0.0.0.0" in line
    assert "(1.3 ms)" in line

    clean = QueryResult(name="ok.test", error=None, rcode="NOERROR",
                        answer="1.2.3.4", blocked=False, latency_ms=10.0)
    assert "ok.test A -> 1.2.3.4" in module.format_result(1, clean)

    failed = QueryResult(name="dead.test", error="TimeoutError: timed out",
                         rcode="?", answer=None, blocked=False, latency_ms=5000.0)
    assert "ERROR TimeoutError" in module.format_result(2, failed)

    nxdomain = QueryResult(name="nx.test", error=None, rcode="NXDOMAIN",
                           answer=None, blocked=False, latency_ms=4.0)
    assert "nx.test A -> NXDOMAIN" in module.format_result(3, nxdomain)

    assert module.is_blocked_answer("0.0.0.0") is True
    assert module.is_blocked_answer(" 0.0.0.0 ") is True
    assert module.is_blocked_answer("1.2.3.4") is False
    assert module.is_blocked_answer(None) is False
