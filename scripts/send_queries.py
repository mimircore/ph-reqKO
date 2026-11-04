"""Demo helper: send a fixed list of DNS queries to a running ph-reqKO server.

No new dependencies (dnspython is already a dev/runtime dependency).
The network part (send_one) is separated from argument parsing and the
result summary so the latter can be unit-tested without a server.
"""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass

import dns.message
import dns.query
import dns.rcode

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5454

# Names queried once per repetition, in this order.
DEFAULT_NAMES: tuple[str, ...] = (
    "example.com",
    "example.com",
    "wikipedia.org",
    "github.com",
    "ads.example.com",
    "ads.example.com",
    "doubleclick.net",
    "doubleclick.net",
    "doubleclick.net",
    "tracker.example.net",
)


@dataclass(frozen=True)
class QueryResult:
    """Outcome of a single query."""

    name: str
    error: str | None  # transport/timeout failure description, if any
    rcode: str  # "NOERROR", "NXDOMAIN", ... (or "?" when error is set)
    answer: str | None  # first answer record as text, if any
    blocked: bool  # True when the first answer set contains 0.0.0.0
    latency_ms: float


@dataclass(frozen=True)
class Summary:
    total: int
    blocked: int
    errors: int


def build_query_list(names: tuple[str, ...] | list[str], count: int) -> list[str]:
    """Repeats the name list ``count`` times."""
    return [name for _ in range(count) for name in names]


def summarize(results: list[QueryResult] | tuple[QueryResult, ...]) -> Summary:
    """Counts total queries, 0.0.0.0-blocked answers, and transport errors."""
    blocked = sum(1 for r in results if r.blocked)
    errors = sum(1 for r in results if r.error is not None)
    return Summary(total=len(results), blocked=blocked, errors=errors)


def format_result(index: int, result: QueryResult) -> str:
    """One line per query: name, first answer or rcode, latency."""
    latency = f" ({result.latency_ms:.1f} ms)"
    if result.error is not None:
        return f"{index:3d}. {result.name} A -> ERROR {result.error}{latency}"
    target = result.answer if result.answer is not None else result.rcode
    return f"{index:3d}. {result.name} A -> {target}{latency}"


def is_blocked_answer(answer: str | None) -> bool:
    """True when an answer record is the sinkhole address 0.0.0.0."""
    return answer is not None and answer.strip() == "0.0.0.0"


def send_one(host: str, port: int, name: str) -> QueryResult:
    """Sends one A query and classifies the response; never raises."""
    start = time.perf_counter()
    try:
        query = dns.message.make_query(name, "A")
        response = dns.query.udp(query, host, port=port, timeout=5.0)
    except Exception as exc:  # timeouts, refused connections, malformed replies
        latency = (time.perf_counter() - start) * 1000.0
        return QueryResult(
            name=name,
            error=f"{type(exc).__name__}: {exc}",
            rcode="?",
            answer=None,
            blocked=False,
            latency_ms=latency,
        )
    latency = (time.perf_counter() - start) * 1000.0
    rcode = dns.rcode.to_text(response.rcode())
    answer: str | None = None
    blocked = False
    if response.answer:
        rrset = response.answer[0]
        for rr in rrset:
            text = rr.to_text()
            if answer is None:
                answer = text
            if is_blocked_answer(text):
                blocked = True
                break
    return QueryResult(
        name=name,
        error=None,
        rcode=rcode,
        answer=answer,
        blocked=blocked,
        latency_ms=latency,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send demo DNS queries to a ph-reqKO server and summarize the answers."
    )
    parser.add_argument("--host", default=DEFAULT_HOST, help="DNS server host")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="DNS server port")
    parser.add_argument(
        "--count",
        type=int,
        default=1,
        help="how many times to repeat the name list",
    )
    parser.add_argument(
        "--names",
        nargs="+",
        default=list(DEFAULT_NAMES),
        help="query names (space separated); default: the built-in demo list",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    names = [
        item for chunk in args.names for item in chunk.split(",") if item
    ]
    query_list = build_query_list(names, args.count)
    results: list[QueryResult] = []
    for index, name in enumerate(query_list, start=1):
        result = send_one(args.host, args.port, name)
        results.append(result)
        print(format_result(index, result))
    summary = summarize(results)
    print(f"Summary: total={summary.total} blocked={summary.blocked} errors={summary.errors}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
