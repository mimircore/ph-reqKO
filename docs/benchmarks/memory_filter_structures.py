#!/usr/bin/env python3
"""
Скрипт воспроизводимого замера потребления памяти структурами фильтрации DNS:
frozenset + Label walk vs наивное префиксное дерево (Trie) на словарях Python.
Также измеряет размер 10 000 реалистичных объектов CacheEntry и скорость парсинга 150k hosts.
Запуск: python3 docs/benchmarks/memory_filter_structures.py
"""

import sys
import time
import tracemalloc


class TrieNode:
    """Узел наивного префиксного дерева по меткам домена (TLD -> SLD -> sub)."""

    __slots__ = ("children", "is_end")

    def __init__(self) -> None:
        self.children: dict[str, "TrieNode"] = {}
        self.is_end: bool = False


class MockRecord:
    __slots__ = ("name", "rtype", "rclass", "ttl", "rdata")

    def __init__(self, name: str, rtype: int, ttl: int, rdata: bytes) -> None:
        self.name = name
        self.rtype = rtype
        self.rclass = 1
        self.ttl = ttl
        self.rdata = rdata


class CacheEntry:
    __slots__ = (
        "qname",
        "qtype",
        "records",
        "cname_targets",
        "response_code",
        "created_at",
        "expires_at",
        "is_negative",
        "original_ttl",
    )

    def __init__(
        self,
        qname: str,
        qtype: int,
        records: list[MockRecord],
        cname_targets: tuple[str, ...],
        response_code: int,
        ttl: int,
    ) -> None:
        self.qname = qname
        self.qtype = qtype
        self.records = records
        self.cname_targets = cname_targets
        self.response_code = response_code
        self.created_at = 1000.0
        self.expires_at = 1000.0 + ttl
        self.is_negative = False
        self.original_ttl = ttl


def benchmark() -> None:
    print(f"Python {sys.version.split()[0]} on {sys.platform}")
    num_domains = 150_000
    print(f"Generating {num_domains} synthetic domains...")
    domains = [
        f"sub{i % 100}.tracker{i % 1000}.adnetwork{i}.com"
        for i in range(num_domains)
    ]

    # 1. Замер frozenset
    tracemalloc.start()
    t0 = time.perf_counter()
    fset = frozenset(domains)
    t_fset = time.perf_counter() - t0
    _, peak_fset = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # 2. Замер Trie на dict
    tracemalloc.start()
    t0 = time.perf_counter()
    root = TrieNode()
    for d in domains:
        node = root
        for label in reversed(d.split(".")):
            if label not in node.children:
                node.children[label] = TrieNode()
            node = node.children[label]
        node.is_end = True
    t_trie = time.perf_counter() - t0
    _, peak_trie = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # 3. Замер 10 000 CacheEntry
    tracemalloc.start()
    cache: dict[tuple[str, int], CacheEntry] = {}
    for i in range(10_000):
        qn = f"host{i}.example.org"
        recs = [MockRecord(qn, 1, 300, b"\x01\x02\x03\x04")]
        cache[(qn, 1)] = CacheEntry(qn, 1, recs, (), 0, 300)
    _, peak_cache = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # 4. Скорость парсинга 150k строк hosts
    lines = [
        f"0.0.0.0 sub{i % 100}.tracker{i % 1000}.adnetwork{i}.com\n"
        for i in range(num_domains)
    ]
    t0 = time.perf_counter()
    parsed = set()
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "0.0.0.0":
            parsed.add(parts[1])
    t_parse = time.perf_counter() - t0

    print("-" * 60)
    print(f"150k frozenset memory:       {peak_fset / (1024*1024):.2f} MB (build: {t_fset*1000:.1f} ms)")
    print(f"150k dict-trie memory:       {peak_trie / (1024*1024):.2f} MB (build: {t_trie*1000:.1f} ms)")
    ratio = peak_trie / peak_fset if peak_fset > 0 else 0
    print(f"Trie / frozenset ratio:      {ratio:.1f}x memory overhead")
    print(f"10k cache entries memory:    {peak_cache / (1024*1024):.2f} MB")
    print(f"150k hosts lines parse time: {t_parse*1000:.1f} ms")
    print("-" * 60)


if __name__ == "__main__":
    benchmark()
