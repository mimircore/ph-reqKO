"""In-memory LRU DNS cache with TTL clamping and negative caching (RFC 2308).

Implements FR-03, FR-04, FR-09.
"""

from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from reqko.dns.protocol import (
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    TYPE_CNAME,
    TYPE_SOA,
    DNSPacket,
    DNSRecord,
    SOARecordData,
    make_response,
)


@dataclass
class CacheEntry:
    qname: str
    qtype: int
    answers: list[DNSRecord]
    authorities: list[DNSRecord]
    additionals: list[DNSRecord]
    cname_targets: tuple[str, ...]
    response_code: int
    created_at: float
    expires_at: float
    is_negative: bool
    original_ttl: int

    def remaining_ttl(self, now: float) -> int:
        return max(0, int(self.expires_at - now))


class DNSCache:
    """LRU DNS Cache using collections.OrderedDict with TTL rewrite on read."""

    def __init__(
        self,
        max_size: int = 10000,
        min_ttl: int = 60,
        max_ttl: int = 86400,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_size = max_size
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self._clock = clock
        self._cache: OrderedDict[tuple[str, int], CacheEntry] = OrderedDict()

    def __len__(self) -> int:
        return len(self._cache)

    def get(self, qname: str, qtype: int) -> CacheEntry | None:
        """Retrieves an entry from cache, evicting if expired.

        Updates LRU order and returns entry with positive remaining TTL.
        """
        key = (qname.strip(".").lower(), qtype)
        entry = self._cache.get(key)
        if entry is None:
            return None

        now = self._clock()
        if entry.remaining_ttl(now) <= 0:
            # Expired
            del self._cache[key]
            return None

        # Move to end (most recently used)
        self._cache.move_to_end(key, last=True)
        return entry

    def set(
        self,
        qname: str,
        qtype: int,
        packet: DNSPacket,
    ) -> CacheEntry | None:
        """Parses and caches a response packet according to RFC 1035 and RFC 2308."""
        rcode = packet.header.rcode
        # Only cache NOERROR and NXDOMAIN
        if rcode not in (RCODE_NOERROR, RCODE_NXDOMAIN):
            return None

        now = self._clock()
        norm_qname = qname.strip(".").lower()

        # Extract CNAME targets from answers
        cname_targets_list: list[str] = []
        for rr in packet.answers:
            if rr.rtype == TYPE_CNAME and isinstance(rr.rdata, str):
                cname_targets_list.append(rr.rdata.strip(".").lower())
        cname_targets = tuple(cname_targets_list)

        is_negative = False
        effective_ttl = self.max_ttl

        # Check for negative response (NXDOMAIN or empty NOERROR NODATA)
        if rcode == RCODE_NXDOMAIN or (rcode == RCODE_NOERROR and len(packet.answers) == 0):
            is_negative = True
            # RFC 2308: negative TTL = min(SOA.TTL, SOA.MINIMUM)
            soa_ttl: int | None = None
            for rr in packet.authorities:
                if rr.rtype == TYPE_SOA and isinstance(rr.rdata, SOARecordData):
                    soa_ttl = min(rr.ttl, rr.rdata.minimum)
                    break
            if soa_ttl is not None:
                effective_ttl = soa_ttl
            else:
                effective_ttl = 300  # Safe default RFC 2308 fallback
        else:
            # Positive response: take minimum TTL of answer records
            if packet.answers:
                effective_ttl = min(rr.ttl for rr in packet.answers)
            else:
                effective_ttl = 300

        original_ttl = effective_ttl
        # Clamp TTL (FR-03)
        clamped_ttl = max(self.min_ttl, min(effective_ttl, self.max_ttl))
        expires_at = now + clamped_ttl

        entry = CacheEntry(
            qname=norm_qname,
            qtype=qtype,
            answers=list(packet.answers),
            authorities=list(packet.authorities),
            additionals=list(packet.additionals),
            cname_targets=cname_targets,
            response_code=rcode,
            created_at=now,
            expires_at=expires_at,
            is_negative=is_negative,
            original_ttl=original_ttl,
        )

        key = (norm_qname, qtype)
        if key in self._cache:
            del self._cache[key]
        elif len(self._cache) >= self.max_size:
            # Evict least recently used
            self._cache.popitem(last=False)

        self._cache[key] = entry
        return entry

    def build_response(
        self,
        request: DNSPacket,
        entry: CacheEntry,
    ) -> DNSPacket:
        """Constructs a DNS response packet from cache, rewriting TTLs to remaining_ttl."""
        now = self._clock()
        rem_ttl = entry.remaining_ttl(now)

        resp = make_response(request, rcode=entry.response_code, aa=False, ra=True)

        for rr in entry.answers:
            resp.answers.append(
                DNSRecord(
                    name=rr.name,
                    rtype=rr.rtype,
                    rclass=rr.rclass,
                    ttl=rem_ttl,
                    rdata=rr.rdata,
                )
            )

        for rr in entry.authorities:
            resp.authorities.append(
                DNSRecord(
                    name=rr.name,
                    rtype=rr.rtype,
                    rclass=rr.rclass,
                    ttl=rem_ttl,
                    rdata=rr.rdata,
                )
            )

        for rr in entry.additionals:
            resp.additionals.append(
                DNSRecord(
                    name=rr.name,
                    rtype=rr.rtype,
                    rclass=rr.rclass,
                    ttl=rem_ttl,
                    rdata=rr.rdata,
                )
            )

        return resp
