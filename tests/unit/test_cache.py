"""Unit tests for DNSCache (FR-03, FR-04, FR-09)."""

from reqko.dns.cache import DNSCache
from reqko.dns.protocol import (
    CLASS_IN,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    TYPE_A,
    TYPE_CNAME,
    TYPE_SOA,
    DNSHeader,
    DNSPacket,
    DNSQuestion,
    DNSRecord,
    SOARecordData,
)


def test_cache_hit_and_ttl_rewrite() -> None:
    current_time = 1000.0

    def mock_clock() -> float:
        return current_time

    cache = DNSCache(max_size=100, min_ttl=60, max_ttl=3600, clock=mock_clock)

    # 1. Populate cache with a positive response (TTL = 300)
    packet = DNSPacket(
        header=DNSHeader(id=1, qr=1, rcode=RCODE_NOERROR),
        questions=[DNSQuestion(name="example.com", qtype=TYPE_A)],
        answers=[
            DNSRecord(
                name="example.com",
                rtype=TYPE_A,
                rclass=CLASS_IN,
                ttl=300,
                rdata="93.184.216.34",
            )
        ],
    )
    cache.set("example.com", TYPE_A, packet)

    # Immediate cache hit
    entry = cache.get("example.com", TYPE_A)
    assert entry is not None
    assert entry.remaining_ttl(current_time) == 300

    # Advance time by 100 seconds
    current_time += 100.0
    req = DNSPacket(
        header=DNSHeader(id=2),
        questions=[DNSQuestion(name="example.com", qtype=TYPE_A)],
    )
    resp = cache.build_response(req, entry)
    assert resp.answers[0].ttl == 200

    # Advance time past expiration (total 350s > 300s)
    current_time += 250.0
    assert cache.get("example.com", TYPE_A) is None


def test_cache_ttl_clamping() -> None:
    cache = DNSCache(min_ttl=60, max_ttl=1000)

    # Response with tiny TTL (5s) should be clamped up to min_ttl (60s)
    packet_small = DNSPacket(
        header=DNSHeader(id=1, rcode=RCODE_NOERROR),
        answers=[
            DNSRecord(
                name="fast.com",
                rtype=TYPE_A,
                rclass=CLASS_IN,
                ttl=5,
                rdata="1.2.3.4",
            )
        ],
    )
    entry_small = cache.set("fast.com", TYPE_A, packet_small)
    assert entry_small is not None
    assert entry_small.expires_at - entry_small.created_at == 60

    # Response with huge TTL (86400s) should be clamped down to max_ttl (1000s)
    packet_large = DNSPacket(
        header=DNSHeader(id=2, rcode=RCODE_NOERROR),
        answers=[
            DNSRecord(
                name="slow.com",
                rtype=TYPE_A,
                rclass=CLASS_IN,
                ttl=86400,
                rdata="1.2.3.4",
            )
        ],
    )
    entry_large = cache.set("slow.com", TYPE_A, packet_large)
    assert entry_large is not None
    assert entry_large.expires_at - entry_large.created_at == 1000


def test_negative_caching_rfc2308() -> None:
    cache = DNSCache(min_ttl=10, max_ttl=3600)

    # NXDOMAIN with SOA (SOA.TTL=1800, SOA.MINIMUM=120) -> neg TTL = min(1800, 120) = 120
    nx_packet = DNSPacket(
        header=DNSHeader(id=1, rcode=RCODE_NXDOMAIN),
        authorities=[
            DNSRecord(
                name="domain.org",
                rtype=TYPE_SOA,
                rclass=CLASS_IN,
                ttl=1800,
                rdata=SOARecordData(
                    mname="ns.domain.org",
                    rname="hostmaster.domain.org",
                    serial=1,
                    refresh=7200,
                    retry=3600,
                    expire=1209600,
                    minimum=120,
                ),
            )
        ],
    )
    entry = cache.set("nonexistent.domain.org", TYPE_A, nx_packet)
    assert entry is not None
    assert entry.is_negative is True
    assert entry.expires_at - entry.created_at == 120


def test_lru_eviction() -> None:
    cache = DNSCache(max_size=2)

    p1 = DNSPacket(header=DNSHeader(id=1, rcode=0), answers=[DNSRecord("d1.com", TYPE_A, 1, 300, "1.1.1.1")])
    p2 = DNSPacket(header=DNSHeader(id=2, rcode=0), answers=[DNSRecord("d2.com", TYPE_A, 1, 300, "1.1.1.2")])
    p3 = DNSPacket(header=DNSHeader(id=3, rcode=0), answers=[DNSRecord("d3.com", TYPE_A, 1, 300, "1.1.1.3")])

    cache.set("d1.com", TYPE_A, p1)
    cache.set("d2.com", TYPE_A, p2)
    assert len(cache) == 2

    # Access d1 so d2 becomes the least recently used
    assert cache.get("d1.com", TYPE_A) is not None

    # Insert d3 -> d2 must be evicted
    cache.set("d3.com", TYPE_A, p3)
    assert len(cache) == 2
    assert cache.get("d2.com", TYPE_A) is None
    assert cache.get("d1.com", TYPE_A) is not None
    assert cache.get("d3.com", TYPE_A) is not None


def test_cname_targets_extraction() -> None:
    cache = DNSCache()
    packet = DNSPacket(
        header=DNSHeader(id=1, rcode=0),
        answers=[
            DNSRecord("portal.com", TYPE_CNAME, 1, 300, "cdn.portal.com"),
            DNSRecord("cdn.portal.com", TYPE_CNAME, 1, 300, "tracker.adservice.net"),
            DNSRecord("tracker.adservice.net", TYPE_A, 1, 300, "1.2.3.4"),
        ],
    )
    entry = cache.set("portal.com", TYPE_A, packet)
    assert entry is not None
    assert entry.cname_targets == ("cdn.portal.com", "tracker.adservice.net")
