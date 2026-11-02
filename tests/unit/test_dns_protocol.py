"""Unit tests for DNS wire parser/serializer (RFC 1035).

Cross-checks against dnspython in both directions.
"""

import dns.message
import dns.rdatatype
import pytest

from reqko.dns.protocol import (
    CLASS_IN,
    RCODE_FORMERR,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    RCODE_REFUSED,
    TYPE_A,
    TYPE_AAAA,
    TYPE_ANY,
    TYPE_CNAME,
    TYPE_SOA,
    DNSFormatError,
    DNSHeader,
    DNSPacket,
    DNSQuestion,
    DNSRecord,
    SOARecordData,
    make_blocking_response,
    make_response,
    parse_wire,
)


def test_roundtrip_basic_query() -> None:
    # 1. Create a query with dnspython
    dnspy_msg = dns.message.make_query("example.com", "A")
    wire_data = dnspy_msg.to_wire()

    # 2. Parse with our parser
    packet = parse_wire(wire_data)
    assert packet.header.id == dnspy_msg.id
    assert packet.header.qr == 0
    assert len(packet.questions) == 1
    assert packet.questions[0].name == "example.com"
    assert packet.questions[0].qtype == TYPE_A
    assert packet.questions[0].qclass == CLASS_IN

    # 3. Serialize back and parse with dnspython
    our_wire = packet.to_wire()
    dnspy_parsed = dns.message.from_wire(our_wire)
    assert dnspy_parsed.id == dnspy_msg.id
    assert dnspy_parsed.question[0].name.to_text() == "example.com."
    assert dnspy_parsed.question[0].rdtype == dns.rdatatype.A


def test_roundtrip_response_with_records() -> None:
    header = DNSHeader(id=0x1234, qr=1, aa=1, rd=1, ra=1, rcode=RCODE_NOERROR)
    packet = DNSPacket(
        header=header,
        questions=[DNSQuestion(name="api.example.com", qtype=TYPE_A)],
        answers=[
            DNSRecord(
                name="api.example.com",
                rtype=TYPE_CNAME,
                rclass=CLASS_IN,
                ttl=300,
                rdata="lb.example.com",
            ),
            DNSRecord(
                name="lb.example.com",
                rtype=TYPE_A,
                rclass=CLASS_IN,
                ttl=60,
                rdata="93.184.216.34",
            ),
        ],
        authorities=[
            DNSRecord(
                name="example.com",
                rtype=TYPE_SOA,
                rclass=CLASS_IN,
                ttl=3600,
                rdata=SOARecordData(
                    mname="ns1.example.com",
                    rname="hostmaster.example.com",
                    serial=2026110201,
                    refresh=7200,
                    retry=3600,
                    expire=1209600,
                    minimum=300,
                ),
            )
        ],
    )

    wire = packet.to_wire()

    # Check with dnspython
    dnspy_msg = dns.message.from_wire(wire)
    assert dnspy_msg.id == 0x1234
    assert len(dnspy_msg.answer) == 2
    assert dnspy_msg.answer[0].name.to_text() == "api.example.com."
    assert dnspy_msg.answer[0].rdtype == dns.rdatatype.CNAME
    assert dnspy_msg.answer[1].name.to_text() == "lb.example.com."
    assert dnspy_msg.answer[1].rdtype == dns.rdatatype.A

    # Parse wire back with our parser
    parsed_packet = parse_wire(wire)
    assert parsed_packet.header.id == 0x1234
    assert len(parsed_packet.answers) == 2
    assert parsed_packet.answers[0].rdata == "lb.example.com"
    assert parsed_packet.answers[1].rdata == "93.184.216.34"
    assert len(parsed_packet.authorities) == 1
    soa = parsed_packet.authorities[0].rdata
    assert isinstance(soa, SOARecordData)
    assert soa.mname == "ns1.example.com"
    assert soa.minimum == 300


def test_roundtrip_dnspython_to_reqko() -> None:
    # Build a complex response in dnspython
    msg = dns.message.make_response(dns.message.make_query("sub.domain.org", "AAAA"))
    rrset_cname = dns.rrset.from_text("sub.domain.org.", 120, "IN", "CNAME", "target.domain.org.")
    rrset_aaaa = dns.rrset.from_text("target.domain.org.", 60, "IN", "AAAA", "2606:2800:220:1:248:1893:25c8:1946")
    msg.answer.extend([rrset_cname, rrset_aaaa])
    wire = msg.to_wire()

    parsed = parse_wire(wire)
    assert parsed.header.qr == 1
    assert parsed.questions[0].name == "sub.domain.org"
    assert parsed.questions[0].qtype == TYPE_AAAA
    assert len(parsed.answers) == 2
    assert parsed.answers[0].rtype == TYPE_CNAME
    assert parsed.answers[0].rdata == "target.domain.org"
    assert parsed.answers[1].rtype == TYPE_AAAA
    assert parsed.answers[1].rdata == "2606:2800:220:1:248:1893:25c8:1946"


def test_malformed_truncated_packet() -> None:
    with pytest.raises(DNSFormatError, match="Packet shorter than DNS header"):
        parse_wire(b"\x00\x01\x01")


def test_compression_loop_detection() -> None:
    # Header: 12 bytes
    header = DNSHeader(id=1, qdcount=1).to_wire()
    # Malformed question name with pointer pointing to itself (offset 12 -> \xC0\x0C)
    loop_packet = header + b"\xc0\x0c\x00\x01\x00\x01"
    with pytest.raises(DNSFormatError, match="loop detected"):
        parse_wire(loop_packet)


def test_invalid_label_length() -> None:
    # Label length says 60, but packet ends prematurely
    header = DNSHeader(id=1, qdcount=1).to_wire()
    bad_packet = header + b"\x3cabc\x00\x00\x01\x00\x01"
    with pytest.raises(DNSFormatError):
        parse_wire(bad_packet)


def test_name_exceeds_255_octets() -> None:
    # 5 labels of 60 chars each = 300 octets
    long_domain = ".".join(["a" * 60] * 5)
    with pytest.raises(DNSFormatError, match="exceeds 255 octets"):
        q = DNSQuestion(name=long_domain, qtype=TYPE_A)
        q.to_wire()


def test_make_blocking_response() -> None:
    req = DNSPacket(
        header=DNSHeader(id=0xCAFE),
        questions=[DNSQuestion(name="adserver.com", qtype=TYPE_A)],
    )

    # NULL mode
    null_resp = make_blocking_response(req, block_mode="NULL")
    assert null_resp.header.rcode == RCODE_NOERROR
    assert len(null_resp.answers) == 1
    assert null_resp.answers[0].rdata == "0.0.0.0"

    # AAAA NULL mode
    req_aaaa = DNSPacket(
        header=DNSHeader(id=0xCAFE),
        questions=[DNSQuestion(name="adserver.com", qtype=TYPE_AAAA)],
    )
    null_aaaa = make_blocking_response(req_aaaa, block_mode="NULL")
    assert null_aaaa.answers[0].rdata == "::"

    # NXDOMAIN mode
    nx_resp = make_blocking_response(req, block_mode="NXDOMAIN")
    assert nx_resp.header.rcode == RCODE_NXDOMAIN
    assert len(nx_resp.answers) == 0

    # NODATA mode
    nodata_resp = make_blocking_response(req, block_mode="NODATA")
    assert nodata_resp.header.rcode == RCODE_NOERROR
    assert len(nodata_resp.answers) == 0

    # Custom make_response with RCODE_FORMERR and RCODE_REFUSED
    err_resp = make_response(req, rcode=RCODE_FORMERR)
    assert err_resp.header.rcode == RCODE_FORMERR
    assert err_resp.header.qr == 1

    refused_resp = make_response(req, rcode=RCODE_REFUSED)
    assert refused_resp.header.rcode == RCODE_REFUSED

    # ANY query
    any_req = DNSPacket(
        header=DNSHeader(id=0xBEEF),
        questions=[DNSQuestion(name="example.com", qtype=TYPE_ANY)],
    )
    assert any_req.questions[0].qtype == TYPE_ANY
