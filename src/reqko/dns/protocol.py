"""DNS wire protocol parser and serializer (RFC 1035).

Supports Header, Question, and Records (A, AAAA, CNAME, SOA, and raw RDATA)
with wire name compression (0xC0), loop detection, and strict validation.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from typing import Any

# DNS Classes
CLASS_IN = 1

# DNS Record Types
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_PTR = 12
TYPE_MX = 15
TYPE_TXT = 16
TYPE_AAAA = 28
TYPE_ANY = 255
TYPE_OPT = 41  # EDNS0 pseudo-RR (RFC 6891)

# EDNS0 (RFC 6891) constants
EDNS_PAYLOAD_SIZE = 1232  # DNS FLAG Day 2020 recommended buffer size

# DNS Response Codes (RCODE)
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4
RCODE_REFUSED = 5

# DNS Opcodes
OPCODE_QUERY = 0

TYPE_NAME_TO_INT: dict[str, int] = {
    "A": TYPE_A,
    "NS": TYPE_NS,
    "CNAME": TYPE_CNAME,
    "SOA": TYPE_SOA,
    "PTR": TYPE_PTR,
    "MX": TYPE_MX,
    "TXT": TYPE_TXT,
    "AAAA": TYPE_AAAA,
    "ANY": TYPE_ANY,
}

INT_TO_TYPE_NAME: dict[int, str] = {v: k for k, v in TYPE_NAME_TO_INT.items()}


class DNSFormatError(ValueError):
    """Raised when parsing a malformed DNS wire packet."""


@dataclass
class DNSHeader:
    id: int
    qr: int = 0  # 0 = query, 1 = response
    opcode: int = OPCODE_QUERY
    aa: int = 0  # Authoritative Answer
    tc: int = 0  # TrunCation
    rd: int = 1  # Recursion Desired
    ra: int = 0  # Recursion Available
    z: int = 0  # Reserved
    rcode: int = RCODE_NOERROR
    qdcount: int = 0
    ancount: int = 0
    nscount: int = 0
    arcount: int = 0

    def to_wire(self) -> bytes:
        flags = (
            ((self.qr & 0x01) << 15)
            | ((self.opcode & 0x0F) << 11)
            | ((self.aa & 0x01) << 10)
            | ((self.tc & 0x01) << 9)
            | ((self.rd & 0x01) << 8)
            | ((self.ra & 0x01) << 7)
            | ((self.z & 0x07) << 4)
            | (self.rcode & 0x0F)
        )
        return struct.pack(
            "!HHHHHH",
            self.id,
            flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        )

    @classmethod
    def from_wire(cls, data: bytes, offset: int = 0) -> tuple[DNSHeader, int]:
        if len(data) - offset < 12:
            raise DNSFormatError("Packet shorter than DNS header (12 bytes)")
        header_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
            "!HHHHHH", data, offset
        )
        qr = (flags >> 15) & 0x01
        opcode = (flags >> 11) & 0x0F
        aa = (flags >> 10) & 0x01
        tc = (flags >> 9) & 0x01
        rd = (flags >> 8) & 0x01
        ra = (flags >> 7) & 0x01
        z = (flags >> 4) & 0x07
        rcode = flags & 0x0F
        return (
            cls(
                id=header_id,
                qr=qr,
                opcode=opcode,
                aa=aa,
                tc=tc,
                rd=rd,
                ra=ra,
                z=z,
                rcode=rcode,
                qdcount=qdcount,
                ancount=ancount,
                nscount=nscount,
                arcount=arcount,
            ),
            offset + 12,
        )


@dataclass
class DNSQuestion:
    name: str  # Lowercase, no trailing dot
    qtype: int
    qclass: int = CLASS_IN

    def to_wire(self, compression_map: dict[str, int] | None = None) -> bytes:
        wire_name = encode_domain_name(self.name, compression_map)
        return wire_name + struct.pack("!HH", self.qtype, self.qclass)


@dataclass
class SOARecordData:
    mname: str
    rname: str
    serial: int
    refresh: int
    retry: int
    expire: int
    minimum: int


def append_domain_name(
    buffer: bytearray, name: str, compression_map: dict[str, int]
) -> None:
    """Appends an RFC 1035 encoded domain name to buffer with compression pointer tracking."""
    norm_name = name.strip(".").lower()
    if not norm_name:
        # Root name ("." or "") encodes as a single zero-length label
        buffer.append(0)
        return

    labels = norm_name.split(".")

    for i in range(len(labels)):
        suffix = ".".join(labels[i:])
        if suffix in compression_map:
            ptr = compression_map[suffix]
            ptr_val = 0xC000 | (ptr & 0x3FFF)
            buffer.extend(struct.pack("!H", ptr_val))
            return

        curr_offset = len(buffer)
        if curr_offset <= 0x3FFF:
            compression_map[suffix] = curr_offset

        label = labels[i]
        b_label = label.encode("ascii")
        if len(b_label) > 63:
            raise DNSFormatError(f"Label '{label}' exceeds 63 octets")
        buffer.append(len(b_label))
        buffer.extend(b_label)

    buffer.append(0)


def encode_domain_name(name: str, compression_map: dict[str, int] | None = None) -> bytes:
    """Encodes a domain name into wire format without external buffer tracking."""
    buf = bytearray()
    append_domain_name(buf, name, compression_map if compression_map is not None else {})
    if len(buf) > 255:
        raise DNSFormatError("Encoded domain name exceeds 255 octets")
    return bytes(buf)


@dataclass
class DNSRecord:
    name: str
    rtype: int
    rclass: int
    ttl: int
    rdata: Any  # str (IP or domain), SOARecordData, or bytes

    def to_wire(self, compression_map: dict[str, int] | None = None) -> bytes:
        wire_name = encode_domain_name(self.name, compression_map)
        wire_rdata = self._encode_rdata(compression_map)
        return (
            wire_name
            + struct.pack("!HHIH", self.rtype, self.rclass, self.ttl, len(wire_rdata))
            + wire_rdata
        )

    def _encode_rdata(self, compression_map: dict[str, int] | None = None) -> bytes:
        if self.rtype == TYPE_A:
            if isinstance(self.rdata, str):
                return ipaddress.IPv4Address(self.rdata).packed
            return bytes(self.rdata)
        elif self.rtype == TYPE_AAAA:
            if isinstance(self.rdata, str):
                return ipaddress.IPv6Address(self.rdata).packed
            return bytes(self.rdata)
        elif self.rtype == TYPE_CNAME:
            target = self.rdata if isinstance(self.rdata, str) else str(self.rdata)
            return encode_domain_name(target, compression_map)
        elif self.rtype == TYPE_SOA:
            if isinstance(self.rdata, SOARecordData):
                mname_bytes = encode_domain_name(self.rdata.mname, compression_map)
                rname_bytes = encode_domain_name(self.rdata.rname, compression_map)
                soa_params = struct.pack(
                    "!IIIII",
                    self.rdata.serial,
                    self.rdata.refresh,
                    self.rdata.retry,
                    self.rdata.expire,
                    self.rdata.minimum,
                )
                return mname_bytes + rname_bytes + soa_params
            raise DNSFormatError(f"Invalid SOA rdata: {self.rdata}")
        else:
            if isinstance(self.rdata, bytes):
                return self.rdata
            if isinstance(self.rdata, str):
                return self.rdata.encode("utf-8")
            return bytes(self.rdata)


@dataclass
class DNSPacket:
    header: DNSHeader
    questions: list[DNSQuestion] = field(default_factory=list)
    answers: list[DNSRecord] = field(default_factory=list)
    authorities: list[DNSRecord] = field(default_factory=list)
    additionals: list[DNSRecord] = field(default_factory=list)

    def to_wire(self) -> bytes:
        self.header.qdcount = len(self.questions)
        self.header.ancount = len(self.answers)
        self.header.nscount = len(self.authorities)
        self.header.arcount = len(self.additionals)

        buffer = bytearray(self.header.to_wire())
        compression_map: dict[str, int] = {}

        for q in self.questions:
            append_domain_name(buffer, q.name, compression_map)
            buffer.extend(struct.pack("!HH", q.qtype, q.qclass))

        for section in (self.answers, self.authorities, self.additionals):
            for rr in section:
                append_domain_name(buffer, rr.name, compression_map)
                if rr.rtype == TYPE_CNAME and isinstance(rr.rdata, str):
                    buffer.extend(struct.pack("!HHI", rr.rtype, rr.rclass, rr.ttl))
                    offset_rdlen = len(buffer)
                    buffer.extend(b"\x00\x00")
                    rdata_start = len(buffer)
                    append_domain_name(buffer, rr.rdata, compression_map)
                    rdlength = len(buffer) - rdata_start
                    struct.pack_into("!H", buffer, offset_rdlen, rdlength)
                elif rr.rtype == TYPE_SOA and isinstance(rr.rdata, SOARecordData):
                    buffer.extend(struct.pack("!HHI", rr.rtype, rr.rclass, rr.ttl))
                    offset_rdlen = len(buffer)
                    buffer.extend(b"\x00\x00")
                    rdata_start = len(buffer)
                    append_domain_name(buffer, rr.rdata.mname, compression_map)
                    append_domain_name(buffer, rr.rdata.rname, compression_map)
                    buffer.extend(
                        struct.pack(
                            "!IIIII",
                            rr.rdata.serial,
                            rr.rdata.refresh,
                            rr.rdata.retry,
                            rr.rdata.expire,
                            rr.rdata.minimum,
                        )
                    )
                    rdlength = len(buffer) - rdata_start
                    struct.pack_into("!H", buffer, offset_rdlen, rdlength)
                else:
                    rdata_bytes = rr._encode_rdata(None)
                    buffer.extend(
                        struct.pack("!HHIH", rr.rtype, rr.rclass, rr.ttl, len(rdata_bytes))
                    )
                    buffer.extend(rdata_bytes)

        return bytes(buffer)


def decode_domain_name(data: bytes, offset: int) -> tuple[str, int]:
    """Decodes a domain name from wire format with compression pointer support.

    Returns (normalized_name, next_offset).
    Detects compression loops and enforces max name length (255) and label length (63).
    """
    labels: list[str] = []
    curr = offset
    jumped = False
    next_offset = -1
    total_len = 0
    visited_offsets: set[int] = set()
    jumps_count = 0
    max_jumps = 50

    while True:
        if curr >= len(data):
            raise DNSFormatError(f"Unexpected EOF while reading domain name at offset {curr}")

        length = data[curr]

        # Check for compression pointer (top two bits set: 0xC0)
        if (length & 0xC0) == 0xC0:
            if curr + 1 >= len(data):
                raise DNSFormatError("Truncated compression pointer")
            if curr in visited_offsets or jumps_count > max_jumps:
                raise DNSFormatError("Compression pointer loop detected")
            visited_offsets.add(curr)
            jumps_count += 1

            pointer = ((length & 0x3F) << 8) | data[curr + 1]
            if pointer >= len(data):
                raise DNSFormatError(f"Compression pointer offset {pointer} exceeds packet length")

            if not jumped:
                next_offset = curr + 2
                jumped = True
            curr = pointer
            continue

        if (length & 0xC0) != 0:
            raise DNSFormatError(f"Invalid label tag {length:#x} at offset {curr}")

        # Normal label
        curr += 1
        if length == 0:
            # End of domain name
            if not jumped:
                next_offset = curr
            break

        if length > 63:
            raise DNSFormatError(f"Label length {length} exceeds maximum 63 octets")

        if curr + length > len(data):
            raise DNSFormatError(f"Label extends beyond packet length at offset {curr}")

        label_bytes = data[curr : curr + length]
        try:
            label_str = label_bytes.decode("ascii")
        except UnicodeDecodeError:
            label_str = label_bytes.decode("latin1")

        labels.append(label_str.lower())
        total_len += length + 1  # 1 octet for length prefix
        if total_len > 255:
            raise DNSFormatError("Total domain name length exceeds 255 octets")

        curr += length

    domain_name = ".".join(labels)
    return domain_name, next_offset



def parse_wire(data: bytes) -> DNSPacket:
    """Parses a full DNS packet from raw wire bytes (RFC 1035)."""
    header, offset = DNSHeader.from_wire(data)
    packet = DNSPacket(header=header)

    # Questions
    for _ in range(header.qdcount):
        name, offset = decode_domain_name(data, offset)
        if len(data) - offset < 4:
            raise DNSFormatError("Truncated question section")
        qtype, qclass = struct.unpack_from("!HH", data, offset)
        offset += 4
        packet.questions.append(DNSQuestion(name=name, qtype=qtype, qclass=qclass))

    # Resource records (Answers, Authorities, Additionals)
    for count, section in (
        (header.ancount, packet.answers),
        (header.nscount, packet.authorities),
        (header.arcount, packet.additionals),
    ):
        for _ in range(count):
            name, offset = decode_domain_name(data, offset)
            if len(data) - offset < 10:
                raise DNSFormatError("Truncated resource record header")
            rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            if len(data) - offset < rdlength:
                raise DNSFormatError(f"Truncated RDATA: expected {rdlength} bytes")

            rdata_raw = data[offset : offset + rdlength]

            # Parse known rdata
            rdata: Any = rdata_raw
            if rtype == TYPE_A:
                if rdlength == 4:
                    rdata = str(ipaddress.IPv4Address(rdata_raw))
                else:
                    raise DNSFormatError(f"Invalid A record rdlength: {rdlength}")
            elif rtype == TYPE_AAAA:
                if rdlength == 16:
                    rdata = str(ipaddress.IPv6Address(rdata_raw))
                else:
                    raise DNSFormatError(f"Invalid AAAA record rdlength: {rdlength}")
            elif rtype == TYPE_CNAME:
                target_name, _ = decode_domain_name(data, offset)
                rdata = target_name
            elif rtype == TYPE_SOA:
                mname, soa_off = decode_domain_name(data, offset)
                rname, soa_off = decode_domain_name(data, soa_off)
                if (offset + rdlength) - soa_off < 20:
                    raise DNSFormatError("Truncated SOA parameters")
                serial, refresh, retry, expire, minimum = struct.unpack_from(
                    "!IIIII", data, soa_off
                )
                rdata = SOARecordData(
                    mname=mname,
                    rname=rname,
                    serial=serial,
                    refresh=refresh,
                    retry=retry,
                    expire=expire,
                    minimum=minimum,
                )

            offset += rdlength
            section.append(
                DNSRecord(
                    name=name,
                    rtype=rtype,
                    rclass=rclass,
                    ttl=ttl,
                    rdata=rdata,
                )
            )

    return packet


def find_request_opt(request: DNSPacket) -> DNSRecord | None:
    """Returns the EDNS0 OPT pseudo-record from the request additionals, if any (RFC 6891)."""
    for rr in request.additionals:
        if rr.rtype == TYPE_OPT:
            return rr
    return None


def make_opt_record(do_flag: bool = False) -> DNSRecord:
    """Builds a fresh EDNS0 OPT pseudo-record (RFC 6891).

    The TTL field carries the extended RCODE (8 bits), version (8 bits),
    the DO bit and Z flags; the class field carries the responder payload size.
    """
    return DNSRecord(
        name=".",
        rtype=TYPE_OPT,
        rclass=EDNS_PAYLOAD_SIZE,
        ttl=(1 << 15) if do_flag else 0,
        rdata=b"",
    )


def make_response(
    request: DNSPacket,
    rcode: int = RCODE_NOERROR,
    aa: bool = False,
    ra: bool = True,
) -> DNSPacket:
    """Creates a response packet copying question and transaction ID from request.

    EDNS consistency: the response carries a fresh OPT record if and only if
    the client request contained one (STEP 2c / RFC 6891).
    """
    header = DNSHeader(
        id=request.header.id,
        qr=1,
        opcode=request.header.opcode,
        aa=1 if aa else 0,
        tc=0,
        rd=request.header.rd,
        ra=1 if ra else 0,
        z=0,
        rcode=rcode,
        qdcount=len(request.questions),
    )
    resp = DNSPacket(
        header=header,
        questions=list(request.questions),
    )
    client_opt = find_request_opt(request)
    if client_opt is not None:
        do_flag = bool(client_opt.ttl & 0x8000)
        resp.additionals.append(make_opt_record(do_flag=do_flag))
    return resp


def make_blocking_response(
    request: DNSPacket,
    block_mode: str,
    blocking_ipv4: str = "0.0.0.0",
    blocking_ipv6: str = "::",
    ttl: int = 300,
) -> DNSPacket:
    """Creates a blocked DNS response according to REQKO_BLOCK_MODE (FR-08).

    - NULL: NOERROR with 0.0.0.0 for A, :: for AAAA
    - NXDOMAIN: RCODE=3 (NXDOMAIN) with no answer records
    - NODATA: NOERROR with empty answer section
    """
    mode = block_mode.upper()
    if mode == "NXDOMAIN":
        return make_response(request, rcode=RCODE_NXDOMAIN, aa=True)
    elif mode == "NODATA":
        return make_response(request, rcode=RCODE_NOERROR, aa=True)
    else:  # NULL (default)
        resp = make_response(request, rcode=RCODE_NOERROR, aa=True)
        if request.questions:
            q = request.questions[0]
            if q.qtype == TYPE_A:
                resp.answers.append(
                    DNSRecord(
                        name=q.name,
                        rtype=TYPE_A,
                        rclass=CLASS_IN,
                        ttl=ttl,
                        rdata=blocking_ipv4,
                    )
                )
            elif q.qtype == TYPE_AAAA:
                resp.answers.append(
                    DNSRecord(
                        name=q.name,
                        rtype=TYPE_AAAA,
                        rclass=CLASS_IN,
                        ttl=ttl,
                        rdata=blocking_ipv6,
                    )
                )
        return resp
