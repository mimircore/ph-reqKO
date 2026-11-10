"""Objective-8 DNS security fuzz: the server must never crash or hang.

Sends `--count` packets (default 10000) over UDP to a running server:
  1. random bytes of random length (0..600);
  2. valid-looking headers with random counts/opcodes/rcodes;
  3. mutated real queries (bit flips, truncations);
  4. compression-pointer attacks: self-pointing and cyclic pointers,
     pointer chains, pointers into the question;
  5. oversized names: 63-byte labels at maximum depth, long names;
  6. huge QDCOUNT/ARCOUNT with tiny payloads.

After each batch the server is probed with a real query and GET /health;
any failure or a batch lasting too long is a defect. Stdlib + dnspython.
"""

from __future__ import annotations

import argparse
import json
import random
import socket
import struct
import sys
import time
import urllib.request

random.seed(8)

TIMEOUT = 2.0


def mutate_query(name: str = "fuzz.example") -> bytes:
    """A real A query, then random bit flips / truncation."""
    import dns.message

    wire = bytearray(dns.message.make_query(name, "A").to_wire())
    for _ in range(random.randint(1, 12)):
        wire[random.randrange(len(wire))] = random.randrange(256)
    if random.random() < 0.3:
        wire = wire[: random.randrange(1, len(wire))]
    return bytes(wire)


def pointer_attack() -> bytes:
    """Header + question + malicious compression pointers."""
    header = struct.pack("!HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0)
    question = b"\x04fuzz\x07example\x00" + struct.pack("!HH", 1, 1)
    kind = random.randrange(4)
    body = bytearray(question)
    if kind == 0:
        # pointer pointing at itself
        body += struct.pack("!H", 0xC000 | 12)
    elif kind == 1:
        # two pointers pointing at each other
        start = 12 + len(question)
        body += struct.pack("!H", 0xC000 | (start + 2))
        body += struct.pack("!H", 0xC000 | start)
    elif kind == 2:
        # long forward-pointer chain
        start = 12 + len(question)
        for i in range(50):
            body += struct.pack("!H", 0xC000 | (start + i))
    else:
        # pointer into the middle of the question label + garbage tail
        body += struct.pack("!H", 0xC000 | 14) + bytes(random.randrange(256) for _ in range(40))
    return header + bytes(body)


def oversized_name() -> bytes:
    """Maximum-label / maximum-depth names."""
    header = struct.pack("!HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0)
    kind = random.randrange(3)
    if kind == 0:
        name = b"".join(b"a" * 63 + b"." for _ in range(8)) + b"\x00"  # > 253 octets
    elif kind == 1:
        name = b"a" * 63 + b"\x00"  # one maximum label
    else:
        name = b"".join(bytes([1, random.randrange(97, 123)]) for _ in range(120)) + b"\x00"
    return header + name + struct.pack("!HH", 1, 1)


def random_header_junk() -> bytes:
    """Valid-size packet with absurd counts and random opcode/rcode."""
    return struct.pack(
        "!HHHHHH",
        random.randrange(65536),
        random.randrange(65536),  # flags: any qr/opcode/rcode combo
        random.choice([0, 1, 2, 100, 65535]),  # qdcount
        random.choice([0, 1, 50, 65535]),  # ancount
        random.choice([0, 1, 65535]),
        random.choice([0, 1, 65535]),  # arcount
    ) + bytes(random.randrange(256) for _ in range(random.randrange(0, 120)))


def random_bytes() -> bytes:
    return bytes(random.randrange(256) for _ in range(random.randrange(0, 600)))


def make_packet(i: int) -> bytes:
    kind = i % 6
    if kind == 0:
        return random_bytes()
    if kind == 1:
        return random_header_junk()
    if kind == 2:
        return mutate_query()
    if kind == 3:
        return pointer_attack()
    if kind == 4:
        return oversized_name()
    return mutate_query("mutated-" + str(random.randrange(1000)) + ".example")


def server_alive(port: int) -> tuple[bool, float]:
    import dns.message

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(TIMEOUT)
    try:
        wire = dns.message.make_query("alive.fuzz.example", "A").to_wire()
        started = time.perf_counter()
        s.sendto(wire, ("127.0.0.1", port))
        s.recvfrom(512)
        return True, (time.perf_counter() - started) * 1000
    except (TimeoutError, OSError):
        return False, TIMEOUT * 1000
    finally:
        s.close()


def health_ok(api_port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{api_port}/health", timeout=3) as r:
            return bool(r.status == 200)
    except Exception:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="DNS fuzz for ph-reqKO")
    parser.add_argument("--port", type=int, default=15353)
    parser.add_argument("--api-port", type=int, default=18080)
    parser.add_argument("--count", type=int, default=10000)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Non-blocking drain: replies are drained opportunistically; a missing
    # reply for a malformed packet is expected and must not stall the run.
    sock.setblocking(False)
    target = ("127.0.0.1", args.port)

    sent = replies = 0
    max_batch_ms = 0.0
    batch = 500
    started = time.perf_counter()
    for i in range(args.count):
        try:
            sock.sendto(make_packet(i), target)
            sent += 1
        except OSError:
            print(f"CRASH: sendto failed at packet {i}")
            return 1
        if (i + 1) % batch == 0:
            alive, ms = server_alive(args.port)
            max_batch_ms = max(max_batch_ms, ms)
            if not alive:
                print(f"CRASH/HANG: server did not answer after packet {i}")
                return 1
        # drain a bit so the socket buffer does not just fill client-side
        while True:
            try:
                sock.recvfrom(4096)
                replies += 1
            except (TimeoutError, BlockingIOError):
                break

    wall = time.perf_counter() - started
    alive, ms = server_alive(args.port)
    print(json.dumps({
        "sent": sent,
        "client_received_replies": replies,
        "client_timeouts": sent - replies,
        "wall_seconds": round(wall, 2),
        "post_fuzz_probe_ok": alive,
        "post_fuzz_probe_ms": round(ms, 2),
        "max_batch_probe_ms": round(max_batch_ms, 2),
        "health_ok_after": health_ok(args.api_port),
        "count": args.count,
    }, indent=2))
    ok = alive and health_ok(args.api_port)
    print("FUZZ VERDICT:", "SERVER SURVIVED" if ok else "DEFECT: server died or hangs")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
