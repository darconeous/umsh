#!/usr/bin/env python3
"""
Generate a pcap file containing the UMSH test-vector packets as UDP payloads:
Examples 1-8, 10 and 11 (Example 9 is a set of derivations, not a frame).

Each packet is sent from 127.0.0.1:1234 to 127.0.0.1:15056 so that Wireshark
(through the UMSH dissector's default UDP port, or its heuristic)
will parse them.

Usage:
    python3 make_test_pcap.py > test_vectors.pcap
    # or write to a file:
    python3 make_test_pcap.py test_vectors.pcap
"""

import struct
import sys
import time

# ─────────────────────────────────────────────────────────────────────────────
# Test-vector packet bytes from docs/protocol/src/test-vectors.md
# ─────────────────────────────────────────────────────────────────────────────

VECTORS = [
    (
        "Example 1: Broadcast Beacon (S=0)",
        bytes.fromhex("C0 ED 54 A5".replace(" ", "")),
    ),
    (
        "Example 2: Broadcast Beacon (S=1)",
        bytes.fromhex(
            "C4 ED 54 A5 9F B1 AC 3A 51 23 93 51 36 29 41 B8"
            " 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC 7A 69 C2 79"
            .replace(" ", "")
        ),
    ),
    (
        "Example 3: Encrypted Unicast (S=0)",
        bytes.fromhex(
            "D0 6C 28 FD ED 54 A5 E0 00 00 00 2A FF 8B 60 67"
            " EB 6C F6 D2 39 C9 05 12 41 ED 8C A4 C2 D8 89 1A"
            " 34 58"
            .replace(" ", "")
        ),
    ),
    (
        "Example 4: Encrypted Unicast with Ack Requested (S=1)",
        bytes.fromhex(
            "DC 6C 28 FD ED 54 A5 9F B1 AC 3A 51 23 93 51 36"
            " 29 41 B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC"
            " 7A 69 C2 79 E0 00 00 00 01 FF 4C A9 EB FE A5 FD"
            " 44 7A 2F E0 FF D5 57 B5 4E E6 E8 91 81"
            .replace(" ", "")
        ),
    ),
    (
        "Example 5: Encrypted Multicast (E=1)",
        bytes.fromhex(
            "E0 B0 8D E0 00 00 00 05 FF D4 4B B6 0E 34 6D E5"
            " F4 F3 C4 8B 8F 96 EA A1 EF F6 19 47 E8 49 77 16"
            " 70"
            .replace(" ", "")
        ),
    ),
    (
        "Example 6: Authenticated Multicast (E=0)",
        bytes.fromhex(
            "E0 B0 8D 60 00 00 00 03 FF ED 54 A5 03 48 65 6C"
            " 6C 6F 14 0E 9E 52 53 A7 3F A6 58 3C 0C 94 C1 5E"
            " EA 9F"
            .replace(" ", "")
        ),
    ),
    (
        "Example 7: Encrypted Unicast with Options and Flood Hops",
        bytes.fromhex(
            "D1 40 6C 28 FD ED 54 A5 E0 00 00 00 0A 70 42 78"
            " 53 FF B7 C4 59 EC 72 BD EA E9 59 DB 86 BA AD 14"
            " 9C 92 5F B4 0B"
            .replace(" ", "")
        ),
    ),
    (
        "Example 8: Blind Unicast (S=0)",
        bytes.fromhex(
            "F0 B0 8D E0 00 00 00 07 FF 1D 7D 4C CE 9C 9E B7"
            " B1 EE 01 4B AF 4C 3E 68 BD 61 82 47 53 98 47 CF"
            " F9 0C 28 70"
            .replace(" ", "")
        ),
    ),
    (
        "Example 10: MAC Ack",
        bytes.fromhex("C8 FE A5 FD 44 16 61 6C D1".replace(" ", "")),
    ),
    (
        "Example 11: MAC Ack with Operator Callsign",
        bytes.fromhex(
            "C8 44 5B BB 08 2C FE A5 FD 44 15 B2 56 E4".replace(" ", "")
        ),
    ),
]

# ─────────────────────────────────────────────────────────────────────────────
# Minimal pcap writer (libpcap format, no scapy dependency)
# ─────────────────────────────────────────────────────────────────────────────

PCAP_MAGIC    = 0xA1B2C3D4
PCAP_VER_MAJ  = 2
PCAP_VER_MIN  = 4
LINKTYPE_EN10MB = 1   # Ethernet

def pcap_global_header():
    return struct.pack(
        "<IHHiIII",
        PCAP_MAGIC,      # magic
        PCAP_VER_MAJ,    # version major
        PCAP_VER_MIN,    # version minor
        0,               # GMT offset
        0,               # timestamp accuracy
        65535,           # snaplen
        LINKTYPE_EN10MB, # link-layer header type
    )

def pcap_record(ts_sec, ts_usec, payload):
    cap_len = len(payload)
    return struct.pack("<IIII", ts_sec, ts_usec, cap_len, cap_len) + payload

def eth_ip_udp(payload, src_port=1234, dst_port=15056,
               src_ip="127.0.0.1", dst_ip="127.0.0.1"):
    """Wrap `payload` in a minimal Ethernet/IP/UDP frame."""
    def ip4(s):
        return bytes(int(x) for x in s.split("."))

    # UDP
    udp_len   = 8 + len(payload)
    udp_hdr   = struct.pack(">HHHH", src_port, dst_port, udp_len, 0)

    # IP (no options)
    ip_len    = 20 + udp_len
    ip_hdr    = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0,          # version/IHL, DSCP/ECN
        ip_len,
        0, 0,             # ID, flags/fragment offset
        64, 17,           # TTL, protocol (UDP=17)
        0,                # checksum (0 = let receiver ignore)
        ip4(src_ip), ip4(dst_ip),
    )

    # Ethernet (fake MACs, EtherType=IPv4)
    eth = bytes(6) + bytes(6) + struct.pack(">H", 0x0800)

    return eth + ip_hdr + udp_hdr + payload


def make_pcap(vectors):
    ts_base = int(time.time())
    out = pcap_global_header()
    for i, (name, pkt_bytes) in enumerate(vectors):
        frame = eth_ip_udp(pkt_bytes)
        out  += pcap_record(ts_base + i, 0, frame)
    return out


if __name__ == "__main__":
    data = make_pcap(VECTORS)
    if len(sys.argv) > 1:
        with open(sys.argv[1], "wb") as fh:
            fh.write(data)
        print(f"Written {len(VECTORS)} packets to {sys.argv[1]}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(data)
