#!/usr/bin/env python3
"""
Generate a pcap file containing all 8 UMSH test-vector packets as UDP payloads.

Each packet is sent from 127.0.0.1:1234 to 127.0.0.1:4242 so that Wireshark
(with udp_port=4242 set in the UMSH preferences, or heuristic detection enabled)
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
            "D0 6C 28 FD ED 54 A5 E0 00 00 00 2A FF 71 35 36"
            " 4B C1 97 6D DC 92 2E BA 11 B7 2E 6B B1 7B 36 49"
            " C5 4A"
            .replace(" ", "")
        ),
    ),
    (
        "Example 4: Encrypted Unicast with Ack Requested (S=1)",
        bytes.fromhex(
            "DC 6C 28 FD ED 54 A5 9F B1 AC 3A 51 23 93 51 36"
            " 29 41 B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC"
            " 7A 69 C2 79 E0 00 00 00 01 FF 9C 77 59 E9 9F 4C"
            " 5F 9D 3E 4F 4E D3 CC B2 1E F5 C0 01 97"
            .replace(" ", "")
        ),
    ),
    (
        "Example 5: Encrypted Multicast (E=1)",
        bytes.fromhex(
            "E0 B0 8D E0 00 00 00 05 FF 39 E5 95 FE 97 AF A8"
            " 90 30 E3 26 92 83 DB 9A 69 AB 12 64 1E B3 22 42"
            " D6"
            .replace(" ", "")
        ),
    ),
    (
        "Example 6: Authenticated Multicast (E=0)",
        bytes.fromhex(
            "E0 B0 8D 60 00 00 00 03 FF ED 54 A5 03 48 65 6C"
            " 6C 6F 53 A5 E2 91 F5 40 0A B9 87 FE C7 14 9D F8"
            " 97 24"
            .replace(" ", "")
        ),
    ),
    (
        "Example 7: Encrypted Unicast with Options and Flood Hops",
        bytes.fromhex(
            "D1 40 6C 28 FD ED 54 A5 E0 00 00 00 0A 20 92 78"
            " 53 FF F4 CF 71 C4 91 19 48 E1 C8 F1 32 05 6A 16"
            " B1 06 34 74 D5"
            .replace(" ", "")
        ),
    ),
    (
        "Example 8: Blind Unicast (S=0)",
        bytes.fromhex(
            "F0 B0 8D E0 00 00 00 07 FF A4 FB D3 6A A0 87 4E"
            " 55 F2 08 51 F6 21 C9 8C 78 F7 90 92 34 0D E7 12"
            " AA 07 AE 77"
            .replace(" ", "")
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

def eth_ip_udp(payload, src_port=1234, dst_port=4242,
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
