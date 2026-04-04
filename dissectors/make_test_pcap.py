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
            "D0 6C 28 FD ED 54 A5 E0 00 00 00 2A 4F A0 84 B2"
            " 92 EA 32 F4 91 09 E8 D4 E6 01 16 73 C1 5B 31 84 F0"
            .replace(" ", "")
        ),
    ),
    (
        "Example 4: Encrypted Unicast with Ack Requested (S=1)",
        bytes.fromhex(
            "DC 6C 28 FD ED 54 A5 9F B1 AC 3A 51 23 93 51 36"
            " 29 41 B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC"
            " 7A 69 C2 79 E0 00 00 00 01 68 CF 7B 96 3F CE BA"
            " 86 8C 92 96 DD E2 E5 0F 5B 54 42 3F"
            .replace(" ", "")
        ),
    ),
    (
        "Example 5: Encrypted Multicast (E=1)",
        bytes.fromhex(
            "E0 B0 8D E0 00 00 00 05 9B B6 F2 5E C7 DA 95 D2"
            " 30 35 87 B0 01 F2 17 98 7A 08 1C F5 6E DC 85 36"
            .replace(" ", "")
        ),
    ),
    (
        "Example 6: Authenticated Multicast (E=0)",
        bytes.fromhex(
            "E0 B0 8D 60 00 00 00 03 ED 54 A5 03 48 65 6C 6C"
            " 6F 7C 9A 9C 4B C0 DD B4 96 65 6A 9D F1 5F 5B 9C C4"
            .replace(" ", "")
        ),
    ),
    (
        "Example 7: Encrypted Unicast with Options and Flood Hops",
        bytes.fromhex(
            "D3 12 78 53 10 FF 40 6C 28 FD ED 54 A5 E0 00 00"
            " 00 0A 6F 2F A3 3C 80 D2 24 72 8E 15 FF 0C B6 EE"
            " CA 27 90 59 AF"
            .replace(" ", "")
        ),
    ),
    (
        "Example 8: Blind Unicast (S=0)",
        bytes.fromhex(
            "F0 B0 8D E0 00 00 00 07 9C A3 DF 8D F8 A6 1A 3B"
            " 73 CD 1B 42 9D E6 DD 47 AD 3A 6B E5 FF 89 BB 16"
            " 15 E8 7A"
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
