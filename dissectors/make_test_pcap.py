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
            "D0 6C 28 FD ED 54 A5 E0 00 00 00 2A FF AE 71 DC"
            " 38 72 61 8E 96 38 FE 4D 9A E8 34 33 1D E8 E0 DD"
            " 06 3E"
            .replace(" ", "")
        ),
    ),
    (
        "Example 4: Encrypted Unicast with Ack Requested (S=1)",
        bytes.fromhex(
            "DC 6C 28 FD ED 54 A5 9F B1 AC 3A 51 23 93 51 36"
            " 29 41 B8 68 E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC"
            " 7A 69 C2 79 E0 00 00 00 01 FF F8 82 EE AA 17 13"
            " 06 26 1C E7 FF F2 FF 01 7F 90 10 A7 D9"
            .replace(" ", "")
        ),
    ),
    (
        "Example 5: Encrypted Multicast (E=1)",
        bytes.fromhex(
            "E0 B0 8D E0 00 00 00 05 FF 7C 16 CC CF 27 32 48"
            " 78 AC BF 20 01 42 05 B1 04 17 5E A6 8F 66 47 78"
            " 83"
            .replace(" ", "")
        ),
    ),
    (
        "Example 6: Authenticated Multicast (E=0)",
        bytes.fromhex(
            "E0 B0 8D 60 00 00 00 03 FF ED 54 A5 03 48 65 6C"
            " 6C 6F 9A 4B FC DE 39 42 FE B2 25 B8 D3 D4 BC E7"
            " 9F DB"
            .replace(" ", "")
        ),
    ),
    (
        "Example 7: Encrypted Unicast with Options and Flood Hops",
        bytes.fromhex(
            "D1 40 6C 28 FD ED 54 A5 E0 00 00 00 0A 20 92 78"
            " 53 FF 81 2D 2F BA 19 2E EA B5 7D 71 E3 52 BD 7D"
            " DF 33 1B 07 27"
            .replace(" ", "")
        ),
    ),
    (
        "Example 8: Blind Unicast (S=0)",
        bytes.fromhex(
            "F0 B0 8D E0 00 00 00 07 FF D5 EC 8B 3D 69 96 88"
            " 94 03 C3 07 C7 46 F3 5E 82 28 3E 3C 14 B0 5D 97"
            " 56 7B 4E 86"
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
