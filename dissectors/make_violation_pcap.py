#!/usr/bin/env python3
"""Generate a pcap of frames the spec's own test vectors do not reach.

Some of these break protocol prohibitions on purpose and some are perfectly
valid; what they have in common is exercising dissector behaviour the spec
vectors cannot, since those are all either beacons or encrypted with keys a
capture does not carry. They live apart from `make_test_pcap.py` for that
reason — every frame in that file is valid and matches the spec byte for
byte. Nothing here is a reference for how to build a packet.

Covered: violation reporting, the application-layer summary lines, and the
options the spec defines but the vectors never carry.

Broadcast is the vehicle for most of it. A broadcast has no SECINFO and no
MIC, so its payload is in cleartext and the application dissectors run on it
without any key being configured.

Usage:  python3 make_violation_pcap.py violations.pcap
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from make_test_pcap import make_pcap  # noqa: E402

SRC_A = "ED 54 A5"  # Node A hint

# Channel IDs of the two well-known channels, derived from their names.
# See docs/protocol/src/multicast-channels.md.
CHAN_PUBLIC = "0A D6"
CHAN_EMERGENCY = "26 C7"


def h(*parts: str) -> bytes:
    return bytes.fromhex("".join(parts).replace(" ", ""))


VECTORS = [
    (
        # Valid: a broadcast advertisement. Present so the summary line has
        # something correct to compare against.
        "Broadcast node identity (valid)",
        h("C0", SRC_A, "FF",
          "01"          # payload type: Node Identity
          "01"          # role: Repeater
          "05"          # caps: REP | TXT
          "09" "42 61 73 65 20 43 61 6D 70"),   # option 0, "Base Camp"
    ),
    (
        # Valid: the one MAC command a broadcast may carry, with a filter.
        "Broadcast identity request with filter (valid)",
        h("C0", SRC_A, "FF",
          "02"          # payload type: MAC Command
          "01"          # command: Identity Request
          "14" "AA BB CC DD"   # option 1 NONCE
          "41" "02"),          # option 5 FILTER_NODE_ROLE = Chat
    ),
    (
        # Only the Identity Request may ride a broadcast.
        "Broadcast echo request (prohibited MAC command in broadcast)",
        h("C0", SRC_A, "FF", "02" "04"),
    ),
    (
        # No filter option, and flood-routed with a non-zero hop count:
        # two separate prohibitions in one frame.
        "Broadcast identity request, unfiltered and flooded",
        h("C1" "40", SRC_A, "FF", "02" "01"),
    ),
    (
        "Beacon with the reserved FCF bit set",
        h("C2", SRC_A),
    ),
    (
        # A text message has no business in a broadcast at all.
        "Text message in a broadcast",
        h("C0", SRC_A, "FF",
          "03"          # payload type: Text Message
          "FF" "48 69"),  # no options, body "Hi"
    ),
    (
        # Chat-room traffic is unicast only. Carried here so the chat-room
        # dissector has something to run on without a key.
        "Chat-room login in a broadcast",
        h("C0", SRC_A, "FF",
          "05"          # payload type: Chat-Room Message
          "02"          # action: Login
          "05" "61 6C 69 63 65"),   # option 0 Handle, "alice"
    ),
    (
        # Node management is unicast only too. The frame list holds one ULCP
        # CMD_PROP_GET of PROP_DEV_VERSION.
        "Node management request in a broadcast",
        h("C0", SRC_A, "FF",
          "08"          # payload type: Node Management
          "00"          # flags: request
          "12 34"       # token
          "FF"          # end of options
          "03" "81 02 02"),   # PUI length 3, then the ULCP frame
    ),
    (
        # Emergency traffic has to be readable by every node in range.
        # The MIC will not verify, so the finding carries its caveat.
        "Encrypted multicast on the emergency channel",
        h("E0", CHAN_EMERGENCY, "E0" "00 00 00 01", "FF",
          "11 22 33 44 55 66 77 88",
          "00" * 16),
    ),
    (
        "Blind unicast on the public channel",
        h("F0", CHAN_PUBLIC, "E0" "00 00 00 02", "FF",
          "11 22 33 44 55 66",      # ENC_DST_SRC
          "77 88 99 AA",            # body
          "00" * 16),
    ),

    # ─── Options the spec defines but the test vectors never carry ───────
    (
        # Trace Route, Route Retry and Trace Signal together. Options are
        # delta-encoded in ascending order: 2, then +4 = 6, then +4 = 10.
        "Beacon carrying trace route, route retry and trace signal",
        h("C0", SRC_A,
          "24" "ED 54 6C 28"    # option 2, two 2-byte router hints
          "40"                  # option 6, zero-length flag
          "44" "5A 32 78 E2"),  # option 10, two hops: -90 dBm/+5.0 dB,
                                #                     -120 dBm/-3.0 dB
    ),
    (
        # Two region codes are explicitly allowed to appear together
        # (packet-options.md); the rule about not adding a second one binds
        # a repeater's action, which no single frame records. This must not
        # be reported.
        "Beacon with two region codes (valid)",
        h("C0", SRC_A, "B2" "78 53" "02" "78 53"),
    ),
    (
        # Minimum RSSI is defined as appearing at most once, and the spec
        # says a packet carrying two of them must be dropped.
        "Beacon with two minimum-RSSI options",
        h("C0", SRC_A, "51" "82" "01" "82"),
    ),
    (
        # The packet an Ack MIC option can refer back to: ack requested, so
        # the dissector records the first four bytes of its MIC.
        "Unicast with ack requested (publishes MIC AABBCCDD)",
        h("D8", "6C 28 FD", SRC_A,
          "00" "00 00 00 01",   # SECINFO: E=0, 4-byte MIC, no salt
          "FF",                 # end of options
          "02 09",              # MAC Command: No-op
          "AA BB CC DD"),       # MIC
    ),
    (
        # A reply that piggy-backs the acknowledgement as option 8 rather
        # than sending a separate MAC ack. It should name the frame above.
        "Unicast carrying a piggy-backed Ack MIC option",
        h("D0", SRC_A, "6C 28 FD",
          "00" "00 00 00 02",
          "84" "AA BB CC DD"    # option 8, the acknowledged MIC prefix
          "FF",
          "02 09",
          "11 22 33 44"),
    ),
]


if __name__ == "__main__":
    data = make_pcap(VECTORS)
    if len(sys.argv) > 1:
        Path(sys.argv[1]).write_bytes(data)
        print(f"Written {len(VECTORS)} packets to {sys.argv[1]}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(data)
