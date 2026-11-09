#!/usr/bin/env python3
"""Generate a pcap of frames the spec's own test vectors do not reach.

Some of these break protocol prohibitions on purpose and some are perfectly
valid; what they have in common is exercising dissector behavior the spec
vectors cannot, since those are all either beacons or encrypted with keys a
capture does not carry. They live apart from `make_test_pcap.py` for that
reason—every frame in that file is valid and matches the spec byte for
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
SRC_A_FULL = (
    "ED 54 A5 9F B1 AC 3A 51 23 93 51 36 29 41 B8 68"
    " E8 5A 60 E3 D7 B2 48 5D 82 88 21 DC 7A 69 C2 79"
)

# Example 14's Frame Signature option value, COUNTER(4) || SIG(64).
FRAME_SIG = (
    "00 00 00 0E"
    " 03 79 A8 FA 3A B8 6E 4F 59 C7 6F 0E E6 5C 76 6B"
    " D2 F1 03 38 0E 62 D9 AD 4E E8 66 E5 89 B3 56 C0"
    " 54 AC F8 50 AF D6 9A DD B7 A3 8B 7C 18 E8 77 A6"
    " AA 55 84 68 F7 01 2F E0 91 24 4E 6B 89 52 BE 0C"
)

# Channel ID of the emergency channel, derived from its name.
# See docs/protocol/src/multicast-channels.md.
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
        # Valid: a request naming one node by hint draws a single reply
        # however far it travels, so its hop count is unconstrained. This
        # must not be reported despite being flooded.
        "Broadcast identity request, hint-filtered and flooded (valid)",
        h("C1" "40", SRC_A, "FF",
          "02" "01"
          "33" "6C 28 FD"),   # option 3 FILTER_NODE_HINT
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
        # Node management is unicast only too. The embedded frame is one
        # ULCP CMD_PROP_GET of PROP_DEV_VERSION.
        "Node management request in a broadcast",
        h("C0", SRC_A, "FF",
          "08"          # payload type: Node Management Request
          "12 34"       # token
          "FF"          # end of options
          "80 02 02"),  # the ULCP frame, to the end of the payload
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
        # Every multicast carrying text on the emergency channel is signed.
        # The MIC is genuine (the channel key is public), so the finding
        # stands without a caveat.
        "Unsigned text message on the emergency channel",
        h("E4", CHAN_EMERGENCY, "60" "00 00 00 01", "FF", SRC_A_FULL,
          "03 FF 48 65 6C 70",      # Text Message, no options, "Help"
          "E6 6A 13 C3 E6 E0 75 18 FB 1B 03 0C 66 74 56 F2"),
    ),

    # ─── Options the spec defines but the test vectors never carry ───────
    (
        # Route Retry and a Trace with signal together. Options are
        # delta-encoded in ascending order: 6, then +1 = 7.
        "Beacon carrying route retry and a trace with signal",
        h("C0", SRC_A,
          "60"                  # option 6, zero-length flag
          "18"                  # option 7, two 4-byte records:
          "ED 54 5A 32"         #   ED54 heard -90 dBm / +5.0 dB
          "6C 28 78 E2"),       #   6C28 heard -120 dBm / -3.0 dB
    ),
    (
        # A trace that shed its signal to fit: 0xFE, then router hints.
        "Beacon carrying a hints-only trace",
        h("C0", SRC_A, "75" "FE" "ED 54 6C 28"),
    ),
    (
        # A trace that also dropped its oldest hops: 0xFF, then hints.
        "Beacon carrying a truncated trace",
        h("C0", SRC_A, "73" "FF" "ED 54"),
    ),
    (
        # Two bytes is neither a record list nor a sentinel form.
        "Beacon carrying a malformed trace",
        h("C0", SRC_A, "72" "ED 54"),
    ),
    (
        # Station Callsign is option 15: delta nibble 13 and one extended
        # byte, 15 - 13 = 2. N0CALL.
        "Beacon carrying a station callsign",
        h("C0", SRC_A, "D4" "02" "5B BB 08 2C"),
    ),
    (
        # Example 14's Frame Signature twice: a sender MUST NOT, and the
        # broadcast is unsigned.
        "Broadcast carrying two frame signatures",
        h("C4", SRC_A_FULL, "0D 37", FRAME_SIG, "0D 37", FRAME_SIG, "FF", "48 69"),
    ),
    (
        # A Frame Signature one byte short is handled as unrecognized.
        "Broadcast carrying a malformed frame signature",
        h("C4", SRC_A_FULL, "0D 36", FRAME_SIG[:-3], "FF", "48 69"),
    ),
    (
        # A frame with SECINFO signs with the SCF's D bit; option 0 is
        # defined for broadcast only.
        "Multicast carrying a frame signature option",
        h("E0", "B0 8D", "60" "00 00 00 03", "0D 37", FRAME_SIG, "FF", SRC_A,
          "03 48 65 6C 6C 6F",
          "00" * 16),
    ),
    (
        # Unknown options named by their classes: 12 is delivery-critical,
        # 13 (+1) is forwarding- and delivery-critical.
        "Beacon carrying unknown critical options",
        h("C0", SRC_A, "C0" "10"),
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
