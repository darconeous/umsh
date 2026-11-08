# Packet Options

UMSH packet options use the delta-length encoding described in [Packet Structure](packet-structure.md#options-field). Each option has a numeric option number whose low four bits encode its semantic attributes:

- **Bit 0**: Forwarding-Critical (1) / not (0)
- **Bit 1**: Dynamic (1) / Static (0)
- **Bits 2 and 3**: both set on a static option (`(number & 0xE) == 0xC`): Delivery-Critical

This means a node can determine an unrecognized option's attributes by inspecting its option number without consulting a registry.

## Attribute Encoding

The attribute combinations and their option number patterns, by the low four bits of the number:

| Low 4 bits | Option numbers | Classification |
|---:|---|---|
| 0, 4, 8 | 0, 4, 8, 16, 20, 24, ... | Non-Critical, Static |
| 1, 5, 9 | 1, 5, 9, 17, 21, 25, ... | Forwarding-Critical, Static |
| 2, 6, 10, 14 | 2, 6, 10, 14, 18, ... | Non-Critical, Dynamic |
| 3, 7, 11, 15 | 3, 7, 11, 15, 19, ... | Forwarding-Critical, Dynamic |
| 12 | 12, 28, 44, ... | Delivery-Critical, Static |
| 13 | 13, 29, 45, ... | Forwarding-Critical, Delivery-Critical, Static |

Dynamic options are never delivery-critical. Delivery-criticality is an end-to-end demand from the sender, and only a static option, which the MIC and any [frame signature](security.md#frame-signatures) cover, can carry one.

## Forwarding and Delivery Criticality

These determine behavior when a node encounters an unknown option. The two classes are independent, and a node that both forwards and receives a packet applies each check to its own role.

- **Forwarding-Critical** (bit 0 set): if unrecognized, a repeater does not forward the packet. It can still deliver the packet locally.
- **Delivery-Critical** (low four bits 12 or 13): if unrecognized, an endpoint does not accept, deliver, or acknowledge the packet. It drops the packet and counts the drop. Repeaters forward it as normal.
- **Non-Critical**: if unrecognized, the option is ignored and the node continues processing.

A recognized option whose value the node cannot interpret, such as one of the wrong length, is handled as unrecognized, within the option's own classes.

[MAC acks](packet-types.md#mac-ack-packet) are exempt from delivery-critical interpretation. An ack delivers nothing, so a receiver accepts an otherwise valid ack whatever delivery-critical options it carries. Every static option on an ack, recognized or not, is still covered by its [ack tag](security.md#ack-tag-construction).

## Dynamic vs. Static

These determine whether an option is covered by the MIC:

- **Dynamic** (bit 1 set): not protected by the security MIC; may be modified in transit by repeaters
- **Static** (bit 1 clear): protected by the security MIC; must not be modified in transit

This distinction allows forwarding-related metadata (source routes, traces, station callsigns) to be modified by repeaters without invalidating end-to-end authentication.

## Defined Options

| Number | Name | Classification | Value |
|---:|---|---|---|
| 0 | Frame Signature | Non-Critical, Static | 68 bytes |
| 1 | *UNASSIGNED* | Forwarding-Critical, Static | |
| 2 | *UNASSIGNED* | Non-Critical, Dynamic | |
| 3 | Source Route | Forwarding-Critical, Dynamic | 0+ bytes |
| 4 | Operator Callsign | Non-Critical, Static | ARNCE/HAM-64 |
| 5 | Minimum RSSI | Forwarding-Critical, Static | 0–1 bytes |
| 6 | Route Retry | Non-Critical, Dynamic | 0 bytes |
| 7 | Trace | Forwarding-Critical, Dynamic | 0+ bytes |
| 8 | Ack MIC | Non-Critical, Static | 4 bytes|
| 9 | Minimum SNR | Forwarding-Critical, Static | 0–1 bytes |
| 10 | *UNASSIGNED* | Non-Critical, Dynamic | |
| 11 | Region Code | Forwarding-Critical, Dynamic | 2 bytes |
| 15 | Station Callsign | Forwarding-Critical, Dynamic | ARNCE/HAM-64 |
| 257 | Fence | Forwarding-Critical, Static | 0 bytes |

### Frame Signature (option 0)
- Type: `FRAME COUNTER (4 B, big-endian) ‖ SIG (64 B)`, exactly 68 bytes.
- Semantics: a [frame signature](security.md#frame-signatures) for a broadcast, which has no SECINFO to carry a counter or the `D` bit. `SIG` is an Ed25519 signature by the source key over the [signature input](security.md#signature-input), in which this option's 64 signature bytes are replaced by zeros. `FRAME COUNTER` is drawn from the sender's [one counter sequence](security.md#frame-counter), and a verified frame is judged by the [signed-frame counter rules](security.md#signed-frame-counters).
- Defined for broadcast only. A sender MUST NOT include it on a packet type that carries SECINFO, which signs with the SCF's `D` bit instead; a receiver ignores it there.
- A value of any other length is handled as an unrecognized option.
- A sender MUST NOT include more than one. A broadcast carrying more than one is treated as unsigned.
- The full source key is not required. A hint-only signed broadcast can be verified only by a receiver that already holds the sender's key.

### Source Route (option 3)
- Semantics: contains an ordered list of repeater hints designating the forwarding path.
- A sender MUST NOT include more than one. A packet carrying more than one is handled as carrying an unrecognized forwarding-critical option.
- Repeater behavior:
  - Only the repeater matching the first hint may forward the packet.
  - That repeater removes its own hint before retransmission.
  - If removing its own hint leaves zero remaining hints, the repeater still preserves the source-route option with an empty value.
    - This is important: the forwarded packet still carries the information that it was explicitly source-routed, even though the route is now exhausted.
    - Removing the last hint does not change what kind of hop this is. The repeater was named, so it forwards as a source-routed hop and leaves [`FHOPS`](packet-structure.md#flood-hop-count), region policy, and signal-quality thresholds alone. The next repeater sees the empty option and is the first to flood.
  - Repeaters that do not match the first hint must not forward the packet.
- Value layout: see [Source Route Option Value](#source-route-option-value).

### Operator Callsign (option 4)
- Encoding: ARNCE/HAM-64 (2, 4, 6, or 8 bytes; encodes callsigns up to 12 characters)
- Semantics: identifies the original packet sender's amateur radio callsign.
- Use: required for locally originated packets in `Licensed-Only` amateur operation.
- In `Hybrid` operation, its presence marks the packet as eligible for forwarding under amateur-radio authority; packets without it may still be forwarded under unlicensed authority if local rules allow.

### Minimum RSSI (option 5)
- Type: unsigned 1-byte integer, interpreted as a negative dBm value
- A sender MUST NOT include more than one. A packet carrying more than one is handled as carrying an unrecognized forwarding-critical option.
- Semantics: packet must be received with at least this RSSI to be flood-forwarded. This option does not apply to source-routed hops.
- Example: value `130` means `-130 dBm`
- If present with no value (length 0), default is `-100 dBm` (THIS VALUE IS SUBJECT TO CHANGE)
- If a repeater has a locally configured minimum RSSI, it must use the higher of the packet's minimum RSSI threshold and the repeater's configured minimum RSSI threshold.

### Route Retry (option 6)
- Type: flag. A sender includes it with no value; a receiver treats the option as present whatever its value, and a forwarder carries the value unchanged.
- Semantics: indicates that the originator is re-attempting delivery of the same logical packet after its acknowledgment timed out: either a route it had assumed failed, or, for a packet that assumed none, the acknowledgment was lost on its way back ([Route Failure Recovery](repeater-operation.md#route-failure-recovery)).
- A sender MUST NOT include more than one. A receiver reads the first and ignores the rest, and a forwarder carries only the first.
- This option is intended for sender-originated route recovery, not for ordinary first transmission. A sender sends at most one Route Retry of a logical packet.
- The failed assumption need not be a source route. A sender that narrowed `FHOPS` because it believed the destination was directly reachable, or reachable within a known flood distance, has made the same kind of assumption; nothing on the wire distinguishes that packet from an ordinary short-radius flood, and the recovery is the same.
- When present, repeaters treat the packet as a distinct forwarding attempt for duplicate-suppression purposes even though the MIC and frame counter are unchanged.
- The destination does **not** treat this option as creating a new logical packet. Replay acceptance and duplicate application delivery remain governed by the packet's normal security state, especially its frame counter.
- A Route Retry that duplicates a packet the destination already acknowledged suggests that acknowledgment was lost. The destination re-acknowledges by a scoped, traced flood instead of along the route the lost acknowledgment took. Because anyone can add the option to a copy, it is no evidence against that route ([Lost Acknowledgments](repeater-operation.md#lost-acknowledgments)).
- A sender using this option for route recovery typically:
  - removes the stale source-route option, if one was present
  - adds or refreshes flood hops, up to but not beyond the budget the sending application was willing to spend; a packet that already flooded at that budget keeps it
  - includes a [Trace option](#trace-option-7) to learn a replacement route
  - preserves the same frame counter and payload

  Each of these rewrites a field the [associated data](security.md#associated-data) excludes, which is what lets the retry reuse the original MIC unchanged. Adding `FHOPS` to a packet that had none also sets the FCF's `H` bit, and the AAD clears that bit for this reason.

### Trace (option 7)
- Semantics: if present, each hop that forwards the packet prepends a record of itself before retransmitting, so the value lists the hops the packet took, most recent first. If absent, no trace information is added.
- Each record names the hop's [router hint](addressing.md#router-hint) and the signal with which that hop received the packet. Value layout and forms: see [Trace Option Value](#trace-option-value).
- The option is forwarding-critical. A repeater that does not implement it does not forward a traced packet, so a trace never silently skips a hop; that repeater still forwards untraced packets.
- A sender MUST NOT include more than one. A receiver reads the first and ignores the rest, and a forwarder carries only the first.
- A malformed value is handled as unrecognized: a repeater does not forward the packet, and a receiver ignores the trace and still delivers the packet.

**Signal.** A record's RSSI byte is the **negative** of the RSSI in dBm (so −90 dBm becomes 90), and its SNR byte is the signed SNR in cB (centibels, or tenths of a dB). A hop that received the packet over a point-to-point link rather than the air—a [bridge](internet-bridging.md), for example—writes zero for both. The zero entry marks a hop with no radio in it, so it has no signal to report and does not lose packets to fading. A hop that received the packet over the air never writes it: a reading of 0 dBm or stronger is carried as an RSSI byte of 1.

**Sender.** A sender that includes a Trace option originates the packet at least one byte below the frame limit, which leaves room for the [last-resort form](#trace-option-value) on a link with the same limit when the repeater adds nothing else. A repeater that also inserts a Region Code or inserts or lengthens a Station Callsign may need more than that byte; if even the last-resort form does not fit, the repeater does not forward the packet on that link.

**Receiver.**
- A complete trace, with signal or hints only, is a complete path. It is used for routes and hop counts; a hints-only trace lacks only the per-hop signal, and the receiver still measures the final link's signal itself.
- A truncated trace reports the most recent hops but is not a complete path. Nothing builds a route from it: [route learning](beacons.md#route-learning), acknowledgement return routes, and source routes built from observed hints all require a complete trace.
- The hop count of a packet with a truncated trace is `FHOPS_ACC + 1` if the packet carries no Source Route option, and unknown if it carries one.

### Ack MIC (option 8)

This option is a piggy-backed acknowledgement: a packet carrying it acknowledges the packet whose `ack_mic` it names, exactly as a MAC ack for that packet would. A destination that answers an ack-requested packet with a unicast or blind unicast of its own MAY include the option in the answer, whether or not it also sends the standalone MAC ack. The original sender takes whichever of the two arrives first as the acknowledgement; the other then matches no outstanding packet and is discarded.

- Type: 4-byte ack MIC—the first 4 bytes of the acknowledged packet's on-wire MIC (see [Ack Tag Construction](security.md#ack-tag-construction)).

The option carries only the correlation handle, not a keyed ack tag: the packet carrying the option is itself authenticated to the original sender, so its own MIC already proves the acknowledgement is genuine. The `ack_mic` value simply identifies which outstanding request the reply acknowledges. The original sender accepts the option only on a packet authenticated as coming from the destination of the packet it names.

The option is a courtesy to the original sender. A sender that cannot fit it into a frame omits it.

Because the option sits in the plaintext options block, forwarders read it under the same terms as a standalone MAC ack, including as an [overheard acknowledgment](repeater-operation.md#ack-cancellation).

On a [Verify Frame](mac-commands.md#verify-frame-12) the option names the packet to be verified instead of acknowledging it: the sender holds that packet but has not accepted it, so the original sender MUST NOT treat the option as an acknowledgement (see [Counter Resynchronization](security.md#counter-resynchronization)). Forwarders still treat it as an [overheard acknowledgment](repeater-operation.md#ack-cancellation), since the named packet has reached its destination.

### Minimum SNR (option 9)
- Type: signed 1-byte integer, in dB
- Semantics: packet must be received with at least this SNR to be flood-forwarded. This option does not apply to source-routed hops.
- If present with no value (length 0), default is `-3 dB`. (THIS VALUE IS SUBJECT TO CHANGE)
- A sender MUST NOT include more than one. A packet carrying more than one is handled as carrying an unrecognized forwarding-critical option.
- If a repeater has a locally configured minimum SNR, it must use the higher of the packet's minimum SNR and the repeater's configured minimum SNR.

### Region Code (option 11)
- Type: 2-byte region identifier
- Semantics: restricts flood-routing to repeaters configured for the specified region.
- A repeater configured for one or more regions MUST NOT flood-forward a packet whose region is none of them. A repeater configured for no regions makes no regional claim and applies no such restriction.
- This option MUST NOT be enforced on a [source-routed hop](repeater-operation.md#routing-invariants), which includes the hop that removes the last remaining hint. A repeater named in the route forwards regardless of region.
- Multiple region-code options may appear on the same packet. In that case, a repeater MAY flood-forward the packet if any one of the listed regions matches local policy.
- Because this option is dynamic, repeaters may insert it while flood-forwarding a packet that currently has no region code.
- A repeater must never rewrite an existing region code and must never add a second region code to a packet that already has one or more region-code options.
- Region insertion is a local policy decision. When no explicit local policy exists, a reasonable default is the IATA code of the closest regional commercial airport.
- Region insertion applies only during flood forwarding. An untagged source-routed packet is first tagged by the repeater that flood-forwards it—the one that receives it with an already-empty source route—not by the repeater that emptied the route.

#### Region Code Encoding

Region codes are 2-byte identifiers derived by one of two methods, depending on the type of region. Both ignore ASCII case—ARNCE/HAM-16 encodes `A`–`Z` and `a`–`z` alike, and the hash folds `A`–`Z` to lowercase `a`–`z` before it is taken, altering no other character. Strings that differ only in ASCII case therefore derive the same code and name the same region.

> As with [channel names](multicast-channels.md#named-channels), folding is restricted to ASCII: correct case-folding of the full Unicode range is locale-dependent, and a name that folded under one implementation and not another would be two regions on one mesh.

**Short codes.** A region named by one to three ASCII letters or digits encodes directly into a 16-bit value with ARNCE/HAM-16, the unused trailing characters left as `NUL`. Three letters are conventionally the IATA code of the nearest airport or of a metro area that has one; two are conventionally an [ISO 3166-1 alpha-2](https://www.iso.org/iso-3166-country-codes.html) country code or a bare subdivision code, for a region that spans one. Examples:

| Short Code | Region Code |
|---|---|
| SJC | `0x7853` |
| MFR | `0x5242` |
| US | `0x8638` |
| WA | `0x8FE8` |

An all-letter short code is *exclusive*: the transform below vacates every one of them, so no named region can ever derive one. A short code bearing a digit—`W7`, `5X2`—encodes just as faithfully and no two short codes ever share a code, but it is not vacated, so it shares its space with the hashes. Such a code is worth using when a mnemonic is wanted in place of a hash, and it is nothing more than that: an implementation MUST NOT display a region code as a digit-bearing short code, because the code it is reading may equally have come from a name.

`/`, `-`, and `^`, though ARNCE spells them, MUST NOT appear in a short code. The transformed codes are led by `/` and `-`, and a short code able to reach that space would read back as a region it is not.

**Named regions.** For regions that a short code does not suit (super-regions, cities without a nearby airport, geographic areas, etc.), the region code is the first two bytes of the SHA-256 hash of the folded region name (UTF-8 encoded), EXCEPT when performing ARNCE/HAM-16 decoding
on the resulting value would yield nothing but letters—one, two, or three of them. In that case, you
additionally perform the following transform:

```python
def transform_letter_chunk(encoded: int) -> int:
    """Transform an all-letter ARNCE chunk into a non-letter ARNCE chunk."""

    LETTER_MIN = 1
    LETTER_MAX = 26

    TRANSFORM_BASE = 27 * 1600                    # 0xA8C0
    TWO_LETTER_BASE = TRANSFORM_BASE + 26 ** 3    # 0xED68
    ONE_LETTER_BASE = TWO_LETTER_BASE + 26 ** 2   # 0xF00C

    a = encoded // 1600
    b = (encoded // 40) % 40
    c = encoded % 40

    def is_letter(x: int) -> bool:
        return LETTER_MIN <= x <= LETTER_MAX

    if not is_letter(a):
        return encoded

    if is_letter(b) and is_letter(c):
        return TRANSFORM_BASE + (a - 1) * 26 * 26 + (b - 1) * 26 + (c - 1)
    if is_letter(b) and c == 0:
        return TWO_LETTER_BASE + (a - 1) * 26 + (b - 1)
    if b == 0 and c == 0:
        return ONE_LETTER_BASE + (a - 1)
    return encoded
```

The three lengths occupy three consecutive blocks, longest first, and together vacate 18,278 of the 64,000 encodable chunks. The highest code the transform yields is `0xF025`; every one of them decodes to a string led by `/` or `-`, and so to nothing that reads as a region.

Examples, with the folded name each hash is taken over:

| Region Name | Folded | SHA-256 prefix | Region Code |
|---|---|---|---|
| Willamette Valley | `willamette valley` | `0xb02d...` | `0xB02D` |
| East Bay | `east bay` | `0x36e2...` | `0x36E2` |
| Rogue Valley | `rogue valley` | `0x3f56...` | `0xC0F9` |
| Wasatch Front | `wasatch front` | `0x5fa0...` | `0xEEDF` |

Note that the first two bytes of the SHA256 of "rogue valley" is 0x3F56, which would decode to `JEN`, so it is transformed to 0xC0F9, which decodes to no letters. "wasatch front" hashes to 0x5FA0, which would decode to the two letters `OL`, and is transformed to 0xEEDF for the same reason.

Thus, a hash-derived region code will never collide with an all-letter short code. This allows all region codes which decode to nothing but letters to be assumed to be short codes and to be used/displayed unambiguously without additional context.

However, collisions can still happen between hash-originated region codes, and between one of those and a digit-bearing short code.
These collisions are rarely of practical concern. If a region code in one part of the world collides with a region code in a different part of the world, there is no actual ambiguity because flood repeating is an inherently local event. In the rare case of a collision within a geographic area, it can be resolved by adjusting the named region slightly (for example, making it more specific).

The assignment and scope of hash-derived region codes—and resolution of any collisions—are generally handled locally.

**Literal codes.** In any context that takes a region's string form, a string of `0x` followed by four hexadecimal digits (e.g. `0x31d9`) denotes the two-byte code it spells. Strings of this shape are by definition excluded from the other two derivations—there is no named region `0x31d9`, only the code. This is also the display form for a code that reads as no short code and whose name is unknown, so a region list read off the air can be fed back in unchanged. Note that a string of one to three characters is a short code before it is anything else: `0x1` encodes as the three characters `0`, `x`, `1`, and only `0x` followed by four hexadecimal digits is a literal.

A region name MUST NOT exceed 24 bytes of UTF-8. Names travel on the wire in [identity payloads](node-identity.md#supported-regions-option-4), and the bound is what lets a list of them fit there.

**Capitalization.** Folding applies to derivation and comparison, not to storage: wherever a region is held or carried in its string form—a repeater's configured list, the Supported Regions identity option—it keeps the capitalization it was written with. A set of regions holds at most one entry per folded string; writing a region already present in a different capitalization respells the entry rather than adding a second one. A short code is displayed uppercase whatever case it was written in.

### Station Callsign (option 15)
- Encoding: ARNCE/HAM-64 (2, 4, 6, or 8 bytes; encodes callsigns up to 12 characters)
- Semantics: identifies the transmitting station's amateur radio callsign.
- If absent, the station callsign is assumed to equal the source callsign (if present)
- This option is forwarding-critical because repeaters must replace or remove it during forwarding.
- Use:
  - in `Licensed-Only` mode, repeaters replace or insert it on every forwarded packet
  - in `Hybrid` mode, repeaters also replace or insert it on every forwarded packet
  - in `Unlicensed` mode, repeaters remove it if present and do not add their own

### Fence (option 257)
- Type: flag. A receiver ignores it whatever its value, and a forwarder carries it unchanged.
- Semantics: none. A sender does not include it.

## Routing Option Layouts

### Source Route Option Value

A source-route option contains zero or more router hints:

```text
+----------+----------+----------+-----+
|  RH[0]   |  RH[1]   |  RH[2]   | ... |
+----------+----------+----------+-----+
    2 B         2 B       2 B
```

Where each `RH[i]` is the first two bytes of a repeater's public key.

Interpretation:

- `RH[0]` is the next repeater that must forward the packet
- when that repeater forwards, it removes `RH[0]`

An empty source-route option indicates that all explicit routing hints have been consumed.

- For forwarding purposes, an empty source-route option behaves the same as an absent source-route option: there is no remaining explicit next hop.
- However, it is still semantically useful and should be preserved when produced by forwarding, because it records that the packet did in fact traverse an explicit source-routed path before the hints were exhausted.

### Trace Option Value

A complete trace with signal contains zero or more 4-byte records:

```text
+----------+--------+--------+----------+--------+--------+-----+
|  RH[0]   | RSSI[0]| SNR[0] |  RH[1]   | RSSI[1]| SNR[1] | ... |
+----------+--------+--------+----------+--------+--------+-----+
    2 B       1 B      1 B       2 B       1 B      1 B
```

Each hop prepends its own record:

```text
new_trace = my_router_hint || rssi || snr || old_trace
```

So the list is ordered most-recent hop first. A [bridge](internet-bridging.md) prepends a record as a repeater does, with zero signal bytes.

A trace can outgrow the frame limit as hops add records: each record adds 4 bytes, and the option's length field gains a byte once the value passes 12 bytes. The path matters more than the per-hop signal, so a trace that no longer fits first sheds its signal and only then drops hops. The value takes one of three forms:

| Form | First byte | Length | Contents |
|---|---|---|---|
| Complete, with signal | any | multiple of 4 | 4-byte records |
| Complete, hints only | `0xFE` | odd | `0xFE ‖` 2-byte router hints |
| Truncated, hints only | `0xFF` | odd | `0xFF ‖` 2-byte router hints, oldest dropped |

Hints are most recent first in every form, and a lone `0xFE` or `0xFF` is valid. The length tells the hints-only forms apart from a record list whose first router hint happens to begin with `0xFE` or `0xFF`. Every other value is malformed: a length of 2 modulo 4, or an odd length beginning with any other byte.

Before forwarding a traced packet, a repeater computes the exact size of the forwarded packet on the outgoing link, including any options it inserts, and takes the first of these that fits:

1. Add its own entry in the trace's current form: a 4-byte record to a trace with signal, or its 2-byte hint to a `0xFE` or `0xFF` trace.
2. For a trace with signal: convert it to `0xFE ‖` hints and add its own hint.
3. Convert it to `0xFF ‖` hints, add its own hint, and drop hints from the end, oldest first, until the packet fits. A lone `0xFF` is the last resort.
4. If even a lone `0xFF` does not fit, do not forward the packet on that link, and count the drop.

Forms only degrade. No repeater adds signal to a hints-only trace, so the forms never mix, and a `0xFF` trace never returns to `0xFE`.
