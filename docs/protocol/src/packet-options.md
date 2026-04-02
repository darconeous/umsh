# Packet Options

UMSH packet options use the delta-length encoding described in [Packet Structure](packet-structure.md#options-field). Each option has a numeric option number whose two least significant bits encode two semantic attributes:

- **Bit 0**: Critical (1) / Non-Critical (0)
- **Bit 1**: Dynamic (1) / Static (0)

This means a node can determine an unrecognized option's attributes by inspecting its option number without consulting a registry.

## Attribute Encoding

The four attribute combinations and their option number patterns:

| Low 2 bits | Option numbers | Classification |
|---:|---|---|
| `0b00` | 0, 4, 8, 12, ... | Non-Critical, Static |
| `0b01` | 1, 5, 9, 13, ... | Critical, Static |
| `0b10` | 2, 6, 10, 14, ... | Non-Critical, Dynamic |
| `0b11` | 3, 7, 11, 15, ... | Critical, Dynamic |

## Critical vs. Non-Critical

These determine behavior when a node encounters an unknown option:

- **Critical** (bit 0 set): if unrecognized, the packet must be dropped
- **Non-Critical** (bit 0 clear): if unrecognized, the option is ignored and the node continues processing

## Dynamic vs. Static

These determine whether an option is covered by the MIC:

- **Dynamic** (bit 1 set): not protected by the security MIC; may be modified in transit by repeaters
- **Static** (bit 1 clear): protected by the security MIC; must not be modified in transit

This distinction allows forwarding-related metadata (source routes, trace routes, station callsigns) to be modified by repeaters without invalidating end-to-end authentication.

## Defined Options

| Number | Name | Classification | Value |
|---:|---|---|---|
| 1 | Region Code | Critical, Static | 2 bytes |
| 2 | Trace Route | Non-Critical, Dynamic | 0+ bytes |
| 3 | Source Route | Critical, Dynamic | 0+ bytes |
| 4 | Operator Callsign | Non-Critical, Static | ARNCE/HAM-64 |
| 5 | Minimum RSSI | Critical, Static | 0–1 bytes |
| 7 | Station Callsign | Critical, Dynamic | ARNCE/HAM-64 |
| 9 | Minimum SNR | Critical, Static | 0–1 bytes |

### Region Code (option 1)
- Type: 2-byte region identifier
- Semantics: restricts flood-routing to repeaters configured for the specified region.
- A repeater that does not recognize or is not configured for the region must not forward the packet when flooding.
- This option is not enforced until the source route list is exhausted.

#### Region Code Encoding

Region codes are 2-byte identifiers derived by one of two methods, depending on the type of region:

**Airport-based regions.** For regions defined by proximity to an airport, encode the airport's 3-letter IATA code into a 16-bit value using ARNCE/HAM-64. Examples:

| IATA Code | Region Code |
|---|---|
| SJC | `0x7853` |
| MFR | `0x5242` |

**Named regions.** For regions that are not associated with a single airport (super-regions, cities without a nearby airport, geographic areas, etc.), the region code is the first two bytes of the SHA-256 hash of the region name (UTF-8 encoded). Examples:

| Region Name | SHA-256 prefix | Region Code |
|---|---|---|
| Rogue Valley | `0xdf6f...` | `0xdf6f` |
| SF Bay Area | `0x31d9...` | `0x31d9` |
| Southern Oregon | `0x6af2...` | `0x6af2` |

IATA-based region codes will never collide with each other. However, because region codes are only 2 bytes, named regions may happen to collide with IATA codes or other named regions.

These collisions are rarely of practical concern. If a region code in one part of the world collides with a region code in a different part of the world, there is no actual ambiguity because flood repeating is an inherently local event. In the rare case of a collision within a geographic area, it can be resolved by adjusting the named region slightly (for example, making it more specific).

The assignment and scope of non-IATA-based region codes—and resolution of any collisions—are generally handled locally.

### Trace Route (option 2)
- Semantics: if present, repeaters prepend their own repeater hint before retransmitting.
- If absent, no trace-route information is added automatically.
- Value layout: see [Trace Route Option Value](#trace-route-option-value).

### Source Route (option 3)
- Semantics: contains an ordered list of repeater hints designating the forwarding path.
- Repeater behavior:
  - Only the repeater matching the first hint may forward the packet.
  - That repeater removes its own hint before retransmission.
  - Repeaters that do not match the first hint must not forward the packet.
- Value layout: see [Source Route Option Value](#source-route-option-value).

### Operator Callsign (option 4)
- Encoding: ARNCE/HAM-64 (2, 4, 6, or 8 bytes; encodes callsigns up to 12 characters)
- Semantics: identifies the original packet sender's amateur radio callsign.
- Use: required for locally originated packets in `Licensed-Only` amateur operation.
- In `Hybrid` operation, its presence marks the packet as eligible for forwarding under amateur-radio authority; packets without it may still be forwarded under unlicensed authority if local rules allow.

### Minimum RSSI (option 5)
- Type: unsigned 1-byte integer, interpreted as a negative dBm value
- Semantics: packet must be received with at least this RSSI to be forwarded.
- Example: value `130` means `-130 dBm`
- If present with no value (length 0), default is `-90 dBm`
- If a repeater has a locally configured minimum RSSI, it must use the higher of the packet's minimum RSSI threshold and the repeater's configured minimum RSSI threshold.

### Station Callsign (option 7)
- Encoding: ARNCE/HAM-64 (2, 4, 6, or 8 bytes; encodes callsigns up to 12 characters)
- Semantics: identifies the transmitting station's amateur radio callsign.
- If absent, the station callsign is assumed to equal the source callsign (if present)
- This option is critical because repeaters must replace or remove it during forwarding.
- Use:
  - in `Licensed-Only` mode, repeaters replace or insert it on every forwarded packet
  - in `Hybrid` mode, repeaters also replace or insert it on every forwarded packet
  - in `Unlicensed` mode, repeaters remove it if present and do not add their own

### Minimum SNR (option 9)
- Type: signed 1-byte integer, in dB
- Semantics: packet must be received with at least this SNR to be forwarded.
- If present with no value (length 0), default is `0 dB`.
- If a repeater has a locally configured minimum SNR, it must use the higher of the packet's minimum SNR and the repeater's configured minimum SNR.

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

An empty source-route option indicates that all explicit routing hints have been consumed. It is not semantically distinct from the absence of a source-route option for forwarding purposes.

### Trace Route Option Value

A trace-route option also contains zero or more router hints:

```text
+----------+----------+----------+-----+
|  RH[0]   |  RH[1]   |  RH[2]   | ... |
+----------+----------+----------+-----+
    2 B         2 B       2 B
```

Repeaters prepend their 2-byte router hint:

```text
new_trace = my_router_hint || old_trace
```

So the list is ordered most-recent repeater first.
