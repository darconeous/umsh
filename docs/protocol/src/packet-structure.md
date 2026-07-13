# Packet Structure

All UMSH packets begin with a one-byte Frame Control Field (`FCF`). Optional common fields then follow in a fixed order, followed by packet-type-specific fields.

## Top-Level Packet Layout

```text
+-----+-------+----------+---------+-----------+---------+---------+-----+
| FCF | FHOPS | DST/CHAN |   SRC   |  SECINFO  | OPTIONS | PAYLOAD | MIC |
+-----+-------+----------+---------+-----------+---------+---------+-----+
  1 B   0/1 B    0/2/3 B   0/3/32 B   0/5/7 B   variable  variable  0-16 B
```

Where:

- `FHOPS` is present if the FCF flood hop count flag is set
- `DST` is a 3-byte destination hint (in MAC Ack packets it is a 3-byte prefix of the original sender's public key)
- `CHAN` is a 2-byte channel identifier
- `SRC` is a compact 3-byte source hint (when `S` flag is clear) or 32-byte source public key (when `S` flag is set); in multicast and blind unicast packets with encryption enabled, `SRC` is encrypted inside the ciphertext rather than appearing as a separate field
- `SECINFO` is present on authenticated/encrypted packet types
- `MIC` is present on authenticated/encrypted packet types; MAC acks carry an [ack tag](security.md#ack-tag-construction) instead

Not all fields are supported for all packet types.

## Frame Control Field

The Frame Control Field is one byte:

```text
  7   6   5   4   3   2   1   0
+-------+-----------+---+---+---+
|  VER  | PKT TYPE  | S | R | H |
+-------+-----------+---+---+---+
 2 bits    3 bits     1   1   1
```

Where:

- `VER` = protocol version (this specification defines version **3**, i.e., both bits set)
- `PKT TYPE` = packet type
- `S` = full 32-byte source address included (when clear, a compact source hint is used instead; see [Source Address](addressing.md#source-address) for hint size by packet type)
- `R` = reserved; senders MUST set to 0; receivers MUST drop packets where this bit is non-zero
- `H` = flood hop count present. Zero if direct.

### Packet Type Values

| Value | Name                                 |
|------:|--------------------------------------|
| 0     | `BCST`: Broadcast                    |
| 1     | `UACK`: MAC Ack                      |
| 2     | `UNIC`: Unicast                      |
| 3     | `UNAR`: Unicast, Ack-Requested       |
| 4     | `MCST`: Multicast                    |
| 5     | *RESERVED*                           |
| 6     | `BUNI`: Blind Unicast                |
| 7     | `BUAR`: Blind Unicast, Ack-Requested |

## Common Optional Fields

### Flood Hop Count

If present, `FHOPS` is a single byte containing two 4-bit fields:

```text
  7   6   5   4   3   2   1   0
+---------------+---------------+
| FHOPS_REM     | FHOPS_ACC     |
+---------------+---------------+
     4 bits          4 bits
```

Where:

- `FHOPS_REM` (high nibble) = hops remaining — the number of additional flood hops remaining. Decremented by each forwarding repeater. When zero, no further flood forwarding is allowed.
- `FHOPS_ACC` (low nibble) = hops accumulated — the number of flood hops already traversed. Incremented by each forwarding repeater.

> [!NOTE]
> `FHOPS_ACC` accumulates **flood** hops only.
> Source routed hops do not increment this number.

The sum `FHOPS_REM + FHOPS_ACC` is constant across forwarding hops and usually equals the original flood hop limit set by the sender. An exception to this rule is [bridging](routing-overview.md#bridging), which can decrease `FHOPS_REM` unilaterally. The maximum flood radius is 15 hops; longer paths can be achieved by combining source routing with flooding (see [Routing Implications](repeater-operation.md#routing-implications)).

`FHOPS_ACC` enables the destination to determine how many flood hops the packet traversed, which is used for [MAC ack routing](packet-types.md#mac-ack-packet) when no trace route is available.

### Options Field

Options use the same delta-length encoding as CoAP (RFC 7252 §3.1). Each option is encoded as a delta from the previous option's number, a length, and a value. The sequence is terminated by a `0xFF` byte if a payload is present.

#### Option Encoding

Each option begins with a single byte containing two 4-bit fields:

```text
  7   6   5   4   3   2   1   0
+---------------+---------------+
| Option Delta  | Option Length |
+---------------+---------------+
     4 bits          4 bits
```

Followed by optional extended delta bytes, optional extended length bytes, and then the option value:

```text
+---------------+---------------+
| Option Delta  | Option Length |  (1 byte)
+---------------+---------------+
| Extended Delta (0-2 bytes)    |
+-------------------------------+
| Extended Length (0-2 bytes)   |
+-------------------------------+
| Option Value (0 or more bytes)|
+-------------------------------+
```

**Delta and length interpretation:**

| Nibble value | Meaning |
|---:|---|
| 0–12 | Literal value |
| 13 | One extended byte follows; value = byte + 13 |
| 14 | Two extended bytes follow; value = uint16 (big-endian) + 269 |
| 15 | Reserved — used only in the delta field to indicate the `0xFF` end-of-options marker |

The value 15 is legal only as part of the `0xFF` end-of-options marker, where *both* nibbles are 15. Any other appearance of nibble value 15 — a delta nibble of 15 whose length nibble is not 15, or a length nibble of 15 in an ordinary option record — is malformed, and the packet MUST be dropped.

The option delta is the difference between this option's number and the previous option's number (or zero for the first option). Options must appear in order of increasing option number. Multiple options with the same number are permitted (delta = 0).

#### End-of-Options Marker

The byte `0xFF` (delta nibble = 15, length nibble = 15) separates the options block from a following variable-length payload.

Parsing proceeds as follows:

1. Determine the **options+payload region**: `buf[options_start .. packet_end − trailer_len]`, where `trailer_len` is the length of the fixed-size trailer at the end of the packet (MIC length from SECINFO, or 8 for ACK_TAG, or 0 for broadcast). The trailer length is known before options are parsed.
2. Scan options in order through that region, consuming each delta-length-value record. Because option records are variable-length, this scan is the only way to locate the end of the options block.
3. If a `0xFF` byte is encountered during the scan, the bytes remaining in the region (between the `0xFF` and the trailer) are the payload. A `0xFF` with zero bytes remaining is a valid empty payload.
4. If the region is exhausted without encountering a `0xFF`, there is no payload.

Senders SHOULD omit `0xFF` when there is no payload. Receivers MUST accept a `0xFF` in any position where the marker is syntactically valid (i.e., immediately after the last option record), regardless of if payload bytes follow.

#### Example

Two options — option 3 (1-byte value) followed by option 9 (2-byte value):

```text
+------+-------+  +------+-------+-------+  +------+
| 0x31 |  val  |  | 0x62 |  val  |  val  |  | 0xFF |
+------+-------+  +------+-------+-------+  +------+
 delta=3 opt 3     delta=6 opt 9             marker
 len=1   val (1B)  len=2   val (2B)
```
