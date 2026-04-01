# Packet Structure

All UMSH packets begin with a one-byte Frame Control Field (`FCF`). Optional common fields then follow in a fixed order, followed by packet-type-specific fields.

## Top-Level Packet Layout

```text
+--------+-----------+--------+--------------+------------+-----------+---------+------+
|  FCF   |  OPTIONS  | FHOPS  | DST/CHANNEL  |    SRC     |  SECINFO  | PAYLOAD | MIC  |
+--------+-----------+--------+--------------+------------+-----------+---------+------+
   1 B      variable    0/1 B      0/2/3 B    0/1/3/32 B    0/5/7 B      var.   0-16 B
```

Where:

- `OPTIONS` are present if the FCF options flag is set
- `FHOPS` is present if the FCF flood hop count flag is set
- `DST` is a 3-byte destination hint (2 bytes in MAC Ack packets)
- `CHANNEL` is a 2-byte channel identifier
- `SRC` is a compact source hint (when `S` flag is clear) or 32-byte source public key (when `S` flag is set); the hint is 1 byte in unicast and blind unicast packets, and 3 bytes in broadcast and multicast packets; in multicast packets with encryption enabled, `SRC` is encrypted inside the ciphertext rather than appearing as a separate field
- `SECINFO` is present on authenticated/encrypted packet types
- `MIC` is present on authenticated/encrypted packet types; MAC acks carry an [ack tag](security.md#ack-tag-construction) instead

## Frame Control Field

The Frame Control Field is one byte:

```text
  7   6   5   4   3   2   1   0
+-------+-----------+---+---+---+
| VER   | PKT TYPE  | S | O | H |
+-------+-----------+---+---+---+
 2 bits    3 bits     1   1   1
```

Where:

- `VER` = protocol version (this specification defines version **3**, i.e., both bits set)
- `PKT TYPE` = packet type
- `S` = full 32-byte source address included (when clear, a compact source hint is used instead; see [Source Address](addressing.md#source-address) for hint size by packet type)
- `O` = options present
- `H` = flood hop count present

### Packet Type Values

| Value | Name                         |
|------:|------------------------------|
| 0     | `BCST`: Broadcast                    |
| 1     | `MACK`: MAC Ack                      |
| 2     | `UNIC`: Unicast                      |
| 3     | `UACK`: Unicast, Ack-Requested       |
| 4     | `MCST`: Multicast                    |
| 5     | *RESERVED*                           |
| 6     | `BUNI`: Blind Unicast                |
| 7     | `BUAK`: Blind Unicast, Ack-Requested |

## Common Optional Fields

### Options Field

Options use the same delta-length encoding as CoAP (RFC 7252 §3.1). Each option is encoded as a delta from the previous option's number, a length, and a value. The sequence is terminated by a `0xFF` byte.

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

The option delta is the difference between this option's number and the previous option's number (or zero for the first option). Options must appear in order of increasing option number. Multiple options with the same number are permitted (delta = 0).

#### End-of-Options Marker

The byte `0xFF` (delta nibble = 15, length nibble = 15) terminates the options field. It is always present when the `O` flag is set in the FCF.

#### Example

Two options — option 3 (1-byte value) followed by option 9 (2-byte value):

```text
+------+-------+  +------+-------+-------+  +------+
| 0x31 |  val  |  | 0x62 |  val  |  val  |  | 0xFF |
+------+-------+  +------+-------+-------+  +------+
 delta=3 opt 3     delta=6 opt 9             marker
 len=1   val (1B)  len=2   val (2B)
```

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

- `FHOPS_REM` (high nibble) = hops remaining — the number of additional flood hops permitted. Decremented by each forwarding repeater. When zero, no further flood forwarding is allowed.
- `FHOPS_ACC` (low nibble) = hops accumulated — the number of flood hops already traversed. Incremented by each forwarding repeater.

The sum `FHOPS_REM + FHOPS_ACC` is constant across forwarding hops and equals the original flood hop limit set by the sender. The maximum flood radius is 15 hops; longer paths can be achieved by combining source routing with flooding (see [Routing Implications](repeater-operation.md#routing-implications)).

`FHOPS_ACC` enables the destination to determine how many flood hops the packet traversed, which is used for [MAC ack routing](packet-types.md#mac-ack-packet) when no trace route is available.
