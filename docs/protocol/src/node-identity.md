# Node Identity

The node identity payload is an application-layer structure carried inside the UMSH payload. Its contents — including the timestamp option below — are not interpreted or required by the MAC layer. The MAC layer itself is timestamp-free (see [Frame Counter](security.md#frame-counter)).

## Structure

```text
+------+------+---------+------+-----------+
| ROLE | CAPS | OPTIONS | 0xFF | SIGNATURE |
+------+------+---------+------+-----------+
  1 B    1 B   variable   1 B     64 B
```

Fields:

- `ROLE` (1 byte) — the node's [primary role](#node-primary-role).
- `CAPS` (1 byte) — the node's [capability bitmap](#capability-bitmap).
- `OPTIONS` (variable, optional) — a CoAP-style option list of [node identity options](#node-identity-options), using the same delta-length encoding as [packet options](packet-options.md#options-field).
- `0xFF` (1 byte, optional) — options-terminator marker. Present only when a signature follows.
- `SIGNATURE` (64 bytes, optional) — EdDSA signature covering `ROLE` through the `0xFF` terminator, inclusive.

The smallest node identity payload is two bytes: role and capability bitmap, with no options or signature.

## Node Primary Role

Defined values:

- `0` — Unspecified
- `1` — Repeater
- `2` — Chat
- `3` — Tracker/Companion-Radio
- `4` — Sensor
- `5` — Bridge
- `6` — Chat Room
- `7` — Temporary Session
- all other values — Reserved

## Capability Bitmap

A single byte describing optional feature support, orthogonal to the primary role:

```text
  7   6   5   4   3   2   1   0
+---+---+---+---+---+---+---+---+
| - | - |CoA|CHR|TLM|TXT|MOB|REP|
+---+---+---+---+---+---+---+---+
```

- bit 0 (`REP`) — Repeater
- bit 1 (`MOB`) — Mobile/Handheld (As opposed to "fixed")
- bit 2 (`TXT`) — Text Messages
- bit 3 (`TLM`) — Public Telemetry
- bit 4 (`CHR`) — Chat Room
- bit 5 (`CoA`) — CoAP
- bits 6–7 — RESERVED (set to zero; ignore on read)

A node may advertise multiple capabilities independently of its primary role. For example, a node with role **Chat** may also set the `REP` bit to advertise repeater duty.

## Node Identity Options

Options use the CoAP-style delta-length encoding defined in [Packet Options](packet-options.md#option-encoding).

| Number | Name | Value |
|---:|---|---|
| 0 | Node Name | UTF-8 string |
| 1 | Node Location | 1-7 bytes, see [Variable-Precision Location Format](#variable-precision-location-format) |
| 2 | Altitude in Meters | The altitude in meters. | 
| 3 | Unix Timestamp | unsigned integer, seconds since the Unix epoch |
| 4 | Supported Regions | one or more concatenated 2-byte region codes |

### Node Name (option 0)
A UTF-8 display name for the node, typically shown in user interfaces. Max length: 24 bytes.

### Node Location (option 1)
The node's geographic position, encoded as a variable-precision grid code. See [Variable-Precision Location Format](#variable-precision-location-format). Max precision: 7 bytes. Implementations MUST ignore bytes beyond the seventh and MUST NOT encode more than 7 bytes.

### Altitude in Meters (option 2)
The node's altitude above mean sea level in meters, encoded as a minimal big-endian signed integer (leading `0x00` and `0xFF` sign-extension bytes omitted, provided the sign bit of the remaining value is unambiguous). Max length: 4 bytes.

### Unix Timestamp (option 3)
Seconds since the Unix epoch indicating when this identity payload was generated. Lets a consumer judge how fresh the identity is — most useful when the identity stands alone (e.g. in a QR code), where a stale capture could otherwise be presented indefinitely. Not used by the MAC layer. Encoded as a minimal big-endian unsigned integer (leading zero bytes omitted). Max length: 4 bytes.

### Supported Regions (option 4)
For repeaters, the list of [region codes](packet-options.md#region-code-encoding) the node will flood-forward for. Entries are 2 bytes each, concatenated with no delimiter. A node that omits this option makes no claim about its regional forwarding policy. Max length: 20 bytes.

### Variable-Precision Location Format

The node location is encoded as a string of one or more bytes, where each byte narrows the position to a 16×16 sub-grid of the preceding byte's cell. Additional bytes increase precision; trailing bytes may be omitted to give a coarser — and therefore more privacy-preserving — location.

#### Grid Subdivision

Each byte splits its parent cell into a 16×16 grid of children. Within each byte, the high nibble indexes along longitude and the low nibble indexes along latitude:

```text
  7   6   5   4   3   2   1   0
+---------------+---------------+
|   LON NIBBLE  |   LAT NIBBLE  |
+---------------+---------------+
     4 bits          4 bits
```

The first byte subdivides the entire globe (longitude in 16 slices of 22.5°, latitude in 16 slices of 11.25°). Each subsequent byte subdivides the cell selected by the byte before it, using the same high-nibble-longitude, low-nibble-latitude convention.

#### Encoding a Location

Given latitude `LAT` in degrees (-90..+90) and longitude `LON` in degrees (-180..+180), an N-byte code can be derived either in a single step or byte by byte.

##### Direct form

Compute two 4N-bit indices over the full desired precision:

- `lon_index = floor((LON + 180) × 16^N / 360)`
- `lat_index = floor((LAT +  90) × 16^N / 180)`

Then read nibbles from most significant to least significant:

- byte _k_ high nibble = `(lon_index >> (4 × (N − 1 − k))) & 0xF`
- byte _k_ low  nibble = `(lat_index >> (4 × (N − 1 − k))) & 0xF`

This form makes the hierarchy explicit: truncating an N-byte code to _k_ bytes yields exactly the _k_-byte code for the same position.

Edge cases: `LON = +180°` is equivalent to `LON = −180°` and wraps `lon_index` to 0. `LAT = +90°` is a single degenerate point; clamp `lat_index` to `16^N − 1`.

##### Iterative form

Emitting one byte at a time, with `lon_step = 22.5° / 16^k` and `lat_step = 11.25° / 16^k`:

- byte _k_ high nibble = `floor(((LON + 180) mod (16 × lon_step)) / lon_step)`
- byte _k_ low  nibble = `floor(((LAT +  90) mod (16 × lat_step)) / lat_step)`

For byte 0 (`k = 0`), `lon_step = 22.5°` and `lat_step = 11.25°`, so the modulus is a no-op for valid inputs and the formulas reduce to:

- `high_nibble = floor((LON + 180) / 22.5)`
- `low_nibble  = floor((LAT +  90) / 11.25)`

##### Worked Example

Encode `(LAT, LON) = (37.331°, −121.883°)` (San Jose, CA) at 3-byte precision.

Direct form:

- `lon_index = floor((−121.883 + 180) × 4096 / 360) = floor(661.13) = 661 = 0x295`
- `lat_index = floor((  37.331 +  90) × 4096 / 180) = floor(2897.22) = 2897 = 0xB51`

Reading nibbles most-significant first:

| Byte | High (lon) | Low (lat) | Value  |
|-----:|:----------:|:---------:|:------:|
|   0  |    `0x2`   |   `0xB`   | `0x2B` |
|   1  |    `0x9`   |   `0x5`   | `0x95` |
|   2  |    `0x5`   |   `0x1`   | `0x51` |

Final code: `2B 95 51`.

#### Precision Scaling

Each additional byte divides both the longitude and latitude spans by 16. The span shrinks geometrically, so just a few bytes yield very fine precision:

| Bytes | Longitude cell  | Latitude cell   | Equator cell size (approx.) |
|---:|---|---|---|
| 1 | 22.5°            | 11.25°            | 2,500 × 1,250 km |
| 2 | 1.40625°         | 0.703125°         | 156 × 78 km      |
| 3 | 0.0879°          | 0.0439°           | 9.8 × 4.9 km     |
| 4 | 0.00549°         | 0.00275°          | 610 × 305 m      |
| 5 | 0.000343°        | 0.000172°         | 38 × 19 m        |
| 6 | 2.15 × 10⁻⁵°     | 1.07 × 10⁻⁵°      | 2.4 × 1.2 m      |
| 7 | 1.34 × 10⁻⁶°     | 6.71 × 10⁻⁷°      | 15 × 7.5 cm      |

Longitude cells narrow with latitude, so cells are physically smaller in east-west extent away from the equator.

> **Comparison with float32:** Two single-precision floats (8 bytes) give non-uniform resolution: ~1.7 m longitude and ~85 cm latitude worst-case near ±180°/±90°, improving to ~1 cm near 0°. At 7 bytes, this encoding achieves ~15 × 7.5 cm uniformly across the globe — better than the float32 worst case while using one fewer byte. At 8 bytes, the cell shrinks to ~9 × 5 mm, better than float32 everywhere.

#### Properties

- **Simple encoding.** Two nibble divisions per byte; no floating-point math required to decode.
- **Arbitrary precision.** Any desired accuracy is reachable by adding bytes.
- **Compact.** Scales linearly with precision: one byte per factor-of-16 refinement in both axes.
- **Free coarsening.** Reducing precision is just truncation; no recomputation is needed. This makes it trivial to publish, say, a 2-byte location in a broadcast and a 5-byte location in a private message, both derived from the same underlying position.

## Signature Usage

The optional 64-byte EdDSA signature is generally included only when the identity data must stand on its own without any authentication, such as:

- QR codes
- broadcasts

When the enclosing packet already carries a MIC, the EdDSA signature MAY be omitted.