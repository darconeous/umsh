# Common Patterns

UMSH reuses a small set of encoding patterns across both the MAC layer and application-layer protocols. This chapter collects them in one place so that individual protocol sections can reference them without repeating the details.

## Byte Order

Multi-byte numeric fields are transmitted in **big-endian** (most-significant byte first), also known as **network byte order**. This is the standard convention for protocol specifications and is straightforward to interpret in packet diagrams. Modern hardware can convert between byte orders at effectively zero cost, so this choice imposes no practical performance penalty.

Non-numeric multi-byte data — such as SHA-256 hashes, Ed25519 public keys, and EdDSA signatures — is transmitted in its most common byte-wise representation, independent of any underlying endianness of the represented value.

## CoAP-Style Option Encoding

UMSH uses the delta-length option encoding defined in CoAP (RFC 7252 §3.1) wherever a set of typed key-value fields needs to be carried compactly. This allows the protocols to be flexible and adapt to future needs while retaining backward compatability.

Each option is encoded as a delta from the previous option's number, a length, and a value. The sequence is terminated by a `0xFF` end-of-options marker if there is additional data present after the options section.

This encoding appears in:

- **MAC-layer packet options** — routing, signal-quality thresholds, callsigns (see [Packet Options](packet-options.md))
- **Text message options** — message type, sender handle, fragmentation, colors (see [Text Messages](app-text-messages.md))
- **Chat room payloads** — room info responses, login parameters (see [Chat Rooms](app-chat-rooms.md))
- **Node identity metadata** — location, battery, uptime (see [Node Identity](node-identity.md))

The full encoding rules — nibble interpretation, extended bytes, and the end marker — are defined in [Packet Structure](packet-structure.md#option-encoding). Application-layer uses follow the same wire format.

## ARNCE/HAM-64 Text Encoding

[ARNCE](https://github.com/arngll/arnce-spec/blob/main/n6drc-arnce.md#introduction) (Amateur Radio Numeric Callsign Encoding), also known as HAM-64, is a compact encoding for short alphanumeric strings. It packs up to 12 characters into 2, 4, 6, or 8 bytes, making it well suited for identifiers that must fit in constrained fields.

UMSH uses ARNCE/HAM-64 for:

- **Operator callsign** (packet option 4) — identifies the originating operator under amateur radio rules
- **Station callsign** (packet option 7) — identifies the transmitting station, updated by repeaters during forwarding
- **Region codes** (packet option 11) — IATA airport codes encoded as 2-byte ARNCE values (e.g. SJC → `0x7853`)

## UTF-8 Strings

All human-readable text in UMSH — message bodies, node names, sender handles, room descriptions — is encoded as UTF-8. String length is determined by context:

- Inside a CoAP-style option, the option's length field defines the string boundary.
- As trailing data after a `0xFF` marker, the string extends to the end of the payload (or to the start of a trailing signature).
- In node identity payloads, the node name is NUL-terminated (`0x00`).

## Base58 Encoding

Public keys and channel keys in human-facing contexts (URIs, QR codes) are encoded using Base58. This avoids visually ambiguous characters (0/O, l/1) and produces compact, copy-paste-friendly strings.

See [URI Formats](uri-formats.md) for the defined URI schemes.
