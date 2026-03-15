# Node Identity

The node identity payload is an application-layer structure carried inside the UMSH payload. Its contents — including the timestamp below — are not interpreted or required by the MAC layer. The MAC layer itself is timestamp-free (see [Frame Counter](security.md#frame-counter)).

A node's identity may be expressed as the following structure:

- **4 bytes**: UNIX timestamp from when this information was last updated, truncated to 32 bits
- **1 byte**: Node primary role
- **1 byte**: Node feature/capability bitmap
- **N bytes, optional**: zero-terminated node name
- **N bytes, optional**: CoAP-style option list, terminated by `0xFF` if EdDSA signature is present.
- **64 bytes, optional**: EdDSA signature over the preceding identity data

## Node Primary Role

Defined values:

- `0` — Unspecified
- `1` — Repeater
- `2` — Chat
- `3` — Tracker
- `4` — Sensor
- `5` — Bridge
- `6` — Chat Room
- `7` — Temporary Session
- all other values — Reserved

## Capability Bitmap

Bit assignments:

- bit 0 — Repeater
- bit 1 — Mobile
- bit 2 — Text Messages
- bit 3 — Telemetry
- bit 4 — Chat Room
- bit 5 — CoAP
- bit 6 — Node name included
- bit 7 — Node options included

If the node-name-included bit is clear, the node name is simply not advertised in this identity payload; it does not imply the node lacks a name.

## Node Identity Options

Possible options include:

- Node Location (longitude/latitude)
- Node Battery Percentage
- Node Uptime (minutes)
- Amateur Radio Callsign

## Signature Usage

The optional 64-byte EdDSA signature is generally included only when the identity data must stand on its own, such as:

- QR codes
- broadcasts without a MIC

When the enclosing packet already carries a MIC, the EdDSA signature is generally omitted.
