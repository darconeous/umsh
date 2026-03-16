# MAC Commands

A MAC command payload consists of:

- **1 byte**: command identifier
- **optional bytes**: command-specific payload

Support for MAC commands is optional.

## Command Registry

| Value | Command | Direction |
|---:|---|---|
| 0 | Beacon Request | Request |
| 1 | Identity Request | Request |
| 2 | Signal Report Request | Request |
| 3 | Signal Report Response | Response |
| 4 | Echo Request | Request |
| 5 | Echo Response | Response |
| 6 | PFS Session Request | Request |
| 7 | PFS Session Response | Response |
| 8 | End PFS Session | Either |

## Beacon Request (0)

Requests that the destination send back a beacon.

| Field | Size | Description |
|---|---:|---|
| Nonce | 0 or 4 bytes | If present, must be copied into the response beacon |

Beacon requests may be used for:

- presence detection
- frame-counter synchronization

## Identity Request (1)

Requests that the destination respond with its [node identity](node-identity.md) payload.

No command-specific payload.

## Signal Report Request (2)

Requests that the destination respond with signal quality information about the link.

No command-specific payload.

## Signal Report Response (3)

Reports signal quality measurements in response to a Signal Report Request.

| Field | Size | Description |
|---|---:|---|
| RSSI | 1 byte | Received signal strength as an unsigned value representing negative dBm (e.g. 130 = -130 dBm) |
| SNR | 1 byte | Signal-to-noise ratio as a signed value in dB |

## Echo Request (4)

Requests that the destination respond with an Echo Response.

| Field | Size | Description |
|---|---:|---|
| Echo data | 0+ bytes | Arbitrary payload, copied verbatim into the Echo Response |

Echo requests may be used for:

- round-trip latency measurement
- reachability testing
- frame-counter synchronization (by observing the frame counter in the response's SECINFO)

## Echo Response (5)

Carries a response to a prior Echo Request, including any echo data from the request.

| Field | Size | Description |
|---|---:|---|
| Echo data | 0+ bytes | Copied verbatim from the Echo Request |

## PFS Session Request (6)

Initiates a perfect-forward-security session between two nodes. The sender generates an ephemeral Ed25519 keypair and sends the public key along with session parameters. If accepted, both nodes use their ephemeral keys for subsequent communication, ensuring that compromise of long-term keys cannot retroactively expose session traffic.

| Field | Size | Description |
|---|---:|---|
| Ephemeral public key | 32 bytes | Sender's newly generated Ed25519 public key for this session |
| Session duration | 2 bytes | Requested session lifetime in minutes (0 = no expiration) |

This ephemeral keypair is associated with the sender's long-term identity for the duration of the session.

## PFS Session Response (7)

Sent in response to a PFS Session Request. The responder generates its own ephemeral Ed25519 keypair and returns the public key. Once both sides have exchanged ephemeral keys, communication proceeds using the new keypair.

| Field | Size | Description |
|---|---:|---|
| Ephemeral public key | 32 bytes | Responder's newly generated Ed25519 public key for this session |
| Session duration | 2 bytes | Accepted session lifetime in minutes |

This ephemeral keypair is associated with the sender's long-term identity for the duration of the session.

## End PFS Session (8)

Terminates an active PFS session. May be sent by either party. Upon receipt, both sides discard the ephemeral private keys and revert to using their long-term keys.

No command-specific payload. The sender and recipient are identified by the packet's addressing fields.

A PFS session also ends automatically when:

- the agreed session duration expires
- either device reboots

Ephemeral private keys should be securely erased when the session ends, regardless of the reason.
