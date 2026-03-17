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

Initiates a PFS session. The sender generates a fresh ephemeral node address and transmits it along with a requested session duration. See [Perfect Forward Secrecy Sessions](security.md#perfect-forward-secrecy-sessions) for the session establishment mechanism, key derivation, and wire-level privacy properties.

| Field | Size | Description |
|---|---:|---|
| Ephemeral node address | 32 bytes | Sender's newly generated ephemeral node address (Ed25519 public key) for this session |
| Session duration | 2 bytes | Requested session lifetime in minutes (0 = no expiration) |

## PFS Session Response (7)

Sent in response to a PFS Session Request. The responder generates its own ephemeral node address, returns it along with the accepted duration, and both sides derive session keys from the ephemeral addresses. See [Perfect Forward Secrecy Sessions](security.md#perfect-forward-secrecy-sessions).

| Field | Size | Description |
|---|---:|---|
| Ephemeral node address | 32 bytes | Responder's newly generated ephemeral node address (Ed25519 public key) for this session |
| Session duration | 2 bytes | Accepted session lifetime in minutes |

## End PFS Session (8)

Terminates an active PFS session. May be sent by either party. Upon receipt, both sides securely erase the private keys for their ephemeral addresses and revert to using their long-term keys. See [Session Lifetime](security.md#session-lifetime) for all conditions under which a session ends.

No command-specific payload. The sender and recipient are identified by the packet's addressing fields.
