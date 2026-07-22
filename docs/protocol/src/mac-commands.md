# MAC Commands

A MAC command payload consists of:

- **1 byte**: command identifier
- **optional bytes**: command-specific payload

Support for MAC commands is optional.

## Command Registry

| Value | Command | Direction |
|---:|---|---|
| 0 | UNALLOCATED | -- |
| 1 | Identity Request | Request |
| 2 | Signal Report Request | Request |
| 3 | Signal Report Response | Response |
| 4 | Echo Request | Request |
| 5 | Echo Response | Response |
| 6 | PFS Session Request | Request |
| 7 | PFS Session Response | Response |
| 8 | End PFS Session | Either |
| 9 | No-op | Request | 

## Identity Request (1)

Requests that the destination respond with its [node identity](node-identity.md).

A common use is resolving a [node hint](addressing.md#node-hint) to a full
address. A node that knows only a peer's hint sends this command as a broadcast
or multicast carrying a [FILTER_NODE_HINT](#identity-request-options) filter; a
matching node replies with an encrypted unicast (or blind unicast) response
carrying its full node identity. When the requester believes the peer may not
yet know the requester's own address, it sends its full source address in the
request so the peer can reply directly.

Because a broadcast Identity Request can solicit many replies:

- A node MAY decline to respond to a request from an unknown source.
- A repeater MAY decline to forward a broadcast Identity Request, particularly
  when its filters are broad enough to solicit a large number of replies.

An Identity Request is answered with a targeted unicast identity response, never
by flooding an [advertisement](beacons.md#advertisements) to the whole network.

### Identity Request Options

A unicast Identity Request requires no payload. A multicast or broadcast request
MUST carry at least one filter option, so that only the intended nodes respond.

Options use the CoAP-style delta-length encoding defined in [Packet
Options](packet-options.md#attribute-encoding). As in CoAP, an option's key encodes
its criticality: odd-numbered keys (least-significant bit set) are **critical**,
even-numbered keys are **elective**. A node that encounters a critical option it
does not understand MUST treat itself as excluded and MUST NOT respond.

Filter options select which nodes respond. They combine as a logical **AND**
across different filter types and a logical **OR** among repeated filters of the
same type: a node responds only if it satisfies every filter type present, and
it satisfies a given filter type if it matches any one of that type's values.
Non-filter options (such as NONCE) do not participate in this matching.

| Key | Critical | Name | Value | Description |
|---:|---|---|---|---|
| 1 | Yes | NONCE | 4 bytes | Correlation identifier the responder MUST echo in its response's [Nonce option](node-identity.md#nonce-option-5). Not a filter. |
| 3 | Yes | FILTER_NODE_HINT | 3 bytes | Respond only if this matches the responder's own [node hint](addressing.md#node-hint). |
| 5 | Yes | FILTER_NODE_ROLE | 1 byte | Respond only if the responder's [primary role](node-identity.md#node-primary-role) equals this value. |
| 7 | Yes | FILTER_NODE_CAPS | 1 byte | Respond only if the responder's [capability bitmap](node-identity.md#capability-bitmap) has every bit set that is set in this value. |

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

## No-Op (9)

This command does nothing, however it will produce a UACK when sent via a packet
type that requests an ACK.
