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

In order to manage the potential flood of responses, the following rules MUST be applied for broadcast (always) and (by default) multicast:

- The Route option must either be absent or empty, otherwise the request should be dropped.
- Responses must be delayed by a random amount of time drawn from a window of
  0.5 to 30 seconds, so that the selected nodes do not all answer at once. A
  delayed response that then fails channel-activity assessment follows the
  responder's normal bounded CCA backoff-and-retry before being dropped.
- One solicitation is answered at most once. A request reaches a node once per
  path it travels, and a plain broadcast carries no frame counter for a lower
  layer to recognize the repeat by; the [NONCE](#identity-request-options) is
  what names the solicitation. A responder suppresses a request matching one it
  has already answered — same sender, same NONCE — for at least as long as it
  may hold the reply. A request carrying no NONCE cannot be distinguished from a
  repeat of itself; a requester that wants a further answer inside that window
  asks with a fresh NONCE.

A [FILTER_NODE_HINT](#identity-request-options) filter names a single node, so a
request carrying one solicits a single reply however far it travels. A partial
hint names a small set rather than one node, and the shorter it is the larger
that set: a requester sends the longest hint it holds. A request with no hint
filter at all selects by role or capability, and every node it reaches may
answer; such a request is therefore confined to the requester's own
neighborhood:

- The FHOPS byte must either be absent or set to 0x00. A request that is flood
  routed — FHOPS present with either nibble nonzero — MUST NOT be answered.
- The response MUST NOT carry a FHOPS field (the FCF flood hop count flag is
  clear). The invariant is that the reply travels exactly as far as the question
  did and no further: a request that crossed one hop is answered across that one
  hop, and a request steered along a [Source Route
  option](packet-options.md#source-route-option-3) is answered back along the
  path it was steered down.

A request steered by a Route option reaches its destination neighborhood with
that option emptied, since each repeater consumes its own hint. The nodes there
are strangers to the requester: they hold no route to it, and their replies carry
no flood budget for a repeater to spend. Such a request therefore carries a
[Trace Route option](packet-options.md#trace-route-option-2), and a node answering
it sends the response as a source route built from the trace the request arrived
with. Repeaters prepend when forwarding, so the accumulated trace already reads
as the path back and is used as-is, without reversal.

A repeater consumes its own hint while forwarding, not while receiving, so a
request whose Route option still names a repeater is one that repeater drops.
Asking a named router to identify itself therefore means steering the request to
the hop *before* it and narrowing it with that router's two-byte hint: the
request arrives with an empty Route option, and the router answers it as any
other node in that neighborhood would.

These requirements MAY be relaxed for specific private channels, but MUST remain in place for all public channels. Note that these requirements are specifically designed to allow discovering identities from a specific repeater location on the mesh network.

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
| 3 | Yes | FILTER_NODE_HINT | 1–3 bytes | Respond only if this is a leading part of the responder's own [node hint](addressing.md#node-hint). A 3-byte value is the whole hint; a 2-byte value is the [router hint](addressing.md#router-hint), which is all a [Source Route](packet-options.md#source-route-option-3) or [Trace Route](packet-options.md#trace-route-option-2) reveals about the hops it names. A zero-length value matches nothing. |
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

The response SHOULD carry the same [trace route](packet-options.md#trace-route-option-2) and [trace signal](packet-options.md#trace-signal-option-10) options the request carried. An echo measures a path, and a response traced differently from the request measures a different one; pairing the two options is what makes the measurement per-hop rather than end to end.

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
