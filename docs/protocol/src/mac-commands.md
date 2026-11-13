# MAC Commands

A MAC command payload consists of:

- **1 byte**: command identifier
- **optional bytes**: command-specific payload

Support for MAC commands is optional.

A receiver reads the fields a command defines and ignores any bytes that follow them. A command shorter than its defined fields, or with an unrecognized identifier, is ignored.

MAC commands are addressed to a single node. Unless a command's definition provides rules for multicast or broadcast use, as [Identity Request](#identity-request-1) does, a node ignores a command that arrives by multicast or broadcast.

A node answering a command carries its response the way the request was carried, as [Response Carriage](payload-format.md#response-carriage) defines.

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
| 10 | Peer Repeaters Request | Request |
| 11 | Peer Repeaters Response | Response |
| 12 | Verify Frame | Request |
| 13 | Frame Verified | Response |

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
- A node SHOULD bound the rate at which it answers requests whose frame does
  not authenticate the sender—a verified [frame
  signature](security.md#frame-signatures), or a unicast or blind unicast MIC.
  Such a request's source address is only a claim, and the reply goes to
  whatever node it names. A request over the bound goes unanswered.

In order to manage the potential flood of responses, the following rules MUST be applied for broadcast (always) and (by default) multicast:

- The Route option must either be absent or empty, otherwise the request should be dropped.
- Responses must be delayed by a random amount of time drawn from a window of
  0.5 to 30 seconds, so that the selected nodes do not all answer at once. A
  delayed response that then fails channel-activity assessment follows the
  responder's normal bounded CCA backoff-and-retry before being dropped.
  A request carrying exactly one [FILTER_NODE_HINT](#identity-request-options),
  of 2 or 3 bytes, is exempt and MUST be answered without the delay: such a
  request names a node rather than a share of the mesh, so there is no crowd of
  replies to spread and the hold would only make the answer late. One byte names
  a 256th of what the request reaches, so it is not exempt. Nor is a request
  carrying more than one hint filter: filters of the same type combine as OR,
  and each value can be chosen to match a node the requester has heard, so the
  request names as many nodes as it has filters.
- One solicitation is answered at most once. A request reaches a node once per
  path it travels, and a plain broadcast carries no frame counter for a lower
  layer to recognize the repeat by; the [NONCE](#identity-request-options) is
  what names the solicitation. A responder suppresses a request matching one it
  has already answered—same sender key, same NONCE—for at least as long as it
  may hold the reply. A request carrying no NONCE cannot be distinguished from a
  repeat of itself; a requester that wants a further answer inside that window
  asks with a fresh NONCE.

A [FILTER_NODE_HINT](#identity-request-options) filter names a single node, so a
request carrying one solicits a single reply however far it travels. A partial
hint names a small set rather than one node, and the shorter it is the larger
that set: a requester sends the longest hint it holds. A request with no hint
filter at all selects by role or capability, and every node it reaches may
answer. A request with several hint filters names one node per filter, and a
flood of it would draw a flooded reply from each. Both are therefore confined
to the requester's own neighborhood:

- The FHOPS byte must either be absent or set to 0x00. A request that is flood
  routed—FHOPS present with either nibble nonzero—MUST NOT be answered.
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
[Trace option](packet-options.md#trace-option-7), and a node answering
it sends the response as a source route built from the trace the request arrived
with, when that trace is complete. Repeaters prepend when forwarding, so the accumulated trace already reads
as the path back and is used as-is, without reversal.

The response carries a Trace option of its own.
The trace on the request is what taught the responder a path home, and it taught
the requester nothing: a broadcast solicitation leaves no route behind at the
requester, and the response reaches it with its own Route option consumed and its
`FHOPS_ACC` counting only the tail of the path. Without a trace on the response
the requester ends the exchange holding no route to the node it just identified.
A broadcast solicitation names no responder, so even one that arrived without
flooding gives the requester no path to whoever answers it; the response traces
regardless of the [general rule](beacons.md#when-to-include-a-trace).

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
| 3 | Yes | FILTER_NODE_HINT | 1–3 bytes | Respond only if this is a leading part of the responder's own [node hint](addressing.md#node-hint). A 3-byte value is the whole hint; a 2-byte value is the [router hint](addressing.md#router-hint), which is all a [Source Route](packet-options.md#source-route-option-3) or [Trace](packet-options.md#trace-option-7) reveals about the hops it names. A zero-length value matches nothing. |
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

The response SHOULD carry a [Trace option](packet-options.md#trace-option-7) when the request carried one. An echo measures a path, and a response traced differently from the request measures a different one; the per-hop signal in the two traces is what makes the measurement per-hop rather than end to end.

The response SHOULD use the MIC size the request used.

## PFS Session Request (6)

Initiates a PFS session. The sender generates a fresh ephemeral node address and transmits it along with a requested session duration. See [Perfect Forward Secrecy Sessions](security.md#perfect-forward-secrecy-sessions) for the session establishment mechanism, key derivation, and wire-level privacy properties.

| Field | Size | Description |
|---|---:|---|
| Ephemeral node address | 32 bytes | Sender's newly generated ephemeral node address (Ed25519 public key) for this session |
| Session duration | 2 bytes | Requested session lifetime in minutes; MUST NOT be 0 |

## PFS Session Response (7)

Sent in response to a PFS Session Request. The responder generates its own ephemeral node address, returns it along with the accepted duration, and both sides derive session keys from the ephemeral addresses. See [Perfect Forward Secrecy Sessions](security.md#perfect-forward-secrecy-sessions).

| Field | Size | Description |
|---|---:|---|
| Ephemeral node address | 32 bytes | Responder's newly generated ephemeral node address (Ed25519 public key) for this session |
| Session duration | 2 bytes | Accepted session lifetime in minutes; MUST NOT be 0 |

The responder MAY accept a shorter lifetime than was requested, and both parties hold the session to the accepted one. A node that receives a duration of 0 treats it as a finite lifetime of its own choosing; a responder answers with that lifetime.

## End PFS Session (8)

Terminates the PFS session between the sender and the recipient. May be sent by either party, including one that no longer holds the session. Upon receipt, both sides securely erase the private keys for their ephemeral addresses and revert to using their long-term keys. See [Session Lifetime](security.md#session-lifetime) for all conditions under which a session ends, and for when the recipient acts on an End.

No command-specific payload. Like the handshake, this command travels between the two parties' long-term addresses under their long-term pairwise keys, and it names the session by its sender: each pair of long-term addresses holds at most one session. A node that has lost its ephemeral keys can therefore still end a session, as it does for a [retired session](security.md#retired-sessions).

## No-Op (9)

Asks nothing of the destination. Sent in a packet that requests an acknowledgement, it tests reachability and measures round-trip latency: the MAC ack is the answer, and the packet is retransmitted and its route recovered like any other acknowledgement-requested packet. As a reachability test it gets its [Route Retry](repeater-operation.md#route-failure-recovery) whether or not the sender has heard from the destination recently.

No command-specific payload. A sender MAY follow the command identifier with filler bytes to give the packet the size it wants to test.

## Peer Repeaters Request (10)

Asks the destination—typically a repeater—for its list of known peer repeaters.

The list is the responder's repeater neighborhood: the repeaters it has heard from their own transmitters. A repeater enters it in one of two ways. Forwarding a frame the responder receives is one—a repeater prepends its record to the frame's [Trace](packet-options.md#trace-option-7), so the first hint names the repeater whose transmission was just heard. Advertising is the other—a [node identity](node-identity.md) claiming the repeater role or capability, heard directly rather than forwarded, on a frame that authenticated its sender and passed replay detection (see [Signature Usage](node-identity.md#signature-usage)). Frames heard from nodes that are not repeaters, identities that arrived through a repeater, and identities believed only on their embedded signature put nothing in the list. A trace hint is not authenticated, so a repeater the list holds only by trace is unproven until it is heard forwarding a frame the responder itself sent. When the list is full, a repeater heard only by trace takes the place of an unproven entry, never a proven one. Nor does anything naming the responder itself: a trace that begins with its own router hint, or its own identity. A neighbor need not be on the air: a repeater reached over a point-to-point link, such as an attached host, is listed the same way and simply carries no signal measurements.

The command-specific payload is a CoAP-style option list, using the delta-length encoding defined in [Packet Options](packet-options.md#attribute-encoding):

| Number | Name | Value | Description |
|---:|---|---|---|
| 0 | Nonce | 2 bytes | Correlation identifier the responder MUST echo in its response's Nonce option. |
| 1 | Cursor | variable | Resume token, copied verbatim from the Cursor option of a previous response. Absent on the first request of an enumeration. |

No payload follows the options, so the sender omits the 0xFF end-of-options marker.

A list too large for one response is retrieved page by page: the first request carries no Cursor, and each response that carries one names the place a follow-up request should resume from. The cursor is opaque to the requester; only the responder gives it meaning.

## Peer Repeaters Response (11)

Returns one page of the responder's peer-repeater list in response to a Peer Repeaters Request:

```text
+---------+------+---------+------+---------+------+     +---------+--------+
| OPTIONS | 0xFF | ENTRY 0 | 0xFF | ENTRY 1 | 0xFF | ... | ENTRY N | (0xFF) |
+---------+------+---------+------+---------+------+     +---------+--------+
```

The response options:

| Number | Name | Value | Description |
|---:|---|---|---|
| 0 | Nonce | 2 bytes | Copied verbatim from the request. Present only when the request carried a Nonce. |
| 1 | Cursor | variable | Opaque resume token for the next page. Present when further entries remain; the final page carries no Cursor. |
| 2 | Total | 1 byte | Unsigned count of entries in the full list, not the page. Required in the response to a cursorless request; optional on later pages. |

The `0xFF` after the response options is the ordinary end-of-options marker; the entry list that follows is the command's payload. Each entry is itself a CoAP-style option list terminated by its own `0xFF` byte. The final entry MAY omit its terminator, consistent with omitting the marker when nothing follows.

The options per entry:

| Number | Name | Value | Description |
|---:|---|---|---|
| 0 | Node Hint | 2 or 3 bytes | The peer's [node hint](addressing.md#node-hint)—3 bytes when the responder holds it in full, or the 2-byte [router hint](addressing.md#router-hint) when that is all it has observed. The only required option. |
| 1 | Node Name | UTF-8, max 24 bytes | The peer's display name, as learned from its [identity](node-identity.md#node-name-option-0). |
| 2 | RSSI/SNR | 2 bytes | Signal measurements from the most recent reception: RSSI as an unsigned value representing negative dBm (e.g. 130 = −130 dBm), then SNR as a signed value in quarter-dB steps. |
| 3 | Last Heard | 1–2 bytes | Minutes since the responder last heard the peer, as a minimal big-endian unsigned integer. Saturates at 65535 (about 45 days). |
| 4 | Location | 1–7 bytes | The peer's position, in the [variable-precision location format](node-identity.md#variable-precision-location-format). |
| 5 | Supported Flood Regions | n × 2 bytes | Concatenated 2-byte [region codes](packet-options.md#region-code-encoding) the peer flood-forwards for. |

An option whose value the responder does not know is omitted. Entries carry region codes rather than the strings the [identity option](node-identity.md#supported-regions-option-4) carries—the entry format is tighter on space, and the string form of a code, when one is wanted, is available from the peer's own identity.

## Verify Frame (12)

Asks the destination to vouch for a packet it sent to the requester whose frame counter the requester could not accept. See [Counter Resynchronization](security.md#counter-resynchronization) for when it is sent and what each side does with the answer.

| Field | Size | Description |
|---|---:|---|
| Nonce | 4 bytes | Chosen by the requester; the responder echoes it in Frame Verified |

The packet carrying the command MUST include an [Ack MIC option](packet-options.md#ack-mic-option-8) naming the packet to verify, and does not request an acknowledgement. A responder ignores a Verify Frame without the option.

## Frame Verified (13)

Answers a Verify Frame naming a packet the responder sent and is still waiting to have acknowledged.

| Field | Size | Description |
|---|---:|---|
| Nonce | 4 bytes | Copied from the Verify Frame |

The packet carrying the command MUST request an acknowledgement. Its acknowledgement acknowledges the verified packet as well.
