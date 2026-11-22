# ULCP: Node Messaging

Node messaging lets a local link exchange UMSH application payloads
through the device's own node. The link hands the device a payload and a
destination, and the device encrypts it, routes it, retries it, and
collects its acknowledgement under the
[device identity](ulcp-device.md#device-identity). In the other
direction, the device hands the link the decrypted payloads of the types
the link has claimed.

[Frame Transport](ulcp-transport.md) is the opposite arrangement: there
the host runs the whole UMSH MAC, with its own keys, counters, and
routes, and the device moves complete frames for it. Node messaging is
for a link that wants to send and receive messages without any of that,
such as a sensor or a small microcontroller wired to the device. What it
sends and receives is the device's own traffic, so the peers and channels
it uses are the device's
([`PROP_DEV_PEERS`](ulcp-device.md#prop-dev-peers),
[`PROP_DEV_CHANNEL_KEYS`](ulcp-device.md#prop-dev-channel-keys)), and
its messages are sent and acknowledged as the device.

Node messaging is available on every local binding: an attached host,
and the [device's own interface](ulcp-core.md#device-interface). It is
not available to an [administrator](app-node-management.md) over the
mesh.

## Capabilities {#capabilities}

Code | Name           | Requires           | Grants
-----|----------------|--------------------|--------
67   | `CAP_NODE_MSG` | `CAP_DEV_IDENTITY` | [`STR_NODE_MSG`](#str-node-msg) and the three properties below

`CAP_NODE_MSG` requires `CAP_DEV_IDENTITY` because everything this
chapter sends is sent as the device identity, and everything it delivers
was addressed to it.

## Properties

Id   | Mnemonic                                       | Commands                 | Description
-----|------------------------------------------------|--------------------------|-------------
51   | [`PROP_NODE_MSG_LISTEN`](#prop-node-msg-listen) | Get, Set                 | The attached host receives node messages
5008 | [`PROP_NODE_MSG_TYPES`](#prop-node-msg-types)   | Get, Set, Insert, Remove | The payload types delivered to a link
5009 | [`PROP_NODE_MSG_MTU`](#prop-node-msg-mtu)       | Get                      | The longest payload every send accepts

### PROP 51: `PROP_NODE_MSG_LISTEN` {#prop-node-msg-listen}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: **REQUIRED** with `CAP_NODE_MSG`
* Scope: Session
* Value Type: BOOL
* Post-Reset Value: 0

Whether the attached host receives node messages. While it is set, the
host is the link that receives them (see [Who Receives](#who-receives));
while it is clear, they go to the device's own interface or wait.

This is [session state](ulcp-core.md#session-state): it is clear at the
start of every [session](ulcp-core.md#sessions), so a host that attaches
only to commission the device does not take the messages an application
on the device's own interface is waiting for. A host that
wants them sets it again in each session.

It is the attached host's alone. The device answers a write from its own
interface with `STATUS_NOT_PERMITTED`: an application there that wants
no messages removes its claims instead.

### PROP 5008: `PROP_NODE_MSG_TYPES` {#prop-node-msg-types}

* Type: Multiple-Value, Read-Write
* Has Item Length Prefix: No
* Asynchronous Updates: No
* Required: **REQUIRED** with `CAP_NODE_MSG`
* Scope: Device
* Item Type: UINT8
* Post-Reset Value: Empty, or the saved value

The [payload types](payload-format.md) the device delivers over node
messaging, each item one octet. A payload type that is listed is
**claimed**: a message of that type addressed to the device identity, to
one of its channels, or broadcast is delivered to a link as this chapter
describes. A type that is not listed is not delivered.

This is device-domain state and is [saved](ulcp-saved-state.md) with the
rest of it, so a device that restarts keeps delivering to an application
that has not yet started again. Setting the property to the value it
already has, or inserting an item already present, changes nothing and
writes nothing to non-volatile storage; an application can set its
claims every time it starts.

A device does not deliver a payload type it consumes itself, and answers
a write that would claim one with `STATUS_NOT_PERMITTED`. Which types
those are depends on the device. The reason is mechanical, not
protective: a claimed type is subject to [pushback](#pushback), so a
claim on a type the device acts on would let a link that stopped reading
stop the device from acting on it too.

### PROP 5009: `PROP_NODE_MSG_MTU` {#prop-node-msg-mtu}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: **REQUIRED** with `CAP_NODE_MSG`
* Scope: Device
* Value Type: UINT16
* Units: Octets

The length of the longest `DATA`, payload type included, that the device
accepts for a send of every kind when the send sets no flag other than
`ACK` and carries no option. Each of the following makes the frame
longer, and so the longest payload shorter, by about:

* `FULL_SOURCE`: 29 octets;
* `SIGNED`: 64 octets, or 70 on a broadcast;
* `TX_OPT_SOURCE_ROUTE` with *N* hints: 2*N*, plus one or two octets.

A send whose `DATA` is too long for the send as asked fails with
`STATUS_INVALID_ARGUMENT`, so a link that needs the exact figure for a
particular send can learn it by asking.

## Streams

Id  | Mnemonic       | Commands   | Description
----|----------------|------------|-------------
114 | `STR_NODE_MSG` | Send, Recv | Application payloads sent and received by the device's node

### STREAM 114: `STR_NODE_MSG` {#str-node-msg}

* Type: Packet-Stream, Input/Output
* Required: **REQUIRED** with `CAP_NODE_MSG`
* Supported Commands: Send, Recv
* Scope: Device
* Value Type: Structure

The stream carries one UMSH payload per command, in the
[`CMD_STR_SEND`](ulcp-transport.md#cmd-str-send) and
[`CMD_STR_RECV`](ulcp-transport.md#cmd-str-recv) structure: `DATA_LEN`,
then `DATA`, then metadata. `DATA` is the
[payload](payload-format.md) as UMSH carries it: the payload type octet,
then the body.

#### Metadata for Send {#send-metadata}

The `Send` metadata is the following fields, in order. Each address
field is present only when the kind calls for it.

Field        | Type       | Meaning
-------------|------------|--------
`TX_KIND`    | UINT8      | 0 unicast, 1 broadcast, 2 blind unicast, 3 multicast
`TX_FLAGS`   | UINT8      | See below
`TX_CHANNEL` | 16 octets  | Present when bit 1 of `TX_KIND` is set: the full [channel identifier](packet-types.md#channel-identifier-derivation) of one of the device's channels
`TX_PEER`    | 32 octets  | Present when bit 0 of `TX_KIND` is clear: the destination's public key
`TX_OPTIONS` | Entries    | To the end of the frame

The metadata is not optional: a send carries at least `TX_KIND` and
`TX_FLAGS`.

`TX_FLAGS`:

* `TX_FLAG_ACK` Bit 0: request an acknowledgement. Valid only for a
  unicast or blind unicast: UMSH has no acknowledgement for a broadcast
  or multicast frame.
* `TX_FLAG_FULL_SOURCE` Bit 1: carry the device's full 32-byte public key
  as the source rather than its hint.
* `TX_FLAG_SIGNED` Bit 2: carry a [frame signature](security.md#frame-signatures).
  Defined for every kind. A device that cannot sign the kind asked for
  answers `STATUS_UNIMPLEMENTED`.
* All other bits: *RESERVED*, transmitted as zero.

`TX_OPTIONS` is a sequence of entries in the
[`CMD_PROP_MULTI_SET` entry form](ulcp-core.md#cmd-prop-multi-set):
`LENGTH` (PUI) | `OPTION` (PUI) | `VALUE`. None is required.

Option | Name                  | Value                                         | Absent
-------|-----------------------|-----------------------------------------------|--------
1      | `TX_OPT_FLOOD_HOPS`   | UINT8, 0–15                                   | The device's default flood budget
2      | `TX_OPT_SOURCE_ROUTE` | 1–15 two-octet router hints, next repeater first | The route the device has learned for the destination, or a flood
3      | `TX_OPT_TX_POWER`     | INT8, as `TX_POWER` in [`STR_PHY_RAW`](ulcp-transport.md#str-radio-raw) | The device identity's transmit power

`TX_OPT_FLOOD_HOPS`
: The flood budget (`FHOPS_REM`, see
  [Packet Structure](packet-structure.md)). Zero sends no flood-hop
  field. For an acknowledged send that carries a source route, this is
  also the budget the [route retry](routing-overview.md) floods with when
  the route fails, so a route with no flood fallback is that route with
  this option set to zero.

`TX_OPT_SOURCE_ROUTE`
: The route as given, used in place of anything the device has learned.
  A [trace](#recv-metadata) received with a message is already in this
  order and can be copied in unchanged.

`TX_OPT_TX_POWER`
: Clamped to the radio's range, as for
  [`PROP_PHY_TX_POWER`](ulcp-radio.md#prop-phy-tx-power).

#### Sending

The device sends `DATA` as the device identity, as the kind and flags
ask:

* A unicast or blind unicast destination need not be in
  `PROP_DEV_PEERS`: the device derives what it needs from the key.
* Any payload type may be sent, including the ones the device itself
  originates. An application administering other nodes sends
  [Node Management](app-node-management.md) requests this way.
* An unknown option, a repeated option, a value of the wrong length or
  out of range, a flag the kind does not allow, or a `DATA` too long for
  the send as asked is `STATUS_INVALID_ARGUMENT`. A device **MUST NOT**
  silently ignore an option it does not recognize: the link asked for
  something specific. Metadata that does not parse is
  `STATUS_PARSE_ERROR`.
* Sends are independent. Two sends may reach the air in either order.

A send with a non-zero TID is answered with one `CMD_PROP_IS` of
`PROP_LAST_STATUS` carrying its TID, once the device knows the outcome.
That is after the acknowledgement arrives or the device stops waiting for
it, for an acknowledged send, and after the frame is on the air
otherwise. A send with TID 0 is not answered.

Status                     | Meaning
---------------------------|--------
`STATUS_OK`                | Acknowledged; or, when no acknowledgement was asked for, on the air
`STATUS_NO_ACK`            | On the air, and no acknowledgement arrived before the device stopped waiting
`STATUS_CCA_FAILURE`       | Never on the air: the channel stayed busy
`STATUS_DUTY_LIMIT`        | Never on the air: it would have exceeded the [duty-cycle limit](ulcp-radio.md#prop-phy-duty-limit)
`STATUS_BUSY`              | The device has no room for another send in progress; send again later
`STATUS_CHANNEL_NOT_FOUND` | `TX_CHANNEL` names a channel the device holds no key for
`STATUS_INVALID_ARGUMENT`  | As above
`STATUS_PARSE_ERROR`       | As above
`STATUS_UNIMPLEMENTED`     | The device cannot sign this kind
`STATUS_NOMEM`             | The device has no room to hold the destination's keys
`STATUS_INVALID_STATE`     | The device has no device identity

#### Metadata for Recv {#recv-metadata}

The `Recv` metadata is the following fields, in order:

Field        | Type          | Meaning
-------------|---------------|--------
`RX_KIND`    | UINT8         | As `TX_KIND`
`RX_FLAGS`   | UINT8         | See below
`RX_CHANNEL` | 16 octets     | Present when bit 1 of `RX_KIND` is set: the full channel identifier
`RX_SRC`     | 32 or 3 octets | The sender: its public key when `RX_FLAG_SRC_KEY` is set, otherwise its 3-byte hint
`RX_OPTIONS` | Entries       | To the end of the frame, in the same entry form as `TX_OPTIONS`

`RX_FLAGS`:

* `RX_FLAG_SRC_KEY` Bit 0: `RX_SRC` is the sender's 32-byte public key.
* `RX_FLAG_SENDER_AUTH` Bit 1: the sender is authenticated, by the
  pairwise MIC of a unicast or by a verified frame signature.
* `RX_FLAG_ACKED` Bit 2: the device acknowledged the message.
* `RX_FLAG_GAP` Bit 3: the device discarded one or more unacknowledged
  messages since the previous delivery (see [Pushback](#pushback)).
* `RX_FLAG_REDELIVERED` Bit 4: the device delivered this message before,
  over a link whose session was then reset, and is delivering it again
  (see [Redelivery](#redelivery)). The link may already have it.
* All other bits: *RESERVED*, transmitted as zero.

`RX_SRC` is the key whenever the device knows it, which is always for a
unicast or blind unicast. Only a multicast or broadcast message from a
sender the device does not know carries the hint.

Option | Name           | Value
-------|----------------|------
1      | `RX_OPT_RSSI`  | UINT8, as `RX_RSSI` in [`STR_PHY_RAW`](ulcp-transport.md#str-radio-raw)
2      | `RX_OPT_SNR`   | INT16, centibels, as `RX_SNR` in `STR_PHY_RAW`
3      | `RX_OPT_TRACE` | The two-octet router hints of a complete [trace](packet-options.md#trace-option-7), nearest repeater first

A link ignores an option it does not recognize. A reply is built from
what was received: `RX_SRC` (a key) becomes `TX_PEER`, `RX_CHANNEL`
becomes `TX_CHANNEL`, and `RX_OPT_TRACE` becomes `TX_OPT_SOURCE_ROUTE`.

## Receiving {#receiving}

### Who Receives {#who-receives}

A message of a claimed type is delivered to at most one link:

1. the attached host, if it has set
   [`PROP_NODE_MSG_LISTEN`](#prop-node-msg-listen);
2. otherwise the device's own interface, if it has one;
3. otherwise no link: the message waits in the device's buffer.

Each message is delivered once, as a `CMD_STR_RECV` on `STR_NODE_MSG`,
and only when the link can take it. Node messages are never live frames
in the sense of [A Link That Stops Reading](ulcp-core.md#stalled-host):
a link that is not reading is not handed one and does not lose one.

### Pushback {#pushback}

The device holds received messages of claimed types in a buffer until a
link takes them. How many it holds is up to the device.

* **A full buffer never displaces an acknowledged message.** When the
  buffer has no room, the device declines a new message that requests an
  acknowledgement: it neither acknowledges nor keeps it (see
  [Packet Processing](packet-processing.md)). Its sender retransmits,
  and the message is accepted once there is room.
* An unacknowledged message may be displaced by a newer one, or
  discarded when there is no room. The next delivery carries
  `RX_FLAG_GAP`.
* A link holds messages in the buffer by exerting its transport's flow
  control: not reading, on BLE, USB, or a socket; withholding XON, on a
  [UART](ulcp-core.md#uart-flow-control).

The acknowledgement a sender receives therefore means that the device
has the message and room for it, not that a link has read it. There is
no delivery confirmation beyond that.

### Redelivery {#redelivery}

A message the device has delivered stays in the buffer until its room is
needed for a new message. Such a message counts as room: it never causes
a new one to be declined, and it is the first to be replaced.

When a link starts a new session with
[`CMD_SESSION_START`](ulcp-core.md#cmd-session-start), or the device ends
a link's session because a frame was [lost](ulcp-core.md#lost-frames),
the device delivers again every message it still holds that it had
delivered to that link, with `RX_FLAG_REDELIVERED` set. The device cannot know which
of them arrived, so the link may receive a message twice; the flag is
how it tells. A link that restarts and opens its session therefore
receives the last few messages delivered to it before it restarted,
flagged.

Messages that have not been delivered are not affected by the end of a
session. They are delivered once a link can take them.

## Sending Text {#sending-text}

A [text message](app-text-messages.md) is payload type 3, its options,
the `0xFF` marker, and the body. The smallest one is the three octets
`03 FF` followed by the body, which a link can send with no knowledge of
the text options at all. Received text is decoded the same way: options
up to the `0xFF` marker, then the body.
