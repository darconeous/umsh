## Companion Radio

> [!NOTE]
> This section remains partly exploratory, but it now describes the intended
> architecture more concretely.

A **companion radio** is a radio device that exposes UMSH capability to another
device such as a phone, tablet, laptop, or small computer. The companion radio
is not merely a dumb modem, but it is also not normally the primary home of the
user's long-term UMSH identity.

The intended model is:

- the **phone or computer** owns the user's long-term identities
- the **companion radio** owns the physical LoRa transceiver and any always-on
  firmware services
- the companion radio may also host one or more **local radio-owned nodes** for
  device management, maintenance, or shared-site infrastructure use

This differs from systems where the radio itself is the user's primary mesh
identity. In UMSH, the user-facing identity usually lives on the host device,
not in the radio.

That separation has important consequences:

- the companion radio does not normally hold the user's long-term private key
- the host device remains the authority for user identity, contacts, and
  high-level application behavior
- the radio may still perform some limited actions while disconnected if the
  host has provisioned the necessary state in advance

## Roles

It is useful to distinguish three logical roles that may coexist on one
physical companion radio.

### 1. Radio-Owned Local Node

The companion radio may host a node that belongs to the radio itself. This node
exists even when no phone is attached and can be used for:

- in-band management
- diagnostics
- repeater or bridge behavior
- announcing the presence or capabilities of the radio

By default, such a node need not advertise itself with ordinary beacons.

### 2. Tethered Host Identities

A phone or computer may attach directly to the companion radio and use it as
its radio interface. In this mode, the host's own UMSH identities remain on the
host, but the radio forwards traffic for them and may cache some related state.

### 3. Bridged or Shared Service

A companion radio may also serve as a shared bridge for one or more nearby
devices, much like a repeater or gateway. In this role it may forward traffic
without being the primary owner of the identities using it.

These modes are not mutually exclusive. For example, a single radio might:

- host its own hidden management node
- act as a user's tethered personal radio
- also expose a shared bridged service to other nearby devices

## Operating Modes

### Tethered

In **tethered** mode, a host device uses the companion radio almost as though
the radio were a local hardware peripheral. This is the most direct mode and is
expected to be the common case for phones.

Tethered mode should support:

- radio configuration
- raw UMSH frame transmit and receive
- receive filtering so the host is not woken for irrelevant traffic
- optional offline assistance when the host disconnects

### Bridged

In **bridged** mode, the companion radio behaves more like an infrastructure
service. One or more host devices may submit traffic through it, or it may
forward traffic on their behalf subject to local policy.

Bridged mode is useful for:

- a fixed radio shared by multiple users in one location
- a site gateway that extends range for nearby devices
- deployments where the host device is intermittent but the radio remains on

Bridged mode should not be confused with the **tethered companion-link
protocol** described later in this chapter. Tethering is one host talking to
its own companion radio over a local control link. Bridging is a separate local
access problem in which nearby devices are treated more like peers or clients
of the radio itself.

### Hybrid Use

A real device may use both modes at once. For example:

- a phone is tethered for its user's personal traffic
- a second device is bridged through the same radio
- the radio's own local node remains available for management

The companion-radio protocol therefore must not assume exclusivity.

## Security Boundary

The fundamental rule is:

> A companion radio must not be provisioned with private keys owned by another
> device.

In particular, the host device keeps ownership of its own long-term and
ephemeral private keys. This keeps the radio from becoming an alternate trust
anchor for the user's identity and reduces the impact of radio compromise,
theft, or firmware bugs.

However, the radio may still be provisioned with some additional keying
material, depending on what offline behavior is desired.

### Material That May Be Provisioned

A host may choose to provision the companion radio with:

- multicast channel keys
- pairwise symmetric keys derived for specific peers
- receive filters tied to specific identities, hints, or packet classes
- queued outbound traffic awaiting transmission
- queued inbound traffic awaiting host delivery

### Material That Must Not Be Provisioned

The companion-radio protocol must not provide a mechanism for provisioning:

- any private key owned by the host device

### Material That Should Generally Be Avoided

Implementations should also avoid provisioning:

- broad contact databases unrelated to radio operation

## Why Provision Pairwise Keys At All?

If the radio does not have the host's long-term private key, it cannot perform
fresh ECDH on the host's behalf. That means it cannot derive new pairwise state
for previously unknown peers by itself.

Nevertheless, there are useful cases where the host may deliberately preload
pairwise symmetric keys for **specific already-known peers**. Examples include:

- allowing the radio to recognize and surface urgent messages from known peers
- sending MAC ACKs on the host node's behalf while the host is briefly asleep or
  disconnected
- enabling simple keyword or alert matching for specific secure conversations

This does not grant the radio the full power of the host's long-term identity.
It only grants limited capability for the specific peers whose pairwise keys
were provisioned.

## Capabilities

The companion-radio interface should be thought of as four capability groups:

### A. Radio Control

The host needs to configure the physical radio link, but this interface should
not be LoRa-specific in shape where that can be avoided. Different radios may
have different parameter sets.

At minimum, the host should be able to:

- select the physical transport profile or channel plan
- configure frequency, bandwidth, spreading factor, coding rate, power, and
  similar link parameters where applicable
- query device capabilities and current active configuration
- observe radio health and diagnostics

### B. Frame Data Plane

The host should be able to use the companion radio as a transport for UMSH
frames.

At minimum, the interface should provide:

- transmit of raw complete UMSH frames
- receive of raw complete UMSH frames
- transmit result / queued / dropped indications
- optional RSSI/SNR and similar receive metadata

This keeps the layering clean: the companion-radio link carries UMSH frames, not
re-encoded UMSH semantics.

### C. Receive Filtering and Wake Policy

A major value of the companion radio is letting the host sleep while the radio
stays awake. For that to work, the radio needs filtering capability so it only
wakes the host when a frame is relevant.

Useful filters include:

- destination hint
- destination full key, if present
- channel identifier
- packet type
- ACK tag
- "all packets"

It may also be useful to support higher-level policy such as:

- wake only on packets matching known peers
- wake only on packets for certain channels
- wake only on packets that require host attention
- enqueue packets for later delivery without waking the host immediately

### D. Offline Assistance

The companion radio may be asked to do limited work while the host is
disconnected.

Examples include:

- buffering inbound frames until the host reconnects
- storing outbound frames prepared by the host for later transmission
- periodically transmitting configured beacons or advertisements
- matching known-peer secure traffic against simple local rules
- sending MAC ACKs for pre-provisioned identities and peers

These should remain tightly scoped. The radio is assisting the host, not fully
impersonating it in the general case.

## Suggested Capability Matrix

The table below summarizes which side should normally own which function.

| Capability | Host | Companion radio |
|---|---|---|
| Long-term private identity key | Yes | Normally no |
| Fresh pairwise derivation for arbitrary new peers | Yes | Normally no |
| Raw frame transmit / receive | Optional | Yes |
| Radio parameter control | Yes | Yes |
| Receive filtering | Configure | Enforce |
| Beacon scheduling | Configure | Execute |
| Channel keys | Optional | Optional |
| Preloaded pairwise keys for known peers | Optional | Optional |
| MAC ACKs for preloaded secure peers while host disconnected | Configure/policy | Possible |
| Message queueing while host absent | Consume | Perform |

## State Synchronization

A companion radio and host will often need to synchronize state incrementally
rather than all at once.

Important state classes include:

- configured local host-owned identities
- pinned peers
- auto-learned peers, if the host wants visibility into them
- channel keys
- queued inbound/outbound frames
- beacon schedules
- alert/filter policy
- frame-counter reservations, if the radio is allowed to send on behalf of a
  host-owned identity

This does not mean all such state must be mirrored perfectly at all times.
Instead, the interface should let the host be explicit about what authority the
radio has been granted.

## Low-Power Expectations

A companion radio is especially useful when the host processor should remain
asleep most of the time. The architecture should support:

- the radio remaining awake while the host sleeps
- filtering and queueing happening on the radio side
- host wakeup only when a policy match occurs or buffered data crosses a
  threshold
- reconnect and drain of queued events without losing radio continuity

This fits well with the broader UMSH design goal that devices should wait on
real events rather than spin in polling loops.

## Companion-Link Protocol

This protocol is for the **tethered** companion-radio use case: one host device
talking directly to one companion radio over a local link such as BLE, USB, or
UART.

It is not the same thing as treating BLE itself as a local ad-hoc mesh or
bridge medium. If a deployment wants nearby devices to discover one another and
exchange UMSH frames over BLE as peers, that is a separate bearer problem and
should not be conflated with the tethered companion-link protocol described
here.

The companion-radio link itself is outside the core UMSH LoRa MAC. However, it
should ideally be a single transport-independent protocol that can run over:

- BLE
- USB
- UART / serial
- TCP or other local transports, if desired

This avoids inventing one protocol for BLE, another for serial, and a third for
USB. Instead, the system should define one **companion-link framing and message
protocol**, then adapt that protocol to whatever local transport is available.

This protocol is **not** intended to solve the bridge or repeater access case
for nearby devices. In that case, BLE is not just a cable replacement between a
host and its own radio. BLE itself becomes a local bearer over which nearby
devices discover the radio, submit frames, receive frames, or otherwise
participate in a small local network. That requires a separate bearer design.

The following is a suggested direction, not yet a normative wire standard.

### Recommended Shape

Use a unified framed message protocol in which every host-to-radio or
radio-to-host interaction is carried inside one companion-link frame. The frame
payload indicates what kind of message it contains, for example:

- command request
- command response
- event notification
- raw received UMSH frame
- transmit request for a raw UMSH frame
- buffered-frame delivery

This keeps the protocol consistent across transports and avoids designing
separate "control channels" and "data channels" when the overall medium is
already low-speed and latency-tolerant.

### Why A Unified Framed Protocol Is Preferable

For companion-radio use, the important problem is not maximizing throughput
through parallel logical channels. The more important goals are:

- one protocol to implement and debug
- one protocol that can be reused over BLE, USB, and serial
- simple framing and resynchronization after transport disruption
- clear sequencing of requests, events, and frame deliveries
- transport independence

Given the low-speed, high-latency nature of the radio side of the system, a
single orderly framed protocol is usually more valuable than splitting control
and data into distinct lanes.

### Spinel-Like Direction

A good starting point is a protocol that largely mirrors the low-level framing
discipline of Spinel while defining a completely UMSH-specific command and
object namespace.

The important ideas to preserve are:

- lightweight binary framing
- small transaction identifiers
- support for multiple in-flight host commands
- state changes communicated by publication of the new authoritative value
- asynchronous indications using the same general message grammar as
  synchronous replies

The important idea **not** to cargo-cult is that everything must be forced into
the property model. Properties are for simple state. Commands are verbs.
Streams are for event-like or packet-like flows.

This section intentionally defines only the byte-level frame shape and the
general semantic categories. It does **not** attempt to fully specify the final
command set.

### Companion-Link Wire Frame

Inside whatever outer transport framing is used (GATT write/notify payload,
L2CAP payload, SLIP/COBS-encoded serial frame, etc.), each logical
companion-link frame should have the following structure:

```text
+--------+-------------+-------------------+
| Header | Command/Key | Command arguments |
+--------+-------------+-------------------+
  1 byte   packed uint     zero or more bytes
```

The first octet is the **link header**:

```text
  7 6   5 4 3   2 1 0
+-----+-------+-------+
|  P  |  IID  |  TID  |
+-----+-------+-------+
```

Where:

- `P` is a 2-bit protocol-pattern / version field
  - the initial value should be fixed so receivers can quickly reject garbage
    or incompatible major revisions
- `IID` is a 3-bit interface identifier
  - `0` should be the default companion-radio interface
  - other values may later identify additional logical services or vendor
    extensions
- `TID` is a 3-bit transaction identifier
  - `0` is reserved for unsolicited indications and stream traffic
  - `1..7` are host-issued transactions

This preserves the useful "up to seven in-flight host commands" property.

### Packed Integer Encoding

Command identifiers, object identifiers, lengths, and similar scalar values
should use a compact packed-unsigned-integer encoding in the style of Spinel.
This keeps common operations to one or two octets while allowing the namespace
to grow later.

The exact packed integer encoding can be finalized later, but the intent is:

- small numeric IDs occupy one octet
- larger IDs may spill into subsequent octets
- receivers can parse the stream incrementally without ambiguity

### Fundamental Semantic Categories

The companion-link protocol should distinguish:

- **commands**, which are verbs
- **properties**, which are simple pieces of state
- **streams**, which are event-like or packet-like flows

Commands are not objects. They are operations applied to properties or streams.

The namespace may still need to distinguish at least two kinds of named object:

- property identifiers
- stream identifiers

These may share one numeric registry or be separated later, but they must
remain semantically distinct.

#### Property

A **property** is simple state that is naturally described as "this interface
currently has this value."

Examples:

- repeater enabled/disabled
- current RF profile
- configured wake policy
- current battery status
- statistics counters

Properties are appropriate when:

- the value is queryable
- the value may change asynchronously
- the authoritative confirmation of a change is publication of the new value

Properties are **not** appropriate for queued actions, packet ingress/egress,
or multi-phase workflows.

#### Stream

A **stream** is an event-like or packet-like flow that is not well modeled as
stable state.

Examples:

- received UMSH frames
- transmit status events
- buffered frame delivery
- diagnostic log records

Streams are generally one-way publications. They may optionally support
flow-control or acknowledgement commands, but they are not properties.

### Fundamental Command Vocabulary

The starting command vocabulary should be small and generic:

- `Noop`
- `Reset`
- `Get`
- `Set`
- `Insert`
- `Remove`
- `Send`
- `Received`
- `ValueIs`
- `LastStatus`

The intended roles are:

- `Get(key)`
  - asks for the authoritative value of a property
- `Set(key, value)`
  - requests that a property be changed
  - successful completion is normally reported by a matching `ValueIs(key,
    value)` indication rather than by inventing a separate "set succeeded"
    payload shape
- `Insert(key, value)`
  - adds one member to a list- or table-like property
- `Remove(key, value-or-selector)`
  - removes one member from a list- or table-like property
- `Send(stream, value)`
  - sends one item into a stream
  - typical examples include host-to-radio frame submission or host
    acknowledgement/consumption of buffered stream items
- `Received(stream, value)`
  - publishes one item received or emitted on a stream
  - typical examples include radio-to-host UMSH frame delivery, transmit status
    events, wake events, or log records
- `ValueIs(key, value)`
  - publishes the authoritative current value of a property
  - used both for replies to `Get`/`Set`/`Insert`/`Remove` and for asynchronous
    change notification
- `LastStatus(code, ...)`
  - reports completion status when there is no more specific authoritative
    publication to send, or when a command fails

If the protocol later needs additional verbs, they should be added explicitly
rather than pretending a new class of action is really a property update.

### Object Namespace

Properties and streams may share one numeric namespace if desired, but the
specification must make their semantic category explicit.

In other words:

- sharing one encoding space is acceptable
- pretending every named thing in that space is a property is not

Every standardized object identifier should therefore be documented with:

- its semantic category: `property` or `stream`
- which verbs are valid for it
- whether it may emit unsolicited `ValueIs` or `Received` indications

### Publication Model

For properties, the authoritative rule should be:

- the result of changing a property is publication of the new value

For example:

```text
Host  -> Set(Prop::RepeaterEnabled, true)
Radio -> ValueIs(Prop::RepeaterEnabled, true)
```

If the value later changes for some other reason, the same `ValueIs` form is
used again:

```text
Radio -> ValueIs(Prop::RepeaterEnabled, false)
```

This makes state reconstruction from an observed packet trace straightforward.

### Streams And Indications

Stream traffic uses explicit stream verbs rather than property publication.

For example:

```text
Host  -> Send(Stream::UmshFrames, tx-envelope)
Radio -> Received(Stream::TransmitState, queued)
Radio -> Received(Stream::TransmitState, transmitted)
Radio -> Received(Stream::TransmitState, acked)
```

Or:

```text
Radio -> Received(Stream::UmshFrames, rx-envelope)
```

Unsolicited indications use `TID = 0`.

Typical examples:

- `Stream::UmshFrames`
- `Stream::TransmitState`
- `Stream::BufferedFrameReady`
- `Stream::LogRecord`

These are not property publications even if they use the same packed integer
encoding and frame grammar.

### Transactions And Ordering

The host may have up to seven in-flight requests per interface because `TID`
values `1..7` are available concurrently.

The radio should:

- preserve the `TID` on direct replies
- use `TID = 0` for unsolicited indications
- avoid requiring strict global serialization unless a specific command family
  needs it

This allows pipelining without abandoning observability.

### Initial Object Families

A first draft of the UMSH companion-link namespace would likely include at
least the following families:

- protocol identity and capabilities
- radio configuration and current RF state
- repeater policy and wake/filter policy
- buffered inbound/outbound queue state
- transmit and queue-control streams
- received-frame and transmit-status streams
- companion health, battery, and diagnostics

The exact object numbers are intentionally left open for now.

### Initial Candidate Properties And Streams

Using the Spinel core specification in `/Users/darco/Projects/spinel-spec` as a
model, the most useful first pass is probably to separate candidate objects
into:

- constant single-value properties
- mutable single-value properties
- multi-value or table-like properties
- stream properties

The table below is intentionally only a starting point. It is meant to make the
object surface concrete enough to review, rename, split, or delete.

| Candidate object | Kind | Likely verbs | Why it likely exists |
|---|---|---|---|
| `PROP_PROTOCOL_VERSION` | Property, constant | `Get`, `ValueIs` | Companion-link major/minor version so the host can reject incompatible radios early |
| `PROP_RADIO_VERSION` | Property, constant | `Get`, `ValueIs` | Human-readable firmware/build identifier for the companion radio |
| `PROP_INTERFACE_TYPE` | Property, constant | `Get`, `ValueIs` | Identifies this as a UMSH companion-radio interface rather than some other service |
| `PROP_CAPS` | Property, multi-value constant | `Get`, `ValueIs` | Advertises supported capabilities, optional features, and available object families |
| `PROP_INTERFACE_COUNT` | Property, constant | `Get`, `ValueIs` | Number of logical interfaces or services exposed by the companion |
| `PROP_LAST_STATUS` | Property, read-only | `Get`, `ValueIs` | Last command status or reset reason; useful for failures and post-reset synchronization |
| `PROP_POWER_STATE` | Property, mutable | `Get`, `Set`, `ValueIs` | Companion-radio power mode such as offline, standby, low-power, online |
| `PROP_HOST_ATTACH_STATE` | Property, mutable or read-only | `Get`, `Set?`, `ValueIs` | Whether a host session is attached, suspended, draining, or detached |
| `PROP_BATTERY_STATE` | Property, read-only | `Get`, `ValueIs` | Battery percentage, voltage, charging state, or external-power presence |
| `PROP_DEVICE_HEALTH` | Property, read-only | `Get`, `ValueIs` | Compact overall health summary for quick status display |
| `PROP_RF_PROFILE` | Property, mutable | `Get`, `Set`, `ValueIs` | Selected RF profile or channel plan name/ID |
| `PROP_RF_REGION` | Property, mutable | `Get`, `Set`, `ValueIs` | Current regulatory region or UMSH region profile |
| `PROP_RF_FREQUENCY` | Property, mutable | `Get`, `Set`, `ValueIs` | Actual center frequency when direct tuning is exposed |
| `PROP_RF_BANDWIDTH` | Property, mutable | `Get`, `Set`, `ValueIs` | Radio bandwidth |
| `PROP_RF_SPREADING_FACTOR` | Property, mutable | `Get`, `Set`, `ValueIs` | LoRa spreading factor |
| `PROP_RF_CODING_RATE` | Property, mutable | `Get`, `Set`, `ValueIs` | LoRa coding rate |
| `PROP_RF_TX_POWER` | Property, mutable | `Get`, `Set`, `ValueIs` | Radio TX power |
| `PROP_RF_RSSI` | Property, read-only | `Get`, `ValueIs` | Latest RSSI snapshot if the host wants direct radio diagnostics |
| `PROP_RF_SNR` | Property, read-only | `Get`, `ValueIs` | Latest SNR snapshot if the host wants direct radio diagnostics |
| `PROP_REPEATER_ENABLED` | Property, mutable | `Get`, `Set`, `ValueIs` | Turns repeater forwarding behavior on or off |
| `PROP_REPEATER_POLICY` | Property, mutable | `Get`, `Set`, `ValueIs` | Encodes repeater thresholds and policy such as min RSSI/SNR and region restrictions |
| `PROP_STATION_CALLSIGN` | Property, mutable | `Get`, `Set`, `ValueIs` | Callsign used by the radio's own repeater behavior where required |
| `PROP_WAKE_POLICY` | Property, mutable | `Get`, `Set`, `ValueIs` | High-level wake behavior while the host sleeps |
| `PROP_WAKE_REASON` | Property, read-only async | `Get`, `ValueIs` | Most recent wake cause, with optional unsolicited publication |
| `PROP_RECEIVE_FILTERS` | Property, multi-value mutable | `Get`, `Set`, `Insert`, `Remove`, `ValueIs`, `Inserted`, `Removed` | Filter table controlling what wakes the host or gets buffered |
| `PROP_BUFFER_LIMITS` | Property, mutable | `Get`, `Set`, `ValueIs` | Queue capacities, thresholds, or retention policy |
| `PROP_BUFFERED_RX_COUNT` | Property, read-only | `Get`, `ValueIs` | Number of buffered inbound items waiting for the host |
| `PROP_BUFFERED_TX_COUNT` | Property, read-only | `Get`, `ValueIs` | Number of queued outbound items awaiting transmission |
| `PROP_BUFFERED_RX_POLICY` | Property, mutable | `Get`, `Set`, `ValueIs` | Policy for retaining and aging buffered inbound items |
| `PROP_INSTALLED_IDENTITIES` | Property, multi-value mutable | `Get`, `Set`, `Insert`, `Remove`, `ValueIs`, `Inserted`, `Removed` | Host-provided identity contexts the radio is allowed to assist |
| `PROP_INSTALLED_CHANNEL_KEYS` | Property, multi-value mutable | `Get`, `Set`, `Insert`, `Remove`, `ValueIs`, `Inserted`, `Removed` | Shared channel keys provisioned to the companion |
| `PROP_INSTALLED_PEER_KEYS` | Property, multi-value mutable | `Get`, `Set`, `Insert`, `Remove`, `ValueIs`, `Inserted`, `Removed` | Pairwise symmetric peer material provisioned for limited offline assistance |
| `PROP_BEACON_JOBS` | Property, multi-value mutable | `Get`, `Set`, `Insert`, `Remove`, `ValueIs`, `Inserted`, `Removed` | Periodic beacon/advertisement jobs owned by the companion |
| `PROP_STATS_COUNTERS` | Property, read-only | `Get`, `ValueIs` | Packet/queue/retry counters suitable for UI and diagnostics |
| `PROP_UNSOL_UPDATE_FILTER` | Property, multi-value mutable | `Get`, `Set`, `Insert`, `Remove`, `ValueIs`, `Inserted`, `Removed` | Filters which properties are allowed to generate unsolicited `ValueIs` updates |
| `PROP_UNSOL_UPDATE_LIST` | Property, multi-value constant | `Get`, `ValueIs` | Lists properties capable of unsolicited publication |
| `STREAM_DEBUG_LOG` | Stream, output-only | `Received` | Human-readable debug/log output from the companion |
| `STREAM_UMSH_FRAMES` | Stream, input/output | `Send`, `Received` | Carries raw UMSH frames across the host/radio boundary, with direction-specific envelopes for transmit and receive metadata |
| `STREAM_TRANSMIT_STATUS` | Stream, output-only | `Received` | Reports queued, transmitted, forwarded, acked, timed-out, or dropped outcomes |
| `STREAM_BUFFERED_RX` | Stream, output-only | `Received` | Delivers previously buffered inbound frames when the host drains them |
| `STREAM_WAKE_EVENT` | Stream, output-only | `Received` | Wake-trigger events such as matching frame, timer, queue threshold, or button press |
| `STREAM_DIAGNOSTIC_EVENT` | Stream, output-only | `Received` | Structured diagnostic/fault events that are not well modeled as properties |

### UMSH Frame Stream

The most important stream is the raw **UMSH frame stream** across the
host/radio boundary.

This stream is best modeled as a single bidirectional stream rather than as
separate "transmit" and "receive" streams.

The stream carries raw UMSH frames together with associated local metadata:

- `Send(STREAM_UMSH_FRAMES, tx-envelope)`
  - host to radio
  - requests transmission of one raw UMSH frame
- `Received(STREAM_UMSH_FRAMES, rx-envelope)`
  - radio to host
  - reports reception of one raw UMSH frame

The envelope contents are direction-specific:

- a **TX envelope** would normally contain:
  - raw UMSH frame bytes
  - any companion-link-local transmit metadata or policy hints
- an **RX envelope** would normally contain:
  - raw UMSH frame bytes
  - receive metadata such as RSSI, SNR, timestamp, queue origin, or buffering
    information

This stream is fundamentally about moving raw UMSH traffic across the
host/radio boundary. It is not a separate application protocol.

One practical consequence is that the host can also communicate with the
companion radio's own local UMSH node using ordinary UMSH frames sent over this
stream, rather than requiring a separate bespoke message path for such traffic.

### Additional Command Candidates

The objects above imply a few likely verbs or verb families beyond the very
basic ones already listed:

| Candidate command | Why it may be needed |
|---|---|
| `Send` | Natural fit for input or bidirectional streams such as `STREAM_UMSH_FRAMES` |
| `Received` | Natural fit for output or bidirectional streams such as `STREAM_UMSH_FRAMES` or `STREAM_TRANSMIT_STATUS` |
| `Acknowledge` or `Advance` | Likely useful if buffered stream delivery needs explicit host acknowledgement without overloading `Send` |
| `Clear` | May be clearer than `Set(empty)` for some queues, logs, or statistics |
| `Describe` | May be useful if the host wants schema-like detail for complex properties or stream item formats |

These are only candidates. A stricter design may decide that some of these are
unnecessary and can be replaced by better property or stream definitions.

## BLE As A Local Bearer

If BLE is used for more than tethering, it should be treated as a separate
local bearer concept rather than an extension of the companion-link protocol.

Two broad BLE directions are relevant:

- **connection-oriented tethering**, where one host talks directly to one radio
  over a local link
- **connectionless or mesh-style local participation**, where multiple nearby
  devices can observe, relay, or respond

The first case is what the companion-link protocol in this chapter is about.
The second case is a different design problem.

For clarity:

- **tethered companion-link** means "my host talks to my radio"
- **BLE local bearer** means "nearby devices can discover and use this radio or
  exchange nearby UMSH-related traffic over BLE"

The first is point-to-point control and framing. The second is local network
access.

### Plausible BLE Building Blocks

BLE does have modes that are closer to local ad-hoc participation than ordinary
GATT tethering:

- ordinary LE advertising for one-to-many broadcast
- periodic advertising for scheduled connectionless broadcast
- Periodic Advertising with Responses (PAwR) for scheduled broadcast with
  slotted responses
- Bluetooth Mesh, which defines an advertising bearer and a GATT bearer

These are the main reasons it is reasonable to think BLE could support a small
local access or bridge protocol. In particular:

- **ordinary advertising** can announce the presence, capabilities, and service
  class of a nearby radio
- **periodic advertising** can provide a more structured broadcast schedule for
  status or downlink announcements
- **PAwR** is notable because it adds scheduled responses, making it one of the
  clearer BLE building blocks for a low-rate shared local uplink/downlink model
- **Bluetooth Mesh** is relevant less as a complete stack to adopt wholesale
  and more as proof that the Bluetooth ecosystem already recognizes both
  advertising-bearer and GATT-bearer styles of participation

### Practical Payload Size Considerations

Not all BLE bearers are equally suitable for carrying complete UMSH frames.

For the **tethered companion-link** case, GATT is attractive partly because its
payload sizes are large enough to be practical for whole-frame carriage. In
BLE, an attribute value may be up to 512 octets, which in practice corresponds
to the familiar "ATT MTU up to 517 bytes" figure once ATT overhead is included.
That is comfortably in the range needed for a unified framed companion-link
protocol.

Advertising-oriented bearers are different. Their payloads are much smaller,
and they should therefore be treated as:

- discovery bearers
- short-message bearers
- or fragmented local bearers

rather than assumed to be "GATT, but connectionless."

As a practical rule of thumb:

| BLE mode | Typical role for UMSH | Payload-size implications |
|---|---|---|
| GATT | Tethered host-to-radio companion link | Large enough for full companion-link frames and often full UMSH frames without special contortions |
| L2CAP CoC | Tethered host-to-radio companion link where available | Similar role to GATT, often a cleaner framing substrate |
| LE advertising / scan response | Discovery, announcements, tiny local messages | Small; should not be treated as a full-frame bearer without fragmentation |
| Periodic advertising | Scheduled broadcast / downlink-style announcements | Still advertising-scale payloads; better for scheduled broadcast than general frame transport |
| PAwR | Scheduled low-rate local access with responses | More interesting for shared local access, but still a constrained bearer compared with GATT |
| Bluetooth Mesh bearers | Separate larger design space | Potentially relevant architecturally, but implies adopting a much larger stack and message model |

This suggests a clean split:

- if the goal is **host-to-radio tethering**, prefer GATT first and L2CAP CoC
  where available
- if the goal is **nearby-device participation over BLE**, assume the bearer is
  constrained and design for small messages or fragmentation from the outset

These suggest that BLE can support a local bearer for discovery and limited
frame exchange. However, this should be specified separately from the tethered
companion-radio protocol.

### Likely Design Guidance

If UMSH eventually wants BLE-based local participation, the cleaner approach is
probably:

- keep the **companion-link protocol** for tethered host-to-radio control and
  frame exchange
- define a separate **BLE local bearer** for nearby-device participation
- ensure both can coexist on the same physical device without sharing message
  semantics unnecessarily

That BLE local bearer would likely need its own answers for questions such as:

- how nearby devices discover an available bridge or repeater
- how access is authorized
- whether traffic is connectionless, connection-oriented, or mixed
- whether the bearer only tunnels complete UMSH frames or also exposes local
  service messages
- how buffering, fairness, and airtime limits are handled when several nearby
  clients share one radio

Bluetooth Mesh is particularly notable because the Bluetooth SIG already defines
an **advertising bearer** and a **GATT bearer**, with Proxy nodes bridging
between them. That architecture is conceptually similar to what a UMSH device
may eventually want: one mode for direct tethered interaction and another for
local many-to-many participation. At the same time, adopting Bluetooth Mesh
itself would mean adopting a substantial stack, not just borrowing the bearer
idea.

## BLE Adaptation Suggestion

If BLE is used, BLE should carry the unified companion-link protocol rather
than defining a BLE-specific control protocol.

### Why GATT Is Still A Good Baseline

For phones, GATT is the most widely deployable BLE interface today. It works on
Android and iOS without requiring unusual privileges or assuming support for
less common BLE features.

The simplest BLE mapping is therefore:

- one custom service
- one write characteristic from host to radio
- one notify characteristic from radio to host

Each write or notification carries one or more companion-link frames, subject
to the MTU and fragmentation rules of the transport.

### Optional L2CAP CoC

Where platform support is available, BLE L2CAP Credit-Based Channels may be a
better transport for the same companion-link frames because they reduce GATT
overhead and simplify fragmentation. But the protocol riding above should
remain the same.

## Serial / USB Adaptation Suggestion

For UART or USB CDC serial, the same companion-link frames can be carried over a
byte stream using an ordinary framing scheme such as:

- length-prefixed frames with CRC
- SLIP-style framing
- COBS framing

The important part is that the message protocol above remains unchanged. The
serial transport should not require a second command language.

### Raw Frame Carriage

Messages carrying raw UMSH frames should include:

- direction (`tx` request vs `rx` indication)
- frame length
- frame bytes
- optional metadata for received frames such as RSSI, SNR, and local timestamp

Large frames may need fragmentation at the companion-link transport layer. That
fragmentation belongs to the companion-radio link, not to UMSH itself.

### Reliability Model

For any transport, a good default is:

- host-originated requests use `TID = 1..7`
- direct replies preserve the request `TID`
- unsolicited indications and stream publications use `TID = 0`
- buffered stream delivery remains queued until the host explicitly advances or
  acknowledges it

This keeps the protocol lightweight while still allowing pipelining and
post-facto reconstruction of companion-link state.

## Suggested Security Requirements For The Companion Link

Whatever transport is used, the companion-radio link should provide:

- authenticated pairing between host and radio
- authorization for which host may use which identities
- replay protection on companion-link control messages
- explicit policy for whether bridged clients may provision keys or only submit
  frames

If BLE is used, link-layer encryption and bonding are helpful but should not be
treated as the entire security story. The application protocol should still
assume that authorization decisions matter.

## Open Questions

The following items remain intentionally open:

- how much queued state the radio should persist durably
- whether the host should mirror all auto-learned peers or only pinned ones
- how MAC ACK delegation should be authorized per identity
- how much application-layer filtering is appropriate before violating layer
  separation
- whether bridged clients should be allowed to provision keys or only use
  pre-provisioned shared services

## Summary

A companion radio should be understood as a **UMSH radio service with optional
delegated capabilities**, not as the default owner of the user's identity. The
host keeps authority over long-term identity, while the radio contributes:

- always-on physical connectivity
- receive filtering and low-power wake support
- queued buffering
- optional narrowly scoped offline assistance

That split preserves UMSH's cryptographic model while still making small,
low-power, phone-connected radios practical.
