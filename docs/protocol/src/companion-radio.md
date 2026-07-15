# Companion Radio

A **companion radio** is a radio device that exposes UMSH capability to another
device such as a phone, tablet, laptop, or small computer. The companion radio
is not merely a dumb modem, but it is also not normally the primary home of the
user's long-term UMSH identity.

This chapter describes the architecture: what a companion radio is, where the
security boundary sits, and which responsibilities belong to each side. The
protocol itself is specified in three companion chapters:

- the [Minimal Companion Radio Protocol](companion-radio-minimal.md) defines
  the frame format, core commands, and the property/stream surface needed to
  configure and use a LoRa radio as a raw frame pipe
- the [Full Companion Radio Protocol](companion-radio-full.md) is a strict
  superset that adds receive filtering, inbound queueing, key provisioning,
  and acknowledgement delegation
- [Companion Radio over BLE](companion-radio-ble.md) binds the protocol to
  BLE GATT; serial transports (UART, USB-CDC) use HDLC-Lite framing as
  described in the minimal protocol

The intended model is:

- the **phone or computer** owns the user's long-term identity
- the **companion radio** owns the physical LoRa transceiver and any always-on
  firmware services
- the companion radio may also host a **local radio-owned node** for
  device management and diagnostics

This differs from systems where the radio itself is the user's primary mesh
identity. In UMSH, the user-facing identity usually lives on the host device,
not in the radio.

That separation has important consequences:

- the companion radio does not hold the user's long-term private key
- the host device remains the authority for user identity, contacts, and
  high-level application behavior
- the radio may still perform some limited actions while disconnected if the
  host has provisioned the necessary state in advance

## Identities

A companion radio deals with at most two node identities:

### The Device Identity

The companion radio may host a node that belongs to the radio itself. This
node exists even when no phone is attached and can be used for:

- in-band management
- diagnostics
- repeater or bridge behavior
- announcing the presence or capabilities of the radio

By default, such a node need not advertise itself with ordinary beacons. Its
private key is either generated on the radio itself (preferred) or installed
once by the host; it is never readable back over the companion link. The
host can read the corresponding public key at any time.

The device identity, its channel keys, its peer list, and the radio's own
settings (RF configuration, and eventually repeater policy, positioning, and
advertisement behavior) form the **device domain**: state that belongs to
the radio and survives a change of host.

### The Tethered Host Identity

A phone or computer attaches to the companion radio and uses it as its radio
interface. The host's UMSH identity remains on the host: the radio learns only
the identity's public key, forwards traffic for it, and may cache narrowly
scoped related state (channel keys, per-peer symmetric keys, queued inbound
frames).

The companion-radio protocol supports exactly **one** tethered host identity
at a time. A host application that manages multiple user identities is
expected to select one for the radio to assist; it can still send and receive
traffic for others through the raw frame stream while attached.

Everything provisioned for the host identity — its public key, channel keys,
peer keys, filters, and queued inbound traffic — forms the **host domain**:
state that is keyed by the host identity and wiped wholesale when a
different host identity takes over the radio. Pairing the radio with a new
phone therefore starts the host state over cleanly while leaving the
radio's own identity and settings untouched.

## Operating Modes

### Tethered

In **tethered** mode, a host device uses the companion radio almost as though
the radio were a local hardware peripheral. This is the most direct mode and
is expected to be the common case for phones. It is the mode the companion
protocol chapters specify.

Tethered mode supports:

- radio configuration
- raw UMSH frame transmit and receive
- receive filtering so the host is not woken for irrelevant traffic
- optional offline assistance when the host disconnects

### Bridged

In **bridged** mode, the companion radio behaves more like an infrastructure
service. One or more nearby devices may submit traffic through it, or it may
forward traffic on their behalf subject to local policy, without being the
primary owner of the identities using it.

Bridged mode is useful for:

- a fixed radio shared by multiple users in one location
- a site gateway that extends range for nearby devices
- deployments where the host device is intermittent but the radio remains on

Bridged mode should not be confused with the tethered companion-link
protocol. Tethering is one host talking to its own companion radio over a
local control link. Bridging is a separate local access problem in which
nearby devices are treated more like peers or clients of the radio itself.
Bridging is not yet specified; see [BLE As A Local
Bearer](#ble-as-a-local-bearer) for the design space.

### Hybrid Use

A real device may use both modes at once. For example, a phone is tethered
for its user's personal traffic while the radio's own local node remains
available for management. The companion-radio protocol therefore must not
assume exclusivity.

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

### Material That Must Not Be Provisioned

The companion-radio protocol must not provide a mechanism for provisioning:

- any private key owned by the host device

### Material That Should Generally Be Avoided

Implementations should also avoid provisioning:

- broad contact databases unrelated to radio operation

## Why Provision Keys At All?

If the radio does not have the host's private key, it cannot perform fresh
ECDH on the host's behalf. That means it cannot derive new pairwise state for
previously unknown peers by itself.

Nevertheless, there are useful cases where the host may deliberately preload
symmetric key material for **specific already-known peers and channels**:

- **Pairwise peer keys** let the radio authenticate inbound secure traffic
  from those peers and send MAC acks on the host's behalf while the host is
  asleep or disconnected, so that senders' retransmission logic is satisfied.
- **Channel keys** let the radio recognize multicast traffic on the host's
  channels — and, importantly, **blind unicast** traffic addressed to the
  host, whose destination and source addresses are concealed under the
  channel key (see [Blind Unicast
  Packet](packet-types.md#blind-unicast-packet)). Without the channel key the
  radio cannot even tell such traffic is for the host.

This does not grant the radio the full power of the host's identity. It only
grants limited capability for the specific peers and channels that were
provisioned. The [Full Companion Radio
Protocol](companion-radio-full.md#provisioning-security) specifies the exact
mechanism and its security consequences.

## Capability Groups

The companion-radio interface can be thought of as four capability groups.
The minimal protocol covers the first two; the full protocol adds the rest.

### A. Radio Control

The host needs to configure the physical radio link, but this interface
should not be LoRa-specific in shape where that can be avoided. Different
radios may have different parameter sets.

At minimum, the host can:

- configure frequency, bandwidth, spreading factor, coding rate, power, and
  similar link parameters where applicable
- query device capabilities and current active configuration
- observe radio health and diagnostics
- observe and limit transmit duty cycle

### B. Frame Data Plane

The host uses the companion radio as a transport for UMSH frames:

- transmit of raw complete UMSH frames
- receive of raw complete UMSH frames, with RSSI/SNR receive metadata
- transmit result indications

This keeps the layering clean: the companion-radio link carries UMSH frames,
not re-encoded UMSH semantics. One practical consequence is that the host can
also communicate with the companion radio's own local UMSH node using
ordinary UMSH frames sent over this stream, rather than requiring a separate
bespoke message path for such traffic.

### C. Receive Filtering and Wake Policy

A major value of the companion radio is letting the host sleep while the
radio stays awake. For that to work, the radio needs filtering capability so
it only wakes the host when a frame is relevant. The full protocol derives
filters implicitly from the provisioned host identity and channel keys, and
lets the host add explicit filters by destination hint, channel identifier,
or packet type — or switch to promiscuous delivery for diagnostics.

### D. Offline Assistance

The companion radio may be asked to do limited work while the host is
disconnected:

- buffering inbound frames until the host reconnects and asks for them
- sending MAC acks for the host identity, for peers whose pairwise keys were
  provisioned
- matching known-peer secure traffic against simple local rules

These remain tightly scoped: the radio is assisting the host, not
impersonating it in the general case. Outbound traffic is deliberately **not**
queued — a transmit either happens or fails while the host is attached to
observe the result.

## Suggested Capability Matrix

The table below summarizes which side owns which function.

| Capability | Host | Companion radio |
|---|---|---|
| Long-term private identity key | Yes | No |
| Fresh pairwise derivation for arbitrary new peers | Yes | No |
| Raw frame transmit / receive | Optional | Yes |
| Radio parameter control | Configure | Enforce |
| Receive filtering | Configure | Enforce |
| Channel keys | Yes | Optional, provisioned |
| Pairwise keys for known peers | Yes | Optional, provisioned |
| MAC acks for provisioned peers while host disconnected | Configure/policy | Perform |
| Inbound queueing while host absent | Drain/consume | Perform |

## Low-Power Expectations

A companion radio is especially useful when the host processor should remain
asleep most of the time. The architecture supports:

- the radio remaining awake while the host sleeps
- filtering, acknowledgement, and queueing happening on the radio side
- host wakeup only when relevant traffic arrives
- reconnect and drain of queued frames without losing radio continuity

This fits well with the broader UMSH design goal that devices should wait on
real events rather than spin in polling loops.

## Companion-Link Protocol

The tethered companion link is a single transport-independent protocol,
inspired by the framing discipline of Spinel but with a UMSH-specific
command and property namespace. The same frames run over:

- UART / USB-CDC serial, using HDLC-Lite framing
- BLE, using the GATT frame transport of
  [Companion Radio over BLE](companion-radio-ble.md)
- any other reliable, ordered, flow-controlled local transport

The key structural ideas:

- lightweight binary framing with a one-byte header and small transaction
  identifiers, allowing up to seven in-flight host commands
- **properties** for simple state — a change is confirmed by publication of
  the new authoritative value, and asynchronous state changes use the same
  publication form
- **streams** for packet-like flows such as raw UMSH frames, which are not
  modeled as state
- unsolicited notifications share the grammar of solicited responses

The [Minimal Companion Radio Protocol](companion-radio-minimal.md) defines
the wire format and the subset sufficient for a raw radio; the
[Full Companion Radio Protocol](companion-radio-full.md) layers the
assistance features on top without changing the framing or the version.

Whatever the transport, the companion link is a privileged interface: an
attached host commands transmission with arbitrary content, timing, and
power, and provisioning moves real key material onto the radio. On serial
transports this is protected by physical possession; the BLE binding
specifies an equivalent barrier
(see [Security](companion-radio-ble.md#ble-security)), and key provisioning
must never be carried over a transport that provides less.

## BLE As A Local Bearer

If BLE is used for more than tethering, it should be treated as a separate
local bearer concept rather than an extension of the companion-link protocol.

Two broad BLE directions are relevant:

- **connection-oriented tethering**, where one host talks directly to one radio
  over a local link
- **connectionless or mesh-style local participation**, where multiple nearby
  devices can observe, relay, or respond

The first case is what the companion-link protocol is about. The second case
is a different design problem.

For clarity:

- **tethered companion-link** means "my host talks to my radio"
- **BLE local bearer** means "nearby devices can discover and use this radio or
  exchange nearby UMSH-related traffic over BLE"

The first is point-to-point control and framing. The second is local network
access.

### Plausible BLE Building Blocks

BLE does have modes that are closer to local ad-hoc participation than
ordinary GATT tethering:

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
That is comfortably in the range needed for the companion-link protocol.

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
  where available — this is what
  [Companion Radio over BLE](companion-radio-ble.md) specifies
- if the goal is **nearby-device participation over BLE**, assume the bearer is
  constrained and design for small messages or fragmentation from the outset

That BLE local bearer would need its own answers for questions such as:

- how nearby devices discover an available bridge or repeater
- how access is authorized
- whether traffic is connectionless, connection-oriented, or mixed
- whether the bearer only tunnels complete UMSH frames or also exposes local
  service messages
- how buffering, fairness, and airtime limits are handled when several nearby
  clients share one radio

Bluetooth Mesh is particularly notable because the Bluetooth SIG already
defines an **advertising bearer** and a **GATT bearer**, with Proxy nodes
bridging between them. That architecture is conceptually similar to what a
UMSH device may eventually want: one mode for direct tethered interaction and
another for local many-to-many participation. At the same time, adopting
Bluetooth Mesh itself would mean adopting a substantial stack, not just
borrowing the bearer idea.

## Open Questions

The following items remain intentionally open:

- how much application-layer filtering is appropriate before violating layer
  separation
- whether and how the radio's own device node should announce itself
- the design of a bridged / local-bearer mode, including whether bridged
  clients may provision keys or only use pre-provisioned shared services

## Summary

A companion radio should be understood as a **UMSH radio service with optional
delegated capabilities**, not as the default owner of the user's identity. The
host keeps authority over long-term identity, while the radio contributes:

- always-on physical connectivity
- receive filtering and low-power wake support
- inbound buffering and delegated acknowledgement for provisioned peers
- optional narrowly scoped offline assistance

That split preserves UMSH's cryptographic model while still making small,
low-power, phone-connected radios practical.
