# Local Control Protocol (ULCP)

The **UMSH Local Control Protocol** (ULCP) is the interface between a UMSH
**device** — hardware that owns a physical transceiver and runs always-on
firmware — and a **host** such as a phone, tablet, laptop, or small computer
that configures or uses it over a local out-of-band link. The device is not
merely a dumb modem, but it is also not normally the primary home of the
user's long-term UMSH identity.

This chapter describes the architecture: what the device and host each are,
where the security boundary sits, and which responsibilities belong to each
side. The protocol itself is specified in the chapters that follow:

- [Framing and Common Semantics](ulcp-core.md) defines the frame format,
  the command grammar and property model, the classes of state a device
  holds, and the status, reset, and capability registries
- one chapter per subsystem — [Radio Control](ulcp-radio.md),
  [Frame Transport](ulcp-transport.md), [Device Domain](ulcp-device.md),
  [Saved State](ulcp-saved-state.md), and
  [Tethered Host Services](ulcp-host.md) — each defining its own
  capabilities, commands, and properties
- [Minimum Requirements](ulcp-conformance.md) states what a device has to
  implement to be a ULCP device, and the
  [Command and Property Index](ulcp-index.md) locates every numeric
  identifier
- [ULCP over BLE](ulcp-ble.md) binds the protocol to BLE GATT; serial
  transports (UART, USB-CDC) use HDLC-Lite framing
- [Node Management](app-node-management.md) carries the same grammar over
  the mesh itself, letting an authorized administrator reach a device's
  device domain in-band, with no local link at all

One protocol serves every deployment of a device; the familiar deployment
names describe configuration, not distinct firmware:

- a **companion radio** is a device tethered to a host that owns the user's
  long-term identity — the device owns the physical LoRa transceiver, and it
  may also host a **local device-owned node** for management and diagnostics
- a **repeater** is a device commissioned over the same protocol and then
  left to run autonomously, forwarding traffic with no host attached

This differs from systems where the radio itself is the user's primary mesh
identity. In UMSH, the user-facing identity usually lives on the host device,
not in the radio.

That separation has important consequences:

- the device does not hold the user's long-term private key
- the host device remains the authority for user identity, contacts, and
  high-level application behavior
- the device may still perform some limited actions while disconnected if the
  host has provisioned the necessary state in advance

## Identities

A device deals with at most two node identities:

### The Device Identity

The device hosts a node that belongs to the device itself. This
node exists even when no phone is attached and can be used for:

- in-band management
- diagnostics
- repeater or bridge behavior
- announcing the presence or capabilities of the device

By default, such a node need not advertise itself with ordinary beacons. Its
private key is either generated on the device itself (preferred) or installed
once by the host; it is never readable back over the ULCP link. The
host can read the corresponding public key at any time.

The device identity, its channel keys, its peer list, and the device's own
settings (RF configuration, and eventually repeater policy, positioning, and
advertisement behavior) form the **device domain**: state that belongs to
the device and survives a change of host.

### The Tethered Host Identity

A phone or computer attaches to the device and uses it as its radio
interface. The host's UMSH identity remains on the host: the device learns only
the identity's public key, forwards traffic for it, and may cache narrowly
scoped related state (channel keys, per-peer symmetric keys, queued inbound
frames).

ULCP supports exactly **one** tethered host identity
at a time. A host application that manages multiple user identities is
expected to select one for the device to assist; it can still send and receive
traffic for others through the raw frame stream while attached.

Everything provisioned for the host identity — its public key, channel keys,
peer keys, filters, and queued inbound traffic — forms the **host domain**:
state that is keyed by the host identity and wiped wholesale when a
different host identity takes over the device. Pairing the device with a new
phone therefore starts the host state over cleanly while leaving the
device's own identity and settings untouched.

## Operating Modes

### Tethered

In **tethered** mode, a host device uses the device almost as though
it were a local hardware peripheral. This is the most direct mode and
is expected to be the common case for phones. It is the mode the ULCP
protocol chapters specify, and a device deployed this way is a
**companion radio**.

Tethered mode supports:

- radio configuration
- raw UMSH frame transmit and receive
- receive filtering so the host is not woken for irrelevant traffic
- optional offline assistance when the host disconnects

### Bridged

In **bridged** mode, the device behaves more like an infrastructure
service. One or more nearby devices may submit traffic through it, or it may
forward traffic on their behalf subject to local policy, without being the
primary owner of the identities using it.

Bridged mode is useful for:

- a fixed radio shared by multiple users in one location
- a site gateway that extends range for nearby devices
- deployments where the host device is intermittent but the radio remains on

Bridged mode should not be confused with tethered ULCP.
Tethering is one host talking to its own companion radio over a
local control link. Bridging is a separate local access problem in which
nearby devices are treated more like peers or clients of the device itself.
Bridging is not yet specified; see [BLE As A Local
Bearer](ulcp.md#ble-as-a-local-bearer) for the design space.

### Hybrid Use

A real device may use both modes at once. For example, a phone is tethered
for its user's personal traffic while the device's own local node remains
available for management. ULCP therefore must not
assume exclusivity.

## Two Kinds of Attach {#attach-relationships}

A host on the ULCP link is doing one of two things, and the
difference is not a mode of the device but a description of the host's
intent. The device does not track it; the host knows which it means and
confines itself accordingly.

**Tethered attach.** The host is *this device's host*. It writes
`PROP_HOST_KEY`, provisions the host domain — channel keys, peer keys,
receive filters, delegation policy — and thereafter the device filters,
queues, and acknowledges on its behalf. A device serves at most one
tethered host at a time, and being tethered is a transient local
relationship: it does not appear in the device's node identity, does not
survive a power cycle, and is re-established on every attach.

**Administrative attach.** The host is *configuring the device*: its own
identity, its radio, its behavior, its saved snapshot. It writes nothing
in the host domain. This is what commissioning a repeater is, and it is
the normal relationship for any device that is not somebody's radio.

The rule that follows is short: configuring a device's device domain
**MUST NOT** claim its host domain. One phone administering ten repeaters
must not write `PROP_HOST_KEY` on any of them — it would make each
repeater start filtering and queueing for a host that has no intention of
coming back, and would displace whatever host the repeater was actually
serving.

Nothing in the protocol distinguishes the two: a host that has reached
the link can do either (see [ULCP over
BLE](ulcp-ble.md#administrative-authorization)). The
distinction belongs in host implementations, which **SHOULD** make it
explicit rather than incidental — an administrative handle that refuses
host-domain writes cannot commit this error by accident.

## Security Boundary

The fundamental rule is:

> A device must not be provisioned with private keys owned by another
> device.

In particular, the host device keeps ownership of its own long-term and
ephemeral private keys. This keeps the device from becoming an alternate trust
anchor for the user's identity and reduces the impact of device compromise,
theft, or firmware bugs.

However, the device may still be provisioned with some additional keying
material, depending on what offline behavior is desired.

### Material That May Be Provisioned

A host may choose to provision the device with:

- multicast channel keys
- pairwise symmetric keys derived for specific peers
- receive filters tied to specific identities, hints, or packet classes

### Material That Must Not Be Provisioned

ULCP must not provide a mechanism for provisioning:

- any private key owned by the host device

### Material That Should Generally Be Avoided

Implementations should also avoid provisioning:

- broad contact databases unrelated to radio operation

## Why Provision Keys At All?

If the device does not have the host's private key, it cannot perform fresh
ECDH on the host's behalf. That means it cannot derive new pairwise state for
previously unknown peers by itself.

Nevertheless, there are useful cases where the host may deliberately preload
symmetric key material for **specific already-known peers and channels**:

- **Pairwise peer keys** let the device authenticate inbound secure traffic
  from those peers and send MAC acks on the host's behalf while the host is
  asleep or disconnected, so that senders' retransmission logic is satisfied.
- **Channel keys** let the device recognize multicast traffic on the host's
  channels — and, importantly, **blind unicast** traffic addressed to the
  host, whose destination and source addresses are concealed under the
  channel key (see [Blind Unicast
  Packet](packet-types.md#blind-unicast-packet)). Without the channel key the
  device cannot even tell such traffic is for the host.

This does not grant the device the full power of the host's identity. It only
grants limited capability for the specific peers and channels that were
provisioned. [Provisioning
Security](ulcp-core.md#provisioning-security) specifies the exact
mechanism and its security consequences.

## Subsystems

The interface divides into five subsystems, each specified by its own
chapter and each discoverable through the capabilities it advertises.
Only the first two are unconditional.

### [Radio Control](ulcp-radio.md)

The host configures the physical radio link, through an interface that is
not LoRa-specific in shape where that can be avoided — different radios
have different parameter sets. The host can:

- configure frequency, bandwidth, spreading factor, coding rate, power, and
  similar link parameters where applicable
- query device capabilities and current active configuration
- observe radio health and diagnostics
- observe and limit transmit duty cycle

### [Frame Transport](ulcp-transport.md)

The host uses the device as a transport for UMSH frames:

- transmit of raw complete UMSH frames
- receive of raw complete UMSH frames, with RSSI/SNR receive metadata
- transmit result indications

This keeps the layering clean: the ULCP link carries UMSH frames,
not re-encoded UMSH semantics. One practical consequence is that the host can
also communicate with the device's own local UMSH node using
ordinary UMSH frames sent over this stream, rather than requiring a separate
bespoke message path for such traffic.

### [Device Domain](ulcp-device.md)

The radio's own node identity and the settings that make it behave the way
its operator commissioned it: its keys and peers, its name, its repeater
switch, what it advertises about itself on the mesh, and its battery
telemetry. This is what a host writes when it is administering a device
rather than being that device's host.

### [Saved State](ulcp-saved-state.md)

The device can snapshot its device-domain configuration to non-volatile
storage and restore it at boot, which is what lets a radio come back after
a power cut still configured and still forwarding with nobody attached.

### [Tethered Host Services](ulcp-host.md)

Receive filtering, inbound queueing, key provisioning, and acknowledgement
delegation: the work a device does on behalf of the host identity it is
serving.

A major value of a companion radio is letting the host sleep while the
device stays awake. For that, the device filters — implicitly from the
provisioned host identity and channel keys, explicitly by destination
hint, channel identifier, or packet type — so it only wakes the host when
a frame is relevant. While the host is disconnected it may also be asked
to buffer inbound frames until the host asks for them, and to send MAC
acks for peers whose pairwise keys were provisioned.

These remain tightly scoped: the device is assisting the host, not
impersonating it in the general case. Outbound traffic is deliberately **not**
queued — a transmit either happens or fails while the host is attached to
observe the result.

## Suggested Capability Matrix

The table below summarizes which side owns which function.

| Capability | Host | Device |
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

- the device remaining awake while the host sleeps
- filtering, acknowledgement, and queueing happening on the device side
- host wakeup only when relevant traffic arrives
- reconnect and drain of queued frames without losing radio continuity

This fits well with the broader UMSH design goal that devices should wait on
real events rather than spin in polling loops.

## Protocol Shape

ULCP is a single transport-independent protocol,
inspired by the framing discipline of Spinel but with a UMSH-specific
command and property namespace. The same frames run over:

- UART / USB-CDC serial, using HDLC-Lite framing
- BLE, using the GATT frame transport of
  [ULCP over BLE](ulcp-ble.md)
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

[Framing and Common Semantics](ulcp-core.md) defines the wire format and
the grammar every device implements; the subsystem chapters layer
configuration and assistance features on top of it without changing the
framing or the version.

Whatever the transport, ULCP is a privileged interface: an
attached host commands transmission with arbitrary content, timing, and
power, and provisioning moves real key material onto the device. On serial
transports this is protected by physical possession; the BLE binding
specifies an equivalent barrier
(see [Security](ulcp-ble.md#ble-security)), and key provisioning
must never be carried over a transport that provides less.

## BLE As A Local Bearer

If BLE is used for more than tethering, it should be treated as a separate
local bearer concept rather than an extension of ULCP.

Two broad BLE directions are relevant:

- **connection-oriented tethering**, where one host talks directly to one radio
  over a local link
- **connectionless or mesh-style local participation**, where multiple nearby
  devices can observe, relay, or respond

The first case is what ULCP is about. The second case
is a different design problem.

For clarity:

- **tethered ULCP** means "my host talks to my radio"
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

For the **tethered ULCP** case, GATT is attractive partly because its
payload sizes are large enough to be practical for whole-frame carriage. In
BLE, an attribute value may be up to 512 octets, which in practice corresponds
to the familiar "ATT MTU up to 517 bytes" figure once ATT overhead is included.
That is comfortably in the range needed for ULCP.

Advertising-oriented bearers are different. Their payloads are much smaller,
and they should therefore be treated as:

- discovery bearers
- short-message bearers
- or fragmented local bearers

rather than assumed to be "GATT, but connectionless."

As a practical rule of thumb:

| BLE mode | Typical role for UMSH | Payload-size implications |
|---|---|---|
| GATT | Tethered host-to-device ULCP link | Large enough for full ULCP frames and often full UMSH frames without special contortions |
| L2CAP CoC | Tethered host-to-device ULCP link where available | Similar role to GATT, often a cleaner framing substrate |
| LE advertising / scan response | Discovery, announcements, tiny local messages | Small; should not be treated as a full-frame bearer without fragmentation |
| Periodic advertising | Scheduled broadcast / downlink-style announcements | Still advertising-scale payloads; better for scheduled broadcast than general frame transport |
| PAwR | Scheduled low-rate local access with responses | More interesting for shared local access, but still a constrained bearer compared with GATT |
| Bluetooth Mesh bearers | Separate larger design space | Potentially relevant architecturally, but implies adopting a much larger stack and message model |

This suggests a clean split:

- if the goal is **host-to-device tethering**, prefer GATT first and L2CAP CoC
  where available — this is what
  [ULCP over BLE](ulcp-ble.md) specifies
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
- whether and how the device's own node should announce itself
- the design of a bridged / local-bearer mode, including whether bridged
  clients may provision keys or only use pre-provisioned shared services

## Summary

A companion radio should be understood as a **UMSH radio service with optional
delegated capabilities**, not as the default owner of the user's identity. The
host keeps authority over long-term identity, while the device contributes:

- always-on physical connectivity
- receive filtering and low-power wake support
- inbound buffering and delegated acknowledgement for provisioned peers
- optional narrowly scoped offline assistance

That split preserves UMSH's cryptographic model while still making small,
low-power, phone-connected radios practical.
