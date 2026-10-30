# LAN Bearer and Wi-Fi Virtual Radio—Research and Implementation Plan

Carry UMSH frames over IP multicast on a local network, so that any radio on
that network acts as a repeater between the LAN and its LoRa mesh, and so that
phones on the same Wi-Fi reach the mesh without a companion radio of their
own. Radios advertise themselves, and the LoRa settings they use, over DNS-SD,
so a phone knows before sending anything whether the LAN reaches the wider
mesh.

The phone side is a *virtual companion radio*: the production ULCP device
session, hosted in an iOS Network Extension that keeps running on chosen Wi-Fi
networks while the app is suspended. The app attaches to it over ULCP exactly
as it attaches to a T1000-E, and the virtual radio acks, queues, and notifies
while the app is away.

This document is a plan, not a protocol specification. None of the proposed
identifiers or behavior is implemented yet. The protocol changes are collected
in [Protocol changes](#protocol-changes) so they can be reviewed as a unit, and
they become one self-contained spec chapter.

The work is in two phases. [Phase 1](#phase-1-protocol-radios-and-host-tooling)
delivers the protocol chapter, the radios, and `umshctl`, and is useful on its
own. [Phase 2](#phase-2-ios) adds the iOS virtual radio.

## Goals

- **Radios as LAN repeaters.** A radio on the LAN sends everything its
  antenna transmits to the multicast group, and hands what it hears there to
  its node as receptions, exactly as backhaul does. With its repeater enabled
  the node forwards them onto LoRa with the same engine it uses for
  LoRa-to-LoRa repeating.
- **Channel bridging.** Several radios on one LAN join their LoRa meshes,
  whether they share LoRa settings or not.
- **Discoverability.** Every radio on the bearer advertises itself and its
  current LoRa settings over DNS-SD.
- **Desktops without a radio.** `umshctl` joins the LAN directly and reaches
  the mesh through any radio on it.
- **Phones without a companion radio.** A phone on the LAN sends and receives
  mesh traffic, gets MAC acks sent for it, and gets notified while the app is
  suspended.
- **Realistic simulation.** The iOS Simulator, desktop tools, the bridge, and
  real radios share one medium.
- **One wire format.** The existing UDP multicast fake radio's datagrams, so
  the dissector, the bridge's `udp-multicast` radio type, and existing tests
  keep working.

## Non-goals

- **Per-phone state on radios.** Radios hold no queues, filters, keys, or
  sessions for phones. Everything a phone needs while away lives on the phone.
- **Delivery across the internet.** The group reaches as far as the
  network's multicast routing carries it, which can span a site's subnets.
  Joining distant sites is the internet bridge's job.
- **nRF52840 boards.** No Wi-Fi.
- **Android.** Later work; nothing here precludes it.

## Research findings

### The existing datagram format is sufficient

`UdpMulticastRadio` (`umsh/src/tokio_support.rs:166-177`) sends one raw frame
per datagram with no header. That carries everything the bearer needs:

- **Protocol discrimination is in the frame.** The top two bits of the first
  octet are the version: `00` for MeshCore v1, `11` for UMSH
  (`docs/meshcore-v1-forwarding-plan.md:117`). A receiver sorts LAN frames the
  way a radio sorts air frames.
- **The sender is the datagram's source address.** No sender identifier is
  needed in the payload.
- **Signal metadata does not belong on the LAN.** A bearer reception is
  unmeasured by definition, like a backhaul reception.

### Echoes are the node's business, except on a simulated radio

Every instance binds the group port with `SO_REUSEPORT` and sends from that
socket, so co-located instances send from an identical `address:15056` and
no source-address check can tell an instance's own datagrams from its
neighbors'. A node already tolerates hearing its own frames, so a bearer
participant takes its echoes like any other datagram. A simulated LoRa radio
cannot: a radio does not hear itself, and its MAC reads a repeat of its own
frame as forwarding confirmation. `UdpMulticastRadio` therefore remembers the
frames it sent and drops the first identical datagram for each.

### A crossing is already defined

The [internet bridge](protocol/src/internet-bridging.md) already defines what
it means to join two meshes through a non-LoRa medium:

- A crossing is two repeater hops: the ingress node forwards, the egress node
  forwards.
- What crosses is the ingress node's rewritten output.
- Egress receives it as an unmeasured backhaul reception.
- The participants' duplicate caches, not the medium, stop circulation.

The integrated client ([ulcp-bridge.md](protocol/src/ulcp-bridge.md#integrated-clients),
`firmware-esp32/firmware/esp32-tracker/src/bridge.rs`) attaches to the radio
multiplexer through `BridgePort` (`crates/umsh-ulcp-runtime/src/radio_mux.rs:98`).
Ingress goes to the node as `RxOrigin::Backhaul`, and egress is the node's
successful transmissions.

The LAN bearer follows the same model—a radio-mux attachment that receives
every frame the antenna transmits and hands its own frames to the node as
receptions—with two deliberate departures, each forced by the LAN being a
shared broadcast space rather than a point-to-point tunnel:

1. **Ingress must contend on LoRa.** The MAC skips the contention window for
   unmeasured receptions because "a frame handed over a point-to-point link
   was heard by exactly one repeater"
   (`crates/umsh-mac/src/coordinator.rs:5930`). On the LAN that is false.
   Every radio on the network hears every datagram, and radios on the same
   LoRa channel would all transmit it at once.
2. **Only over-the-air copies may speak for the LoRa channel.** A LAN copy
   says nothing about which LoRa channel, if any, its sender transmitted on.
   Today any duplicate defers a pending forward, and an unmeasured one
   reschedules it with zero delay. Any copy matching a post-TX listen also
   ends it (`observe_forwarding_confirmation`, called at `coordinator.rs:2688`
   with no origin check). Deferral is a LoRa-channel observation and must
   come only from `RxOrigin::Air`. Confirmation is not: a LAN copy is a frame
   some radio transmitted, and confirms as a backhaul copy does.

These are properties of any shared broadcast bearer, not of IP. The MAC work
is written for any number of bearers, of which the LAN is the first; a later
BLE bearer would be another.

### iOS: suspension is the only real constraint

A suspended app runs no code, so nothing it would receive is processed until
it resumes. Whatever holds frames and sends acks while the app is away has to
run somewhere else. With per-phone state on radios ruled out, that somewhere
is a Network Extension on the phone.

**Local Push Connectivity** (`NEAppPushProvider`, iOS 14 and later):

- An app extension target. The app saves an `NEAppPushManager` configuration
  whose `matchSSIDs` names the Wi-Fi networks it applies to.
- iOS launches the extension when the phone joins a listed network and stops
  it when the phone leaves, independent of the app's state.
- Apple does not prescribe its protocol. `start()` runs ordinary
  Network.framework or BSD socket code. Apple's sample uses TCP; nothing
  requires it.
- It can post local notifications.

**App ↔ extension channel.** `NEAppPushProvider` has no message API (that
exists only on tunnel providers). The extension listens on a Unix domain
socket in a shared App Group container, and the app connects to it. Only apps
in the group can reach the socket file, which serves as ULCP's possession
binding. `NWEndpoint.unix(path:)` makes this a small variant of
`TcpRadioConnection.swift:63` (HDLC-Lite over `NWConnection`). Socket paths
are limited to about 104 octets, so the filename must be short.

**Keychain.** Items are already stored as
`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
(`IdentityVault.swift:121`, `ChannelKeyVault.swift:39`), the class an
extension needs to read them while the phone is locked. Neither an App Group
nor a keychain access group exists yet. Under the ULCP capability split, the
virtual radio needs only what the app provisions to it and its own state, not
the phone's identity key.

**Entitlements.**

- `com.apple.developer.networking.multicast` (Apple review) for IP multicast
  on a physical device. The Simulator does not enforce it. The extension
  probably needs it too, as a separate bundle ID.
- Network Extension with `app-push-provider`. Believed to be self-service;
  unverified.
- `NSLocalNetworkUsageDescription` and `NSBonjourServices` (`_umsh._udp`) in
  Info.plist. DNS-SD browsing itself needs no special entitlement.

### The device session already does the host-absent work

The production ULCP device `Session` owns the host receive filters, auto-ack
policy, and inbound queue (`crates/umsh-ulcp-device/src/session.rs:1904`), and
reports queued frames through `QueuedNotice { class, cue, depth }`
(`session.rs:820-835`). The phone already drains with `CMD_QUEUE_DRAIN`,
provisions pairwise keys for open direct conversations, sets
`PROP_HOST_AUTO_ACK`, and handles `RxBuffered` on drained frames. A T1000-E
turns `QueuedNotice` into a buzzer chirp; the extension turns it into a local
notification.

`umsh-ulcp-simdev` already wraps that session behind an in-memory link, but it
is a test fixture: deterministic seeded identity, RAM storage, and stand-in
entropy (`crates/umsh-ulcp-simdev/src/lib.rs:1-15`). The virtual radio needs
the same wrapper with real storage, OS entropy, and persistent counters.

### ESP32 networking

- Wi-Fi images: Heltec V2, Heltec V3 (bridge image), T-Beam Supreme, T-LoRa
  Pager. On the V3 the Wi-Fi image has no BLE, for RAM reasons; the LAN bearer
  lives in the bridge image there.
- embassy-net 0.8 has `udp` and `multicast` features
  (`Stack::join_multicast_group`); no image enables either today.
- There is no mDNS anywhere in the repo. `docs/protocol/src/ulcp-ip.md:473`
  defers it "for whatever first needs it". This is that.
- Wi-Fi power save (PS Minimum) delays multicast reception to the DTIM
  interval. At LoRa timescales that is acceptable.

## Architecture

```
 LoRa X ── radio A ──┐                                ┌── radio B ── LoRa Y
     (antenna TX out, Bearer ingress)                 │
                     ╞══════ LAN multicast group ═════╡
                     │         239.255.134.121:15056      │
          desktop tools, bridge,           phone: Network Extension
          iOS Simulator (in-process)       (virtual companion radio)
                                                 │ ULCP / HDLC-Lite
                                                 │ Unix socket (App Group)
                                                 └── UMSH app (MAC + chat)
```

**Radios** attach the group to the radio multiplexer as a `BridgePort`, as
backhaul and the integrated internet client do. The MAC has no bearer
machinery of its own:

- **Ingress:** a datagram reaches the node as `RxOrigin::Bearer` and goes
  through the ordinary forwarding procedure, which requires the repeater.
- **Egress:** every frame the antenna transmits, from any mux client, is
  copied to the attachment (`BridgePort::transmitted`) and sent to the group.
  A frame the radio does not transmit does not reach the LAN.

### Forwarding matrix

There is no matrix of its own. A node with its repeater disabled forwards
nothing, from any medium; its own and its host's transmissions still reach
the LAN because the antenna sent them. A node with its repeater enabled
repeats LAN receptions on LoRa, and its LoRa repeats reach the LAN.

- **Nothing returns to the LAN unsent.** A LAN reception reaches the LAN
  again only if the node repeats it on air, where every participant has
  already seen it and drops it as a duplicate.
- **One decision, one rewrite.** The LAN copy is byte-for-byte the frame
  the antenna sent.

### Worked crossings

**Two radios, different settings.**

1. A node on X transmits.
2. Radio A (on X) hears it, decides, and repeats it on X. The transmission
   goes to the LAN.
3. Radio C (on Y) receives the datagram as `Bearer`. It passes the dup check,
   decrements the hop, and repeats on Y after a contention window. That
   transmission goes to the LAN too, where A drops it as a duplicate.

The crossing costs two flood hops, as with the internet bridge.

**Three radios on X, one on Y.**

- **X to Y:** A and B both hear the LoRa frame and contend. The first to
  transmit crosses; the other hears it over the air and defers.
- **Y to X:** C's repeat on Y reaches the LAN. A and B each receive it as
  `Bearer` and contend with windows drawn uniformly from the flood contention
  range. A transmits first; B hears it over the air and defers.

**A phone's frame.** The virtual radio sends it to the group. Every radio
receives it as `Bearer` and contends; the first to transmit on each channel
suppresses the others on that channel. One flood hop is spent at each radio
that carries it onto LoRa.

**A radio's own traffic.** A node originating a message on X transmits on X,
and the transmission goes to the LAN.

**The virtual radio** is a ULCP device whose PHY is the multicast group:

- Its transmissions are datagrams to the group. Radios hear them as bearer
  ingress and forward them onto LoRa, so a phone's frame costs one flood hop.
- Its receptions are every datagram from the group, delivered to the host
  with no signal measurements, as bridge host interfaces already do.
- It has no node and no repeater. It performs host receive filtering,
  auto-acks for provisioned peers, and inbound queueing, like any companion
  radio.
- It has its own device identity, generated from the OS CSPRNG and persisted
  in the App Group container.

**Where the virtual radio runs:**

| Situation | Host process | Background behavior |
|---|---|---|
| Physical phone on a listed Wi-Fi network | Network Extension | Acks, queues, notifies |
| Foreground on an unlisted network with radios present | App, in-process | None |
| iOS Simulator | App, in-process | None |

**Radio selection on the phone.** A configured BLE companion radio that is
reachable wins. Otherwise the app uses the virtual radio. Switching:

- **To BLE:** drain the virtual radio's queue, then set *the virtual radio's*
  `PROP_PHY_ENABLED` false and save. With the PHY off it neither acks nor
  queues, so two radios never act for one identity.
- **To Wi-Fi:** enable the virtual radio's PHY and save. Saved state survives
  the extension being stopped and relaunched on network changes, so the
  virtual radio listens even if the app is never opened.
- **The BLE companion radio's PHY is never touched by a handover.** Switching
  to Wi-Fi happens only when the BLE radio is unconfigured or unreachable, and
  an unreachable companion keeps doing its own host-absent work, to be drained
  when it reconnects.
- A frame queued by both radios during a handover is absorbed by the MAC's
  duplicate cache. This needs a test.

**Discovery.** Radios advertise `_umsh._udp` with their LoRa settings in TXT.
The app browses, shows which radios the LAN reaches and on which settings, and
offers to add the current network to the extension's `matchSSIDs`.

**Notifications.** The extension maps `QueuedNotice` to a local notification:
generic text by class ("New direct message", "N new group messages"), honoring
the existing mute tables. When the app drains the queue it must not notify a
second time for the same frames. Rich content (sender name, message text) needs
decryption, the text layer, and contact names in the extension; that is
[later work](#later-work).

## Protocol changes

All normative LAN bearer text lives in **one new chapter,
`docs/protocol/src/lan-bearer.md`**, listed after Internet Bridging. It is the
document the multicast entitlement request points to, so it must stand alone:
a reader who knows nothing else of UMSH learns from it what the group carries,
who sends to it, how participants are discovered, and what a participant does
with a datagram. Other chapters get one-line cross-references, never
normative text of their own.

The forwarding and channel-access rules are written for bearers in general,
because they are. They live in this chapter until a second bearer exists, at
which point they move to `repeater-operation.md` and `channel-access.md` and
this chapter links to them.

Two things stay outside the chapter, following existing precedent:

- **Device configuration** goes in `ulcp-lan-bearer.md`, beside
  [Bridge Client](protocol/src/ulcp-bridge.md), the same split the internet
  bridge uses.
- **The Unix socket ULCP transport** is part of phase 2 and lands with the
  iOS work.

### P1. Chapter outline (`lan-bearer.md`)

1. **Overview.** What the bearer is for, the participant roles (bridging
   radio, endpoint, virtual radio), and why a multicast group: every
   participant hears every other with no server.
2. **Transport** (P2).
3. **Datagram format** (P2).
4. **Discovery** (P3).
5. **Forwarding across bearers** (P4).
6. **Channel access** (P5).
7. **Security considerations.**
   - UMSH frames are already authenticated, and encrypted where the
     payload type calls for it. The LAN adds nothing and removes nothing.
   - The group reaches as far as the network routes it.
   - Anyone on the LAN can inject frames. They are bounded by the ingress
     limit and the duty ceiling, the same exposure as anyone with a LoRa
     radio, at a higher offered rate.
   - DNS-SD records reveal what a radio's LoRa transmissions already reveal.

### P2. Transport and datagram format

- **Transport:** UDP over IPv4 multicast. Default group `239.255.134.121`,
  default port 15056, both drawn at random (the port from an unassigned IANA block
  below the common ephemeral ranges) so the group is unlikely to be shared by
  anything else. Senders
  use a multicast TTL of 16; containment is left to the network's multicast
  routing and the group's administrative scope.
- **Datagram:** exactly one frame, with no header. UMSH and MeshCore v1 frames
  are distinguished by their version bits. Senders MUST NOT send a frame
  larger than 255 octets. Receivers drop, with accounting, datagrams that are
  empty, oversized, or carry an unknown version.
- **Shared port:** every participant sends from the group's port as well as
  to it; see [P9](#p9-point-to-point-and-the-shared-port).
- **Echo:** a participant MAY drop datagrams whose source is its own address
  and port; it otherwise takes its echoes like any datagram.
- **Bearer semantics:** a datagram is a bearer reception: unmeasured, subject to
  [P4](#p4-forwarding-across-bearers) and [P5](#p5-channel-access).
- **Ingress limit:** a radio limits LAN-to-LoRa forwards with a token bucket
  (frames per minute). The duty ceiling applies as for any forward.

### P3. Discovery

DNS-SD service type `_umsh._udp`. The instance name is the device name. The
SRV port is the group port. Every bearer participant with a LoRa radio SHOULD
advertise; whether others advertise is decision D8. TXT keys:

| Key | Value | Present |
|---|---|---|
| `v` | TXT schema version, `1` | Always |
| `grp` | Multicast group address | Always |
| `id` | Node public key, base58 (44 characters) | Always |
| `f` | LoRa center frequency, Hz | When the node has a LoRa radio |
| `bw` | LoRa bandwidth, Hz | With `f` |
| `sf` | Spreading factor | With `f` |
| `cr` | Coding rate denominator (5–8) | With `f` |
| `rep` | `1` if LoRa repeating is enabled | With `f` |
| `mc` | `1` if MeshCore v1 forwarding is enabled | Optional |
| `ib` | `1` if an internet bridge link is up | Optional |

A participant updates its TXT record when any value changes. Clients treat a
missing optional key as false and ignore unknown keys.

### P4. Forwarding across bearers

- **The model:** a node may have one or more *bearers* in addition to its
  radio, each working as backhaul does: receptions in, the antenna's
  transmissions out. The repeater switch alone decides forwarding.
- **Bearer identity:** a reception records which bearer it arrived on.
- **Hop accounting:** a crossing between two radios costs two flood hops. A
  frame a bridging radio originates costs one, at the radio that repeats it.
- **Trace:** a bearer reception adds the existing "nothing was measured" trace
  signal entry, so no new trace semantics are needed. A distinct bearer marker
  is deferred until route scoring has a use for it.
- **Source routes:** a hint consumed by a bridging node leads to one
  transmission, which reaches both the air and the LAN.
- **Duty ceiling:** LoRa transmissions of bearer input count against it like
  any other forward. LAN copies spend no LoRa airtime.

### P5. Channel access

- **Contention for bearer receptions:** a frame received from a bearer carries
  no LoRa measurement but was heard by every bridging node on that bearer. Its
  flood contention window is drawn uniformly from `[W_min, W_max]`, plus the
  usual jitter.
- **Point-to-point backhaul:** keeps its zero window.
- **Only over-the-air receptions defer:**
  - Only a copy received over the air may defer or suppress a pending
    forward. Receptions from a bearer or a backhaul say nothing about who
    heard the radio channel.
  - This also corrects the internet bridge's co-located-client case, where a
    tunnel copy currently reschedules a pending forward to fire immediately.
- **Bearer copies confirm:** a copy received from a bearer satisfies
  [forwarding confirmation](protocol/src/repeater-operation.md#forwarding-confirmation),
  as a backhaul copy does. A LAN endpoint's frame comes back to the group
  when a radio repeats it on air; that return is the endpoint's
  confirmation.
- **Ack-MIC cancellation is unchanged.** It stays origin-independent: an
  acknowledgment proves delivery whichever way it arrived.

### P6. ULCP surface (`ulcp-lan-bearer.md`)

`CAP_LAN_BEARER`, tentatively 63, the next free code after
`CAP_MESHCORE_FORWARDER` (62); recheck before allocating. It requires no
other capability. Group and state belong to every device with the bearer;
the switch, the ingress limit, and the counters belong to a device that
forwards between the LAN and LoRa, one advertising `CAP_REPEATER`.
Device-domain properties, saved by `CMD_SAVE` and writable by authorized mesh
administrators. Numbers are tentative, chosen clear of the MeshCore block
(4976–4978):

| Prop | Name | Type | Access | Notes |
|---|---|---|---|---|
| 4992 | `PROP_LAN_BEARER_ENABLED` | BOOL | Get/Set | Default false |
| 4993 | `PROP_LAN_BEARER_GROUP` | Address and port | Get/Set | Default `239.255.134.121:15056`; empty write restores it |
| 4994 | `PROP_LAN_BEARER_INGRESS_LIMIT` | UINT16 | Get/Set | Frames per minute; zero invalid; empty write restores the default |
| 4995 | `PROP_LAN_BEARER_STATE` | UINT8 | Get/Is | 0 Disabled, 1 Active, 2 No network |

**Defaults are followed, not copied.** A group or ingress limit that nobody
has set holds no value of its own: a read reports the default in effect, an
empty write returns a set one to that state, and `CMD_SAVE` records it as
unset. A device that saves its settings for any reason therefore keeps
following its firmware's default, and a firmware with a different default
brings it along. Saving the default's value instead would freeze whatever
default was current at the first save of any setting. The precedent for the
empty write is `PROP_IDENT_ROLE`, where empty means "derive your own."

**Independence from other switches.** Enabling the bearer does not change
`PROP_MAC_REPEATER_ENABLED` or the Wi-Fi properties. When Wi-Fi is off or not
associated, the bearer reports state 2.

Counters under `CAP_STATS`: received, dropped by the ingress limit, malformed,
sent to the group, and dropped from the transmit queue.

**Virtual radio.** No new identifiers. It declares `CAP_LAN_BEARER`, whose
group property chooses the group its PHY uses, and the existing host-side
capabilities (raw stream, host filters, auto-ack, inbound queue, saved state),
and none of the identity, repeater, Wi-Fi, or hardware ones. What it reports
for PHY settings is decision D10.

### P7. Cross-references in existing text

- **`SUMMARY.md`:** list `lan-bearer.md` after Internet Bridging and
  `ulcp-lan-bearer.md` after Bridge Client.
- **`repeater-operation.md`, `channel-access.md`, `packet-processing.md`:**
  one line each where bearer receptions change behavior, linking to P4 and
  P5.
- **`internet-bridging.md`:** a node may run an integrated client and the LAN
  bearer together; frames move between them through the one forwarding
  decision.
- **`ulcp-ip.md`:** replace the deferred mDNS item with a link to the
  discovery section.
- **`ulcp-index.md`:** the new capability, properties, and counters.
- **`dissectors/README.md`:** the UDP heuristic now describes a protocol, not
  a test fixture.

### P8. Phase 2: local ULCP transport (`ulcp-core.md`)

HDLC-Lite over a Unix domain socket, whose possession requirement is met by
filesystem access to the socket. A connection opening is an attach and its
closing a detach, and a new connection replaces the current one, so a host
that died without closing never holds the device against its successor. It
is general, not iOS-specific, and lands with the iOS work because that is
its first user. It sits beside the other transport bindings in
[Local Sockets](protocol/src/ulcp-core.md#local-sockets).

### P9. Point-to-point and the shared port

- **Shared port:** every participant sends from the group's port and listens
  on it, so a peer always knows where to answer, and a stateful firewall or
  NAT passes the answer to an outgoing datagram.
- **Point-to-point:** `PROP_LAN_BEARER_GROUP` MAY hold a unicast address,
  naming the one peer of a link. Nothing is joined; datagrams go to the peer
  at the group's port, and only datagrams from the peer's address and port
  are taken. Each end names the other on the same port. The property refuses
  `0.0.0.0` and `255.255.255.255`.
- **Discovery:** unchanged; `grp` reports whatever address is configured.

### P10. LAN interfaces on the internet bridge (`internet-bridging.md`)

- **Interface:** a bridge participant MAY join a bearer group as an
  interface—the server beside its radio and clients, a client beside or
  instead of its radio. Datagrams arrive unmeasured; frames leave as
  datagrams.
- **Crossing rule:** no repeater stands between the group and the bridge,
  so a participant carries a frame across a LAN interface at most once, in
  either direction, within 30 seconds, judged by the frame's octets. This
  is the one exception to the relay procedure's ban on duplicate
  suppression; it stops two participants on one LAN, or a participant and
  its own echo, from circulating a frame, and drops only frames the far
  side's duplicate caches have already seen.
- **Limits:** the server MUST rate-limit its LAN interface, as it does a
  host interface. `umsh-bridge` defaults the limit to the bearer's own
  ingress limit.
- **Client:** with a radio and a LAN interface, a client copies each frame
  from any of the three (radio, LAN, tunnel) to the other two.

## Implementation

The work splits into two phases. **Phase 1 stands alone:** radios bridge
across the LAN, desktops join it with no hardware, and the protocol chapter is
published. **Phase 2** adds the iOS virtual radio on top, reusing phase 1's
crates unchanged.

### Phase 1: protocol, radios, and host tooling

#### 1.1 Protocol chapter, then the entitlement request

- Write `lan-bearer.md` (P1–P5), `ulcp-lan-bearer.md` (P6), and the
  cross-references (P7).
- Publish it with the rest of the spec book, so it has a stable URL.
- **File the multicast entitlement request pointing at that URL.** Approval is
  the long pole for phase 2, so it should start as soon as the chapter exists.

#### 1.2 ESP32 spike (no merge)

The V3 bridge image with embassy-net `udp` and `multicast` plus an mDNS
responder (`edge-mdns` or a minimal announcer). Measure RAM and stack before
committing to an approach.

#### 1.3 MAC and HAL (host-tested)

**`umsh-hal`.**

- Add `RxOrigin::Bearer`, with `is_measured()` false and a bearer identity
  (decision D5 settles its shape).
- Audit every `match` on `RxOrigin` and every `is_measured()` call.
  Measurement gates stay as they are; the contention and confirmation sites
  change.

**`umsh-mac`.**

- **No bearer state.** The MAC gains no configuration, queue, or export
  path; ingress arrives through the radio mux and the repeater gate in
  `maybe_forward_received` applies unchanged.
- **Contention:** `sample_flood_contention_delay_ms` (`coordinator.rs:5929`)
  draws uniformly over the window for `Bearer`.
- **Deferral and confirmation:** `defer_pending_forward`
  (`coordinator.rs:5999`) acts only on `Air`; `observe_forwarding_confirmation`
  accepts every origin.

**Tests in `umsh-mac`.**

- a bearer reception repeated only with the repeater enabled;
- a nonzero window for `Bearer` and zero for `Backhaul`;
- no deferral from `Bearer` or `Backhaul` copies;
- confirmation from a `Bearer` copy.

**Topology test.** Three nodes on two simulated LoRa channels sharing one
bearer, using the `SimulatedNetwork` harness in
`crates/umsh-mac/src/test_support.rs`.

#### 1.4 `crates/umsh-lan-bearer` (std)

- Move `UdpMulticastRadio` out of `umsh/src/tokio_support.rs`, so the
  umbrella, `umsh-bridge`, `umshctl`, and later `umsh-mobile-core` share one
  implementation.
- One socket on the group's port for sending and receiving, TTL 16, a join
  only for a multicast group, and a peer filter for a unicast one.
- A receive-origin setting: `Bearer` for real use, and the current fixed
  measured `Air` for simulation tests that need signal values.
- DNS-SD advertise and browse for hosts (the `mdns-sd` crate), with the P3 TXT
  codec.
- Update the bridge's `udp-multicast` radio and tests, and the examples.

#### 1.5 Radio multiplexer

- `radio_mux_with_bridge` takes a slice of attachments, each with its own
  ingress `RxOrigin`. Hand-off is round-robin among them.
- `transmitted()` copies every frame the antenna sends, from any client, to
  every attachment.
- An attachment says whether the ULCP session hears it too. The LAN does: it
  is a shared medium the device hears, like the air, so an attached host in
  promiscuous or filtered mode sees bearer receptions as unmeasured frames.
  The internet tunnel does not.
- Images with Wi-Fi can then run the internet client and the LAN bearer side
  by side.
- Extend the existing mux tests.

#### 1.6 ESP32 firmware

- embassy-net `udp` and `multicast` features in the Wi-Fi images.
- A LAN bearer task: one UDP socket, group join, ingress limit, transmit
  what the mux attachment receives.
- An mDNS responder publishing P3, updated on LoRa settings changes.
- The P6 properties and counters.
- Rejoin the group after a Wi-Fi reconnect.
- Measure RAM and stack on every image; the V3 bridge image is the tight one.

#### 1.7 Soft device core

Split `umsh-ulcp-simdev` into a production core (pluggable storage, OS entropy,
persistent counters, real identity generation) and the deterministic simulated
configuration on top of it. Its first production user is `umshctl --lan`; the
iOS virtual radio is its second.

#### 1.8 umshctl

- **`umshctl lan show|on|off|group|limit`:** configure a radio's LAN bearer
  over any existing target, mirroring the `bridge` subcommand
  (`tools/umshctl/src/command/bridge.rs`).
- **`umshctl lan browse`:** list DNS-SD participants with their LoRa settings
  and roles. Needs no radio.
- **`--lan[=GROUP:PORT]` target:** host the soft device core in-process with
  the LAN as its PHY, beside `--port`, `--ble`, and `--tcp`. Every command
  (`message`, `discover`, `ping`, `capture`, and the rest) then works against
  the LAN with no hardware. This is the desktop counterpart of the iOS virtual
  radio, so phase 2 starts from a virtual radio that is already exercised.
  - Its state (identity, saved configuration) lives under the umshctl state
    directory, locked so two processes never run one identity.
  - Unlike a LoRa radio, umshctl switches its PHY on whenever it opens it:
    choosing `--lan` is choosing the LAN.

#### 1.9 Phase 1 validation

- **Host:** two `umshctl --lan` instances and the bridge on one Mac through
  the group; several instances per host; a point-to-point link between
  two hosts.
- **Radios:** two ESP32 radios on different LoRa settings bridged by one LAN;
  a crossing in each direction; contention when both hear the same LAN frame.
- **Desktop to mesh:** `umshctl --lan` messages a LoRa-only node through a
  radio, and `lan browse` shows that radio's settings.

### Phase 2: iOS

#### 2.1 iOS spike (no merge)

- an `NEAppPushProvider` extension launching on a listed SSID;
- the app ↔ extension Unix socket in an App Group container;
- whether the extension needs its own multicast entitlement;
- posting a local notification from the extension;
- the extension's memory ceiling, measured with the device session linked in;
- how the app learns the current SSID (permission requirements for
  `NEHotspotNetwork.fetchCurrent`);
- what survives an extension stop and relaunch.

#### 2.2 Protocol

P8, the Unix socket transport binding.

#### 2.3 UMSHMobileCore

A `VirtualRadio` UniFFI object owning the phase 1 soft device core and the
`umsh-lan-bearer` socket, exposing the HDLC-Lite byte stream and
`QueuedNotice`.

#### 2.4 App and extension

- **App:**
  - `UnixSocketRadioConnection`, the TCP connection with a Unix endpoint;
  - an in-process connection for the Simulator and unlisted networks;
  - the DNS-SD browser and a radios-on-this-network view;
  - SSID registration into `matchSSIDs`;
  - the BLE/Wi-Fi selection policy and handover.
- **Extension target:** hosts `VirtualRadio`, listens on the socket, posts
  notifications. The project file is hand-written, so the new target and files
  need manual `project.pbxproj` edits.
- **Entitlements and plumbing:** App Group on both targets, holding the
  radio's state and its socket; no keychain access group, since the radio
  has no identity of its own; multicast and `app-push-provider`
  entitlements; Wi-Fi information on the app, to list the network;
  Info.plist keys.

#### 2.5 Phase 2 validation

- With the app suspended, a direct message from a LoRa node is acked, queued,
  and notified, then delivered once on resume.
- Handover to BLE and back without double acks.
- The iOS Simulator joins the same group as phase 1's radios and desktops.

## Acceptance criteria

**Phase 1.**

- A LoRa node on settings X and one on settings Y exchange direct messages
  through two radios sharing a LAN, with correct hop accounting.
- With several radios on one channel on one LAN, the radios carrying a
  bridged frame onto that channel transmit staggered by contention rather
  than together, and an overheard copy defers the rest. Whether a deferred
  radio later transmits anyway is the ordinary deferral limit's business,
  not the bearer's.
- A radio with its repeater disabled forwards nothing between the LAN and
  LoRa.
- No frame circulates. Each node forwards a given frame at most once.
- LAN ingress is rate-limited; bridged LoRa transmissions stay under the duty
  ceiling.
- `umshctl --lan` reaches a LoRa-only node with no local radio, and
  `umshctl lan browse` lists the radios and their LoRa settings.
- No radio holds per-phone or per-host state.
- The protocol chapter is published and self-contained.

**Phase 2.**

- A phone with no companion radio, on a listed network, receives a direct
  message while the app is suspended: the sender sees it acknowledged, and the
  phone shows a notification.
- The app lists the radios on the network with their LoRa settings before
  sending anything.
- The iOS Simulator, desktop tools, and a real radio exchange messages through
  one group.

## Risks and decisions

- **D1. Multicast entitlement.** Approval is not guaranteed. Without it,
  physical phones fall back to BLE only; the Simulator and desktop work
  regardless. Whether the extension needs its own grant comes from the spike.
- **D2. SSID acquisition.** The extension runs only on listed networks, and
  reading the current SSID may need location permission. The fallback is
  asking the user to confirm the network when radios are first found.
- **D3. Who may bridge.** *Decided: the repeater switch.* A node forwards
  between the LAN and LoRa only with its repeater enabled; a bearer's switch
  alone makes it a participant on the LAN, carrying its own and its host's
  traffic, as a repeater-off device is a leaf on the internet bridge.
- **D4. Integrated internet client parity.** *Decided: both are mux
  attachments.* The LAN and the internet client receive the same transmitted
  frames and enter the node the same way.
- **D5. Bearer identity in `RxOrigin`.** *Decided: a payload,
  `RxOrigin::Bearer(BearerId)`, with up to eight bearers.* A payload on `RxOrigin::Bearer`
  (a small bearer index) versus a separate tag carried beside the reception.
  The first is simpler; `RxOrigin` is matched in many places.
- **D6. IPv4 only.** ESP32 images are IPv4-only. An IPv6 link-local group can
  follow if a platform needs it.
- **D7. Admission.** Anyone on the LAN can transmit on LoRa through a radio.
  The ingress limit and duty ceiling bound it; an allow-list is not proposed.
- **D8. Non-radio participants in DNS-SD.** *Decided for phase 1: radios
  only. The spec makes advertising a SHOULD for bridging radios and a MAY for
  everyone else.* Whether desktop tools, the bridge,
  and the virtual radio also advertise, and with what role marker.
- **D9. Notification content.** Generic first; rich content later.
- **D10. Virtual radio PHY settings.** *Decided for phase 1: `umshctl --lan`
  reports the default profile's settings, fixed. The discovered-slowest
  proposal remains open for phase 2.* The phone's MAC times acks from the
  radio's frame time, but its frames are actually transmitted later by a LoRa
  radio. Proposed: report the slowest LoRa settings among discovered radios,
  read-only.
- **D11. Bridge hub on the LAN.** The hub's existing `udp-multicast` radio
  already joins a group as a segment. Whether that becomes a supported way to
  connect a LAN to the internet bridge, or the integrated client on a radio is
  the only path.

**Risks.**

- **Traffic merging.** Bridging meshes puts each mesh's floods on the others'
  airtime. Region policy and the existing exit clamp are the tools. A
  per-bearer region list is a possible follow-up if field use shows the need.
- **ESP32 RAM.** If the bearer and mDNS do not fit beside the internet client
  on an image, that image ships one or the other, decided per board.

## Later work

- Rich notifications: decryption, the text layer, and contact names in the
  extension.
- An IPv6 link-local group.
- Android: a foreground service in place of the Network Extension.
- MeshCore v1 frames across the LAN once the MeshCore forwarder exports them.
- Further bearers on the same MAC mechanism, such as BLE extended advertising
  ([ble-bearer-plan.md](ble-bearer-plan.md)).
