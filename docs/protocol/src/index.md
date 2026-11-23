# Index

Every numbered UEP, published or planned, in number order, followed by the
[proposals](#proposals) not yet numbered. [UEP-0001](uep-0001.md) defines the
process. The number of a planned UEP is tentative until the UEP is
published.

**Requires** lists each UEP's normative dependencies. They come before it,
except where a UEP introduces the ones that follow, as UEP-0013 does for
forwarding. **Source** names the chapters of the legacy specification
(`docs/protocol-legacy/`) its content comes from.

| UEP | Title | Type | Status | Requires | Scope | Source |
|---|---|---|---|---|---|---|
| [0001](uep-0001.md) | UEP Process | Process | Active | — | Drafts, numbering, status, revisions, header, document structure, registries, early allocation, experimental values | — |
| [0002](uep-0002.md) | Architecture Overview | Informational | Experimental | — | Motivation, use cases, guiding principles, goals, non-goals, and the high-level design: layers, nodes and identity, unicast, groups, forward secrecy, delivery, devices and hosts | `introduction`, `routing-overview`, `ulcp`, `limitations` |
| [0003](uep-0003.md) | Conventions and Encodings | Standards | Experimental | — | Requirement language, cross-cutting terminology, byte order, packed unsigned integers, option encoding, strings, ARNCE, base58 | `definitions`, `common-patterns`, `packet-structure`, `ulcp-core` |
| [0004](uep-0004.md) | Addressing | Standards | Experimental | 0003 | Public-key addresses, their presentation and parsing, node and repeater hints, hint rendering, hint collisions | `addressing`, `limitations`, `security-considerations` |
| [0005](uep-0005.md) | Frame Format | Standards | Experimental | 0003 0004 | Packet layout, frame control field, packet types, source address, flood hop count, SECINFO field encoding, the layout of each packet type, locating the options, option attributes and criticality, payload type (a packed unsigned integer) and packet type compatibility, response carriage | `packet-structure`, `packet-types`, `packet-options`, `payload-format`, `addressing`, `security` |
| [0006](uep-0006.md) | MAC Commands | Standards | Experimental | 0003 0005 | Command encoding, reserved identifiers, carriage, Echo (4/5), No-Op (9) | `mac-commands` |
| [0007](uep-0007.md) | Cryptographic Processing | Standards | Experimental | 0003 0004 0005 0006 | Address validation, key conversion, pairwise, group, and group unicast keys, group ID and group hint, associated data, MIC and encryption, MIC size, frame signatures and Frame Signature (option 0), frame counters, replay detection, counter persistence and resynchronization, Verify Frame and Frame Verified (12/13), ack tags and Ack MIC (option 8), duplicate acknowledgments, receive procedure | `security`, `packet-processing`, `security-considerations`, `packet-options`, `packet-types`, `mac-commands` |
| [0008](uep-0008.md) | Groups | Standards | Experimental | 0003 0005 0007 | Group keys, named and simple private groups, sender attribution, group traffic, answering multicast requests | `multicast-channels`, `limitations` |
| [0009](uep-0009.md) | Perfect Forward Secrecy Sessions | Standards | Experimental | 0004 0005 0006 0007 | Handshake, session traffic, linkability, session lifetime, retired sessions, PFS Session commands (6–8) | `security`, `mac-commands` |
| [0010](uep-0010.md) | Location Codes | Standards | Experimental | 0003 | Location code format, encoding, decoding, precision, diluted locations | `node-identity` |
| [0011](uep-0011.md) | Node Identity | Standards | Experimental | 0003 0004 0005 0006 0007 0008 0010 | Identity payload, roles, capability bitmap, identity options, signatures, advertisements and announcing them on a schedule, Identity Request (1) | `node-identity`, `beacons`, `mac-commands` |
| [0012](uep-0012.md) | UMSH over LoRa | Standards | Experimental | 0005 | Channel parameters, sync word, modulation, framing and MTU, `T_frame`, demodulation floor, duty cycle, channel sensing, backoff, immediate acknowledgment, acknowledgment protection interval | `channel-access`, `ulcp-radio` |
| [0013](uep-0013.md) | Forwarding | Standards | Experimental | 0003 0004 0005 0007 0009 0011 0012 0014 0015 0016 | Flood and source-routed forwarding, and which a hop is. The forwarding procedure: the stages later UEPs add to (eligibility, routed or flood hop, flood-only checks, edits to the packet, scheduling), stage outcomes (forward, decline, decline and record) and when the duplicate is recorded, edit order and the outgoing-link fit check, and how a packet arrived (measured on a radio, on a shared medium without measurement, or over a point-to-point link). The pending forward and the events that defer, cut short, abandon, confirm, and retry it. Routing invariants, duplicate suppression, `D_ack` hold-back, forwarding confirmation, overheard acknowledgments, Route Retry (option 6) as a forwarding identity, acknowledgment pacing. A repeater implements UEP-0014, 0015, and 0016 with it | `repeater-operation`, `routing-overview`, `channel-access`, `security`, `packet-options`, `mac-commands` |
| [0014](uep-0014.md) | Flood Forwarding | Standards | Experimental | 0003 0005 0011 0012 0013 | Flood hops, the flood hop count and its accounting, the flood radius limit, the flood contention window and the `SNR_low` a later UEP may raise, Region Code (option 11), region code encoding (short codes, named regions, literal codes), a repeater's regions and default region, Supported Regions (identity option 4) | `repeater-operation`, `routing-overview`, `channel-access`, `packet-options`, `packet-structure`, `node-identity` |
| [0015](uep-0015.md) | Source Routing | Standards | Experimental | 0004 0005 0007 0011 0012 0013 0014 | Source Route (option 3), routed hops, the switch from a source route to flooding, `D_ack` with source-route hops still pending, building a source route, budgeting the flood beyond a route | `packet-options`, `routing-overview`, `repeater-operation`, `channel-access` |
| [0016](uep-0016.md) | Path Discovery | Standards | Experimental | 0003 0004 0005 0006 0007 0010 0011 0013 0014 0015 | Trace (option 7) and its forwarding edit, beacons, the startup beacon, announcing beacons on a schedule, the trace a flooded beacon carries, when to include a trace and what a receiver learns from one, choosing a source route, route learning and the one-hop rule for an identity heard directly, scoping flood hops to a known route, routing acknowledgments by `FHOPS_ACC`, route failure recovery, lost acknowledgments, Peer Repeaters (10/11) | `beacons`, `packet-options`, `packet-structure`, `routing-overview`, `repeater-operation`, `node-identity`, `mac-commands` |
| [0017](uep-0017.md) | Amateur Radio Operation | Standards | Experimental | 0003 0005 0007 0012 0013 | Operating modes, Licensed-Only discard of received encrypted packets, forwarding authority and the Station Callsign edit, Operator Callsign and Station Callsign (options 4/15) | `amateur-radio`, `packet-options` |
| [0018](uep-0018.md) | Adaptive Forwarding | Standards | Experimental | 0011 0012 0013 0014 0015 | Forwarding where no other forwarder is heard: routed and flood hops, the beside and group rules, the contention offset and confirmation timeout, which overheard copies count against a pending forward, the engaged hold, the battery rule, states, identity | `repeater-operation`, `channel-access` |
| [0019](uep-0019.md) | URI Formats | Standards | Experimental | 0003 0004 0008 0011 0014 | Node, group, and `coap-umsh` URIs: syntax and percent-encoding, the node URI and its identity bundle, named-group and group-key URIs and their parameters, the CoAP URI | `uri-formats`, `multicast-channels` |
| [0020](uep-0020.md) | Text Messages | Standards | Experimental | 0003 0005 0007 0008 0019 | Payload and conversations, the options and the display rules that keep a message readable, message types, replies and reactions, sender handle, Message Sequence (message ID and fragments), sequence reset, regarding, editing, colors, padding, message body, group invitations, test messages, message repair (ordering and gaps, the resend request, Group Resend, responding, Message Unavailable, automatic repair and its limits, group repair) | `app-text-messages` |
| [0021](uep-0021.md) | Default Groups | Standards | Experimental | 0005 0007 0008 0020 | `public` and `EMERGENCY`: recognition by key, default membership, the 10-hop flood limit, group unicast only for repair, `public`'s source rule, `EMERGENCY`'s encryption, source, and signature rules, forwarding priority, emergency use, test messages, security considerations | `multicast-channels` |
| [0022](uep-0022.md) | Contact Exchange | Standards | Experimental | 0003 0004 0005 0007 0011 0012 | Session keys, Meet payloads and their carriage, model identifiers, code and session color, exchange, crossed requests, timeouts, malformed frames, nearby, alike colors, transmit power, security considerations (code strength, relays, key erasure, correlation, linking a name to a key) | `app-meet`, `security-considerations` |

## Proposals {#proposals}

Proposals not yet given a number. A planned UEP is numbered when a numbered
UEP requires it or every node of its kind implements it; the rest take a
number when written. Until then, a requirement on one is shown by its title.

| Title | Type | Requires | Scope | Source |
|---|---|---|---|---|
| ULCP: Core | Standards | 0003 0004 | Data representation, frame format, command grammar, properties and streams, mutation atomicity, core properties (0–6), multi-get and multi-set, sessions, state classes, property allocation, attach relationships and synchronization, the security boundary, provisioning security, reboot and DFU, status and reset codes, the capability mechanism | `ulcp-core`, `ulcp` |
| ULCP: Serial Binding | Standards | ULCP: Core | HDLC-Lite, UART flow control (`PROP_UART_WINDOW`), waking a device on a UART | `ulcp-core` |
| ULCP: BLE Binding | Standards | ULCP: Core | GATT binding, segmentation and reassembly, bonding, advertising, `PROP_DEV_DISCOVERABLE` | `ulcp-ble`, `ulcp-device` |
| ULCP: Saved State | Standards | ULCP: Core | Saved snapshot, changes made at the device, `CMD_SAVE`, `CMD_CLEAR`, `CMD_RESTORE`, `CMD_FACTORY_RESET`, `PROP_SAVED` | `ulcp-saved-state` |
| ULCP: Device Node | Standards | 0007 0008 0011, ULCP: Core, ULCP: Saved State | The device identity; `PROP_DEV_KEY`, `PROP_DEV_PRIVATE_KEY`, `PROP_DEV_NAME`, `PROP_DEV_PEERS`, `PROP_DEV_CHANNEL_KEYS`; the identity it advertises: `PROP_IDENT`, `PROP_IDENT_ROLE`, `PROP_IDENT_MOBILE`, `PROP_IDENT_LOCATION`, `PROP_IDENT_ALTITUDE`, `PROP_IDENT_CONTACT` | `ulcp-device` |
| ULCP: Radio Control | Standards | 0012, ULCP: Core | Radio properties (32–44, 4820–4822), `CAP_PHY_LORA`, `CAP_PHY_DUTY_LIMIT`, `CAP_STATS`, radio statistics (4832–4837, 4850, 4851) | `ulcp-radio` |
| ULCP: Repeater Control | Standards | 0013 0014 0016 0018, ULCP: Device Node | `CAP_REPEATER`, `PROP_MAC_REPEATER_MODE` and `PROP_MAC_REPEATER_STATE` including the adaptive mode and states, `PROP_MAC_REPEATER_REGIONS`, `PROP_MAC_REPEATER_DEFAULT_REGION`, forwarding statistics (4838–4840), `PROP_MAC_REPEATERS_HEARD` | `ulcp-device`, `ulcp-radio` |
| ULCP: Announcing | Standards | 0011 0016, ULCP: Device Node | `CAP_ADVERT`, `PROP_ADVERT_INTERVAL`, `PROP_BEACON_INTERVAL`, `PROP_STARTUP_BEACON`, `CMD_ANNOUNCE` | `ulcp-device` |
| Signal Reports | Standards | 0006 0012 | Signal Report Request and Response (2/3) | `mac-commands` |
| Signal-Quality Filtering | Standards | 0014, ULCP: Repeater Control | Minimum RSSI and Minimum SNR (options 5/9), raising the contention window's `SNR_low`. ULCP: `PROP_MAC_REPEATER_MIN_RSSI`, `PROP_MAC_REPEATER_MIN_SNR` | `packet-options`, `routing-overview`, `repeater-operation`, `channel-access`, `ulcp-device` |
| MeshCore Forwarding | Standards | 0012 0013 | Forwarding MeshCore traffic. ULCP: `PROP_MESHCORE_FORWARDING_ENABLED`, `PROP_MESHCORE_REGION_POLICY`, `PROP_MESHCORE_REGIONS`, MeshCore statistics (4841–4844) | `ulcp-device`, `ulcp-radio` |
| ULCP: Wi-Fi | Standards | ULCP: Core, ULCP: Saved State | Station and access point properties (4880–4887, 4912–4915), choosing a network, sharing the radio | `ulcp-wifi` |
| ULCP: IP Connectivity | Standards | ULCP: Wi-Fi | IPv4 and IPv6 state and configuration, DNS (4896–4903) | `ulcp-ip` |
| UMSH over IP Multicast | Standards | 0008 0012 0013, ULCP: IP Connectivity | Transport, echoes, datagram format, discovery, ingress limit, channel access for nodes with a LoRa radio. ULCP: IP multicast properties and counters, virtual radios | `ip-multicast`, `ulcp-ip-multicast` |
| Chat Rooms | Standards | 0020 | Room actions, login and logout, fetching messages and users, admin commands, message distribution, room updates | `app-chat-rooms` |
| Identity Export Format | Standards | 0007 0008 0011 | Envelope, key derivation, sections, restore procedure, QR part framing | `identity-export` |
| ULCP: Frame Transport | Standards | 0012, ULCP: Core, ULCP: Radio Control | `STR_PHY_RAW`, `CMD_STR_SEND`, `CMD_STR_RECV`, send and receive metadata, `PROP_MAC_PROMISCUOUS` | `ulcp-transport`, `ulcp-host` |
| ULCP: Tethered Host Services | Standards | 0008 0009 0011 0020, ULCP: Device Node, ULCP: Frame Transport | The tethered host identity, host keys (96–98), receive filtering, acknowledgment delegation, inbound queueing and `CMD_QUEUE_DRAIN`, receipt cues, muting, standing down, host replacement, host identity heard elsewhere, host drop statistics (4852/4853) | `ulcp-host`, `ulcp-core`, `ulcp-radio` |
| Node Management | Standards | 0005, ULCP: Core, ULCP: Device Node, ULCP: Tethered Host Services | Payload types 8/9, exchanges, multi-property requests, resets, DFU entry, at-most-once processing, cursors, authorization. ULCP: `PROP_DEV_ADMINS`, `CAP_ADMIN`, cursor and authorization status codes | `app-node-management`, `payload-format`, `ulcp-core` |
| ULCP: Node Messaging | Standards | ULCP: Device Node, ULCP: Frame Transport, Node Management | `PROP_NODE_MSG_LISTEN`, `PROP_NODE_MSG_TYPES`, `PROP_NODE_MSG_MTU`, `STR_NODE_MSG`, receiving, sending text | `ulcp-node-messaging` |
| Internet Bridging | Standards | 0013 0014, ULCP: IP Connectivity, UMSH over IP Multicast, ULCP: Frame Transport, ULCP: Tethered Host Services | Bridge model, tunnel transport, radio attachment, integrated clients, host and LAN interfaces, relay procedure, traffic limits, acknowledgments across a bridge. ULCP: bridge client properties, `PROP_MAC_BACKHAUL` | `internet-bridging`, `ulcp-bridge`, `ulcp-host` |
| ULCP: I2C Bus Access | Standards | Node Management | `PROP_I2C_BUSES`, `PROP_I2C_DEVICES`, transfers, scans, sharing the bus, the Node Management binding | `ulcp-i2c` |
| ULCP: Battery Reporting | Standards | ULCP: Core | `PROP_BATTERY`, battery diagnostics (4944–4958) | `ulcp-device` |
| ULCP: Time and Time Zone | Standards | ULCP: Core | `PROP_TIME`, `PROP_TZ_RULE`, `PROP_TIME_24H` | `ulcp-device` |
| ULCP: GNSS | Standards | 0010 0011, ULCP: Time and Time Zone | GNSS properties (88–93), identity updates, time trust (4868–4870) | `ulcp-device` |
| ULCP: Environmental Sensors | Standards | ULCP: Core | `PROP_ILLUMINANCE`, `PROP_TEMPERATURES`, `PROP_TEMPERATURE_NAMES` | `ulcp-device` |
| ULCP: Locate Alert | Standards | ULCP: Core | `PROP_ALERT` | `ulcp-device` |
| ULCP: Communicator Peripherals | Standards | 0021, ULCP: Core, ULCP: Tethered Host Services | Display brightness, timeout, and motion wake; keyboard light and aids; directional control; sound; setup complete, `PROP_TEST_MESSAGE_ALERTS` | `ulcp-device` |
| Threat Model and Design Rationale | Informational | — | What UMSH protects against and what it does not, metadata exposure, cryptographic design rationale, group-specific considerations | `security-considerations` |
| Repeater Profile | Profile | Listed UEPs | The UEPs a repeater implements | — |
| ULCP: Device Profile | Profile | Listed UEPs | The minimum a device implements to be a ULCP device | `ulcp-conformance` |
| Communicator Profile | Profile | Listed UEPs | The UEPs a standalone keyboard-and-screen node implements | — |

## Outside the Series

### Registries

Kept as data in `docs/protocol/registries/`, one file per registry, each
created by the UEP or proposal named here. A registry is published as a page
once its UEP is:

| Registry | Created by |
|---|---|
| [Packet Types](registries/packet-types.md) | 0005 |
| [Packet Options](registries/packet-options.md) | 0005 |
| [Payload Types](registries/payload-types.md) | 0005 |
| [MAC Commands](registries/mac-commands.md) | 0006 |
| [Node Roles](registries/node-roles.md) | 0011 |
| [Capability Bits](registries/capability-bits.md) | 0011 |
| [Identity Options](registries/identity-options.md) | 0011 |
| [Identity Request Options](registries/identity-request-options.md) | 0011 |
| [Text Message Types](registries/text-message-types.md) | 0020 |
| [Text Message Options](registries/text-message-options.md) | 0020 |
| [Model Identifiers](registries/model-identifiers.md) | 0022 |
| Chat Room Actions | Chat Rooms |
| Identity Export Sections | Identity Export Format |
| Node Management Options | Node Management |
| ULCP Commands | ULCP: Core |
| ULCP Properties and Streams | ULCP: Core |
| ULCP Capabilities | ULCP: Core |
| ULCP Status Codes | ULCP: Core |
| ULCP Reset Codes | ULCP: Core |

They replace the registry tables in the legacy chapters and the legacy
`ulcp-index`.

### Guide

Unnumbered, because each describes the whole system and changes as it does:

| Page | Source |
|---|---|
| ULCP Architecture | `ulcp` |
| FAQ | `faq` |
| Comparison with MeshCore | `meshcore-comparison` |
| Comparison with Meshtastic | `meshtastic-comparison` |
| Comparison with Reticulum | `reticulum-comparison` |
| Repeater Operation | `repeater-operation`, `routing-overview` |

Repeater Operation is the forwarding procedure of UEP-0013 with every stage
filled in by the UEPs that add to it, each step linked to its UEP. Like every
Guide page, it is not normative.

### Distributed or Archived

- `test-vectors`: each vector moves to the Test Vectors section of the UEP that
  defines its construction.
- `limitations`: hint collision properties move to UEP-0004, multicast sender
  authentication to UEP-0008, and the absence of fragmentation to UEP-0002.
  Each open issue becomes a draft.
- `ulcp-index`: replaced by the ULCP registries.
- `ulcp-minimal` and `ulcp-full`: moved to `docs/archive/`.

## Terminology

Some UEP terms differ from those of the legacy book and the code:

| Legacy book and code | UEPs |
|---|---|
| Channel, when it means a shared key | Group |
| Channel key | Group key |
| Named channel, private channel | Named group, simple private group |
| Default channels | Default groups |
| Channel identifier (2 bytes) | Group hint |
| Channel commitment | Group ID |
| Channel tag (16 bytes) | The first 16 bytes of the group ID |
| Blind unicast (`BUNI`, `BUAR`) | Group unicast (`GUNI`, `GUAR`) |
| Router hint | Repeater hint |

"Channel" for a radio channel, as in Channel Access, is unchanged.

## Content Moves

In the legacy text, some normative references run against the order above.
These moves resolve them:

1. The SECINFO field encoding moves from `security` into UEP-0005, so parsing a
   frame does not depend on UEP-0007.
2. MAC command encoding, Echo, and No-Op form UEP-0006, ahead of UEP-0007,
   because counter resynchronization may probe with an Echo Request.
3. Acknowledgment pacing moves from `security` into UEP-0013, which defines
   the forwarding-confirmation window pacing is measured against, and how a
   re-acknowledgment is routed after a Route Retry into UEP-0016.
4. The `public` and `EMERGENCY` groups move into UEP-0021, after the text
   message UEP their rules cite.
5. The flood contention window moves from `channel-access` into UEP-0014,
   the give-way rule into UEP-0013, and `T_frame` into UEP-0012.
6. `repeater-operation`'s statements about IP multicast groups and bridges move
   into UMSH over IP Multicast and Internet Bridging, which state which of
   UEP-0013's arrival classes their medium is and the bridge's flood hop
   clamp, and its remark on route learning into UEP-0016.
7. `ulcp-core`'s host replacement and standing-down material moves into
   ULCP: Tethered Host Services, and its Node Management material
   (`PROP_DEV_ADMINS`, `CAP_ADMIN`, the cursor and authorization status codes,
   the DFU TID rule) into Node Management. `ulcp-device`'s at-most-once note
   moves into Node Management as well.
8. `ulcp-saved-state` stops listing other subsystems' properties; each UEP
   states the state class of the properties it defines.
9. `beacons`' Beacons, Advertisements, and Announcing on a Schedule sections
   split by subject: advertisements and their schedule join `node-identity`
   in UEP-0011, and beacons, the startup beacon, and their schedule move
   into UEP-0016 with path discovery.
10. The option record encoding and end marker move from `packet-structure`
    into UEP-0003, since identity, text message, and chat room payloads use
    them too. Finding the end of a packet's options block stays in UEP-0005.
11. `definitions` keeps only cross-cutting terms in UEP-0003. Terms that belong
    to one feature, such as beacon, bridge, trace, flood hop, and frame
    counter, move into that feature's UEP.
12. `addressing`'s Source Address section moves into UEP-0005, since the
    choice between a hint and a full key is made by the frame control field.
13. `ulcp-core`'s packed unsigned integer encoding moves into UEP-0003, since
    payload types use it too.
14. The rule that an Echo Response is traced like its request moves from
    `mac-commands` into UEP-0016, and No-Op's Route Retry into UEP-0016.
15. The group ID and group hint derivations move from
    `packet-types` and `security` into UEP-0007, which derives the group keys
    from them.
16. `security`'s allowance for a split device and host, where the device
    passes an authenticated duplicate to the host to suppress, moves into
    ULCP: Tethered Host Services.
17. Percent-decoding a group name taken from a URI moves from
    `multicast-channels` into UEP-0019.
18. `mac-commands`' Identity Request rules that rest on routing move into
    UEP-0016: a solicitation whose Source Route option is not empty goes
    unanswered, the answer is source-routed along the request's trace, and
    the answer carries a Trace option of its own.
19. `node-identity`'s rule that only an identity heard directly from its
    node places it one hop away moves into UEP-0016.
20. Supported Regions, identity option 4, moves into UEP-0014.
21. The demodulation floor moves from `channel-access`'s contention window
    into UEP-0012, since UEP-0014's contention window uses it.
22. `channel-access`'s rule that a forwarder holds back by `D_ack` moves into
    UEP-0013, and its exception for a packet with source-route hops still
    pending into UEP-0015. UEP-0012 defines `D_ack` and the immediate
    acknowledgment it protects.
23. `mac-commands`' allowance for a repeater to decline to forward a
    broadcast Identity Request moves into UEP-0013, and `channel-access`'s
    adaptive-forwarder contention window into UEP-0018.
24. A location's longitude of +180° now falls in the last cell, as +90°
    latitude does, rather than wrapping to the first. The code already
    encodes it so.
25. `repeater-operation`'s forwarding procedure becomes UEP-0013's, in
    stages that later UEPs add to without reordering it. UEP-0013 decides
    whether a hop is routed or a flood, and introduces UEP-0014, 0015, and
    0016, which every repeater implements with it. Flood hop accounting and
    the region policy step move into UEP-0014, Source Route forwarding into
    UEP-0015, and Trace's value format and forwarding edit into UEP-0016.
    The signal-quality thresholds move into Signal-Quality Filtering, and
    the adaptive contention offset, battery check, and overheard-copy rules
    into UEP-0018, each as an addition to a named stage. Route failure
    recovery and lost acknowledgments move from `repeater-operation` into
    UEP-0016, since they rest on a sender's route state.
26. The ULCP properties of the planned feature UEPs move to ULCP proposals:
    repeater control to ULCP: Repeater Control, announcing to ULCP:
    Announcing, and `PROP_TEST_MESSAGE_ALERTS` to ULCP: Communicator
    Peripherals. A UEP numbered after ULCP: Core defines its ULCP interface
    itself.
27. `node-identity`'s location format moves into UEP-0010, since GNSS
    reporting and location sharing use it apart from any identity. UEP-0011
    keeps the Location identity option, which refers to it.

## Open Items

- Managed groups, whose manager admits and removes members and rotates the
  key, have no wire format. They become a draft once one is designed.
- Payload type 7 (CoAP-over-UMSH) is used by the code but not allocated, and
  only its URI form is specified. It gets a UEP once it is specified.
- `ulcp-ble` links to `node-mgmt.md`, which does not exist; the intended
  target is `app-node-management`.
