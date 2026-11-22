# Index

Every numbered UEP, published or planned, in number order, followed by the
[proposals](#proposals) not yet numbered. [UEP-0001](uep-0001.md) defines the
process. The number of a planned UEP is tentative until the UEP is
published.

**Requires** lists each UEP's normative dependencies, all of which come before
it. **Source** names the chapters of the legacy specification
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
| 0009 | Perfect Forward Secrecy Sessions | Standards | Planned | 0006 0007 | Handshake, session key derivation, wire-level privacy, session lifetime, retired sessions, PFS Session commands (6–8) | `security`, `mac-commands` |
| 0010 | Node Identity | Standards | Planned | 0006 0007 | Identity payload, roles, capability bitmap, identity options, signatures, Identity Request (1). ULCP: `PROP_IDENT`, `PROP_IDENT_ROLE`, `PROP_IDENT_MOBILE`, `PROP_IDENT_LOCATION`, `PROP_IDENT_ALTITUDE`, `PROP_IDENT_CONTACT` | `node-identity`, `mac-commands`, `ulcp-device` |
| 0011 | UMSH over LoRa | Standards | Planned | 0005 | LoRa PHY parameters, sync word, MTU, `T_frame`, duty cycle. ULCP: radio properties (32–44, 4820–4822), radio statistics (4832, 4834–4837, 4850, 4851) | `ulcp-radio`, `channel-access` |
| 0012 | Channel Access | Standards | Planned | 0005 0011 | Channel sensing, backoff, ACK protection interval, immediate ACK. ULCP: `PROP_STAT_TX_CHANNEL_BUSY` | `channel-access`, `ulcp-radio` |
| 0013 | Flood Routing | Standards | Planned | 0006 0007 0010 0012 | Routing invariants, duplicate suppression, forwarding procedure, flood hop count forwarding, flood contention window, forwarding confirmation, overheard acknowledgments, route failure recovery, Route Retry (option 6), acknowledgment pacing. ULCP: `PROP_MAC_REPEATER_MODE`, `PROP_MAC_REPEATER_STATE`, forwarding statistics (4838–4840) | `repeater-operation`, `routing-overview`, `channel-access`, `security`, `packet-options`, `packet-structure`, `mac-commands`, `ulcp-device`, `ulcp-radio` |
| 0014 | Signal-Quality Filtering | Standards | Planned | 0013 | Minimum RSSI and Minimum SNR (options 5/9). ULCP: `PROP_MAC_REPEATER_MIN_RSSI`, `PROP_MAC_REPEATER_MIN_SNR` | `packet-options`, `routing-overview`, `ulcp-device` |
| 0015 | Region Scoping | Standards | Planned | 0010 0013 | Region Code (option 11), Supported Regions (identity option 4). ULCP: `PROP_MAC_REPEATER_REGIONS`, `PROP_MAC_REPEATER_DEFAULT_REGION` | `packet-options`, `node-identity`, `routing-overview`, `ulcp-device` |
| 0016 | Amateur Radio Operation | Standards | Planned | 0005 0013 | Operating modes, locally originated packets, Operator Callsign and Station Callsign (options 4/15) | `amateur-radio`, `packet-options` |
| 0017 | Beacons and Advertisements | Standards | Planned | 0010 0013 | Beacons, advertisements, announcing on a schedule. ULCP: `PROP_ADVERT_INTERVAL`, `PROP_BEACON_INTERVAL`, `PROP_STARTUP_BEACON`, `CMD_ANNOUNCE` | `beacons`, `ulcp-device` |
| 0018 | Source Routing and Path Discovery | Standards | Planned | 0006 0013 0017 | Source Route (option 3), Trace (option 7), path discovery, route learning, scoping flood hops to a known route, the flood hop count on source-routed hops, routing acknowledgments by `FHOPS_ACC`, Peer Repeaters (10/11). ULCP: `PROP_MAC_REPEATERS_HEARD` | `beacons`, `packet-options`, `packet-structure`, `routing-overview`, `mac-commands`, `ulcp-radio` |
| 0019 | Adaptive Forwarding | Standards | Planned | 0010 0013 0018 | Forwarding where no other forwarder is heard: source-routed and flood hops, giving way, engagement, battery, states, identity | `repeater-operation` |
| 0020 | URI Formats | Standards | Planned | 0004 0008 | Node, group, and `coap-umsh` URIs | `uri-formats` |
| 0021 | Text Messages | Standards | Planned | 0007 0008 0020 | Message type, sender handle, regarding, editing, colors, padding, message body, group invitations, test messages | `app-text-messages` |
| 0022 | Message Sequencing and Repair | Standards | Planned | 0021 | Message sequence, ordering, gaps, automatic repair, sequence reset, group resend | `app-text-messages` |
| 0023 | Default Groups | Standards | Planned | 0008 0021 0022 | `public` and `EMERGENCY`. ULCP: `PROP_TEST_MESSAGE_ALERTS` | `multicast-channels`, `ulcp-device` |
| 0024 | Contact Exchange | Standards | Planned | 0004 0010 0020 | Session keys, Meet payloads, code and color, exchange, nearby, transmit power, linking a name to a key, security considerations | `app-meet`, `security-considerations` |

## Proposals {#proposals}

Proposals not yet given a number. Each takes one when it is written; until
then, a requirement on one is shown by its title.

| Title | Type | Requires | Scope | Source |
|---|---|---|---|---|
| ULCP: Core | Standards | 0003 0004 | Data representation, frame format, command grammar, properties and streams, mutation atomicity, core properties (0–6), multi-get and multi-set, sessions, state classes, property allocation, attach relationships and synchronization, the security boundary, provisioning security, reboot and DFU, status and reset codes, the capability mechanism | `ulcp-core`, `ulcp` |
| ULCP: Serial Binding | Standards | ULCP: Core | HDLC-Lite, UART flow control (`PROP_UART_WINDOW`), waking a device on a UART | `ulcp-core` |
| ULCP: BLE Binding | Standards | ULCP: Core | GATT binding, segmentation and reassembly, bonding, advertising, `PROP_DEV_DISCOVERABLE` | `ulcp-ble`, `ulcp-device` |
| ULCP: Saved State | Standards | ULCP: Core | Saved snapshot, changes made at the device, `CMD_SAVE`, `CMD_CLEAR`, `CMD_RESTORE`, `CMD_FACTORY_RESET`, `PROP_SAVED` | `ulcp-saved-state` |
| ULCP: Device Node | Standards | 0007 0008, ULCP: Core, ULCP: Saved State | The device identity; `PROP_DEV_KEY`, `PROP_DEV_PRIVATE_KEY`, `PROP_DEV_NAME`, `PROP_DEV_PEERS`, `PROP_DEV_CHANNEL_KEYS` | `ulcp-device` |
| Signal Reports | Standards | 0006 0011 | Signal Report Request and Response (2/3) | `mac-commands` |
| MeshCore Forwarding | Standards | 0013 0015 | Forwarding MeshCore traffic. ULCP: `PROP_MESHCORE_FORWARDING_ENABLED`, `PROP_MESHCORE_REGION_POLICY`, `PROP_MESHCORE_REGIONS`, MeshCore statistics (4841–4844) | `ulcp-device`, `ulcp-radio` |
| ULCP: Wi-Fi | Standards | ULCP: Core, ULCP: Saved State | Station and access point properties (4880–4887, 4912–4915), choosing a network, sharing the radio | `ulcp-wifi` |
| ULCP: IP Connectivity | Standards | ULCP: Wi-Fi | IPv4 and IPv6 state and configuration, DNS (4896–4903) | `ulcp-ip` |
| UMSH over IP Multicast | Standards | 0008 0012 0013, ULCP: IP Connectivity | Transport, echoes, datagram format, discovery, ingress limit, channel access for nodes with a LoRa radio. ULCP: IP multicast properties and counters, virtual radios | `ip-multicast`, `ulcp-ip-multicast` |
| Chat Rooms | Standards | 0021 | Room actions, login and logout, fetching messages and users, admin commands, message distribution, room updates | `app-chat-rooms` |
| Identity Export Format | Standards | 0007 0008 0010 | Envelope, key derivation, sections, restore procedure, QR part framing | `identity-export` |
| ULCP: Frame Transport | Standards | 0011, ULCP: Core | `STR_PHY_RAW`, `CMD_STR_SEND`, `CMD_STR_RECV`, send and receive metadata, `PROP_MAC_PROMISCUOUS` | `ulcp-transport`, `ulcp-host` |
| ULCP: Tethered Host Services | Standards | 0008 0009 0017 0021, ULCP: Device Node, ULCP: Frame Transport | The tethered host identity, host keys (96–98), receive filtering, acknowledgment delegation, inbound queueing and `CMD_QUEUE_DRAIN`, receipt cues, muting, standing down, host replacement, host identity heard elsewhere, host drop statistics (4852/4853) | `ulcp-host`, `ulcp-core`, `ulcp-radio` |
| Node Management | Standards | 0005, ULCP: Core, ULCP: Device Node, ULCP: Tethered Host Services | Payload types 8/9, exchanges, multi-property requests, resets, DFU entry, at-most-once processing, cursors, authorization. ULCP: `PROP_DEV_ADMINS`, `CAP_ADMIN`, cursor and authorization status codes | `app-node-management`, `payload-format`, `ulcp-core` |
| ULCP: Node Messaging | Standards | ULCP: Device Node, ULCP: Frame Transport, Node Management | `PROP_NODE_MSG_LISTEN`, `PROP_NODE_MSG_TYPES`, `PROP_NODE_MSG_MTU`, `STR_NODE_MSG`, receiving, sending text | `ulcp-node-messaging` |
| Internet Bridging | Standards | 0013, ULCP: IP Connectivity, UMSH over IP Multicast, ULCP: Frame Transport, ULCP: Tethered Host Services | Bridge model, tunnel transport, radio attachment, integrated clients, host and LAN interfaces, relay procedure, traffic limits, acknowledgments across a bridge. ULCP: bridge client properties, `PROP_MAC_BACKHAUL` | `internet-bridging`, `ulcp-bridge`, `ulcp-host` |
| ULCP: I2C Bus Access | Standards | Node Management | `PROP_I2C_BUSES`, `PROP_I2C_DEVICES`, transfers, scans, sharing the bus, the Node Management binding | `ulcp-i2c` |
| ULCP: Battery Reporting | Standards | ULCP: Core | `PROP_BATTERY`, battery diagnostics (4944–4958) | `ulcp-device` |
| ULCP: Time and Time Zone | Standards | ULCP: Core | `PROP_TIME`, `PROP_TZ_RULE`, `PROP_TIME_24H` | `ulcp-device` |
| ULCP: GNSS | Standards | 0010, ULCP: Time and Time Zone | GNSS properties (88–93), identity updates, time trust (4868–4870) | `ulcp-device` |
| ULCP: Environmental Sensors | Standards | ULCP: Core | `PROP_ILLUMINANCE`, `PROP_TEMPERATURES`, `PROP_TEMPERATURE_NAMES` | `ulcp-device` |
| ULCP: Locate Alert | Standards | ULCP: Core | `PROP_ALERT` | `ulcp-device` |
| ULCP: Communicator Peripherals | Standards | ULCP: Core, ULCP: Tethered Host Services | Display brightness, timeout, and motion wake; keyboard light and aids; directional control; sound; setup complete | `ulcp-device` |
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
| Node Roles | 0010 |
| Capability Bits | 0010 |
| Identity Options | 0010 |
| Text Message Options | 0021 |
| Chat Room Actions | Chat Rooms |
| Contact Exchange Messages | 0024 |
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
3. Acknowledgment pacing, and how a re-acknowledgment is routed after a Route
   Retry, move from `security` into UEP-0013, which defines the
   forwarding-confirmation window pacing is measured against.
4. The `public` and `EMERGENCY` groups move into UEP-0023, after the text
   message UEPs their rules cite.
5. The flood contention window and the give-way rule move from
   `channel-access` into UEP-0013, and `T_frame` moves into UEP-0011.
6. `repeater-operation`'s statements about IP multicast groups and bridges move
   into UMSH over IP Multicast and Internet Bridging, and its remark on route
   learning into UEP-0018.
7. `ulcp-core`'s host replacement and standing-down material moves into
   ULCP: Tethered Host Services, and its Node Management material
   (`PROP_DEV_ADMINS`, `CAP_ADMIN`, the cursor and authorization status codes,
   the DFU TID rule) into Node Management. `ulcp-device`'s at-most-once note
   moves into Node Management as well.
8. `ulcp-saved-state` stops listing other subsystems' properties; each UEP
   states the state class of the properties it defines.
9. `node-identity`'s remark that an advertisement need not carry an embedded
   signature moves into UEP-0017.
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
    `mac-commands` into UEP-0018, and No-Op's Route Retry into UEP-0013.
15. The group ID and group hint derivations move from
    `packet-types` and `security` into UEP-0007, which derives the group keys
    from them.
16. `security`'s allowance for a split device and host, where the device
    passes an authenticated duplicate to the host to suppress, moves into
    ULCP: Tethered Host Services.
17. Percent-decoding a group name taken from a URI moves from
    `multicast-channels` into UEP-0020.

## Open Items

- Managed groups, whose manager admits and removes members and rotates the
  key, have no wire format. They become a draft once one is designed.
- Payload type 7 (CoAP-over-UMSH) is used by the code but not allocated, and
  only its URI form is specified. It gets a UEP once it is specified.
- `ulcp-ble` links to `node-mgmt.md`, which does not exist; the intended
  target is `app-node-management`.
