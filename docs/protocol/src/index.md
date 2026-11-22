# Index

Every UEP, published or planned, in number order. [UEP-0001](uep-0001.md)
defines the process. The number of a planned UEP is tentative until the UEP
is published.

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
| 0006 | MAC Commands | Standards | Planned | 0005 | Command encoding, requests and responses, Echo (4/5), No-Op (9) | `mac-commands` |
| 0007 | Cryptographic Processing | Standards | Planned | 0004 0005 0006 | Key agreement, HKDF inputs, AES-SIV, multicast packet keys, associated data, ack tags and Ack MIC (option 8), frame signatures (option 0), blind unicast address encryption, counter resynchronization with Verify Frame (12/13), receive procedure, implementation requirements | `security`, `packet-processing`, `security-considerations`, `packet-options`, `mac-commands` |
| 0008 | Channels | Standards | Planned | 0005 0007 | Channel keys and identifiers; named, private, and managed channels; joining; payload reuse; multicast sender authentication | `multicast-channels`, `packet-types`, `limitations` |
| 0009 | Perfect Forward Secrecy Sessions | Standards | Planned | 0006 0007 | Handshake, session key derivation, wire-level privacy, session lifetime, retired sessions, PFS Session commands (6–8) | `security`, `mac-commands` |
| 0010 | ULCP: Core | Standards | Planned | 0003 0004 | Data representation, frame format, command grammar, properties and streams, mutation atomicity, core properties (0–6), multi-get and multi-set, sessions, state classes, property allocation, attach relationships and synchronization, the security boundary, provisioning security, reboot and DFU, status and reset codes, the capability mechanism | `ulcp-core`, `ulcp` |
| 0011 | ULCP: Serial Binding | Standards | Planned | 0010 | HDLC-Lite, UART flow control (`PROP_UART_WINDOW`), waking a device on a UART | `ulcp-core` |
| 0012 | ULCP: BLE Binding | Standards | Planned | 0010 | GATT binding, segmentation and reassembly, bonding, advertising, `PROP_DEV_DISCOVERABLE` | `ulcp-ble`, `ulcp-device` |
| 0013 | ULCP: Saved State | Standards | Planned | 0010 | Saved snapshot, changes made at the device, `CMD_SAVE`, `CMD_CLEAR`, `CMD_RESTORE`, `CMD_FACTORY_RESET`, `PROP_SAVED` | `ulcp-saved-state` |
| 0014 | ULCP: Device Node | Standards | Planned | 0007 0008 0010 0013 | The device identity; `PROP_DEV_KEY`, `PROP_DEV_PRIVATE_KEY`, `PROP_DEV_NAME`, `PROP_DEV_PEERS`, `PROP_DEV_CHANNEL_KEYS` | `ulcp-device` |
| 0015 | Node Identity | Standards | Planned | 0006 0007 0014 | Identity payload, roles, capability bitmap, identity options, signatures, Identity Request (1). ULCP: `PROP_IDENT`, `PROP_IDENT_ROLE`, `PROP_IDENT_MOBILE`, `PROP_IDENT_LOCATION`, `PROP_IDENT_ALTITUDE`, `PROP_IDENT_CONTACT` | `node-identity`, `mac-commands`, `ulcp-device` |
| 0016 | UMSH over LoRa | Standards | Planned | 0005 0010 0013 | LoRa PHY parameters, sync word, MTU, `T_frame`, duty cycle. ULCP: radio properties (32–44, 4820–4822), radio statistics (4832, 4834–4837, 4850, 4851) | `ulcp-radio`, `channel-access` |
| 0017 | Channel Access | Standards | Planned | 0005 0016 | Channel sensing, backoff, ACK protection interval, immediate ACK. ULCP: `PROP_STAT_TX_CHANNEL_BUSY` | `channel-access`, `ulcp-radio` |
| 0018 | Signal Reports | Standards | Planned | 0006 0016 | Signal Report Request and Response (2/3) | `mac-commands` |
| 0019 | Flood Routing | Standards | Planned | 0006 0007 0014 0015 0017 | Routing invariants, duplicate suppression, forwarding procedure, flood hop count forwarding, flood contention window, forwarding confirmation, overheard acknowledgments, route failure recovery, Route Retry (option 6), acknowledgment pacing. ULCP: `PROP_MAC_REPEATER_MODE`, `PROP_MAC_REPEATER_STATE`, forwarding statistics (4838–4840) | `repeater-operation`, `routing-overview`, `channel-access`, `security`, `packet-options`, `packet-structure`, `ulcp-device`, `ulcp-radio` |
| 0020 | Signal-Quality Filtering | Standards | Planned | 0019 | Minimum RSSI and Minimum SNR (options 5/9). ULCP: `PROP_MAC_REPEATER_MIN_RSSI`, `PROP_MAC_REPEATER_MIN_SNR` | `packet-options`, `routing-overview`, `ulcp-device` |
| 0021 | Region Scoping | Standards | Planned | 0015 0019 | Region Code (option 11), Supported Regions (identity option 4). ULCP: `PROP_MAC_REPEATER_REGIONS`, `PROP_MAC_REPEATER_DEFAULT_REGION` | `packet-options`, `node-identity`, `routing-overview`, `ulcp-device` |
| 0022 | Amateur Radio Operation | Standards | Planned | 0005 0019 | Operating modes, locally originated packets, Operator Callsign and Station Callsign (options 4/15) | `amateur-radio`, `packet-options` |
| 0023 | Beacons and Advertisements | Standards | Planned | 0015 0019 | Beacons, advertisements, announcing on a schedule. ULCP: `PROP_ADVERT_INTERVAL`, `PROP_BEACON_INTERVAL`, `PROP_STARTUP_BEACON`, `CMD_ANNOUNCE` | `beacons`, `ulcp-device` |
| 0024 | Source Routing and Path Discovery | Standards | Planned | 0006 0019 0023 | Source Route (option 3), Trace (option 7), path discovery, route learning, scoping flood hops to a known route, the flood hop count on source-routed hops, routing acknowledgments by `FHOPS_ACC`, Peer Repeaters (10/11). ULCP: `PROP_MAC_REPEATERS_HEARD` | `beacons`, `packet-options`, `packet-structure`, `routing-overview`, `mac-commands`, `ulcp-radio` |
| 0025 | Adaptive Forwarding | Standards | Planned | 0015 0019 0024 | Forwarding where no other forwarder is heard: source-routed and flood hops, giving way, engagement, battery, states, identity | `repeater-operation` |
| 0026 | MeshCore Forwarding | Standards | Planned | 0019 0021 | Forwarding MeshCore traffic. ULCP: `PROP_MESHCORE_FORWARDING_ENABLED`, `PROP_MESHCORE_REGION_POLICY`, `PROP_MESHCORE_REGIONS`, MeshCore statistics (4841–4844) | `ulcp-device`, `ulcp-radio` |
| 0027 | ULCP: Wi-Fi | Standards | Planned | 0010 0013 | Station and access point properties (4880–4887, 4912–4915), choosing a network, sharing the radio | `ulcp-wifi` |
| 0028 | ULCP: IP Connectivity | Standards | Planned | 0027 | IPv4 and IPv6 state and configuration, DNS (4896–4903) | `ulcp-ip` |
| 0029 | UMSH over IP Multicast | Standards | Planned | 0008 0017 0019 0028 | Transport, echoes, datagram format, discovery, ingress limit, channel access for nodes with a LoRa radio. ULCP: IP multicast properties and counters, virtual radios | `ip-multicast`, `ulcp-ip-multicast` |
| 0030 | URI Formats | Standards | Planned | 0004 0008 | Node, channel, and `coap-umsh` URIs | `uri-formats` |
| 0031 | Text Messages | Standards | Planned | 0007 0008 0030 | Message type, sender handle, regarding, editing, colors, padding, message body, channel invitations, test messages | `app-text-messages` |
| 0032 | Message Sequencing and Repair | Standards | Planned | 0031 | Message sequence, ordering, gaps, automatic repair, sequence reset, channel group resend | `app-text-messages` |
| 0033 | Default Channels | Standards | Planned | 0008 0031 0032 | `public` and `EMERGENCY`. ULCP: `PROP_TEST_MESSAGE_ALERTS` | `multicast-channels`, `ulcp-device` |
| 0034 | Chat Rooms | Standards | Planned | 0031 | Room actions, login and logout, fetching messages and users, admin commands, message distribution, room updates | `app-chat-rooms` |
| 0035 | Contact Exchange | Standards | Planned | 0004 0015 0030 | Session keys, Meet payloads, code and color, exchange, nearby, transmit power, linking a name to a key, security considerations | `app-meet`, `security-considerations` |
| 0036 | Identity Export Format | Standards | Planned | 0007 0008 0015 | Envelope, key derivation, sections, restore procedure, QR part framing | `identity-export` |
| 0037 | ULCP: Frame Transport | Standards | Planned | 0010 0016 | `STR_PHY_RAW`, `CMD_STR_SEND`, `CMD_STR_RECV`, send and receive metadata, `PROP_MAC_PROMISCUOUS` | `ulcp-transport`, `ulcp-host` |
| 0038 | ULCP: Tethered Host Services | Standards | Planned | 0008 0009 0014 0023 0031 0037 | The tethered host identity, host keys (96–98), receive filtering, acknowledgment delegation, inbound queueing and `CMD_QUEUE_DRAIN`, receipt cues, muting, standing down, host replacement, host identity heard elsewhere, host drop statistics (4852/4853) | `ulcp-host`, `ulcp-core`, `ulcp-radio` |
| 0039 | Node Management | Standards | Planned | 0005 0010 0014 0038 | Payload types 8/9, exchanges, multi-property requests, resets, DFU entry, at-most-once processing, cursors, authorization. ULCP: `PROP_DEV_ADMINS`, `CAP_ADMIN`, cursor and authorization status codes | `app-node-management`, `payload-format`, `ulcp-core` |
| 0040 | ULCP: Node Messaging | Standards | Planned | 0014 0037 0039 | `PROP_NODE_MSG_LISTEN`, `PROP_NODE_MSG_TYPES`, `PROP_NODE_MSG_MTU`, `STR_NODE_MSG`, receiving, sending text | `ulcp-node-messaging` |
| 0041 | Internet Bridging | Standards | Planned | 0019 0028 0029 0037 0038 | Bridge model, tunnel transport, radio attachment, integrated clients, host and LAN interfaces, relay procedure, traffic limits, acknowledgments across a bridge. ULCP: bridge client properties, `PROP_MAC_BACKHAUL` | `internet-bridging`, `ulcp-bridge`, `ulcp-host` |
| 0042 | ULCP: I2C Bus Access | Standards | Planned | 0039 | `PROP_I2C_BUSES`, `PROP_I2C_DEVICES`, transfers, scans, sharing the bus, the Node Management binding | `ulcp-i2c` |
| 0043 | ULCP: Battery Reporting | Standards | Planned | 0010 | `PROP_BATTERY`, battery diagnostics (4944–4958) | `ulcp-device` |
| 0044 | ULCP: Time and Time Zone | Standards | Planned | 0010 | `PROP_TIME`, `PROP_TZ_RULE`, `PROP_TIME_24H` | `ulcp-device` |
| 0045 | ULCP: GNSS | Standards | Planned | 0015 0044 | GNSS properties (88–93), identity updates, time trust (4868–4870) | `ulcp-device` |
| 0046 | ULCP: Environmental Sensors | Standards | Planned | 0010 | `PROP_ILLUMINANCE`, `PROP_TEMPERATURES`, `PROP_TEMPERATURE_NAMES` | `ulcp-device` |
| 0047 | ULCP: Locate Alert | Standards | Planned | 0010 | `PROP_ALERT` | `ulcp-device` |
| 0048 | ULCP: Communicator Peripherals | Standards | Planned | 0010 0038 | Display brightness, timeout, and motion wake; keyboard light and aids; directional control; sound; setup complete | `ulcp-device` |
| 0049 | Threat Model and Design Rationale | Informational | Planned | — | What UMSH protects against and what it does not, metadata exposure, cryptographic design rationale, channel-specific considerations | `security-considerations` |
| 0050 | Repeater Profile | Profile | Planned | Listed UEPs | The UEPs a repeater implements | — |
| 0051 | ULCP: Device Profile | Profile | Planned | Listed UEPs | The minimum a device implements to be a ULCP device | `ulcp-conformance` |
| 0052 | Communicator Profile | Profile | Planned | Listed UEPs | The UEPs a standalone keyboard-and-screen node implements | — |

## Outside the Series

### Registries

Kept as data in `docs/protocol/registries/`, one file per registry, each
created by the UEP named here:

| Registry | Created by |
|---|---|
| Packet Types | 0005 |
| Packet Options | 0005 |
| Payload Types | 0005 |
| MAC Commands | 0006 |
| Node Roles | 0015 |
| Capability Bits | 0015 |
| Identity Options | 0015 |
| Text Message Options | 0031 |
| Chat Room Actions | 0034 |
| Contact Exchange Messages | 0035 |
| Identity Export Sections | 0036 |
| Node Management Options | 0039 |
| ULCP Commands | 0010 |
| ULCP Properties and Streams | 0010 |
| ULCP Capabilities | 0010 |
| ULCP Status Codes | 0010 |
| ULCP Reset Codes | 0010 |

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

## Content Moves

In the legacy text, some normative references run against the order above.
These moves resolve them:

1. The SECINFO field encoding moves from `security` into UEP-0005, so parsing a
   frame does not depend on UEP-0007.
2. MAC command encoding, Echo, and No-Op form UEP-0006, ahead of UEP-0007,
   because counter resynchronization may probe with an Echo Request.
3. Acknowledgment pacing moves from `security` into UEP-0019, which defines the
   forwarding-confirmation window it is measured against.
4. The `public` and `EMERGENCY` channels move into UEP-0033, after the text
   message UEPs their rules cite.
5. The flood contention window and the give-way rule move from
   `channel-access` into UEP-0019, and `T_frame` moves into UEP-0016.
6. `repeater-operation`'s statements about IP multicast groups and bridges move
   into UEP-0029 and UEP-0041, and its remark on route learning into UEP-0024.
7. `ulcp-core`'s host replacement and standing-down material moves into
   UEP-0038, and its Node Management material (`PROP_DEV_ADMINS`, `CAP_ADMIN`,
   the cursor and authorization status codes, the DFU TID rule) into UEP-0039.
   `ulcp-device`'s at-most-once note moves into UEP-0039 as well.
8. `ulcp-saved-state` stops listing other subsystems' properties; each UEP
   states the state class of the properties it defines.
9. `node-identity`'s remark that an advertisement need not carry an embedded
   signature moves into UEP-0023.
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

## Open Items

- Payload type 7 (CoAP-over-UMSH) is registered, but only its URI form is
  specified. It gets a UEP once it is specified.
- `ulcp-ble` links to `node-mgmt.md`, which does not exist; the intended
  target is `app-node-management`.
