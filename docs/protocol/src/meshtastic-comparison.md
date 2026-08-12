# Comparison with Meshtastic

This section compares UMSH with [Meshtastic](https://meshtastic.org/), a popular open-source LoRa mesh project. The comparison is based on the exact Meshtastic firmware tag [`v2.7.26.54e0d8d`](https://github.com/meshtastic/firmware/releases/tag/v2.7.26.54e0d8d) and its pinned [protobuf definitions](https://github.com/meshtastic/protobufs/tree/6b1ded439633cd03d4af85b44231b91d1d106278).

> [!NOTE]
> This comparison aims to be as fair and accurate as possible, not
> promotional material. If you spot any unfair comparisons, factual
> errors, or other mistakes, please [file an issue](https://github.com/darconeous/umsh/issues/new)!

Meshtastic and UMSH occupy different positions in the design space. Meshtastic is a mature, widely deployed application-focused system optimized for ease of use and broad hardware support. UMSH prioritizes authenticated communication, compact encoding, and explicit separation between its MAC and application protocols. The comparison below describes technical differences without implying that one set of tradeoffs is universally better than the other.

## Identity and Addressing

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Identity basis | 32-byte Ed25519 public key | 32-bit node number, normally initialized from the low 32 bits of a platform hardware identifier or MAC-like address; may be randomly reassigned after a detected collision |
| Cryptographic identity | Public key is the address | Curve25519 keypair generated and used for PKC where supported; not used for addressing |
| Source address in packets | Compact 3-byte hint (S=0) or 32-byte key (S=1) | 4-byte node number (cleartext) |
| Destination address | 3-byte hint | 4-byte node number or broadcast value (cleartext) |
| Channel identifier | 2-byte derived hint | 1-byte XOR of channel-name bytes and effective key bytes |
| Address spoofing resistance | Cryptographic for pairwise unicast because keys are derived from public-key addresses | None for channel traffic; PKC authenticates against a stored or verified public key, but the node number is not cryptographically bound to that key |

UMSH identifies nodes by their Ed25519 public keys, which serve as both the address and the cryptographic credential. Possession of the corresponding private key is required to authenticate and decrypt pairwise traffic. Meshtastic's normal initial node number comes from a platform hardware identifier, but this is not universally a Bluetooth MAC and collision handling can assign a random replacement. The node number itself is not cryptographically bound to a key.

On supported, non-amateur builds, Meshtastic normally generates a Curve25519 keypair and uses PKC automatically for eligible unicast traffic when the peer key is known. A learned public key is associated with a node number and later mismatches are rejected; users can also verify keys explicitly. This provides conditional sender authentication for PKC traffic, but it remains a stored or verified association rather than an address derived from the key. Channel-encrypted traffic has no per-node authentication regardless of whether PKC keys are configured.

## Packet Structure

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Header | 1-byte FCF with version, type, flags | 16-byte fixed header (always cleartext) |
| Payload encoding | Raw bytes with 1-byte payload type prefix | Protobuf-encoded `Data` message |
| Packet types | 8 (via 3-bit field in FCF) | Implicit in protobuf `portnum` field (30+ registered values) |
| Routing info | CoAP-style composable options | Fixed fields: hop limit (3-bit), next hop (1 byte), relay node (1 byte) |
| Flood hop count | Split 4-bit FHOPS field (max 15) | Mandatory 3-bit field (encoded maximum 7) |
| Max LoRa payload | Approximately 255 bytes | 255-byte frame; the `Data.payload` schema permits 233 bytes, but usable application capacity depends on the encoded `Data` fields and security mode |
| Common unicast overhead relative to application body | 17 bytes with compact source and 4-byte MIC, or 29 bytes with 16-byte MIC; excludes salt, FHOPS, and options | Approximately 22–23 bytes for channel encryption or 34–35 bytes for PKC, depending on protobuf length encoding |

Before counting UMSH's 1-byte payload-type prefix, FHOPS, or packet options, the fixed fields of a compact-source secured unicast occupy 16–30 bytes depending on MIC length and salt presence. A full 32-byte source raises that range to 45–59 bytes. The common-case row above adds the payload-type prefix and selects no salt with either a 4-byte or 16-byte MIC.

UMSH uses a compact 1-byte Frame Control Field with optional expansion: fields are present only when needed for the packet type. Meshtastic uses a fixed 16-byte header on every packet, with source and destination node numbers, packet ID, flags, channel hash, and routing fields always present.

Meshtastic's header is always transmitted in cleartext, exposing sender node number, destination field, packet ID, and channel hash to any passive observer. For unicast, the destination field identifies the recipient; for broadcast, it contains the broadcast value rather than an individual recipient. UMSH's addressing fields are compact hints that do not directly reveal a complete node identity, and blind unicast and encrypted multicast conceal their address fields as defined below.

Meshtastic encodes application payloads in the schema-based, extensible protobuf `Data` envelope. UMSH uses raw byte payloads with a 1-byte type prefix, minimizing encoding overhead while leaving structure to the selected application protocol.

## Cryptography

| Aspect | UMSH | Meshtastic (channel) | Meshtastic (eligible unicast PKC) |
|---|---|---|---|
| Encryption | AES-256-CTR (AES-SIV, RFC 5297) | AES-128-CTR or AES-256-CTR, selected by effective PSK length; the default effective key is 16 bytes | AES-CCM |
| Authentication | S2V (AES-CMAC), 4/8/12/16-byte MIC | **None** | 8-byte CCM authentication tag |
| Key exchange | X25519 ECDH | Pre-shared key | Curve25519 ECDH |
| Key derivation | HKDF-SHA256 with domain separation | Effective PSK used directly | SHA-256 of ECDH shared secret |
| Nonce construction | Frame counter + optional salt in SECINFO | Packet ID + sender node number | Packet ID + 4-byte random contribution + sender node number |
| Duplicate/replay handling | 4-byte monotonic frame counter with replay window | Partially randomized 32-bit packet ID and finite duplicate cache | Same packet-ID duplicate cache as channel traffic |
| Forward secrecy | [Optional PFS sessions](security.md#perfect-forward-secrecy-sessions) | No | No |

### Channel Encryption

The most significant cryptographic difference is that Meshtastic's channel-encrypted packets have **no authentication**. AES-CTR provides confidentiality but no integrity protection. This means:

- Ciphertext can be modified in transit without a cryptographic integrity check. When an attacker knows or can predict the corresponding plaintext, CTR bit flipping can be targeted without knowing the key.
- Any node with the channel key can forge packets claiming to be from another node, since channel mode has no per-node authentication and the sender's node number in the cleartext header is not cryptographically bound to the ciphertext.

UMSH authenticates every secured packet with an S2V MIC (4–16 bytes; see [MIC Size Selection Guidance](security.md#mic-size-selection-guidance)). Even with a 4-byte MIC, UMSH provides 2^-32 forgery resistance, which is qualitatively different from the absence of an integrity check on Meshtastic channel traffic. A UMSH channel packet cannot be modified in transit or injected by a non-member without detection.

The second bullet above, however, describes a property UMSH multicast shares, and it is not a difference between the two protocols. A shared symmetric key proves channel membership but cannot distinguish one member from another, so a UMSH channel member can likewise claim another member's source address; see [Multicast Sender Authentication](limitations.md#multicast-sender-authentication). What UMSH provides on channel traffic is integrity and membership authentication against outsiders, not per-sender attribution within the channel. Attribution to a specific sender requires unicast, where pairwise keys bind the source.

### PKC for Eligible Unicast Traffic

Meshtastic uses Curve25519 ECDH with AES-CCM for eligible unicast traffic, providing confidentiality and authentication against the public key associated with the claimed sender node number. It is not limited to text direct messages. The firmware considers PKC automatically for locally originated, non-broadcast application traffic when keys are available, except for position, node info, routing, traceroute, amateur operation, and certain serial/GPIO cases. Broadcast traffic such as position, telemetry, and channel text remains in channel mode and therefore unauthenticated.

UMSH applies the same S2V-based construction to secured unicast and multicast, so there is no secured traffic class left unauthenticated and no separate authenticated mode to opt into. [Broadcast packets](packet-types.md#broadcast-packet) carry no security information and make no claim of authenticity.

### Key Derivation

Meshtastic uses the effective channel PSK directly as the AES key for channel encryption. A configured one-byte PSK is not a one-byte AES key: it is a public shorthand alias expanded by the firmware into an effective 16-byte key. For PKC, the ECDH shared secret is hashed with SHA-256 to produce the AES key.

UMSH uses HKDF-SHA256 with domain-separated labels to derive independent encryption and authentication keys from each shared secret. This prevents cross-purpose key reuse and follows standard cryptographic practice.

## Routing

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Flood routing | Yes, bounded by flood hop count | Yes (managed flood with SNR-based priority) |
| Source routing | Yes, via source-route option | No |
| Source route followed by flood tail | Yes, both can be carried in the same packet | No; learned next-hop delivery can fall back to flooding, but there is no source-route field |
| Next-hop routing | N/A | Yes (learned from ACK paths, v2.6+) |
| Hop budget | 15 flood hops plus source-routed hops | 3-bit encoded budget (max 7); selected favorite-router infrastructure hops may preserve the budget |
| Duplicate detection | MIC cache | Finite cache keyed by sender and partially randomized 32-bit packet ID |
| Forwarding confirmation | Hop-by-hop retries with backoff for source-routed hops; retries at a flood origin | Reliable (`want_ack`) origin: initial transmission plus at most two retransmissions; directed intermediate: initial transmission plus at most one retransmission; intermediate flood relays do not retry |
| Channel access | CAD with random backoff; SNR-based contention windows | CAD with random backoff; channel-utilization-based local contention and SNR-based flood contention |
| Signal-quality controls | Min RSSI and min SNR eligibility options | Lower-SNR/farther flood candidates tend to transmit earlier; infrastructure roles also affect priority |
| Region-scoped flooding | Region code option | Not defined |
| Traceroute | Trace-route option on any packet | Dedicated `TRACEROUTE_APP` port |

Both protocols use flood-based routing as their primary discovery and fallback mechanism. Meshtastic's managed flood gives lower-SNR receptions smaller contention windows, treating apparent distance from the sender as a heuristic for useful forwarding progress. `ROUTER` nodes receive a separate early-transmission advantage. Most roles cancel a queued rebroadcast after overhearing a duplicate, while infrastructure roles such as `ROUTER` may intentionally transmit anyway. UMSH instead provides explicit signal-quality thresholds that allow the sender to control flood-relay eligibility per packet.

Meshtastic's 3-bit field encodes a maximum hop budget of 7, but this is not an unconditional cap on the physical number of relays. After the first hop, selected transitions between configured `ROUTER`, `ROUTER_LATE`, or `CLIENT_BASE` infrastructure nodes can preserve the budget when the previous relay is a favorite. UMSH's 4-bit flood hop count permits up to 15 flood hops, while source-routed hops consume packet space rather than flood budget.

Meshtastic v2.6+ added next-hop routing for unicast: after a successful ACK exchange, the firmware learns which relay carried the response and uses that relay as the designated next hop for subsequent packets. UMSH achieves directed delivery through source-route options learned via trace routes. The recipient can cache the accumulated trace directly as a source route for subsequent communication with the sender because the trace is already built most-recent hop first; see [Route Learning](beacons.md#route-learning).

Both protocols perform channel activity detection and randomized contention. Meshtastic sizes normal local-send contention from recent channel utilization and uses received SNR for flood-rebroadcast contention. UMSH uses CAD with random backoff and SNR-based contention windows as defined by its channel-access rules.

Both protocols provide forwarding confirmation, but the scopes differ. For a Meshtastic `want_ack` transmission, the origin makes at most three total attempts: the initial transmission and two retransmissions. When a learned next hop is in use, the final origin attempt falls back to flooding. A directed intermediate relay also listens for its designated next hop and may retransmit once; intermediate flood relays do not retry because no single next hop is designated. UMSH applies passive forwarding confirmation and retry to each source-routed hop and to a flood origin, while intermediate flood relays likewise do not retry.

## Privacy

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Header confidentiality | Addressing fields are compact hints; blind modes encrypt source/destination | Header always cleartext: sender, destination field, packet ID, and channel hash exposed |
| Source concealment | Encrypted multicast, blind unicast | Not supported |
| Destination concealment | Blind unicast | Not supported |
| Node ID linkability | Public key; ephemeral keys are supported | Normally persistent hardware-derived node number, with possible random collision reassignment |
| Anonymous first contact | Ephemeral Ed25519 key with S=1 flag | Not supported |

Meshtastic's 16-byte cleartext header exposes the complete sender node number and destination field on every packet. A unicast packet therefore exposes both node numbers; a broadcast exposes the sender and the broadcast destination value. A passive observer can still correlate sender node numbers, build traffic graphs, and track a normally persistent identifier over time without the channel key.

UMSH's compact hints reveal less information directly, and blind unicast and encrypted multicast modes conceal their defined source and/or destination fields. Nodes can also use ephemeral keypairs for anonymous communication.

## Multicast and Group Communication

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Channel key size | 32 bytes | Configured as 0, 1-byte public alias, 16, or 32 bytes; effective AES key is 0, 16, or 32 bytes |
| Channel identifier | 2-byte derived hint | 1-byte XOR of channel-name bytes and effective key bytes |
| Channels per node | Unlimited (implementation-defined) | Up to 8 |
| Multi-hop multicast | Yes (flood with flood hop count) | Yes (managed flood with hop limit) |
| Group message auth | Channel-key-based S2V MIC | None (AES-CTR only) |
| Source privacy | Source encrypted when encryption enabled | No (source in cleartext header) |
| Named channels | Yes (key derived from name) | Yes (name + PSK configured together) |

Both protocols support multiple channels with independent keys. Meshtastic limits a node to 8 configured channels. Under an independent uniform-candidate model, a specific unrelated channel has a 1-in-256 chance of matching Meshtastic's 1-byte hint and a 1-in-65536 chance of matching UMSH's 2-byte identifier. With `m` independent configured candidates, the probability of at least one match is `1-(255/256)^m` for Meshtastic and `1-(65535/65536)^m` for UMSH. Meshtastic's XOR construction is not a cryptographic hash, so these are modeling assumptions rather than exact operational rates. A matching Meshtastic hint causes the receiver to try the corresponding channel key and validate the resulting protobuf.

## Application Layer

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Payload typing | 1-byte payload type prefix | Protobuf `portnum` field (30+ registered values) |
| Payload encoding | Raw bytes | Protocol Buffers or port-specific binary/text formats |
| Structured data | CoAP-over-UMSH (block-wise transfer) | Protobuf with defined message schemas |
| Text messaging | UMSH text message payload | `TEXT_MESSAGE_APP` (portnum 1) |
| Position/telemetry | Not defined (delegated to higher-layer protocols) | Built-in `POSITION_APP`, `TELEMETRY_APP` |
| Node identity | Identity payload with role, capabilities, name | `NODEINFO_APP` with `User` protobuf |
| Remote administration | Node management MAC commands | `ADMIN_APP` (portnum 6) |
| Audio | Not defined | `AUDIO_APP` (codec2, 2.4 GHz only) |
| Store and forward | Not defined | `STORE_FORWARD_APP`; Store-and-Forward++ schema for native Linux nodes |
| Other registered integrations | Higher-layer protocols can be assigned payload types | TAK/ATAK (including V2), Reticulum, LoRaWAN bridge, Cayenne, and remote-shell wire schema, among others |
| Amateur radio | Operator/station callsign options, explicit unencrypted mode | `is_licensed` state plus dedicated ham-mode command; callsign in long name, automatic PSK/admin removal, and licensed relay restrictions |
| Implementation | Protocol spec (language-agnostic) | C++ firmware + protobuf definitions and companion applications |

Meshtastic defines a rich application ecosystem with built-in firmware support, companion-side integrations, and registered wire schemas for position sharing, telemetry, waypoints, audio, store-and-forward, TAK, Reticulum, remote shell, and other uses. Registration of a `PortNum` and schema does not imply that every firmware build contains a native handler for that application.

UMSH defines a smaller set of application protocols (text messaging, chat rooms, node identity, node management) and delegates richer application functionality to higher-layer protocols carried in the payload, such as CoAP. This is less feature-complete out of the box but allows UMSH to carry arbitrary higher-layer content without changing the MAC protocol.

Both protocols address amateur radio operation, but at different levels. Meshtastic's dedicated ham-mode command sets the callsign as the node's long name, sets the short name and radio overrides, raises the NodeInfo cadence required for identification, changes rebroadcasting to local-only, and automatically removes channel PSKs and admin access. Setting the raw `is_licensed` owner flag also clears encryption automatically, but the operator must separately ensure the callsign fields are populated. Licensed nodes refuse to relay packets to or from nodes known to be unlicensed. The callsign is carried in the existing user-info field rather than a dedicated per-packet protocol field.

UMSH defines dedicated packet options for operator and station callsigns, and its security-control field explicitly indicates whether encryption is enabled. In licensed-only mode, monitoring software can verify the presence of the required callsign option and the absence of encryption directly from the packet. Both protocols still require the operator to select and configure the lawful operating mode.

## Layer Separation

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Protocol organization | MAC layer with separately specified application protocols | Shared firmware and protobuf registry spanning radio integration, routing control, and applications |
| Forwarding-time payload interpretation | Opaque at the MAC layer | Clear raw header is sufficient for forwarding; encrypted `Data` may remain opaque to a relay |
| Fragmentation | Delegated to higher-layer protocols | No generic mesh-layer fragmentation; individual applications or transports may define their own |
| Application registration | Application protocols are architecturally separate | 30+ application identifiers registered in the core `PortNum` schema |

UMSH specifies an explicit boundary between its MAC layer and application protocols: the MAC treats payloads opaquely and can carry any assigned higher-layer protocol. Meshtastic likewise has a concrete wire boundary between its 16-byte raw forwarding header and the encrypted protobuf `Data` envelope, so a relay can forward traffic it cannot decrypt. Its `Data` schema also contains port, payload, response-correlation, and some routing-related fields, and its application identifiers live in the shared core protobuf registry. The result is greater integration between routing, firmware modules, and application dispatch than in UMSH, but not an absence of all layer boundaries.

Neither protocol defines generic fragmentation at the mesh/MAC layer. UMSH explicitly delegates it to higher-layer protocols such as CoAP block-wise transfer. Meshtastic applications and companion transports can define their own mechanisms; for example, the Reticulum tunnel port is specified to carry fragmented RNS packets.

## Timestamps and Time Dependency

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Replay/duplicate handling | 4-byte monotonic frame counter with replay window | Partially randomized 32-bit packet ID and finite duplicate cache |
| Timestamps in packets | None at MAC layer | `rx_time` metadata (not transmitted in the LoRa header and not used for routing decisions) |
| Clock synchronization required | No | No |

Neither protocol requires clock synchronization for core operation. Meshtastic records reception timestamps as local metadata but does not use them for routing or duplicate suppression. UMSH provides replay protection with monotonic frame counters and a receive window. Meshtastic suppresses recent duplicates by caching the sender and partially randomized packet ID; because that cache is finite, this should not be described as durable cryptographic replay protection.

## Packet Overhead Comparison

The following compares overhead relative to the application body for a common secured unicast message. The UMSH columns use a compact source, no salt, no FHOPS, and no packet options. The Meshtastic columns assume a common one-byte `portnum` value and the locally originated `Data.bitfield`; the protobuf envelope is 6 bytes while the application body is shorter than 128 bytes and normally 7 bytes once its length requires a two-byte varint.

| Field | UMSH (S=0, 16B MIC) | UMSH (S=0, 4B MIC) | Meshtastic (channel) | Meshtastic (PKC) |
|---|---:|---:|---:|---:|
| Header/FCF | 1 | 1 | 16 | 16 |
| Destination | 3 | 3 | (in header) | (in header) |
| Source | 3 | 3 | (in header) | (in header) |
| SECINFO | 5 | 5 | — | — |
| Payload-type prefix | 1 | 1 | — | — |
| MIC | 16 | 4 | — | — |
| Protobuf `Data` envelope | — | — | 6–7 | 6–7 |
| PKC tag + random nonce contribution | — | — | — | 12 |
| **Total overhead** | **29** | **17** | **22–23** | **34–35** |

Meshtastic channel mode derives its AES-CTR nonce from the cleartext packet ID and sender node number and transmits no separate channel nonce. PKC uses those header fields plus a transmitted 4-byte random contribution and carries an 8-byte CCM tag, adding exactly 12 bytes beyond an otherwise equivalent channel `Data` envelope.

UMSH with a 16-byte MIC has 29 bytes of application-body-to-wire overhead under the stated conditions, compared with approximately 22–23 bytes for Meshtastic channel mode. UMSH's total includes authentication that Meshtastic channel mode lacks. With a 4-byte MIC, UMSH uses 17 bytes under the same conditions while still providing a truncated authentication tag.

The Meshtastic `Data.payload` field is sized for as many as 233 bytes, but that schema capacity is not a universal application-body limit. For a common locally originated text packet, the encoded port, payload length, and required bitfield make about 232 bytes fit in channel mode; the additional 12 PKC bytes reduce the analogous PKC capacity to about 220 bytes. Other `Data` fields or larger `portnum` encodings reduce it further.

## Power Consumption

Power consumption on a battery-constrained LoRa node is influenced by radio airtime, receive duty cycle, retransmission behavior, and CPU work after a packet is received. The protocol and firmware establish which operations occur, but their practical energy magnitude requires measurement on representative hardware.

### Channel Filtering and False Positives

For channel traffic, a compact channel identifier is a pre-crypto filter. If an unrelated incoming channel produces the same identifier as one configured locally, the receiver must try the local candidate key to determine whether the packet is valid.

| Protocol | Channel identifier width | Uniform per-candidate match probability |
|---|---:|---:|
| Meshtastic | 8 bits (XOR of channel name and effective key) | 1 in 256 |
| UMSH | 16 bits (derived hint) | 1 in 65536 |

Under independent uniform assumptions, the per-candidate probability differs by a factor of 256. With `m` configured candidates, the probability of at least one match is `1-(255/256)^m` for Meshtastic and `1-(65535/65536)^m` for UMSH. Meshtastic's XOR construction is not a uniform cryptographic hash in every real configuration, so these figures are a model rather than measured traffic rates.

The Meshtastic receive loop confirms the mechanism: every configured channel whose hint matches triggers an AES-CTR decryption and protobuf parse attempt until one succeeds or the candidates are exhausted. This is additional CPU work, but no measurement cited here establishes a meaningful battery-life impact, and the AES cost may be small compared with LoRa receive airtime.

### Unicast Filtering

For unicast packets, Meshtastic's 4-byte cleartext node number provides an exact destination comparison before payload decryption. UMSH's 3-byte destination hint has a modeled 1-in-16,777,216 per-identity false-positive probability. A collision requires cryptographic processing to determine whether the packet is actually addressed to the receiver; pairwise keys can be cached after first contact, so known-sender handling does not require a fresh ECDH operation.

This is a protocol tradeoff: Meshtastic spends one additional cleartext destination byte and exposes the complete unicast node number, while UMSH uses a shorter, less identifying prefilter with a small collision probability. The practical power significance of that difference depends on traffic and hardware and is not asserted here.

### Packet Length and Airtime

Meshtastic's fixed 16-byte header is transmitted on every packet. UMSH includes only fields required by the packet type. Longer LoRa packets consume more airtime and receiver-on time, but the total comparison depends on UMSH's selected MIC, optional fields, and source form as well as on Meshtastic's security mode and protobuf envelope.

### Forwarding Power

Both protocols use flooding, so forwarding nodes may receive and retransmit packets. Transmit is normally among the most power-intensive radio operations. Meshtastic defaults to the `CLIENT` role with rebroadcast mode `ALL`, so ordinary client nodes participate in managed rebroadcasting. A node that should not forward must use `CLIENT_MUTE`, rebroadcast mode `NONE`, or another appropriately restrictive configuration. The old `REPEATER` role is deprecated; current infrastructure configurations include roles such as `ROUTER`, `ROUTER_LATE`, and `CLIENT_BASE`.

Meshtastic's managed flood gives lower-SNR receptions shorter expected delays, allowing nodes that appear farther from the sender to relay earlier. Most client-like roles cancel a queued transmission after overhearing a duplicate. `ROUTER` nodes receive separate early priority and intentionally do not cancel every duplicate. These policies reduce or redirect redundant transmissions compared with an unsuppressed flood, but the effect depends on topology and role configuration.

UMSH's minimum-RSSI and minimum-SNR options allow the original sender to set explicit flood-forwarding thresholds. A repeater below the threshold does not retransmit the packet. Meshtastic's approach chooses contention priority automatically; UMSH's approach makes relay eligibility explicit but requires the sender to choose suitable thresholds.

UMSH repeaters do not need to decrypt or verify the application payload before forwarding because the MAC layer treats it opaquely. Meshtastic forwarding likewise uses the clear raw header and can relay both channel and PKC ciphertext without decrypting the protobuf `Data` body.

## Summary of Design Differences

Meshtastic is a full-featured mesh communication system with a large and active user community. It provides a rich application ecosystem, broad hardware support, and an easy on-ramp for non-technical users. Its channel-based encryption model is simple to configure and deploy, while eligible unicast traffic can use PKC when peer keys are available.

UMSH prioritizes authenticated secured traffic, compact encoding, metadata-concealment modes, and explicit MAC/application boundaries. Secured unicast and multicast packets carry authentication; unsecured broadcast packets intentionally make no authenticity claim.

Key tradeoffs:

- **Authentication**: UMSH authenticates every secured unicast and multicast packet. Meshtastic channel traffic has no integrity check; eligible PKC unicast traffic is authenticated against the stored or verified peer key.
- **Privacy**: UMSH provides compact addressing hints and opt-in blind modes. Meshtastic exposes the complete sender and destination fields in every cleartext header; unicast therefore exposes both endpoint node numbers, while broadcast uses the broadcast destination value.
- **Identity model**: UMSH uses cryptographic public keys as addresses. Meshtastic uses a normally hardware-derived node number that is not cryptographically bound to its PKC key.
- **Overhead**: Under the conditions in the overhead table, UMSH uses 17 bytes with a 4-byte MIC or 29 with a 16-byte MIC; Meshtastic uses approximately 22–23 bytes for channel mode or 34–35 for PKC. UMSH's totals include authentication, while Meshtastic channel mode does not.
- **Application richness**: Meshtastic provides a much richer built-in and companion application ecosystem. UMSH delegates richer functionality to higher-layer protocols.
- **Protocol organization**: UMSH specifies MAC and application protocols separately. Meshtastic has a distinct raw forwarding header and encrypted application envelope, while application registration, routing control, and firmware modules share a common protobuf and firmware ecosystem.
- **Implementation**: Meshtastic is a mature C++ firmware with broad device support. UMSH is not tied to an implementation language or runtime, and its compact wire design can target bare-metal microcontrollers.
- **Ease of deployment**: Meshtastic is designed for immediate use with consumer hardware. UMSH requires implementation effort and explicit key configuration.
