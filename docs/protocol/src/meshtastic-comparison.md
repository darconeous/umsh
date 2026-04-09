# Comparison with Meshtastic

This section compares UMSH with [Meshtastic](https://meshtastic.org/), a popular open-source LoRa mesh project. The comparison is based on Meshtastic firmware v2.5+ and its [documentation](https://meshtastic.org/docs/) and [protobuf definitions](https://buf.build/meshtastic/protobufs).

Meshtastic and UMSH occupy different positions in the design space. Meshtastic is a mature, widely deployed application-focused system optimized for ease of use and broad hardware support. UMSH prioritizes cryptographic rigor, compact encoding, and clean layer separation. The comparison below highlights the technical differences without implying that one set of tradeoffs is universally better than the other.

## Identity and Addressing

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Identity basis | 32-byte Ed25519 public key | 32-bit node number derived from Bluetooth MAC address |
| Cryptographic identity | Public key is the address | Optional Curve25519 keypair (PKC, v2.5+), not used for addressing |
| Source address in packets | compact 3-byte hint (S=0) or 32-byte key (S=1) | 4-byte node number (cleartext) |
| Destination address | 3-byte hint | 4-byte node number (cleartext) |
| Channel identifier | 2-byte derived hint | 1-byte DJB2 hash of channel name |
| Address spoofing resistance | Cryptographic — pairwise keys are derived from public keys | None — node numbers are hardware-derived and trivially spoofable |

UMSH identifies nodes by their Ed25519 public keys, which serve as both the address and the cryptographic credential. A node's identity is inseparable from its ability to authenticate and decrypt. Meshtastic identifies nodes by a 32-bit number derived from the device's Bluetooth MAC address. This number is not cryptographically bound to any key — any device can claim any node number.

Meshtastic added optional Curve25519 keypairs in v2.5 for direct message encryption, but these are not used for addressing. The node number remains the primary identifier, and channel-encrypted traffic has no per-node authentication regardless of whether PKC keys are configured.

## Packet Structure

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Header | 1-byte FCF with version, type, flags | 16-byte fixed header (always cleartext) |
| Payload encoding | Raw bytes with 1-byte payload type prefix | Protobuf-encoded `Data` message |
| Packet types | 8 (via 3-bit field in FCF) | Implicit in protobuf `portnum` field (~30+ application types) |
| Routing info | CoAP-style composable options | Fixed fields: hop limit (3-bit), next hop (1 byte), relay node (1 byte) |
| Flood hop count | Split 4-bit FHOPS field (max 15) | Mandatory 3-bit field (max 7 hops) |
| Max LoRa payload | ~255 bytes | 255 bytes (233 bytes application payload after header and encoding overhead) |
| Minimum header overhead | 1 byte (broadcast, no options) | 16 bytes (always) |

UMSH uses a compact 1-byte Frame Control Field with optional expansion — the header scales from 1 byte (minimal broadcast) to the full addressing and security fields as needed. Meshtastic uses a fixed 16-byte header on every packet, with source and destination node numbers, packet ID, flags, channel hash, and routing fields always present.

Meshtastic's header is always transmitted in cleartext, exposing sender and recipient node numbers, packet IDs, and channel hashes to any passive observer. UMSH's addressing fields are compact hints that do not directly reveal node identity, and in blind unicast or encrypted multicast modes, the source address is encrypted.

Meshtastic encodes application payloads using Protocol Buffers (protobuf), which adds encoding overhead but provides a flexible, self-describing serialization format. UMSH uses raw byte payloads with a 1-byte type prefix, minimizing encoding overhead at the cost of less built-in structure.

## Cryptography

| Aspect | UMSH | Meshtastic (channel) | Meshtastic (PKC DM) |
|---|---|---|---|
| Encryption | AES-128-CTR (SIV-style) | AES-256-CTR | AES-CCM |
| Authentication | AES-CMAC (4/8/12/16-byte MIC) | **None** | CCM auth tag |
| Key exchange | X25519 ECDH | Pre-shared key | Curve25519 ECDH |
| Key derivation | HKDF-SHA256 with domain separation | PSK used directly | SHA-256 of ECDH shared secret |
| Nonce construction | Frame counter + optional salt in SECINFO | Packet ID + sender node number | 8-byte random nonce |
| Replay protection | 4-byte monotonic frame counter | 32-bit random packet ID (duplicate cache) | Not defined |
| Forward secrecy | [Optional PFS sessions](security.md#perfect-forward-secrecy-sessions) | No | No |

### Channel Encryption

The most significant cryptographic difference is that Meshtastic's channel-encrypted packets have **no authentication**. AES-CTR provides confidentiality but no integrity protection. This means:

- An attacker who knows the channel key can modify ciphertext in transit (CTR mode bit-flipping), and the recipient has no way to detect the tampering.
- Any node with the channel key can forge packets claiming to be from any other node, since there is no per-node authentication and the sender's node number in the cleartext header is not cryptographically bound to anything.

UMSH authenticates every secured packet with an AES-CMAC MIC (4–16 bytes, see [MIC Size Selection Guidance](security.md#mic-size-selection-guidance)). Even with a 4-byte MIC, UMSH provides 2^-32 forgery resistance — qualitatively different from Meshtastic's complete absence of authentication on channel traffic.

### PKC Direct Messages

Meshtastic v2.5+ added Curve25519 ECDH with AES-CCM for direct messages, providing both confidentiality and authentication. This is a substantial improvement over channel-only encryption, but applies only to direct messages — all broadcast traffic (position, telemetry, channel text) remains unauthenticated.

UMSH authenticates all traffic uniformly — unicast, multicast, and broadcast — using the same CMAC-based construction. There is no distinction between "authenticated" and "unauthenticated" packet classes.

### Key Derivation

Meshtastic uses the channel PSK directly as the AES key for channel encryption, with no key derivation step. For PKC, the ECDH shared secret is hashed with SHA-256 to produce the AES key.

UMSH uses HKDF-SHA256 with domain-separated labels to derive independent encryption and authentication keys from each shared secret. This prevents cross-purpose key reuse and is the standard practice recommended by cryptographic literature.

## Routing

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Flood routing | Yes, bounded by flood hop count | Yes (managed flood with SNR-based priority) |
| Source routing | Yes, via source-route option | No |
| Hybrid routing | Source route + flood hop count in same packet | No |
| Next-hop routing | N/A | Yes (learned from ACK paths, v2.6+) |
| Max hops | 15 flood + "many" source-routed | 7 (3-bit hop limit) |
| Duplicate detection | MIC cache | Packet ID cache (32-bit random IDs) |
| Forwarding confirmation | Yes (hop-by-hop retries with backoff when source routing) | Implicit ACK for broadcasts (sender listens for neighbor rebroadcast, up to 3 retries); not hop-by-hop |
| Channel access | CAD with random backoff; SNR-based contention windows | SNR-based contention windows |
| Signal-quality filtering | Min RSSI and min SNR options | SNR-based rebroadcast priority (implicit) |
| Region-scoped flooding | Region code option | Not defined |
| Traceroute | Trace-route option on any packet | Dedicated TRACEROUTE_APP port |

Both protocols use flood-based routing as their primary delivery mechanism. Meshtastic's managed flood uses SNR-based contention windows to prioritize better-positioned relays, which is an effective heuristic for reducing redundant rebroadcasts. UMSH provides explicit signal-quality thresholds (minimum RSSI and SNR options) that allow the sender to control relay eligibility per packet.

Meshtastic's 3-bit hop limit caps multi-hop delivery at 7 hops. UMSH's 4-bit flood hop count allows up to 15 flood hops, and source routing allows packets to traverse specific paths without flooding (with no hop limit).

Meshtastic v2.6+ added next-hop routing for direct messages: after a successful ACK exchange, the firmware learns which relay carried the response and uses it as a designated next hop for subsequent packets. UMSH achieves similar directed delivery through source-route options learned via trace routes — the recipient caches the accumulated trace directly as a source route for all subsequent communication with the sender, because the trace is already built most-recent hop first (see [Route Learning](beacons.md#route-learning)).

Both protocols define channel access mechanisms. Meshtastic uses SNR-based contention windows to prioritize better-positioned relays. UMSH uses CAD (Channel Activity Detection) with random backoff and SNR-based contention windows for collision avoidance.

Both protocols provide forwarding confirmation, but with different scope. Meshtastic's sender listens for any neighbor to rebroadcast a flooded packet; if no rebroadcast is overheard, the sender retransmits up to 3 times (with the final retry falling back to flooding if next-hop routing was in use). This provides 0-hop reliability — the originator can confirm that at least one neighbor forwarded the packet — but intermediate relays do not confirm onward delivery. UMSH defines hop-by-hop forwarding confirmation: each forwarding node (whether source-route hop or flood originator) listens for retransmission by the next hop and retries with backoff if none is heard, providing reliability across the full forwarding chain.

## Privacy

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Header confidentiality | Addressing fields are compact hints; blind modes encrypt source/destination | Header always cleartext — sender, recipient, packet ID, channel hash exposed |
| Source concealment | Encrypted multicast, blind unicast | Not supported |
| Destination concealment | Blind unicast | Not supported |
| Node ID linkability | Public key (can use ephemeral keys) | Hardware MAC-derived (persistent identifier) |
| Anonymous first contact | Ephemeral Ed25519 key with S=1 flag | Not supported |

Meshtastic's 16-byte cleartext header exposes the full sender and recipient node numbers on every packet. A passive observer with a LoRa receiver can identify who is communicating with whom, build traffic graphs, and track individual devices over time — even without the channel key. Node numbers are derived from hardware MAC addresses, making them persistent identifiers tied to physical devices.

UMSH's compact hints reveal far less information to passive observers, and blind unicast and encrypted multicast modes encrypt the source and/or destination entirely. Nodes can also use ephemeral keypairs for anonymous communication.

## Multicast and Group Communication

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Channel key size | 32 bytes | 1, 16, or 32 bytes (PSK) |
| Channel identifier | 2-byte derived hint | 1-byte DJB2 hash of channel name |
| Channels per node | Unlimited (implementation-defined) | Up to 8 |
| Multi-hop multicast | Yes (flood with flood hop count) | Yes (managed flood with hop limit) |
| Group message auth | Channel-key-based CMAC | None (AES-CTR only) |
| Source privacy | Source encrypted when encryption enabled | No (source in cleartext header) |
| Named channels | Yes (key derived from name) | Yes (name + PSK configured together) |

Both protocols support multiple channels with independent keys. Meshtastic limits nodes to 8 simultaneous channels. Meshtastic's 1-byte channel hash has a high collision probability (1 in 256), requiring trial decryption when collisions occur. UMSH's 2-byte channel identifier reduces this to 1 in 65536.

## Application Layer

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Payload typing | 1-byte payload type prefix | Protobuf `portnum` field (~30+ types) |
| Payload encoding | Raw bytes | Protocol Buffers |
| Structured data | CoAP-over-UMSH (block-wise transfer) | Protobuf with defined message schemas |
| Text messaging | UMSH text message payload | TEXT_MESSAGE_APP (portnum 1) |
| Position/telemetry | Not defined (delegated to higher-layer protocols) | Built-in POSITION_APP, TELEMETRY_APP |
| Node identity | Identity payload with role, capabilities, name | NODEINFO_APP with User protobuf |
| Remote administration | Node management MAC commands | ADMIN_APP (portnum 6) |
| Audio | Not defined | AUDIO_APP (codec2, 2.4 GHz only) |
| Store and forward | Not defined | STORE_FORWARD_APP |
| Amateur radio | Operator/station callsign options, explicit unencrypted mode | Not defined |
| Implementation | Protocol spec (language-agnostic) | C++ firmware + protobuf definitions |

Meshtastic defines a rich application layer with built-in support for position sharing, telemetry, waypoints, audio, store-and-forward, and TAK integration. These are tightly integrated into the firmware and protobuf schema.

UMSH defines a smaller set of application protocols (text messaging, chat rooms, node identity, node management) and delegates richer application functionality to higher-layer protocols carried in the payload, such as CoAP. This approach is less feature-complete out of the box but allows UMSH to carry arbitrary higher-layer content without protocol changes.

## Layer Separation

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Protocol scope | MAC layer with separate application protocols | Monolithic — radio, routing, and application layers interleaved |
| Payload interpretation | Opaque at MAC layer | Protobuf `Data` message decoded at every layer |
| Fragmentation | Delegated to higher-layer protocols | Not defined (single-frame limit) |
| Application coupling | Application protocols are architecturally separate | ~30+ application types defined in core protobuf schema |

UMSH maintains a clean boundary between the MAC layer and application protocols. The MAC layer treats payloads opaquely and can carry any higher-layer protocol. Meshtastic's protobuf-defined `Data` message structure spans from radio-level fields to application payloads in a single schema, with no clean separation between layers.

## Timestamps and Time Dependency

| Aspect | UMSH | Meshtastic |
|---|---|---|
| Replay protection | 4-byte monotonic frame counter | 32-bit random packet ID (duplicate cache) |
| Timestamps in packets | None at MAC layer | `rx_time` metadata (not used for protocol decisions) |
| Clock synchronization required | No | No |

Neither protocol requires clock synchronization for core operation. Meshtastic includes reception timestamps as metadata but does not use them for routing or replay protection. Both protocols detect duplicates without relying on wall-clock time — UMSH via monotonic frame counters, Meshtastic via random packet ID caching.

## Packet Overhead Comparison

Minimum overhead for a typical encrypted unicast message:

| Field | UMSH (S=0, 16B MIC) | UMSH (S=0, 4B MIC) | Meshtastic (channel) | Meshtastic (PKC DM) |
|---|---|---|---|---|
| Header/FCF | 1 | 1 | 16 | 16 |
| Destination | 3 | 3 | (in header) | (in header) |
| Source | 3 | 3 | (in header) | (in header) |
| SECINFO | 5 | 5 | — | — |
| MIC / auth tag | 16 | 4 | — | ~12 |
| Nonce / IV | — | — | (derived, not transmitted) | (8 in payload) |
| Protobuf overhead | — | — | ~6 | ~6 |
| **Total overhead** | **28** | **16** | **~22** | **~42** |

Meshtastic's nonce is derived from header fields (packet ID + sender node number) rather than transmitted, saving bytes compared to protocols that transmit the IV. However, the fixed 16-byte cleartext header and protobuf encoding overhead partially offset this advantage.

UMSH with a 16-byte MIC has slightly more overhead than Meshtastic channel encryption (28 vs ~22 bytes), but UMSH's overhead includes full authentication that Meshtastic's channel mode lacks entirely. With a 4-byte MIC, UMSH achieves 16 bytes of overhead — lower than Meshtastic's ~22 bytes — while still providing authentication that Meshtastic channel traffic does not have.

Meshtastic PKC direct messages add approximately 20 bytes of overhead beyond channel encryption (ECDH-derived key, CCM nonce, and authentication tag), bringing total overhead to roughly 42 bytes for authenticated direct messages.

## Power Consumption

Power consumption on a battery-constrained LoRa node is driven by two factors: how long the radio is active (airtime), and how much CPU work is required after each received packet.

### Channel Filtering and False Positives

In a LoRa mesh, broadcast and multicast traffic (position reports, telemetry, channel messages) outnumber unicast packets. For this traffic, the only pre-crypto filter available is the channel identifier. When a packet's channel identifier matches a channel the node does not belong to, the node must attempt decryption to confirm the mismatch — a false positive.

| Protocol | Channel identifier width | False-positive rate per broadcast packet |
|---|---|---|
| Meshtastic | 8 bits (1-byte DJB2 hash) | ~1 in 256 |
| UMSH | 16 bits (2-byte derived hint) | ~1 in 65536 |

Meshtastic's 1-byte channel hash produces ~256× more false positives than UMSH's 2-byte channel identifier. Each false positive requires an AES-256-CTR decryption attempt (cheap relative to ECDH, but still unnecessary CPU work and a delay before the MCU can return to sleep). In a busy mesh with many active channels, this adds up.

### Unicast Filtering

For unicast packets, Meshtastic's 4-byte cleartext node number provides near-zero false-positive filtering with no cryptographic work — the destination can be checked by simple integer comparison before any decryption is attempted. UMSH's 3-byte destination hint has a ~1-in-16,777,216 false-positive rate; when a collision occurs, verification requires decrypting the payload with AES-CTR and computing CMAC over the result — pairwise keys are cached after first contact so no ECDH is needed for known senders, but the decrypt-then-MAC work still applies.

This is a genuine power tradeoff: Meshtastic achieves cheaper unicast filtering by including the full destination identifier in the cleartext header, while UMSH accepts a small false-positive rate in exchange for transmitting fewer bytes and not fully exposing node identity to passive observers.

### Packet Length and Airtime

Meshtastic's fixed 16-byte header is transmitted on every packet regardless of content. UMSH's header scales from 1 byte upward depending on which optional fields are present. On a LoRa network, longer packets mean longer airtime, which means nearby nodes must keep their radios active longer to receive each packet — a cost that compounds across all nodes in range, not just the sender.

### Repeater Power

Both protocols use flood routing as their primary delivery mechanism, so nodes configured as repeaters must receive and retransmit packets. Transmit is the most power-intensive radio operation on a LoRa node. In practice, repeating is enabled only on dedicated infrastructure nodes; end-user devices are typically configured as non-repeating and incur no forwarding transmit cost.

Meshtastic's managed flood uses SNR-based contention windows: after receiving a packet, each potential relay waits a random delay inversely proportional to its received SNR before retransmitting. If it hears a better-positioned node retransmit first, it suppresses its own retransmission. This heuristic reduces the number of redundant rebroadcasts compared to simple flooding and saves transmit power across the network.

UMSH's signal-quality filtering options (minimum RSSI and minimum SNR) allow the original sender to set explicit thresholds: a repeater that received the packet below the threshold must not retransmit it. This gives the sender direct control over which links are used for forwarding, avoiding transmit power wasted on paths unlikely to deliver the packet. Meshtastic's SNR-based approach is automatic but implicit; UMSH's approach is explicit but requires the sender to configure appropriate thresholds.

UMSH repeaters do not need to decrypt or verify the payload before forwarding — the MAC layer treats payloads opaquely. Meshtastic repeaters also forward without decryption for channel traffic.

## Summary of Design Differences

Meshtastic is a full-featured, batteries-included mesh communication system with a large and active user community. It provides a rich application layer (position sharing, telemetry, store-and-forward, TAK integration), broad hardware support, and an easy on-ramp for non-technical users. Its channel-based encryption model is simple to configure and deploy.

UMSH prioritizes cryptographic robustness, compact encoding, and architectural cleanliness. It authenticates all traffic, provides privacy modes for metadata concealment, and maintains strict layer separation that allows it to carry arbitrary higher-layer protocols.

Key tradeoffs:

- **Authentication**: UMSH authenticates every packet. Meshtastic's channel traffic has no authentication — only PKC direct messages (v2.5+) are authenticated.
- **Privacy**: UMSH provides compact addressing hints and opt-in blind modes. Meshtastic exposes full sender and recipient identifiers in cleartext headers on every packet.
- **Identity model**: UMSH uses cryptographic public keys as addresses. Meshtastic uses hardware-derived node numbers that are not cryptographically bound to any key.
- **Overhead**: Comparable in the common case (~14–26 bytes for UMSH vs ~22 bytes for Meshtastic channel), but UMSH's overhead includes authentication.
- **Application richness**: Meshtastic provides a far richer built-in application layer. UMSH delegates richer functionality to higher-layer protocols.
- **Layer separation**: UMSH cleanly separates MAC and application concerns. Meshtastic is a monolithic system where protocol and application are interleaved.
- **Implementation**: Meshtastic is a mature C++ firmware with broad device support. UMSH is not tied to any implementation language or runtime, and its compact design can target bare-metal microcontrollers.
- **Ease of deployment**: Meshtastic is designed for immediate use with consumer hardware. UMSH requires implementation effort and explicit key configuration.
