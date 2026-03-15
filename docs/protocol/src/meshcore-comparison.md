# Comparison with MeshCore

This section compares UMSH with [MeshCore](https://github.com/meshcore-dev/MeshCore), a LoRa mesh protocol with similar goals. The comparison is based on MeshCore firmware v1.12.0 and its primary source code and documentation.

## Identity and Addressing

Both protocols use Ed25519 public keys as node identities and perform X25519 ECDH for pairwise key agreement.

| Aspect | UMSH | MeshCore |
|---|---|---|
| Identity key | 32-byte Ed25519 public key | 32-byte Ed25519 public key |
| Source address in packets | 2-byte hint (S=0) or full 32-byte key (S=1) | 1-byte hash (first byte of public key) |
| Destination address | 2-byte hint | 1-byte hash |
| Channel identifier | 2-byte derived hint | 1-byte hash of SHA-256 of channel key |

UMSH uses 2-byte hints for both source and destination, with an explicit `S` flag to include the full 32-byte source key when needed (first contact, ephemeral keys). MeshCore uses 1-byte hashes for all regular addressing, with a dedicated `ANON_REQ` packet type that carries the full 32-byte sender public key for first-contact or anonymous exchanges. The tradeoff is that MeshCore saves one additional byte per address field in the common case, but requires a special packet type for any situation where the full key must be transmitted.

## Packet Structure

| Aspect | UMSH | MeshCore |
|---|---|---|
| Header | 1-byte FCF with version, type, flags | 1-byte header with version, type, route mode |
| Packet types | 8 (via 3-bit field in FCF) | 16 payload types (via 4-bit field) |
| Routing info | CoAP-style options (source route, trace route, region, RSSI/SNR thresholds) | Path field (up to 64 bytes), transport codes |
| Hop count | Optional 1-byte field | Implicit via path length |
| Region support | Optional region code option | Transport codes (2 × 16-bit) |

UMSH separates routing metadata into composable options, allowing packets to carry source routes, trace routes, signal-quality thresholds, and region codes independently. MeshCore uses a simpler flat structure with a path field and route-type bits.

## Cryptography

| Aspect | UMSH | MeshCore |
|---|---|---|
| Encryption algorithm | AES-128-CTR (SIV-style: MIC used as CTR IV) | AES-128-ECB |
| Authentication | AES-CMAC (16-byte MIC) | HMAC-SHA256 (truncated to 2-byte MAC) |
| Key derivation | HKDF-SHA256 with domain-separated keys (K_enc, K_mic) | Raw ECDH shared secret used directly |
| Key separation | Separate 16-byte encryption and 16-byte MIC keys | Same shared secret for both AES key (first 16 bytes) and HMAC key (full 32 bytes) |
| Nonce misuse resistance | Yes (SIV construction) | No (ECB mode is deterministic) |
| Replay protection | 4-byte monotonic frame counter (timestamp-free) | UNIX-timestamp-based (requires clock synchronization) |

The cryptographic gap is substantial:

- **AES-128-ECB** is a textbook-insecure mode: it uses no IV or nonce, and identical plaintext blocks produce identical ciphertext blocks, leaking structural information about the payload. AES-128-CTR with a synthetic IV (as used by UMSH) does not have this weakness.

- **2-byte MAC truncation** in MeshCore means an attacker has a 1-in-65536 chance of forging a valid MAC per attempt, which is marginal for a protocol where an attacker can observe and replay packets at will. UMSH's 16-byte MIC provides a forgery probability of 2^-128.

- **No key separation** in MeshCore means the same bytes of the ECDH shared secret serve as both the AES key and the beginning of the HMAC key. UMSH derives independent keys via HKDF with domain-specific labels, which is the standard practice for preventing cross-protocol or cross-purpose key reuse.

- **MAC verification timing**: MeshCore's `MACThenDecrypt` function uses `memcmp` to compare HMAC values, which is not constant-time and introduces a timing side channel. This is primarily a concern in contexts where an attacker can measure verification timing with sufficient precision.

## Routing

| Aspect | UMSH | MeshCore |
|---|---|---|
| Flood routing | Yes, bounded by hop count | Yes (ROUTE_TYPE_FLOOD) |
| Direct/source routing | Yes, via source-route option | Yes (ROUTE_TYPE_DIRECT) |
| Hybrid routing | Source route + hop count in same packet | Not supported |
| Path discovery | Trace-route option on any flooded packet | Dedicated PATH payload type |
| Route learning | Trace-route accumulates hints during flooding | Explicit returned-path messages |
| Signal-quality filtering | Min RSSI and min SNR options | Not defined at protocol level |
| Region-scoped flooding | Region code option | Transport codes |

UMSH's hybrid routing model allows a single packet to be source-routed to a specific area and then flood locally, which is useful for reaching a node in a known geographic region without flooding the entire mesh. MeshCore treats flood and direct routing as mutually exclusive modes selected by route-type bits.

Both protocols support automatic route learning, but through different mechanisms. UMSH uses a trace-route option that accumulates router hints as a packet floods; the recipient can use the accumulated trace directly as a source route. MeshCore uses a dedicated returned-path message type.

## Privacy and Blind Modes

| Aspect | UMSH | MeshCore |
|---|---|---|
| Multicast source concealment | Yes (source encrypted inside ciphertext when encryption enabled) | No |
| Blind unicast | Yes (source encrypted with channel key, payload with pairwise key) | No |
| Anonymous requests | Ephemeral Ed25519 key with S=1 flag | Dedicated ANON_REQ packet type |
| Metadata concealment | Channel-key-based, hides sender and/or destination from non-members | Not supported |

UMSH provides protocol-level privacy features that conceal sender and destination information from observers who do not possess the relevant channel key. Encrypted multicast conceals the source address, and blind unicast conceals both sender and destination. MeshCore does not define equivalent privacy modes.

Both protocols support anonymous first-contact requests, but through different mechanisms. UMSH uses an ephemeral keypair as the source address with the `S` flag set — no dedicated packet type is needed. MeshCore defines a specific `ANON_REQ` payload type that carries the full 32-byte sender public key.

## Multicast

| Aspect | UMSH | MeshCore |
|---|---|---|
| Channel key size | 16 bytes | Variable (shared secret) |
| Channel identifier | 2-byte derived hint | 1-byte hash of SHA-256 of key |
| Group message auth | Channel-key-based CMAC | Channel-key-based HMAC (2-byte MAC) |
| Sender authentication | Not cryptographically verified (symmetric key limitation) | Not cryptographically verified (same limitation) |
| Source privacy | Source encrypted when encryption enabled | No |

Both protocols share the fundamental limitation that symmetric-key multicast cannot authenticate individual senders — any channel member can forge a packet with any claimed source address.

## Application Layer

| Aspect | UMSH | MeshCore |
|---|---|---|
| Payload typing | 1-byte payload type prefix | 4-bit payload type in header |
| Structured data | CoAP-over-UMSH (block-wise transfer) | Multipart packets |
| Node identity | Identity payload with role, capabilities, name, options, optional EdDSA signature | Advertisement payload with public key, timestamp, EdDSA signature, appdata |
| URI scheme | `umsh:n:`, `umsh:ck:`, `umsh:cs:`, `coap-umsh://` | Not defined |
| Amateur radio | Operator/station callsign options, explicit unencrypted mode | Not defined |

UMSH's payload types identify which higher-layer protocol is carried inside the payload — whether UMSH-defined (text messages, chat rooms, node identity) or third-party (CoAP, 6LoWPAN). The MAC layer treats all payloads identically. MeshCore's payload types define application-level semantics directly at the protocol level, without a clean separation between MAC and application concerns. UMSH defines a CoAP-over-UMSH transport (payload type 7) that inherits CoAP's block-wise transfer for payloads larger than a single LoRa frame. MeshCore defines a multipart packet type for segmented transfers at the protocol level.

## Layer Separation

| Aspect | UMSH | MeshCore |
|---|---|---|
| Protocol scope | MAC layer with cleanly separated application protocols | Combined MAC, network, and application layer |
| Payload interpretation | Opaque at MAC layer — application protocols defined separately | Protocol defines payload types with application semantics (text messages, advertisements, login, etc.) |
| Fragmentation | Delegated to higher-layer protocols in the payload | Multipart packet type defined at protocol level |
| Node identity / advertisements | Application-layer payload (see [Node Identity](node-identity.md)) | Protocol-level advertisement packet with mandatory fields |
| Time dependency | Timestamp-free — monotonic frame counters for replay protection (see [Frame Counter](security.md#frame-counter)) | Relies on UNIX timestamps for replay protection, advertisement freshness, and login sequencing |

UMSH maintains a clean boundary between the MAC layer and higher-layer protocols. The MAC layer defines framing, addressing, encryption, authentication, and forwarding, and treats payload content as opaque. UMSH also defines its own application-layer protocols (text messaging, chat rooms, node identity, node management), but these are architecturally separate from the MAC layer and carried in the payload alongside any other higher-layer protocol.

MeshCore takes a more vertically integrated approach: the protocol directly defines payload types for text messages, node advertisements, login sequences, and multipart transfers without a clear separation between MAC and application concerns.

The practical consequence is that UMSH's MAC layer can carry any higher-layer protocol (6LoWPAN, CoAP, custom application formats) without modification, while MeshCore's payload type system is tightly coupled to its built-in application set.

## Timestamps and Time Dependency

MeshCore relies on UNIX timestamps in several protocol-critical roles:

- **Replay protection**: MeshCore uses timestamps rather than sequence counters to detect replayed packets. This requires nodes to maintain a reasonably accurate clock.
- **Advertisement freshness**: Node advertisements carry a timestamp used to determine which advertisement is most recent.
- **Login sequencing**: The login handshake incorporates timestamps.

UMSH is entirely timestamp-free at the MAC layer. Replay protection is based on monotonic 4-byte frame counters (see [Frame Counter](security.md#frame-counter)), which require no clock synchronization and no access to absolute time. Higher-layer payloads (such as the node identity payload in [Node Identity](node-identity.md)) may optionally carry timestamps for application-level purposes, but the MAC layer neither requires nor interprets them.

This distinction matters for deployments where nodes may lack reliable time sources — battery-powered sensors, nodes without GPS or NTP access, or devices that reboot frequently. UMSH's counter-based approach works correctly regardless of clock accuracy, while MeshCore's timestamp-based approach requires nodes to agree on approximate wall-clock time.

## Packet Overhead Comparison

Minimum overhead for a typical encrypted unicast message (no options, no hop count):

| Field | UMSH (S=0) | UMSH (S=1) | MeshCore |
|---|---|---|---|
| Header/FCF | 1 | 1 | 1 |
| Path length | — | — | 1 |
| Destination | 2 | 2 | 1 |
| Source | 2 | 32 | 1 |
| Security info | 5 | 5 | — |
| MAC/MIC | 16 | 16 | 2 |
| ECB block padding | — | — | 0–15 (avg ~8) |
| **Total overhead** | **26** | **56** | **~14** |

MeshCore's use of AES-128-ECB requires the plaintext to be padded to a multiple of 16 bytes. This wastes 0–15 bytes per packet depending on the payload size, averaging roughly 8 bytes of dead space. When this padding overhead is included, MeshCore's effective overhead rises from 6 bytes to approximately 14 bytes.

MeshCore still achieves lower per-packet overhead than UMSH by using 1-byte addresses, a 2-byte MAC, and no frame counter or security control field. However, this compactness comes at a significant cost to security (ECB mode, 2-byte MAC, no replay protection counter, no key separation) and to flexibility (no first-contact without ANON_REQ, no blind unicast, no composable options).

UMSH with `S=0` provides a middle ground: 26 bytes of overhead with full AES-SIV security, monotonic frame counter replay protection, and 16-byte MIC integrity — at the cost of roughly 12 additional bytes compared to MeshCore's effective overhead.

## Summary of Design Differences

MeshCore optimizes aggressively for minimal packet overhead in the common case, accepting significant cryptographic and flexibility tradeoffs to maximize payload capacity within LoRa frame constraints. It takes a vertically integrated approach, defining application-layer payload types and relying on UNIX timestamps for replay protection and advertisement freshness.

UMSH prioritizes cryptographic robustness, composable routing, privacy features, and strict layer separation, accepting higher overhead in exchange for stronger security guarantees and a more extensible protocol structure. By restricting itself to the MAC layer and using monotonic frame counters instead of timestamps, UMSH avoids coupling to specific application assumptions or clock synchronization requirements. The `S` flag allows the overhead to scale based on whether the receiver already knows the sender's public key, bridging the gap for established communication pairs while still supporting zero-prior-state first contact.
