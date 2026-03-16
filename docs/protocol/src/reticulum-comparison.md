# Comparison with Reticulum

This section compares UMSH with [Reticulum](https://reticulum.network/), a cryptography-based networking stack designed for operation over a wide range of mediums, including LoRa. The comparison is based on Reticulum v0.9.x and its [manual](https://reticulum.network/manual/) and [source code](https://github.com/markqvist/Reticulum).

## Protocol Scope

The most fundamental difference between UMSH and Reticulum is their scope.

UMSH defines a **MAC layer** with cleanly separated application protocols. The MAC layer handles framing, addressing, encryption, authentication, and forwarding, and treats payloads opaquely. Application protocols (text messaging, chat rooms, node management) are architecturally separate and carried in the payload alongside any other higher-layer content such as CoAP or 6LoWPAN.

Reticulum is a **complete network stack** that replaces the IP layer entirely. It provides addressing, routing, link establishment, encryption, reliable delivery (via its Resources API), request/response patterns, and bidirectional channels — all within a single monolithic Python implementation. Reticulum does not separate MAC-layer concerns from application-layer concerns; these are interwoven throughout the stack.

This difference has practical implications: UMSH can be implemented on constrained microcontrollers with a few kilobytes of RAM, while Reticulum requires a full Python 3 runtime. UMSH's MAC layer can carry arbitrary higher-layer protocols, while Reticulum applications must use Reticulum's own APIs for structured communication.

## Identity and Addressing

| Aspect | UMSH | Reticulum |
|---|---|---|
| Identity key | 32-byte Ed25519 public key | 512-bit keyset: 256-bit X25519 + 256-bit Ed25519 |
| Address in packets | 2-byte hint (S=0) or full 32-byte key (S=1) | 16-byte truncated SHA-256 hash |
| Source address | 2-byte hint or 32-byte key | Not included (no source address in packets) |
| Destination address | 2-byte destination hint | 16-byte destination hash |
| Channel identifier | 2-byte derived hint | 16-byte destination hash |

UMSH identifies nodes directly by their Ed25519 public keys and uses compact 2-byte hints as prefilters for efficient matching. The `S` flag allows including the full 32-byte key when needed (first contact, ephemeral keys). Reticulum derives 16-byte destination hashes from the SHA-256 of the destination's identity and "aspect" name (a hierarchical dotted string like `app.sensor.temperature`). These hashes are larger than UMSH hints but serve a different purpose — they are meant to be globally unique identifiers rather than prefilters.

Reticulum does not include a source address in any packet. This provides initiator anonymity by default but means that the recipient must already have context (via an established link or a prior announce) to know who sent a given packet. UMSH includes the source address (as a 2-byte hint or full key) in every packet, which allows stateless first-contact and simplifies protocol logic at the cost of revealing the sender's identity to observers. UMSH offers explicit [blind unicast](introduction.md#blind-unicast) as an opt-in privacy mode that encrypts the source address.

## Packet Structure

| Aspect | UMSH | Reticulum |
|---|---|---|
| Header | 1-byte FCF with version, type, flags | 2-byte header (flags + hop count) |
| Packet types | 8 (via 3-bit field in FCF) | 4 (DATA, ANNOUNCE, LINKREQUEST, PROOF) |
| Destination types | Implicit in packet type (unicast, multicast, broadcast, blind) | 4 (SINGLE, GROUP, PLAIN, LINK) |
| Routing info | CoAP-style composable options | Transport ID field (16 bytes) in HEADER_2 |
| Hop count | Optional 1-byte field | Mandatory 1-byte field |
| MTU | LoRa frame size (typically 255 bytes) | 500 bytes (hard protocol limit) |
| Minimum header overhead | 1 byte (broadcast, no options) | 19 bytes (HEADER_1) or 35 bytes (HEADER_2) |

UMSH achieves very compact headers by using 1-byte and 2-byte fields with optional expansion. Reticulum's 16-byte destination hashes and optional 16-byte transport IDs result in significantly larger headers. For a LoRa link with a 255-byte frame limit, this difference is consequential: Reticulum's minimum 19-byte header (or 35 bytes when routed through transport nodes) consumes a substantial fraction of the available frame.

Reticulum's 500-byte MTU exceeds what most LoRa configurations can carry in a single frame. In practice, Reticulum relies on the underlying interface to handle framing and may require link-layer fragmentation for LoRa, whereas UMSH is designed to fit within a single LoRa frame.

UMSH uses composable CoAP-style options for routing metadata (source routes, trace routes, signal-quality thresholds, region codes), allowing packets to carry exactly the routing information they need. Reticulum uses a fixed two-header-type system: HEADER_1 for direct packets and HEADER_2 for transport-routed packets, with no equivalent to UMSH's composable options.

## Cryptography

| Aspect | UMSH | Reticulum |
|---|---|---|
| Encryption | AES-128-CTR (SIV-style: MIC used as CTR IV) | AES-256-CBC with PKCS7 padding |
| Authentication | AES-CMAC (16-byte MIC) | HMAC-SHA256 (32-byte tag) |
| Key exchange | X25519 ECDH | X25519 ECDH |
| Key derivation | HKDF-SHA256, domain-separated (K\_enc, K\_mic) | HKDF-SHA256, 64-byte output split into HMAC key + AES key |
| Nonce handling | SIV construction (MIC as CTR IV) | Random 16-byte IV per packet |
| Replay protection | 4-byte monotonic frame counter | Duplicate packet hash detection |
| Per-packet overhead (crypto) | 5–7 bytes (SECINFO) + 16 bytes (MIC) = 21–23 bytes | 16 bytes (IV) + 32 bytes (HMAC) = 48 bytes minimum |
| Forward secrecy | Optional PFS sessions via MAC commands (per-session ephemeral keys) | Per-packet ephemeral key for SINGLE; optional ratchets for LINK |

### Encryption Mode

UMSH uses an AES-SIV-inspired construction where the MIC doubles as the CTR IV, providing nonce-misuse resistance. Reticulum uses AES-256-CBC with a random 16-byte IV. Both are sound constructions — the primary difference in practice is overhead: CBC requires transmitting a 16-byte IV and adds 1–16 bytes of PKCS7 padding, while UMSH's SIV construction derives the IV from the MIC (which is already transmitted) and uses CTR mode which requires no padding.

### Authentication and Integrity

UMSH's 16-byte AES-CMAC MIC provides 128-bit integrity protection. Reticulum's 32-byte HMAC-SHA256 tag provides 256-bit integrity — stronger in absolute terms, but at twice the overhead. Both are more than adequate; UMSH's choice is driven by the constrained LoRa frame budget.

### Key Management

For unicast, UMSH derives stable pairwise keys from the ECDH shared secret via HKDF with domain-separated labels. These keys are reused across packets, with per-packet variability provided by the frame counter and optional salt in SECINFO. This is efficient: no per-packet key exchange overhead. For forward secrecy, UMSH defines [PFS session MAC commands](mac-commands.md#pfs-session-request-6) that allow two nodes to exchange ephemeral Ed25519 keypairs and communicate using session-specific keys for an agreed duration. Compromise of long-term keys does not expose traffic encrypted under PFS session keys. PFS sessions require a 3-packet handshake (request, response, acknowledgement) but add no per-packet overhead once established.

Reticulum uses two approaches. For SINGLE (one-off) destinations, each packet includes a fresh ephemeral X25519 public key (32 bytes), providing per-packet forward secrecy at substantial overhead cost — 32 extra bytes on every packet. For LINK (session) destinations, a single ECDH exchange establishes symmetric keys that persist for the link's lifetime — similar to UMSH's stable pairwise keys. Reticulum also offers an optional ratchet mechanism that rotates keys at configurable intervals (minimum 1800 seconds), providing periodic forward secrecy within a link.

Both protocols offer forward secrecy, but with different granularity and overhead tradeoffs. Reticulum's SINGLE mode provides per-packet forward secrecy at 32 bytes per packet; UMSH's PFS sessions provide per-session forward secrecy at zero per-packet overhead after setup.

### Replay Protection

UMSH uses explicit 4-byte monotonic frame counters, which provide deterministic, stateless replay detection with a well-defined forward window. A receiver can immediately reject a replayed packet by comparing the counter to its stored state.

Reticulum detects duplicates by caching packet hashes. This approach works but has different tradeoffs: it requires maintaining a hash cache of bounded size, and once a packet ages out of the cache, it could potentially be replayed. The cache size and eviction policy are implementation-defined.

### Cryptographic Overhead

For an encrypted unicast message, the total cryptographic overhead differs significantly:

| Component | UMSH (16B MIC) | UMSH (4B MIC) | Reticulum (SINGLE) | Reticulum (LINK) |
|---|---|---|---|---|
| SECINFO | 5 B | 5 B | — | — |
| MIC / HMAC | 16 B | 4 B | 32 B | 32 B |
| IV | — | — | 16 B | 16 B |
| Ephemeral pubkey | — | — | 32 B | — |
| CBC padding | — | — | 1–16 B (avg ~8) | 1–16 B (avg ~8) |
| **Subtotal (crypto)** | **21 B** | **9 B** | **~88 B** | **~56 B** |

UMSH supports MIC sizes of 4, 8, 12, and 16 bytes (see [Security & Cryptography](security.md#security-control-field)), allowing deployments to trade integrity margin for payload capacity. Even with a 16-byte MIC, UMSH's 21 bytes of crypto overhead is far less than Reticulum's 56–88 bytes.

## Routing

| Aspect | UMSH | Reticulum |
|---|---|---|
| Flood routing | Yes, bounded by hop count | Yes (broadcast propagation) |
| Source routing | Yes, via source-route option | No |
| Hybrid routing | Source route + hop count in same packet | No |
| Transport/directed routing | N/A | Transport nodes with next-hop forwarding |
| Path discovery | Trace-route option on any flooded packet | Announce flooding + path request/response |
| Max hops | Limited by hop-count byte (255) | 128 |
| Signal-quality filtering | Min RSSI and min SNR options | Not defined at protocol level |
| Region-scoped flooding | Region code option | Not defined |
| Announce bandwidth cap | Not defined (implementation policy) | 2% of interface bandwidth |

UMSH and Reticulum take fundamentally different approaches to routing.

UMSH provides **source routing** — the sender can specify the exact sequence of repeaters a packet should traverse, using 1-byte router hints. This can be combined with flood routing: a packet can be source-routed to a specific area and then flood locally. Path discovery is built into the MAC layer via the trace-route option, which accumulates router hints as a packet floods — the recipient can reverse the trace to obtain a source route back to the sender.

Reticulum uses **next-hop routing** via Transport Nodes — dedicated forwarding nodes that maintain path tables learned from announces. Regular nodes do not forward packets. When no path is known, a 51-byte path request is flooded; transport nodes with cached paths respond. This approach is more automatic but requires designated infrastructure nodes and does not support sender-specified routing.

UMSH's signal-quality filtering (minimum RSSI and SNR options) allows packets to avoid weak links, which is valuable in LoRa networks where marginal links waste airtime on packets that are unlikely to be received reliably. Reticulum does not define equivalent mechanisms at the protocol level.

## Privacy and Anonymity

| Aspect | UMSH | Reticulum |
|---|---|---|
| Source address in packets | Yes (2-byte hint or 32-byte key) | No (default initiator anonymity) |
| Blind unicast | Yes (source encrypted with channel key) | N/A (no source to conceal) |
| Multicast source concealment | Yes (source encrypted inside ciphertext) | N/A |
| Anonymous first contact | Ephemeral Ed25519 key with S=1 flag | Per-packet ephemeral key for SINGLE destinations |
| Destination concealment | Not defined | Not defined |
| Interface access control | Not defined | IFAC (truncated Ed25519 signature per packet) |

The two protocols achieve privacy through different structural choices.

Reticulum omits the source address from all packets, providing initiator anonymity as a default property of the protocol. The tradeoff is that recipients must establish context through other means (announces, link establishment) before they can identify who is communicating with them.

UMSH includes source addresses by default but provides explicit privacy modes. Blind unicast encrypts the source address with a channel key so that only channel members can identify the sender. Encrypted multicast conceals the source inside the ciphertext. These are opt-in features that allow nodes to choose their privacy posture per packet.

Reticulum's IFAC (Interface Access Code) mechanism provides network-level access control: packets are signed with a shared Ed25519 identity derived from a passphrase, and interfaces reject packets with invalid signatures. UMSH does not define an equivalent mechanism.

## Multicast and Group Communication

| Aspect | UMSH | Reticulum |
|---|---|---|
| Channel key size | 16 bytes | 32 bytes (AES-256) |
| Channel identifier | 2-byte derived hint | 16-byte destination hash |
| Multi-hop multicast | Yes (flood with hop count) | No (single-hop broadcast only) |
| Group message auth | Channel-key-based CMAC (16-byte MIC) | Channel-key-based HMAC-SHA256 (32-byte tag) |
| Source privacy | Source encrypted when encryption enabled | No source address to conceal |
| Named channels | Yes (key derived from name) | Not defined |

UMSH supports multi-hop multicast via flood forwarding with hop-count limits. Reticulum's GROUP destinations are currently limited to single-hop broadcast — multi-hop group communication is listed as future work. This is a significant limitation for LoRa mesh networks where multi-hop coverage is essential.

## Application Layer

| Aspect | UMSH | Reticulum |
|---|---|---|
| Payload typing | 1-byte payload type prefix | 1-byte context field (20+ defined values) |
| Structured data | CoAP-over-UMSH (block-wise transfer) | Resources API (multi-packet reliable transfer) |
| Node identity | Identity payload with role, capabilities, name, options | Announce packets with public key, name hash, app data, Ed25519 signature |
| Service discovery | Beacon broadcasts | Aspect-based naming + announce propagation |
| Amateur radio | Operator/station callsign options, explicit unencrypted mode | Not defined |
| Implementation language | Protocol spec (language-agnostic) | Python 3 (reference and only implementation) |

UMSH defines a protocol specification that can be implemented in any language on any platform, including bare-metal microcontrollers. Reticulum is defined primarily by its Python implementation. While the Reticulum manual documents the protocol, the Python codebase is the authoritative reference, and the tight coupling between protocol and implementation makes independent reimplementation non-trivial.

UMSH delegates reliable multi-packet transfer to CoAP's block-wise transfer mechanism, reusing a well-established standard. Reticulum provides its own Resources API for the same purpose, including compression, sequencing, and checksumming — capable but proprietary to the Reticulum stack.

## Timestamps and Time Dependency

Both protocols are designed to operate without clock synchronization.

| Aspect | UMSH | Reticulum |
|---|---|---|
| Replay protection | 4-byte monotonic frame counter | Duplicate packet hash cache |
| Timestamps in headers | None | None (explicitly removed from Fernet-derived token format) |
| Clock synchronization required | No | No |

Both protocols avoid timestamp dependencies at the protocol level. UMSH uses monotonic frame counters for replay protection. Reticulum uses packet hash caching for duplicate detection. Neither requires nodes to agree on wall-clock time.

Reticulum's optional ratchet mechanism uses local time for 30-day key expiry, but this is a local policy decision rather than a protocol requirement.

## Packet Overhead Comparison

Minimum overhead for a typical encrypted unicast message:

| Field | UMSH (S=0, 16B MIC) | UMSH (S=0, 4B MIC) | Reticulum (SINGLE) | Reticulum (LINK) |
|---|---|---|---|---|
| Header/FCF | 1 | 1 | 2 | 2 |
| Destination | 2 | 2 | 16 | 16 |
| Transport ID | — | — | — | 16 (if routed) |
| Source | 2 | 2 | — | — |
| Context byte | — | — | 1 | 1 |
| SECINFO | 5 | 5 | — | — |
| Ephemeral pubkey | — | — | 32 | — |
| IV | — | — | 16 | 16 |
| MIC / HMAC | 16 | 4 | 32 | 32 |
| CBC padding | — | — | 1–16 | 1–16 |
| **Total overhead** | **26** | **14** | **~108** | **~91** |

On a 255-byte LoRa frame:

| | UMSH (S=0, 16B MIC) | UMSH (S=0, 4B MIC) | Reticulum (SINGLE) | Reticulum (LINK) |
|---|---|---|---|---|
| **Available payload** | **229 B** | **241 B** | **~147 B** | **~164 B** |

With a 16-byte MIC, UMSH provides roughly 40–55% more payload capacity than Reticulum. With a 4-byte MIC, UMSH's 14 bytes of total overhead leaves 241 bytes for payload — over 60% more than Reticulum on a typical LoRa frame. For a protocol operating at kilobit-per-second data rates where every byte of airtime is expensive, this difference is substantial.

Note that Reticulum's 500-byte MTU exceeds what most LoRa configurations can transmit in a single frame, so Reticulum may require link-layer fragmentation that further reduces effective throughput.

## Summary of Design Differences

Reticulum is a comprehensive, general-purpose network stack designed to operate across a wide range of mediums — from gigabit Ethernet to sub-kilobit LoRa. It prioritizes medium independence, automatic path discovery, initiator anonymity by default, and a rich application API. Its Python implementation provides a full-featured development environment but limits deployment to platforms that can run a Python runtime.

UMSH is purpose-built for constrained LoRa networks. It prioritizes compact packet encoding, minimal overhead, composable routing options, and strict layer separation. By defining a protocol specification rather than a specific implementation, UMSH can be deployed on bare-metal microcontrollers with minimal resources.

Key tradeoffs:

- **Overhead**: UMSH achieves 60–85% lower per-packet overhead than Reticulum (depending on MIC size), maximizing payload capacity within tight LoRa frame budgets.
- **Cryptographic overhead**: UMSH's SIV construction avoids transmitting a separate IV and requires no padding; Reticulum's CBC mode adds 17–32 bytes of IV and padding overhead per packet.
- **Routing flexibility**: UMSH offers composable source routing, hybrid routing, and signal-quality filtering. Reticulum offers automatic next-hop routing via transport nodes.
- **Privacy model**: Reticulum provides initiator anonymity by default (no source address). UMSH provides source addresses by default with opt-in privacy modes.
- **Multicast**: UMSH supports multi-hop multicast. Reticulum's group communication is currently single-hop only.
- **Scope**: Reticulum is a complete network stack with reliable delivery, sessions, and application APIs. UMSH is a MAC layer with defined-but-separate application protocols, designed to carry arbitrary higher-layer content.
- **Implementation**: Reticulum requires Python 3. UMSH is implementation-agnostic and targets constrained devices.
