# Comparison with Reticulum

This section compares UMSH with [Reticulum](https://reticulum.network/), a cryptography-based networking stack designed for operation over a wide range of mediums, including LoRa. The comparison is based on Reticulum v1.1.4 (tag [`1.1.4`](https://github.com/markqvist/Reticulum/releases/tag/1.1.4)) and its [manual](https://reticulum.network/manual/) and [source code](https://github.com/markqvist/Reticulum/tree/1.1.4).

The Reticulum claims in this document can be independently verified against the following source files:

| File | Relevant claims |
|---|---|
| [`RNS/Reticulum.py`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Reticulum.py) | MTU, header sizes, announce bandwidth cap, IFAC derivation |
| [`RNS/Packet.py`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Packet.py) | Packet types, header layout, context values |
| [`RNS/Identity.py`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Identity.py) | Key sizes, ECDH, HKDF derivation, ephemeral keys, ratchet system, announce format |
| [`RNS/Destination.py`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Destination.py) | Destination types, destination hash construction, GROUP limitations, ratchet interval |
| [`RNS/Transport.py`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Transport.py) | Routing, replay protection via packet hash cache, max hop cap, IFAC generation |
| [`RNS/Cryptography/Token.py`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Cryptography/Token.py) | AES-256-CBC, PKCS7, HMAC-SHA256, IV handling, timestamp removal |
| [`RNS/Link.py`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Link.py) | LINK session ECDH, symmetric key persistence, MTU signalling, link modes |
| [`RNS/Interfaces/Interface.py`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Interfaces/Interface.py) | Link MTU auto-configuration (`optimise_mtu`) |
| [`RNS/Discovery.py`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Discovery.py) | On-network interface discovery, network identity system |

## Protocol Scope

The most fundamental difference between UMSH and Reticulum is their scope.

UMSH defines a **MAC layer** with cleanly separated application protocols. The MAC layer handles framing, addressing, encryption, authentication, and forwarding, and treats payloads opaquely. Application protocols (text messaging, chat rooms, node management) are architecturally separate and carried in the payload alongside any other higher-layer content such as CoAP or 6LoWPAN.

Reticulum is a **complete network stack** that replaces the IP layer entirely. It provides addressing, routing, link establishment, encryption, reliable delivery (via its Resources API), request/response patterns, and bidirectional channels — all within a single monolithic Python implementation. Reticulum does not separate MAC-layer concerns from application-layer concerns; these are interwoven throughout the stack.

This difference has practical implications: UMSH can be implemented on constrained microcontrollers with a few kilobytes of RAM, while Reticulum requires a full Python 3 runtime. UMSH's MAC layer can carry arbitrary higher-layer protocols, while Reticulum applications must use Reticulum's own APIs for structured communication.

## Identity and Addressing

| Aspect | UMSH | Reticulum |
|---|---|---|
| Identity key | 32-byte Ed25519 public key | 512-bit keyset: 256-bit X25519 + 256-bit Ed25519 ([`Identity.py:58`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Identity.py#L58), `KEYSIZE = 256*2`) |
| Address in packets | compact hint (S=0; 1 byte for unicast SRC, 3 bytes for DST/BCST/MCST SRC) or full 32-byte key (S=1) | 16-byte truncated SHA-256 hash ([`Reticulum.py:146`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Reticulum.py#L146), `TRUNCATED_HASHLENGTH = 128`) |
| Source address | 1-byte hint (unicast) or 3-byte hint (broadcast/multicast), or full 32-byte key | Not included (no source address in packets) |
| Destination address | 3-byte destination hint | 16-byte destination hash |
| Channel identifier | 2-byte derived hint | 16-byte destination hash |

UMSH identifies nodes directly by their Ed25519 public keys and uses compact hints as prefilters for efficient matching — 3 bytes for destination hints and broadcast/multicast source hints, 1 byte for unicast source hints. The `S` flag allows including the full 32-byte key when needed (first contact, ephemeral keys). Reticulum derives 16-byte destination hashes via a two-step construction ([`Destination.py:118`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Destination.py#L118)): (1) the aspect name (a dotted string like `app.sensor.temperature`) is hashed with SHA-256 and truncated to 10 bytes ([`Identity.py:80`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Identity.py#L80), `NAME_HASH_LENGTH = 80`); (2) the final address is `SHA-256(name_hash || identity_hash)[:16]`, where `identity_hash = SHA-256(public_key)[:16]`. These hashes are larger than UMSH hints but serve a different purpose — they are meant to be globally unique identifiers rather than prefilters.

Reticulum does not include a source address in any packet. This provides initiator anonymity by default but means that the recipient must already have context (via an established link or a prior announce) to know who sent a given packet. UMSH includes the source address (as a compact hint or full key) in every packet, which allows stateless first-contact and simplifies protocol logic at the cost of revealing the sender's identity to observers. UMSH offers two opt-in mechanisms that reduce identity exposure. [Blind unicast](introduction.md#blind-unicast) encrypts the source address with the channel key so that only channel members can identify the sender. [PFS sessions](security.md#perfect-forward-secrecy-sessions) use ephemeral node addresses for the duration of the session, so an observer sees only hints derived from short-lived keys rather than the nodes' long-term identities — the long-term identity hints never appear on the wire during the session. This identity obscuration is not unconditional: because the PFS handshake is authenticated with the nodes' long-term keys, an attacker who later compromises a long-term private key can retroactively attribute the session to those identities, even though the session's content remains protected.

## Packet Structure

| Aspect | UMSH | Reticulum |
|---|---|---|
| Header | 1-byte FCF with version, type, flags | 2-byte header (flags + hop count) |
| Packet types | 8 (via 3-bit field in FCF) | 4: DATA, ANNOUNCE, LINKREQUEST, PROOF ([`Packet.py:60–63`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Packet.py#L60-L63)) |
| Destination types | Implicit in packet type (unicast, multicast, broadcast, blind) | 4: SINGLE, GROUP, PLAIN, LINK ([`Destination.py:63–66`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Destination.py#L63-L66)) |
| Routing info | CoAP-style composable options | Transport ID field (16 bytes) in HEADER_2 |
| Flood hop count | Split 4-bit FHOPS field (max 15) | Mandatory 1-byte field |
| MTU | LoRa frame size (typically 255 bytes) | 500-byte network MTU ([`Reticulum.py:91`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Reticulum.py#L91), `MTU = 500`); per-link MTU discovery (since v0.9.3) allows upward negotiation on capable links |
| Minimum header overhead | 1 byte (broadcast, no options) | 19 bytes HEADER_1 or 35 bytes HEADER_2 ([`Reticulum.py:148–149`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Reticulum.py#L148-L149), `HEADER_MINSIZE`/`HEADER_MAXSIZE`) |

UMSH achieves very compact headers by using 1-byte and 2-byte fields with optional expansion. Reticulum's 16-byte destination hashes and optional 16-byte transport IDs result in significantly larger headers. For a LoRa link with a 255-byte frame limit, this difference is consequential: Reticulum's minimum 19-byte header (or 35 bytes when routed through transport nodes) consumes a substantial fraction of the available frame.

Reticulum's 500-byte network MTU exceeds what most LoRa configurations can carry in a single frame. Reticulum introduced link MTU discovery in v0.9.3, which allows adjacent nodes to negotiate a higher effective MTU than 500 bytes when the underlying interface can support it — but this only applies to high-bandwidth interfaces. The `Interface.optimise_mtu()` method ([`Interface.py:115–138`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Interfaces/Interface.py#L115-L138)) maps link speed to hardware MTU, and sets `HW_MTU = None` for any interface running at or below 62,500 bps — which encompasses every LoRa configuration. When `HW_MTU` is `None`, the link request falls back to signalling the base 500-byte MTU ([`Link.py:273–278`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Link.py#L273-L278)), and link MTU discovery is never entered. For LoRa interfaces, Reticulum relies on the RNode firmware to reassemble sub-255-byte air frames into 500-byte packets before presenting them to the stack via KISS. UMSH is designed to fit within a single LoRa frame, avoiding fragmentation entirely.

UMSH uses composable CoAP-style options for routing metadata (source routes, trace routes, signal-quality thresholds, region codes), allowing packets to carry exactly the routing information they need. Reticulum uses a fixed two-header-type system: HEADER_1 for direct packets and HEADER_2 for transport-routed packets, with no equivalent to UMSH's composable options.

## Cryptography

| Aspect | UMSH | Reticulum |
|---|---|---|
| Encryption | AES-128-CTR (SIV-style: MIC used as CTR IV) | AES-256-CBC with PKCS7 padding ([`Token.py:91`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Cryptography/Token.py#L91)); AES-128 support removed in v1.0.0 |
| Authentication | AES-CMAC (16-byte MIC) | HMAC-SHA256 (32-byte tag, [`Token.py:50`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Cryptography/Token.py#L50), `TOKEN_OVERHEAD = 48`) |
| Key exchange | X25519 ECDH | X25519 ECDH ([`Identity.py:581`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Identity.py#L581)) |
| Key derivation | HKDF-SHA256, domain-separated (K\_enc, K\_mic) | HKDF-SHA256, 64-byte output split into HMAC key + AES key ([`Identity.py:86`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Identity.py#L86), `DERIVED_KEY_LENGTH = 512//8`) |
| Nonce handling | SIV construction (MIC as CTR IV) | Random 16-byte IV per packet ([`Token.py:89`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Cryptography/Token.py#L89), `os.urandom(16)`) |
| Replay protection | 4-byte monotonic frame counter | Duplicate packet hash detection ([`Transport.py:59`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Transport.py#L59), `packet_hashlist`) |
| Per-packet overhead (crypto) | 5–7 bytes (SECINFO) + 16 bytes (MIC) = 21–23 bytes | 16 bytes (IV) + 32 bytes (HMAC) = 48 bytes minimum (LINK); +32 bytes ephemeral pubkey for SINGLE |
| Forward secrecy | Optional PFS sessions via MAC commands (per-session ephemeral keys) | Per-packet ephemeral key for SINGLE ([`Identity.py:574`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Identity.py#L574)); optional ratchets for LINK (default min 30 min rotation, [`Destination.py:90`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Destination.py#L90), up to 512 ratchet keys stored per destination, 30-day expiry) |
| Future modes | — | AES-256-GCM defined (link mode 0x02) but reserved; OTP/post-quantum modes reserved |

### Encryption Mode

UMSH uses an AES-SIV-inspired construction where the MIC doubles as the CTR IV, providing nonce-misuse resistance. Reticulum uses AES-256-CBC with a random 16-byte IV. Both are sound constructions — the primary difference in practice is overhead: CBC requires transmitting a 16-byte IV and adds 1–16 bytes of PKCS7 padding, while UMSH's SIV construction derives the IV from the MIC (which is already transmitted) and uses CTR mode which requires no padding.

### Authentication and Integrity

UMSH's 16-byte AES-CMAC MIC provides 128-bit integrity protection. Reticulum's 32-byte HMAC-SHA256 tag provides 256-bit integrity — stronger in absolute terms, but at twice the overhead. Both are more than adequate; UMSH's choice is driven by the constrained LoRa frame budget.

### Key Management

For unicast, UMSH derives stable pairwise keys from the ECDH shared secret via HKDF with domain-separated labels. These keys are reused across packets, with per-packet variability provided by the frame counter and optional salt in SECINFO. This is efficient: no per-packet key exchange overhead. For forward secrecy, UMSH defines [PFS sessions](security.md#perfect-forward-secrecy-sessions) in which both nodes exchange ephemeral node addresses via a two-message handshake and communicate using session-specific keys for an agreed duration. Compromise of long-term keys does not expose traffic encrypted under PFS session keys. PFS sessions add no per-packet overhead once established.

Reticulum uses two approaches. For SINGLE (one-off) destinations, each packet includes a fresh ephemeral X25519 public key (32 bytes), providing per-packet forward secrecy at substantial overhead cost — 32 extra bytes on every packet ([`Identity.py:574`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Identity.py#L574), `ephemeral_key = X25519PrivateKey.generate()`). For LINK (session) destinations, a single ECDH exchange establishes symmetric keys that persist for the link's lifetime — similar to UMSH's stable pairwise keys ([`Link.py:340`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Link.py#L340), `self.shared_key = self.prv.exchange(self.peer_pub)`). Reticulum also offers a ratchet mechanism that rotates keys at a configurable minimum interval (default 30 minutes, adjustable per-destination via `Destination.set_ratchet_interval()` ([`Destination.py:514`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Destination.py#L514))), providing periodic forward secrecy within a link ([`Destination.py:90`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Destination.py#L90), `RATCHET_INTERVAL = 30*60`). Up to 512 ratchet keys are stored per destination, each expiring after 30 days. Ratchet key presence is signalled via a context flag in announce packets, allowing senders to use the most recent ratchet key in place of the static identity key, providing forward secrecy for single-packet communication without the full 32-byte ephemeral pubkey overhead.

Both protocols offer forward secrecy, but with different granularity and overhead tradeoffs. Reticulum's SINGLE mode provides per-packet forward secrecy at 32 bytes per packet; UMSH's PFS sessions provide per-session forward secrecy at zero per-packet overhead after setup.

### Replay Protection

UMSH uses explicit 4-byte monotonic frame counters, which provide deterministic, stateless replay detection with a well-defined forward window. A receiver can immediately reject a replayed packet by comparing the counter to its stored state.

Reticulum detects duplicates by caching packet hashes ([`Transport.py:59`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Transport.py#L59), `packet_hashlist = set()`). This approach works but has different tradeoffs: it requires maintaining a hash cache, and once the cache fills it is evicted in bulk via a two-generation rolling scheme — when the active set exceeds 500,000 entries it is moved into a `packet_hashlist_prev` set ([`Transport.py:60`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Transport.py#L60)) and a fresh set starts accumulating ([`Transport.py:565–567`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Transport.py#L565-L567), cap: [`Transport.py:115`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Transport.py#L115), `hashlist_maxsize = 1000000`). A replayed packet that was seen in neither the current nor the previous generation would not be detected.

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
| Flood routing | Yes, bounded by flood hop count | Yes (broadcast propagation) |
| Source routing | Yes, via source-route option | No |
| Hybrid routing | Source route + flood hop count in same packet | No |
| Transport/directed routing | N/A | Transport nodes with next-hop forwarding |
| Path discovery | Trace-route option on any flooded packet | Announce flooding + path request/response |
| Max hops | 15 flood + unlimited source-routed | 128 (hard-coded announce propagation cap, [`Transport.py:41`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Transport.py#L41), `PATHFINDER_M`) |
| Forwarding confirmation | Yes (retries with backoff) | No — forwarding is fire-and-forget; reliability is end-to-end via cryptographic proofs |
| Channel access | CAD with random backoff; SNR-based contention windows | Not defined at protocol level; RNode firmware implements CSMA with persistence probability for LoRa interfaces |
| Signal-quality filtering | Min RSSI and min SNR options | Not defined at protocol level |
| Region-scoped flooding | Region code option | Not defined |
| Announce bandwidth cap | Not defined (implementation policy) | Default 2% of interface bandwidth ([`Reticulum.py:115`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Reticulum.py#L115), `ANNOUNCE_CAP = 2`), configurable per-interface via `announce_cap` key |
| Interface discovery | Not defined | On-network auto-discovery via `rnstransport.discovery.interface` destination (since v1.1.0) |

UMSH and Reticulum take fundamentally different approaches to routing.

UMSH provides **source routing** — the sender can specify the exact sequence of repeaters a packet should traverse, using 1-byte router hints. This can be combined with flood routing: a packet can be source-routed to a specific area and then flood locally. Path discovery is built into the MAC layer via the trace-route option, which accumulates router hints as a packet floods — the recipient reverses the accumulated trace and caches it as a source route for all subsequent communication with the sender (see [Route Learning](beacons.md#route-learning)).

UMSH defines channel access mechanisms (CAD with random backoff, SNR-based contention windows) and forwarding confirmation with retries, providing reliable hop-by-hop delivery and collision avoidance. Reticulum does not define equivalent mechanisms at the protocol level, though RNode firmware provides CSMA with persistence probability for LoRa interfaces independently of Reticulum.

Reticulum uses **next-hop routing** via Transport Nodes — dedicated forwarding nodes that maintain path tables learned from announces. Regular nodes do not forward packets. When no path is known, a path request is flooded (51 bytes in non-transport mode: 19-byte HEADER_1 + 16-byte destination hash + 16-byte request tag); transport nodes with cached paths respond. This approach is more automatic but requires designated infrastructure nodes and does not support sender-specified routing.

Reticulum's maximum announce propagation is 128 hops ([`Transport.py:41`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Transport.py#L41), `PATHFINDER_M`). This constant is hard-coded; the hop count field is one byte and could technically carry values up to 255, but transport logic enforces the 128-hop limit.

Reticulum v1.1.0 introduced on-network interface discovery: nodes can broadcast structured discovery announces (containing interface type, LoRa parameters, IFAC credentials, and GPS coordinates) to the `rnstransport.discovery.interface` destination. Other nodes can receive these announces and automatically connect to trusted remote interfaces. This capability requires the LXMF module and uses proof-of-work stamps to prevent spam. UMSH does not define an equivalent mechanism.

UMSH's signal-quality filtering (minimum RSSI and SNR options) allows packets to avoid weak links, which is valuable in LoRa networks where marginal links waste airtime on packets that are unlikely to be received reliably. Reticulum does not define equivalent mechanisms at the protocol level.

## Privacy and Anonymity

| Aspect | UMSH | Reticulum |
|---|---|---|
| Source address in packets | Yes (compact hint or 32-byte key) | No (default initiator anonymity) |
| Blind unicast | Yes (source encrypted with channel key) | N/A (no source to conceal) |
| Multicast source concealment | Yes (source encrypted inside ciphertext) | N/A |
| Anonymous first contact | Ephemeral Ed25519 key with S=1 flag | Per-packet ephemeral key for SINGLE destinations |
| Destination concealment | Not defined | Not defined |
| Interface access control | Not defined | IFAC (truncated Ed25519 signature per packet) |
| Network trust domains | Not defined | Network Identity system (since v1.1.0) |

The two protocols achieve privacy through different structural choices.

Reticulum omits the source address from all packets, providing initiator anonymity as a default property of the protocol. The tradeoff is that recipients must establish context through other means (announces, link establishment) before they can identify who is communicating with them.

UMSH includes source addresses by default but provides explicit privacy modes. Blind unicast encrypts the source address with a channel key so that only channel members can identify the sender. Encrypted multicast conceals the source inside the ciphertext. These are opt-in features that allow nodes to choose their privacy posture per packet.

Reticulum's IFAC (Interface Access Code) mechanism provides network-level access control: a shared 64-byte keypair (X25519 + Ed25519) is derived from the network name and/or passphrase via `HKDF-SHA256(SHA-256(network_name) || SHA-256(passphrase))`. Each packet is signed with the Ed25519 key, and a configurable-length tail of that signature (1–64 bytes) is appended to the packet as the IFAC code ([`Transport.py:1485–1490`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Transport.py#L1485-L1490)). Interfaces reject packets with invalid IFAC codes. UMSH does not define an equivalent mechanism.

Reticulum v1.1.0 introduced a Network Identity system: a standard Reticulum identity keypair can be designated as a network's signing authority. Network Identity keys sign interface discovery announces, allowing receiving nodes to verify that a discovered interface belongs to a trusted administrative domain. This enables optional encrypted discovery and provides a foundation for inter-network trust and future distributed name resolution. UMSH does not define an equivalent network identity layer.

Reticulum v1.1.0 also introduced a distributed blackhole list: specific identities can be blacklisted, causing their announces to be dropped by participating nodes. The blackhole list can be published and updated across the network. UMSH has no equivalent mechanism.

## Multicast and Group Communication

| Aspect | UMSH | Reticulum |
|---|---|---|
| Channel key size | 32 bytes | 32 bytes (AES-256) |
| Channel identifier | 2-byte derived hint | 16-byte destination hash |
| Multi-hop multicast | Yes (flood with flood hop count) | No (single-hop broadcast only) |
| Group message auth | Channel-key-based CMAC (16-byte MIC) | Channel-key-based HMAC-SHA256 (32-byte tag) |
| Source privacy | Source encrypted when encryption enabled | No source address to conceal |
| Named channels | Yes (key derived from name) | Not defined |

UMSH supports multi-hop multicast via flood forwarding with flood hop count limits. Reticulum's GROUP destinations are currently limited to single-hop broadcast — the [manual states](https://reticulum.network/manual/understanding.html#destinations):

> Packets to this type of destination are not currently transported over multiple hops, although a planned upgrade to Reticulum will allow globally reachable group destinations.

This is a significant limitation for LoRa mesh networks where multi-hop coverage is essential.

## Application Layer

| Aspect | UMSH | Reticulum |
|---|---|---|
| Payload typing | 1-byte payload type prefix | 1-byte context field (21 defined values; [`Packet.py:72–92`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Packet.py#L72-L92)) |
| Structured data | CoAP-over-UMSH (block-wise transfer) | [Resources API](https://reticulum.network/manual/understanding.html#resources) (multi-packet reliable transfer) |
| Node identity | Identity payload with role, capabilities, name, options | [Announce packets](https://reticulum.network/manual/understanding.html#public-key-announcements) with public key, name hash, app data, Ed25519 signature ([`Identity.py:355`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Identity.py#L355), `validate_announce()`) |
| Service discovery | Beacon broadcasts | Aspect-based naming + announce propagation |
| Interface discovery | Not defined | On-network auto-discovery with trust verification (since v1.1.0) |
| Network identity | Not defined | Signing authority keypair for administrative domains (since v1.1.0) |
| Amateur radio | Operator/station callsign options, explicit unencrypted mode | Not defined |
| Implementation language | Protocol spec (language-agnostic) | Python 3 (reference implementation); unofficial [Rust implementation](https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs) exists |

Reticulum is defined primarily by its Python implementation. While the Reticulum manual documents the protocol, the Python codebase is the authoritative reference, and the tight coupling between protocol and implementation makes independent reimplementation non-trivial. An unofficial [Rust implementation](https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs) exists but is not officially associated with the Reticulum project. UMSH is not tied to any single implementation language or runtime.

UMSH delegates reliable multi-packet transfer to CoAP's block-wise transfer mechanism, reusing a well-established standard. Reticulum provides its own [Resources API](https://reticulum.network/manual/understanding.html#resources) for the same purpose, including compression, sequencing, and checksumming — capable but proprietary to the Reticulum stack.

Reticulum v1.1.0 introduced structured interface discovery at the application layer: nodes can publish and consume typed discovery records that include interface parameters, GPS coordinates, IFAC credentials, and network identity signatures. This enables a form of self-organizing network management that has no counterpart in UMSH, which relies on out-of-band coordination for infrastructure configuration.

## Timestamps and Time Dependency

Both protocols are designed to operate without clock synchronization.

| Aspect | UMSH | Reticulum |
|---|---|---|
| Replay protection | 4-byte monotonic frame counter | Duplicate packet hash cache |
| Timestamps in headers | None | None (explicitly removed from Fernet-derived token format; [`Token.py:41–49`](https://github.com/markqvist/Reticulum/blob/1.1.4/RNS/Cryptography/Token.py#L41-L49)) |
| Clock synchronization required | No | No |

Both protocols avoid timestamp dependencies at the protocol level. UMSH uses monotonic frame counters for replay protection. Reticulum uses packet hash caching for duplicate detection. Neither requires nodes to agree on wall-clock time.

Reticulum's ratchet mechanism uses local time for 30-day key expiry and minimum rotation intervals, but this is a local policy decision rather than a protocol requirement — no timestamp is transmitted on the wire.

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

Reticulum's 500-byte network MTU exceeds what most LoRa configurations can transmit in a single frame, so Reticulum requires link-layer fragmentation at the LoRa interface that further reduces effective throughput. Link MTU discovery (added in v0.9.3) allows Reticulum to negotiate larger MTUs on capable links, but provides no relief for LoRa interfaces with sub-500-byte physical limits.

## Power Consumption

The power profiles of UMSH and Reticulum differ across every dimension: platform, per-packet overhead, and filtering behavior.

### Platform Power Floor

The reference Reticulum implementation requires a Python 3 runtime and therefore runs on Linux-capable hardware — a Raspberry Pi, SBC, or similar computer. These platforms consume on the order of 1–5 watts continuously. This is an implementation choice rather than a protocol requirement: the unofficial [Rust implementation](https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs) could in principle run on more constrained hardware. However, Reticulum's protocol design places a higher floor than UMSH regardless of implementation language — the path table state required for Transport Node operation, the 500-byte MTU requiring larger packet buffers, and the complexity of the announce propagation and link establishment machinery all demand more RAM and processing than UMSH's simpler MAC-layer model.

UMSH's compact encoding, minimal per-packet state, and single-frame design allow it to run on bare-metal microcontrollers drawing microamps in sleep and milliwatts when active. For battery-powered or solar-powered field deployments this difference is significant: a minimal UMSH node can operate for months or years on a single battery in a way that a full Reticulum stack — even a hypothetical embedded Rust implementation — would find difficult to match.

### False-Positive Filtering

Reticulum's 16-byte (128-bit) destination addresses have an essentially zero collision probability — a node receiving a packet addressed to someone else will never mistake it for its own. There is no wasted cryptographic work from address false positives. UMSH's 3-byte destination hints have a ~1-in-16,777,216 false-positive rate; when a collision occurs, the node must attempt full packet verification before discarding it. Pairwise keys are cached after first contact, so no ECDH is needed for known senders — but verification still requires decrypting the payload with AES-CTR (using the transmitted MIC as the CTR IV) and then computing CMAC over the decrypted plaintext to confirm the MIC matches. ECDH and HKDF would additionally be required for a false positive from an unknown sender transmitting with a full 32-byte source key (S=1), which is rare in normal operation. In practice, on a LoRa network with modest traffic, spurious collisions are rare enough that this cost is negligible.

### Packet Length and Airtime

Reticulum's minimum packet overhead is 19–35 bytes (header alone), and per-packet crypto adds at minimum 48 bytes (LINK) or 80 bytes (SINGLE), before any payload. UMSH's minimum overhead is 1 byte, with 14–26 bytes for a typical authenticated unicast. Shorter packets mean less airtime per message, which translates directly to less receive power for every node in range — a cost the sender imposes on the whole network.

### Fragmentation

Reticulum's 500-byte network MTU exceeds the ~255-byte LoRa frame limit, requiring link-layer fragmentation for larger messages. A node receiving a fragmented message must keep its radio and MCU active across multiple frames until reassembly completes. UMSH is designed to fit each packet into a single LoRa frame, so the radio can return to sleep as soon as one frame is processed.

### Announce Traffic and Repeater Power

Reticulum relies on periodic announce flooding to build and maintain path tables. Even at the default 2% bandwidth cap, this represents a continuous background of traffic that all nodes must receive and re-broadcast, regardless of whether they are acting as Transport Nodes. UMSH does not define an equivalent mechanism — path discovery is on-demand via the trace-route option and imposes no standing overhead.

For data packet forwarding, Reticulum divides nodes into two classes at the protocol level: regular nodes, which do not forward unicast packets, and Transport Nodes, which maintain path tables and forward on behalf of others. This means most nodes in a Reticulum network incur zero transmit cost for forwarding unicast traffic. UMSH makes the same distinction at the configuration level — repeating is enabled only on dedicated infrastructure nodes, and end-user devices are typically configured as non-repeating. The practical power implication for non-repeating nodes is the same in both protocols; the difference is that Reticulum enforces the separation in the protocol itself rather than leaving it to deployment configuration.

The infrastructure dependency is the key tradeoff: Reticulum's routing model requires Transport Nodes to be present and reachable, and these nodes need reliable power to maintain path tables. UMSH's flood-based model works without any fixed infrastructure, with repeater nodes sharing the forwarding load.

## Summary of Design Differences

Reticulum is a comprehensive, general-purpose network stack designed to operate across a wide range of mediums — from gigabit Ethernet to sub-kilobit LoRa. It prioritizes medium independence, automatic path discovery, initiator anonymity by default, and a rich application API. Its Python implementation provides a full-featured development environment but limits deployment to platforms that can run a Python runtime. Recent versions (v1.1.0+) have added on-network interface discovery and a network identity system that enable more sophisticated network management and trust hierarchies.

UMSH is purpose-built for constrained LoRa networks. It prioritizes compact packet encoding, minimal overhead, composable routing options, and strict layer separation. Its small per-packet overhead, single-frame design, and absence of mandatory runtime state (no path tables, no clock synchronization) make it deployable on bare-metal microcontrollers with minimal resources.

Key tradeoffs:

- **Overhead**: UMSH achieves 60–85% lower per-packet overhead than Reticulum (depending on MIC size), maximizing payload capacity within tight LoRa frame budgets.
- **Cryptographic overhead**: UMSH's SIV construction avoids transmitting a separate IV and requires no padding; Reticulum's CBC mode (AES-256 only since v1.0.0) adds 17–32 bytes of IV and padding overhead per packet.
- **Routing flexibility**: UMSH offers composable source routing, hybrid routing, and signal-quality filtering. Reticulum offers automatic next-hop routing via transport nodes, and on-network interface auto-discovery since v1.1.0.
- **Privacy model**: Reticulum provides initiator anonymity by default (no source address), plus a network identity system for administrative trust domains. UMSH provides source addresses by default with opt-in privacy modes.
- **Multicast**: UMSH supports multi-hop multicast. Reticulum's group communication is currently single-hop only (multi-hop planned).
- **Scope**: Reticulum is a complete network stack with reliable delivery, sessions, and application APIs. UMSH is a MAC layer with defined-but-separate application protocols, designed to carry arbitrary higher-layer content.
- **Implementation**: Reticulum requires Python 3. UMSH is not tied to any implementation language or runtime, and its compact design targets constrained devices.
