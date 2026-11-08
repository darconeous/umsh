# Security Considerations

This chapter consolidates the security properties, limitations, and implementation guidance that are distributed throughout the specification. It is intended as a reference for implementers and reviewers evaluating UMSH's security posture.

## Threat Model

UMSH is designed for a shared radio medium where any device in range can observe and inject packets. The threat model assumes:

- **Passive eavesdroppers** can observe all traffic on the channel, including packet timing, size, hint values, and frame counters.
- **Active attackers** can inject, replay, modify, or selectively drop packets.
- **Compromised nodes** may leak their long-term private keys, channel keys, or both.

UMSH does **not** assume a trusted infrastructure, a reliable transport, or a synchronized clock.

## What UMSH Protects Against

**Eavesdropping.** When encryption is enabled, payload content is protected by AES-256-CTR keyed with material derived from ECDH (unicast) or the channel key (multicast). An observer without the relevant key cannot recover plaintext.

**Forgery.** All authenticated packets carry a MIC computed with S2V (AES-CMAC). An attacker who does not possess the encryption and authentication keys cannot produce a valid MIC. The [MIC size](security.md#security-control-field) determines the forgery resistance—from 2^-32 (4-byte MIC) to 2^-128 (16-byte MIC).

**Sender impersonation on signed frames.** A [frame signature](security.md#frame-signatures) covers the header, frame counter, and payload, and on a channel the channel itself. Only the holder of the signing key can produce one, so a verified signature attributes a broadcast or multicast to its sender, which a channel MIC cannot.

**Replay attacks.** Monotonically increasing [frame counters](security.md#frame-counter) allow receivers to detect and reject replayed packets. The [backward window and MIC cache](security.md#replay-detection) provide tolerance for out-of-order delivery without weakening replay protection. An unsigned multicast is the exception; see [Replay of Unsigned Multicast](#replay-of-unsigned-multicast).

**Nonce misuse.** The [AES-SIV construction](security.md#encrypted-packets) derives the CTR IV from the key, associated data, and plaintext, so accidental nonce reuse (e.g., due to a buggy counter implementation) does not produce the catastrophic plaintext leakage that would occur with AES-GCM or raw AES-CTR. In the worst case, an attacker can detect when two packets carry identical associated data and plaintext—the keys and other traffic remain uncompromised.

**Long-term key compromise (with PFS).** If a [PFS session](security.md#perfect-forward-secrecy-sessions) was active and the ephemeral keys were properly erased, traffic from that session cannot be retroactively decrypted even if the long-term private keys are later compromised.

## What UMSH Does Not Protect Against

**Traffic analysis.** A passive observer can see packet timing, frequency, size, hint values, frame counters, and flood hop counts—all in the clear. This reveals communication patterns (who is active, how often, rough network topology) even when payloads are encrypted. Hint values are stable for a given identity, enabling long-term tracking of a node's activity.

**Multicast sender impersonation.** Multicast authentication is based on the shared channel key. Any node possessing the key can construct a valid packet with any claimed source address, and other channel members cannot cryptographically distinguish the true sender from an impersonator. A multicast with a verified [frame signature](security.md#frame-signatures) is the exception, but an unsigned multicast, or one whose signature does not verify, carries no such attribution. See [Multicast Sender Authentication](limitations.md#multicast-sender-authentication).

**Selective packet dropping.** A compromised or malicious repeater can selectively drop packets without detection. UMSH provides no mechanism to verify that a repeater faithfully forwarded a packet. The flood routing model provides redundancy (multiple paths), but a strategically positioned adversary can still disrupt delivery.

**Denial of service.** An attacker can flood the radio channel with valid-looking packets, forcing receivers to expend computation on cryptographic verification. The 3-byte destination hint reduces this cost (only ~1 in 16,777,216 unicast packets will trigger verification for any given node), but the shared medium provides no isolation. The `EMERGENCY` channel's priority forwarding could be abused to amplify DoS traffic, though the frame-signature requirement limits this to attackers who possess a valid Ed25519 keypair.

**Bounded extra forwarding via route recovery.** The [Route Retry option](packet-options.md#route-retry-option-6) intentionally allows one extra forwarding wave for an already-seen authenticated packet when the sender is recovering from a stale route. Because the option is dynamic and not MIC-protected, an observer who can copy a packet can also add the option and potentially trigger that extra forwarding attempt. This is a real amplification tradeoff, but it is tightly bounded: the cache key distinguishes only the original packet and the route-retry form, not an unbounded sequence of retries. Implementations should preserve that bound and must not treat arbitrary dynamic-option changes as creating new forwarding identities.

**Peer-registry exhaustion by first-contact senders.** If an implementation automatically learns peers from inbound full-key packets, an attacker can generate many distinct keypairs and send valid first-contact traffic in an attempt to fill the peer table. If successful, this can crowd out legitimate peers or prevent future first contact. Implementations should distinguish between explicitly configured peers and opportunistically learned peers. Explicit peers should be pinned and must not be displaced by auto-learning. Opportunistically learned peers should be bounded separately or recycled with an eviction policy such as least-recently-seen replacement. Multicast traffic needs no peer registration to be delivered: an [unsigned multicast](security.md#unsigned-multicast) is judged by duplicate suppression alone. A stranger's signed frame takes a receive window, which first contacts from freshly minted keys could displace on demand; the [signed-frame counter rules](security.md#signed-frame-counters) bound how often they may.

**Traffic amplification via broadcast or multicast requests.** An unsigned broadcast packet is unauthenticated, a multicast packet may be attributable only to a shared channel key, and even a [signed](security.md#frame-signatures) one may come from an ephemeral source identity. An attacker can exploit this by sending a request that appears to warrant a response or some other follow-on action from every receiving node. If the request does not include a complete [trace](packet-options.md#trace-option-7), recipients do not learn a specific return path. Any per-node reply may therefore fall back to flood routing, using the inbound `FHOPS_ACC` as a distance estimate or flooding more broadly if no better routing state exists. The result is an amplification attack: one injected request can trigger many independent flood-routed responses, consuming airtime and effectively causing a distributed denial of service. Implementations and application protocols must therefore treat broadcast and multicast requests as fan-out hazards. They should not automatically generate per-node responses unless those responses are explicitly designed to avoid amplification through mechanisms such as route learning, strict rate limits, randomized suppression, aggregation, or making the request one-way only.

**Non-repudiation.** UMSH's MIC is computed with symmetric pairwise keys that both sender and recipient possess, so a recipient cannot cryptographically prove to a third party who authored a given packet—either party could have constructed it. However, UMSH does not claim to provide deniability. Real-world deniability depends on the entire system: usage patterns, device forensics, metadata, and interactions with other systems. The symmetric MIC is a narrow property, not a deniability guarantee. A [frame signature](security.md#frame-signatures) (as required on the `EMERGENCY` channel) or an EdDSA signature in an identity payload gives up even this narrow property—a signature can only be produced by the private key holder, and anyone holding the signed bytes can check it.

**Forward secrecy without PFS sessions.** Normal unicast traffic uses stable pairwise keys derived from long-term ECDH. If a node's long-term private key is compromised, all past and future unicast traffic with that node can be decrypted. Forward secrecy requires explicit use of [PFS sessions](security.md#perfect-forward-secrecy-sessions).

**Anonymous channel membership.** Possessing a channel key is both necessary and sufficient for channel membership. There is no mechanism to verify *who* holds a key, revoke access to a specific node without re-keying the entire channel (except via [managed channels](multicast-channels.md#managed-channels)), or detect how many members a channel has.

## Implementation Requirements

The following requirements are critical for security. Failure to implement any of them correctly can compromise the properties described above.

### Frame Counter Monotonicity

The frame counter must strictly increase for each packet a node address sends. Reusing a counter value with the same key undermines replay protection and, in the worst case, can leak information about plaintext differences (though the AES-SIV construction limits the damage). See [Frame Counters](security.md#frame-counter).

### Frame Counter Persistence

A node must not reuse frame counter values across reboots. Implementations must either persist the counter to non-volatile storage or advance it on startup by a margin large enough to pass every value used, yet smaller than the forward window. A node must likewise persist each known peer's receive baseline and restore it at startup; one that loses a peer's baseline accepts a replay of that peer's earlier frames as first contact. If writing to non-volatile storage, care must be taken to avoid wearing out the storage medium. See [Counter Persistence](security.md#counter-persistence) and [Counter Resynchronization](security.md#counter-resynchronization).

### Ephemeral Key Erasure

PFS sessions derive their security from the guarantee that ephemeral private keys are erased when the session ends. Implementations must ensure that ephemeral keys are:

- Never written to persistent storage, swap files, or logs
- Explicitly zeroed in memory upon session termination (not just freed—freed memory may not be overwritten promptly)
- Not retained in core dumps or crash reports

Failure to erase ephemeral keys eliminates the forward secrecy property entirely. See [Session Lifetime](security.md#session-lifetime).

### Constant-Time MIC Verification

MIC comparison must use constant-time comparison (e.g., a fixed-iteration XOR-and-OR loop) rather than `memcmp` or similar short-circuiting functions. A timing side channel in MIC verification allows an attacker to incrementally guess MIC bytes by measuring response time.

### Public Key Validation

Implementations must reject malformed Ed25519 public keys before converting them to X25519 form. Accepting a malformed key can produce a low-order X25519 point, resulting in a shared secret of zero—which would cause all pairwise keys to be identical across different peers. See [Ed25519 to X25519 Conversion](security.md#ed25519-to-x25519-conversion).

### Reserved Bits

Packets with non-zero reserved bits in the [Security Control Field](security.md#security-control-field) must be dropped. Accepting unknown bit patterns could indicate a protocol version mismatch or a malformed packet; processing them risks undefined behavior.

## Metadata Exposure

Even with encryption enabled, the following information is visible to a passive observer. Which fields are present depends on the packet type:

| Field | Packet types | What it reveals |
|---|---|---|
| Packet timing and frequency | All | Communication patterns—when a node is active, how often it transmits |
| Destination hint (3 bytes) | Unicast | Stable per-identity; enables tracking a node's correspondents over time |
| Source hint (3 bytes) | Unicast, unencrypted multicast, broadcast | Stable per-identity; enables tracking a node's activity over time |
| Channel identifier (2 bytes) | Multicast, blind unicast | Stable per-channel; reveals which channel a packet belongs to |
| Frame counter | All authenticated | Monotonically increasing; reveals total packet count and transmission rate |
| Flood hop count | All with FHOPS | Reveals approximate distance from the original sender |
| Packet size | All | May correlate with payload type or content length |
| MIC | All authenticated | Unique per-packet; usable as a packet fingerprint for correlation across hops |
| Ack MIC (4 bytes) | MAC Ack | Prefix of the acknowledged packet's MIC; links the ack to the original packet and confirms its delivery. Carries no explicit endpoint identifier (the MAC Ack has no destination hint), but the link to the original packet remains a correlation vector |

In encrypted multicast, the source address is encrypted inside the ciphertext. In blind unicast, both the source and destination addresses are encrypted using the channel key—only the channel identifier remains in the clear. Normal unicast exposes both the destination hint and source hint (or full source key) to passive observers.

### Frame Counter Correlation and PFS

If a device uses a single monotonic frame counter across all traffic (including PFS sessions), an observer can correlate PFS session traffic with the device's long-term identity by observing counter continuity. Implementations concerned with PFS unlinkability should consider using independent frame counters for PFS sessions. See [Wire-Level Privacy](security.md#wire-level-privacy).

### Hint Stability and Tracking

Because hints are derived deterministically from public keys, they remain stable for the lifetime of a node identity. An observer who associates a hint with a physical location or person can track that identity across sessions, power cycles, and network changes. The only countermeasure is generating a new identity (a new Ed25519 keypair), which requires all peers to re-learn the new public key.

## Cryptographic Design Rationale

### AES-SIV over AES-GCM

UMSH uses AES-SIV (RFC 5297) rather than AES-GCM. AES-GCM is catastrophically vulnerable to nonce reuse: a single repeated nonce leaks the authentication key and allows forgery of arbitrary messages. On a mesh network where counter management is distributed across many independent nodes and persistence across reboots is not guaranteed, nonce reuse is a realistic failure mode. AES-SIV degrades gracefully—nonce reuse reveals only whether two packets are identical, without compromising keys or enabling forgery. Deterministic SIV-style alternatives built on other primitives, such as ChaCha20-Poly1305-SIV, were considered, but none is as mature or as widely analyzed as RFC 5297. See the [FAQ](faq.md#why-use-aes-siv-instead-of-aes-gcm).

### AES-256 over AES-128

UMSH's asymmetric layer—Ed25519 identities and X25519 key agreement—provides roughly 128-bit classical security, so AES-128 would be a matched choice against classical adversaries, and a cheaper one on low-power hardware. UMSH uses AES-256 anyway, because the symmetric layer is the one part of the protocol that can meaningfully survive a quantum adversary.

No standardized post-quantum key exchange or signature scheme fits within a LoRa frame budget, so the asymmetric layer cannot be hardened against Shor's algorithm. Recovering a private key that way, however, requires the complete public key. Most UMSH traffic exposes only a 3-byte hint, and blind unicast conceals even a full first-contact source key inside the channel-encrypted address block. A deployment that avoids exposing full public keys and leans on shared channel keys therefore retains meaningful—though reduced—security against a quantum adversary: physical compromise of any channel member defeats it, but a purely over-the-air attacker is left facing the symmetric layer alone. That fallback is only as strong as the symmetric primitives, and Grover's algorithm halves a symmetric key's effective strength: AES-128 would be reduced to roughly 64-bit post-quantum strength, while AES-256 remains far out of reach. Choosing AES-256 preserves the symmetric fallback at the cost of extra cycles and code size on constrained devices.

### Stable Keys over Ratcheting

UMSH uses stable pairwise keys rather than a ratcheting protocol. Ratcheting provides forward secrecy per-message but requires synchronized state between sender and receiver. On a lossy, high-latency mesh where packets are routinely dropped, duplicated, or delivered out of order, ratchet state can desynchronize—potentially requiring expensive resynchronization exchanges over a slow radio link. UMSH's stable keys combined with per-packet counter and salt inputs provide per-packet IV uniqueness without requiring synchronized state. Optional [PFS sessions](security.md#perfect-forward-secrecy-sessions) provide forward secrecy when needed, without imposing ratcheting's fragility on all traffic. See the [FAQ](faq.md#why-does-umsh-use-stable-pairwise-keys-instead-of-a-ratcheting-scheme-like-the-signal-protocol).

### Single Keypair for Signing and Key Agreement

UMSH uses a single Ed25519 keypair per node for both identity (signing) and key agreement (via X25519 conversion). Standard guidance recommends separate keys, but the alternative would require distributing an additional 32-byte X25519 public key per identity and cryptographically binding it to the Ed25519 key. On a ~255-byte LoRa frame, this overhead is significant. The Ed25519/X25519 conversion is a well-understood, deterministic mapping over birationally equivalent curves, used by Signal's X3DH and libsodium. See [Ed25519 to X25519 Conversion](security.md#ed25519-to-x25519-conversion).

## Channel-Specific Considerations

### Named Channel Security

Named channels derive their key from a human-readable name via HKDF-Extract. Anyone who knows (or guesses) the name can derive the key. Named channels should be treated as public—they provide a shared namespace, not confidentiality. Long, high-entropy names offer practical obscurity but should not be relied upon for security.

### Replay of Unsigned Multicast

An [unsigned multicast](security.md#unsigned-multicast) is judged by duplicate suppression alone. Once a receiver's duplicate cache forgets a frame, by age or because later traffic displaced it, a replay of that frame is accepted as new. Anyone who recorded it can replay it, including a node without the channel key. A window kept per claimed source would refuse such a replay, but it would buy little: the channel key does not say who sent a frame, so any member could forge a new frame under any source anyway, and could push such a window past the claimed sender's counter and silence it. Traffic that must not be replayable after the fact should be signed, since a signed multicast is judged by its signer's receive window.

### Emergency Channel Integrity

The `EMERGENCY` channel requires unencrypted transmission, full source key (`S=1`), and a [frame signature](security.md#frame-signatures). These requirements ensure that emergency traffic is universally readable and cryptographically attributable. The [channel commitment](security.md#channel-commitment) keeps a signed emergency message from being replayed on another channel that shares its identifier, and [signed-frame counters](security.md#signed-frame-counters) keep it from being replayed on this one. A receiver also [remembers](multicast-channels.md#emergency) each signed frame it accepts on the channel for a day, so a replay is refused after the sender's window has been discarded. A receiver that has restarted, or whose record was full when the message arrived, can still accept one replay of a message whose sender's window it has discarded. However, an attacker with a valid Ed25519 keypair can still send fraudulent emergency messages—the signature proves only that the sender possesses the key, not that the emergency is real. Social and operational controls (e.g., reputation, identity verification) are needed to complement the cryptographic guarantees.

### Blind Unicast Key Binding

Blind unicast payload keys are [derived by XORing](security.md#blind-unicast-payload-keys) the pairwise unicast keys with the channel's multicast keys. This ensures that decrypting a blind unicast payload requires both the pairwise shared secret and the channel key. Compromise of one without the other is insufficient. 

## Contact Exchange

### Code Strength

A device in the middle of a [contact exchange](app-meet.md) must send its commitment before it learns the other side's nonce, and cannot change its nonce after it learns it. Each attempt therefore gives it one guess at making both holders see the same code: a one-in-a-million chance, paid for with an attempt both holders see fail. The code proves only that the two devices talking are the two in the holders' hands; it says nothing about the names those devices then send.

### Session Key Erasure

Session keys are ephemeral keys and fall under the same [erasure requirements](#ephemeral-key-erasure) as PFS session keys. Because a new key is drawn for every attempt, Nearby rows heard in one attempt cannot be linked by key to the next.

### Correlation That Remains

A Hello names a hardware model, and a rare model narrows who is nearby. The long-term identity keeps sending its ordinary traffic while a session is open, so an observer can correlate the two by timing and location.
