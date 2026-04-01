# Security Considerations

This chapter consolidates the security properties, limitations, and implementation guidance that are distributed throughout the specification. It is intended as a reference for implementers and reviewers evaluating UMSH's security posture.

## Threat Model

UMSH is designed for a shared radio medium where any device in range can observe and inject packets. The threat model assumes:

- **Passive eavesdroppers** can observe all traffic on the channel, including packet timing, size, hint values, and frame counters.
- **Active attackers** can inject, replay, modify, or selectively drop packets.
- **Compromised nodes** may leak their long-term private keys, channel keys, or both.

UMSH does **not** assume a trusted infrastructure, a reliable transport, or a synchronized clock.

## What UMSH Protects Against

**Eavesdropping.** When encryption is enabled, payload content is protected by AES-128-CTR keyed with material derived from ECDH (unicast) or the channel key (multicast). An observer without the relevant key cannot recover plaintext.

**Forgery.** All authenticated packets carry a MIC computed with AES-CMAC. An attacker who does not possess the encryption and authentication keys cannot produce a valid MIC. The [MIC size](security.md#security-control-field) determines the forgery resistance — from 2^-32 (4-byte MIC) to 2^-128 (16-byte MIC).

**Replay attacks.** Monotonically increasing [frame counters](security.md#frame-counters) allow receivers to detect and reject replayed packets. The [backward window and MIC cache](security.md#replay-detection) provide tolerance for out-of-order delivery without weakening replay protection.

**Nonce misuse.** The [AES-SIV-inspired construction](security.md#encrypted-packets) derives the CTR IV from the MIC, so accidental nonce reuse (e.g., due to a buggy counter implementation) does not produce the catastrophic plaintext leakage that would occur with AES-GCM or raw AES-CTR. In the worst case, an attacker can detect when two packets carry identical plaintext — the keys and other traffic remain uncompromised.

**Long-term key compromise (with PFS).** If a [PFS session](security.md#perfect-forward-secrecy-sessions) was active and the ephemeral keys were properly erased, traffic from that session cannot be retroactively decrypted even if the long-term private keys are later compromised.

## What UMSH Does Not Protect Against

**Traffic analysis.** A passive observer can see packet timing, frequency, size, hint values, frame counters, and flood hop counts — all in the clear. This reveals communication patterns (who is active, how often, rough network topology) even when payloads are encrypted. Hint values are stable for a given identity, enabling long-term tracking of a node's activity.

**Multicast sender impersonation.** Multicast authentication is based on the shared channel key. Any node possessing the key can construct a valid packet with any claimed source address. Other channel members cannot cryptographically distinguish the true sender from an impersonator. See [Multicast Sender Authentication](limitations.md#multicast-sender-authentication).

**Selective packet dropping.** A compromised or malicious repeater can selectively drop packets without detection. UMSH provides no mechanism to verify that a repeater faithfully forwarded a packet. The flood routing model provides redundancy (multiple paths), but a strategically positioned adversary can still disrupt delivery.

**Denial of service.** An attacker can flood the radio channel with valid-looking packets, forcing receivers to expend computation on cryptographic verification. The 3-byte destination hint reduces this cost (only ~1 in 16,777,216 unicast packets will trigger verification for any given node), but the shared medium provides no isolation. The `EMERGENCY` channel's priority forwarding could be abused to amplify DoS traffic, though the signature requirement limits this to attackers who possess a valid Ed25519 keypair.

**Traffic amplification via broadcast or multicast requests.** A broadcast packet is unauthenticated by design, and a multicast packet may be attributable only to a shared channel key or an ephemeral source identity. An attacker can exploit this by sending a request that appears to warrant a response or some other follow-on action from every receiving node. If the request does not include a trace-route option, recipients do not learn a specific return path. Any per-node reply may therefore fall back to flood routing, using the inbound `FHOPS_ACC` as a distance estimate or flooding more broadly if no better routing state exists. The result is an amplification attack: one injected request can trigger many independent flood-routed responses, consuming airtime and effectively causing a distributed denial of service. Implementations and application protocols must therefore treat broadcast and multicast requests as fan-out hazards. They should not automatically generate per-node responses unless those responses are explicitly designed to avoid amplification through mechanisms such as route learning, strict rate limits, randomized suppression, aggregation, or making the request one-way only.

**Non-repudiation.** UMSH's MIC is computed with symmetric pairwise keys that both sender and recipient possess, so a recipient cannot cryptographically prove to a third party who authored a given packet — either party could have constructed it. However, UMSH does not claim to provide deniability. Real-world deniability depends on the entire system: usage patterns, device forensics, metadata, and interactions with other systems. The symmetric MIC is a narrow property, not a deniability guarantee. When the application layer includes an EdDSA signature in the payload (as required by the `EMERGENCY` channel), even this narrow property is lost — a signature can only be produced by the private key holder.

**Forward secrecy without PFS sessions.** Normal unicast traffic uses stable pairwise keys derived from long-term ECDH. If a node's long-term private key is compromised, all past and future unicast traffic with that node can be decrypted. Forward secrecy requires explicit use of [PFS sessions](security.md#perfect-forward-secrecy-sessions).

**Anonymous channel membership.** Possessing a channel key is both necessary and sufficient for channel membership. There is no mechanism to verify *who* holds a key, revoke access to a specific node without re-keying the entire channel (except via [managed channels](multicast-channels.md#managed-channels)), or detect how many members a channel has.

## Implementation Requirements

The following requirements are critical for security. Failure to implement any of them correctly can compromise the properties described above.

### Frame Counter Monotonicity

The frame counter must strictly increase for each packet sent in a given traffic direction. Reusing a counter value with the same key undermines replay protection and, in the worst case, can leak information about plaintext differences (though the AES-SIV construction limits the damage). See [Frame Counters](security.md#frame-counters).

### Frame Counter Persistence

A node must not reuse frame counter values across reboots. Implementations must either persist the counter to non-volatile storage or advance it by a large margin on startup. If writing to non-volatile storage, care must be taken to avoid wearing out the storage medium. See [Counter Persistence](security.md#counter-persistence) and [Counter Resynchronization](security.md#counter-resynchronization).

### Ephemeral Key Erasure

PFS sessions derive their security from the guarantee that ephemeral private keys are erased when the session ends. Implementations must ensure that ephemeral keys are:

- Never written to persistent storage, swap files, or logs
- Explicitly zeroed in memory upon session termination (not just freed — freed memory may not be overwritten promptly)
- Not retained in core dumps or crash reports

Failure to erase ephemeral keys eliminates the forward secrecy property entirely. See [Key Erasure](security.md#key-erasure).

### Constant-Time MIC Verification

MIC comparison must use constant-time comparison (e.g., a fixed-iteration XOR-and-OR loop) rather than `memcmp` or similar short-circuiting functions. A timing side channel in MIC verification allows an attacker to incrementally guess MIC bytes by measuring response time.

### Public Key Validation

Implementations must reject malformed Ed25519 public keys before converting them to X25519 form. Accepting a malformed key can produce a low-order X25519 point, resulting in a shared secret of zero — which would cause all pairwise keys to be identical across different peers. See [Ed25519 to X25519 Conversion](security.md#ed25519-to-x25519-conversion).

### Reserved Bits

Packets with non-zero reserved bits in the [Security Control Field](security.md#security-control-field) must be dropped. Accepting unknown bit patterns could indicate a protocol version mismatch or a malformed packet; processing them risks undefined behavior.

## Metadata Exposure

Even with encryption enabled, the following information is visible to a passive observer. Which fields are present depends on the packet type:

| Field | Packet types | What it reveals |
|---|---|---|
| Packet timing and frequency | All | Communication patterns — when a node is active, how often it transmits |
| Destination hint (3 bytes) | Unicast | Stable per-identity; enables tracking a node's correspondents over time |
| Source hint (1 byte, unicast; 3 bytes, broadcast/multicast) | Unicast, unencrypted multicast, broadcast | Stable per-identity; enables tracking a node's activity over time |
| Channel identifier (2 bytes) | Multicast, blind unicast | Stable per-channel; reveals which channel a packet belongs to |
| Frame counter | All authenticated | Monotonically increasing; reveals total packet count and transmission rate |
| Flood hop count | All with FHOPS | Reveals approximate distance from the original sender |
| Packet size | All | May correlate with payload type or content length |
| MIC | All authenticated | Unique per-packet; usable as a packet fingerprint for correlation across hops |

In encrypted multicast, the source address is encrypted inside the ciphertext. In blind unicast, both the source and destination addresses are encrypted using the channel key — only the channel identifier remains in the clear. Normal unicast exposes both the destination hint and source hint (or full source key) to passive observers.

### Frame Counter Correlation and PFS

If a device uses a single monotonic frame counter across all traffic (including PFS sessions), an observer can correlate PFS session traffic with the device's long-term identity by observing counter continuity. Implementations concerned with PFS unlinkability should consider using independent frame counters for PFS sessions. See [Wire-Level Privacy](security.md#wire-level-privacy).

### Hint Stability and Tracking

Because hints are derived deterministically from public keys, they remain stable for the lifetime of a node identity. An observer who associates a hint with a physical location or person can track that identity across sessions, power cycles, and network changes. The only countermeasure is generating a new identity (a new Ed25519 keypair), which requires all peers to re-learn the new public key.

## Cryptographic Design Rationale

### AES-SIV over AES-GCM

UMSH uses an AES-SIV-inspired construction rather than AES-GCM. AES-GCM is catastrophically vulnerable to nonce reuse: a single repeated nonce leaks the authentication key and allows forgery of arbitrary messages. On a mesh network where counter management is distributed across many independent nodes and persistence across reboots is not guaranteed, nonce reuse is a realistic failure mode. The AES-SIV construction degrades gracefully — nonce reuse reveals only whether two plaintexts are identical, without compromising keys or enabling forgery. See the [FAQ](faq.md#why-aes-siv-instead-of-aes-gcm).

### Stable Keys over Ratcheting

UMSH uses stable pairwise keys rather than a ratcheting protocol. Ratcheting provides forward secrecy per-message but requires synchronized state between sender and receiver. On a lossy, high-latency mesh where packets are routinely dropped, duplicated, or delivered out of order, ratchet state can desynchronize — potentially requiring expensive resynchronization exchanges over a slow radio link. UMSH's stable keys combined with per-packet counter and salt inputs provide per-packet IV uniqueness without requiring synchronized state. Optional [PFS sessions](security.md#perfect-forward-secrecy-sessions) provide forward secrecy when needed, without imposing ratcheting's fragility on all traffic. See the [FAQ](faq.md#why-doesnt-umsh-use-a-ratcheting-protocol-for-forward-secrecy).

### Single Keypair for Signing and Key Agreement

UMSH uses a single Ed25519 keypair per node for both identity (signing) and key agreement (via X25519 conversion). Standard guidance recommends separate keys, but the alternative would require distributing an additional 32-byte X25519 public key per identity and cryptographically binding it to the Ed25519 key. On a ~255-byte LoRa frame, this overhead is significant. The Ed25519/X25519 conversion is a well-understood, deterministic mapping over birationally equivalent curves, used by Signal's X3DH and libsodium. See [Ed25519 to X25519 Conversion](security.md#ed25519-to-x25519-conversion).

## Channel-Specific Considerations

### Named Channel Security

Named channels derive their key from a human-readable name via HKDF-Extract. Anyone who knows (or guesses) the name can derive the key. Named channels should be treated as public — they provide a shared namespace, not confidentiality. Long, high-entropy names offer practical obscurity but should not be relied upon for security.

### Emergency Channel Integrity

The `EMERGENCY` channel requires unencrypted transmission, full source key (`S=1`), and an EdDSA payload signature. These requirements ensure that emergency traffic is universally readable and cryptographically attributable. However, an attacker with a valid Ed25519 keypair can still send fraudulent emergency messages — the signature proves only that the sender possesses the key, not that the emergency is real. Social and operational controls (e.g., reputation, identity verification) are needed to complement the cryptographic guarantees.

### Blind Unicast Key Binding

Blind unicast payload keys are [derived by XORing](security.md#blind-unicast-payload-keys) the pairwise unicast keys with the channel's multicast keys. This ensures that decrypting a blind unicast payload requires both the pairwise shared secret and the channel key. Compromise of one without the other is insufficient. 