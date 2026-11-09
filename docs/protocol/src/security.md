# Security & Cryptography

UMSH authenticates and optionally encrypts packets using AES-SIV (RFC 5297) with AES-256. Unicast packets are secured with pairwise keys derived from X25519 ECDH between sender and recipient Ed25519 keys. Multicast packets are secured with keys derived from the shared channel key. A monotonic frame counter provides replay protection without requiring synchronized clocks, for every frame authenticated as one sender's; an [unsigned multicast](#unsigned-multicast), which any channel member could have sent, is judged by duplicate suppression instead. Any frame other than a MAC ack may also carry an Ed25519 [frame signature](#frame-signatures) that attributes it to its sender's key.

Each secured packet carries a Security Information (SECINFO) field containing a Security Control Field, a frame counter, and an optional salt. The sections below describe these fields, the key derivation process, and the cryptographic operations applied to each packet.

## Security Information (SECINFO)

### SECINFO Encoding

```text
+--------+--------------------+----------------+
|  SCF   | FRAME COUNTER (4B) | [SALT (2B)]    |
+--------+--------------------+----------------+
   1 B            4 B              0/2 B
```

### Security Control Field

```text
  7   6   5   4   3   2   1   0
+---+-------+---+---+-----------+
| E |  MIC  | S | D | RESERVED  |
+---+-------+---+---+-----------+
 1b   2 bits 1b  1b    3 bits
```

Where:

- `E` = encrypted payload flag
- `MIC` = MIC size code
- `S` = salt included
- `D` = signed: a 64-byte [frame signature](#frame-signatures) follows the payload
- `RESERVED` = must all be set to zero

If the `RESERVED` bits read as anything other than zero, the packet MUST be dropped by the recipient.

MIC size encodings:

| Value | MIC Length |
|------:|------------|
| 0     | 4 bytes    |
| 1     | 8 bytes    |
| 2     | 12 bytes   |
| 3     | 16 bytes   |

The MIC is produced by computing the full 16-byte synthetic IV `V` with S2V (RFC 5297 §2.4) and truncating to the specified length. The S2V output is an AES-CMAC, and truncation of CMAC outputs is permitted by NIST SP 800-38B.

#### MIC Size Selection Guidance

Shorter MICs save bytes on the wire but reduce forgery resistance and increase the probability of duplicate-suppression collisions in repeater caches (see [Duplicate Suppression](repeater-operation.md#duplicate-suppression)). The following guidelines help choose an appropriate MIC size:

- **16 bytes** (default): Recommended for long-term stable identities where the same pairwise keys may be used for months or years. The cost of a successful forgery is high (attacker gains persistent access to impersonate a node), and the 2^-128 forgery probability makes brute-force infeasible regardless of how many packets an attacker can attempt.

- **8 bytes**: A reasonable middle ground for most communication. Provides 2^-64 forgery probability—well beyond practical brute-force for LoRa's low packet rates—while saving 8 bytes per packet. Suitable for general unicast and multicast traffic.

- **4 bytes**: Appropriate for short-lived contexts where the keys will be discarded soon, such as [PFS sessions](#perfect-forward-secrecy-sessions) or one-time exchanges using ephemeral node addresses. The 2^-32 forgery probability (~1 in 4 billion) is adequate when the window of exposure is brief. Also useful for latency-sensitive or payload-constrained scenarios where every byte matters, such as sensor telemetry on slow LoRa links.

- **12 bytes**: Available as an intermediate option when 8 bytes feels too tight but 16 bytes is more overhead than warranted. Provides 2^-96 forgery probability.

As a general principle: the longer the keys will be in use and the higher the value of the traffic they protect, the larger the MIC should be. For ephemeral keys that will be erased within minutes, a small MIC is sufficient. For a node's long-term identity keys, prefer the full 16 bytes.

### Frame Counter

The 4-byte frame counter must increase monotonically. UMSH uses this monotonic counter—rather than timestamps—for replay protection, keeping the protocol free of any dependency on synchronized clocks or absolute time.

A node address draws the counters of all its secured and signed frames—unicast, blind unicast, multicast, and [signed broadcast](packet-options.md#frame-signature-option-0)—from one monotonic sequence, and MUST NOT let that sequence go backward (see [Counter Persistence](#counter-persistence)). A receiver judges every frame authenticated as a peer's, whether pairwise or by a frame signature, against one baseline for that peer, so the sequence belongs to the sending address, not to a destination or channel.

#### Replay Detection

A receiver determines whether a frame counter is acceptable by computing:

```text
delta = (received_counter - last_accepted_counter) mod 2^32
```

If `delta` is zero or exceeds the forward window, the packet is rejected. This modular comparison allows the counter to wrap around `2^32` without requiring special overflow handling. The suggested default forward window is **172800**. Implementations MAY use a different value, but it should be large enough to accommodate gaps from packets sent to other destinations and small enough to limit the scope of replay attacks.

Implementations that need to tolerate out-of-order delivery may also define a **backward window**—a small range of counter values *behind* the highest accepted counter within which late-arriving packets are still considered. The suggested default backward window is **8**. When a packet's counter falls within the backward window, the receiver checks a small cache of recently accepted packets, keyed by frame counter and MIC (similar to the approach used for [duplicate suppression](repeater-operation.md#duplicate-suppression) in repeaters): if the packet is already present, it is a replay and is rejected; if not, the packet is accepted and added to the cache.

A sender SHOULD NOT have more acknowledgement-requested packets awaiting acknowledgement from one peer than the suggested backward window, so that a retransmission of the earliest still falls inside the receiver's window when nothing else was sent in between. A retransmission that the sender's other traffic pushed further behind is recovered by [counter resynchronization](#counter-resynchronization).

Regardless of window sizes, a packet must not be accepted if it is more than **5 minutes** out of order—that is, if the highest accepted counter was last advanced more than 5 minutes ago and the received counter is behind it. MIC cache entries only need to be retained for the duration of this time bound. Additionally, the first packet accepted from a given node (or after a [counter resynchronization](#counter-resynchronization)) establishes that node's counter baseline—packets with earlier counter values must be rejected, even if they arrive within the backward window.

##### Duplicate Acknowledgement Window {#duplicate-acknowledgement-window}

Rejecting a packet as a duplicate does not prohibit retransmitting its MAC
acknowledgement. An authenticated packet that requests an acknowledgement and
whose MIC identifies it as a previously received packet **MAY** be acknowledged
again if its frame counter is no more than **8** counts behind the highest
accepted counter from that sender, inclusive. Equivalently:

```text
ack_distance = (last_accepted_counter - received_counter) mod 2^32
```

The duplicate may be acknowledged only when `ack_distance <= 8`. A receiver
**MUST NOT** acknowledge a replay farther behind the stored counter. Re-sending
the acknowledgement is idempotent and allows a sender to recover when the
original acknowledgement was lost; it does not accept the packet as new and
**MUST NOT** advance or otherwise modify the stored replay baseline. A receiver
may suppress duplicate delivery itself. In a split implementation, such as a
companion radio and host MAC, it may instead pass the authenticated duplicate to
the host, which is then responsible for suppressing duplicate application
delivery.

Eligibility is not obligation: re-acknowledgement SHOULD be paced. Flood
routing delivers one transmission as several copies, and a copy of a
transmission whose acknowledgement was already sent proves nothing was lost. A
receiver SHOULD NOT acknowledge the same packet more than once per
[forwarding-confirmation
window](repeater-operation.md#forwarding-confirmation), measured from its most
recent acknowledgement of that packet: copies arriving inside the window share
the acknowledgement already sent, while a sender that lost its acknowledgement
cannot retransmit before its own confirmation window has lapsed.

A duplicate that carries the [Route Retry option](packet-options.md#route-retry-option-6), of a packet already acknowledged and arriving after this window, shows that the acknowledgement was lost on its way back. Its re-acknowledgement SHOULD NOT follow the route the lost one took ([Lost Acknowledgments](repeater-operation.md#lost-acknowledgments)). Any other late duplicate may have crossed an acknowledgement still in transit and says nothing about the route.

Payload acceptance does not begin the acknowledgement pacing window. A destination may accept an overheard source-routed copy while hints remain, withholding its ACK until the route is consumed. The first eligible copy may then be acknowledged immediately. A duplicate remains the same accepted packet: acknowledging it does not renew its replay-retention interval or deliver the payload again.

##### Signed-Frame Counters {#signed-frame-counters}

A frame whose [frame signature](#frame-signatures) verifies is judged by the rules above against its signer's counter, and is either accepted or dropped. The cache of recently accepted packets keys a signed broadcast, which has no MIC, by its frame counter and the first 16 bytes of its signature.

- **Known peer.** A frame signed by a known peer is checked against that peer's receive baseline, the one its unicast traffic is checked against. Because the peer draws every counter from [one sequence](#frame-counter), its signed multicast and broadcast frames continue the sequence its unicast frames follow.
  - An accepted frame advances the baseline, which is [persisted](#counter-persistence) as for unicast.
  - A replay is dropped.
  - A frame behind the baseline or outside the forward window is dropped. Unless the receiver recognizes it as a late copy of a frame it accepted, it MAY start [counter resynchronization](#counter-resynchronization) with an Echo Request, at the usual rate limit.
- **Stranger.** A frame that verifies against a key that is not a known peer's is first contact: it is accepted at face value, as [Counter Resynchronization](#counter-resynchronization) describes for any new peer. Later frames from that key are judged by the same rules, in a window the receiver keeps for that signing key. A frame behind that window's baseline or outside it is dropped, with no resynchronization, since there is no pairwise relationship to run one over.
  - A receiver MAY discard a stranger's window when it is idle or under memory pressure.
  - A key costs nothing to mint, so a burst of first contacts could otherwise discard every stranger's window on demand. A receiver SHOULD bound how many strangers' windows new signers displace; the suggested bound is **4** every **10 minutes**. No window is kept for a new signer whose frame arrives once the bound is spent; its frames are judged as an [unsigned multicast](#unsigned-multicast) is, by duplicate suppression alone.
  - After a discard, or after the receiver restarts, the stranger's next frame is first contact again, so a replay of one of its earlier frames is accepted once. With no prior knowledge of the sender, a receiver cannot tell that replay from a new frame.

##### Unsigned Multicast {#unsigned-multicast}

A multicast without a frame signature, or whose signature does not verify, is authenticated only as the work of some holder of the channel key: its `SRC` names a sender any other member could have named. A receiver judges it by duplicate suppression alone, keyed by its MIC and by nothing a forwarder may rewrite: a multicast whose MIC matches one already accepted is a replay, with or without a [Route Retry option](packet-options.md#route-retry-option-6).

An unsigned multicast MUST NOT advance or otherwise modify any replay state kept for the source it names. A member able to move that state could send one frame under another member's source, with a counter far ahead of that member's, and so silence it.

Once a receiver's duplicate-suppression entry for a multicast ages out or is displaced, a replay of that multicast is accepted as new. See [Replay of Unsigned Multicast](security-considerations.md#replay-of-unsigned-multicast).

#### Counter Persistence

How a node persists and recovers its own frame counter across reboots is implementation-specific. Possible strategies include writing the counter to non-volatile storage periodically or advancing the counter by a large margin on startup to avoid replaying previously used values. A node MUST advance its counter on startup by less than the suggested forward window: a larger jump puts its next frame outside every peer's window, and each peer must resynchronize before accepting it.

A node MUST also persist each known peer's receive baseline and restore it at startup. A node that lost a peer's baseline would treat that peer's next frame as first contact and accept a replay of any earlier one.

- The persisted baseline MAY lag the live one, so that writes can be batched. A node SHOULD write a peer's baseline once it has accepted 16 frames from that peer since the last write, however far those frames moved the counter. The frames accepted since the last successful write are what an unexpected restart leaves replayable.
- Before a deliberate restart, a node SHOULD write every baseline that has changed since its last write.

> [!CAUTION]
> If counters or baselines are written to non-volatile storage, care should
> be taken to avoid wearing out the underlying storage medium if it has a
> limited number of writes.

#### Counter Resynchronization

On first contact with a new peer, the received frame counter is accepted at face value and recorded as the baseline for future replay detection.

An authenticated packet from a known peer whose frame counter falls outside the window, or in an unspent slot of the backward window past the 5-minute bound, means the two nodes disagree about that counter, whatever the gap—for example, because the peer rebooted and lost its persisted counter, or because a retransmission fell behind the backward window. A packet whose counter the backward window records as spent is a replay at any age, and one the receiver still recognizes by its counter and MIC as one it accepted is only a late copy; neither prompts anything. For any other, the receiver MAY re-establish a baseline with one of the two exchanges below. It SHOULD send at most one such probe to a peer every **5 seconds**, and a [Verify Frame](mac-commands.md#verify-frame-12) or [Frame Verified](mac-commands.md#frame-verified-13) never prompts one.

When the packet requested an acknowledgement, the receiver—the requester—holds it without acknowledging it and sends Verify Frame to the peer, naming the packet in an [Ack MIC option](packet-options.md#ack-mic-option-8). The peer—the responder—proceeds as follows:

1. It matches the option against the acknowledgement-requested packets it sent to the requester that are still awaiting acknowledgement. If none matches, it ignores the Verify Frame.
2. It stops retransmitting the matched packet and answers with Frame Verified, which requests an acknowledgement.
3. When Frame Verified is acknowledged, it treats the matched packet as acknowledged. If Frame Verified is never acknowledged, the matched packet has failed.

The responder processes a Verify Frame whose own counter falls outside its window for the requester, since the match with an outstanding packet already shows the request is fresh. When Frame Verified is acknowledged, it adopts that counter as the requester's new baseline. A Verify Frame whose counter falls within the window is subject to the ordinary replay rules.

When a Frame Verified arrives echoing the nonce of a Verify Frame for a packet the requester still holds, the requester adopts its frame counter as the peer's new baseline, whatever the value. It then delivers the held packet and acknowledges Frame Verified; that acknowledgement stands for the held packet too, which is not acknowledged separately. A requester that no longer holds the packet discards Frame Verified without acknowledging it, so the responder reports the packet as failed. The requester MUST choose nonces so that a Frame Verified recorded from an earlier exchange cannot match a later one. A requester cannot tell a held packet from one it accepted earlier and no longer recognizes, so a packet whose acknowledgement was lost can be delivered a second time this way.

When the packet did not request an acknowledgement, the peer has nothing outstanding to match, so the receiver MAY instead send an [Echo Request](mac-commands.md#echo-request-4) carrying a nonce. An Echo Response echoing it establishes the response's frame counter as the peer's new baseline. The packet that prompted the probe is dropped.

When that packet is itself an Echo Request, the receiver answers it with an Echo Response before sending its own probe, and only when it sends the probe, so the answer shares the probe's rate limit. Two nodes each outside the other's window would otherwise refuse each other's probes indefinitely. The Echo Request is accepted no further: it is not delivered, and it moves no baseline.


### Salt

The optional 2-byte salt is chosen randomly to reduce the likelihood of a nonce collision.

## Cryptographic Processing

### Unicast Key Agreement

For unicast and blind unicast:

1. Start with sender Ed25519 keypair and recipient Ed25519 keypair.
2. Convert both Ed25519 keys to X25519 form.
3. Perform X25519 ECDH.
4. Feed the resulting shared secret into HKDF-SHA256, bound to both parties' Ed25519 public keys.
5. Derive separate stable pairwise keys for encryption and MIC/authentication.

### Ed25519 to X25519 Conversion

UMSH uses a single Ed25519 keypair per node as both its identity (for addressing) and the basis for key agreement. Standard cryptographic guidance recommends separate keys for signing and key agreement, so this choice warrants justification.

The Ed25519 and X25519 curves are birationally equivalent (both are defined over Curve25519), and the conversion between Edwards and Montgomery form is a well-understood, deterministic mapping. Using a single keypair for both purposes is not itself insecure—it is the approach taken by, among others, the Signal protocol's X3DH key agreement and libsodium's `crypto_sign_ed25519_pk_to_curve25519` API.

The alternative—carrying separate Ed25519 (signing) and X25519 (key agreement) keys per node—would require a cryptographic binding between the two. Each node must distribute an additional 32-byte X25519 public key alongside its Ed25519 key, and the binding must be authenticated (e.g. by including the X25519 key in a signed advertisement). Every recipient must then verify that binding before trusting the key agreement key. On a LoRa link where the entire frame budget is ~255 bytes, even 32 extra bytes per identity exchange is a significant cost. By deriving X25519 keys from Ed25519 keys, UMSH eliminates this overhead entirely: the node address *is* the key agreement key, with no additional key distribution required.

UMSH assumes standard Edwards-to-Montgomery conversion:

- sender Ed25519 private key → sender X25519 private key
- sender Ed25519 public key → sender X25519 public key
- recipient Ed25519 private key → recipient X25519 private key
- recipient Ed25519 public key → recipient X25519 public key

Implementations MUST reject malformed public keys before conversion. A public key is accepted only if re-encoding its decoded point yields the same 32 bytes, which rejects non-canonical encodings of a point.

### ECDH Shared Secret

The ECDH shared secret is:

```text
ss = X25519(local_x25519_private, remote_x25519_public)
```

This shared secret is used as the input keying material for deriving the cryptographic keys to secure and authenticate messages.

### HKDF Inputs for Unicast

For unicast packets, the encryption and MIC keys are derived from the X25519 ECDH shared secret and both nodes' Ed25519 public keys, and are stable for a given pair of nodes. These keys are not derived from packet-specific fields.

Let:

```text
ss = X25519(local_x25519_private, remote_x25519_public)
```

The pairwise key material is then derived as:

```text
ikm  = ss
salt = "UMSH-PAIRWISE-SALT"
info = "UMSH-UNICAST-V3" || min(PK_a, PK_b) || max(PK_a, PK_b)
okm  = HKDF-SHA256(ikm, salt, info, 64)
```

`PK_a` and `PK_b` are the two nodes' 32-byte Ed25519 public keys, ordered by comparing their encodings lexicographically, so both ends derive the same keys. Binding the full keys gives each key its own pairwise keys: an Ed25519 key and its negation convert to the same X25519 key and so produce the same shared secret, but not the same `info`.

The output keying material is split as follows:

```text
K_mic = okm[0..32]
K_enc = okm[32..64]
```

Where:

- `K_mic` is the 32-byte message authentication key (the S2V key)
- `K_enc` is the 32-byte encryption key (the CTR key)

This layout makes `okm` exactly the AES-SIV key `K` from RFC 5297: `K_mic` is the leftmost half `K1` (S2V) and `K_enc` is the rightmost half `K2` (CTR), so `okm` can be handed directly to an AEAD_AES_SIV_CMAC_512 implementation.

These keys are stable for the sender/recipient pair and may be cached by the implementation. They do not change from packet to packet.

Because the key derivation depends only on the ECDH shared secret, the two public keys, and fixed UMSH-specific HKDF parameters, it does not need to be recomputed for each transmitted packet.

### Blind Unicast Payload Keys

Blind unicast payload encryption and authentication must require knowledge of *both* the pairwise shared secret and the channel key. This ensures that an attacker who compromises one of the two secrets—but not both—cannot decrypt blind unicast payloads.

The blind unicast payload keys are derived by XORing the pairwise unicast keys (see [HKDF Inputs for Unicast](#hkdf-inputs-for-unicast)) with the channel's multicast keys (see [Multicast Packet Keys](#multicast-packet-keys)):

```text
K_enc_blind = K_enc_pairwise XOR K_enc_channel
K_mic_blind = K_mic_pairwise XOR K_mic_channel
```

Where:

- `K_enc_pairwise`, `K_mic_pairwise` are the stable pairwise keys derived from the sender/recipient ECDH shared secret
- `K_enc_channel`, `K_mic_channel` are the stable channel keys derived from the channel key

Both sets of input keys are independent HKDF outputs—pseudorandom and uncorrelated. XOR of two independent uniform random values is uniform random: an attacker who knows only one side sees the combined key as informationally equivalent to a one-time pad over the unknown side.

These combined keys are stable for a given (sender, recipient, channel) triple and may be cached. If the same two nodes use blind unicast over different channels, they get different payload keys—compromise of one channel key does not expose blind unicast traffic on another channel between the same pair.

Both the pairwise and channel keys can be cached independently by the implementation. Computing the blind unicast keys requires only a 32-byte XOR per key, with no additional HKDF calls.

### Per-Packet Security Inputs

Although `K_enc` and `K_mic` are stable for a given node pair, each packet still carries per-packet security inputs in `SECINFO`.

These inputs are:

- the 4-byte frame counter
- the optional 2-byte salt

These values are not used to derive the pairwise keys. Instead, they are used as packet-specific inputs to encryption, authentication, and replay protection.

For encrypted packets:

- `K_enc` and `K_mic` are the stable pairwise keys
- `SECINFO` and other immutable header fields are supplied as associated data
- the frame counter and optional salt provide packet-specific variability and replay-detection context

For authenticated but unencrypted packets:

- `K_mic` is the stable pairwise MIC key
- the MIC is computed over the protected packet contents and relevant static fields

The frame counter must increase monotonically for a given sending address (see [Frame Counter](#frame-counter)). Receivers must not rely on the construction's resistance to nonce misuse as a substitute for replay detection.

### Multicast Packet Keys

For multicast, the configured channel key is the base secret. The encryption and authentication keys are derived once and are stable for a given channel.

```text
ikm  = channel_key
salt = "UMSH-MCAST-SALT"
info = "UMSH-MCAST-V2" || channel_id
okm  = HKDF-SHA256(ikm, salt, info, 64)

K_mic = okm[0..32]
K_enc = okm[32..64]
```

As with the pairwise keys, `okm` is exactly the RFC 5297 AES-SIV key for the channel: S2V key first, CTR key second.

These keys are stable for the channel and may be cached by the implementation. They do not change from packet to packet. Per-packet variability is provided by the frame counter and optional salt in SECINFO, which serve as inputs to encryption and replay detection (see [Per-Packet Security Inputs](#per-packet-security-inputs)).

### Encrypted Packets

When encryption is enabled, UMSH uses **AES-SIV (RFC 5297) with AES-256**.

The processing is:

1. Compute the full 16-byte synthetic IV `V = S2V(K_mic, S1, S2)` per RFC 5297 §2.4, where `S1` is the canonical associated data (see [Associated Data](#associated-data)) and `S2` is the plaintext.
2. Truncate `V` to the MIC length specified by the SCF; this is the on-wire MIC.
3. Construct the CTR IV from the MIC (see [CTR IV Construction](#ctr-iv-construction)).
4. Encrypt the plaintext using **AES-256-CTR** with `K_enc` and the constructed IV. The counter is the full 16-byte IV, incremented as a 128-bit big-endian integer (RFC 5297 §2.5).

The plaintext `S2` is the region of the packet after its options and before its MIC:

| Family | `S2` |
|---|---|
| Unicast | `PAYLOAD [‖ SIG]` |
| Multicast | `SRC ‖ PAYLOAD [‖ SIG]` |
| Blind unicast | `PAYLOAD [‖ SIG]` |

`SIG` is the [frame signature](#frame-signatures), present when the SCF's `D` bit is set. Blind unicast's address block is not part of `S2`: it is covered through the [associated data](#associated-data) and encrypted separately (see [Blind Unicast Address Encryption](#blind-unicast-address-encryption)).

The MIC is transmitted at the end of the packet rather than prepended as in RFC 5297, allowing its length to be controlled independently via the SCF MIC size field.

With a 16-byte MIC, the result is byte-for-byte **AEAD_AES_SIV_CMAC_512** (RFC 5297 §6.3): the key is `K = K_mic || K_enc`, the canonical AAD is the single associated-data component, and the CTR IV construction reduces to the RFC's initial counter `Q`. Shorter MIC lengths use the same computation and differ only in how the CTR IV is filled.

As in RFC 5297, the synthetic IV binds the ciphertext to the key, associated data, and plaintext, so there is no caller-supplied nonce to misuse: repeating all three inputs yields an identical packet and reveals only the repetition itself. Truncated MICs weaken this bound in proportion to the truncation, since the CTR IV is reconstructed from the truncated MIC and SECINFO rather than the full `V`.

### CTR IV Construction

The 16-byte CTR IV is constructed by appending the SECINFO field to the MIC, zero-padding or truncating the result to exactly 16 bytes, and then clearing the top bit of bytes 8 and 12 as RFC 5297 §2.6 does when forming the initial counter:

```text
IV     = truncate_or_pad_to_16( MIC || SECINFO )
IV[8]  = IV[8]  & 0x7F
IV[12] = IV[12] & 0x7F
```

The bit-clearing step is applied unconditionally, whatever bytes—MIC, SECINFO, or zero padding—occupy positions 8 and 12.

For the 16-byte MIC, SECINFO is entirely truncated away and the IV is the masked synthetic IV—exactly the initial counter `Q` from RFC 5297 §2.6. For shorter MICs, the IV incorporates the frame counter and optional salt from SECINFO, providing additional per-packet IV variability.

| MIC Length | SECINFO (5 B) | SECINFO (7 B) | SECINFO bytes in IV |
|---:|---|---|---|
| 16 B | truncate to 16 | truncate to 16 | 0 (IV = masked MIC) |
| 12 B | truncate to 16 | truncate to 16 | 4 |
| 8 B | zero-pad to 16 | zero-pad to 16 | 5 or 7 |
| 4 B | zero-pad to 16 | zero-pad to 16 | 5 or 7 |

### Unencrypted Packets

When encryption is disabled, the MIC is computed exactly as for encrypted packets—the truncated `S2V(K_mic, S1 = AAD, S2)`, with the same `S2`—and the encryption step is simply omitted. An unencrypted multicast's `SRC` is therefore covered as part of `S2`, just as when it is encrypted.

### Associated Data

The associated data (AAD) binds the immutable header fields to the MIC so that any modification is detected. The canonical AAD enters S2V as the single associated-data component `S1`; the plaintext `S2` (see [Encrypted Packets](#encrypted-packets)) is the final component.

The AAD is the packet's header fields in wire order, with these differences:

- `FHOPS` is omitted, and the FCF enters with its flood-hops-present (`H`) bit cleared.
- The static options are re-encoded as type-length-value triples (see below) and dynamic options are omitted.
- The options are followed by the 2-byte terminator `FF FF`, which is present even when there are no static options.
- Blind unicast's address block, `DST ‖ SRC`, follows the terminator in plaintext form, whether or not it is encrypted on the wire.
- Multicast's `SRC` is not part of the AAD. It is part of `S2`, with either value of `E`.

Addresses enter as they appear on the wire: a hint as a 3-byte hint, and a full key only where the packet carries one.

| Family | AAD |
|---|---|
| Broadcast | `FCF ‖ SRC ‖ options ‖ FF FF` |
| MAC ack (`AAD_ack`) | `FCF ‖ options ‖ FF FF` |
| Unicast | `FCF ‖ DST ‖ SRC ‖ SECINFO ‖ options ‖ FF FF` |
| Multicast | `FCF ‖ CHANNEL ‖ SECINFO ‖ options ‖ FF FF` |
| Blind unicast | `FCF ‖ CHANNEL ‖ SECINFO ‖ options ‖ FF FF ‖ DST ‖ SRC` |

No AAD depends on `E`: two packets that differ only in `E` have AADs that differ only in the SCF byte. A broadcast has no MIC; its AAD is used only by a [frame signature](#frame-signatures).

The AAD is unambiguous because the packet format is self-describing from left to right. The FCF decides which fields are present, and its `S` bit gives `SRC`'s length; SECINFO's own SCF gives its length. On the wire the options block is delimited by its `0xFF` end-of-options marker, which the type-length-value re-encoding drops; the `FF FF` terminator restores that delimiter. No static option can begin with it: option number `0xFFFF` has both low bits set, so it is dynamic and never enters the AAD, and no larger option number exists (see [Option Encoding](packet-structure.md#option-encoding)). The AAD therefore fixes its own end.

Dynamic options and the flood hop count are excluded from the AAD because they may be modified by repeaters during forwarding. The FCF's flood-hops-present (`H`) bit is part of that budget rather than of the packet's identity, and is cleared before the byte enters the AAD: a sender abandoning a source route re-floods a packet that is already sealed, which adds `FHOPS` where the original had none. Masking the bit does not weaken the binding. Flipping it on the wire shifts every field the parser reads after it, so the fields that follow enter the AAD as different values and the MIC check still fails.

A [MAC Ack](packet-types.md#mac-ack-packet) has no DST, CHANNEL, SRC, or SECINFO field, so its AAD is the FCF, static options, and terminator alone (see [Ack Tag Construction](#ack-tag-construction)). For an ack, masking `H` is what lets a re-sent acknowledgement, which may differ from the first only in its flood budget, carry the same tag.

#### Static Option Encoding in AAD

Static options are not included in their wire delta-length form. Instead, each static option present in the packet is re-encoded using absolute type-length-value triples:

```text
+----------+----------+-------+
|  number  |  length  | value |
+----------+----------+-------+
    2 B (BE)   2 B (BE)  var.
```

Where `number` is the option's absolute option number (not a delta), encoded as a 2-byte big-endian unsigned integer, and `length` is the value length in bytes, also encoded as a 2-byte big-endian unsigned integer. Static options appear in the AAD in order of increasing option number. This avoids recomputing deltas after dynamic options have been removed.

Using 2-byte fields for both `number` and `length` ensures that option numbers above 255 (which are valid in the CoAP-style encoding used on the wire) and long option values are represented without truncation or ambiguity. A packet that names an option number above `0xFFFF` is malformed (see [Option Encoding](packet-structure.md#option-encoding)).

### Ack Tag Construction

When a packet type requests an acknowledgement (UNAR or BUAR), the acknowledgement carries two 4-byte fields: an **ack MIC** for correlation and an **ack tag** for authentication.

The **ack MIC** is simply the first 4 bytes of the original packet's on-wire MIC:

```text
ack_mic = first_4_bytes( on_wire_MIC )
```

It is public—any node that received the original packet, including forwarding repeaters, can compute it. Its purpose is correlation: it lets the original sender match the ack to the outstanding request it belongs to, and lets a repeater that forwarded the original packet recognize the ack as its acknowledgement (enabling passive-ack optimizations). It is not an authenticator.

The **ack tag** is the MIC of the acknowledgement itself. Only the original sender and the final destination can produce it, and it covers the acknowledgement's static options as well as the packet it answers:

```text
ack_tag = truncate_to_4( S2V( K_mic, S1 = AAD_ack, S2 = V, S3 = ack_mic ) )
```

Where:

- `K_mic` is the MIC key that sealed the original packet—the pairwise key for unicast (see [HKDF Inputs for Unicast](#hkdf-inputs-for-unicast)), or the combined blind unicast key for blind unicast (see [Blind Unicast Payload Keys](#blind-unicast-payload-keys))
- `V` is the original packet's full 16-byte S2V output, before truncation to its on-wire MIC length
- `AAD_ack` is the acknowledgement's [associated data](#associated-data): its FCF with the `H` bit cleared, followed by its static options and the `FF FF` terminator

The three components take the shape of any other packet's MIC: associated data first, `V` where a nonce would sit, and `ack_mic` as the payload. The component count and the acknowledgement's own FCF keep the result distinct from every packet MIC computed under the same key. Dynamic options and the flood hop count stay outside `AAD_ack`, so forwarding does not disturb the tag.

Binding `V` ties the tag to one exchange in one direction. Both peers hold the same pairwise keys, but an acknowledgement of a packet one peer sent cannot pass for one answering a packet the other sent. `V` need not be secret for this; a packet sent with a 16-byte MIC carries all of it.

The standalone [MAC Ack](packet-types.md#mac-ack-packet) carries both fields (`ack_mic` followed by `ack_tag`, 8 bytes total). The [Ack MIC option](packet-options.md#ack-mic-option-8) carries only `ack_mic`, because the packet carrying the option is itself authenticated to the original sender and therefore needs no separate keyed tag.

The `ack_mic` is a prefix of the original packet's on-wire MIC, so it was already visible to anyone who received that packet. Producing the `ack_tag` requires `K_mic`, so an observer who intercepts the original packet can neither forge a standalone ack nor alter the static options of a genuine one. With a 4-byte tag, a blind forgery succeeds with probability `2^-32` per attempt, and only while the original packet still awaits acknowledgement: no offline check exists, each guess costs a transmission, and a failed guess draws no response. A successful forgery would cause the sender to treat an undelivered packet as delivered and suppress retransmission, or to act on options the destination never sent—a reliability denial-of-service confined to one exchange, not a confidentiality break. A weaker variant needs no forged tag at all: an observer who saw the original packet can send its public `ack_mic`, which is all a repeater can read. Repeaters therefore treat an [overheard acknowledgment](repeater-operation.md#ack-cancellation) as a hint that makes a pending forward give way to a busy channel, never as grounds to remove it. Such a forgery costs the attacker a transmission and the sender at most one retry.

The correlation exposed by `ack_mic` is deliberate. To an observer who already received the original packet, it confirms that the packet was delivered and links the ack to that packet. Because the MAC ack carries no destination hint, it adds no explicit endpoint identifier of its own—which removes the direct sender-identity leak a destination hint would introduce. This is not a guarantee of unlinkability: a determined adversary may still correlate an ack with its endpoints through timing, RF fingerprinting, return-path analysis, or by tying the `ack_mic` back to an original packet that itself exposed endpoint hints. For blind unicast, whose forward frame reveals no endpoint identity to a non-channel observer, omitting the destination hint keeps that concealment from being undone by the ack.

### Blind Unicast Address Encryption

Blind unicast packets encrypt both the destination hint and source address together, separately from the payload. The address block is encrypted with the **channel key alone**, so that any channel member can recover both the intended recipient and the sender's identity. The payload is then encrypted with the **combined blind unicast keys** (see [Blind Unicast Payload Keys](#blind-unicast-payload-keys)), which require both the channel key and the pairwise shared secret.

The address block is encrypted using AES-256-CTR with the channel's derived encryption key `K_enc_channel` (see [Multicast Packet Keys](#multicast-packet-keys)), using the CTR IV constructed from the packet MIC and SECINFO (see [CTR IV Construction](#ctr-iv-construction)).

Let:

- `K_enc_channel` = channel encryption key derived from the channel key via HKDF
- `IV` = CTR IV constructed from the packet MIC and SECINFO
- `DST` = 3-byte destination hint
- `SRC` = source address: 3-byte source hint when `S=0`, or 32-byte source public key when `S=1`

Then:

```text
ENC_DST_SRC = AES-256-CTR( key=K_enc_channel, iv=IV, plaintext=DST || SRC )
```

This allows a receiver possessing the channel key to recover both the destination (to confirm the packet is addressed to them) and the source address (to derive the pairwise keys needed to authenticate and decrypt the payload).

The address block is covered by the MIC. `DST ‖ SRC` enters the [associated data](#associated-data) in plaintext form, so the sender computes the MIC over the plaintext addresses and only then encrypts the block with the IV that MIC yields. The receiver decrypts the block from the on-wire MIC and the channel key, which it can do before it knows the payload keys, then derives the payload keys from the recovered `SRC` and verifies the MIC. Any change to the encrypted block changes the recovered addresses, and the MIC fails. Because the MIC covers the addresses it was derived from, the address block's IV is a true synthetic IV.

### Frame Signatures

A frame signature is an Ed25519 signature by the sender's node key over the bytes the MIC covers. It attributes a frame to a key: a verified signature shows that the holder of that key sent this frame, with this header and frame counter, on this channel. A channel MIC alone shows only that the sender holds the channel key.

The signature is carried in one of two ways:

- **Frames with SECINFO** (unicast, multicast, blind unicast): the SCF's `D` bit is set, and a 64-byte `SIG` follows the payload and precedes the MIC. `SIG` is the last part of [`S2`](#encrypted-packets), so the MIC covers it, and with `E` set it is encrypted with the payload.
- **Broadcast**: the [Frame Signature option](packet-options.md#frame-signature-option-0) carries a frame counter and the signature.

#### Signature Input

The signed bytes are:

```text
signature_input = "UMSH-SIG" || AAD || [CHANNEL_COMMITMENT] || plaintext
```

Where:

- `"UMSH-SIG"` is the 8 ASCII bytes `55 4D 53 48 2D 53 49 47`. It is never transmitted.
- `AAD` is the frame's [associated data](#associated-data), with the SCF's `D` bit set. For a broadcast, the Frame Signature option enters the AAD with its 64 signature bytes replaced by zeros; its frame counter enters as sent.
- `CHANNEL_COMMITMENT` is present only on multicast and blind unicast (see [Channel Commitment](#channel-commitment)).
- `plaintext` is `S2` without `SIG`, in plaintext form whether or not it is encrypted on the wire:

| Family | `plaintext` |
|---|---|
| Broadcast | `PAYLOAD` |
| Unicast | `PAYLOAD` |
| Multicast | `SRC ‖ PAYLOAD` |
| Blind unicast | `PAYLOAD` |

A multicast's `SRC` is not in its AAD, so it enters the signature input at the front of the plaintext. The `SRC` that names the signing key is therefore always covered by the signature.

The input is unambiguous without length prefixes: the label has a fixed length, the AAD fixes its own end, the FCF inside the AAD decides whether a 32-byte commitment follows, and the plaintext is everything after that.

#### Channel Commitment

The `CHANNEL` field carries only a 2-byte channel identifier, which distinct channel keys can share. Without a commitment, someone holding two channel keys with the same identifier could move a signed frame from one channel to the other and recompute its MIC, and the signature would still verify on a channel its sender never signed for. The channel commitment binds the signature to the channel key:

```text
CHANNEL_COMMITMENT = first_32_bytes( HKDF-SHA256(ikm = channel_key, salt = "UMSH-CHAN-ID", info = "") )
```

This is the same derivation as the [channel identifier](packet-types.md#channel-identifier-derivation), extended to 32 bytes; the 2-byte `channel_id` and the 16-byte channel identifier are prefixes of it. The commitment is never transmitted. A receiver computes it from the channel key that verified the frame's MIC, so when channel identifiers collide the signature is checked against the channel whose key authenticated the frame, never one matched by identifier alone.

HKDF is one-way, so a receiver can disclose a channel's commitment to let a third party verify an unencrypted signed multicast without disclosing the channel key.

#### Verification

A receiver verifies a frame signature against the signer's public key: the full `SRC` when the frame carries one, or the key of the one known peer whose hint matches `SRC`. A hint-only signed frame can be verified only by a receiver that already holds the sender's key.

- A frame whose signature verifies is attributed to that key, and its counter is judged by [Signed-Frame Counters](#signed-frame-counters).
- A frame whose signature does not verify, or whose key cannot be resolved, is not attributed to any key. It is processed as an unsigned frame from the same source would be. A failed verification is not by itself grounds to drop the frame: a hint can match a different known peer than the one that signed.

The signature does not change how a frame is authenticated. A secured frame's MIC is verified as usual, and a frame whose MIC fails is dropped before its signature is considered.

## Perfect Forward Secrecy Sessions

UMSH provides optional perfect forward secrecy (PFS) via ephemeral node addresses exchanged using the [PFS Session MAC commands](mac-commands.md#pfs-session-request-6). Once a PFS session is established, traffic between the two nodes is encrypted and authenticated exactly as if the ephemeral addresses were any other long-term node identities. Compromise of either node's long-term private key cannot retroactively expose traffic encrypted during a PFS session, because the private keys for the ephemeral addresses are erased when the session ends and the session's ECDH shared secret is irrecoverable. 

### Handshake

A PFS session is established via a two-message exchange over the existing authenticated unicast channel:

1. **Initiator**: Generates a fresh ephemeral node address. Sends a [PFS Session Request](mac-commands.md#pfs-session-request-6) carrying the new ephemeral address and a requested session duration. The request is authenticated with the initiator's long-term keys.

2. **Responder**: Generates its own fresh ephemeral node address. Sends a [PFS Session Response](mac-commands.md#pfs-session-response-7) carrying the responder's ephemeral address and the accepted session duration. The response is authenticated with the responder's long-term keys.

After this exchange, both sides hold each other's ephemeral addresses and can independently derive the session keys. No further setup messages are required.

The responder's confirmation that the response arrived is the MAC ack of the response, when the response requested one, or the initiator's first frame from its ephemeral address, authenticated under the session keys, whichever comes first. Until one arrives, the responder receives under the session but sends nothing under it, and goes on using the long-term keys: if the response was lost, the initiator does not hold the session.

Two nodes hold at most one session with each other: a new one replaces any earlier one. When two nodes each send a request to the other before either receives a response, the request whose ephemeral address is lower, compared as a big-endian unsigned integer, stands. The node that sent it ignores the other's request; the other node abandons its own request and answers.

A node that receives a response it is no longer waiting for, and holds no session with its sender, answers with [End PFS Session](mac-commands.md#end-pfs-session-8), so that the responder drops its half. This covers a request that was abandoned or timed out, and a node that rebooted after sending its request. A response received while a session is held with its sender is dropped: it repeats the response that opened the session, or is older than it.

### Session Key Derivation

A PFS session is cryptographically identical to a normal UMSH unicast session in every respect—the only difference is that the participating node addresses are ephemeral rather than long-term. Key derivation follows the exact same process as [Unicast Key Agreement](#unicast-key-agreement).

The PFS property arises not from any difference in how the keys are derived, but from the fact that the private keys for the ephemeral addresses are never stored durably and are securely erased when the session ends.

An ephemeral node address is a fully functional temporary UMSH node identity: it has an address hint, can be addressed directly, and its private key is converted to X25519 for ECDH the same way a long-term identity is.

Because a PFS session is processed exactly like an ordinary unicast session at the MAC layer, it requires no changes to MAC-layer processing and no changes to any application-layer protocol.

Packets sent between the ephemeral addresses SHOULD use a 4-byte MIC (see [MIC Size Selection Guidance](#mic-size-selection-guidance)). The session's keys are erased when it ends, so the shorter tag suffices, and each session packet is 12 bytes smaller than it would be with a 16-byte MIC.

### Wire-Level Privacy

While a PFS session is active, packet hint fields are derived from the ephemeral node address rather than the long-term address. A passive observer sees packets flowing between two unfamiliar node IDs that appear only for the duration of the session. The only packets that expose the long-term node IDs are the two handshake messages (PFS Session Request and PFS Session Response), which are themselves protected by the long-term pairwise keys.

Because ephemeral node addresses are structurally identical to long-term node addresses, an observer cannot tell ephemeral addresses from long-term ones, nor associate the ephemeral addresses with the original nodes that created the session.

This identity separation is not unconditional. The PFS handshake messages are authenticated with the nodes' long-term keys, so an attacker who later compromises a long-term private key can retroactively identify which long-term identities established the session—even though the session's content remains protected by the erased ephemeral keys.

The SCF is sent in the clear, so a session packet's 4-byte MIC is visible to an observer. It suggests that a packet may be session traffic, but not which long-term identities it belongs to.

Additionally, implementations that use a single device-wide frame counter expose a correlation opportunity: an observer who can read the frame counter field across packets (e.g. by receiving a packet before and after the PFS handshake) may notice continuity in the counter value and link the ephemeral addresses to the originating nodes. Implementations that wish to preserve wire-level identity unlinkability should use independent frame counters for each node address—including ephemeral ones—so that session traffic is not correlated with long-term traffic through counter continuity.

A node that keeps records of its [retired sessions](#retired-sessions) holds, in its storage, the link between each ephemeral address and the long-term identities that established it. Anyone who can read that storage learns which ephemeral addresses belonged to whom. The same link is usually available to a patient observer anyway: the handshake names the long-term addresses, and the ephemeral addresses appear on the air immediately afterward.

From the application layer's perspective, the implementation maps the ephemeral identity back to the originating long-term node ID throughout the session, so applications continue to see communication with the same peer they initiated the session with.

### Session Lifetime

A PFS session ends when any of the following occur:

- The agreed session duration expires.
- Either party sends an [End PFS Session](mac-commands.md#end-pfs-session-8) command.
- Either device reboots.
- Three consecutive frames a node sends under the session with an acknowledgement requested go unacknowledged, and nothing from the peer under the session arrives in between. The node ends the session and sends End PFS Session.

A node sends End PFS Session under its long-term keys once it holds no session with the recipient, so a node that has lost a session, by rebooting or otherwise, can still send one. The recipient ends the session it holds with the sender only if the End's frame counter comes after, in the modular comparison of [Replay Detection](#replay-detection), the counter of the sender's half of that session's handshake: the request the recipient answered, or the response it accepted. An End that does not was sent before that session began—delayed, or replayed after the recipient lost its receive window for the sender—and is ignored. A request still waiting for its response is not ended by End PFS Session. An End received under the session's own ephemeral addresses ends that session.

Upon session end, both sides **must securely erase/zeroize the private keys for their ephemeral addresses**. Without those private keys, the session's ECDH shared secret cannot be reconstructed, and the session traffic cannot be decrypted even by an attacker who later obtains the long-term private keys. This erasure is the mechanism that provides forward secrecy.

> [!CAUTION]
> Implementations must ensure that the private keys for ephemeral addresses are not swapped to disk, written to logs, or otherwise persisted in any form. On embedded platforms, this requires explicitly zeroing the key material in RAM before releasing it. Failure to securely erase these keys eliminates the PFS property entirely.

### Retired Sessions

A device that reboots loses its ephemeral private keys, and with them every session it held. Its peer has no way to learn this on its own and goes on sending to the lost ephemeral address until the session's duration runs out.

To end such a session promptly, a node MAY keep, in durable storage, the *public* half of each session it holds: its own ephemeral address, the peer's ephemeral address, the peer's long-term address, and when the session expires. After a reboot, a session it can no longer use is *retired*. The node keeps its record until the agreed duration has passed, the session is ended, or a new session with that peer replaces it. A node that cannot tell how much of the duration remains counts the whole agreed duration from when it booted.

When a node receives a unicast or blind unicast whose destination hint is that of a retired session's local ephemeral address, and whose source is that session peer's ephemeral address, it discards the packet. It SHOULD then send an [End PFS Session](mac-commands.md#end-pfs-session-8) to the peer, and forget the record once that command is acknowledged. A node that does not hear an acknowledgment keeps the record, and the next such packet prompts another End PFS Session.

Only public keys are kept. The private keys are erased exactly as for any other session end, so a retired session's traffic stays as irrecoverable as that of a session that simply expired.
