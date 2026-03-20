# Security & Cryptography

UMSH authenticates and optionally encrypts packets using a construction inspired by AES-SIV (RFC 5297). Unicast packets are secured with pairwise keys derived from X25519 ECDH between sender and recipient Ed25519 keys. Multicast packets are secured with keys derived from the shared channel key. In both cases, a monotonic frame counter provides replay protection without requiring synchronized clocks.

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
+---+-------+---+---------------+
| E |  MIC  | S |   RESERVED    |
+---+-------+---+---------------+
 1b   2 bits 1b      4 bits
```

Where:

- `E` = encrypted payload flag
- `MIC` = MIC size code
- `S` = salt included
- `RESERVED` = must all be set to zero

If the `RESERVED` bits read as anything other than zero, the packet MUST be dropped.

MIC size encodings:

| Value | MIC Length |
|------:|------------|
| 0     | 4 bytes    |
| 1     | 8 bytes    |
| 2     | 12 bytes   |
| 3     | 16 bytes   |

The MIC is produced by computing the full 16-byte AES-CMAC and truncating to the specified length. Truncation of CMAC outputs is permitted by NIST SP 800-38B.

#### MIC Size Selection Guidance

Shorter MICs save bytes on the wire but reduce forgery resistance and increase the probability of duplicate-suppression collisions in repeater caches (see [Duplicate Suppression](repeater-operation.md#duplicate-suppression)). The following guidelines help choose an appropriate MIC size:

- **16 bytes** (default): Recommended for long-term stable identities where the same pairwise keys may be used for months or years. The cost of a successful forgery is high (attacker gains persistent access to impersonate a node), and the 2^-128 forgery probability makes brute-force infeasible regardless of how many packets an attacker can attempt.

- **8 bytes**: A reasonable middle ground for most communication. Provides 2^-64 forgery probability — well beyond practical brute-force for LoRa's low packet rates — while saving 8 bytes per packet. Suitable for general unicast and multicast traffic.

- **4 bytes**: Appropriate for short-lived contexts where the keys will be discarded soon, such as [PFS sessions](#perfect-forward-secrecy-sessions) or one-time exchanges using ephemeral node addresses. The 2^-32 forgery probability (~1 in 4 billion) is adequate when the window of exposure is brief. Also useful for latency-sensitive or payload-constrained scenarios where every byte matters, such as sensor telemetry on slow LoRa links.

- **12 bytes**: Available as an intermediate option when 8 bytes feels too tight but 16 bytes is more overhead than warranted. Provides 2^-96 forgery probability.

As a general principle: the longer the keys will be in use and the higher the value of the traffic they protect, the larger the MIC should be. For ephemeral keys that will be erased within minutes, a small MIC is sufficient. For a node's long-term identity keys, prefer the full 16 bytes.

### Frame Counter

The 4-byte frame counter must increase monotonically for a given shared secret and
traffic direction. UMSH uses this monotonic counter — rather than timestamps — for replay protection, keeping the protocol free of any dependency on synchronized clocks or absolute time.

The exact mechanism for how the frame counter is handled is implementation specitic,
assuming that it always increases. For example, the frame counter may be unique for
each source+destination node pair, or it may be a single frame counter for the entire
device. On constrained devices, it may make sense to use a combination of the two:
have a fixed set of counters (say, 32) that are initialized with random starting values,
and derive a pseudo-random number from 0-31 from the shared secret to pick which of
those counters is being used. 

#### Replay Detection

A receiver determines whether a frame counter is acceptable by computing:

```text
delta = (received_counter - last_accepted_counter) mod 2^32
```

If `delta` is zero or exceeds a reasonable forward window (implementation-defined), the packet is rejected. This modular comparison allows the counter to wrap around `2^32` without requiring special overflow handling.

If we have communicated with this node before and the frame counter is wildly outside
of our window (say, by several thousand frames at least), then the node should resync
the the frame counter using an echo request [MAC command](mac-commands.md).

#### Counter Persistence

How a node persists and recovers its frame counter across reboots is implementation-specific. Possible strategies include writing the counter to non-volatile storage periodically or advancing the counter by a large margin on startup to avoid replaying previously used values.

> [!CAUTION]
> If the counter is written to non-volatile storage, care should be taken
> to avoid wearing out the underlying storage medium if it has a limited
> number of writes.

Nodes that cannot guarantee counter continuity across restarts may use the Echo Request MAC command (see [MAC Commands](mac-commands.md#echo-request)) to learn a peer's current counter expectations before resuming communication.

### Salt

The optional 2-byte salt is chosen randomly to reduce the liklihood of a nonce collision.

## Cryptographic Processing

### Unicast Key Agreement

For unicast and blind unicast:

1. Start with sender Ed25519 keypair and recipient Ed25519 keypair.
2. Convert both Ed25519 keys to X25519 form.
3. Perform X25519 ECDH.
4. Feed the resulting shared secret into HKDF-SHA256.
5. Derive separate stable pairwise keys for encryption and MIC/authentication.

### Ed25519 to X25519 Conversion

UMSH uses a single Ed25519 keypair per node as both its identity (for addressing) and the basis for key agreement. Standard cryptographic guidance recommends separate keys for signing and key agreement, so this choice warrants justification.

The Ed25519 and X25519 curves are birationally equivalent (both are defined over Curve25519), and the conversion between Edwards and Montgomery form is a well-understood, deterministic mapping. Using a single keypair for both purposes is not itself insecure — it is the approach taken by, among others, the Signal protocol's X3DH key agreement and libsodium's `crypto_sign_ed25519_pk_to_curve25519` API.

The alternative — carrying separate Ed25519 (signing) and X25519 (key agreement) keys per node — would require a cryptographic binding between the two. Each node must distribute an additional 32-byte X25519 public key alongside its Ed25519 key, and the binding must be authenticated (e.g. by including the X25519 key in a signed advertisement). Every recipient must then verify that binding before trusting the key agreement key. On a LoRa link where the entire frame budget is ~255 bytes, even 32 extra bytes per identity exchange is a significant cost. By deriving X25519 keys from Ed25519 keys, UMSH eliminates this overhead entirely: the node address *is* the key agreement key, with no additional key distribution required.

UMSH assumes standard Edwards-to-Montgomery conversion:

- sender Ed25519 private key → sender X25519 private key
- sender Ed25519 public key → sender X25519 public key
- recipient Ed25519 private key → recipient X25519 private key
- recipient Ed25519 public key → recipient X25519 public key

Implementations should reject malformed public keys before conversion.

### ECDH Shared Secret

The ECDH shared secret is:

```text
ss = X25519(local_x25519_private, remote_x25519_public)
```

This shared secret is ised as the input keying material for deriving the cryptographic
keys to secure and authenticate messages.

### HKDF Inputs for Unicast

For unicast and blind unicast, packet encryption and MIC keys are derived from the X25519 ECDH shared secret and are stable for a given pair of nodes. These keys are not derived from packet-specific fields.

Let:

```text
ss = X25519(local_x25519_private, remote_x25519_public)
```

The pairwise key material is then derived as:

```text
ikm  = ss
salt = "UMSH-PAIRWISE-SALT"
info = "UMSH-UNICAST-V1"
okm  = HKDF-SHA256(ikm, salt, info, 32)
```

The output keying material is split as follows:

```text
K_enc = okm[0..15]
K_mic = okm[16..31]
```

Where:

- `K_enc` is the 16-byte encryption key
- `K_mic` is the 16-byte message authentication key

These keys are stable for the sender/recipient pair and may be cached by the implementation. They do not change from packet to packet.

Because the key derivation depends only on the ECDH shared secret and fixed UMSH-specific HKDF parameters, it does not need to be recomputed for each transmitted packet.

### Per-Packet Security Inputs

Although `K_enc` and `K_mic` are stable for a given node pair, each packet still carries per-packet security inputs in `SECINFO`.

These inputs are:

- the 4-byte frame counter
- the optional 2-byte salt

These values are not used to derive the pairwise keys. Instead, they are used as packet-specific inputs to encryption, authentication, and replay protection.

For encrypted packets using AES-SIV:

- `K_enc` and `K_mic` are the stable pairwise keys
- `SECINFO` and other immutable header fields are supplied as associated data
- the frame counter and optional salt provide packet-specific variability and replay-detection context

For authenticated but unencrypted packets:

- `K_mic` is the stable pairwise MIC key
- the MIC is computed over the protected packet contents and relevant static fields

The frame counter must increase monotonically for a given traffic direction. Receivers should use it for replay detection even though AES-SIV is resistant to nonce misuse.

### Multicast Packet Keys

For multicast, the configured channel key is the base secret. The encryption and authentication keys are derived once and are stable for a given channel.

```text
ikm  = channel_key
salt = "UMSH-MCAST-SALT"
info = "UMSH-MCAST-V1" || channel_id
okm  = HKDF-SHA256(ikm, salt, info, 32)

K_enc = okm[0..15]
K_mic = okm[16..31]
```

These keys are stable for the channel and may be cached by the implementation. They do not change from packet to packet. Per-packet variability is provided by the frame counter and optional salt in SECINFO, which serve as inputs to encryption and replay detection (see [Per-Packet Security Inputs](#per-packet-security-inputs)).

### Encrypted Packets

When encryption is enabled, UMSH uses a construction inspired by **AES-SIV** (RFC 5297), with the MIC and encryption steps separated to allow future support for different MIC lengths.

The processing is:

1. Compute the full 16-byte AES-CMAC over the AAD and plaintext using `K_mic`.
2. Truncate the CMAC to the MIC length specified by the SCF.
3. Construct the CTR IV from the MIC (see [CTR IV Construction](#ctr-iv-construction)).
4. Encrypt the plaintext using **AES-128-CTR** with `K_enc` and the constructed IV.

The MIC is transmitted separately from the ciphertext (not prepended as in standard AES-SIV), allowing the MIC length to be controlled independently via the SCF MIC size field.

A key design goal is robustness against nonce reuse. Because the CTR IV is derived from the MIC (as in SIV-style constructions), accidental reuse of nonces or counters is not cryptographically catastrophic in the way it would be for CTR or GCM.

### CTR IV Construction

The 16-byte CTR IV is constructed by appending the SECINFO field to the MIC, then zero-padding or truncating the result to exactly 16 bytes:

```text
IV = truncate_or_pad_to_16( MIC || SECINFO )
```

For the 16-byte MIC, SECINFO is entirely truncated away and the IV equals the MIC — identical to standard AES-SIV. For shorter MICs, the IV incorporates the frame counter and optional salt from SECINFO, providing additional per-packet IV variability that compensates for the increased probability of truncated-MIC collisions.

| MIC Length | SECINFO (5 B) | SECINFO (7 B) | SECINFO bytes in IV |
|---:|---|---|---|
| 16 B | truncate to 16 | truncate to 16 | 0 (IV = MIC) |
| 12 B | truncate to 16 | truncate to 16 | 4 or 2 |
| 8 B | zero-pad to 16 | zero-pad to 16 | 5 or 7 |
| 4 B | zero-pad to 16 | zero-pad to 16 | 5 or 7 |

### Unencrypted Packets

When encryption is disabled, the MIC is calculated using **CMAC** with `K_mic`.

### Associated Data

The associated data (AAD) binds the immutable header fields to the MIC so that any modification is detected.

The AAD is constructed by concatenating the following fields in order:

1. **FCF** (1 byte)
2. **Static options** — re-encoded as type-length-value (see below)
3. **DST** (2 bytes, unicast) or **CHANNEL** (2 bytes, multicast)
4. **SRC** (2 or 32 bytes) — included only when the source field is outside the ciphertext
5. **SECINFO** (5 or 7 bytes)

Dynamic options and the hop count are excluded from the AAD because they may be modified by repeaters during forwarding.

#### Static Option Encoding in AAD

Static options are not included in their wire delta-length form. Instead, each static option present in the packet is re-encoded using absolute type-length-value triples:

```text
+--------+--------+-------+
| number | length | value |
+--------+--------+-------+
   1 B      1 B     var.
```

Where `number` is the option's absolute option number (not a delta) and `length` is the value length in bytes. Static options appear in the AAD in order of increasing option number. This avoids recomputing deltas after dynamic options have been removed.

### Ack Tag Construction

When a packet type requests an acknowledgement (UACK or BUAK), both the sender and receiver independently compute an **ack tag** — an 8-byte value that the receiver includes in the MAC ack and the sender uses to match incoming acks to outstanding requests.

The ack tag is computed as follows:

1. Compute the full 16-byte AES-CMAC over the AAD and plaintext using `K_mic` (this is the same computation used to produce the packet MIC, before any truncation).
2. Encrypt the 16-byte CMAC with a single AES-128-ECB block encryption using the pairwise `K_enc`.
3. Truncate the result to 8 bytes.

```text
ack_tag = truncate_to_8( AES-128-ECB( key=K_enc, block=full_16B_CMAC ) )
```

Where:

- `K_enc` is the **pairwise** encryption key derived from the sender/recipient ECDH shared secret (see [HKDF Inputs for Unicast](#hkdf-inputs-for-unicast)), even for blind unicast packets
- `full_16B_CMAC` is the full 16-byte AES-CMAC computed during packet processing, before truncation to the on-wire MIC length

The ack tag is never transmitted in the original packet — it appears only in the [MAC Ack](packet-types.md#mac-ack-packet) response. Because it requires knowledge of `K_enc`, a passive observer who intercepts the original packet cannot forge a valid ack, regardless of the MIC size used on the wire. The ack tag also bears no visible relationship to the on-wire MIC, preventing observers from correlating ack packets with the original packets by comparing values.

AES-ECB on a single 16-byte block is the raw AES block cipher — a pseudorandom permutation — and does not have the pattern-leakage weakness associated with multi-block ECB encryption.

### Blind Unicast Source Encryption

Blind unicast packets encrypt the source address separately from the payload.

The source address is encrypted using AES-128-CTR with the channel's derived encryption key `K_enc` (see [Multicast Packet Keys](#multicast-packet-keys)), using the CTR IV constructed from the packet MIC and SECINFO (see [CTR IV Construction](#ctr-iv-construction)).

Let:

- `K_enc` = channel encryption key derived from the channel key via HKDF
- `IV` = CTR IV constructed from the packet MIC and SECINFO
- `SRC` = 32-byte source public key

Then:

```text
ENC_SRC = AES-128-CTR( key=K_enc, iv=IV, plaintext=SRC )
```

This allows a receiver possessing the channel key to derive `K_enc`, recover the source address, and then derive the stable pairwise keys needed to authenticate and decrypt the payload itself.

## Perfect Forward Secrecy Sessions

UMSH provides optional perfect forward secrecy (PFS) via ephemeral node addresses exchanged using the [PFS Session MAC commands](mac-commands.md#pfs-session-request-6). Once a PFS session is established, traffic between the two nodes is encrypted and authenticated exactly as if the ephemeral addresses were any other long-term node identities. Compromise of either node's long-term private key cannot retroactively expose traffic encrypted during a PFS session, because the private keys for the ephemeral addresses are erased when the session ends and the session's ECDH shared secret is irrecoverable. 

### Handshake

A PFS session is established via a two-message exchange over the existing authenticated unicast channel:

1. **Initiator**: Generates a fresh ephemeral node address. Sends a [PFS Session Request](mac-commands.md#pfs-session-request-6) carrying the new ephemeral address and a requested session duration. The request is authenticated with the initiator's long-term keys.

2. **Responder**: Generates its own fresh ephemeral node address. Sends a [PFS Session Response](mac-commands.md#pfs-session-response-7) carrying the responder's ephemeral address and the accepted session duration. The response is authenticated with the responder's long-term keys.

After this exchange, both sides hold each other's ephemeral addresses and can independently derive the session keys. No further setup messages are required. The first data packet sent by the initiator using the ephemeral address hints serves as an implicit acknowledgement to the responder that the response was received and the session is active.

### Session Key Derivation

A PFS session is cryptographically identical to a normal UMSH unicast session in every respect — the only difference is that the participating node addresses are ephemeral rather than long-term. Key derivation follows the exact same process as [Unicast Key Agreement](#unicast-key-agreement).

The PFS property arises not from any difference in how the keys are derived, but from the fact that the private keys for the ephemeral addresses are never stored durably and are securely erased when the session ends.

An ephemeral node address is a fully functional temporary UMSH node identity: it has an address hint, can be addressed directly, and its private key is converted to X25519 for ECDH the same way a long-term identity is.

Because a PFS session is indistinguishable from an ordinary unicast session at the MAC layer, it requires no changes to MAC-layer processing, no changes to any application-layer protocol, and adds zero per-packet overhead. Once the two-message handshake completes, every subsequent packet in the session is exactly the size it would have been without PFS.

### Wire-Level Privacy

While a PFS session is active, packet hint fields are derived from the ephemeral node address rather than the long-term address. A passive observer sees packets flowing between two unfamiliar node IDs that appear only for the duration of the session. The only packets that expose the long-term node IDs are the two handshake messages (PFS Session Request and PFS Session Response), which are themselves protected by the long-term pairwise keys.

Because ephemeral node addresses are structurally identical to long-term node addresses, an observer cannot distinguish PFS session traffic from ordinary unicast traffic, nor associate the ephemeral addresses with the original nodes that created the session.

However, implementations that use a single device-wide frame counter expose a correlation opportunity: an observer who can read the frame counter field across packets (e.g. by receiving a packet before and after the PFS handshake) may notice continuity in the counter value and link the ephemeral addresses to the originating nodes. Implementations that wish to preserve wire-level identity unlinkability should use independent frame counters for each node address — including ephemeral ones — so that session traffic is not correlated with long-term traffic through counter continuity.

From the application layer's perspective, the implementation maps the ephemeral identity back to the originating long-term node ID throughout the session, so applications continue to see communication with the same peer they initiated the session with.

### Session Lifetime

A PFS session ends when any of the following occur:

- The agreed session duration expires.
- Either party sends an [End PFS Session](mac-commands.md#end-pfs-session-8) command.
- Either device reboots.

Upon session end, both sides **must securely erase/zeroize the private keys for their ephemeral addresses**. Without those private keys, the session's ECDH shared secret cannot be reconstructed, and the session traffic cannot be decrypted even by an attacker who later obtains the long-term private keys. This erasure is the mechanism that provides forward secrecy.

> [!CAUTION]
> Implementations must ensure that the private keys for ephemeral addresses are not swapped to disk, written to logs, or otherwise persisted in any form. On embedded platforms, this requires explicitly zeroing the key material in RAM before releasing it. Failure to securely erase these keys eliminates the PFS property entirely.

