# Security & Cryptography

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

MIC size encodings:

| Value | MIC Length | Status                  |
|------:|------------|-------------------------|
| 0     | 4 bytes    | reserved / unsupported  |
| 1     | 8 bytes    | reserved / unsupported  |
| 2     | 12 bytes   | reserved / unsupported  |
| 3     | 16 bytes   | supported               |

### Frame Counter

The 4-byte frame counter must increase monotonically for a given traffic direction. UMSH uses this monotonic counter — rather than timestamps — for replay protection, keeping the protocol free of any dependency on synchronized clocks or absolute time.

#### Replay Detection

A receiver determines whether a frame counter is acceptable by computing:

```text
delta = (received_counter - last_accepted_counter) mod 2^32
```

If `delta` is zero or exceeds a reasonable forward window (implementation-defined), the packet is rejected. This modular comparison allows the counter to wrap around `2^32` without requiring special overflow handling.

#### Counter Persistence

How a node persists and recovers its frame counter across reboots is implementation-specific. Possible strategies include writing the counter to non-volatile storage periodically or advancing the counter by a large margin on startup to avoid replaying previously used values.

Nodes that cannot guarantee counter continuity across restarts may use the Echo Request MAC command (see [MAC Commands](mac-commands.md#echo-request)) to learn a peer's current counter expectations before resuming communication.

### Salt

The optional 2-byte salt is chosen randomly.

## Cryptographic Processing

### Unicast Key Agreement

For unicast and blind unicast:

1. Start with sender Ed25519 keypair and recipient Ed25519 keypair.
2. Convert both Ed25519 keys to X25519 form.
3. Perform X25519 ECDH.
4. Feed the resulting shared secret into HKDF-SHA256.
5. Derive separate stable pairwise keys for encryption and MIC/authentication.

### Ed25519 to X25519 Conversion

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

For multicast and blind multicast, the configured channel key is the base secret. The encryption and authentication keys are derived once and are stable for a given channel.

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

1. Compute the MIC over the AAD and plaintext using `K_mic` via **AES-CMAC**.
2. Encrypt the plaintext using **AES-128-CTR** with `K_enc`, using the MIC as the CTR IV.

The MIC is transmitted separately from the ciphertext (not prepended as in standard AES-SIV), allowing the MIC length to be controlled independently via the SCF MIC size field. Only the 16-byte MIC mode is currently supported.

A key design goal is robustness against nonce reuse. Because the MIC is used as the CTR IV (as in SIV-style constructions), accidental reuse of nonces or counters is not cryptographically catastrophic in the way it would be for CTR or GCM.

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

### Blind Unicast Source Encryption

Blind unicast source-address protection uses AES-128-CTR with the channel key and packet MIC as IV.

Let:

- `channel_key` = multicast channel key
- `MIC` = final packet MIC (16 bytes)
- `SRC` = 32-byte source public key

Then:

```text
ENC_SRC = AES-128-CTR( key=channel_key, iv=MIC[0..15], plaintext=SRC )
```

This allows a receiver possessing the channel key to recover the source address first, then derive the stable pairwise keys needed to authenticate and decrypt the payload itself.
