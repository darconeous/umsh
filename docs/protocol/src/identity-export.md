# Identity Export Format

This appendix defines a portable, passphrase-protected artifact for backing
up and restoring a node identity, together with the secret material and local
knowledge that make a restored identity immediately useful. It is produced
and consumed by host implementations — phones, tablets, and desktops. A
companion radio never generates, stores, or parses an export artifact, and a
companion radio's own device identity is never exported through this format.

The artifact is a single binary object with two layers:

- an **envelope** that binds a format version and key-derivation parameters
  to an encrypted, authenticated body; and
- a **payload** inside the envelope: a CBOR map carrying the identity secret,
  counter-recovery information, and optional local state.

The same format serves two profiles distinguished only by which payload
sections are present:

- a **core export** carries only the identity and counter sections. It is
  small enough to render as a short QR sequence (see
  [QR Part Framing](#qr-part-framing)) and suits printed or engraved
  recovery copies.
- a **full export** additionally carries channel keys, contacts, and
  application settings. It is intended for file storage.

No `umsh:` URI form is defined for export artifacts. This is deliberate:
private key material must not flow through link handlers, pasteboards, or
URI-preview machinery. The recommended file extension is `.umshid`.

## Envelope

All multi-byte integers are big-endian, as elsewhere in UMSH.

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 6 | Magic | ASCII `UMSHID` |
| 6 | 1 | Format version | `0x01` |
| 7 | 1 | KDF identifier | `0x01` = Argon2id |
| 8 | 4 | Argon2id memory cost *m* | KiB |
| 12 | 4 | Argon2id time cost *t* | passes |
| 16 | 1 | Argon2id parallelism *p* | lanes |
| 17 | 16 | KDF salt | random per export |
| 33 | 1 | Cipher identifier | `0x01` = UMSH SIV construction |
| 34 | 16 | MIC | full AES-CMAC tag |
| 50 | — | Ciphertext | encrypted payload |

Bytes 0–33 (everything before the MIC) form the **envelope header**. The
header is authenticated as associated data; any modification of the version,
KDF parameters, salt, or cipher identifier invalidates the MIC.

The KDF salt **MUST** be freshly generated from a cryptographically secure
random source for every export, including re-exports of the same identity.

Unrecognized format version, KDF identifier, or cipher identifier values
**MUST** cause the importer to reject the artifact before attempting key
derivation.

## Key Derivation

The passphrase is encoded as UTF-8 after Unicode NFC normalization.
Normalization is required: text input methods on different platforms produce
different codepoint sequences for visually identical passphrases, and a
cross-platform artifact must decrypt identically everywhere.

```text
prk  = Argon2id(passphrase, kdf_salt, m, t, p, taglen = 32)

ikm  = prk
salt = "UMSH-IDEXPORT-SALT"
info = "UMSH-IDEXPORT-V1"
okm  = HKDF-SHA256(ikm, salt, info, 32)

K_enc = okm[0..15]
K_mic = okm[16..31]
```

Exporters **MUST** use at least *m* = 19456 KiB, *t* = 2, *p* = 1, and
**SHOULD** use *m* = 65536 KiB, *t* = 3, *p* = 1 where device memory allows.
Importers **MUST** honor the parameters carried in the header, but **MAY**
refuse artifacts whose parameters exceed a local resource ceiling (for
example *m* > 1048576 KiB, *t* > 32, or *p* > 4) to avoid resource-exhaustion
attacks through crafted headers.

## Encryption and Authentication

The payload is protected with the same SIV-style construction used for
packets (see [Encrypted Packets](security.md#encrypted-packets)), with the
full 16-byte MIC and the envelope header as associated data:

1. Compute the full 16-byte AES-CMAC over the envelope header followed by
   the payload plaintext, using `K_mic`.
2. Use the MIC directly as the 16-byte CTR IV, as in standard AES-SIV.
3. Encrypt the payload using **AES-128-CTR** with `K_enc` and that IV.

To import, derive the keys, decrypt the ciphertext, recompute the CMAC over
the header and recovered plaintext, and compare it to the stored MIC in
constant time. On mismatch the importer **MUST** report a single generic
failure: a wrong passphrase and a corrupted or forged artifact are
deliberately indistinguishable.

## Payload

The payload is a CBOR (RFC 8949) map using unsigned-integer keys.
Definite-length encoding **MUST** be used. Deterministic encoding is not
required; the envelope, not the payload encoding, provides integrity.

| Key | Section | Type | Presence |
|---|---|---|---|
| 1 | Identity | map | required |
| 2 | Counters | map | required |
| 3 | Channels | array of maps | optional |
| 4 | Contacts | array of maps | optional |
| 5 | Application settings | map | optional |

Importers **MUST** ignore unrecognized top-level keys and unrecognized keys
within any section. Unrecognized content **MUST NOT** be preserved into a
later re-export: a section defined by a future version may carry security
state that must not outlive the format revision that understands it.

### Identity Section

| Key | Field | Type | Presence |
|---|---|---|---|
| 1 | Private key seed | 32-byte byte string | required |
| 2 | Created | unsigned (Unix seconds) | optional |
| 3 | Display name | text string | optional |
| 4 | Advertisement | byte string | optional |

The seed is the node's Ed25519 private key seed, from which the Ed25519
public key and the derived X25519 key are obtained. The public key is not
stored; the importer **MUST** derive it from the seed, and that derived key
is the restored identity's address.

The advertisement, when present, is the node's most recent
[advertisement](beacons.md#advertisements) in canonical wire form. The
importer **SHOULD** verify its signature against the derived public key and
discard it — without failing the restore — if verification fails.

### Counter Section

| Key | Field | Type | Presence |
|---|---|---|---|
| 1 | TX counter floor | unsigned | required |
| 2 | Restore generation | unsigned | required |

The TX counter floor is the highest outbound
[frame counter](security.md#frame-counter) value the exporting
implementation knows to have been used, maximized across however many
outbound counters it tracks. It is a floor, not a current value: the
exporting device may continue transmitting after the export is created, so
the artifact is stale by an unknown amount the moment it exists. Restore
safety comes from the advance rule below, not from the accuracy of this
field.

The restore generation records how many times this identity had been
restored from an export when the artifact was created. It begins at zero,
and each successful restore records one more than the value found in the
artifact. It is bookkeeping for diagnostics and future exports; it is not a
security mechanism.

### Channel Section

Each entry describes one channel membership:

| Key | Field | Type | Presence |
|---|---|---|---|
| 1 | Channel key | 32-byte byte string | required |
| 2 | Kind | unsigned | required |
| 3 | Name | text string | optional |

Kind values: `1` =
[private channel](multicast-channels.md#private-channels), `2` =
[named channel](multicast-channels.md#named-channels), `3` =
[managed channel](multicast-channels.md#managed-channels). For named
channels the key is derivable from the canonical name, but the key is stored
regardless so that import never depends on name canonicalization. The name
field carries the canonical name for named channels and the local display
name otherwise.

### Contact Section

Each entry describes one known peer:

| Key | Field | Type | Presence |
|---|---|---|---|
| 1 | Public key | 32-byte byte string | required |
| 2 | Local alias | text string | optional |
| 3 | Advertisement | byte string | optional |

The advertisement, when present, is the peer's cached
[advertisement](beacons.md#advertisements) in canonical wire form. The
importer **SHOULD** verify its signature against the entry's public key and
discard it on failure. Local aliases are display state, not protocol state.

Ephemeral session state is never exported: PFS sessions are local to the
device that negotiated them, and receive-side replay baselines are
re-established through the normal
[first-contact and re-baselining rules](security.md#frame-counter).

### Application Settings Section

A map with text-string keys and arbitrary CBOR values, namespaced by the
producing application (for example `ios.notifications.previews`). Contents
are application-defined and restored best-effort; importers **MUST** ignore
entries they do not understand. This section **MUST NOT** contain key
material or any other secret — secrets belong only in the sections defined
above.

## Restore Procedure

1. Parse the envelope; reject unknown version, KDF, or cipher identifiers.
2. Derive keys from the passphrase and header parameters; decrypt and
   authenticate. Report authentication failure generically.
3. Derive the public key from the seed and present the identity (name,
   complete address) for explicit confirmation before committing anything.
4. On confirmation, compute the restored outbound frame counter:

   ```text
   block    = 2^24
   restored = (floor(tx_floor / block) + 2) * block
   ```

   If `restored` does not fit in the 4-byte counter space, the restore
   **MUST** fail; the identity's counter space is effectively exhausted and
   the identity should be retired rather than restored.
5. Persist the identity, the restored counter value, and the incremented
   restore generation before the identity sends any authenticated traffic.
6. Import optional sections, verifying signatures where specified.

The advance rule skips at least one full block of 2²⁴ counter values beyond
the recorded floor. This dominates any plausible transmission volume between
export and restore on a LoRa-class link, and bounds the identity to roughly
250 restores across its lifetime — a deliberate trade of counter space for
safety against a stale floor.

Restoring an identity does not revoke the source: the exporting device, and
every other copy of the artifact, still holds a working private key. The
restore flow **MUST** state that the exporting device is to stop using the
identity; concurrent use violates the monotonic-counter assumption that
peers rely on for replay protection. After a successful restore,
implementations **SHOULD** encourage creating a fresh export, since existing
artifacts remain valid but describe a stale counter floor and generation.

## QR Part Framing

An artifact rendered as QR codes is split into parts, each carried in one
symbol using QR byte mode:

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | Part magic | ASCII `UMQR` |
| 4 | 1 | Framing version | `0x01` |
| 5 | 4 | Artifact check | first 4 bytes of SHA-256 of the complete envelope |
| 9 | 1 | Part index | 0-based |
| 10 | 1 | Part count | total parts, ≥ 1 |
| 11 | — | Chunk | envelope bytes |

Concatenating the chunks in index order reproduces the envelope.
An importer **MUST NOT** combine parts whose artifact check values differ,
and **MUST** verify the reassembled envelope against the check value before
attempting decryption. The check value is a reassembly guard against mixing
parts from different exports; the envelope MIC remains the integrity
mechanism.

A core export fits in two to three modest QR symbols. Full exports are not
intended for QR presentation.

## Security Considerations

**The passphrase is the floor.** Argon2id raises the cost of guessing but
cannot rescue a weak passphrase, and the artifact is exposed to offline
attack wherever it is stored. Applications should communicate this when the
passphrase is chosen.

**A full export is more than a key.** Channel keys are membership
credentials; an attacker who decrypts a full export can read and send on
every included channel, not merely impersonate the identity. Applications
should present a full export as at least as sensitive as the identity
itself.

**Artifacts cannot be revoked.** Every copy of an export remains a valid
credential for as long as the identity and the included channel keys remain
in use. Deleting the file an application knows about does not delete copies.
Retiring a compromised export means retiring the identity and rotating the
included channel keys.

**Decrypted material must be handled like the live key.** Implementations
zeroize decrypted payload buffers, never log payload contents, and never
expose the seed or channel keys outside the component that consumes them.

**Header parameters are attacker-controlled until authenticated.** The KDF
parameters are read before any authentication is possible; the resource
ceilings in [Key Derivation](#key-derivation) exist so a crafted header
cannot demand unbounded memory or time.
