# Channels

A **channel** is a shared symmetric key that enables group communication and metadata concealment. Channels serve two distinct roles in UMSH:

- **Multicast** — any node that possesses the channel key can send and receive packets addressed to the channel, enabling group communication.
- **Blind unicast** — the channel key conceals both sender and destination addresses on the wire, while the payload itself is protected end-to-end using [combined keys](security.md#blind-unicast-payload-keys) that require both the channel key and the pairwise shared secret. The channel serves as a metadata-concealment layer; the payload is readable only by the intended recipient, not by all channel members. See [Blind Unicast Packet](packet-types.md#blind-unicast-packet) and [Blind Unicast Source Encryption](security.md#blind-unicast-source-encryption) for details.

In both cases, the channel key is the membership credential — possessing it is both necessary and sufficient to participate.

## Channel Keys

A channel key is a 32-byte symmetric key. It serves as the root secret from which encryption, authentication, and identification keys are derived (see [Multicast Packet Keys](security.md#multicast-packet-keys)).

How a node obtains a channel key depends on the type of channel — see [Joining a Channel](#joining-a-channel) below.

## Channel Identifier

Each channel is identified on the wire by a 2-byte channel identifier [derived from the channel key](packet-types.md#channel-identifier-derivation). This identifier is a compact hint that allows receivers to quickly identify candidate channels without attempting decryption with every configured key. Like destination hints, channel identifiers are not cryptographically authoritative — collisions are possible and must be resolved by attempting cryptographic verification.

## Encrypted and Unencrypted Modes

Channel-addressed packets (multicast and blind unicast) may be sent with or without encryption, controlled by the `E` flag in the Security Control Field.

- **Encrypted** (E=1): The source address is encrypted together with the payload, concealing the sender's identity from observers who do not possess the channel key. Only channel members can recover the source address and payload. See [Encrypted Multicast](packet-types.md#encrypted-multicast-e--1) for the packet layout.

- **Unencrypted** (E=0): The source address and payload appear in cleartext, but the packet is still authenticated with a MIC derived from the channel key. This mode is useful for amateur radio operation or other contexts where encryption is not permitted. See [Unencrypted Multicast](packet-types.md#unencrypted-multicast-e--0) for the packet layout.

## Multi-Hop Delivery

Channel-addressed packets are delivered via flood forwarding, bounded by the optional flood hop count field. Repeaters forward these packets according to the standard [forwarding procedure](repeater-operation.md#forwarding-procedure), including duplicate suppression, signal-quality filtering, and region-scoped flooding.

## Sender Authentication

Multicast authentication is based on the shared channel key, not on individual sender identity. The MIC proves that the sender possesses the channel key, but any channel member can construct a valid packet with any claimed source address. This is a fundamental property of symmetric-key multicast — see [Multicast Sender Authentication](limitations.md#multicast-sender-authentication) for further discussion.

Blind unicast payloads are additionally authenticated using pairwise keys derived from the sender and recipient's key agreement, so only the true sender can produce a valid payload and only the intended recipient can verify it.

## Joining a Channel

UMSH supports three models for channel membership, from simplest to most capable.

### Named Channels

Channel keys may be derived from human-readable channel names rather than distributed as raw keys. A named channel is identified by a `umsh:cs:` URI (see [URI Formats](uri-formats.md#channel-uris)):

```text
umsh:cs:Public
```

Named channels are effectively public — anyone who knows the name can derive the key and participate. Long, high-entropy names may provide practical obscurity, but this should not be treated as strong secrecy.

The channel key is derived from the channel name using HKDF-Extract:

```text
channel_key = HKDF-Extract-SHA256(salt = "UMSH-CHANNEL-V1", ikm = UTF-8(channel_name))
```

Where `channel_name` is the name portion of the `umsh:cs:` URI (everything after `umsh:cs:`), after percent-decoding, encoded as a UTF-8 byte string. For example, given `umsh:cs:Public`, the input is the UTF-8 encoding of `Public`. The output is a 32-byte pseudorandom key that serves as the channel key. This key then flows through the standard [Multicast Packet Keys](security.md#multicast-packet-keys) derivation to produce `K_enc` and `K_mic`.

HKDF-Extract is appropriate here because named channels are not secrets — the name is public input keying material, not a password. Password-based KDFs (PBKDF2, Argon2) would add computational cost without meaningful security benefit, since the channel name is assumed to be known to all participants.

### Private Channels

For channels that require real secrecy, the channel key is distributed out-of-band — via QR codes, `umsh:ck:` URIs (see [URI Formats](uri-formats.md#channel-uris)), or any other secure channel (including in-band exchange over an existing authenticated unicast session). Anyone who possesses the key is a member; there is no central authority and no mechanism to revoke membership without changing the key for everyone.

### Managed Channels

A managed channel is administered by a designated managing node that controls membership. Unlike named and private channels, a managed channel supports adding and removing individual members without requiring all remaining members to re-join manually.

> **Note:** The specific wire formats and MAC commands for managed channel operations (join requests, key distribution, rotation signalling) are not yet defined. The MAC layer itself is unaffected — managed channels use the same multicast packet format and cryptographic processing as any other channel.

To join a managed channel, a node provides its public key to the managing node — either out-of-band or via an in-band join request that the manager can accept or deny. Once accepted, the new member receives the current channel key and channel metadata from the managing node.

The managing node periodically rotates the channel key. When a key rotation occurs, each current member receives the new key along with the time at which it becomes active, allowing a coordinated switchover. Because the [channel identifier](packet-types.md#channel-identifier-derivation) is derived from the channel key, a key rotation also changes the channel's on-wire identifier; the application layer masks this from the user so the channel appears to be the same.

To remove a member, the managing node distributes a new key to all members *except* the excluded node. The excluded node still holds the old key but cannot decrypt traffic encrypted under the new one.

Members that are offline during a key rotation can request the current key from the managing node when they reconnect.

## Default Channels

Implementations should recognize two well-known named channels with specific behavior requirements.

### `public`

The `public` channel (derived from `umsh:cs:public`) is the default flooded group chat channel. It provides a shared communication space analogous to an open town square — any node that knows the name can participate.

- Maximum flood hops: **5** without a region code, **7** with a region code.
- Traffic **may** be encrypted (E=1).
- Chat messages that do not include the full source key (`S=1`) **must not** be displayed in the user interface. This ensures that users can always verify sender identity on the public channel, even though the channel key itself is public knowledge.

### `EMERGENCY`

The `EMERGENCY` channel (derived from `umsh:cs:EMERGENCY`, case-sensitive) is reserved for emergency communications. Repeaters should prioritize forwarding packets on this channel.

- Maximum flood hops: **5** without a region code, **7** with a region code.
- Chat messages **must not** be encrypted — all emergency traffic must be readable by any node in range, including nodes that have not explicitly joined the channel.
- Chat messages **must** include the full source key (`S=1`).
- Chat messages **must** include an EdDSA signature in the payload.
- Messages that do not meet all three requirements (unencrypted, full source key, signed) **must not** be accepted or displayed by the user interface.

These requirements ensure that emergency traffic is universally readable, attributable to a specific node, and cryptographically authenticated against impersonation.

## Payload Reuse

Application-layer channel communication reuses the same payload types as unicast. For example, group chat uses the same [text message](app-text-messages.md) and [chat room](app-chat-rooms.md) payload formats as direct messaging. However, not all application types are valid over multicast — see [Payload Types](payload-format.md) for compatibility.
