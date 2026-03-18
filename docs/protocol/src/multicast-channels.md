# Multicast Channels

A multicast channel is a group communication primitive based on a shared symmetric key. Any node configured with a given channel key is a member of that channel and can send and receive packets addressed to it.

## Channel Keys

A channel key is a 16-byte symmetric key. It serves as both the membership credential and the root secret from which encryption, authentication, and identification keys are derived (see [Multicast Packet Keys](security.md#multicast-packet-keys)).

How a node obtains a channel key depends on the type of channel — see [Joining a Channel](#joining-a-channel) below.

## Channel Identifier

Each channel is identified on the wire by a 2-byte channel identifier [derived from the channel key](packet-types.md#channel-identifier-derivation). This identifier is a compact hint that allows receivers to quickly identify candidate channels without attempting decryption with every configured key. Like destination hints, channel identifiers are not cryptographically authoritative — collisions are possible and must be resolved by attempting cryptographic verification.

## Encrypted and Unencrypted Modes

Multicast packets may be sent with or without encryption, controlled by the `E` flag in the Security Control Field.

- **Encrypted** (E=1): The source address is encrypted together with the payload, concealing the sender's identity from observers who do not possess the channel key. Only channel members can recover the source address and payload. See [Encrypted Multicast](packet-types.md#encrypted-multicast-e--1) for the packet layout.

- **Unencrypted** (E=0): The source address and payload appear in cleartext, but the packet is still authenticated with a MIC derived from the channel key. This mode is useful for amateur radio operation or other contexts where encryption is not permitted. See [Unencrypted Multicast](packet-types.md#unencrypted-multicast-e--0) for the packet layout.

## Multi-Hop Delivery

Multicast packets are delivered via flood forwarding, bounded by the optional hop count field. Repeaters forward multicast packets according to the standard [forwarding procedure](repeater-operation.md#forwarding-procedure), including duplicate suppression, signal-quality filtering, and region-scoped flooding.

## Sender Authentication

Multicast authentication is based on the shared channel key, not on individual sender identity. The MIC proves that the sender possesses the channel key, but any channel member can construct a valid packet with any claimed source address. This is a fundamental property of symmetric-key multicast — see [Multicast Sender Authentication](limitations.md#multicast-sender-authentication) for further discussion.

## Joining a Channel

UMSH supports three models for channel membership, from simplest to most capable.

### Named Channels

Channel keys may be derived from human-readable channel names rather than distributed as raw keys. A named channel is identified by a `umsh:cs:` URI (see [URI Formats](uri-formats.md#channel-uris)):

```text
umsh:cs:Public
```

Named channels are effectively public — anyone who knows the name can derive the key and participate. Long, high-entropy names may provide practical obscurity, but this should not be treated as strong secrecy.

The exact key derivation function for named channels is not yet specified (see [Open Items](limitations.md#open-items-and-provisional-areas)).

### Private Channels

For channels that require real secrecy, the channel key is distributed out-of-band — via QR codes, `umsh:ck:` URIs (see [URI Formats](uri-formats.md#channel-uris)), or any other secure channel (including in-band exchange over an existing authenticated unicast session). Anyone who possesses the key is a member; there is no central authority and no mechanism to revoke membership without changing the key for everyone.

### Managed Channels

A managed channel is administered by a designated managing node that controls membership. Unlike named and private channels, a managed channel supports adding and removing individual members without requiring all remaining members to re-join manually.

> **Note:** The specific wire formats and MAC commands for managed channel operations (join requests, key distribution, rotation signalling) are not yet defined. The MAC layer itself is unaffected — managed channels use the same multicast packet format and cryptographic processing as any other channel. 

To join a managed channel, a node provides its public key to the managing node — either out-of-band or via an in-band join request that the manager can accept or deny. Once accepted, the new member receives the current channel key and channel metadata from the managing node.

The managing node periodically rotates the channel key. When a key rotation occurs, each current member receives the new key along with the time at which it becomes active, allowing a coordinated switchover. Because the [channel identifier](packet-types.md#channel-identifier-derivation) is derived from the channel key, a key rotation also changes the channel's on-wire identifier; the application layer masks this from the user so the channel appears to be the same.

To remove a member, the managing node distributes a new key to all members *except* the excluded node. The excluded node still holds the old key but cannot decrypt traffic encrypted under the new one.

Members that are offline during a key rotation can request the current key from the managing node when they reconnect.

## Relationship to Blind Unicast

Channels also enable [blind unicast](packet-types.md#blind-unicast-packet), which uses a channel key to conceal both the sender and destination addresses while protecting the payload end-to-end with pairwise encryption. In this mode, the channel serves as a metadata-concealment layer rather than a group communication mechanism — the payload is readable only by the intended recipient, not by all channel members.

## Payload Reuse

Application-layer multicast communication reuses the same payload types as unicast. For example, group chat uses the same [text message](app-text-messages.md) and [chat room](app-chat-rooms.md) payload formats as direct messaging. However, not all application types are allowed over multicast.




