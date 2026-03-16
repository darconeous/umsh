# Multicast Channels

A multicast channel is a group communication primitive based on a shared symmetric key. Any node configured with a given channel key is a member of that channel and can send and receive packets addressed to it.

## Channel Keys

A channel key is a 16-byte symmetric key. It serves as both the membership credential and the root secret from which encryption, authentication, and identification keys are derived (see [Multicast Packet Keys](security.md#multicast-packet-keys)).

Channel keys are distributed out-of-band — via QR codes, `umsh:ck:` URIs (see [URI Formats](uri-formats.md#channel-uris)), or any other secure channel.

UMSH does not currently define an in-band key distribution protocol.

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

## Named Channels

Channel keys may be derived from human-readable channel names rather than distributed as raw keys. A named channel is identified by a `umsh:cs:` URI (see [URI Formats](uri-formats.md#channel-uris)):

```text
umsh:cs:Public
```

Named channels are effectively public or semi-public — anyone who knows the name can derive the key. Long, high-entropy names may provide practical obscurity, but this should not be treated as strong secrecy.

The exact key derivation function for named channels is not yet specified (see [Open Items](limitations.md#open-items-and-provisional-areas)).

## Relationship to Blind Unicast

Channels also enable [blind unicast](packet-types.md#blind-unicast-packet), which uses a channel key to conceal both the sender and destination addresses while protecting the payload end-to-end with pairwise encryption. In this mode, the channel serves as a metadata-concealment layer rather than a group communication mechanism — the payload is readable only by the intended recipient, not by all channel members.

## Payload Reuse

Application-layer multicast communication reuses the same payload types as unicast. For example, group chat uses the same [text message](app-text-messages.md) and [chat room](app-chat-rooms.md) payload formats as direct messaging.
