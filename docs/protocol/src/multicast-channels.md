# Multicast Channels

A multicast channel is fundamentally a symmetric key shared among all participants.

## Channel Membership

Any node configured with a given channel key is considered joined to that channel and may receive packets sent to it.

## Channel Hint

A 2-byte channel hint is derived from the channel key and placed in multicast packets to help nodes identify likely matching channels without attempting every configured key.

When encryption is enabled, the source address is encrypted inside the ciphertext along with the payload, concealing the sender's identity from observers who do not possess the channel key. When encryption is not enabled, the source address appears in cleartext.

## Named Channels

Some channel keys may be derived directly from channel names. These are effectively public or semi-public channels:

- Anyone who knows the name can derive the key
- Long, high-entropy names may provide some practical obscurity, but this should not be treated as strong secrecy unless the derivation method and entropy support it

## Multicast Payload Reuse

Application-layer multicast communication generally reuses the same payload types used for ordinary one-to-one communication. For example, group chat can use the same message payload formats as direct chat.
