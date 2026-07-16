# Addressing

UMSH nodes are identified by their 32-byte Ed25519 public keys. Including a full 32-byte address in every packet would be expensive in the constrained LoRa frame budget, so UMSH defines several compact **hint** representations — short prefixes of a public key that allow receivers to quickly identify likely matches without the full key. Hints are not cryptographically authoritative; they serve only as cheap prefilters to avoid unnecessary work.

The sections below describe the three addressing forms used across the protocol: node hints, router hints, and source addresses.

## Presentation

UMSH addresses are canonically encoded and displayed using [base 58](https://bitcoinwiki.org/wiki/base58). Addresses may also be rendered using base 16 as 64 hexadecimal digits — lowercase preferred, either case accepted when parsing — but the preferred encoding is base58. The two forms are unambiguously distinguished by length.

The base58 encoding is fixed-length: a 32-byte address always renders as exactly 44 digits, left-padded with `1` (the base58 zero digit) when its numeric value would otherwise encode shorter.

## Node Hint

A **node hint** is defined as:

- the **first three bytes of a node's 32-byte public key**

Node hints serve as the destination hint in unicast packets and as the compact source hint in source addresses (see below). A node hint is not authoritative and is used only as a fast prefilter to avoid unnecessary cryptographic work.

A receiver that sees a matching destination hint must still confirm that it is the intended destination by successfully processing the packet cryptographically.

### Rendering Node Hints

Rendering a node hint to the user is a little tricky due to the fact that *most* node hints can be rendered as just the first four characters of the encoded public key. In these cases, we would simply take our node hint, append 29 zeros, perform the base 58 encoding, and just drop everything except the first four characters.

However, in some cases when using this method, the fourth character may differ from the fourth character in the actual address. This is highly undesirable.

One way to address this is to perform two base58 encodings: one padded with 0x00 and one padded with 0xFF. If the fourth encoded character is the same between them both, then four characters can be used as the rendered node hint. However, if the encodings differ, the rendered hint is the longest common prefix of the two encodings followed by a single `*`. The common prefix is three characters except in the rare case where a carry propagates into the third digit, leaving two verified characters. Every character preceding the `*` is guaranteed to match the full base58 rendering of any matching address.

Note that there are more efficient ways of calculating this than padding with 0x00 and 0xFF and encoding the whole address twice, but logically that is the process.

## Router Hint

A **router hint** is defined as:

- the **first two bytes of the repeater's 32-byte public key**

Router hints are used in:

- source-route options
- trace-route options

Because router hints are only 2 bytes, collisions are possible in dense networks but are handled gracefully: the MIC-based duplicate suppression ensures that each repeater forwards a given packet at most once, so a router hint collision causes a spurious forward but not a loop or incorrect delivery.

### Rendering Router Hints

Router hints are rendered using the same procedure as node hints, with a three-character budget and 30 bytes of padding. Because two bytes pin down only slightly more than two base58 digits, the third character is ambiguous for most router hints; the two-characters-plus-`*` form is the common case.

## Source Address

A source address in a packet is either:

- a **compact source hint** (a prefix of the sender's 32-byte public key), when the `S` flag in the FCF is clear, or
- the **full 32-byte public key**, when the `S` flag is set.

The source hint is **3 bytes** (the first three bytes of the public key) when `S` is clear.

The source hint is a compact reference used when the receiver is expected to already have the sender's full public key cached (e.g., from a prior advertisement or first-contact exchange). When the full public key is present, the receiver can perform ECDH directly from the packet without any prior state.

In encrypted multicast and blind unicast packets, the source address is carried inside the ciphertext: a 3-byte hint when `S` is clear, or the full 32-byte public key when `S` is set.
