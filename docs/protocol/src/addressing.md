# Addressing

UMSH nodes are identified by their 32-byte Ed25519 public keys. Including a full 32-byte address in every packet would be expensive in the constrained LoRa frame budget, so UMSH defines several compact **hint** representations — short prefixes of a public key that allow receivers to quickly identify likely matches without the full key. Hints are not cryptographically authoritative; they serve only as cheap prefilters to avoid unnecessary work.

The sections below describe the three addressing forms used across the protocol: destination hints, router hints, and source addresses.

## Destination Hint

A **destination hint** is defined as:

- the **first two bytes of the destination node's 32-byte public key**

This hint is not authoritative and is used only as a fast prefilter to avoid unnecessary cryptographic work.

A receiver that sees a matching destination hint must still confirm that it is the intended destination by successfully processing the packet cryptographically.

## Router Hint

A **router hint** is defined as:

- the **first byte of the repeater's 32-byte public key**

Router hints are used in:

- source-route options
- trace-route options

Because router hints are only 1 byte, collisions are expected and acceptable. A router hint is therefore only a compact routing selector, not a globally unique repeater identifier.

## Source Address

A source address in a packet is either:

- a **2-byte source hint** (the first two bytes of the sender's 32-byte public key), when the `S` flag in the FCF is clear, or
- the **full 32-byte public key**, when the `S` flag is set.

The source hint is a compact reference used when the receiver is expected to already have the sender's full public key cached (e.g., from a prior advertisement or first-contact exchange). When the full public key is present, the receiver can perform ECDH directly from the packet without any prior state.

In encrypted multicast and blind unicast packets, the source address is carried inside the ciphertext but still follows the `S` flag convention: a 2-byte hint when `S` is clear, or the full 32-byte public key when `S` is set.
