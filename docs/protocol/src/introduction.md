# Introduction

UMSH is a LoRa-oriented mesh protocol inspired by cryptographically addressed mesh systems such as MeshCore. In UMSH, endpoints are identified by public keys, and multicast communication is based on shared symmetric channel keys. At its core, UMSH defines a **MAC layer** — framing, addressing, encryption, authentication, and hop-by-hop forwarding. UMSH also defines application-layer protocols for text messaging, chat rooms, and node management that are built on top of the MAC layer. The MAC layer treats payloads opaquely and can equally carry UMSH-defined application protocols, third-party protocols such as 6LoWPAN or CoAP, or any other higher-layer content.

This document treats the terms **channel** and **multicast group** as equivalent. Unless otherwise noted, "channel" refers to a multicast group secured by a shared symmetric key.

UMSH is designed to support:

- Public-key-addressed unicast
- Symmetric-key multicast
- Optional payload encryption
- End-to-end authentication across multi-hop paths
- Selective flooding and source-routed delivery
- Operation in both encrypted and amateur-radio-compliant unencrypted modes

## Design Model

### Nodes

Each node is identified by a 32-byte public key. That public key is the node's long-term network identity.

### Unicast

Unicast packets are addressed to a destination node and may be authenticated or encrypted using per-destination cryptographic material derived from sender/recipient key agreement.

### Multicast Channels

A multicast channel is represented by a shared symmetric key. All nodes configured with that key are considered members of the channel and may receive packets addressed to it.

A 2-byte channel hint is derived from the channel key and included in multicast packets to help receivers identify candidate channels efficiently.

### Blind Modes

UMSH supports "blind" modes, where some addressing metadata is concealed from observers who do not possess the appropriate channel key:

- **Blind multicast** hides the source address from non-members of the multicast channel.
- **Blind unicast** is intended to hide both sender and destination from observers lacking the channel key, while still restricting payload access to the final recipient.

### Layer Separation

The UMSH MAC layer provides framing, addressing, encryption, authentication, and single-hop or multi-hop forwarding. It does not interpret payload content — the payload field carries higher-layer data opaquely, constrained only by the LoRa frame size budget.

This clean separation means that features such as fragmentation, end-to-end reliable delivery, and application-level routing are handled by higher-layer protocols carried in the payload. For example, a payload might carry a 6LoWPAN-compressed IPv6 datagram, a CoAP request, or one of the UMSH-defined application protocols such as text messaging. If fragmentation is needed, it must be provided by the higher-layer protocol (e.g., CoAP block-wise transfer, 6LoWPAN fragmentation).
