# Introduction

UMSH is a LoRa-oriented mesh protocol inspired by cryptographically
addressed mesh systems such as MeshCore. In UMSH, endpoints are identified
by public keys, and multicast communication is based on shared symmetric
channel keys. At its core, UMSH defines a **MAC layer** — framing,
addressing, encryption, authentication, and hop-by-hop forwarding. UMSH
also defines application-layer protocols for text messaging, chat rooms,
and node management that are built on top of the MAC layer. The MAC
layer treats payloads opaquely and can equally carry UMSH-defined
application protocols, third-party protocols such as CoAP, or any other
higher-layer content.

Point-by-point protocol comparisons with [MeshCore](meshcore-comparison.md), [Meshtastic](meshtastic-comparison.md), and [Reticulum](reticulum-comparison.md) are available.

UMSH is designed to support:

- Public-key-addressed unicast
- Symmetric-key multicast
- Optional payload encryption
- End-to-end authentication across multi-hop paths
- Selective flooding and source-routed delivery
- Operation in both encrypted and amateur-radio-compliant unencrypted modes
- Ability to operate in a way that preserves perfect forward secrecy (PFS)
- Timestamp-free at the MAC layer
- Low-power operation

## Use Cases

UMSH is designed for deployments where LoRa's range and low power consumption are valuable and where the constraints of LoRa — low data rates, small frame sizes, shared channel — make protocol efficiency and cryptographic robustness important.

**Intended use cases include:**

- **Off-grid text communication** — chat, direct messaging, and group channels between people in areas without cellular coverage: hiking, expeditions, disaster response, rural communities.
- **Emergency and disaster communications** — resilient mesh networking that operates without any fixed infrastructure and degrades gracefully as nodes go offline.
- **IoT and sensor telemetry** — authenticated sensor readings from battery-powered field devices, where per-packet overhead directly affects battery life and where tampered readings could have real consequences.
- **Amateur radio mesh networking** — the protocol defines explicit amateur-radio-compliant modes with callsign fields and mandatory unencrypted operation, supporting legal use on amateur frequencies.
- **Privacy-sensitive communication** — blind unicast and encrypted multicast allow metadata concealment (sender and recipient identity) for contexts where traffic analysis is a concern.
- **Embedded and constrained deployments** — compact encoding (1-byte FCF, 2-byte hints, minimal per-packet overhead), single-frame design, and no mandatory runtime state (no path tables, no clock synchronization) make UMSH suitable for bare-metal microcontrollers with minimal RAM and no operating system.

**UMSH is not designed for:**

- High-bandwidth applications — LoRa data rates (typically 0.3–27 kbps) make real-time voice, video, or large file transfer impractical.
- Applications requiring low latency — multi-hop flood delivery adds variable latency that makes UMSH unsuitable for interactive or time-sensitive protocols.

## Design Model

This document treats the terms **channel** and **multicast group** as
equivalent. Unless otherwise noted, "channel" refers to a multicast
group secured by a shared symmetric key.

### Layer Separation

The UMSH MAC layer provides framing, addressing, encryption, authentication, and single-hop or multi-hop forwarding. It does not interpret payload content — the payload field carries higher-layer data opaquely, constrained only by the LoRa frame size budget.

This clean separation means that features such as fragmentation, end-to-end reliable delivery, and application-level routing are handled by higher-layer protocols carried in the payload. For example, a payload might carry a 6LoWPAN-compressed IPv6 datagram, a CoAP request, or one of the UMSH-defined application protocols such as text messaging. If fragmentation is needed, it must be provided by the higher-layer protocol (e.g., CoAP block-wise transfer, 6LoWPAN fragmentation).

### Nodes

A **node** is a logical endpoint on the network, identified by a 32-byte
Ed25519 public key. That public key is the node's long-term network
identity — it serves as both its address and its cryptographic credential.
A single physical device may host multiple nodes (e.g., a repeater node
and a chat node), each with its own keypair.

A node's public key must be known to communicate with it directly. Public
keys can be learned through several mechanisms:

- **Beacons and advertisements** — nodes periodically broadcast their
  presence, optionally including identity information (see [Node Identity](node-identity.md))
- **QR codes and URIs** — public keys can be shared out-of-band via
  `umsh:n:` URIs (see [URI Formats](uri-formats.md))
- **First-contact packets** — a sender can set the `S` flag to include
  its full public key in any packet, allowing the receiver to learn it directly from the wire

Once a node's public key is known, it can be cached and subsequent packets
can use a compact 2-byte source hint instead of the full key, saving 30
bytes per packet.

#### Node Metadata

Nodes may also advertise additional metadata — such as a human-readable name,
role, capabilities, and location — via the [Node Identity](node-identity.md)
payload. Metadata can also be contained in QR codes and URIs. This metadata
is carried at the application layer and is not required by the MAC layer.

#### Perfect Forward Security

Nodes can be created on the fly to support perfect forward security. For example,
two nodes could share the public keys of temporary special-purpose nodes that they
have created just for communication between them, throwing away the private
keys afterward. 

### Unicast

Unicast packets are addressed to a destination node and may be authenticated or encrypted using per-destination cryptographic material derived from sender/recipient key agreement.

### Multicast Channels

A multicast channel is represented by a shared symmetric key. All nodes configured with that key are considered members of the channel and may receive packets addressed to it.

A 2-byte channel hint is derived from the channel key and included in multicast packets to help receivers identify candidate channels efficiently. When encryption is enabled, the source address is encrypted inside the ciphertext, concealing the sender from non-members.

### Blind Unicast

**Blind unicast** hides both the sender and destination from observers who do not possess the appropriate channel key, while still restricting payload access to the final recipient. The recipient must also possess the channel key.

