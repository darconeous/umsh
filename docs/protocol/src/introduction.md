# Introduction

UMSH is a LoRa-oriented mesh protocol that grew out of a simple question: what would a cryptographically addressed LoRa mesh look like if designed from the ground up with strong security and clean architecture? Inspired by MeshCore, UMSH started as a thought experiment addressing what its author saw as [critical shortcomings](meshcore-comparison.md#cryptography)—shortcomings that would practically require backward-incompatible changes to fix. What began as a toy protocol has since been developed into this comprehensive specification.

The ideas in UMSH are free for anyone to adopt. MeshCore may never introduce a breaking protocol revision, but individual techniques described here — compact authenticated framing, nonce-misuse-resistant encryption, blind addressing — could be useful to other similar LoRa mesh protocols. Meshtastic has discussed the possibility of a breaking v3 revision, and some of these ideas may be relevant there as well.

## Overview

In UMSH, endpoints are identified
by public keys, and multicast communication is based on shared symmetric
channel keys. At its core, UMSH defines a **MAC layer** with framing,
addressing, encryption, authentication, and hop-by-hop forwarding. UMSH
also defines application-layer protocols for text messaging, chat rooms,
and node management that are built on top of this foundation. The MAC
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
- Ability to operate in a way that preserves [perfect forward secrecy (PFS)](security.md#perfect-forward-secrecy-sessions)
- Timestamp-free at the MAC layer

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

## Design Principles

The following principles guide UMSH's design. They reflect the constraints of LoRa — small frames, low data rates, unreliable delivery, no infrastructure — and together they determine what the protocol can and cannot do well.

**Single-frame design.** Every UMSH packet must fit in a single LoRa frame (~255 bytes). There is no multi-frame reassembly, no fragmentation state machine, and no assumption that related packets will arrive in order or at all. This constraint drives nearly every other design decision: compact encodings, short headers, and delegation of larger-than-one-frame operations to higher-layer protocols.

**Robustness.** Where a design choice exists between a construction that is slightly more efficient and one that fails more gracefully, UMSH chooses the latter. The AES-SIV-inspired encryption tolerates nonce reuse without catastrophic failure. Key derivation uses well-separated HKDF domains so that a flaw in one derivation path does not compromise others.

**Tolerance of loss and disorder.** LoRa is a lossy, high-latency medium where packets are routinely dropped, duplicated, or delivered out of order. The protocol assumes none of these conditions are exceptional. Replay protection uses simple monotonic counters. No operation requires both sides to maintain tightly coupled session state that can desynchronize when packets go missing. Cryptographic schemes that fail closed on missed or reordered messages are a poor fit for this environment.

**Privacy by default.** Passive observers should learn as little as possible from the wire. Addresses appear as compact hints rather than cleartext identifiers. Encrypted multicast conceals the sender. Blind unicast conceals both sender and destination. No mandatory metadata (timestamps, sequence numbers, node names) is leaked in the clear.

**Brevity.** Every byte costs airtime, and airtime costs battery. The protocol minimizes per-packet overhead — 1-byte frame control, 2-byte hints, variable-length options that are absent when unused — so that maximum payload capacity is available to higher layers.

**Layer separation.** The core protocol treats payloads opaquely. It provides framing, addressing, encryption, authentication, and hop-by-hop forwarding, but does not interpret payload content. Application-layer concerns — message types, fragmentation, delivery confirmation — are handled by higher-layer protocols carried in the payload. A payload might carry a UMSH-defined text message, a CoAP request, or a 6LoWPAN-compressed IPv6 datagram; the core protocol does not distinguish between them.

**Minimal mandatory state.** A node can receive and process any packet using only its own keypair and configured channel keys. There are no mandatory path tables, no clock synchronization, and no session state required for basic operation. This makes the protocol suitable for bare-metal microcontrollers with minimal RAM and no operating system.

## Key Concepts

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
- **First-contact packets** — a sender can set the [`S` flag](packet-structure.md#frame-control-field) to include
  its full public key in any packet, allowing the receiver to learn it directly from the wire

Once a node's public key is known, it can be cached and subsequent packets
can use a compact 2-byte source hint instead of the full key, saving 30
bytes per packet.

#### Node Metadata

Nodes may also advertise additional metadata — such as a human-readable name,
role, capabilities, and location — via the [Node Identity](node-identity.md)
payload. Metadata can also be contained in QR codes and URIs. This metadata
is carried at the application layer and is not required by the MAC layer.

### Unicast

Unicast packets are addressed to a destination node and may be authenticated or encrypted using per-destination cryptographic material derived from sender/recipient key agreement (see [Frame Types](packet-types.md) and [Security & Cryptography](security.md)).

### Channels

A channel is a shared symmetric key that serves two roles: **multicast** group communication and **blind unicast** metadata concealment. All nodes configured with a given channel key are members and can send and receive multicast packets addressed to it. Blind unicast uses the channel key to hide sender and destination addresses on the wire, while protecting the payload with [combined keys](security.md#blind-unicast-payload-keys) that require both the channel key and the pairwise shared secret — only the intended recipient can read it. See [Channels](multicast-channels.md) for channel types, membership models, and default channels.

### Perfect Forward Secrecy

UMSH supports [perfect forward secrecy](security.md#perfect-forward-secrecy-sessions) via ephemeral node addresses. Either node can initiate a PFS session, after which both parties communicate using ephemeral node addresses whose private keys are never stored durably and are erased at session end. Compromise of long-term keys cannot retroactively expose traffic protected by a completed PFS session.

