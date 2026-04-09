# Limitations & Open Items

## Known Limitations

### No MAC-Layer Fragmentation

UMSH intentionally does not define a fragmentation mechanism at the MAC layer. The MAC layer delegates fragmentation to higher-layer protocols carried in the payload (see [Layer Separation](introduction.md#layer-separation)). LoRa payloads are typically limited to approximately 200–250 bytes, and UMSH header overhead (FCF, addresses, SECINFO, MIC) consumes a significant portion of this budget. Higher-layer protocols that require payloads larger than a single frame must provide their own segmentation — for example, CoAP block-wise transfer or 6LoWPAN fragmentation.

### Multicast Sender Authentication

Multicast channels use a shared symmetric key. Any node possessing the channel key can send packets with any claimed source address, and other channel members cannot cryptographically verify that the claimed sender actually produced the packet. When the `S` flag is set, the source public key is carried in the packet and can be used for application-level trust decisions, but the protocol-level MIC authenticates only channel membership, not individual sender identity.

This is a fundamental property of symmetric-key multicast and is shared by other protocols with similar designs, including MeshCore.

## Known Hint Collision Properties

MeshCore originally used 1-byte hints for source, destination, and source-routing addresses, placing the birthday bound at just 16 nodes — far too low for practical networks. UMSH uses 3-byte hints for node addresses and 2-byte hints for router and trace-route addresses.

As a concrete example, consider a regional network of approximately 600 active nodes (roughly the scale of the Oregon MeshCore network, concentrated in the Portland area). The probability of at least one collision among all nodes for a given hint size:

| Hint size | Collision probability (600 nodes) |
|---|---|
| 1 byte (256 values) | ~100% |
| 2 bytes (65,536 values) | ~94% |
| 3 bytes (16,777,216 values) | ~1% |

### Node hints (3 bytes)

The destination hint is a prefilter: a match causes the receiver to attempt full cryptographic verification. A false positive wastes computation on every packet exchanged between the two colliding nodes, for the lifetime of both identities. The cost is persistent and proportional to traffic volume. The source hint is used for source identification, traffic attribution, and diagnostics.

With 3-byte hints the collision probability drops to ~1% even in a 600-node regional network. The only remedy for a collision is for one node to generate a new identity (a new Ed25519 keypair), which for a chat node means all peers must re-learn the new public key. The 3-byte size makes this scenario rare.

### Router hints (2 bytes)

Router hints are used in source-route and trace-route options. A router hint collision causes an unintended repeater to forward the packet; MIC-based duplicate suppression ensures each repeater forwards a given packet at most once, so collisions add traffic but not loops or incorrect delivery.

Source routing is an inherently local operation — only repeaters within radio range of the transmitting node can act on the hint. For a local population of ~50 repeaters:

- 1-byte hints: ~46% collision probability
- 2-byte hints: ~1.9% collision probability

2-byte router hints reduce the collision probability by roughly 24× relative to 1-byte hints for typical deployments, at a cost of 1 extra byte per hop in source-route and trace-route options.

## Open Issues

### Bridge Hop Confirmation

A **bridge** is a node that relays UMSH packets over a different medium or channel than the one it received them on — for example, an internet backhaul, a wired link, or a different radio band connecting two geographically distant segments. Bridges are transparent to the protocol at the MAC layer: they consume source-route hints and forward packets exactly as repeaters do.

The simplest approach to bridge confirmation is to have the bridge retransmit the packet on the same inbound medium in addition to forwarding it to the other medium. This fully preserves the existing implicit confirmation mechanism with no protocol changes — the previous-hop sender hears the retransmission and confirms delivery exactly as it would with a normal repeater. The cost is doubled on-air time for every bridged packet on the inbound segment.

Retransmitting the entire packet solely to signal receipt is wasteful. However, if the bridge does not retransmit, the previous-hop node cannot observe the bridge's onward transmission and will assume delivery failed — triggering retries that are even more wasteful, since the bridge did receive the packet successfully.

To be honest, it isn't entirely clear that this is a problem worth optimizing. Bridges aren't expected to exactly be common. But it is worth thinking about, so here is a possible solution:

#### Possibility: Hop Signal for non-retransmitting bridges

A **Hop Signal** is a local-only BCST (no FHOPS field, so it is never forwarded) emitted by the bridge on its inbound medium immediately after handling a packet. The BCST carries a MIC reference to the original packet for correlation, a signal type (Hop Ack or Hop Nak), and the bridge's own 3-byte SRC hint for identification. It is smaller than a full retransmission and can also convey failure (Hop Nak) rather than just presence.

Because only one packet type slot (value 5) remains reserved, a Hop Signal would be defined as a MAC option on BCST rather than a dedicated packet type, preserving the reserved slot for a future use case with stronger architectural justification.

Hop signals would be informational only. A forged Hop Ack is equivalent to silent dropping — already in the threat model — so senders must still fall back to full MAC ack timeout if no Hop Ack arrives. The format of the Hop Signal option and the complete emission rules have not yet been defined.

### Intermediate Node Error Feedback

#### Problem

When a packet cannot be delivered — for example, because a bridge's backhaul link is down, or because a source-routed path is broken — intermediate nodes have no reliable way to inform the original sender. The sender can only detect failure by waiting for a MAC ack that never arrives.

This timeout-based detection is slow and provides no diagnostic information: the sender cannot distinguish a slow destination from a broken path.

Two independent gaps make this hard to address:

- **Routing**: an intermediate node needs a return path to send anything back. The sender's 3-byte SRC hint provides a destination address, but that alone is not enough — the error packet needs to know how to get there. Flood routing is not an option: flooding an error response across the mesh in response to a delivery failure would be prohibitively expensive. A return path is only available if the original packet carried a trace route option, whose accumulated hops already describe the return path from the receiver back toward the original sender.

- **Authentication**: an intermediate node cannot send an authenticated reply without the sender's full public key. Any error reply sent without it is unencrypted and unauthenticated. Only the final destination — which has the full source key and performs ECDH — can send a fully authenticated reply.

Without a trace route, there is no viable return path and no error feedback is possible.

#### Possible Approach: Trace-Route Return Path

If the original packet carries a trace route option, an intermediate node can use the accumulated hops directly as a source route back toward the original sender and emit an error packet along that path, addressed to the sender's 3-byte SRC hint.

This is opt-in by the sender: include a trace route to signal willingness to receive error feedback; omit it to suppress errors. No special flag or option is needed. If no trace route is present, the intermediate node has no viable return path and should remain silent.

The on-wire format for such an error packet would likely be similar or identical to the Hop Signal mechanism described above — a compact notification carrying a signal type and a MIC reference — differing only in that it carries a source route and travels end-to-end rather than remaining local. Defining a single format that covers both cases would reduce protocol surface area.

Any such error is unencrypted and unauthenticated. Senders MUST treat it as untrusted diagnostic information only — a forged error is equivalent in effect to a dropped packet, which is already in the threat model.

This remains an open design question. No mechanism is specified in the current version of this protocol. The format and semantics of error reports — error codes, triggering conditions, encoding — have not yet been defined.
