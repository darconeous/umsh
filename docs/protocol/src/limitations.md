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

However, retransmitting the entire packet just to communicate the fact that it was received could be considered wasteful. However, if the bridge doesn't somehow acknowledge the packet, the previous-hop node cannot observe the bridge's onward transmission and, upon not hearing the expected retransmission, will assume delivery failed and retry. These retries are even more wasteful: the bridge did receive the packet successfully, but there is no way for the previous hop to know that.

To be honest, it isn't entirely clear that this is a problem worth optimizing. Bridges aren't expected to exactly be common. But it is worth thinking about.

#### Possibility: Hop Signal for non-retransmitting bridges

A **Hop Signal** is a local-only BCST (no FHOPS field, so it is never forwarded) emitted by the bridge on its inbound medium immediately after handling a packet. The BCST carries a MIC reference to the original packet for correlation, a signal type (Hop Ack or Hop Nak), and the bridge's own 3-byte SRC hint for identification. It is smaller than a full retransmission and can also convey failure (Hop Nak) rather than just presence.

Because only one packet type slot (value 5) remains reserved, a Hop Signal would be defined as a MAC option on BCST rather than a dedicated packet type, preserving the reserved slot for a future use case with stronger architectural justification.

Hop signals would be informational only. A forged Hop Ack is equivalent to silent dropping — already in the threat model — so senders must still fall back to full MAC ack timeout if no Hop Ack arrives. The format of the Hop Signal option and the complete emission rules have not yet been defined.

### Intermediate Node Error Feedback

#### Problem

When a packet cannot be delivered — for example, because a bridge's backhaul link is down, or because a source-routed path is broken — intermediate nodes have no reliable way to inform the original sender. The sender can only detect failure by waiting for a MAC ack that never arrives.

This timeout-based detection is slow (the sender must wait long enough to account for bridge round-trip latency) and provides no diagnostic information: the sender cannot distinguish a slow destination from a broken path.

A fully addressed error reply from an intermediate node is not possible in the general case. Unicast packets carry only a 3-byte source hint — insufficient to address a response or derive the sender's public key. Only the final destination, which has the full source key (either from cache or the packet itself) and uses it to perform ECDH, can send an authenticated reply.

#### Possible Approaches

**1. S=1 (full source key) enables complete error replies — no spec change needed**

When the sender sets `S=1`, any intermediate node receives the full 32-byte Ed25519 public key and has everything needed to construct an authenticated unicast reply. Senders who want error feedback on a specific packet can opt in simply by including their key.

The drawback is overhead: `S=1` costs 31 additional bytes and conflates "error feedback desired" with "I'm announcing my public key." For packets already setting `S=1` (e.g., first contact, PFS session establishment), this is free. For routine traffic, it is a significant per-packet cost.

**2. Feedback Address option — small, explicit opt-in**

Define a new MAC option carrying only the sender's own 3-byte hint. This is ~5 bytes with option encoding — much cheaper than `S=1`. Intermediate nodes that detect an error can address a best-effort response to this 3-byte hint.

The returned error packet is unencrypted (no ECDH possible) and unauthenticated, but carries the original packet's MIC-REF for correlation. A 3-byte destination hint gives ~1-in-16M false positives: the sender can treat a match as high-confidence even without cryptographic verification. The receiver must treat this as untrusted diagnostic information only.

This approach requires a new option number and an unencrypted error packet type or convention.

**3. Reversed trace route path notification**

If the original packet carries a trace route option, the return path back to the sender accumulates hop by hop. An intermediate node that detects an error can reverse the accumulated trace to reconstruct a source route toward the sender, then emit an unencrypted error packet that hops back along that path.

The sender's 3-byte SRC hint is used as a coarse destination filter on the returning packet, giving a ~1-in-16M false-positive rate — a false match simply causes an unrelated node to read an error message it cannot correlate to any of its own traffic. The MIC-REF is the real correlator.

This requires no new addressing mechanism but only works when the sender included a trace route option. It is naturally opt-in: senders who want error feedback include a trace route; senders who do not, don't. It requires defining what this error packet looks like (a new packet type, or a BCST-with-option convention similar to the Hop Signal mechanism proposed for bridges).

**4. Extend Hop Signal with a return path**

The Hop Signal mechanism (a BCST with a MIC-REF option, emitted by bridges for local ack/nak) could be extended: when a trace route is present, append the reversed path to the Hop Signal so it can travel back toward the sender rather than remaining local. This unifies the bridge ack/nak mechanism with the broader error-feedback problem under a single option definition.

#### Considerations

Options 2 and 3 compose well: the Feedback Address option provides a 3-byte return address, and the reversed trace route provides the return path. Together they form a lightweight opt-in error feedback mechanism with ~5–7 bytes of per-packet overhead when enabled.

Option 1 is available today with no spec changes, covers more than just error feedback, and is already justified on packets that are already setting `S=1`.

Any error feedback message traveling back through the network using options 2 and 3 is unencrypted and unauthenticated. The original senders MUST treat such messages as untrusted diagnostic information — a forged error message is equivalent in effect to a dropped packet, which is already in the threat model.

This remains an open design question. No approach is specified in the current version of this protocol. Additionally, regardless of which addressing mechanism is chosen, the format and semantics of error reports themselves — error codes, what conditions trigger them, how they are encoded — have not yet been defined.
