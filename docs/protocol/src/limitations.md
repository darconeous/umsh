# Limitations & Open Items

## Known Limitations

### No MAC-Layer Fragmentation

UMSH intentionally does not define a fragmentation mechanism at the MAC layer. The MAC layer delegates fragmentation to higher-layer protocols carried in the payload (see [Layer Separation](introduction.md#layer-separation)). LoRa payloads are typically limited to approximately 200–250 bytes, and UMSH header overhead (FCF, addresses, SECINFO, MIC) consumes a significant portion of this budget. Higher-layer protocols that require payloads larger than a single frame must provide their own segmentation — for example, CoAP block-wise transfer or 6LoWPAN fragmentation.

### Multicast Sender Authentication

Multicast channels use a shared symmetric key. Any node possessing the channel key can send packets with any claimed source address, and other channel members cannot cryptographically verify that the claimed sender actually produced the packet. When the `S` flag is set, the source public key is carried in the packet and can be used for application-level trust decisions, but the protocol-level MIC authenticates only channel membership, not individual sender identity.

This is a fundamental property of symmetric-key multicast and is shared by other protocols with similar designs, including MeshCore.

## Open Issues

### Hint Collisions

Two-byte destination hints will occasionally collide, causing a receiver to attempt cryptographic verification on packets intended for a different node. The protocol does not define a mechanism to mitigate this beyond treating hints as a prefilter (see [Addressing](addressing.md#destination-hint)). The probability of any *specific* pair of nodes sharing a hint is low (~1 in 65,536), but by the birthday bound, once a network approaches 256 active nodes the probability of *at least two* nodes sharing a hint rises above 40%.

The cost of a hint collision is wasted computation, not incorrect behavior. However, on battery-constrained devices the wasted computation can be significant: a destination hint collision persists for the lifetime of both node identities, causing repeated unnecessary cryptographic verification on every packet exchanged between the colliding nodes. The only remedy is for one of the nodes to generate a new identity (a new Ed25519 keypair). For a dedicated repeater or sensor node this is relatively painless, but for a chat node it means all peers must re-learn the new public key.

MeshCore originally used 1-byte hints for source, destination, and source-routing addresses. This placed the birthday bound at just 16 nodes — far too low for practical networks.

UMSH uses 2-byte source and destination hints, raising the birthday bound to 256 nodes. UMSH retains 1-byte hints for source-routing (router hints), which may affect source-routed delivery in denser areas.

#### How big is big enough?

Moving to 3-byte hints would raise the birthday bound to approximately 4,096 nodes — a significant improvement over both 16 and 256. But is the extra byte per hint worth it?

The answer depends on the effective network size. A collision is only relevant when both colliding nodes are regularly reachable from each other. For flood-routed traffic, this means all nodes reachable by flooding. For source-routed traffic, only nodes along the path matter, but path composition can be unpredictable and hard to characterize in advance.

The impact of router hint collisions during source routing is not entirely clear. In theory, an unnecessary retransmission caused by a collision should fizzle out quickly (the next hop hint is unlikely to also collide). But if a particular source route is used frequently, even a small amount of extra traffic per use can accumulate. Repeater operators are more likely to coordinate hint assignments among themselves, but this cannot be assumed in all deployments. MeshCore addressed this by introducing 2-byte and 3-byte repeater hints, though with the majority of MeshCore traffic appearing to be flood-routed, it is not clear whether this represents a material improvement in practice.

As a concrete example, consider a regional network of approximately 600 active nodes (roughly the scale of the Oregon MeshCore network, concentrated in the Portland area). The probability of at least one destination hint collision for different hint sizes:

| Hint size | Collision probability |
|---|---|
| 1 byte (256 values) | ~100% |
| 2 bytes (65,536 values) | ~94% |
| 3 bytes (16,777,216 values) | ~1% |

For destination hints — which serve as a prefilter that determines whether a node must perform cryptographic verification — moving to 3 bytes dramatically reduces false-positive verification work and seems well worth the overhead.

#### Source hints

The source hint serves a different purpose than the destination hint. It is not used as a prefilter; rather, it helps the receiver narrow down which cached pairwise key to try first. A source hint collision means the receiver may occasionally try the wrong cached key before finding the right one, but implementations can mitigate this by prioritizing recently matched keys.

The worst case arises when two (or more) nodes sharing a source hint are both in regular contact with a third node. That third node will experience more frequent key-lookup misses and additional cryptographic verification attempts. This is primarily a concern for infrastructure nodes (which tend not to be as power-constrained) rather than battery-powered endpoints, so the problem may be self-limiting.

An asymmetric design — 1-byte source hints and 3-byte destination hints — would maintain the current per-packet overhead while strengthening prefiltering where it matters most. It would also maintain the current minimum-packet-overhead with MeshCore.

However, source hints can be useful beyond key lookup: they can help identify traffic patterns and diagnose network issues. Whether this diagnostic value justifies the extra byte (or two) remains an open question.


