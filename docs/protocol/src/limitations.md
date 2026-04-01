# Limitations & Open Items

## Known Limitations

### No MAC-Layer Fragmentation

UMSH intentionally does not define a fragmentation mechanism at the MAC layer. The MAC layer delegates fragmentation to higher-layer protocols carried in the payload (see [Layer Separation](introduction.md#layer-separation)). LoRa payloads are typically limited to approximately 200–250 bytes, and UMSH header overhead (FCF, addresses, SECINFO, MIC) consumes a significant portion of this budget. Higher-layer protocols that require payloads larger than a single frame must provide their own segmentation — for example, CoAP block-wise transfer or 6LoWPAN fragmentation.

### Multicast Sender Authentication

Multicast channels use a shared symmetric key. Any node possessing the channel key can send packets with any claimed source address, and other channel members cannot cryptographically verify that the claimed sender actually produced the packet. When the `S` flag is set, the source public key is carried in the packet and can be used for application-level trust decisions, but the protocol-level MIC authenticates only channel membership, not individual sender identity.

This is a fundamental property of symmetric-key multicast and is shared by other protocols with similar designs, including MeshCore.

## Known Hint Collision Properties

UMSH uses asymmetric hint sizes chosen to minimize false-positive work where it matters most while preserving overall packet compactness.

MeshCore originally used 1-byte hints for source, destination, and source-routing addresses, placing the birthday bound at just 16 nodes — far too low for practical networks. UMSH addresses this with larger, role-differentiated hints.

As a concrete example, consider a regional network of approximately 600 active nodes (roughly the scale of the Oregon MeshCore network, concentrated in the Portland area). The probability of at least one collision among all nodes for a given hint size:

| Hint size | Collision probability (600 nodes) |
|---|---|
| 1 byte (256 values) | ~100% |
| 2 bytes (65,536 values) | ~94% |
| 3 bytes (16,777,216 values) | ~1% |

### Destination hints (3 bytes)

The destination hint is a prefilter: a match causes the receiver to attempt full cryptographic verification. A false positive wastes computation on every packet exchanged between the two colliding nodes, for the lifetime of both identities. The cost is persistent and proportional to traffic volume.

With 3-byte destination hints the collision probability drops to ~1% even in a 600-node regional network. The only remedy for a collision is for one node to generate a new identity (a new Ed25519 keypair), which for a chat node means all peers must re-learn the new public key. The 3-byte size makes this scenario rare.

### Source hints (unicast: 1 byte; broadcast and multicast: 3 bytes)

The source hint serves a different purpose in different packet types.

**Unicast source hint (1 byte).** In unicast and blind unicast, the destination hint already handles prefiltering. The source hint is used only to narrow down which cached pairwise key to try first. A collision means the receiver tries the wrong cached key before finding the correct one — an extra AES-CMAC call, not a persistent per-packet cost. This is primarily a concern for endpoint nodes that communicate with many peers and therefore maintain large caches of pairwise keys. Using a 1-byte source hint offsets the +1 byte cost of the 3-byte destination hint, keeping unicast packet overhead at 4 bytes total for addressing.

**Broadcast and multicast source hint (3 bytes).** These packet types carry no destination hint. The source hint is therefore the primary addressing field visible to receivers and is used for source identification, traffic attribution, and diagnostics. At 2 bytes, ~94% of nodes in a 600-node network share a hint, making the field nearly useless for attribution. At 3 bytes, the probability drops to ~1%.

### Router hints (2 bytes)

Router hints are used in source-route and trace-route options. A router hint collision causes an unintended repeater to forward the packet; MIC-based duplicate suppression ensures each repeater forwards a given packet at most once, so collisions add traffic but not loops or incorrect delivery.

Source routing is an inherently local operation — only repeaters within radio range of the transmitting node can act on the hint. For a local population of ~50 repeaters:

- 1-byte hints: ~46% collision probability
- 2-byte hints: ~1.9% collision probability

2-byte router hints reduce the collision probability by roughly 24× relative to 1-byte hints for typical deployments, at a cost of 1 extra byte per hop in source-route and trace-route options.


