# Limitations & Open Items

## Known Limitations

### No MAC-Layer Fragmentation

UMSH intentionally does not define a fragmentation mechanism at the MAC layer. The MAC layer delegates fragmentation to higher-layer protocols carried in the payload (see [Layer Separation](introduction.md#layer-separation)). LoRa payloads are typically limited to approximately 200–250 bytes, and UMSH header overhead (FCF, addresses, SECINFO, MIC) consumes a significant portion of this budget. Higher-layer protocols that require payloads larger than a single frame must provide their own segmentation — for example, CoAP block-wise transfer or 6LoWPAN fragmentation.

### Multicast Sender Authentication

Multicast channels use a shared symmetric key. Any node possessing the channel key can send packets with any claimed source address, and other channel members cannot cryptographically verify that the claimed sender actually produced the packet. When the `S` flag is set, the source public key is carried in the packet and can be used for application-level trust decisions, but the protocol-level MIC authenticates only channel membership, not individual sender identity.

This is a fundamental property of symmetric-key multicast and is shared by other protocols with similar designs, including MeshCore.

### Destination-Hint Collisions

Two-byte destination hints will occasionally collide, causing a receiver to attempt cryptographic verification on packets intended for a different node. The protocol does not define a mechanism to mitigate this beyond treating hints as a prefilter (see [Addressing](addressing.md#destination-hint)). In practice, collisions are rare (~1 in 65536) and the cost is wasted computation, not incorrect behavior.

## Open Items

1. **Protocol version statement**
   - The FCF includes a `VER` field, but the introduction does not state which protocol version this document describes.

2. **"Optional payload encryption" clarification**
   - The introduction lists "Optional payload encryption" as a feature but does not specify when encryption is optional (e.g., amateur-radio-compliant modes, broadcasts, all frame types).

3. **"Low-power operation" specificity**
   - The introduction lists "Low-power operation" as a feature, but unlike the other items it describes a design goal rather than a concrete protocol property. Consider making it more specific or folding it into the use cases section.

4. **PFS subsection placement in introduction**
   - Perfect Forward Secrecy is currently a sub-subsection under Nodes, but PFS is a session-level property involving pairs of nodes. Consider promoting it to a sibling of Unicast / Multicast Channels / Blind Unicast.
