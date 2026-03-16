# Limitations & Open Items

## Known Limitations

### No MAC-Layer Fragmentation

UMSH intentionally does not define a fragmentation mechanism at the MAC layer. The MAC layer delegates fragmentation to higher-layer protocols carried in the payload (see [Layer Separation](introduction.md#layer-separation)). LoRa payloads are typically limited to approximately 200–250 bytes, and UMSH header overhead (FCF, addresses, SECINFO, MIC) consumes a significant portion of this budget. Higher-layer protocols that require payloads larger than a single frame must provide their own segmentation — for example, CoAP block-wise transfer or 6LoWPAN fragmentation.

### Multicast Sender Authentication

Multicast channels use a shared symmetric key. Any node possessing the channel key can send packets with any claimed source address, and other channel members cannot cryptographically verify that the claimed sender actually produced the packet. When the `S` flag is set, the source public key is carried in the packet and can be used for application-level trust decisions, but the protocol-level MIC authenticates only channel membership, not individual sender identity.

This is a fundamental property of symmetric-key multicast and is shared by other protocols with similar designs, including MeshCore.

## Open Items and Provisional Areas

The following areas remain provisional or deployment-defined:

1. **Region-code namespace**
   - Region encoding and allocation are deployment-defined.

2. **Destination-hint collisions**
   - Destination hints are only a prefilter and are expected to collide.

3. **Router-hint collisions**
   - Router hints are only one byte and are expected to collide.

4. **Duplicate cache sizing**
   - The MIC cache depth and eviction details are implementation configurable.

5. **MAC Ack PKTMIC width**
   - 8 bytes is recommended, but this can be fixed explicitly by the protocol if desired.

6. **Channel-name-to-key derivation**
   - The exact derivation function for named channels is not yet specified in this draft.

7. **Routing-Critical option attribute**
   - A third option attribute for routing-critical semantics is planned but not yet defined (see [Packet Options](packet-options.md)).
