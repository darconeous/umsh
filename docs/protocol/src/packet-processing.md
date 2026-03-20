# Packet Processing

This chapter describes how a receiving node processes an incoming packet. This procedure applies to all nodes, not just repeaters. Repeater-specific forwarding logic is described separately in [Repeater Operation](repeater-operation.md).

## Receive Procedure

1. **Well-formedness check**
   - If the packet is malformed (invalid FCF, truncated fields, non-zero reserved bits in the SCF), drop.

2. **MAC Ack handling**
   - If the packet is a MAC Ack:
     - If this node was not expecting the ack, stop.
     - Otherwise, handle the ack and stop.

3. **Address matching**
   - If the packet is a broadcast, continue.
   - If the packet carries a destination hint that matches this node, continue.
   - If the packet carries a channel hint matching a configured channel, continue.
   - Otherwise, stop.

   A node always attempts to handle a packet that matches its destination hint, even if the packet has remaining source-route hops. This differs from systems like MeshCore and allows two nodes that are suddenly in direct range of each other to recover quickly without waiting for the packet to traverse the full source route. The packet may also be forwarded according to the normal [forwarding procedure](repeater-operation.md#forwarding-procedure) if the node is acting as a repeater.

4. **Channel processing** (multicast and blind unicast)

   4.1. If the packet is a blind unicast:
      - Decrypt the source address using the channel's derived encryption key `K_enc`.
      - If the source address is a hint (`S=0`), look up candidate public keys matching the hint. If no candidates exist, stop.

   4.2. Attempt decryption and MIC verification for each candidate channel key.
      - For blind unicast, this may require re-decrypting the source address for each candidate channel from step 4.1.
      - If no candidate channel succeeds, stop.

5. **Unicast processing**

   5.1. If the source address is a hint (`S=0`), look up candidate public keys matching the hint. If no candidates exist, stop.

   5.2. Attempt MIC verification (and decryption if encrypted) for each candidate source address.
      - If no candidate succeeds, stop.

   5.3. If the source address is blacklisted, drop.

6. **Payload type validation**
   - If the payload type is not allowed for this packet type (see [Payload and Packet Type Compatibility](payload-format.md#payload-and-packet-type-compatibility)), drop.

7. **Ack Processing**
   - If the packet type requests an ACK, the receiving node (i.e., the final destination) computes the [ack tag](security.md#ack-tag-construction) from the full 16-byte CMAC and pairwise `K_enc`, prepares a MAC Ack packet, and adds it to the outbound queue. Repeaters do not generate acks — see [MAC Ack Packet](packet-types.md#mac-ack-packet).

8. **Application processing**
   - Continue processing the application payload.
