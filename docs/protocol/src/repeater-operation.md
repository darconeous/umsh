# Repeater Operation

Forwarding logic is intentionally conservative. A repeater should evaluate packets in the following order.

## Duplicate Suppression

Each repeater maintains a fixed-size cache of recently seen **cache keys** used to detect duplicate packets.

Parameters:

- cache size = implementation configurable (see [sizing guidance](#cache-sizing) below)
- eviction policy = oldest entry removed when full

The cache key is derived from the packet as follows:

- **Authenticated packets** (unicast, multicast, blind unicast): the cache key is the packet's MIC. Because the MIC covers all static fields and is unaffected by repeater modifications to dynamic options or the flood hop count, it remains stable across forwarding hops.
- **MAC acks and broadcasts**: these packet types do not carry a MIC. The cache key is a locally-computed hash of the packet content, excluding the flood hop count and dynamic options — the same fields that would be excluded from a MIC. The hash does not need to be cryptographic; CRC-32 is suggested, but any hash with comparable distribution is acceptable. The choice of hash algorithm is a local implementation detail.

Before forwarding a packet, the repeater checks the cache:

- if the cache key is already present, do not forward
- if the cache key is not present, continue processing
- once the repeater decides the packet is eligible, insert the cache key into the cache

To avoid racy reforward behavior, the repeater should insert the cache key into the cache as soon as it accepts the packet for forwarding, not after transmission completes.

Shorter cache keys increase the probability of false-positive collisions. Deployments that use 4-byte or 8-byte MICs should account for this when sizing the duplicate cache.

### Cache Sizing

Each cache entry is small (equal to the cache key size — typically 4 to 16 bytes), so generous sizing is inexpensive. The recommended minimum is **32 entries**; the suggested default is **64 entries**. High-traffic deployments or networks with large diameters may benefit from 128 or more entries.

## Forwarding Procedure

1. **Duplicate suppression**
   - If this packet was forwarded recently, do not forward.

2. **Locally-Handled Unicast**
   - If this packet was a unicast (bind or direct) packet that was fully handled and processed according to [Packet Processing](packet-processing.md), do not forward.

2. **RSSI threshold check**
   - If either the packet or repeater imposes a minimum RSSI, the effective threshold is the higher of the two. If the received RSSI is below the effective threshold, do not forward.

3. **SNR threshold check**
   - If either the packet or repeater imposes a minimum SNR, the effective threshold is the higher of the two. If the received SNR is below the effective threshold, do not forward.

4. **Unknown critical options**
   - If the packet contains any critical option the repeater does not understand, do not forward.

5. **Policy checks**
   - If the packet does not satisfy local repeater policy, do not forward.

6. **Source-route match**
   - If the packet contains a non-empty source-route option:
     - If this repeater does not match the next source-route hint, do not forward.
     - Otherwise, remove the repeater's own hint from the source-route option.

7. **Transition from source-routing to flooding**
   - If the source-route option is now empty:
     - If the packet has a region code option and this repeater is not configured for that region, do not forward.
     - If the packet has a flood hop count field with `FHOPS_REM > 0`, decrement `FHOPS_REM` and increment `FHOPS_ACC`.
     - Otherwise, do not forward.

8. **Trace route processing**
   - If the packet contains a trace-route option, prepend this repeater's hint. If prepending the hint would cause the packet to exceed the maximum frame size, drop the packet.

9. **Retransmit**
   - Forward the modified packet.

## Forwarding Confirmation

Repeaters do not generate MAC acks — acks are generated only by the [final destination](packet-types.md#mac-ack-packet). Instead, a node can passively confirm that a transmitted or forwarded packet was received by listening for a subsequent retransmission of the same packet.

This applies to:

- **Source-routed packets**: Each forwarding hop listens for the next hop — the node matching the next source-route hint — to retransmit.
- **Flood originators**: The originating node listens for any node to retransmit.
- **Flood repeaters**: Intermediate flood-forwarding nodes MUST NOT retry. Multiple nodes may forward the same flood packet, and a repeater has no designated next hop to listen for; retrying would increase congestion without improving reliability.

After transmitting, the node listens for the same packet — identified by its [cache key](#duplicate-suppression) — to be retransmitted. The listening window duration is sampled uniformly from [T_frame, 3 × T_frame], where T_frame is defined in [Channel Access](channel-access.md#frame-duration). If the packet is heard before the window expires, delivery is confirmed.

If the listening window expires without a retransmission, the node SHOULD retransmit. A node MUST NOT retry more than 3 times. Each retry is preceded by normal CAD and backoff as described in [Channel Access](channel-access.md#backoff-procedure).

## Routing Implications

This forwarding model allows hybrid routing behavior.

For example, a packet can be source-routed to a specific repeater and also carry a flood hop count. Once the source-route hints are consumed, the packet transitions to flood-based forwarding bounded by `FHOPS_REM`. This permits "delivery-to-region, then flood" behavior, which is useful when searching for a node in a known geographic area without flooding the entire mesh.
