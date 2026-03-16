# Repeater Operation

Forwarding logic is intentionally conservative. A repeater should evaluate packets in the following order.

## Duplicate Suppression

Repeaters detect duplicate packets by MIC.

Each repeater maintains a fixed-size cache of recently seen MIC values.

Parameters:

- cache entry = full packet MIC
- cache size = implementation configurable
- eviction policy = oldest entry removed when full

Before forwarding a packet, the repeater checks the MIC cache:

- if MIC is already present, do not forward
- if MIC is not present, continue processing
- once the repeater decides the packet is eligible, insert the MIC into the cache

To avoid racy reforward behavior, the repeater should insert the MIC into the cache as soon as it accepts the packet for forwarding, not after transmission completes.

Because duplicate suppression depends directly on the MIC, shorter MIC sizes increase the probability of false-positive collisions in the cache. Deployments that use 4-byte or 8-byte MICs should account for this when sizing the duplicate cache.

## Forwarding Procedure

1. **Duplicate suppression**
   - If this packet was forwarded recently, do not forward.

2. **RSSI threshold check**
   - If either the packet or repeater imposes a minimum RSSI:
     - If the received RSSI is below the effective threshold, do not forward.

3. **SNR threshold check**
   - If either the packet or repeater imposes a minimum SNR:
     - If the received SNR is below the effective threshold, do not forward.

4. **Unknown critical routing options**
   - If the packet contains any routing-critical option the repeater does not understand, do not forward.

5. **Policy checks**
   - If the packet does not satisfy local repeater policy, do not forward.

6. **Source-route match**
   - If the packet contains a non-empty source-route option:
     - If this repeater does not match the next source-route hint, do not forward.
     - Otherwise, remove the repeater's own hint from the source-route option.

7. **Transition from source-routing to flooding**
   - If the source-route option is now empty:
     - If the packet has a region code option and this repeater is not configured for that region, do not forward.
     - If the packet has a non-zero hop count, decrement it.
     - Otherwise, do not forward.

8. **Trace route processing**
   - If the packet contains a trace-route option, prepend this repeater's hint.

9. **Retransmit**
   - Forward the modified packet.

## Routing Implications

This forwarding model allows hybrid routing behavior.

For example, a packet can be source-routed to a specific repeater and also carry a hop count. Once the source-route hints are consumed, the packet transitions to flood-based forwarding bounded by the remaining hop count. This permits "delivery-to-region, then flood" behavior, which is useful when searching for a node in a known geographic area without flooding the entire mesh.
