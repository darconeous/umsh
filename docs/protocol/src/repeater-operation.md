# Repeater Operation

Forwarding logic is intentionally conservative. A repeater should evaluate packets in the following order.

## Routing Invariants

The routing model is governed by a few simple rules:

- Every currently defined on-mesh packet type is routable.
  - In the current protocol this includes broadcast, MAC ack, unicast, multicast, and blind unicast packets.
  - Reserved or opaque packet types are not routable until the protocol defines their forwarding semantics.
- Repeaters MUST mutate specific dynamic routing metadata while forwarding ([source route](packet-options.md#source-route-option-3), [trace route](packet-options.md#trace-route-option-2), [hop count](packet-structure.md#flood-hop-count), etc)
  - A repeater MUST NOT simply repeat a packet without making specific changes.
  - Typical examples are flood hop counts, trace routes, source routes.
  - Repeaters themselves to not add the Route Retry flag, only the original sender does that.
  - These mutations do **not** create a new logical packet.
- A packet's logical delivery identity and its repeater forwarding identity are related but distinct.
  - The final destination decides whether a packet is new by its normal replay and destination-processing rules.
  - Repeaters suppress duplicates using a forwarding identity that remains stable across legal forwarding rewrites.
- Forwarding confirmation uses the same identity as repeater duplicate suppression.
  - This ensures a sender or repeater recognizes "the same packet, forwarded onward" even if the next hop mutates dynamic routing metadata.

## Duplicate Suppression

Each repeater maintains a fixed-size cache of recently seen **cache keys** used to detect duplicate packets.

Parameters:

- cache size = implementation configurable (see [sizing guidance](#cache-sizing) below)
- eviction policy = oldest entry removed when full

The cache key is derived from the packet as follows:

- **Authenticated packets** (unicast, multicast, blind unicast): the cache key is normally the packet's MIC. Because the MIC covers all static fields and is unaffected by repeater modifications to dynamic options or the flood hop count, it remains stable across forwarding hops.
  - If the packet carries the [Route Retry option](packet-options.md#route-retry-option-6), the cache key must distinguish that retry attempt from the same packet without the option present. A simple and sufficient rule is to treat the cache key as `(MIC, route_retry_present)`.
  - This gives a packet two bounded forwarding identities: the original forwarding attempt and one explicit reroute attempt.
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

3. **Unknown critical options**
   - If the packet contains any critical option the repeater does not understand, do not forward.

4. **Policy checks**
   - If the packet does not satisfy local repeater policy, do not forward.

5. **Source-route match**
   - If the packet contains a non-empty source-route option:
     - If this repeater does not match the next source-route hint, do not forward.
     - Otherwise, remove the repeater's own hint from the source-route option.
   - If the repeater mutates a source-route option, it MUST preserve the option on the forwarded packet even when no hints remain.
     - In that case, the forwarded packet carries a source-route option with zero remaining hops.
     - This preserves provenance: downstream nodes can still determine that the packet arrived via explicit source routing rather than by pure flooding.
   - If the source-route option is still non-empty after removing this repeater's hint, skip directly to step 9 (trace route processing). The remaining steps apply only to flood forwarding.

6. **Transition from source-routing to flooding**
   - If the source-route option is now empty:
     - If the packet has a region code option and this repeater is not configured for that region, do not forward.
     - If the packet has a flood hop count field with `FHOPS_REM > 0`, decrement `FHOPS_REM` and increment `FHOPS_ACC`.
     - Otherwise, do not forward.

7. **RSSI threshold check**
   - If either the packet or repeater imposes a minimum RSSI, the effective threshold is the higher of the two. If the received RSSI is below the effective threshold, do not forward.

8. **SNR threshold check**
   - If either the packet or repeater imposes a minimum SNR, the effective threshold is the higher of the two. If the received SNR is below the effective threshold, do not forward.

9. **Trace route processing**
   - If the packet contains a trace-route option, prepend this repeater's hint. If prepending the hint would cause the packet to exceed the maximum frame size, drop the packet.

10. **Retransmit**
    - Forward the modified packet.

## Forwarding Confirmation

Repeaters do not generate MAC acks — acks are generated only by the [final destination](packet-types.md#mac-ack-packet). Instead, a node can passively confirm that a transmitted or forwarded packet was received by listening for a subsequent retransmission of the same packet.

This applies to:

- **Source-routed packets**: Each forwarding hop listens for the next hop — the node matching the next source-route hint — to retransmit.
- **Flood originators**: The originating node listens for any node to retransmit.
- **Flood repeaters**: Intermediate flood-forwarding nodes MUST NOT retry. Multiple nodes may forward the same flood packet, and a repeater has no designated next hop to listen for; retrying would increase congestion without improving reliability.

After transmitting, the node listens for the same packet — identified by its [cache key](#duplicate-suppression) — to be retransmitted. This confirmation timeout MUST be large enough to cover the worst-case forwarding delay allowed by [Channel Access](channel-access.md#flood-forwarding-contention-window), plus the airtime of the forwarded frame itself, plus a guard margin. A safe default is:

```text
confirm_timeout = 2 × T_frame + W_max
```

where `W_max` is the maximum intentional forwarding-delay window permitted for the path. With the suggested default `W_max = 2 × T_frame`, this yields `confirm_timeout = 4 × T_frame`.

If the packet is heard before `confirm_timeout` expires, forwarding is confirmed.

If `confirm_timeout` expires without a retransmission, the node SHOULD schedule a retry after a jittered exponential delay:

```text
retry_delay_n = uniform_random(0, min(2^(n−1) × T_frame, 4 × T_frame))
```

where `n` is the 1-based retry number. After this delay expires, the retry is transmitted using normal CAD and backoff as described in [Channel Access](channel-access.md#backoff-procedure).

A node MUST NOT retry more than 3 times.

### Source-Route Failure Recovery

When a node uses a cached source route for an ack-requested unicast or blind-unicast packet and that attempt fails, it needs a way to re-attempt delivery without causing duplicate application delivery at the final destination.

A practical recovery rule is:

1. if the sender exhausts the retry budget for a packet sent using a cached source route, it SHOULD treat that cached route as failed
2. the failed route SHOULD be discarded or marked unusable for immediate reuse
3. if the sender wishes to re-attempt delivery of the **same logical packet**, it SHOULD:
   - preserve the same frame counter, payload, and MIC
   - remove the stale source-route option
   - add or refresh flood hops
   - include a trace-route option if route rediscovery is desired
   - set the [Route Retry option](packet-options.md#route-retry-option-6)

This recovery transmission is intentionally the same logical packet, not a new application message. The destination therefore still accepts it at most once according to the normal replay rules. The Route Retry option exists only to let repeaters forward the rerouted attempt even if they already suppressed the original source-routed attempt as a duplicate.

This preserves a useful separation of responsibilities:

- **routing recovery** remains a MAC concern
- **duplicate application delivery** remains prevented by the end-to-end replay rules
- **repeaters** remain largely stateless and do not need to understand application semantics

For flood-forwarding repeaters that have accepted a packet for forwarding but have not yet transmitted it, overhearing another forwarding of the same packet SHOULD normally cause a bounded deferral rather than an immediate transmission. A safe default is:

1. resample a forwarding delay using the contention-window procedure in [Channel Access](channel-access.md#flood-forwarding-contention-window)
2. restart the waiting period
3. after 3 such deferrals, abandon the pending forward

This behavior is still provisional and should be validated empirically. The intent is to reduce near-simultaneous forwarding while still allowing a second or third repeater to contribute if an earlier forward was not widely heard.

## Routing Implications

This forwarding model allows hybrid routing behavior.

For example, a packet can be source-routed to a specific repeater and also carry a flood hop count. Once the source-route hints are consumed, the packet transitions to flood-based forwarding bounded by `FHOPS_REM`. This permits "delivery-to-region, then flood" behavior, which is useful when searching for a node in a known geographic area without flooding the entire mesh.
