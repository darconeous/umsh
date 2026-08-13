# Repeater Operation

Forwarding logic is intentionally conservative. A repeater should evaluate packets in the following order.

## Routing Invariants

The routing model is governed by a few simple rules:

- Every currently defined on-mesh packet type is routable.
  - In the current protocol this includes broadcast, MAC ack, unicast, multicast, and blind unicast packets.
  - Reserved or opaque packet types are not routable until the protocol defines their forwarding semantics (there is only one at the moment, type 5).
- A repeater forwards other nodes' traffic, never its own and never traffic that has arrived.
  - A repeater MUST NOT forward a packet whose source address identifies one of its own identities, by hint or in full-key form. Re-flooding its own transmission wastes airtime, and prepending its hint to the trace route would fabricate a hop that never happened.
  - A repeater MUST NOT forward a packet whose destination address identifies one of its own identities. Such a packet has reached its destination; whether the repeater could actually process it is a separate question.
- A packet is forwarded as either a source-routed hop or a flood hop, never both.
  - A hop named in the source route is a source-routed hop, including the hop that consumes the final hint.
  - Every other forwarded hop is a flood hop.
  - Rules written for flood forwarding — [flood hop accounting](packet-structure.md#flood-hop-count), signal-quality thresholds, [region policy](#forwarding-procedure), and forwarding contention — apply to flood hops only.
- Repeaters MUST mutate specific dynamic routing metadata while forwarding ([source route](packet-options.md#source-route-option-3), [trace route](packet-options.md#trace-route-option-2), [hop count](packet-structure.md#flood-hop-count), etc)
  - Typical examples are flood hop counts, trace routes, source routes.
  - A repeater SHALL NOT simply repeat a packet verbatim under any circumstances.
  - The Route Retry flag MUST NOT be added to a packet by anyone other than the original sender.
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
- entry lifetime = bounded (see [entry expiry](#entry-expiry) below)

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

### Entry Expiry

Cache entries MUST also age out. Capacity alone does not bound how long a key is suppressed, and a MIC-less packet's cache key is derived from its content: a node that repeats an identical packet — a beacon, whose body is empty and whose non-dynamic options do not change — produces the same key every time. On a quiet mesh, capacity-only eviction would suppress that node's packets for as long as the repeater runs.

An entry SHOULD be discarded once it is older than a **cache lifetime** measured from when the key was first inserted. One hour is a reasonable default: long enough that every retransmission of a single packet still collapses to one forward, short enough that a node re-announcing itself is heard again well within the time anyone would wait for it.

A repeat of a key already held MUST NOT extend that entry's lifetime. Refreshing the timestamp on each sighting would let a node repeating itself inside the window hold its own suppression open indefinitely, which is the behavior expiry exists to prevent.

### Cache Sizing

Each cache entry is small (equal to the cache key size — typically 4 to 16 bytes), so generous sizing is inexpensive. The recommended minimum is **32 entries**; the suggested default is **64 entries**. High-traffic deployments or networks with large diameters may benefit from 128 or more entries.

## Forwarding Procedure

1. **Duplicate suppression**
   - If this packet was forwarded recently, do not forward.

2. **Local origin and local destination**
   - If this repeater's own radio already transmitted this packet, do not forward. A repeater that shares its radio with another stack—an attached host, most commonly—receives a copy of what that stack transmits. Forwarding it would put a packet back on the air that this antenna already sent, and the source address belongs to the other stack, so the check below cannot catch it. The repeater MUST insert the cache key as if it had forwarded the packet: a neighbor's repeat arrives shortly after, and it is the same packet, already carried.
   - If the packet's source address identifies one of this repeater's own identities, do not forward.
   - If the packet's destination address identifies one of this repeater's own identities, do not forward.

3. **Locally-handled unicast**
   - If this packet was a unicast (blind or direct) packet that was fully handled and processed according to [Packet Processing](packet-processing.md), do not forward. This covers the blind-unicast case, where the destination address is encrypted and step 2 cannot see it.

4. **Unknown critical options**
   - If the packet contains any critical option the repeater does not understand, do not forward.

5. **Policy checks**
   - If the packet does not satisfy local repeater policy, do not forward.

6. **Source-route match**
   - If the packet contains a non-empty source-route option:
     - If this repeater does not match the next source-route hint, do not forward.
     - Otherwise, remove the repeater's own hint from the source-route option.
   - If the repeater mutates a source-route option, it MUST preserve the option on the forwarded packet even when no hints remain.
     - In that case, the forwarded packet carries a source-route option with zero remaining hops.
     - This preserves provenance: downstream nodes can still determine that the packet arrived via explicit source routing rather than by pure flooding.
   - If this repeater matched a source-route hint, it is forwarding a source-routed hop. Skip directly to step 10 (trace route processing), **including when the hint just removed was the last one**. Steps 7 through 9 describe flood forwarding and MUST NOT be applied to a source-routed hop.

7. **Region policy** *(flood forwarding only!)*
   - If the router has no region configuration at all, skip this section. A repeater with no configured regions applies no regional restriction and forwards a tagged packet whatever its region.
   - If none of the region codes in the packet match those configured on the repeater, do not forward.
   - If the packet has no region code option, the repeater SHOULD insert its configured default region before flood-forwarding. A repeater with no default region configured forwards the packet untagged; the default region is not implied by the configured region list.
     - If one or more region codes are already present, the repeater MUST preserve them unchanged.
     - A repeater MUST NOT add a second region code to a packet that already carries at least one region code.

8. **Flood hop accounting** *(flood forwarding only!)*
   - If the packet has a flood hop count field with `FHOPS_REM > 0`, decrement `FHOPS_REM` and increment `FHOPS_ACC`.
   - Otherwise, do not forward.

9. **Signal-quality thresholds** *(flood forwarding only!)*
   - If either the packet or repeater imposes a minimum RSSI, the effective threshold is the higher of the two. If the received RSSI is below the effective threshold, do not forward.
   - If either the packet or repeater imposes a minimum SNR, the effective threshold is the higher of the two. If the received SNR is below the effective threshold, do not forward.
   - These thresholds ask how well the packet was heard. A packet handed to the repeater over a point-to-point link rather than a radio was not heard at all, and carries no measurement to compare; the thresholds do not apply to it.

10. **Trace route processing**
   - If the packet contains a trace-route option, prepend this repeater's hint. If prepending the hint would cause the packet to exceed the maximum frame size, drop the packet.

11. **Retransmit**
   - If this is a flood forward, implement the [flood forwarding contention window](channel-access.md#flood-forwarding-contention-window)
     - The contention window staggers the repeaters that all heard one transmission. A packet that arrived over a point-to-point link was heard by this repeater alone, so there is no contention to resolve and no window to wait out.
   - Forward the modified packet according to normal [channel access rules](channel-access.md).

A packet that arrives carrying an **empty** source-route option matched no hint at this repeater, so it takes the flood path: steps 7 through 9 apply in full. This is how a hybrid route transitions to flooding — the transition is observed by the repeater *after* the one that emptied the route, not performed by it.

Bridges follow the same packet-rewrite rules as repeaters.

## Forwarding Confirmation

Repeaters do not generate MAC acks — acks are generated only by the [final destination](packet-types.md#mac-ack-packet). Instead, a node can passively confirm that a transmitted or forwarded packet was received by listening for a subsequent retransmission of the same packet (or it's ack).

This applies to:

- **Source-routed packets**: Each forwarding hop listens for the next hop — the node matching the next source-route hint — to retransmit.
- **Flood originators**: The originating node listens for any node to retransmit.
- **Flood repeaters**: Intermediate flood-forwarding nodes MUST NOT retry. Multiple nodes may forward the same flood packet, and a repeater has no designated next hop to listen for; retrying would increase congestion without improving reliability.

Confirmation, and the retry ladder below, apply whether or not the packet requests an ACK. An ack-requested sender goes on to await the ACK once forwarding is confirmed; a sender that requested no ACK is finished the moment it hears the packet carried onward, and if the retry budget runs out without that, the send simply ends — there is no failure signal to wait for. A point-to-point packet with no flood budget and no source route travels straight to its destination, confirms nothing, and MUST be transmitted exactly once.

After transmitting, the node listens for the same packet — identified by its [cache key](#duplicate-suppression) — to be retransmitted. This confirmation timeout MUST be large enough to cover the worst-case forwarding delay allowed by [Channel Access](channel-access.md#flood-forwarding-contention-window), plus the airtime of the forwarded frame itself, plus a guard margin. A safe default is:

```text
confirm_timeout = 2 × T_frame + W_max + D_ack
```

where `W_max` is the maximum intentional forwarding-delay window permitted for the path and `D_ack` is the [ACK protection interval](channel-access.md#ack-protection-interval) when it applies. With the suggested defaults `W_max = 2 × T_frame` and `D_ack = 0.25 × T_frame`, this yields `confirm_timeout = 4.25 × T_frame`.

If the packet is heard before `confirm_timeout` expires, forwarding is confirmed.

If `confirm_timeout` expires without a retransmission, the node SHOULD schedule a retry after a jittered delay:

```text
retry_delay = uniform_random(0, T_frame)
```

The delay does not grow with the retry number. Its only job is to decorrelate retries between nodes, and one frame time is enough for that; every additional window would be time the payload spends undelivered. After this delay expires, the retry is transmitted using normal CAD and backoff as described in [Channel Access](channel-access.md#backoff-procedure).

A node MUST NOT retry more than 3 times.

### Ack Cancellation

A MAC ack echoes the acknowledged packet's `ack_mic` — the first four bytes of its on-wire MIC — which any forwarder can read without keys, and which survives the mutations repeaters perform. A repeater that overhears a MAC ack (or an [Ack MIC option](packet-options.md#ack-mic-option-8)) whose `ack_mic` matches the MIC prefix of a queued, not-yet-transmitted forward of an ack-eliciting packet (UNAR or BUAR) SHOULD cancel that forward: the destination provably has the packet, and repeating it spends airtime on nothing. The [ACK protection interval](channel-access.md#ack-protection-interval) puts the ack on the air ahead of pending forwards precisely so that this observation is available.

Cancellation acts on the queue, not on the future. It removes whatever matching forward is queued at that moment — a [Route Retry](packet-options.md#route-retry-option-6) copy included — and records nothing. A Route Retry copy received *after* a cancellation is a separate forwarding identity under [duplicate suppression](#duplicate-suppression) and is forwarded normally: the origin resorts to it precisely because the ack never reached it, and carrying the copy prompts the destination to acknowledge again. That copy is in turn cancelable by another overheard ack.

The duplicate-cache entry for a cancelled forward remains. The packet was handled; a later copy of the same attempt is still a duplicate.

A repeater cannot verify the keyed `ack_tag` half of the trailer, so cancellation rests on the public `ack_mic` alone. The [forgery this exposes](security.md#ack-tag-construction) suppresses at most one queued forward per overheard ack and is bounded by the Route Retry path.

### Route Failure Recovery

When a node sends an ack-requested unicast or blind-unicast packet against a cached route and that attempt fails, it needs a way to re-attempt delivery without causing duplicate application delivery at the final destination.

Two kinds of cached route can fail this way, and they fail identically from the sender's point of view:

- an explicit **source route**, carried in the packet as a [source-route option](packet-options.md#source-route-option-3)
- a cached **distance** — the destination believed to be directly reachable, or reachable within a known number of flood hops — which narrows `FHOPS` and leaves no trace in the options

A practical recovery rule is:

1. if the sender exhausts the retry budget for a packet sent against a cached route, it SHOULD treat that cached route as failed
2. the failed route SHOULD be discarded or marked unusable for immediate reuse
3. if the sender wishes to re-attempt delivery of the **same logical packet**, it SHOULD:
   - preserve the same frame counter, payload, and MIC
   - remove the stale source-route option, if one was present
   - add or refresh flood hops
   - include a trace-route option if route rediscovery is desired
   - set the [Route Retry option](packet-options.md#route-retry-option-6)

These edits touch only fields the [associated data](security.md#associated-data) excludes, which is what lets the MIC carry over. Adding `FHOPS` where the original had none also sets the FCF's `H` bit, and the AAD clears that bit for this reason.

The restored flood radius SHOULD be the one the sending application asked for. A radius the application chose for itself is not a failed cache entry, and recovery MUST NOT widen it: a sender that was told to reach no further than one hop has not made a stale assumption, it has been given an instruction.

This recovery transmission is intentionally the same logical packet, not a new application message. The destination therefore still accepts it at most once according to the normal replay rules. The Route Retry option exists only to let repeaters forward the re-attempted packet even if they already suppressed the original as a duplicate.

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

For example, a packet can be source-routed to a specific repeater and also carry a flood hop count. The routed hops cost nothing against `FHOPS_REM`, so the whole budget is available to the flood that begins where the route ends. This permits "delivery-to-region, then flood" behavior, which is useful when searching for a node in a known geographic area without flooding the entire mesh, and it is why the flood radius limit of 15 bounds the flood rather than the total path length.

A sender sizing `FHOPS_REM` for a source-routed packet is therefore budgeting the flood *beyond* the route's last hop, not the route itself.
