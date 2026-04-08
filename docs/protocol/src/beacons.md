# Beacons & Path Discovery

## Beacons

A **Beacon** is defined as either:

- a broadcast packet with no payload, or
- a multicast packet with no payload

Beacons are used to announce the presence of a node on the network without carrying additional data.

A beacon with a trace-route option can inform listeners of both:

- the node's presence
- a repeater path that may be usable to reach it

This is particularly useful when a receiver already knows the node's identity information.

## Path Discovery

UMSH does not define a dedicated path-discovery packet type. Instead, path discovery is performed using existing primitives:

1. **Outbound discovery**: Node A sends a unicast packet to Node B with the trace-route option present and an appropriate flood hop count. The packet floods through the mesh; repeaters prepend their router hints to the trace-route option as they forward.

2. **Path learning**: When Node B receives the packet, the trace-route option contains the sequence of repeater hints traversed, ordered most-recent first. Node B can use this list directly as a candidate source route back to Node A.

3. **Return path**: Node B can now send unicast packets to Node A using the learned source route. If the packet was ack-requested, Node B's MAC ack also traverses the mesh, allowing Node A to confirm reachability.

4. **Bidirectional establishment**: If Node A also needs a source route to Node B, it can include the trace-route option on its initial packet. When Node B responds (e.g., with an ack, beacon, or identity payload) using its learned route and also including a trace-route option, Node A can learn its own source route to Node B.

Because router hints are only two bytes, different repeaters may share the same hint, which may result in redundant (but harmless) forwarding along a source route.

## Route Learning

When a node successfully processes an incoming packet, it SHOULD update its routing state for the sender:

- **Trace route**: if the packet contains a trace-route option, the node caches the reversed trace route as a source route for future packets to the sender. This is the primary mechanism for learning precise multi-hop paths.
- **Flood hop count**: if the packet contains a flood hop count, the node caches the sender's `FHOPS_ACC` value as a distance estimate. When no source route is available, this value can be used as `FHOPS_REM` for flood responses — scoping the flood to approximately the right radius rather than flooding the entire network.

This routing state applies to all subsequent communication with the sender — replies, acknowledgments, and new messages alike. A node MAY replace a cached route when a newer packet provides a fresher trace route, and SHOULD discard cached routes that have proven unreachable.

In practice, "proven unreachable" usually means that an ack-requested packet sent using the cached source route exhausted its retry budget without end-to-end success. In that case, the sender should stop trusting the stale route and return to route-discovery behavior:

- discard or demote the cached source route
- send the same logical packet again using flood hops instead of the stale source route
- include a trace-route option so that a fresh source route can be learned from the peer's reply
- set the [Route Retry option](packet-options.md#route-retry-option-6) so intermediate repeaters treat the rerouted attempt as a new forwarding opportunity even though the packet's MIC and frame counter are unchanged

Once the peer replies and a fresher trace route is learned, the sender can resume normal source-routed transmission using the replacement route.

## Potential Improvement: Proactive Route Refresh

The recovery behavior above is reactive: a node continues using a cached source route until that route appears to have failed. In mobile scenarios, this may mean the sender does not attempt to discover a fresher route until after packets have already stopped flowing end-to-end.

One possible future improvement would be to allow a sender to occasionally perform a low-rate exploratory route refresh even when there is no strong indication of failure. This behavior is **not part of the current specified protocol behavior** and has **not been validated with real-world measurements**. It is described here only as a possible future optimization.

A conservative version of this idea would look like:

- only perform exploratory refresh when the sender is believed to be mobile or moving
- use a normal cached source route, but also include a trace-route option
- allow only a small flood budget, capped at no more than `source_route_hops + 1`
- perform this no more than occasionally, for example no more than once every `N` successful transmissions and no more than once every `T` minutes, whichever is longer

The intent would be to probe for a slightly better or fresher route without incurring the cost of a full rediscovery flood. A small tail flood could help discover alternate final hops or nearby replacement repeaters when the old route is only partially stale.

This approach has important limitations:

- if the cached source route breaks early, a small tail flood will not help, because forwarding remains constrained by the explicit source route until that route is exhausted
- excessive probing would waste airtime and increase contention, especially on busy meshes
- a newly observed route is not necessarily better and may require local policy before replacing the old route

If this idea is ever standardized, meshes should converge on the same probing policy and parameter values so that behavior remains predictable across implementations. Any such policy should be treated as provisional until it has been evaluated on real radios in mobile conditions.
