# Beacons & Path Discovery

## Beacons

A **Beacon** is defined as either:

- a broadcast packet with no payload, or
- a multicast packet with no payload

Beacons are used to announce the presence of a node on the network without carrying additional data. Because beacons have no payload, they omit the `0xFF` end-of-options marker; the options block is parsed until the end of the packet. The minimum beacon size is unchanged.

A beacon with a trace-route option can inform listeners of both:

- the node's presence
- a repeater path that may be usable to reach it

This is particularly useful when a receiver already knows the node's identity information.

Pairing the trace-route option with [Trace
Signal](packet-options.md#trace-signal-option-10) makes the beacon report
the quality of each hop as well as its identity, which is what
distinguishes a path that merely works from one worth using.

## Advertisements

An **advertisement** is a broadcast or multicast packet whose payload is a
[node identity](node-identity.md) payload—a beacon that additionally
identifies and describes its sender. Advertisements are sent unsolicited,
announcing presence, name, role, and capabilities. To obtain a specific
node's identity, use the [Identity Request](mac-commands.md#identity-request-1)
MAC command, which is answered with a targeted unicast identity response
rather than a broadcast advertisement.

## Announcing on a Schedule

A node MAY emit beacons and advertisements on periods of its own. The two
are configured separately because they announce different things at very
different costs: a beacon publishes a path for a handful of bytes, while
an advertisement carries a signed identity and is the largest frame a node
originates unprompted. A mesh is normally best served by refreshing the
path often and restating the identity rarely.

A scheduled advertisement SHOULD be sent without flood hops. What it
carries is a standing statement rather than news, so flooding it across
the mesh on every period spends airtime out of proportion to what a
distant listener learns; a node that wants to be findable further away
publishes a path with a beacon instead.

A configured period is a minimum rather than an exact cadence. A node
SHOULD scatter each period by a random fraction of it—a quarter is a
reasonable choice—and that scatter MUST only delay an announcement,
never bring it forward, so the configured value remains a floor on how
often the node transmits unasked. Nodes commissioned alike and powered on
together otherwise stay in step for as long as they run, colliding every
period and colliding again on each retry, since a shared schedule makes
them contend from the same instant every time. Carrier sensing resolves
the individual collision; the scatter is what keeps the mesh from having
to resolve one on every period.

A node that has just restarted is the node whose neighbours hold the
stalest paths to it, so emitting one beacon at bring-up is RECOMMENDED.
That beacon is not delayed: nodes do not restart in unison, so bring-up
is already scattered by whatever staggered it.

On a device managed over [ULCP](ulcp-device.md#prop-advert-interval),
these periods are the advertisement-policy properties.

## Path Discovery

UMSH does not define a dedicated path-discovery packet type. Instead, path discovery is performed using existing primitives:

1. **Outbound discovery**: Node A sends a unicast packet to Node B with the trace-route option present and an appropriate flood hop count. The packet floods through the mesh; repeaters prepend their router hints to the trace-route option as they forward.

2. **Path learning**: When Node B receives the packet, the trace-route option contains the sequence of repeater hints traversed, ordered most-recent first. Node B can use this list directly as a candidate source route back to Node A.

3. **Return path**: Node B can now send unicast packets to Node A using the learned source route. If the packet was ack-requested, Node B's MAC ack also traverses the mesh, allowing Node A to confirm reachability.

4. **Bidirectional establishment**: The trace Node A sent taught Node B a path back, and nothing else. A node responding to a packet that carried a trace-route option SHOULD carry one on its response, whatever form that response takes—MAC ack, beacon, or application payload. Where the response is a MAC ack, that ack is the whole of what Node A receives, so an ack without a trace leaves Node A holding no route to Node B at all.

A sender decides whether to originate the option from what it already knows about the destination. One that holds no source route and permits flooding SHOULD include a trace route: the trace is what turns that flood into a path. This includes a peer heard directly, since hearing the peer does not establish that the peer can hear the sender. A sender following a source route SHOULD NOT routinely trace it, since that path is already known and re-recording it on every packet is the [proactive refresh](#potential-improvement-proactive-route-refresh) this specification does not define. An ACK-requested packet is an exception: it SHOULD include a trace so the destination can construct a return route for its ACK.

The reason to omit a trace applies to a path the sender holds, which is what makes the re-recording redundant. A response steered down the trace its own request accumulated—the [Identity Request](mac-commands.md#identity-request-1) answered from a source route built out of the trace, for one—is following the requester's path rather than one either side had, and the response rule above governs: the requester holds nothing until the response records something.

A packet carrying neither flood hops nor a source route SHOULD NOT carry a trace route at all, whatever the sender knows. No repeater may forward such a packet, so the option can only arrive as empty as it left, and its arrival already proves what an empty trace would have said.

Because router hints are only two bytes, different repeaters may share the same hint, which may result in redundant (but harmless) forwarding along a source route.

## Route Learning

A destination may overhear a frame while source-route hints remain unconsumed. Its empty or partial trace describes a path that has not finished traversing the selected repeaters, so it is unsuitable for replacing a cached route. A consumed route can supply a complete trace. Historical buffered frames likewise do not establish current reachability.

When a node successfully processes other live incoming packets, it can update its routing state for the sender:

- **Trace route**: if the packet contains a trace-route option, the node caches that trace route as a source route for future packets back to the sender. Because the trace route is accumulated most-recent first, it already describes the return path from the receiver back toward the original sender. This is the primary mechanism for learning precise multi-hop paths.
- **Flood hop count**: if the packet contains a flood hop count, the node caches the sender's `FHOPS_ACC` value together with any region-code options that arrived on the packet. When no source route is available, these cached flood parameters can be reused for flood responses—scoping the flood to approximately the right radius and regional domain rather than flooding the entire network.

- **Neither**: a packet that arrives carrying no flood hop count and no source route was one that no repeater had permission to forward, so it reached the receiver off the sender's own transmitter. The node SHOULD cache the sender as a direct neighbor. This is the same conclusion an empty trace route supports, drawn from the packet's structure rather than from an option, which is what lets an unforwardable packet leave the trace route off.

A MAC ack can also supply routing evidence. It names no source, but its [ack trailer](security.md#ack-tag-construction) correlates it to an outstanding request and so to the peer that sent it. Its trace can establish a route or replace a provisional direct observation with a repeater path. An ACK confirms that the exchange succeeded; its return path may differ from the outbound path, so it need not replace a working source route. Route selection and retention are local policy.

A packet that arrives carrying a source-route option—including one whose hints are all consumed—spends flood hops only after the route runs out, so its `FHOPS_ACC` counts the tail of the path rather than its length. Such a packet SHOULD NOT be used to derive a flood-distance estimate.

This routing state applies to all subsequent communication with the sender—replies, acknowledgments, and new messages alike. A node MAY replace a cached route when a newer packet provides a fresher trace route, and SHOULD discard cached routes that have proven unreachable.

An ACK timeout is evidence that the exchange failed, not proof that the outbound leg alone failed. When an ACK-requested packet exhausts its retry budget on a cached route, the sender can return to route discovery:

- discard or demote the cached source route
- send the same logical packet again using flood hops instead of the stale source route
- include a trace-route option so that a fresh source route can be learned from the peer's reply
- set the [Route Retry option](packet-options.md#route-retry-option-6) so intermediate repeaters treat the rerouted attempt as a new forwarding opportunity even though the packet's MIC and frame counter are unchanged

Trading a source route for flood hops rewrites only fields the [associated data](security.md#associated-data) excludes. Adding `FHOPS` sets the FCF's `H` bit, which the AAD clears, so the MIC carries over unchanged.

Recovery stays within the sender's original flood ceiling; disabled flooding does not authorize a flooded retry. Once a replacement route is learned, normal routed transmission can resume. An ACK following Route Retry confirms delivery of the logical packet but does not identify which attempt delivered it.

## Scoping Flood Hops to a Known Route

A wide flood hop count is a first-contact cost. Once routing state exists for a destination, the sender SHOULD scope `FHOPS_REM` to what the known path actually costs, plus a small margin:

- **Source route**: named repeaters consume hints without spending flood budget; the margin is available only after all hints are consumed.
- **Flood distance**: the cached `FHOPS_ACC` is the radius at which the destination was last heard.
- **Direct observation**: no repeater carried the observed packet, but the reverse direction may still need one.

The margin—one hop is a reasonable default—keeps delivery self-healing when the path has grown by a hop since it was learned, without paying for a mesh-wide flood on every packet. A route that has failed outright is repaired through the route-retry behavior above, which floods at the sender's full budget rather than the narrowed one.

The margin also accommodates asymmetric links: a direct observation can still require a repeater in the reverse direction. ACKs can use the same allowance, retaining the request's region codes to scope any flooding even when the ACK also follows a source route. A consumed source route without a usable return trace supplies no total distance; a direct observation alone is insufficient to bound that ACK's return path. The request's flood ceiling governs the request, not the ACK's independently selected return path.

An optional hop does not imply that a repeater is present. Not hearing a repeat is therefore insufficient reason to retransmit a directly addressed packet that requests no ACK, or an ACK sent directly with that allowance. Strong reception does not establish reverse reachability, and a successful exchange with the margin does not show it was unnecessary.

## Potential Improvement: Proactive Route Refresh

The recovery behavior above is reactive: a node continues using a cached source route until that route appears to have failed. In mobile scenarios, this may mean the sender does not attempt to discover a fresher route until after packets have already stopped flowing end-to-end.

One possible future improvement would be to allow a sender to occasionally perform a low-rate exploratory route refresh even when there is no strong indication of failure. This behavior is **not part of the current specified protocol behavior** and has **not been validated with real-world measurements**. It is described here only as a possible future optimization.

A conservative version of this idea would look like:

- only perform exploratory refresh when the sender is believed to be mobile or moving
- use a normal cached source route, but also include a trace-route option
- allow only a small flood budget, capped at one flood hop more than the source route has hints
- perform this no more than occasionally, for example no more than once every `N` successful transmissions and no more than once every `T` minutes, whichever is longer

The intent would be to probe for a slightly better or fresher route without incurring the cost of a full rediscovery flood. A small tail flood could help discover alternate final hops or nearby replacement repeaters when the old route is only partially stale.

This approach has important limitations:

- if the cached source route breaks early, a small tail flood will not help, because forwarding remains constrained by the explicit source route until that route is exhausted
- excessive probing would waste airtime and increase contention, especially on busy meshes
- a newly observed route is not necessarily better and may require local policy before replacing the old route

If this idea is ever standardized, meshes should converge on the same probing policy and parameter values so that behavior remains predictable across implementations. Any such policy should be treated as provisional until it has been evaluated on real radios in mobile conditions.
