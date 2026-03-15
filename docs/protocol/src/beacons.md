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

1. **Outbound discovery**: Node A sends a unicast packet to Node B with the trace-route option present and an appropriate hop count. The packet floods through the mesh; repeaters prepend their router hints to the trace-route option as they forward.

2. **Path learning**: When Node B receives the packet, the trace-route option contains the sequence of repeater hints traversed, ordered most-recent first. Node B can use this list directly as a candidate source route back to Node A.

3. **Return path**: Node B can now send unicast packets to Node A using the learned source route. If the packet was ack-requested, Node B's MAC ack also traverses the mesh, allowing Node A to confirm reachability.

4. **Bidirectional establishment**: If Node A also needs a source route to Node B, it can include the trace-route option on its initial packet. When Node B responds (e.g., with an ack, beacon, or identity payload) using its learned route and also including a trace-route option, Node A can learn its own source route to Node B.

Because router hints are only one byte, different repeaters may share the same hint, which may result in redundant (but harmless) forwarding along a source route.
