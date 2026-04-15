# Routing Overview

UMSH packets can be delivered directly to nodes within radio range, flooded across the mesh, source-routed through a specific sequence of repeaters, or delivered using a hybrid of source routing and flooding. This chapter gives a high-level picture of how these mechanisms fit together; detailed procedures are covered in the sections linked below.

In general, it is the responsibility of the individual endpoints to properly route their traffic to their destination.

## Direct (Single-Hop) Delivery

The simplest case: the sender transmits a packet with no source-route option and no flood hop count. Only nodes within direct radio range will receive it. No repeater forwarding occurs. This is appropriate when the destination is known to be a direct neighbor, or for local broadcasts and beacons that do not need multi-hop propagation.

## Flood Routing

The sender sets a **flood hop count** in the packet header, and every repeater that receives the packet decrements the remaining count, increments the accumulated count, and retransmits. The packet radiates outward until the hop count is exhausted or all reachable repeaters have forwarded it.

Flood routing requires no prior knowledge of the network topology. It is used for broadcasts, multicast, and unicast when no source route is known. The cost is airtime: every repeater in range participates, so a high hop count can saturate a busy mesh.

See [Packet Structure § Flood Hop Count](packet-structure.md#flood-hop-count) for encoding details and [Repeater Operation § Forwarding Procedure](repeater-operation.md#forwarding-procedure) for the forwarding rules.

### Region Scoping

The **region code option** restricts flood forwarding to repeaters configured for that specific geographic region. A repeater that does not recognize or is not configured for the region MUST NOT flood-forward the packet.
If multiple region code options are present, matching any one of them is sufficient for flood forwarding. If a packet is being flood-forwarded without a region code, a repeater may add one according to local policy, but it must never rewrite an existing region code or add a second one.
Region scoping is not enforced during the source-routed portion of a hybrid route — only after the source-route hints are exhausted and the packet transitions to flooding.

See [Packet Options § Region Code](packet-options.md#region-code-option-11).

### Signal-Quality Filtering

Two packet options let the sender control which links are acceptable for flood forwarding:

- **Minimum RSSI** — a repeater that received the packet below the specified signal strength must not flood-forward it.
- **Minimum SNR** — a repeater that received the packet below the specified signal-to-noise ratio must not flood-forward it.

These thresholds prevent retransmission over weak links that are unlikely to deliver the packet reliably, saving airtime and transmit power. The repeater may also enforce its own local thresholds; the effective threshold is the higher of the two.

See [Packet Options § Minimum RSSI](packet-options.md#minimum-rssi-option-5) and [Packet Options § Minimum SNR](packet-options.md#minimum-snr-option-9).

## Source Routing

When the sender knows a path to the destination, it can include a **source-route option** listing the sequence of repeater hints the packet should traverse. Each repeater checks whether it matches the next hint, removes its own hint, and forwards. Only the designated repeaters handle the packet, so source routing avoids the airtime cost of flooding.

Source routes are learned from the **trace-route option**: when a flooded packet carries a trace-route option, each forwarding repeater prepends its own hint. The recipient can reverse the accumulated trace and cache it as a source route for future replies. This means path discovery is not a separate operation — it falls out of normal packet exchange.

See [Packet Options § Source Route](packet-options.md#source-route-option-3), [Packet Options § Trace Route](packet-options.md#trace-route-option-2), and [Beacons & Path Discovery § Route Learning](beacons.md#route-learning).

## Hybrid Routing

A packet can carry both a source-route option and a flood hop count. The packet is source-routed through the listed repeaters first; once the source-route hints are exhausted, it transitions to flood routing bounded by the remaining flood hop count. This enables "deliver to a region, then flood locally" behavior — useful for reaching a node in a known area without flooding the entire mesh.

See [Repeater Operation § Routing Implications](repeater-operation.md#routing-implications).

## Bridging

A **bridge** is a node that relays UMSH packets between two different media or RF channels — for example, from a local LoRa radio to an internet backhaul and back to a distant LoRa radio, or between two radio bands.

Bridges are not prohibited per-se, as that is not a protocol-level decision. Instead, this document provides some guidance on how bridges can be deployed while lowering the risk of hurting local mesh performance.

Bridges are largely protocol-transparent: they consume source-route hints and forward packets as repeaters do. Currently, a bridge also retransmits on the inbound medium — even for source-routed packets — to provide forwarding confirmation to the previous hop, though [this may be optimized in the future](limitations.md#bridge-hop-confirmation).

Bridges participate in source routes and trace routes like any other repeater. A trace route that crosses a bridge will contain the bridge's router hint, and source-routed packets will traverse the bridge transparently.

Flooding works across bridges, but the remaining flood hop count is clamped when a packet exits the bridge — by default, to a maximum of 1. This clamping applies even to hybrid-routed packets that transition from source routing to flooding after crossing the bridge. The effect is to keep individual meshes local and accountable while still enabling multi-segment routing.

> [!CAUTION]
> Internet bridges have the potential to be destructive to the mesh and are generally discouraged
> because 1) they cannot be relied upon in an emergency, and 2) they can waste airtime with useless,
> non-local chatter. Moreso than other types of bridges, internet bridges MUST limit the flood hop count
> of packets which transit the bridge.

## Forwarding Confirmation and Recovery

UMSH provides hop-by-hop forwarding confirmation for both source-routed and flood-originated packets. After transmitting, a node listens for the next hop to retransmit the same packet. If no retransmission is heard within a timeout, the node retries with exponential backoff (up to 3 retries). The original sender does not currently receive any notification of a forwarding failure when source routing.

If a cached source route fails entirely (noticed because of a timeout), the sender can fall back to flood routing for the same logical packet using the **route retry option**, which allows repeaters to forward it even if they already suppressed the original source-routed attempt.

See [Repeater Operation § Forwarding Confirmation](repeater-operation.md#forwarding-confirmation) and [Repeater Operation § Source-Route Failure Recovery](repeater-operation.md#source-route-failure-recovery).

## Channel Access

Before any transmission — original, forwarded, or acknowledgment — a node performs Channel Activity Detection (CAD) and backs off if the channel is busy. Flood-forwarding repeaters additionally use a contention window based on received SNR, so that better-positioned repeaters transmit first and weaker ones can suppress their retransmission if they overhear an earlier forward.

See [Channel Access](channel-access.md).
