# UMSH over IP Multicast

UMSH can be used over IP multicast the way it is used over LoRa. A frame sent
to a multicast group on a local network is heard by every node in the group,
as a frame transmitted on a LoRa channel is heard by every node in range, and
the group carries UMSH as a LoRa channel does: nodes on it address one
another, flood, route, acknowledge, and share
[channels](multicast-channels.md) by the same rules. Phones and computers on
one network form a UMSH mesh among themselves, with no LoRa radio anywhere.

A node with a LoRa radio may join the group too. With its repeater enabled it
is a [bridge](routing-overview.md#bridging) between the group and its LoRa
channel, as described in [Nodes With a LoRa Radio](#nodes-with-a-lora-radio),
so that the nodes on the network and the nodes within reach of its radio
share one mesh. The group needs no LoRa radio to work.

## Why a Multicast Group

A multicast group gives a local network an independent UMSH segment that
works as soon as a node joins it. There is no server to set up and no
connection to establish or authenticate: a node needs only the group's
address and port, which have defaults, and from then on it hears every other
node in the group and is heard by them. Nothing at the transport needs
authenticating, because UMSH [secures its frames](security.md) end to end and
a node trusts a frame on its contents, never on where it arrived from.

The group can be this simple because it is the kind of medium UMSH is
designed for. UMSH frames are sent to a medium, not to a peer:

- **A frame names no link-layer receiver.** A unicast frame is addressed by
  a hint of its destination's public key, and a
  [multicast channel](multicast-channels.md) frame by its channel. It is
  transmitted once, every node in range hears it, and the node it is meant
  for recognizes it by its cryptographic contents.
- **A sender needs no picture of the network.** A frame sent with no route
  reaches every node in
  [direct range](routing-overview.md#direct-single-hop-delivery); beyond
  that, a flood carries it, and routes are learned from the traffic itself.
  Every node in the group is in direct range of every other, so a frame
  reaches its destination with no route at all.

Over unicast, the same segment would need each node to find its peers and
send every frame once per peer, or a server for every node to connect to and
relay through. Either is something to set up and keep running that the
group does without.

A multicast group is appropriate only because UMSH is a low-bandwidth
protocol. Its frames are at most 255 octets, and its rates are set by LoRa:
well under a kilobyte per second. Every datagram sent to the group reaches
every host in it and, on Wi-Fi, is sent to every station at a low basic
rate. That cost is negligible at UMSH's rates; a protocol that carried
pictures or video would not belong in a multicast group, and UMSH is not
designed to carry either.

## Transport

Frames travel in UDP datagrams sent to an IPv4 multicast group. The default
group is
`239.255.134.121`, in the administratively scoped range, and the default port
is 15056. A deployment MAY configure another IPv4 multicast group and another
nonzero port; every node that is to hear the others uses the same pair.

Every node sends from the group's port as well as to it, and listens on it;
several nodes on one host share it.

A node joins the group on the interface it uses for the local network and
sends to the group from that interface, with a multicast TTL of 16 unless
configured otherwise. How far the group reaches is the network's decision:
routers forward a multicast group only where they are configured to, and
`239.255.0.0/16` is scoped to the organization. A network that routes the
group between its subnets joins their nodes into one group.

### Echoes

A node in a multicast group hears its own datagrams when multicast loopback,
or an access point repeating a station's multicast, hands them back. A node
MAY drop a datagram whose source address and port are its own, which on a
host with several nodes also drops the others'. A node that is alone on its
host MAY instead disable multicast loopback.

### Point-to-Point

A unicast address MAY be configured in place of the group, naming the one
peer of a point-to-point link. The node joins nothing, sends to the peer at
the group's port, and drops every datagram whose source address and port are
not the peer's. Each end names the other, on the same port.

## Datagram Format

A datagram carries exactly one frame, with no header: the frame exactly as it
is transmitted over LoRa.

- A sender **MUST NOT** send a datagram that is empty or larger than 255
  octets.
- A receiver drops, with accounting, a datagram that is empty or larger than
  255 octets, and handles any other as a frame received over LoRa.

The sender of a frame is not identified in the datagram, and nothing about
the datagram's source address is carried onward.

A datagram is a **group reception**. It was heard by every node in the
group, and measured by none of them: it carries no RSSI or SNR, and the
[signal-quality thresholds](repeater-operation.md#forwarding-procedure) do
not apply to it.

## Traffic

A node sends a datagram only when it transmits a frame: one it originates,
an acknowledgment, or, on a node with a LoRa radio, a frame its radio
transmits. There is no keepalive, membership, or routing exchange of the
group's own.

Every node in the group hears every datagram, so one datagram delivers a
frame to the whole group. A frame reaches the group again when a bridge
repeats it onto LoRa, and what a radio sends to the group is bounded by its
airtime and its [duty cycle](channel-access.md).

A node whose only medium is the group **SHOULD NOT** repeat. Every node it
could reach has already heard the frame, so a repeat spends a flood hop and
sends one more datagram to every host in the group while carrying the frame
to no one new. A network on which a multicast datagram does not reach every
node, such as an ad hoc Wi-Fi network whose nodes are not all in range of one
another, is the exception: there a repeater carries frames to nodes the
sender cannot reach.

## Discovery

Nodes advertise themselves with DNS-SD over multicast DNS, under the service
type `_umsh._udp`. A bridge **SHOULD** advertise; other nodes MAY.

- The instance name is the node's device name.
- The SRV port is the group's port.
- The TXT record carries the keys below.

Key | Value | Present
----|-------|--------
`v` | TXT schema version: `1` | Always
`grp` | The group address, dotted decimal with no leading zeros | Always
`id` | The node's public key, as 44 base58 characters | Always
`f` | LoRa center frequency, in Hz | When the node has a LoRa radio with its PHY enabled
`bw` | LoRa bandwidth, in Hz | With `f`
`sf` | LoRa spreading factor | With `f`
`cr` | LoRa coding rate denominator, 5 to 8 | With `f`
`rep` | `1` if the node repeats LoRa to LoRa, else `0` | With `f`
`ib` | `1` if an [internet bridge](internet-bridging.md) link is up | Optional

Numbers are decimal with no leading zeros. A node updates its record when any
value changes.

A node reading a record ignores keys it does not recognize, treats a missing
optional key as false, and ignores a record whose `v` it does not recognize.
Discovery is only discovery: frames travel over the group whatever the
records say, and a node learns from them which LoRa meshes the group reaches
and on which settings, before it sends anything.

## Nodes With a LoRa Radio

A node with a LoRa radio that joins the group is attached to both its LoRa
channel, called *the air* below, and the group:

- **What arrives from the group is a reception.** The node handles it as it
  handles a frame heard on its radio, recording that it arrived from the
  group, and applies the
  [forwarding procedure](repeater-operation.md#forwarding-procedure) to it
  once. With its repeater enabled the node may repeat it on its radio; with
  its repeater disabled it forwards nothing, whatever the frame arrived on.
- **What the radio transmits goes to the group.** Each frame the node's
  radio puts on the air is sent to the group, its repeats included. A frame
  the radio does not transmit—a repeat abandoned to a better-placed
  repeater, or given up to a busy channel—does not reach the group.

A node whose repeater is disabled is therefore a member of the group and
nothing more; only a node with its repeater enabled is a bridge.

A frame a node on the group originates spends one flood hop at each bridge
that carries it onto the air. A frame heard on the air and carried back onto
the air by way of the group spends one hop at the bridge that hears it and
repeats it, which is what reaches the group, and one at each bridge that
receives it from the group and repeats it. A repeat returns to the group,
where every node has already seen the frame and suppresses it as a
duplicate.

A bridge that repeats a group reception prepends a
[Trace](packet-options.md#trace-option-7) record with zero signal bytes,
the record for a hop that measured nothing.

The [duty cycle](channel-access.md) a radio spends repeating group receptions
counts against its limit like any other forward. Copies sent to the group
spend no radio airtime.

### Ingress Limit

A bridge **MUST** bound the rate at which it accepts group receptions, so
that a busy network cannot spend the radio's airtime faster than its operator
allows. A token bucket of frames per minute is recommended.
Receptions over the limit are dropped with accounting.

### Channel Access

Every bridge in the group receives each datagram at once, so bridges on the
same LoRa channel would carry it onto the air together. Group receptions
therefore contend, and only what is heard over the air says anything about
the air.

- **Group receptions contend.** A group reception carries no measurement to
  rank bridges by. Its
  [flood contention window](channel-access.md#flood-forwarding-contention-window)
  is drawn uniformly from `[W_min, W_max]`, and the jitter and `D_ack` are
  added as for any other forward.
- **Only the air defers.** Only a copy received over the radio defers or
  abandons a pending forward. A copy received from the group says nothing
  about who has transmitted on the radio's channel, and is a duplicate and
  nothing more.
- **A group copy confirms.** A copy received from the group is a frame some
  radio transmitted, and satisfies
  [forwarding confirmation](repeater-operation.md#forwarding-confirmation) as
  a copy overheard on the air does.
- **Overheard acknowledgments are unchanged.** An acknowledgment
  [cuts the budget](repeater-operation.md#ack-cancellation) of a matching
  pending forward whatever it arrived on.

Bridges on one LoRa channel that hear the same group reception draw different
windows. The first to transmit is overheard by the others, which defer as
they would for any repeat they overheard.

## Security Considerations

- **Frames are protected end to end.** A UMSH frame that carries security
  information is authenticated, and encrypted where it is marked encrypted,
  by the node that sends it, before it reaches any medium. The group adds no
  protection and removes none: what crosses the network is what crosses the
  air, and a node trusts a frame on its contents, never on where it arrived
  from.
- **Anyone on the network hears the group.** A listener on the network
  learns what a LoRa receiver in range of the same nodes would.
- **Anyone on the network can send to the group.** The group is as open as
  a LoRa channel is to anyone with a radio. A frame that fails
  authentication is dropped by the node it is addressed to. Where bridges are present, the
  ingress limit and the duty-cycle limit bound what injected traffic costs
  the air.
- **The group reaches as far as the network routes it.** The default group
  is administratively scoped. A network that routes it between subnets has
  extended the group, and any bridges in it, to everyone the routing
  reaches.
- **DNS-SD records are public.** A record reveals a node's public key and,
  for a node with a LoRa radio, its LoRa settings—which its transmissions
  already reveal to anyone in range—to everyone on the network.
- **Bridges join meshes.** The cautions in
  [Routing Overview § Bridging](routing-overview.md#bridging) apply: a bridge
  in the group puts the flood traffic of every LoRa mesh reachable through
  the group on its own mesh's airtime. Region policy and the flood hop budget
  are the tools for keeping that local.
