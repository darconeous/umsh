# Internet Bridging

> [!NOTE]
> This section is an early work in progress and this protocol may change significantly.

This appendix defines a client–server realization of the bridge described
in [Routing Overview § Bridging](routing-overview.md#bridging): a set of
radios in different places, joined by an authenticated tunnel over a
reliable stream transport such as the internet. It specifies the tunnel
wire protocol, how a participant attaches its radio, and the small number
of decisions the tunnel itself makes about what it carries.

> [!CAUTION]
> The cautions in [Routing Overview § Bridging](routing-overview.md#bridging)
> apply in full: internet bridges cannot be relied upon in an emergency and
> can waste airtime with non-local chatter. This appendix exists so that
> bridges which are deployed anyway behave predictably and conservatively.

## Model

A bridge consists of one **bridge server** and one or more **bridge
clients**. Together they form a hidden radio layer: a medium that joins
segments which are nowhere near each other.

- Each participant fronts a ULCP device of its own, attached as a
  tethered host in [backhaul mode](#radio-attachment). The host is
  therefore not on the shared medium at all — it is a point-to-point
  neighbor of the device's own node.
- The server's **interfaces** are its own radio, when it has one, plus
  one interface per connected client. The server's radio is a
  participant like any other; nothing distinguishes it but the absence
  of a tunnel.
- The server copies each frame it receives to its other interfaces. It
  makes no forwarding decisions and holds no mesh state.

The bridge has no identity on the mesh. It appears in no route, answers
to no address, and originates no traffic. The nodes that carry bridged
traffic are the ones behind the participants' radios, and each holds its
own identity.

### A Crossing Is Two Repeater Hops

Because every participant is a point-to-point neighbor of its device's
node, the node's [repeater](repeater-operation.md) is the bridge's
forwarding policy — hop accounting, duplicate suppression, region and
signal policy, all applied to bridged traffic exactly as to anything
else the node hears.

A packet crosses in four steps:

1. A node on the ingress segment transmits. The participant's device
   hears it off the air and its node forwards it by the ordinary
   [forwarding procedure](repeater-operation.md#forwarding-procedure):
   duplicate check, flood hop accounting, trace prepend with a real
   signal measurement, and a transmission on that same segment.
2. That transmission is delivered to the attached host, which writes it
   to the tunnel. What crosses is the ingress node's *output*, already
   rewritten — not the frame as it was first heard.
3. The server copies it to its other interfaces.
4. Each receiving participant hands the frame to its own device's node,
   which receives it as a packet carrying no measurements and forwards
   it by the same procedure: a second duplicate check, a second hop
   accounting, a trace signal entry recording that nothing was measured,
   and no [contention window](channel-access.md#flood-forwarding-contention-window),
   since nobody else heard it.

Two consequences follow, and deployments should plan for both. A
crossing spends **two** flood hops rather than one, so a packet sent
with a budget of three arrives on the far segment with one. And the
ingress node's transmission in step 1 is an ordinary repeat on the
segment the packet came from, which is exactly what the previous hop
listens for: the bridge satisfies
[forwarding confirmation](repeater-operation.md#forwarding-confirmation)
without transmitting anything for the purpose.

Everything the node transmits reaches its host, so everything the node
transmits crosses: its repeats, its beacons, its acknowledgements, and
its own application traffic. That is the node participating in the mesh
the bridge has joined it to.

### Tunnel Echoes

A frame transmitted by an egress node in step 4 is delivered to that
node's own host in the same way, written to the tunnel, and copied
onward. Each of the other participants' nodes then receives a packet it
has already forwarded, and its duplicate cache ends it there.

This costs one extra round of tunnel messages per crossing and no
airtime at all. It is what makes the arrangement safe: the duplicate
caches at the participants, not any rule in the bridge, are what stop a
frame circulating. A deployment **MUST NOT** attach a participant whose
device does not suppress duplicates.

Radio configuration is local to each participant: a client configures
its own device, and the tunnel provides no mechanism for managing a
remote participant's radio.

## Tunnel Transport

### Connection and Authentication

The tunnel is a TLS 1.3 connection over TCP; the client connects to the
server. Earlier TLS versions **MUST NOT** be negotiated.

Peer authentication uses either external pre-shared keys (TLS 1.3 PSK
handshakes) or mutually authenticated certificates with pinned or locally
trusted roots. Each client **SHOULD** hold a distinct credential: it is
how the server identifies a client for policy and rate limiting, and it
allows one client to be revoked without re-keying the rest.

A deployment **MAY** use an Ed25519 node identity as its certificate key,
each side pinning the peer's public key rather than a certificate. The
pinned key **MUST** then be held against the TLS 1.3 `CertificateVerify`
signature — proof that the peer possesses the identity, independent of
anything the certificate claims — rather than against the certificate's
contents. This gives every tunnel credential a UMSH address, so a
participant's credential can later serve as a mesh-addressable identity
for management without re-keying.

The tunnel carries no version of its own. Participants **SHOULD** offer
the ALPN protocol identifier `umsh-bridge/1`, so that an incompatible
future revision fails the handshake instead of misparsing frames.

### Message Framing

The tunnel is a stream of
[HDLC-Lite](https://github.com/openthread/openthread/blob/thread-reference-20180926/doc/spinel-protocol-src/spinel-framing.md#hdlc-lite-hdlc-lite)
frames, exactly as ULCP uses on asynchronous serial links (see
[Framing and Common Semantics](ulcp-core.md)). The frame check sequence is
redundant beneath TLS but is retained so implementations can reuse their
existing framing code unchanged.

There is no message header. A non-empty frame contains one
[`STR_PHY_RAW`](ulcp-transport.md#str-radio-raw) structure and nothing
else; an empty frame is a [keepalive](#keepalive). Because the payload is
exactly the ULCP stream structure, a participant relays bytes without
parsing them:

- **Client to server**: something the client's node transmitted — the
  body of the [`CMD_STR_RECV`](ulcp-transport.md#cmd-str-recv) that
  delivered it, written unmodified, `RX_FLAG_SELF_TX` and all.
- **Server to client**: a frame to hand to the client's node, passed as
  the body of a [`CMD_STR_SEND`](ulcp-transport.md#cmd-str-send) on
  `STR_PHY_RAW`.

The metadata a frame carries across the tunnel describes how it was
*received*, and a transmit request needs metadata of its own. The
participant that hands a frame to its device therefore **MUST** replace
the accompanying metadata with transmit metadata, and **SHOULD** do so
only at that point, so that the received metadata — including any
[buffered-frame](ulcp-transport.md#buffered-metadata) age — remains
available to the staleness rule below for as long as the frame is in
flight.

A frame that is malformed, or larger than the receiving participant is
prepared to transmit, is discarded.

### Keepalive and Reconnection {#keepalive}

A participant writes a bare flag octet (`0x7E`) whenever it has sent
nothing for a keepalive interval — 10 seconds is a reasonable default —
and closes the connection once it has received nothing for an idle
timeout, by default 30 seconds. The two directions are independent.

Empty frames are the idle fill of HDLC-Lite and a conforming decoder
already discards them, so the keepalive needs no message of its own. Two
properties make it sufficient. Liveness is measured in received octets
rather than decoded messages, so a discarded flag still counts as
activity. And because the keepalive is written by the participant's own
relay logic, a peer whose relay has wedged stops emitting it even while
its TLS connection stays open.

A stalled *local* transmit path is not visible to the idle timer, since
the peer keeps talking. It appears as tunnel-queue backpressure instead,
which is bounded below.

Frames queued for a tunnel that fails or backs up are stale by
definition: participants **MUST** bound their tunnel queues, **SHOULD**
drop the oldest frames first under backpressure, and **MUST** discard
queued frames when a connection is re-established rather than flushing
them into the new session.

Staleness is enforced by the sender, and no age accompanies a frame on
the wire. A participant **SHOULD** discard a frame rather than write it
once the frame is older than a configured limit — ten seconds is a
reasonable default — counting any device-side queueing reported through
[buffered-frame metadata](ulcp-transport.md#buffered-metadata). A frame
that old describes a mesh that has moved on.

## Radio Attachment {#radio-attachment}

Each participant attaches to its device as an ordinary tethered host,
without resetting it, and sets
[`PROP_MAC_BACKHAUL`](ulcp-host.md#prop-mac-backhaul) to true. This
requires the device to advertise `CAP_MAC_BACKHAUL`, which in turn
requires `CAP_REPEATER`.

A device that does not advertise `CAP_MAC_BACKHAUL` **MUST NOT** be
attached to a bridge on the shared medium instead. A host on the medium
transmits directly: its frames reach the air without passing any node's
duplicate suppression, hop accounting, or forwarding policy, which are
the whole of what makes a crossing safe.

A participant **SHOULD** also set
[`PROP_MAC_PROMISCUOUS`](ulcp-host.md#prop-mac-promiscuous) to true. In
backhaul mode this widens what the host is delivered from those of the
node's transmissions that pass its receive filtering to all of them —
which for a device with a provisioned host domain is the difference
between carrying the node's repeats and silently dropping them. A device
with no host domain provisioned filters nothing, so this is a safeguard
rather than a requirement.

Both properties are session-scoped and revert on every attach, so both
must be re-asserted after each reconnection to the device.

A participant **MUST NOT** write
[`PROP_MAC_REPEATER_ENABLED`](ulcp-host.md). Whether a device repeats is
persisted, device-domain configuration belonging to whoever provisioned
it. A participant whose device has its repeater disabled is a **leaf**:
its node is reachable across the bridge and its own traffic crosses, but
nothing is carried onward from its segment, and nothing arriving from
the bridge reaches the air. This is a legitimate deployment, and an
implementation **SHOULD** report it rather than treat it as a fault.

Transmission requires the device to advertise
[`CAP_WRITABLE_RAW_STREAM`](ulcp-transport.md#capabilities). Participants
**SHOULD** use confirmed transmissions (non-zero TID) so that refusals
are observed rather than silent, and bridged transmissions **MUST NOT**
set `TX_FLAG_NODUTY`: the device's duty-cycle enforcement is the backstop
against a bridge that would otherwise consume a segment's airtime budget.

A backhauled hand-off crosses a wire. It contends for no channel, spends
no airtime, and is not charged against the duty limit — the airtime is
spent later, and accounted to the node, if the node decides to transmit.
What a hand-off can meet is a node whose receive queue is full, which is
reported as `STATUS_CCA_FAILURE` for want of a better code. A participant
**SHOULD** wait briefly and offer the frame again, and **MUST** continue
draining its device's receive path while it waits: draining the node's
output is what makes room in its input.

Whether a handed-off frame reaches the air is the node's decision. A
duplicate it has already forwarded, or one whose flood budget is spent,
ends at the node. That is the forwarding policy working, and a
participant **MUST NOT** treat it as a failed hand-off or retry it.

No participant provisions node logic for the bridge: there is no bridge
identity to provision. A participant's device is configured as whatever
node its owner intends it to be.

## Relay Procedure {#relay-procedure}

For a frame arriving on interface *I*, the server:

1. Discards it if it has grown stale (see [Keepalive and
   Reconnection](#keepalive)).
2. Charges it against *I*'s [traffic limits](#traffic-limits), and
   discards it if the limit is spent.
3. Applies the [exit clamp](#exit-clamp), if one is configured.
4. Copies it to every interface except *I*, subject to any configured
   per-interface-pair rules.

There is no step that reads what the frame means. The server **MUST NOT**
suppress duplicates, account for hops, match source routes, prepend trace
entries, or apply signal-quality thresholds; those belong to the
participants' nodes, which apply them to bridged traffic and local
traffic alike. A frame the server cannot parse is carried unchanged like
any other.

Clients apply nothing at all beyond the framing rules above: a client
relays bytes between its radio and the tunnel.

## Traffic Limits {#traffic-limits}

The server **SHOULD** rate-limit per client. An authenticated but
misbehaving client is the realistic failure mode of a bridge, and the
duty ledgers of the devices at the far end should be the backstop, not
the policy.

A limit counts everything the client's node transmits, which includes
that node's repeats of frames the bridge itself handed it. A crossing
therefore charges a little against every participant, not only the one
whose segment the traffic came from. Budgets should be set with that in
mind.

### Exit Clamp {#exit-clamp}

A deployment **MAY** configure the server to clamp the remaining flood
budget of frames passing through it. This is the one thing the server
does that depends on a frame's contents, and it exists so that an
operator can pull a bridge's reach in quickly without reconfiguring
every device behind it.

When a clamp of *n* is configured, the server rewrites `FHOPS_REM` to *n*
for any frame whose `FHOPS_REM` exceeds it. The
[flood hop count](packet-structure.md#flood-hop-count) is dynamic routing
metadata excluded from the MIC, so the packet remains authentic — this is
the same field a repeater decrements. The server **MUST NOT** alter
`FHOPS_ACC`, which is a record of hops already taken; **MUST NOT** add
the field to a frame that carries none, since a sender that omitted it
meant the frame not to be flooded onward; and **MUST NOT** discard a
frame it cannot parse, which is carried unchanged.

The clamp is off by default. A crossing already spends two flood hops,
which bounds a bridged flood without any configuration, and a clamp
narrows the reach of every deployment behind the bridge at once. A clamp
of 0 stops bridged floods at the egress segment while leaving traffic
addressed to the participants' own nodes unaffected.

## Acknowledgements Across a Bridge

Acknowledgements cross as ordinary traffic. A destination's
[MAC ack](packet-types.md#mac-ack-packet) is transmitted by its node,
reaches that node's attached host, crosses the tunnel, and is forwarded
back toward the originator by the repeaters along the way — two hops for
the crossing, as for anything else.

The round trip therefore costs four flood hops of the sender's budget:
two out and two back. A sender whose budget does not cover the round trip
receives no acknowledgement even though the packet arrived. Where an
[exit clamp](#exit-clamp) is configured, the returning ack is clamped
too, and
[route failure recovery](repeater-operation.md#route-failure-recovery)
cannot repair that: the restored flood is clamped the same way.

Source-routed hops spend nothing from `FHOPS`, so explicit routes cross
bridges at any depth. Ack-requesting traffic that crosses a bridge
**SHOULD** either carry a
[trace-route option](packet-options.md#trace-route-option-2) — the
participants' nodes record themselves in it, which is what makes the
reversed trace routable — or be sent along a known source route.

## Operational Guidance

- **Budget for two hops.** Traffic expected to cross a bridge needs a
  flood budget that covers the crossing at both ends, and twice that if
  an acknowledgement is expected back.
- **Co-located clients.** Two clients whose radios share a segment cause
  every copied frame to be handed to that segment twice. Their nodes'
  duplicate caches keep it from being transmitted twice, but the tunnel
  traffic is real; per-interface-pair rules are the place to exclude one
  from the other's fan-out.
- **Region and signal policy.** These are configured on each
  participant's device, where the decision to transmit is actually made.
  A bridge whose segments sit in different regions relies on each node's
  own region matching.
- **Leaf participants.** A participant whose device does not repeat still
  reaches the whole bridge and is reachable from it. This is the right
  configuration for a device that should benefit from a bridge without
  spending its segment's airtime on other people's traffic.

## Security Considerations

TLS provides tunnel authentication, integrity, and replay protection;
the shared secret or pinned credential is the sole admission control.
UMSH frames are already end-to-end authenticated and encrypted at the
MAC layer, so the tunnel's confidentiality mainly shields routing
metadata — hints, options, traffic volume — from path observers.

Using a node identity as a tunnel credential does not let the two
protocols' signatures be confused for one another: the TLS 1.3
`CertificateVerify` payload is domain-separated by a fixed 64-octet
padding prefix and context string that no UMSH signed structure begins
with.

A compromised client credential is equivalent to granting the attacker an
RF presence on every segment the bridge touches: it can inject arbitrary
well-formed frames and replay captured ones. It cannot forge other nodes'
authenticated traffic. The damage is bounded by the same mechanisms that
bound a hostile local transmitter, and by the same parties: every frame
it injects is subject to the duplicate suppression, hop accounting,
region policy, and duty-cycle enforcement of the node that would have to
transmit it. Per-client rate limits, an exit clamp, and revocation of the
client's credential bound it further.

A backhauled host is off the medium and is delivered only what its own
node transmits, so promiscuous delivery grants it nothing beyond the
repeats it exists to carry. Operators should still treat the server as
privileged infrastructure: it observes the metadata of every frame every
participant's node transmits.
