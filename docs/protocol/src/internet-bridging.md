# Internet Bridging

> ![NOTE]
> This section is an early work in progress and this protocol may change significantly.

This appendix defines a client–server realization of the bridge described
in [Routing Overview § Bridging](routing-overview.md#bridging): a single
virtual repeater whose radios sit in different places, connected by an
authenticated tunnel over a reliable stream transport such as the
internet. It specifies the tunnel wire protocol, the forwarding rules the
bridge applies, and how the bridge satisfies the forwarding-confirmation
expectations of the meshes it joins.

> [!CAUTION]
> The cautions in [Routing Overview § Bridging](routing-overview.md#bridging)
> apply in full: internet bridges cannot be relied upon in an emergency and
> can waste airtime with non-local chatter. This appendix exists so that
> bridges which are deployed anyway behave predictably and conservatively.

## Model

A bridge consists of one **bridge server** and one or more **bridge
clients**.

- The server owns the bridge's node identity. Trace routes crossing the
  bridge carry this identity's router hint, source routes name it, and
  packets addressed to it are processed by the server whatever interface
  they arrive on.
- The server and each client front a ULCP device of their own, attached as
  a tethered host with promiscuous delivery enabled (see
  [Radio Attachment](#radio-attachment)).
- The server's **interfaces** are its own radio plus one interface per
  connected client. All forwarding decisions are made at the server;
  clients relay frames between their radio and the tunnel and apply no
  forwarding logic of their own.

The whole assembly is **one** virtual repeater. It maintains a single
[duplicate-suppression cache](repeater-operation.md#duplicate-suppression)
shared across all interfaces, performs hop accounting once per crossing,
and records itself in a trace route and trace signal once per crossing —
regardless of how many interfaces or clients participate.

Radio configuration is local to each participant: a client configures its
own device, and the tunnel provides no mechanism for managing a remote
participant's radio.

## Tunnel Transport

### Connection and Authentication

The tunnel is a TLS 1.3 connection over TCP; the client connects to the
server. Earlier TLS versions **MUST NOT** be negotiated.

Peer authentication uses either external pre-shared keys (TLS 1.3 PSK
handshakes) or mutually authenticated certificates with pinned or locally
trusted roots. Each client **SHOULD** hold a distinct credential: it is
how the server identifies a client for policy and rate limiting, and it
allows one client to be revoked without re-keying the rest.

A deployment **MAY** use each participant's Ed25519 node identity as its
certificate key, each side pinning the peer's public key rather than a
certificate. The pinned key **MUST** then be held against the TLS 1.3
`CertificateVerify` signature — proof that the peer possesses the
identity, independent of anything the certificate claims — rather than
against the certificate's contents. This gives every tunnel credential a
UMSH address, so a client's credential can later serve as a
mesh-addressable identity for management without re-keying.

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

- **Client to server**: a candidate reception — the body of the
  [`CMD_STR_RECV`](ulcp-transport.md#cmd-str-recv) that delivered the
  frame, written unmodified. The receive metadata **SHOULD** be present
  (sentinel-filled where the radio cannot measure), because the server's
  [signal-quality checks](#forwarding-procedure) depend on it.
- **Server to client**: a transmit request, passed unmodified as the body
  of a [`CMD_STR_SEND`](ulcp-transport.md#cmd-str-send) on
  `STR_PHY_RAW`.

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
that old has already outlived every
[forwarding-confirmation retry](repeater-operation.md#forwarding-confirmation)
that could have wanted it.

## Radio Attachment {#radio-attachment}

Each participant attaches to its device as an ordinary tethered host and
sets [`PROP_MAC_PROMISCUOUS`](ulcp-host.md#prop-mac-promiscuous) to true.
The property is session-scoped and reverts on every attach, so it must be
re-asserted after each reconnection to the device. Because
promiscuous-only frames are never queued while the host is detached, a
device outage leaves no stale backlog to drain — attachment starts clean
by construction.

Transmission requires the device to advertise
[`CAP_WRITABLE_RAW_STREAM`](ulcp-transport.md#capabilities). Participants
**SHOULD** use confirmed transmissions (non-zero TID) so that duty-limit
and channel failures are observed rather than silent, and bridged
transmissions **MUST NOT** set `TX_FLAG_NODUTY`: the device's duty-cycle
enforcement is the backstop against a bridge that would otherwise consume
a segment's airtime budget.

A confirmed transmission reports channel-access failure to the
participant rather than retrying on its own, and the local control
protocol carries no retry count to delegate one: one `CMD_STR_SEND` is
one channel-access attempt. The
[backoff procedure](channel-access.md#backoff-procedure) is therefore
the participant's to run, and it runs the same one every other
transmitter on that segment does. A participant **MUST** continue
draining its device's receive path while it waits out a backoff; a
participant that stops listening in order to talk costs its segment
other stations' traffic as well as its own.

The server provisions its host domain as any MAC-owning host would.
Clients **SHOULD NOT** configure a host key or acknowledgement delegation
on their devices; the bridge identity's node logic lives entirely at the
server.

## Forwarding Procedure {#forwarding-procedure}

The bridge follows the
[repeater forwarding procedure](repeater-operation.md#forwarding-procedure),
adapted to multiple interfaces. For a frame arriving on interface *I*:

1. **Duplicate suppression** — Check the shared cache using the
   [repeater cache-key rules](repeater-operation.md#duplicate-suppression).
   If the key is present, do not forward; see
   [Re-confirmation](#re-confirmation) for the one transmission a
   duplicate may still trigger. A [Route Retry](packet-options.md#route-retry-option-6)
   variant is a distinct cache key and forwards normally.

2. **Local origin and local destination** — If the source or destination
   address identifies the bridge's own identity, do not forward. This is
   also what keeps the bridge's own transmissions, overheard by another of
   its interfaces, from being re-bridged.

3. **Locally handled unicast** — If the frame was a unicast (blind or
   direct) fully handled by the server's node logic, do not forward.

4. **Unknown critical options** — If the frame carries a critical option
   the bridge does not understand, do not forward.

5. **Policy** — Apply local bridge policy: per-interface and
   per-interface-pair forwarding rules, per-client rate limits, and region
   matching if configured. The bridge **MUST NOT** rewrite existing
   [region codes](packet-options.md#region-code-option-11) and, unlike an
   ordinary repeater, **SHOULD NOT** insert one: its interfaces may sit in
   different regions, and a code added at one segment's exit would
   misdescribe the packet everywhere else it travels.

6. **Source-route match** — If the frame carries a non-empty
   [source-route option](packet-options.md#source-route-option-3):
   if the next hint does not match the bridge's router hint, do not
   forward; otherwise remove the hint, preserving the option even when it
   empties. This is a source-routed hop: skip steps 7 and 8.

7. **Flood hop accounting** — If the frame has a
   [flood hop count](packet-structure.md#flood-hop-count) with
   `FHOPS_REM > 0`, decrement `FHOPS_REM` and increment `FHOPS_ACC`.
   Otherwise, do not forward.

8. **Signal-quality thresholds** — Apply minimum-RSSI and minimum-SNR
   checks against the measurements of the radio that heard the frame —
   for a client interface, the receive metadata carried alongside the
   tunneled frame.

9. **Exit clamp** — Clamp `FHOPS_REM` to the configured exit maximum.
   The default is 1, and internet-tunneled deployments **SHOULD NOT**
   raise it. The clamp applies to source-routed hops as well, bounding
   the flood budget of a hybrid route that transitions to flooding beyond
   the bridge.

10. **Trace route and trace signal** — If the frame carries a
    [trace-route option](packet-options.md#trace-route-option-2), prepend
    the bridge's router hint. If it carries a
    [trace-signal option](packet-options.md#trace-signal-option-10),
    prepend the receive measurements of step 8 — the reading of whichever
    of the bridge's radios heard the frame, wherever that radio sits.
    Either prepend applies to a source-routed hop as well, which reaches
    this step without passing through step 8. If a prepend would exceed
    the maximum frame size, drop the frame.

    The bridge crosses once, so it writes one entry in each option, and
    it **MUST** write to both or neither. A hop that grows the trace
    route without growing the trace signal destroys the correspondence
    between hint and reading for every hop recorded before it, not only
    its own.

    Where the arriving metadata reports no measurement, or does not
    decode, the bridge writes a placeholder entry rather than omitting
    one — the correspondence is owed whether or not the reading exists.
    An RSSI byte of zero serves, being 0 dBm at the receiver and so
    unreachable as a real reading.

11. **Accept** — Insert the cache key into the shared cache now, before
    any transmission.

12. **Fan-out** — Transmit the rewritten frame on every interface except
    *I*, subject to the policy decisions of step 5.

13. **Confirmation copy** — Transmit the confirmation copy on *I*, as
    specified in [Forwarding Confirmation](#forwarding-confirmation).

Fan-out transmissions introduce the packet to segments that have not yet
carried it, so the [flood forwarding contention window](channel-access.md#flood-forwarding-contention-window)
does not apply to them; ordinary channel access does.

## Forwarding Confirmation {#forwarding-confirmation}

A bridge retransmits on the arrival interface so the previous hop can
[confirm forwarding](repeater-operation.md#forwarding-confirmation), as
[Routing Overview § Bridging](routing-overview.md#bridging) requires. The
**confirmation copy** is the rewritten frame exactly as fanned out in
step 12, except that `FHOPS_REM` is forced to zero (when the field is
present).

This form is deliberate:

- The previous hop still recognizes it. Confirmation matches on the
  [cache key](repeater-operation.md#duplicate-suppression), which excludes
  the flood hop count for every packet type.
- It recruits no forwarders. A repeater receiving the copy rejects it at
  flood hop accounting, so the bridge is flood-neutral on the arrival
  segment: it confirms receipt without extending the local flood.
- It cannot sterilize the live flood. Repeaters insert cache keys only on
  acceptance for forwarding; a repeater that hears the zero-`FHOPS_REM`
  copy before the live flood reaches it caches nothing and forwards the
  live copy normally. Bridges depend on that insertion timing, which is
  therefore normative for them.
- Delivery from the copy is sound. A destination hearing only the
  confirmation copy processes it normally, and its `FHOPS_ACC` honestly
  counts the hop through the bridge.

The copy is a full-length frame, so this mechanism confirms cheaply in
forwarding terms but not in airtime; the airtime optimization remains
open (see [Bridge Hop Confirmation](limitations.md#bridge-hop-confirmation)).

For flood hops, the confirmation copy is a flood forward on a segment
actively carrying the packet: it **SHOULD** use the
[contention window](channel-access.md#flood-forwarding-contention-window),
defer when another forwarding of the same packet is overheard, and may be
abandoned under the usual deferral rules — any overheard forwarding
confirms the previous hop just as well. For source-routed hops the copy
is the previous hop's only confirmation; it uses ordinary channel access
and is not abandoned.

### Re-confirmation {#re-confirmation}

If the confirmation copy is lost, the previous hop retries — and the
retry is a duplicate the cache would otherwise suppress into silence,
letting the previous hop exhaust its retry budget and wrongly declare the
route failed. Therefore: when a duplicate of an accepted frame arrives on
the interface it was originally accepted from, within a bounded window of
the original acceptance, the bridge **MAY** re-transmit the confirmation
copy on that interface. It **MUST NOT** re-forward the frame on any other
interface. The considerations mirror the
[duplicate-acknowledgement window](security.md#duplicate-acknowledgement-window);
thirty seconds is a reasonable default. Duplicates arriving on other
interfaces are ordinary suppressed duplicates and trigger nothing.

This requires the cache entry to record the arrival interface and
acceptance time alongside the key.

## Acknowledgements Across a Bridge

The exit clamp makes flood-returned acknowledgements asymmetric. On the
forward path the clamp already limits delivery to nodes near the bridge's
exit, so a destination that received the packet is bridge-adjacent. The
returning [MAC ack](packet-types.md#mac-ack-packet), flooded with a
radius taken from `FHOPS_ACC`, is clamped again on its way back — and
dies there unless the *originator* is within the clamp of the bridge on
its own segment. Flood routing alone therefore does not round-trip an
acknowledgement across a bridge, and
[route failure recovery](repeater-operation.md#route-failure-recovery)
cannot repair this: the restored flood is clamped the same way.

Source-routed hops spend nothing from `FHOPS`, so explicit routes cross
bridges at any depth. Ack-requesting traffic that crosses a bridge
**SHOULD** either carry a
[trace-route option](packet-options.md#trace-route-option-2) — the
bridge's hint prepend is what makes the reversed trace routable — or be
sent along a known source route. A sender with neither should not expect
an acknowledgement back across a bridge.

## Co-located Repeater Role

A device backing a bridge interface **MAY** additionally run its own
repeater role, in which case two co-located repeaters exist — the device
and the bridge — each with its own duplicate cache and hop accounting.
This composes, with two rules:

- The device's repeater role **MUST NOT** treat the tethered host
  identity's hints as its own for source-route matching. Routed hops
  through the bridge identity belong to the bridge.
- The device's normal flood re-forward on the arrival radio already
  serves as the previous hop's confirmation, so the bridge **SHOULD**
  suppress its flood-hop confirmation copies on that interface. It
  **MUST** still emit confirmation copies for source-routed hops, which
  the device will not forward.

The division is imperfect: when the device's own policy declines a
forward, no flood confirmation is emitted by either party. This matches a
standalone repeater declining the same packet, but deployments that want
the bridge's confirmation behavior to be exact **SHOULD** leave the
repeater role disabled on bridge-backing devices.

## Bridge-Originated Traffic

The bridge is a node present on every segment it touches. Its own
traffic — application packets, beacons, and the MAC acks it generates as
a destination — is ordinary node behavior applied per interface, not
subject to the forwarding procedure or the exit clamp, transmitted on
whichever interfaces its routing state selects. It **MAY** beacon on all
interfaces. Step 2 of the forwarding procedure keeps this traffic from
being re-bridged when one of its own transmissions is overheard through
another interface.

## Operational Guidance

- **Rate limiting.** The server **SHOULD** rate-limit forwarding per
  client and per interface pair. An authenticated but misbehaving client
  is the realistic failure mode, and the device duty ledger should be the
  backstop, not the policy.
- **Co-located clients.** Two clients whose radios share a segment cause
  every fanned-out frame to be transmitted twice there. The shared cache
  keeps their mutual receptions from looping, but the duplicate airtime
  is real; policy (step 5) is the place to group or exclude them.
- **Region codes.** A bridge whose segments sit in different regions
  should rely on region matching in step 5 rather than tagging: see the
  insertion prohibition there.

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
bound a hostile local transmitter — duplicate suppression, the exit
clamp, per-client rate limits, and duty-cycle enforcement — plus
revocation of the client's credential.

The bridge forwards frames it cannot decrypt; promiscuous delivery is
what a repeater's role requires, not an information grant. Operators
should still treat the server as privileged infrastructure: it observes
the metadata of every frame on every segment it bridges.
