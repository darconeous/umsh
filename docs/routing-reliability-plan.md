# Route Learning and Repeating—Reliability Plan

This is a plan, not a specification. It takes stock of how UMSH nodes learn
and choose routes today, names the structural reasons a marginal direct link
wins over a reliable repeater path, and proposes a set of mechanisms—most of
them local policy, a few of them protocol additions—that let devices converge
on reliable routes quickly across fixed, mobile, sparse, and dense
deployments. It closes with a simulator proposal, because the one lesson the
LoRa mesh community keeps relearning is that forwarding heuristics tuned by
intuition do not survive contact with asymmetric links and background traffic.

## The problem, as observed

Several fixed repeaters are deployed. A distant node floods a packet with a
trace route. The destination happens to hear the origin's own transmission,
marginally, before any repeater's copy arrives, so it records the origin as
a direct neighbor and answers direct. The reverse link does not work—the
destination is a handheld, the origin is not—and the answer dies. A
repeater sitting next to the destination would have carried the reply
reliably, but nothing in the learning rule can prefer it. The only way to
make the exchange work today is to attenuate the origin so that the direct
copy is never heard at all.

The specific failure generalizes: whenever a node hears a marginal copy of a
packet before a good one, it learns the marginal path, and the good one is
thrown away as a duplicate.

## How routing state is learned and used today

This section records the implementation as it stood on 2026-09-30, so the
proposals can be judged against what actually ran rather than what the spec
permits. Route failure, the one-hop slack, and the first-ack fix landed
shortly after; what the scoring work changed is in
[What landed on 2026-10-09](#what-landed-on-2026-10-09).

### Route cache

The MAC holds one route per peer. `CachedRoute` in
`crates/umsh-mac/src/peers.rs` is `Direct`, `Source(hints)`, or
`Flood { flood_hops, regions }`, stored in `PeerInfo.route` beside a
`last_seen_ms` that exists for eviction. There is no quality, no
confidence, no counter, no age of the route itself, and no alternate. The
table holds 16 peers on a device and 64 on the phone, evicts the least
recently seen unpinned peer, and lives in RAM; `restore_peer_route` exists
and nothing calls it.

### Learning

`learn_route_for_peer` in `coordinator.rs` runs on every accepted unicast,
blind unicast, multicast from a registered peer, and MAC ack—never on a
broadcast, so beacons and advertisements teach no route. First match wins:

1. a trace-route option present: empty means `Direct`, otherwise `Source`
   of the trace as-is (repeaters prepend, so it already reads as the way
   back);
2. a source-route option present, even emptied: keep whatever is cached;
3. no FHOPS field: `Direct`;
4. otherwise `Flood` of `FHOPS_ACC` and the frame's region codes.

Whatever it decides overwrites the cached route unconditionally. A
multicast from a known peer that arrives by flood therefore replaces a
learned source route with a flood distance.

Duplicates are learned from, but only after a hold-off: a copy of an
ack-requested frame arriving inside `forward_confirm_timeout` is discarded
before learning, and only copies arriving later—the origin's retries—feed
the rule. The repeater copies of one transmission all land inside the
hold-off, so they teach nothing. For a cache with one slot that always
overwrites this is the right call: learning from repeated copies would
replace every direct neighbor with the longest path its packets happened to
take. It becomes the wrong call the moment there is more than one slot.

### Sending

`effective_source_route` uses an explicit route or a cached `Source`;
`Direct` and `Flood` never produce one. `effective_flood_hops` narrows the
application's budget to what the cached route costs plus
`ESTABLISHED_ROUTE_EXTRA_FLOOD_HOPS`, which has been 0 since 35f08f078: a
source-routed send, or a send to a `Direct` peer, leaves the FHOPS field
off entirely. A trace is attached to any repeatable send that has no source
route unless the peer is cached `Direct`, and to a source-routed send only
when it asks for an ack.

### Failure

The first-hop ladder resends up to three times when no repeat is
overheard. When the ack deadline passes, exactly one route retry is allowed
if a source route was attached or the budget was narrowed: it drops the
source route, adds a trace and Route Retry, and floods at the first
available of the application's budget, the frame's remaining hops, the
cached flood distance, the route length, or five. After that, `AckTimeout`.

**Nothing in the MAC ever clears a cached route.** The only caller of
`clear_route` is the application-facing API. A route that has failed is
used again for the next send and stays until a newer frame from the peer
overwrites it—which, if the peer's replies are dying on that very route,
may be never.

### Signal quality

Received RSSI and SNR reach three places: the repeater's forwarding
thresholds, the flood contention delay, and the Trace Signal entry a
repeater prepends. None of them feeds route selection. The trace signal is
parsed for display in ping results and the iOS route view and used for
nothing else.

### Acknowledgments

`queue_mac_ack_for_peer` attaches a cached `Source` route as-is, a cached
`Flood` distance clamped to 1–15 with the peer's region codes, and nothing
at all for `Direct`. It mirrors the request's trace only when the ack is
repeatable. A repeatable ack gets the repeat-confirmed retry ladder; a bare
one is sent once. The device-delegated ack in `umsh-ulcp-device`
(`AckReturn`) is a second implementation with no cache: it reads the route
off the frame and floods at `max(tail, 5)` for a source-routed frame
without a trace. Any change to ack routing has two homes.

### Repeater side

`maybe_forward_received` runs the spec's forwarding procedure. The
duplicate key is inserted only when a forward is actually queued, so a
copy refused by a threshold leaves room for a better copy. The contention
delay is `sample_flood_contention_delay_ms`: an SNR- and RSSI-driven
window of 0 to W_max with W_max = T_frame/2, jitter of T_frame/10, an ack
guard of T_frame/4, and one deliberate deviation from the spec—`SNR_low`
is raised to whatever minimum-SNR threshold is in effect. Source-routed
hops forward with zero delay. On overhearing another copy the forward is
re-timed, at most three times, then dropped. Nothing about the repeater's
own role or mobile bit enters the delay; the MAC has no notion of role at
all—`RepeaterConfig` is `enabled` plus thresholds.

The nRF firmware fixes T_frame at bring-up to the SF7, 62.5 kHz value of
808 ms, so the window is 0–404 ms, the jitter 0–80 ms, and the ack guard
202 ms whatever the radio is actually configured to.

### What a node already records about its neighborhood

Two tables exist, both filled passively and both used only to answer Peer
Repeaters requests:

- `TransmitterObservations` (`crates/umsh-mac/src/observations.rs`): up to
  16 router hints, taken from the first hint of any overheard trace, with
  the RSSI/SNR heard here and a last-seen time. No expiry.
- `PeerRepeaterTable` (`crates/umsh-node/src/peer_repeaters.rs`): up to 16
  identities heard directly that claim the repeater role or bit, with
  name, location, regions, mobile bit, signal, and last-identity time. No
  expiry.

Neither is consulted when a route is chosen or an ack is addressed. The
phone keeps a third, unbounded table of channel-member traces used only to
steer Identity Requests.

### Discovery and motion

The repeater query is an unflooded Identity Request filtered by role or
capability; every responder holds its reply for a uniform 0.5–30 s and
suppresses repeats for 60 s. `umsh-motion` exists and is wired to nothing
but the ESP32 pager's display wake; its `Consumer::Location` slot is
defined and unused, and the nRF boards have no motion path at all.

## Why the current rules produce this outcome

Five properties of the current design combine to produce the observed
behavior. None is a bug against the spec; each is a rule that was reasonable
on its own.

1. **First copy wins, and the first copy is structurally the worst one.**
   Route learning records whatever the first accepted copy of a packet
   carried. Repeaters delay by a contention window before forwarding, so the
   origin's own transmission, if it is heard at all, always arrives first.
   The rule therefore prefers the zero-hop path in exactly the case where
   the zero-hop path is marginal: a copy heard at the demodulation floor is
   still a copy.

2. **Later copies teach nothing.** A copy arriving inside the
   forwarding-confirmation hold-off is discarded before route learning
   sees it, and the repeater copies of one transmission—including the one
   that arrived cleanly through the repeater next door—all arrive inside
   it. The cheapest topology information the mesh produces is dropped on
   the floor. That is correct for a cache with one slot that always
   overwrites, which is why the fix is not "learn from duplicates" alone
   but a candidate set first.

3. **Reverse paths are assumed to work.** A trace records who heard the
   packet and how well, in the forward direction. Reversing it into a source
   route assumes every hop works backward too. That assumption is the one
   DSR made in 1996 and the one the ad hoc routing literature spent the
   following decade retracting: link asymmetry is common, and it is most
   common on exactly the hops that involve a handheld (low transmit power,
   poor antenna, body loss, high local noise floor). The first and last hop
   of any path involving a person are the ones most likely to be one-way.

4. **A direct route carries no recovery.** A packet with no flood budget and
   no source route is transmitted exactly once and confirms nothing. Since
   the established-route slack was set to zero, a peer cached as direct is
   answered with a frame that has no repeater permission and no retry. The
   full end-to-end retry ladder has to run before anything changes, and when
   it does run, the destination re-acknowledges over the same dead link.

5. **One route per peer, chosen once, never withdrawn.** The cache holds a
   single route with no quality, no confidence, no history, and no
   alternates, and the MAC never clears it on failure. There is nothing to
   fall back to, no way to express "this works but barely," and no way for
   a failure to be remembered.

6. **An early overheard copy disarms the routed one.** A destination
   handles a packet the moment it matches, route consumed or not. The
   overheard copy earns no ack, teaches `Direct` from its empty trace, and
   starts the duplicate hold-off that silences the routed copy behind it.
   Choosing the repeater by hand does not escape the failure (M0).

7. **Ack cancellation cuts the repeater out of the reply.** A repeater
   that overhears the destination's direct ack cancels its own pending
   forward of the data, correctly—the destination has it. But the ack it
   overheard is the one dying on the asymmetric link, and cancellation
   gives the repeater no reason to carry it.

## What the literature says

The mechanisms below are not novel; they are the parts of thirty years of
ad hoc routing research that apply to a bandwidth-starved source-routed LoRa
mesh, chosen to fit the primitives UMSH already has.

- **Measure both directions; never assume symmetry.** The ETX metric (De
  Couto et al., MobiCom 2003) scores a link by the product of forward and
  reverse delivery ratios, which penalizes asymmetric links automatically.
  Babel ([RFC 8966](https://www.rfc-editor.org/rfc/rfc8966)) refuses to use
  a link until the neighbor's "I Heard You" confirms the reverse direction.
  Marina and Das ([MobiCom 2002](https://dl.acm.org/doi/10.1145/513800.513803))
  compared exploiting unidirectional links against eliminating them and
  found elimination—AODV's blacklist ([RFC 3561](https://www.rfc-editor.org/rfc/rfc3561)
  §6.8)—cheaper and better. The recent LoRa-specific work reaches the same
  conclusion: the FLoRa distance-vector protocol
  ([2024](https://www.researchgate.net/publication/383138733_A_minimalistic_distance-vector_routing_protocol_for_LoRa_mesh_networks))
  keeps per-neighbor reverse state specifically to handle asymmetric links.
- **Data-driven estimates beat beacon-driven ones for links in use.** The
  Collection Tree Protocol's four-bit link estimator (Fonseca et al., 2007)
  blends periodic-beacon estimates with acknowledgment success on real
  traffic and treats the latter as more trustworthy. UMSH's forwarding
  confirmation is precisely such a data-driven measurement and is currently
  used only to decide whether to retry.
- **Stale source-route caches are the dominant failure under mobility.** The
  DSR cache literature ([survey](https://www.researchgate.net/publication/279712921_Route_Cache_Update_Mechanisms_in_DSR_Protocol_-_A_Survey))
  converges on three fixes: negative caches (remember what failed), explicit
  error propagation (tell the cache holders a hop broke), and adaptive
  expiry driven by observed change rather than fixed timers.
- **Learn the route from the response, not the request.** Meshtastic's
  next-hop router ([mesh algorithm](https://meshtastic.org/docs/overview/mesh-algo/))
  records as next hop the node that relayed the *reply*, because the reply
  arriving proves the reverse direction works, and it falls back to
  flooding on the last retry. Its open
  [issue #11934](https://github.com/meshtastic/firmware/issues/11934) is a
  cautionary tale about duplicate handling: a destination that will not
  re-acknowledge a duplicate makes a single lost ack tear down a working
  route. UMSH's duplicate-acknowledgment window already avoids that trap;
  the proposals below lean on it harder.
- **Suppress redundant rebroadcasts locally; elect relays only if the
  two-hop neighborhood is cheap to know.** The broadcast storm paper (Ni et
  al., MobiCom 1999) showed that counter-based suppression—do not
  rebroadcast if you have heard *k* copies during your assessment delay—
  removes most redundancy with no coordination. OLSR's multipoint relays
  ([RFC 3626](https://www.rfc-editor.org/rfc/rfc3626)) do better but need
  each node to know its neighbors' neighbors, which is too much signaling
  for LoRa. Gossip-based flooding (Haas et al., 2002) is the probabilistic
  middle ground. UMSH's deferral rule is already a counter-based scheme;
  the "auto" mode below is a matter of choosing *k* and the delay class per
  node type.
- **Simulate with asymmetry or do not bother.** The MeshCore community's
  attempt to auto-tune repeater delays from local density
  ([discussion #2053](https://github.com/meshcore-dev/MeshCore/discussions/2053))
  produced a simulator recommendation of zero delays that raised the field
  error rate from 45.7% to 50.1%; the participants blamed a channel model
  without interference, asymmetry, or background traffic. The
  [Meshtastic adaptive relay study](https://github.com/StrazPrzyszlosci/MESHTASTIC_ADAPTIVE_RELAY)
  is the methodological counterexample: many seeds, many topologies, a
  frozen holdout set, confidence intervals, and a reference router kept
  unchanged for comparison.

## Design principles

Everything that follows applies these rules.

- **A route has a score and a confidence, not just a shape.** Scores come
  from measured per-hop signal quality in the direction of travel where it
  is known, and from a pessimistic prior where it is not. Confidence comes
  from evidence that the route has carried something in the direction it
  will be used.
- **Every received frame is evidence, including the ones the replay rules
  discard.** Duplicates, forwarded copies of our own transmissions, beacons
  of repeaters we will never talk to: all of it feeds the tables below.
- **The reverse direction is measured, never inferred.** A hop is confirmed
  bidirectional only when the node at the far end has demonstrably heard
  us: it forwarded our frame, acknowledged it, or told us so.
- **Candidates come from traces; confirmation comes from authenticated
  evidence.** Trace Route and Trace Signal are dynamic options: any
  forwarder can rewrite them. They are good enough to propose a route and
  never enough to trust one. An ack, a response, or a report inside the
  MIC is what promotes a candidate.
- **Fixed repeaters are the skeleton.** They do not move, they are always
  on, and they announce themselves. Routes should be built through them by
  preference; mobile repeaters and handhelds are last resorts.
- **Recovery is local before it is global.** The cheapest fix for a bad hop
  is one extra flood hop at the point that failed; the most expensive is a
  mesh-wide rediscovery. The slack a route carries is a function of how much
  is known about it.
- **Airtime is the budget.** Every mechanism states what it costs in
  transmissions per exchange, and the default is the cheapest one that
  addresses the failure.

## Proposed mechanisms

Numbered for reference. Sections marked *local policy* change no bytes on
the air and interoperate with unmodified nodes. Anything that touches the
wire is deferred to the protocol section that follows.

### M0. Keep an early overheard copy from poisoning the exchange *(local policy)*

A node handles a packet that matches its destination hint even while the
source route still names repeaters—deliberately, so two nodes that come
into range recover at once. Two consequences of that rule combine badly
when the origin explicitly routes through a repeater the destination can
also overhear directly:

- the overheard copy carries an *empty* trace, because no repeater has
  touched it yet, and route learning reads an empty trace as `Direct`;
- the overheard copy is accepted by replay detection but earns no ack
  (the route is unconsumed), and the routed copy that arrives a moment
  later—the first ack-eligible one—falls inside the duplicate hold-off and
  earns none either.

The destination ends up holding `Direct` and having sent nothing. The
origin's route retry then floods, the direct copy of the flood arrives
first, and the destination re-learns `Direct` and acks over the dead link.
Explicitly choosing the repeater does not help today; this has been
reproduced against the current MAC in a modeled three-node topology.

Two fixes, both in the MAC:

- A copy received with an unconsumed source route teaches nothing about
  the path. Its empty trace means "not yet forwarded," not "direct." Under
  M1 it may still register that the peer is audible, as an unconfirmed
  direct candidate with the measured SNR.
- The duplicate hold-off is keyed on whether an ack was *queued* for the
  accepted copy, not on whether the copy was accepted. The first
  ack-eligible copy of a frame is always acknowledged.

Cost: nothing on the air. These are correctness fixes, need no candidate
set, and belong in the simulator's first regression set.

### M1. Route candidates instead of a route *(local policy)*

Replace the single cached route per peer with a small candidate set—three
is enough—each entry holding:

- the path (direct, a source route of hints, or a flood distance);
- the last-hop RSSI and SNR measured locally when a frame arrived by it;
- the per-hop forward signal from the Trace Signal option, where the frame
  carried one;
- a score (M2) and a confidence (M4);
- counters: frames received by this path, sends attempted, sends confirmed
  (forwarding confirmation on the first hop), sends acknowledged
  end-to-end, consecutive failures;
- timestamps: first seen, last received, last confirmed;
- provenance: trace on a request, trace on an ack, beacon, advertisement,
  duplicate copy, computed from the repeater graph (M7).

Eviction prefers dropping the lowest-scored unconfirmed entry; a confirmed
entry is only displaced by a confirmed entry with a better score.

### M2. Score routes by signal, not by arrival order *(local policy)*

Each candidate gets an ETX-style score: the product over hops of an
estimated delivery probability, divided by a mild per-hop cost so that a
shorter path wins a tie.

- The per-hop delivery estimate is a logistic function of SNR margin above
  the demodulation floor for the configured spreading factor (−7.5 dB at
  SF7 through −20 dB at SF12), with an RSSI floor as a secondary guard.
  The exact curve is a tunable to be fitted in the simulator (S1) and on
  the bench, not a protocol constant.
- The last hop into this node is measured directly. Interior hops use the
  Trace Signal entries. A hop with no measurement gets the prior below.
- **Asymmetry prior.** A hop measured in one direction only is scored as if
  the unmeasured direction were several dB worse (a starting value of 6 dB,
  to be tuned). This is what makes a marginal direct copy lose to a clean
  repeater copy: the direct candidate's one measurement is near the floor
  and the prior pushes its reverse estimate below it.
- **Hint class.** A hop through a hint known (from a heard identity) to
  belong to a mobile repeater is discounted; a hop through an unknown hint
  is scored as fixed. Nothing on the wire says which is which, and that is
  acceptable: the discount is a preference, not a correctness rule, and it
  yields to evidence—a mobile repeater that keeps carrying a peer's
  traffic, two people traveling together, earns the discount back.

Selection for a send is by score among confirmed candidates first, then by
score among unconfirmed ones. A direct candidate whose last-hop SNR sits
below a configured comfort margin is never selected while any other
candidate exists.

Two guards keep selection from thrashing. Switching away from a route that
is currently working requires a meaningful score margin, not a marginal
one. And a small exploration budget—one send in N, bounded per peer and
per hour—goes to the second-best candidate, so that a mediocre route does
not become permanent merely because nothing else was ever tried.

### M3. Learn from duplicates *(local policy)*

Route learning runs on every copy of a frame that passes MIC verification,
not only the first. The forwarding-confirmation hold-off keeps its role in
deciding whether to re-acknowledge, but it no longer gates learning: a copy
rejected by replay detection, or falling inside the hold-off or the
duplicate-acknowledgment window, still updates the candidate set for its
source. This is the single change that addresses the observed failure most
directly: the repeater's clean copy of the origin's packet becomes a
candidate the moment it arrives, a few hundred milliseconds after the
marginal direct one.

M1 is a hard prerequisite. With one slot, learning from repeated copies is
the regression the hold-off was added to prevent.

Cost: nothing on the air; a MIC check per duplicate, which the receiver
already pays to recognize the duplicate.

### M4. Bidirectional confirmation from evidence we already have *(local policy)*

A candidate is *confirmed* once the node has evidence that the path works
in the direction it will be used. Three existing events supply it:

- **Forwarding confirmation of a source-routed send.** The named first hop
  repeated our frame: it heard us. This is the Babel "I Heard You" for hop
  one, obtained for free.
- **An acknowledgment or response to a frame sent via the candidate.** The
  path the frame was actually sent on carried it, so that candidate is
  confirmed in the outbound direction. The response's own arrival is
  evidence about the *inbound* direction of whatever path it took; a
  traced response reversed is a new outbound candidate, not a confirmation
  of one. An exchange sent via X and answered via Y confirms X outbound and
  Y inbound, and says nothing about Y outbound.
- **Our own frame heard forwarded with a Trace Signal entry.** When a
  repeater forwards our traced frame, the copy we overhear carries the
  signal the repeater measured. That is the forward-direction quality of
  hop one, the number ETX needs and the one no other mechanism can supply.
  The forwarding-confirmation listener already recognizes this frame; it
  should record the entry into the link table (M6) and score the first hop
  with it.

A direct candidate is confirmed only by an acknowledgment or response that
arrived direct. Hearing a peer well is not evidence that the peer hears
us.

### M5. Slack as a function of confidence *(local policy)*

The established-route extra flood hop currently sits at zero. Instead of a
constant, derive it:

| Route state | Extra flood hops |
|---|---:|
| Confirmed, no failures since confirmation, peer and self not known mobile | 0 |
| Unconfirmed (learned from a trace or a duplicate, never used) | 1 |
| Any failure since last confirmation | 1 |
| Last hop into the destination measured marginal (below comfort margin) | 1 |
| Peer advertises the mobile bit, or this node is not known stationary (M9) | 1 |
| Learned through a hint known to be a mobile repeater | 1 |
| Retry budget exhausted | full application budget, Route Retry (existing) |

The tail costs one forwarded transmission by the repeaters that hear the
last routed hop, suppressed by the ordinary contention rules to one or two
in practice.

Trimming is the careful half. A send that carried a tail and was
acknowledged proves that *something* delivered it, not that the narrower
route did: the ack may have come home only because the tail carried it.
Slack comes off after an exchange sent *without* it succeeds. Ordinary
traffic supplies those tests once confidence is high enough to try one
bare—every Nth send, or the next ping—and a failure of the test puts the
slack back at once. Add slack quickly, remove it slowly, with hysteresis,
so a route does not oscillate. Once P2 exists the report on the ack says
which path actually delivered the frame, and the test is no longer
needed.

The same table applies to acknowledgments. An ack for a frame received
direct at marginal SNR should go out with one flood hop and a trace: it
still reaches the origin direct if the link happens to work, and a nearby
repeater carries it if not. This is the change that makes the *first*
attempt of the observed exchange succeed rather than the second. Immediate
ack transmission is unaffected—the ack still leaves without CAD; it merely
carries a budget.

### M6. A link table: who we hear, and who hears us *(local policy)*

Two thirds of this table already exists. `TransmitterObservations` keys on
router hint with the RSSI/SNR heard here and a last-seen time;
`PeerRepeaterTable` holds the identity, mobile bit, and location of
repeaters heard directly. What is missing is reverse evidence, expiry, and
a consumer other than the Peer Repeaters responder. Grow them into one
table of directly heard nodes—every repeater and every peer whose frame
arrived without forwarding—kept separate from routes to peers:

- hint and, when known, full address, name, role, mobile bit, location;
- an EWMA of RSSI and SNR as heard here, and last-heard time;
- **reverse evidence**: the number of times this node has forwarded or
  acknowledged something we sent, against the number of opportunities it
  had (a frame we transmitted that it could have forwarded), and the SNR it
  reported hearing us at (from Trace Signal entries on our forwarded frames,
  per M4);
- a derived *neighbor class*: confirmed fixed repeater, confirmed mobile
  repeater, heard-only repeater, peer.

Repeaters flood-forward under contention, so an unforwarded opportunity is
weak negative evidence (someone else may have won the window); a named
source-route hop that fails to forward is strong negative evidence. Weight
them accordingly.

The best confirmed fixed repeater in the table is this node's **anchor**.
The anchor is not a route; it is the answer to "if I must hand this to a
repeater, which one is proven to hear me."

### M7. A repeater graph from beacons, and routes computed on it *(local policy)*

Fixed repeaters beacon hourly with a trace route and Trace Signal. A node
that listens learns, from each forwarded beacon, a chain of directed edges:
repeater *X* was heard by *R₁* at some SNR, *R₁* by *R₂*, and so on. The
signal entries are measured in the direction the beacon traveled, so the
graph is directed and asymmetric edges are visible as different weights in
the two directions—exactly the information a reversed trace lacks.

Today the broadcast path teaches the MAC nothing, and the observations
table keeps only the first hint of a trace. The graph builder is a new
consumer on the beacon path that walks the whole trace and its signal
entries. Store the result as a small directed graph of hints with per-edge
SNR and age. With it:

- **Every peer gets an anchor too.** The last hint in a trace a peer's
  frame arrived with is the repeater that first forwarded it—the peer's
  anchor at that moment. Record it with the peer.
- **Routes are computed, not only recorded.** A route to a peer is the
  best-scored path from our anchor to the peer's anchor over the graph,
  using edge weights in the direction of travel, followed by the peer's
  anchor's last hop. Computed routes enter the candidate set (M1) as
  unconfirmed, so they carry the one-hop tail (M5) until proven.
- **Interior asymmetry is avoided rather than discovered.** A hop that the
  graph shows working only one way is not chosen in the wrong direction.

The Peer Repeaters listing (MAC commands 10/11) supplies the same directed
edges—each entry is "the responder heard this neighbor at this
SNR"—for a repeater whose beacons have not been heard. Its use is
deliberately sparse: at most one page per repeater per day, and only when
the graph has a gap on the path to a peer the user is actually trying to
reach or when the user opens the topology view. It is never walked
proactively. Beacons are the ambient source; the listing is the repair
tool.

Two-byte hints make graph nodes ambiguous. Accept it: a collision produces
a route that fails and is replaced, which is the same failure mode the
existing source routes have.

### M8. Negative evidence at the destination *(local policy)*

A destination that receives the same acknowledged frame again has been told
something: its acknowledgment probably did not arrive. Today it
re-acknowledges the same way. Instead:

1. First duplicate inside the duplicate-acknowledgment window:
   re-acknowledge over the same route (an ack can be lost to a collision).
2. Second duplicate, or any copy carrying the Route Retry option: record a
   failure against the route the ack used, select the next candidate, and
   re-acknowledge with one flood hop and a trace regardless of the M5 table.
3. A copy that arrives by a different path than the one being acked is
   itself a fresh candidate (M3) and is the natural next choice.

This turns the origin's retry ladder—which already exists and already costs
airtime—into route repair at the far end.

### M9. Movement, and the expiry of routes *(local policy)*

Routes learned in one place are wrong in another. The device has three
signals of increasing cost:

- **Neighborhood fingerprint.** The set of repeaters heard in the last few
  beacon periods, with their SNR bands, is a radio position. Record the
  fingerprint a route was learned under; when the current fingerprint no
  longer overlaps it—the anchor has gone quiet, or new strong repeaters
  have appeared—demote every route learned there to unconfirmed. No sensors
  are involved, and this also catches the case where the node did not move
  but the mesh changed.
- **Known-stationary.** Accelerometer sampling at a low duty cycle reliably
  answers "has this device been still for the last *N* minutes." Known
  stationary suspends time-based decay and the M5 mobility slack. The
  absence of that answer—the device may be moving—does the opposite. This
  uses the cheap side of the sensor and never attempts to classify motion.
  `umsh-motion` already has an unused `Consumer::Location` slot for
  exactly this consumer; the nRF boards have no motion path yet and the
  phone has its own motion APIs.
- **Displacement.** Where GNSS is running anyway, a displacement of more
  than a configured fraction of a typical repeater cell since a route was
  learned demotes it outright.

The active repeater query (a role-filtered Identity Request, unflooded,
thirty seconds to complete) is the expensive refresh. Run it in the
background on a stationary transition after movement, and on the first
route failure after a fingerprint change—never on a schedule.

### M10. Contention by repeater class *(local policy, spec text)*

The flood contention window makes weak-but-clean receptions forward first.
Add a class offset so that, among repeaters with similar reception, fixed
infrastructure wins:

| Class | Offset added to the contention delay |
|---|---|
| Fixed repeater | 0 |
| Mobile repeater (mobile bit set) | + W_max / 2 |
| Auto-mode forwarder (M11) | + W_max |

Mobile repeaters and handhelds still forward when nobody else does—the
offset delays them, it does not exclude them—but the trace of a packet that
crossed a mixed neighborhood names the fixed repeater, and that is the hint
receivers will build routes through.

The forwarding-confirmation timeout is sized to the worst-case forwarding
delay. Class offsets extend that worst case; the timeout formula must
include the largest offset a sender can expect, or senders will retry into
a repeater that was about to forward. This is spec text in
`channel-access.md`, not a wire change.

### M11. Auto forwarding mode *(local policy, ULCP surface)*

Forwarding today is a boolean. Add a third setting, *auto*, meant for a
device someone carries: it forwards when a packet would otherwise go
uncarried and stays quiet when someone better has already carried it.

Density is the wrong input. A handheld that hears three fixed repeaters
may still be the only node that also hears the person behind the ridge,
and a table of heard repeaters cannot tell it so. What can tell it is the
packet itself: an auto forwarder that receives a flood with budget
remaining and hears no forward of it during a full contention window is,
for that packet, the coverage nobody else provided. Auto mode is therefore
a per-packet decision, not a state machine:

- always eligible, never first: the auto class carries the largest
  contention offset (M10), so every fixed and every explicit mobile
  repeater in range gets its turn before an auto forwarder's window opens;
- suppressed by **one** overheard copy, not deferred up to three times;
  hearing anyone carry the packet ends the auto forwarder's interest in it;
- ordered among its own kind by a per-packet priority drawn from a hash of
  the packet and the node's hint, so that in a cluster of auto-mode
  devices different devices win different packets and the battery cost is
  spread;
- prompt when named: a source route that names an auto forwarder is
  forwarded with zero delay like any routed hop;
- bounded by its own duty budget and a battery floor, below which the node
  stops carrying others' traffic whatever it hears;
- never inserting a region code.

The link table still matters, as a soft input: a confirmed fixed repeater
heard well lengthens the auto window further, and a neighborhood that just
changed (M9) shortens it, so a device that has just walked out of coverage
becomes willing sooner.

How it scales: five people camping with no infrastructure all forward,
and per packet the first to forward in each radio neighborhood suppresses
the rest, so each packet costs one or two forwards per neighborhood—what a
fixed deployment would have cost. Two hundred people at an event with
three fixed repeaters hear the repeaters carry every packet and forward
nothing, except the ones behind the ridge, who hear no such forward and
carry it. Two hundred people with no repeaters produce one or two forwards
per neighborhood per packet and no more, at the price of a slower flood
(the auto-class offset) and some hidden-terminal redundancy that is needed
for coverage anyway.

The repeater capability bit is set while auto is on: the node may forward,
and the mobile bit and the M2 discount tell receivers how much to build on
it. A future design could exchange compact, expiring relay-selection
information in the OLSR multipoint-relay style, maintained with
Trickle-style suppression ([RFC 6206](https://www.rfc-editor.org/rfc/rfc6206)),
but OLSR's symmetric-neighbor assumption would have to be replaced by the
directed evidence in M6 first. Not proposed now.

On the ULCP side `PROP_MAC_REPEATER_ENABLED` is a BOOL and the MAC's
`RepeaterConfig.enabled` is a bool, so this is either a new tri-state
property or a sibling *auto* flag that the enabled bit reports the live
result of. The advertised role stays under the operator's control as it is
now; the capability bit tracks the live state as the spec already
requires.

## What landed on 2026-10-09

A field report started this round: pings to some devices across the mesh
showed a working path, yet no route was learned, even after management
commands. Captures showed the M0 case exactly: an early copy of a reply,
overheard before its source route ran out, was accepted and taught
nothing, and the complete copy that followed was dropped as a replay. MAC
acks failed the same way. The fix grew into a reduced M1–M4 plus a
contention change, all in the MAC. Decisions, and where they depart from
the mechanisms above:

**M0, revised.** An early copy no longer teaches nothing. It teaches the
whole path the sender chose: the remaining source-route hints reversed,
then the trace. That is never the shortcut through the repeater that
happened to be overheard, since being audible says nothing about hearing
us. The complete copy that follows is weighed against it like any other.
This covers unicasts, blind unicasts, management replies, and MAC acks.

**M1, reduced.** No candidate set. Each peer keeps one route plus its score
and when an acknowledgment last vouched for it. Copies are weighed as they
arrive, so the comparison a set would make mostly happens anyway, and the
nRF RAM budget stays intact: the MAC grew by roughly 0.9 KB. A set becomes
worth having with M7, when routes can be computed rather than only
received.

**M2, revised.** Scoring is integer log-space, in centibels, the unit the
MAC measures SNR in:

- Each hop is charged by how far its SNR falls short of a comfort level of
  −5 dB: one-for-one up to a 4 dB knee, three-for-one past it. Charges add
  along the path, and the largest (least negative) total wins. Adding
  decibels multiplies in power, so the sum behaves like a product of
  delivery odds with no probability arithmetic. The steep segment stops one
  hop barely above its floor from tying with several that are only
  somewhat weak.
- No spreading-factor physics at endpoints. An endpoint cannot know the
  medium of a link it does not own, and a bridge hides even that, so the
  logistic curve proposed above is replaced by offset-then-clamp, which
  prefers stronger links without modeling them.
- Every hop costs 1 dB on top of its charge, bridged hops included. A
  zero Trace Signal entry is a bridged hop and is charged only that.
- A hop measured only toward us is charged as if 6 dB worse. An unmeasured
  air hop is charged the knee.
- A new route displaces the current one only with a 3 dB margin, plus a 6 dB
  credit for a route an acknowledgment vouched for in the last ten minutes.
  The credit replaces "confirmed ranks first" from M1: every established
  send carries a one-hop flood tail, so an ack does not prove that the
  narrower route delivered it.
- A flood distance never displaces a path. A route nothing scored, one
  installed by hand or restored from umshctl's cache, yields to any
  measured path. The exception is an ack's way back, which replaces only a
  direct route.

**M3, as planned, bounded.** A duplicate teaches when its MIC exactly
matches a copy accepted within twice the forwarding-confirmation timeout,
and at least 5 s. The last four completed acks are remembered by trailer,
so later copies of an ack still teach. Multicast duplicates do not teach
yet.

**M4/M6, first slice.** A 16-entry uplink table, with a 30-minute lifetime,
records forward-direction evidence from this node's own frames as
repeaters forward them. The last hint of the trace took the frame off our
transmission, and its Trace Signal entry is how well it heard us. On a
flood, every other hint forwarded a copy taken from another repeater, which
is weak evidence that it does not hear us. The first hop of a candidate path
is scored from this table: outbound when heard, with a 12 dB charge when
recently unheard, and inbound with the asymmetry charge otherwise.

**Trace Signal travels with every trace route** the MAC attaches, on
unicast, blind unicast, and MAC acks, so management traffic carries the
per-hop data scoring needs. Cost: one option-header byte plus two bytes per
hop.

**Contention, SF-relative.** The SNR band is now measured from the
demodulation floor of the spreading factor in use (floor + 6 dB to floor +
18 dB). A reception below the band waits out the whole window and a jitter
range before contending, breaking the tie at `W_max` between "barely
demodulated" and "right next to the sender." The radio runner publishes
the spreading factor it configured. A radio that reports none is graded
as SF10, which reproduces the old absolute band.

**Radio drivers, findings only.** On the SX126x and LR1110, lora-phy
reports `RssiPkt`, which is total in-band power, signal plus noise, and
discards `SignalRssiPkt`. Near the floor that overstates the signal by
`10·log10(1 + 10^(−SNR/10))` dB. Both the SX126x and SX127x paths round SNR
to whole dB, so the quarter-dB the chips measure never reaches UMSH. Fixing
both is a lora-rs change and comes before P1.

Still open: the simulator, and with it every constant above; M5's slack
table, M7, M8, M9, M10, and M11; multicast duplicates; and an interaction
between the 30 s `failed_route` hold-off and umshctl's harvest step, which
drops a peer whose MAC route is momentarily absent.

## Protocol changes

Everything above runs without changing a byte on the air. The following are
the additions that would make the mechanisms above complete, each stated
with what it costs and what breaks. P0 records spec changes that have
landed; the rest are proposals for the spec, not decisions.

### P0. Spec changes that landed with the scoring work

No wire format changed. Every change below is spec text.

- **Contention band** (`channel-access.md`): `SNR_low` and `SNR_high` are
  the spreading factor's demodulation floor plus 6 dB and 18 dB, replacing
  the absolute −9 dB and +3 dB. A reception below `SNR_low` waits
  `W = W_max + W_jitter` before its jitter draw. The floor is −7.5 dB at
  SF7 and 2.5 dB lower for each step up. Bandwidth moves sensitivity in
  dBm, not the SNR required.
- **Confirmation timeout** (`channel-access.md`, `repeater-operation.md`):
  `confirm_timeout = 2 × T_frame + W_max + 2 × W_jitter + D_ack`, which is
  2.95 × T_frame at the defaults, up from 2.85.
- **Zero Trace Signal entry** (`packet-options.md`): it now means a
  point-to-point hop only, such as a bridge. An air reading of 0 dBm or
  stronger is carried as RSSI 1, so no air hop ever writes the marker. A
  radio that reports no signal quality is no longer given a zero entry.
- **Trace Signal beside Trace Route** (`beacons.md`, Path Discovery): a
  packet that carries a trace route SHOULD also carry a trace signal.
- **Route Learning** (`beacons.md`): an early copy's way back is its
  remaining hints reversed, then its trace. Copies of one packet or one
  ack, arriving over different paths, MAY be weighed against each other
  and against the held route. A late copy is a replay, not a path.

### P1. Trace Signal SNR in quarter-dB, not centibels

The Trace Signal entry carries SNR as one signed byte of centibels, which
saturates at ±12.7 dB. LoRa demodulates down to −20 dB at SF12; the
Peer Repeaters entry already uses quarter-dB (±32 dB) for the same
quantity. Change the Trace Signal entry to match. This is a wire break for
the option's value. The option is non-critical, but since 2026-10-09 the MAC
attaches it to every traced send and scores routes from it, so it is now
load-bearing. Deferred: the radio drivers deliver whole-dB SNR today (see
[What landed](#what-landed-on-2026-10-09)), so finer units on the wire would
carry no extra information until lora-rs passes through what the chip
measures.

### P2. Received Route report on acknowledgments and responses

The trace on a response describes the path the response took. Nothing
tells the origin how its own frame arrived: which path delivered it, how
well each hop heard it, whether it was the routed copy or an overheard
early one. Only the destination knows, and it is the forward-direction
half of every measurement above.

Add a static, non-critical packet option that a responder MAY place on a
MAC ack or any response, carrying what it saw on the frame it answers: the
RSSI and SNR of its own reception (two bytes, in the Trace Signal
encoding), followed by the Trace Route hints and Trace Signal entries the
frame arrived with, and the number of source-route hints still unconsumed
at arrival. On a direct exchange it is the two signal bytes; on a traced
one, two bytes per hop more. A responder includes the full report when the
answered frame carried a trace, mirroring the rule that already governs
traces on acks, and the two signal bytes alone otherwise.

With it, one acknowledged exchange gives the origin both directions of
every hop: the report is the forward path and its per-hop quality, the
ack's own trace and measured SNR are the reverse. For a direct exchange it
is the *only* way the origin can learn that the destination hears it
marginally, which is what keeps a sender from trusting a direct route the
destination cannot use. It is also what lets M5 trim slack without a
probe: the report says whether the tail was needed.

A static option is MIC-protected, so the report is the destination's own
authenticated statement—unlike the trace it describes, which is dynamic,
unauthenticated, and forgeable in transit. That is the reason to carry a
copy inside the protected region rather than trust the mutable original:
candidates may come from traces, but confirmation must come from something
the peer signed. Repeaters do not touch it; old receivers ignore it. The
existing Signal Report MAC command becomes the standalone form of the
first two bytes.

### P3. Route Error notification *(deferred)*

A repeater that exhausts its retries on a named source-route hop knows the
route is broken there, and the origin does not learn it until its own
end-to-end ladder runs out. DSR's route error is the textbook fix. In UMSH
a repeater rarely shares a key with the origin, so the notice would have to
be unauthenticated, and an unauthenticated "your route is broken" is a
route-eviction attack. If this is ever added it should carry the failed
frame's ack MIC as correlation and be treated as a hint that raises the
route's failure count, never as authoritative. Not recommended until the
local mechanisms above have been evaluated; M5 and M8 cover most of the
benefit.

### P4. Wildcard first hop *(considered, not recommended)*

A reserved router hint meaning "any repeater that hears this" would let a
source route begin with a flood hop, expressing "someone near me, then
*R₂*, then *R₃*." It would serve a node that knows the far end of a path
but not who can hear it. The anchor (M6) answers the same question with a
proven repeater instead of a guess, and the hybrid route—source route to
the anchor, then flood—already exists. Not proposed.

### P5. Repeater class in the trace *(considered, not recommended)*

Marking a trace entry as mobile would let receivers discount mobile hops
without having heard the repeater's identity. Two-byte hints have no spare
bits and a third byte per hop is too expensive. The identity cache (M2's
hint class) plus the contention offset (M10), which keeps mobile hints out
of traces whenever a fixed repeater was present, is enough.

## The observed scenario, replayed

Origin *A*, far away. Destination *B*, a handheld. Fixed repeater *R* next
to *B*. *A* floods a ping with trace route and Trace Signal.

- *B* hears *A*'s own transmission at −8 dB SNR. M2 scores the direct
  candidate low: one measurement near the floor, asymmetry prior on top.
  M5 says a marginal direct link gets a flood hop, so *B*'s immediate ack
  leaves direct with one flood hop and a trace.
- A few hundred milliseconds later *R*'s copy arrives at +7 dB with trace
  `[R]` and a Trace Signal entry showing *R* heard *A* at +2 dB. M3 adds
  the candidate `[R]` with a much better score.
- *R* hears *B*'s ack (it is within range, that is the point) and forwards
  it, prepending its hint. *A* receives the ack via *R* with trace `[R]`,
  learns a confirmed route to *B*, and heard *R* forward its own ping with
  *R*'s signal entry, so its link table holds both directions of *A↔R*.
- *A*'s next message goes source-routed `[R]`. *B* receives it via *R*,
  which matches its best candidate; *B*'s ack goes back `[R]` with zero
  slack once confirmed. The exchange converged in one round trip with one
  extra forwarded ack.

Had *R* not been within range of *B*'s first ack—say the ack was
collided—*A*'s retry would arrive at *B* as a duplicate; M8 would switch
*B* to `[R]` and re-acknowledge with a trace, converging on the second
round trip. Neither case requires the origin to be attenuated.

And if *A* had been told to route via *R* by hand, M0 is what makes that
work: *B* no longer learns `Direct` from the overheard copy and no longer
withholds the ack from the routed one.

## Simulator

Every mechanism above has a tunable, and the MeshCore experience says that
tuning them by intuition and validating on a handful of walks will produce
confident wrong answers. A simulator is not a luxury here; it is how the
scoring curve, the asymmetry prior, the slack table, the contention offsets,
and the auto-mode thresholds get their values.

### S1. What it must model

- **The real MAC.** Instances of the actual `umsh-mac` coordinator, driven
  by a virtual clock, so that what is simulated is what ships and a change
  to forwarding policy is tested by running it, not by reimplementing it.
- **Asymmetric links by construction.** Per-node transmit power, antenna
  gain, and receiver noise floor; per-link shadowing drawn independently
  for each direction; log-distance path loss with terrain classes. This is
  the model the MeshCore study lacked and the reason its result inverted in
  the field.
- **LoRa reception.** SNR-to-PER curves per spreading factor and frame
  length; the capture effect (a stronger co-SF frame arriving within the
  preamble survives, roughly 6 dB); CAD as a probabilistic detector with
  false negatives at low SNR; half-duplex radios that miss what arrives
  while they transmit.
- **Background traffic**, MeshCore and other UMSH traffic alike, as a
  configurable load that occupies the channel without being routable.
- **Mobility traces**: stationary, walking, driving; a node that moves
  between neighborhoods mid-exchange.
- **Determinism.** Seeded, so a failing scenario replays exactly; the MAC's
  cryptographic RNG is seeded per node from the scenario seed. This is a
  host tool and the no-non-crypto-RNG rule does not reach it.

### S2. Scenario library

- The observed case: far origin, handheld destination, repeater beside it,
  first hop asymmetric.
- The user's actual deployment, from the repeaters' advertised locations
  and a path-loss class per link, so that field observations have a
  simulated twin.
- Linear chain, star, bridge between two clusters, dense urban grid.
- Camping: five handhelds, no infrastructure, auto mode.
- Event: two hundred handhelds with and without three fixed repeaters.
- Mobile repeater passing through a fixed deployment.
- The M0 regression set: an early overheard copy of a routed frame; an
  ack returning by a different path than the data; a broken first,
  interior, and last hop each in turn; a mobile handoff mid-exchange.

### S3. Metrics and method

Delivery ratio as the application sees it and as the sender confirms it,
transmissions and airtime per confirmed delivery, time to first delivery
and to recovery after a break, round trips to route convergence,
chosen-route ETX against the best available, forwards per packet per
neighborhood, and discovery overhead. Report tail latency and the
worst-served nodes beside the averages, and attribute every loss to a
cause: radio, collision, policy rejection, duplicate suppression, or a
reply that never made it home. Compare policies under identical airtime
budgets, so that none wins merely by transmitting more. Every comparison is
against the unchanged current policy as reference, over many seeds and all
topologies, with confidence intervals and a frozen holdout set of seeds
that tuning never sees. A field capture from `umshctl` should be
replayable into the simulator to calibrate the channel model against
reality.

### S4. Where it lives

A host-only tool under `tools/`, built on the modeled network that already
exists in the MAC's test support, with the channel model, a discrete-event
driver, and a per-node seeded platform as the new parts.

**What exists.** `umsh_mac::test_support::ModeledNetwork`
(`crates/umsh-mac/src/test_support.rs`) is most of S1 already: a seedable
virtual-time medium with per-link connectivity, base RSSI/SNR with jitter,
propagation delay, Bernoulli loss, CAD that reports busy while a connected
neighbor is in flight, and a crude collision rule (any overlap at a
receiver drops both frames). Real `Mac` coordinators run on it—ten in the
largest existing test—stepped by `pump_modeled_until`, and
`Mac::earliest_deadline_ms()` is public, so a discrete-event driver can
jump the clock to the next deadline instead of stepping.
`umsh_radio_loraphy::airtime_ms` is a pure time-on-air formula.

**What it lacks**, in the order it matters here: geometry and path loss
(links are hand-configured, so asymmetry has to be typed in per link); an
SNR decode threshold and PER curve (signal values are reported, never used
to drop); receiver deafness while transmitting; capture; frame-length
airtime (a flat T_frame per radio); and a `transmit` that returns at the
start of the transmission rather than its end, which starts ack timers
early.

**What blocks determinism.** `DummyRng` fills bytes with a counter from
zero, so every node draws the same jitter and backoff—fatal for a
contention study. `TokioPlatform` and `MobilePlatform` hardcode
`ThreadRng` and a real clock. The simulator needs its own `Platform` with a
per-node ChaCha `StdRng` seeded from the scenario seed; rand's `std_rng`
feature is not enabled in the umbrella today.

**What is structural.** `umsh-ulcp-runtime`, where beacon and
advertisement scheduling live, has process-global statics and uses
embassy's global time driver, so one process can hold one firmware node
runtime. Beacons and advertisement policy are therefore either re-hosted
into a per-instance node layer or reimplemented by the simulator harness.
The MAC and `umsh-node` are `Rc`-based, static-free, and instantiate
freely.

The other multi-node pieces—`SimulatedNetwork` (perfect delivery, no
time), the bridge's soft hosts (real time, one shared broadcast domain
with no measurements), the UDP multicast radio, and the iOS staging
star—are not starting points for a channel model.

## Sequencing

Ordered by value per unit of work, and by what unblocks what. Items 1 and 2
have landed, item 2 in the reduced form described in
[What landed](#what-landed-on-2026-10-09), together with the first slice of
item 4 and SF-relative contention.

1. **M0 + the M5 ack rule**—the two small MAC repairs: a copy with an
   unconsumed route teaches nothing, the first ack-eligible copy is always
   acknowledged, and an unproven direct reply carries one flood hop and a
   trace. No wire change, no candidate set needed, endpoints only. This is
   the field fix, and it can be validated on the existing deployment
   without reflashing repeaters.
2. **M1 + M2 + M3**—candidate set, signal-scored selection with the
   asymmetry prior, learning from duplicates. No wire change.
3. **M5 + M8**—the full slack table with test-before-trim, and
   destination-side negative evidence.
4. **M4 + M6**—directional confirmation and the link table; the anchor
   falls out of it.
5. **S1–S4**—the simulator, started alongside 2–4 with the M0 scenarios as
   its first regression set, and used to tune 2–4 before their defaults
   are frozen.
6. **P1 + P2**—Trace Signal units and the Received Route report. Small,
   coordinated spec and implementation change; reflash repeaters for P1.
7. **M7**—the repeater graph and computed routes, once beacons with
   Trace Signal (P1) are on the air.
8. **M10 + M9**—class offsets and movement-aware expiry, evaluated in the
   simulator first because the offsets move confirmation deadlines.
9. **M11**—auto mode, last, evaluated in the simulator before it is
   enabled anywhere.

## Open questions

- The comfort margin (M2, M5) and the asymmetry prior are the two numbers
  that decide when a direct link is trusted. They need the simulator, but
  a first bench value—say 5 dB above the floor for the margin—should be
  picked now so that item 1 above can ship.
- Whether the phone or the device owns the candidate set. Today route
  learning is in the MAC, which runs on both; the link table and repeater
  graph are naturally host-side on a phone-tethered device and device-side
  on a standalone tracker. The split should follow where the MAC already
  learns routes.
- How much of the link table to persist across reboots. Routes are cheap
  to relearn; the repeater graph is not.
- Whether the device-delegated ack path keeps its own route logic or is
  folded into the MAC's. M5 and M8 change how acks are addressed, and two
  implementations of that will drift.
- Whether auto mode should also consider *time since the last forward it
  was needed for*, so a dormant device with dead infrastructure notices.
