# ULCP: Tethered Host Services

A device is most useful to a phone when it can keep working while the
phone is asleep or out of range. The services in this chapter are what
that means concretely: the device learns which traffic is relevant to its
host, holds that traffic while the host is away, and — for peers the host
has explicitly provisioned — acknowledges it so that senders' retransmission
logic is satisfied.

Everything here is **assistance**, tightly scoped. The host still owns the
UMSH MAC and its own private keys; the device is helping its host, not
impersonating it in the general case.

## The Tethered Host Identity {#host-identity}

The **tethered host identity** is the single UMSH identity owned by the
attached host. Of the identity keypair itself, the device holds only the
32-byte public key; the host's private key **MUST NOT** be transferred to
the device, and this protocol provides no mechanism for doing so (see
[Security Boundary](ulcp.md#security-boundary)). The device may
additionally hold host-domain state derived or delegated by the host —
channel keys, per-peer symmetric keys, filters, and queued traffic — as
defined in this chapter.

Because the device never holds the host's private key, it cannot perform
ECDH on the host's behalf. All pairwise key material the device uses for
the host identity is derived by the host and explicitly provisioned per
peer (see [`PROP_HOST_PEER_KEYS`](ulcp-host.md#prop-host-peer-keys)).

ULCP supports exactly one tethered host identity at a time. Everything
provisioned for it forms the [host domain](ulcp-core.md#host-domain),
which is volatile across a power cycle and wiped wholesale when a
different host identity takes over the device.

### Host Replacement {#host-replacement}

The host domain is keyed by `PROP_HOST_KEY`. Setting `PROP_HOST_KEY` to a
value **different** from its current value — including setting it to empty
— **MUST** atomically reset the entire host domain to defaults: the key
tables and filter table are cleared, `PROP_HOST_AUTO_ACK` reverts to
false, and the inbound queue is discarded. Because the host domain is
never persisted, this is a live-state operation with no durable component:
a power cycle cannot resurrect a previous host's provisioning regardless.

Setting `PROP_HOST_KEY` to its current value is idempotent and has no side
effects.

This rule is what makes re-pairing safe: when a companion radio is paired
with a different phone, the new host configures its own identity and the
previous host's keys, filters, and queued traffic cease to exist — while
the device domain (the radio's own identity, channels, and settings) is
untouched.

## Capabilities

Code | Name                | Requires                             | Grants
-----|---------------------|--------------------------------------|--------
32   | `CAP_HOST_FILTER`   | —                                    | `PROP_HOST_KEY`, `PROP_MAC_PROMISCUOUS`, `PROP_HOST_RX_FILTERS`, and the receive-filtering behavior
33   | `CAP_HOST_RX_QUEUE` | `CAP_HOST_FILTER`                    | The inbound queue, its properties, `CMD_QUEUE_DRAIN`, and the buffered-frame metadata
34   | `CAP_HOST_KEYS`     | `CAP_HOST_FILTER`                    | `PROP_HOST_CHANNEL_KEYS` and `PROP_HOST_PEER_KEYS`
35   | `CAP_HOST_AUTO_ACK` | `CAP_HOST_KEYS`, `CAP_HOST_RX_QUEUE` | `PROP_HOST_AUTO_ACK` and acknowledgement delegation

A device advertising none of these is a transparent radio: it delivers
every frame it receives and holds nothing on anyone's behalf.

## Commands

Id | Mnemonic          | Dir          | Description
---|-------------------|--------------|-------------
11 | `CMD_QUEUE_DRAIN` | Host->Device | Deliver queued inbound frames

### CMD 11: (Host -> Device) `CMD_QUEUE_DRAIN` {#cmd-queue-drain}

~~~
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|1 0| RES | TID |CMD_QUEUE_DRAIN|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
~~~
Figure: Structure of `CMD_QUEUE_DRAIN`

Deliver queued inbound frames. Commands the device to deliver every frame
currently held in the inbound queue (see [Inbound Queueing](ulcp-host.md#inbound-queueing)), oldest
first, as ordinary `CMD_STR_RECV` commands on `STR_PHY_RAW` carrying the
buffered-frame metadata described in [Buffered-Frame Metadata](ulcp-transport.md#buffered-metadata). The command
payload SHOULD be empty and MUST be ignored.

Queued frames are **only** delivered in response to this command; attaching
to the device does not by itself cause queued frames to be delivered (see
[Inbound Queueing](ulcp-host.md#inbound-queueing)). This lets the host finish synchronizing its session
and signal that it is actually ready to process backlogged traffic.

The drain covers exactly the frames held in the queue when the command is
received. Because accepted frames are always delivered live while a host
is attached, the queue cannot grow while a drain is in progress: the drain
always covers a fixed set of frames and always terminates. If the command
was sent with a non-zero TID, the device reports completion by emitting
`CMD_PROP_IS` for `PROP_LAST_STATUS` with `STATUS_OK` and the matching TID
immediately after delivering the last covered frame. Draining an empty
queue succeeds immediately.

Frames that arrive while a drain is in progress are not part of it: they
are delivered live, and MAY therefore interleave with the buffered
deliveries. `RX_FLAG_BUFFERED` distinguishes the two, and UMSH does not
guarantee in-order delivery in any case (see [Inbound Queueing](ulcp-host.md#inbound-queueing)).

If the device does not implement queueing (`CAP_HOST_RX_QUEUE` not
advertised), the command fails with `STATUS_UNIMPLEMENTED`.

If an error occurs, the value of the emitted `PROP_LAST_STATUS` will be set
accordingly to the status code for the error.

## Properties

The host domain occupies property identifiers 96–111.
`PROP_MAC_PROMISCUOUS` is the exception: it is a live diagnostic mode
rather than provisioning, and is the protocol's only session-scoped
property.

Id  | Mnemonic                      | Commands                 | Description
----|-------------------------------|--------------------------|-------------
48  | `PROP_MAC_PROMISCUOUS`        | Get, Set                 | Deliver all frames (session-scoped)
96  | `PROP_HOST_KEY`               | Get, Set                 | Tethered host identity public key
97  | `PROP_HOST_CHANNEL_KEYS`      | Get, Set, Insert, Remove | Host channel keys
98  | `PROP_HOST_PEER_KEYS`         | Get, Set, Insert, Remove | Host pairwise peer keys
99  | `PROP_HOST_RX_FILTERS`        | Get, Set, Insert, Remove | Host receive filter table
100 | `PROP_HOST_AUTO_ACK`          | Get, Set                 | Acknowledgement delegation enable
101 | `PROP_HOST_RX_QUEUE_COUNT`    | Get                      | Frames currently queued
102 | `PROP_HOST_RX_QUEUE_CAPACITY` | Get, Set                 | Queue capacity in frames
103 | `PROP_HOST_RX_QUEUE_DROPPED`  | Get                      | Frames dropped from the queue

### PROP 48: `PROP_MAC_PROMISCUOUS` {#prop-mac-promiscuous}

* Type: Single-Value, Read-Write, Session-Scoped
* Asynchronous Updates: No
* Required: `CAP_HOST_FILTER`
* Value Type: BOOL
* Post-Attach Value: 0 (false)

When true, every frame the PHY successfully receives is delivered to the
host over `STR_PHY_RAW`, bypassing receive filtering. This is a live-session
diagnostic mode: frames that are delivered *only* because of promiscuous
mode are never queued while the host is detached, and never acknowledged on
the host's behalf.

This is the only session-scoped property: it reverts to false on every
attach.

### PROP 96: `PROP_HOST_KEY` {#prop-host-key}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_HOST_FILTER`
* Value Type: 32 octets, or empty
* Post-Reset Value: Empty

The Ed25519 public key of the **tethered host identity**. Setting this
property tells the device which node identity it is assisting; an empty value
means no host identity is configured.

Setting this property to a value different from its current value resets
the entire host domain, as specified in [Host Replacement](ulcp-host.md#host-replacement). Setting it to
its current value is idempotent.

Like the rest of the host domain, this property is never saved: it is
empty at every power-on, whatever the radio was doing before.

A configured host key acts as an implicit destination-hint receive filter
(see [Receive Filtering](ulcp-host.md#receive-filtering)).

### PROP 97: `PROP_HOST_CHANNEL_KEYS` {#prop-host-channel-keys}

* Type: Multiple-Value, Read-Write
* Has Item Length Prefix: No
* Asynchronous Updates: No
* Required: `CAP_HOST_KEYS`
* Item Form: 32 octets (the channel key)
* Digest Form: 2 octets (the derived channel identifier)
* Remove Selector: the 32-octet channel key
* Post-Reset Value: Empty

The set of [channel keys](multicast-channels.md#channel-keys) provisioned
for the **host identity**. For each key the device derives the channel
identifier and the channel `K_enc`/`K_mic`; the digest form is the derived
channel identifier, and the key itself is never read back.

Each derived channel identifier acts as an implicit channel receive filter
(see [Receive Filtering](ulcp-host.md#receive-filtering)). Host channel keys serve two assistance
purposes:

* recognizing multicast traffic on the host's channels while the host is
  detached, so it can be queued; and
* recognizing **blind unicast** traffic addressed to the host identity,
  which requires the channel key to decrypt the concealed
  destination/source addresses (see
  [Blind Unicast Processing](packet-types.md#blind-unicast-processing)) and
  to form the combined
  [blind unicast payload keys](security.md#blind-unicast-payload-keys) used
  for authentication and acknowledgement.

Channel keys are group-membership credentials, not host private keys, so
provisioning them is consistent with the
[security boundary](ulcp.md#security-boundary). They still grant
whoever holds the device the ability to read and send traffic on those
channels; see [Provisioning Security](ulcp-core.md#provisioning-security).

### PROP 98: `PROP_HOST_PEER_KEYS` {#prop-host-peer-keys}

* Type: Multiple-Value, Read-Write
* Has Item Length Prefix: No
* Asynchronous Updates: No
* Required: `CAP_HOST_KEYS`
* Item Form: Structure, 96 octets
* Digest Form: 32 octets (the peer's public key)
* Remove Selector: the 32-octet peer public key
* Post-Reset Value: Empty

Pairwise symmetric key material provisioned for specific already-known
peers of the host identity. The item form is:

~~~
+---------------------+-----------+-----------+
| PEER_PUBLIC_KEY     |   K_ENC   |   K_MIC   |
+---------------------+-----------+-----------+
        32 B              32 B        32 B
~~~
Figure: Peer key entry item form

Where `PEER_PUBLIC_KEY` is the peer's Ed25519 public key and `K_ENC` and
`K_MIC` are the stable pairwise keys for the (host, peer) pair, derived by
the **host** as described in
[HKDF Inputs for Unicast](security.md#hkdf-inputs-for-unicast). The device
never derives these itself — it cannot, because it does not hold the host's
private key.

As an exception to the usual `CMD_PROP_INSERT` duplicate rule, inserting an
entry whose `PEER_PUBLIC_KEY` matches an existing entry replaces that
entry. Replacement updates only the stored key material: the peer's replay
baseline (see [Acknowledgement Delegation](ulcp-host.md#ack-delegation)) and any frames already queued from that
peer are unaffected, since both are keyed by the peer's identity rather
than by the key values. The digest form is the peer public key alone:
`K_ENC` and `K_MIC` are never read back.

Provisioned peer keys let the device authenticate inbound unicast and blind
unicast from those specific peers and acknowledge it on the host's behalf
(see [Acknowledgement Delegation](ulcp-host.md#ack-delegation)). They grant no capability regarding any other peer,
and do not allow the device to establish new pairwise relationships.

### PROP 99: `PROP_HOST_RX_FILTERS` {#prop-host-rx-filters}

* Type: Multiple-Value, Read-Write
* Has Item Length Prefix: Yes
* Asynchronous Updates: No
* Required: `CAP_HOST_FILTER`
* Item Form: Structure
* Remove Selector: the full item
* Post-Reset Value: Empty

The explicit receive filter table. Each item is a filter entry:

~~~
+-------------+----------------------+
| FILTER_TYPE | FILTER_VALUE ...
+-------------+----------------------+
     1 B          type-specific
~~~
Figure: Filter entry format

Type | Name                 | Value       | Matches
-----|----------------------|-------------|---------
0    | `FILTER_DEST_HINT`   | 3 octets    | Frames whose destination hint field equals the value
1    | `FILTER_CHANNEL_ID`  | 2 octets    | Channel-addressed frames (`MCST`, `BUNI`, `BUAR`) whose channel identifier equals the value
2    | `FILTER_PKT_TYPE`    | 1 octet     | Frames whose FCF packet-type field equals the value (0–7)

Entries with an unrecognized `FILTER_TYPE`, or whose value length does not
match the type, fail with `STATUS_INVALID_ARGUMENT`.

See [Receive Filtering](ulcp-host.md#receive-filtering) for how this table combines with the implicit
filters derived from `PROP_HOST_KEY` and `PROP_HOST_CHANNEL_KEYS`.

### PROP 100: `PROP_HOST_AUTO_ACK` {#prop-host-auto-ack}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_HOST_AUTO_ACK`
* Value Type: BOOL
* Post-Reset Value: 0 (false)

When true, the device sends MAC acknowledgements on behalf of the host
identity for qualifying frames received while the host is detached, as
specified in [Acknowledgement Delegation](ulcp-host.md#ack-delegation). When false, the device never transmits on the
host identity's behalf.

### PROP 101: `PROP_HOST_RX_QUEUE_COUNT` {#prop-host-rx-queue-count}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_HOST_RX_QUEUE`
* Value Type: UINT16_LE
* Units: frames
* Post-Reset Value: 0

The number of frames currently held in the inbound queue. The host
typically reads this right after attaching to decide whether (and when) to
issue `CMD_QUEUE_DRAIN`.

### PROP 102: `PROP_HOST_RX_QUEUE_CAPACITY` {#prop-host-rx-queue-capacity}

* Type: Single-Value, Read-Write
* Asynchronous Updates: No
* Required: `CAP_HOST_RX_QUEUE` (`CMD_PROP_SET` support is **OPTIONAL**)
* Value Type: UINT16_LE
* Units: frames
* Post-Reset Value: Implementation-Specific

The maximum number of frames the inbound queue can hold. Devices with a fixed
queue size fail `CMD_PROP_SET` with `STATUS_UNIMPLEMENTED`; devices that allow
adjustment fail values they cannot honor with `STATUS_INVALID_ARGUMENT`.

### PROP 103: `PROP_HOST_RX_QUEUE_DROPPED` {#prop-host-rx-queue-dropped}

* Type: Single-Value, Read-Only
* Asynchronous Updates: No
* Required: `CAP_HOST_RX_QUEUE`
* Value Type: UINT32_LE
* Units: frames
* Post-Reset Value: 0

The cumulative number of frames discarded from the inbound queue — evicted
by the circular queue-full policy or otherwise not retained (see
[Inbound Queueing](ulcp-host.md#inbound-queueing)) — since the device last reset. A non-zero increase
across a detached interval tells the host that its view of that interval
is incomplete. The counter wraps modulo 2^32.

## Receive Filtering {#receive-filtering}

Receive filtering determines which successfully received frames are
**accepted** for the host — delivered live when the host is attached, or
queued when it is not.

The device evaluates each received frame against the union of:

* the **explicit filters** in `PROP_HOST_RX_FILTERS`;
* an **implicit destination-hint filter** for the first 3 bytes of
  `PROP_HOST_KEY`, when a host key is configured; and
* an **implicit channel filter** for the derived channel identifier of each
  key in `PROP_HOST_CHANNEL_KEYS`.

A frame matching any filter is accepted. Hints and channel identifiers are
prefilters, not proof (see [Addressing](addressing.md)); filtering by them
can only over-accept, never mis-reject, and the host performs full
cryptographic verification as usual.

The implicit destination-hint filter matches unicast traffic addressed to
the host identity. Encrypted blind unicast addressed to the host is
matched through its channel filter (its destination hint is concealed on
the wire); the device MAY additionally use a provisioned channel key to
decrypt the address block and narrow the match.

Two kinds of returning traffic identify themselves only by the MIC of a frame
the host previously sent, so no destination or channel filter can address
them: a [MAC Ack](packet-types.md#mac-ack-packet) carries no destination hint
and its public `ack_mic` is the first 4 bytes of the acknowledged frame's
MIC, and a repeater's onward copy of a host frame keeps the host's MIC while
its destination hint names the remote peer. The device therefore records the
leading 4 MIC bytes of each frame it transmits on the host's behalf and
implicitly accepts any received frame whose trailer opens with a recorded
value — for a MAC Ack this matches the returning acknowledgement, and for
other packet types it matches the host's own send being carried onward, which
the host's forwarding-confirmation machinery must overhear to stop
retransmitting. These records evict lazily, so multiple echoes of one send —
acks arriving over different return routes, repeats from different
repeaters — are all delivered. A MAC Ack whose `ack_mic` matches no recorded
frame is still accepted if an explicit `FILTER_PKT_TYPE` entry selects it.

Broadcast packets — payload-carrying broadcasts and beacons alike — are
implicitly accepted **for live delivery**: a broadcast is addressed to
every node, the host included. The rule is live-only. While the host is
detached, a broadcast is queued only when an explicit filter selects it
(e.g., a `FILTER_PKT_TYPE` entry with value 0), so ambient broadcast
traffic cannot displace queued unicast frames.

Device-domain state never creates implicit host filters: frames for the
device identity or its channels reach the host only if the host's own
filtering matches them.

**Compatibility rule:** when no host key is configured, no host channel
keys are provisioned, and the explicit filter table is empty, filtering is
considered unconfigured and **every** successfully received frame is
accepted. This is exactly how a device with no host services at all
behaves, so a host using the radio as a plain frame pipe observes no
difference on a filtering device in its factory state. As soon as any
filter (implicit or explicit) exists, only matching frames are accepted.

Promiscuous mode (see [`PROP_MAC_PROMISCUOUS`](ulcp-host.md#prop-mac-promiscuous)) bypasses filtering for live
delivery only.

## Inbound Queueing {#inbound-queueing}

When `CAP_HOST_RX_QUEUE` is supported and the host is **detached**,
accepted frames are placed in a FIFO inbound queue instead of being
discarded. Each queue entry records the frame, its receive metadata (RSSI,
LQI, SNR), the time of reception, and whether the device acknowledged it (see
[Acknowledgement Delegation](ulcp-host.md#ack-delegation)).

When the host is **attached**, accepted frames are delivered live over
`STR_PHY_RAW` as they always are. Attaching does not flush
the queue: frames queued while the host was away remain queued until the
host issues [`CMD_QUEUE_DRAIN`](ulcp-host.md#cmd-queue-drain). Frames received
after attach are therefore delivered live even while older frames remain
queued, and live deliveries MAY interleave with buffered deliveries during
a drain (`RX_FLAG_BUFFERED` distinguishes them). A host that wants to
process the backlog first drains promptly after attaching and MAY defer
its processing of interleaved live deliveries; `RX_AGE` in the
buffered-frame metadata gives coarse (one-second) relative timing but is
not sufficient to reconstruct a strict total order — and UMSH itself does
not guarantee in-order delivery in any case.

The queue is **circular**: when a new frame is accepted and the queue is
full, the oldest queued frame is discarded and the new frame is appended.
The queue therefore always holds the most recent accepted traffic. Every
frame discarded by this eviction increments
`PROP_HOST_RX_QUEUE_DROPPED`.

Eviction can discard a frame that was already acknowledged on the host's
behalf — the sender believes it delivered, but the host will never
receive it. This is the same best-effort custody semantic that applies to
power loss (see [Acknowledgement Delegation](ulcp-host.md#ack-delegation) and [Saved State](ulcp-saved-state.md#saved-state)): a delegated ack
asserts volatile custody, not guaranteed delivery.

Duplicate detection for queueing uses the standard final-destination
mechanisms of [replay detection](security.md#replay-detection): per-peer
frame-counter state and the recent accepted-MIC cache used for the
backward window, where the device holds the keys to apply them. A frame
identified as a previously accepted frame **MUST NOT** consume an
additional queue slot; it is coalesced with the existing entry. A
[Route Retry](packet-options.md#route-retry-option-6) form of a queued
frame is the same logical packet (same MIC and frame counter) and
coalesces with it. Coalescing a duplicate is separate from acknowledging
it — a coalesced duplicate may still have its ack retransmitted under the
duplicate-acknowledgement window (see [Acknowledgement Delegation](ulcp-host.md#ack-delegation)). For frames the
device cannot authenticate (no provisioned keys), no protocol-defined
duplicate detection applies and each received frame occupies its own
entry.

## Acknowledgement Delegation {#ack-delegation}

With `PROP_HOST_AUTO_ACK` enabled, the device acknowledges qualifying inbound
frames so that senders' retransmission logic is satisfied while the host is
away. The device **MUST** transmit a MAC ack for a received frame if and only
if all of the following hold:

1. `PROP_HOST_AUTO_ACK` is true and no host is attached.
2. The frame's packet type requests acknowledgement: `UNAR`, or `BUAR`
   where the device also holds the frame's channel key.
3. The frame is addressed to the host identity: its (possibly decrypted)
   destination hint matches `PROP_HOST_KEY`, and its source resolves to
   an entry in `PROP_HOST_PEER_KEYS` — by full public key when the `S`
   flag is set, or by unique 3-byte prefix match otherwise.
4. The frame authenticates: its MIC verifies under the pairwise `K_MIC`
   for `UNAR`, or under the combined
   [blind unicast payload keys](security.md#blind-unicast-payload-keys)
   for `BUAR`.
5. The frame is accepted as new by the
   [replay-detection rules](security.md#replay-detection), applied per
   provisioned peer. The device advances a peer's replay baseline only when
   it accepts a frame from that peer into the queue; a frame it fails to
   store leaves the baseline unchanged, so its retransmissions remain
   acceptable later.
6. The frame was placed in the inbound queue (see [Inbound Queueing](ulcp-host.md#inbound-queueing)).
   Because the queue is circular, placement normally succeeds by evicting
   the oldest entry when full; a frame that nevertheless cannot be stored
   (for example, one exceeding the device's buffer) is not acknowledged, so
   the sender keeps retrying until the host returns.

**Duplicates.** An authenticated frame that replay detection identifies as
a previously accepted frame — typically a retransmission whose original
ack was lost — is not queued again, but the device **MAY** retransmit its
acknowledgement under the core
[duplicate-acknowledgement window](security.md#duplicate-acknowledgement-window):
only when the frame authenticates and its counter is no more than 8 behind
the peer's baseline, and without advancing or otherwise modifying the
replay baseline. Re-acknowledging a duplicate is independent of queue
coalescing (see [Inbound Queueing](ulcp-host.md#inbound-queueing)) and does not mark anything newly
accepted. Frames farther behind the baseline **MUST NOT** be acknowledged.

**Reboot.** Per-peer replay baselines are not saved (see [Saved State](ulcp-saved-state.md#saved-state)).
After a device reset, the first authenticated frame accepted from a
provisioned peer re-establishes that peer's baseline at face value,
exactly as on first contact (see
[Counter Resynchronization](security.md#counter-resynchronization)). The
consequence is that after a reboot, previously captured authenticated
frames may be accepted, queued, and acknowledged if replayed in a counter
sequence acceptable from the newly established baseline. The host MAC
remains authoritative for duplicate suppression when the frames are
eventually delivered, so this creates a limited availability and
resource-consumption window (queue slots and delegated acks), but it does
not permit forgery or duplicate application delivery. Implementations
concerned about this threat **MAY** persist a compact per-peer counter
watermark (batched or range-reserved to limit flash wear), but hosts
**MUST NOT** assume they do.

**Custody.** A delegated ack acknowledges *volatile* custody by default:
the frame is held in RAM until drained, and the loss window on power
failure is documented in [Saved State](ulcp-saved-state.md#saved-state). Implementations that persist the
queue provide durable custody, but hosts and application protocols
**MUST NOT** rely on it.

The acknowledgement is an ordinary
[MAC Ack packet](packet-types.md#mac-ack-packet): the `ack MIC` is the
first 4 bytes of the acknowledged frame's MIC and the 4-byte `ack tag` is
computed as specified in
[Ack Tag Construction](security.md#ack-tag-construction), using the
provisioned pairwise keys (combined with the channel keys for `BUAR`). The
ack carries no destination hint. If the original frame carried a flood hop
count, the ack's `FHOPS_REM` is initialized from the original frame's
`FHOPS_ACC`.

Delegated ack transmissions use the device's normal transmit path and are
subject to the configured duty-cycle limit; the device **MUST NOT** exceed the
limit to send an ack. An ack that cannot be sent leaves the queued frame
marked unacknowledged.

Frames that are accepted but fail any of conditions 2–5 — no peer key, no
channel key, authentication impossible to evaluate — are still queued
(subject to filtering); they are simply not acknowledged. The host
performs its own verification after draining and may ack late if the
application finds that useful.

While a host is attached, the device never acks on its behalf: live-delivered
frames are the host's responsibility. Acks generated by the **device
identity** for its own traffic are ordinary device-node behavior and are
not governed by this section.
