# MeshCore v1 Forwarding—Research and Implementation Plan

Add an optional, autonomous MeshCore v1 forwarder to the ordinary UMSH
firmware. It shares the radio, device identity, forwarding master switch,
regional policy, channel-access machinery, and duty ceiling with the UMSH
node. It implements MeshCore's forwarding decisions and wire mutations
independently and exposes its own ULCP enable.

This document is a plan, not a protocol specification. None of the proposed
ULCP identifiers or behavior is implemented yet.

## Compatibility baseline

The reference for MeshCore wire behavior is the `repeater-v1.17.1` release,
commit
[`d92964352441e53b93e8667b802e04f6e072b39e`](https://github.com/meshcore-dev/MeshCore/tree/d92964352441e53b93e8667b802e04f6e072b39e),
released [August 14, 2026](https://blog.meshcore.io/2026/08/14/release-1-17-1).
The same commit is tagged for the companion and room server. Interoperability
vectors name the commit they were derived from. MeshCore is MIT-licensed;
copied or substantially ported source must retain its copyright and license
notice.

The goal is interoperability, not replication. A MeshCore node must not be
able to tell, from the frames it receives, that a forwarder is not a MeshCore
repeater. This splits the behavior into two classes:

- **Wire behavior must match.** Parsing and rejection rules, duplicate
  identity, path mutation, direct-route matching, payload-specific forwarding
  decisions, ACK replacement, TRACE mutation, transport-code derivation and
  matching, and the flood limits determine what other nodes receive and how
  their own tables and routes behave. These follow the baseline.
- **Local policy uses UMSH machinery.** Airtime estimation, channel access,
  busy handling, duty limiting, randomness, and table and queue capacities are
  invisible to other nodes beyond their statistical effect. Where UMSH already
  has a mechanism, the forwarder uses it rather than porting MeshCore's.

MeshCore's randomized retransmit window is kept in shape, because it decides
how a UMSH forwarder contends with neighboring MeshCore repeaters, but it is
computed with UMSH's airtime estimate and RNG. Nothing is reproduced for
fidelity's sake: no out-of-bounds reads on malformed input, no MeshCore
busy-retry schedule, no chip-specific airtime rounding.

The forwarder must be low-impact on the UMSH MAC. It is a separate radio
client with its own engine; it must not require changes to UMSH's contention,
queueing, or forwarding logic, and shared code is touched only where the
change is independently correct for UMSH.

The baseline moves only by deliberate review. Following MeshCore `main`
would let routing behavior change without a UMSH release decision.

Primary source references:

- [packet constants and route/type encoding](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/Packet.h)
- [packet parsing and duplicate hash input](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/Packet.cpp)
- [payload-specific routing behavior](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/Mesh.cpp)
- [repeater defaults, region filter, loop detection, and delays](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/examples/simple_repeater/MyMesh.cpp)
- [reserved identity prefixes](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/examples/simple_repeater/main.cpp)
- [flood-limit policy](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/helpers/RoutingPolicy.h)
- [region-name and transport-code derivation](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/helpers/RegionMap.cpp)
  and [transport key calculation](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/helpers/TransportKeyStore.cpp)

## Goals

- Forward MeshCore v1 traffic interoperably: parsing, duplicate suppression,
  path mutation, payload-specific behavior, region scoping, and flood limits
  as the baseline repeater applies them.
- Give MeshCore forwarding its own enable, defaulting to false and
  independent of `PROP_MAC_REPEATER_MODE`, so a device can forward either
  protocol without the other.
- Use the UMSH device identity's Ed25519 public key as the MeshCore repeater
  identity. Never create or persist a second identity.
- Give MeshCore its own region list, `PROP_MESHCORE_REGIONS`, holding
  MeshCore region names as MeshCore spells them, separate from the UMSH
  list in `PROP_MAC_REPEATER_REGIONS`.
- Apply `PROP_MAC_REPEATER_MIN_RSSI` and `PROP_MAC_REPEATER_MIN_SNR` to flood
  forwarding in both protocols.
- Reuse UMSH's airtime calculation, CAD gate, busy backoff rule, duty
  ledger, and RNG.
- Use the device identity only through its public key. The forwarder
  performs no private-key operation of any kind.
- Work in ordinary shared-medium and `PROP_MAC_BACKHAUL` infrastructure modes
  without a mode exclusion, mode-specific toggle, or MeshCore-aware bridge.
- Ship only on boards where a repeater role makes sense, selected per board
  manifest. A board that leaves it out carries no forwarder code and no
  `CAP_MESHCORE_FORWARDER`.
- Leave the UMSH MAC's behavior and code structure unchanged.

## Non-goals

- Event-for-event or timing-exact replication of a MeshCore repeater.
- MeshCore's internal airtime budget, receive-delay scoring, busy-detection
  state machine, or forced-transmit rule. UMSH equivalents replace them.
- Acting as a MeshCore companion, room server, owner-managed repeater, or
  MeshCore application endpoint.
- MeshCore owner, ACL, contact, channel, advertisement scheduling, discovery,
  clock, telemetry, command, serial/BLE management, and firmware update
  mechanisms, and exposing any MeshCore management command through ULCP.
- Originating MeshCore advertisements, discovery responses, telemetry,
  messages, or region-management replies.
- Recognizing or consuming MeshCore requests addressed to the device. An
  ANON_REQ is forwarded like any other flood; see the research findings.
- Exposing MeshCore's tunables (delay factors, flood limits, loop
  detection) through ULCP in the first release. The baseline defaults are
  constants until a deployment needs otherwise.
- Sharing UMSH peer, channel, or region tables with MeshCore. Only the
  device identity and the link-quality thresholds are shared.
- Applying `PROP_MAC_REPEATER_DEFAULT_REGION` to MeshCore packets. It
  inserts a UMSH region code, and the forwarder never inserts or rewrites
  MeshCore transport codes.
- Translating UMSH packets to MeshCore or MeshCore packets to UMSH.

## Research findings

### The protocols can be separated before parsing

Both protocols already use the same private LoRa physical layer in the
shipping firmware. MeshCore v1 has version bits `00`; current UMSH has version
bits `11`, checked first in `PacketHeader::parse`, and the baseline parser
rejects any version other than `00`. Every received raw frame can therefore
be fanned to both engines, which reject the other protocol before doing
forwarding work. No heuristic or radio-mode switch is needed.

The current MeshCore-US PHY is 910.525 MHz, SF7, 62.5 kHz, CR 4/5, explicit
header, CRC, normal IQ, and the private sync word. Those settings can be
shared. MeshCore v1.17.1 transmits a 32-symbol preamble at SF7–SF8 and a
16-symbol preamble at SF9–SF12. The fixed SF7 MeshCore-compatible profile
already transmits 32 symbols, and the vetted profile catalog uses 32 at every
spreading factor. A transmit preamble at least as long as MeshCore's is
interoperable, because receivers detect after a shorter minimum, so no
per-request preamble override is needed. RX acquisition settings are not
part of this plan.

### Forwarding is payload-aware

MeshCore does not blindly rebroadcast every syntactically valid v1 frame.
The baseline behavior includes:

- flood and transport-flood forwarding for ACK, PATH, REQ, RESPONSE, TXT,
  ANON_REQ, GRP_DATA, GRP_TXT, and valid ADVERT packets;
- direct forwarding only when the first route entry matches this device's
  one-, two-, or three-byte public-key prefix;
- removing the matching first entry from an ordinary direct route;
- appending this device's public-key prefix to a flood path;
- forwarding a direct ACK on the remaining path with no retransmit delay.
  The baseline builds a fresh ACK packet, but the result is byte-identical
  to the received frame with the first path entry removed, except that a
  TRANSPORT_DIRECT ACK comes out as plain DIRECT with its transport codes
  dropped. A direct multipart ACK is re-emitted the same way as an ordinary
  ACK, after a delay of 300 ms times one more than its remaining count;
- appending quarter-dB SNR to a direct TRACE and using its special path
  interpretation;
- never forwarding a direct CONTROL packet whose high flag bit is set, at
  any hop count. Direct CONTROL packets without that bit follow the
  ordinary direct rule, and flooded CONTROL packets are not forwarded;
- not flood-forwarding RAW_CUSTOM, MULTIPART, unknown, or reserved payload
  types; and
- forwarding an ADVERT only after verifying its Ed25519 signature. The
  baseline also skips its own advertisement, which is vacuous here: the
  forwarder never advertises, and a forged advertisement carrying its key
  fails the signature check anyway.

Consequently, an opaque packet copier would not be compatible.

### The only cryptography is signature verification

Ordinary forwarded messages remain opaque: the forwarder has no MeshCore
contacts or channel secrets and does not decrypt their payloads. One
baseline decision requires cryptography: ADVERT signature verification is a
condition of forwarding. A forwarder that skipped it would repeat forged
advertisements that every MeshCore repeater drops, which is both a visible
divergence and a flood-amplification vector. UMSH's crypto crate already
provides Ed25519 verification; only the bridge code links it today, so it
is new flash on the boards that include the forwarder, and none on the
boards that do not.

The baseline repeater also decrypts an ANON_REQ whose one-byte destination
hash matches its own and whose MAC verifies under the X25519 shared secret,
consuming it instead of forwarding it. The forwarder does not reproduce
this, and forwards every well-formed ANON_REQ like any other flood. The
reasoning:

- Nobody can address a request to the forwarder. MeshCore companions learn
  repeaters from their advertisements, and the forwarder never advertises.
  Direct traces reveal only hash prefixes, not a key.
- A request for another node that happens to share the hash prefix fails
  authentication at a MeshCore repeater and is forwarded. The forwarder
  forwards it too. The two behave identically in the only case that occurs.
- A request genuinely encrypted to the forwarder's key is the one
  divergence, and it is already detectable: a MeshCore repeater answers it,
  and the forwarder never will. Consuming the request would buy no
  interoperability.
- Consumption would need X25519 agreement, HMAC-SHA256, and AES-128 ECB.
  UMSH has only AES-256, so this would add a cipher to the crypto stack and
  the only private-key operation in the whole feature.

With an empty MeshCore contact and channel database, ordinary addressed REQ,
RESPONSE, TXT, and group payloads cannot be recognized as local either. The
bare-forwarder model is therefore uniform: nothing is ever local, and every
forwarding decision depends only on public data in the frame.

### Identity reuse is safe within this scope

The device's single Ed25519 key serves both protocols, but only its public
half is ever used on the MeshCore side: for direct-route matching and flood
path entries. The forwarder never signs, agrees,
encrypts, or decrypts in its MeshCore role, so no key material derived from
the UMSH identity exists in MeshCore form. Any future MeshCore origination,
such as advertisements or login replies, would be the first such use and
needs its own cross-protocol analysis before it is considered.

### Reserved identity prefixes

The MeshCore repeater regenerates a new key while `pub_key[0]` is `0x00` or
`0xFF` and refuses to import a private key whose public key starts that
way, calling those reserved identity hashes. Nothing in the baseline receive
path treats such a hash specially; the rule is a constraint on which
identities may run a repeater. UMSH identities are not constrained this
way, so roughly 2 in 256 devices have a reserved prefix.
Because the forwarder never creates a second identity, such a device cannot
run the MeshCore forwarder: the device refuses to enable it, and clients
explain why in the UI. Replacing the device identity is the only remedy.

### Wire and resource behavior

These rules must match the baseline:

- Maximum radio frame: 255 bytes. Payloads longer than 184 bytes and encoded
  paths longer than 64 bytes are rejected.
- The path header's upper two bits select one-, two-, or three-byte hashes;
  mode 3 is rejected. Its lower six bits are the entry count.
- Duplicate identity is the first eight bytes of
  `SHA256(payload_type || payload)`. TRACE instead hashes
  `payload_type || path_len_le16 || payload`, where `path_len_le16` is the
  encoded one-byte path header followed by a zero byte, because the baseline
  hashes both in-memory bytes of a `uint16_t`. ACKs use the same identity as
  other payloads.
- There is no TTL beyond path capacity, the three flood limits, duplicate
  suppression, region filtering, and optional loop detection.

These are local choices:

- Duplicate memory is a bounded cyclic table of eight-byte hashes. The
  baseline holds 160, which is a sensible default at 1,280 bytes.
- Delayed transmits wait in a bounded queue sized to the firmware's memory
  budget. Exhaustion drops the new work.
- Queue order follows MeshCore's simple priority because it costs nothing:
  ordinary direct traffic first, direct TRACE at priority 5, and floods by
  path count after appending this device, with insertion order breaking ties.

### MeshCore regions are their own list

MeshCore and UMSH name regions differently. A UMSH region code derives
from its string without ASCII case, so `SJC` and `sjc` are one region. A
MeshCore transport key derives from the exact bytes of `#` and the name, so
`#us-ca` and `#US-CA` are unrelated regions, and MeshCore communities
conventionally spell theirs in lower case. A shared list works only when
the operator happens to type the MeshCore spelling into the UMSH list, and
the two communities' region names need not coincide at all. MeshCore regions
therefore live in their own property, `PROP_MESHCORE_REGIONS`, specified
below under Proposed ULCP surface.

The `#` is implicit. Every MeshCore region this forwarder can hold is a
public hashtag region, so items are stored and shown without it and the
device supplies it when deriving the key. For every stored
`PROP_MESHCORE_REGIONS` item, derive a MeshCore public transport key as
follows:

1. Use the stored UTF-8 bytes exactly, with `#` prepended.
2. Take the first 16 bytes of SHA-256 over that byte string as the transport
   key.
3. For each candidate packet, compute HMAC-SHA256 over
   `payload_type || payload` and take its first two bytes as the transport
   code. Preserve the MeshCore wire byte order; map `0000` to `0001` and
   `ffff` to `fffe`.
4. Compare only the packet's first transport code, as the baseline does.

Items compare octet for octet, matching the derivation. A string such as
`0x1234` is an ordinary MeshCore name deriving from `#0x1234`; the UMSH
literal-code interpretation does not apply.

A name beginning with `$` is a MeshCore private region. Its transport key is
loaded from MeshCore's keystore rather than derived from the name. The bare
forwarder deliberately has no such keystore, so the property refuses items
beginning with `$` rather than quietly deriving `#$name`, and refuses a
leading `#`, which would derive `##name`. Clients strip a `#` the user types.

The forwarder never inserts, removes, or rewrites transport codes under any
policy.

### Region policy

MeshCore's own configuration has two postures toward floods. Its wildcard
region, which stands for unscoped FLOOD packets, forwards by default and can
be set to deny. A scoped TRANSPORT_FLOOD is forwarded only when its first
transport code matches a configured region that allows floods; an unmatched
code is always dropped, because a repeater without the key cannot tell which
region the packet belongs to. The forwarder exposes this choice, plus one
posture MeshCore cannot take, as `PROP_MESHCORE_REGION_POLICY`:

| Value | Name | Unscoped FLOOD | Scoped, matching | Scoped, unmatched |
|---:|---|---|---|---|
| 0 | Open (default) | forwarded | forwarded | dropped |
| 1 | Scoped only | dropped | forwarded | dropped |
| 2 | Ignore | forwarded | forwarded | forwarded |

Open is the baseline repeater's default and what a MeshCore operator expects
of a repeater with a region list. Scoped only is the baseline with its
wildcard denied. Ignore is not a posture a MeshCore repeater can configure,
because a repeater forwards a scoped flood only when it holds that region's
key. On the air, though, its output is indistinguishable from a repeater
configured for every region, private ones included: the frame goes out with
the same transport codes and one more path entry. The effect is on scope,
not on detectability. A region-scoped message crosses one hop beyond its
region; downstream MeshCore repeaters without the key drop it, while
companions within earshot of the forwarder hear it. The mode exists for
operators who do not maintain a MeshCore region list and accept that.

The policy governs floods only. Direct and transport-direct traffic is
forwarded on its route regardless of transport codes, as in the baseline.
With an empty region list, Open forwards only unscoped floods and Scoped
only forwards no floods at all. UMSH's own forwarder has no equivalent
switch: untagged UMSH packets are always forwarded and an empty list imposes
no check on tagged ones, which sits between Ignore and Open. The property is
MeshCore-specific because the MeshCore side is where the baseline offers the
choice.

### Flood limits and loop detection

The three flood limits are cumulative: reject a flood when its received path
count is greater than or equal to any limit applicable to that packet. The
baseline defaults are 64 for every flood, 64 for unscoped FLOOD packets, and
8 for ADVERT packets. The forwarder applies these as constants.

The baseline's optional loop detection counts occurrences of this device's
hash in the received flood path and rejects the flood when the count reaches
a threshold. For hash sizes one/two/three the thresholds are 4/2/1 in
minimal mode, 2/1/1 in moderate mode, and 1/1/1 in strict mode, so strict
mode rejects any flood that already carries this device once. It is off by
default, and the forwarder does not implement it. If a deployment needs it,
it arrives together with its ULCP tunable.

### Link-quality gates apply to both protocols

`PROP_MAC_REPEATER_MIN_RSSI` and `PROP_MAC_REPEATER_MIN_SNR` gate MeshCore
flood forwarding, FLOOD and TRANSPORT_FLOOD alike, under the same rules the
UMSH forwarder follows:

- They apply only to frames received over the radio. Backhaul and
  local-transmit deliveries carry no measurement and pass.
- Direct (source-routed) frames are exempt, because they are forwarded on
  the strength of the route rather than the link.
- MeshCore frames carry no packet-imposed minimum, so only the device
  thresholds apply.
- A copy rejected by a link-quality gate is not recorded in the duplicate
  table, as in the UMSH forwarder, so a stronger copy of the same packet can
  still be forwarded. Every other MeshCore drop records the duplicate on
  receipt, as the baseline does.

A MeshCore repeater has no such gates. They are an operator's local choice
about which receptions are worth repeating and do not affect
interoperability: to its neighbors, a gated forwarder looks like a repeater
with a shorter reach.

### Timing and channel access

The retransmit delay keeps MeshCore's shape:
`t = trunc(airtime(path_bytes + payload_len + 2) * factor)`, then a uniform
random delay in `0..=5t` milliseconds. The default factor is 0.5 for floods
and 0.3 for direct traffic; the tagged source is authoritative where older
documentation says 0.2. The `+ 2` counts the header and path-length bytes and
excludes transport codes, as the baseline does. `airtime` is UMSH's estimate
for the active modulation, and the random value comes from UMSH's
cryptographic RNG. The factors are compile-time constants, 500 and 300
thousandths, applied in integer arithmetic.

UMSH already has a preamble-aware airtime helper,
`lora_airtime_ms_with_preamble`, which the session uses for
`PROP_PHY_T_FRAME`. The duty ledger and the radio runner's frame-time
estimate still call the older helper, whose fixed 12-symbol preamble term
under-prices every 32-symbol transmission by about 24 symbol times. That
is a UMSH accounting defect independent of this feature; the fix is to
point those two callers at the existing helper. The forwarder's retransmit
delay takes its airtime from the duty ledger's `airtime_ms`, so it inherits
whichever estimate the ledger uses.

Forwarded MeshCore frames use `CadPolicy::Gate`, the same channel-access rule
the UMSH MAC applies to its own non-ACK transmits. MeshCore's default of
skipping CAD is a local choice; gating only reduces collisions and does not
affect interoperability.

The radio mux already serializes clients: a MeshCore request waits in its
virtual queue while another client owns the radio, then transmits. The radio
runner refuses a transmit that arrives during a reception with
`TxError::CadTimeout`, the CAD gate reports a busy channel the same way, and
so does the duty gate. The MeshCore client handles every `CadTimeout` with
the rule the UMSH MAC already uses: back off by a uniform random delay in
`T_frame/40..=T_frame/4`, retry, and abandon the frame after the MAC's
attempt limit. MeshCore's own schedule of 120, 240, or 360 ms with a forced
transmit after four seconds is local policy and is not reproduced; the
forced transmit in particular is what tears down receptions in progress.
No mux contract change is needed. The backoff arithmetic is a few lines
inline in the coordinator today; if it is lifted into a shared helper so
both clients call the same code, that is a refactor with no behavior
change for UMSH.

The runner's receive gate currently allows three refusals per reception
before transmitting over it, a count shared by every client. A third client
makes exhausting it during a long reception more likely. Replacing the strike
count with a modulation-derived deadline is independently correct for UMSH
and is tracked as separate radio-runner work; this plan does not depend on it.

### Duty limiting

The MeshCore forwarder has no internal airtime budget. Its transmits go
through the existing shared duty ledger, so `PROP_PHY_DUTY_LIMIT` bounds UMSH
and MeshCore airtime together. A transmit the ledger refuses is shed, as for
every other client, rather than waiting for the budget to refill. The
refusal reaches the client as `CadTimeout` and consumes backoff attempts
like any other busy verdict, exactly as it does for the UMSH MAC, so no
special case is needed.

### SNR for TRACE

A direct TRACE carries `(int8_t)(snr * 4)`, the received SNR in quarter-dB
steps. UMSH's `Snr` type stores integer centibels, which is sufficient: a
quarter-dB value converted to centibels and rounded is off by at most 0.05 dB,
well inside the 0.125 dB needed to round back to the same quarter, provided
both conversions round to nearest. The constraint is upstream of `Snr`:
lora-phy currently rounds packet SNR to whole decibels before the runner sees
it. The planned quarter-dB SNR change to UMSH removes that loss, and TRACE
forwarding depends on it.

## Proposed ULCP surface

These are ULCP protocol additions. Reserve a new `CAP_MESHCORE_FORWARDER`
capability requiring `CAP_REPEATER`, and allocate three device-domain
properties in the extended device and transport range. All take the next
free numbers in the ULCP index when the normative specification is updated
during implementation; the capability numbers through the fifties and the
properties through the 4890s are already assigned.

| Property | Type | Default | Purpose |
|---|---|---:|---|
| `PROP_MESHCORE_FORWARDING_ENABLED` | BOOL | false | MeshCore-specific opt-in |
| `PROP_MESHCORE_REGION_POLICY` | UINT8 enum | 0 | Flood region posture: 0 open, 1 scoped only, 2 ignore |
| `PROP_MESHCORE_REGIONS` | multi-value strings | empty | MeshCore regions forwarded for scoped floods |

`PROP_MESHCORE_REGION_POLICY` selects how transport codes gate flood
forwarding, as defined under Region policy above. Values outside 0–2 fail
with `STATUS_INVALID_ARGUMENT`. It reads and writes whether or not MeshCore
forwarding is enabled, like the other repeater settings.

MeshCore's repeater tunables (the two retransmit delay factors, the three
flood limits, and the loop-detection mode) are deliberately not exposed.
The forwarder runs the baseline defaults as constants. Each tunable would
cost a describe-table row, web-debugger name, mobile binding, CLI verb, and
saved-schema row, for a knob no deployment has asked to turn. If one does,
adding a property later is one row each; nothing in this design closes the
door.

Setting `PROP_MESHCORE_FORWARDING_ENABLED` to true fails with
`STATUS_INVALID_STATE` when the first byte of the live `PROP_DEV_KEY` is
`0x00` or `0xFF`. Clients can apply the same test to `PROP_DEV_KEY` and
explain why the option is unavailable before the user tries it.

The effective gates are:

~~~text
UMSH forwarding     = PHY enabled AND MAC_REPEATER_MODE
MeshCore forwarding = PHY enabled AND MESHCORE_FORWARDING_ENABLED
                      AND running identity prefix not reserved
~~~

The forwarder holds a copy of the identity's 32-byte public key and nothing
else of the identity. Like the UMSH device node's identity handle, it is
captured at bring-up, so a replaced identity takes effect for both
forwarders at the next boot. Until then both keep forwarding under the
running identity, and neither originates anything under it. An identity
change leaves both forwarding enables as they are.

The last term of the MeshCore gate covers the one case the set-time refusal
cannot: MeshCore forwarding is enabled and the identity is then replaced with
a key whose prefix is reserved. The enable keeps its value, but after the
reboot the forwarder does not run, and clients explain why from
`PROP_DEV_KEY` exactly as they do before an enable is attempted.

One change to existing ULCP behavior accompanies the additions. The
descriptions of `PROP_MAC_REPEATER_MIN_RSSI` and `PROP_MAC_REPEATER_MIN_SNR`
say they apply to flood forwarding; they must state that this includes
MeshCore floods.

Whenever the MeshCore gate is false, the forwarder stops and discards its
volatile state. Restarting with an empty duplicate table can at most repeat a
forward of a frame heard just before the gate closed, which other nodes'
duplicate suppression absorbs.

All three properties are saved. `SAVED_SCHEMA` holds about forty rows against a
64-bit duplicate-detection mask, so the rows fit without touching the
snapshot machinery. Snapshot encode, decode, reset, clear, restore ordering,
and older-snapshot compatibility all need tests.

### MeshCore region list

`PROP_MESHCORE_REGIONS` (4978) is a multiple-value, read-write property
required by `CAP_MESHCORE_FORWARDER`, with length-prefixed items, Insert and
Remove, and no asynchronous updates, shaped like `PROP_MAC_REPEATER_REGIONS`
except where MeshCore's naming differs:

- Each item is 1 to 30 octets of UTF-8, the MeshCore region name without its
  `#`. Thirty is the longest name the baseline's region table stores. An
  empty or longer item, invalid UTF-8, or a leading `#` or `$` fails with
  `STATUS_INVALID_ARGUMENT`.
- Items compare octet for octet, case included. An insert identical to a held
  item reports `STATUS_ALREADY`; one differing only in case is a second
  region. The remove selector matches the same way.
- The device holds eight, the forwarder's key capacity, and may refuse a
  write that exceeds it.
- The empty factory default holds no region, so Open forwards only unscoped
  floods and Scoped only forwards none, exactly as before.

`PROP_MESHCORE_REGION_POLICY` matches scoped floods against this list alone.
`PROP_MAC_REPEATER_REGIONS` no longer feeds MeshCore, and nothing the device
advertises carries MeshCore regions: a UMSH node identity describes UMSH
forwarding.

The device derives keys when the setting changes, not per packet, so the
runtime snapshot carries the names and the forwarder holds the derived keys,
as it already did. The snapshot grows by the names, about 250 octets, which
the ESP32 stack check must still pass on the T-Beam.

A transport code cannot be turned back into a name: it is a two-octet
truncation of an HMAC under a key hashed from the name. The only way to learn
an unknown region is to test candidate names against captured scoped floods,
which belongs in a host tool if anywhere, not in the device.

### Counters

Four statistics join the `PROP_STAT_*` family, implied by
`CAP_MESHCORE_FORWARDER` together with `CAP_STATS` and behaving exactly as
the existing counters do: cumulative `UINT32_LE`, reset by writing four zero
octets, untouched by `CMD_RST`, absent on a device without the forwarder.

| Property | Counts |
|---|---|
| `PROP_STAT_MESHCORE_SEEN` | MeshCore packets received while the forwarder runs |
| `PROP_STAT_MESHCORE_FORWARDED_ROUTED` | forwards along a source route, at the decision |
| `PROP_STAT_MESHCORE_FORWARDED_FLOOD` | floods, at the decision |
| `PROP_STAT_MESHCORE_DECLINED` | packets neither forwarded nor duplicates |

Seen equals the two forwarded counters, declined, and duplicates together;
duplicates have no counter of their own and are the difference. Copies of
this device's own transmissions, which the mux hands every client, are not
receptions. Counting forwards at the decision matches `PROP_STAT_FORWARDED`;
a forward the channel never let out still shows here and not in
`PROP_STAT_TX_PACKETS`.

The forwarder feeds the device's shared `StatsLedger` directly from its own
task, so a host's reset holds the way it does for every other counter.

## Architecture

Create a new `no_std` library crate, tentatively
`crates/umsh-meshcore-forwarder`, containing only the compatibility engine:

- safe MeshCore v1 parser and serializer;
- packet and path mutation;
- payload-specific decision logic;
- the duplicate table and bounded delay queue;
- region-key and transport-code calculation;
- retransmit-delay scheduling;
- injected clock, RNG, airtime estimate, device public key, and radio
  adapter, so the engine is testable on the host; and
- counters useful for tests and diagnostics, without defining new management
  behavior.

The client task that drives the engine belongs in `umsh-ulcp-runtime`
beside the device node, where the other mux clients live, so both firmware
workspaces share one implementation. Each firmware that includes it adds one
static `Channels` bundle to its mux client list and spawns the task; nothing
else is per-board.

Inclusion is a firmware feature chosen per board manifest, not a property of
the shared image source. A tracker worn on a belt is not a repeater site,
and the classic-ESP32 Heltec V2 has no room to spare, so neither carries the
forwarder; boards that are plausibly left in place as infrastructure, such
as the SenseCAP Solar P1 and the Heltec V3, do. The exact list is a release
decision. A board without the feature links no engine, no third client, and
no Ed25519 verification, and it omits `CAP_MESHCORE_FORWARDER`, so a host
learns the difference the ordinary way. The ESP32 manifests keep a shared
feature table in step through `scripts/check_esp32_manifests.py`; a
per-board feature needs that check to allow the difference. The client wraps its virtual bundle in the same
`DutyGatedRadio` decorator the device node uses, which supplies the shared
duty ledger and the `CadTimeout` busy verdict for free, and takes its
airtime estimate from the ledger's `airtime_ms`. Add it as a third virtual
radio client after the ULCP session and UMSH device node:

~~~text
ULCP session (client A) ─┐
UMSH device node (B) ────┼── radio mux ── shared duty gate ── LoRa radio
MeshCore forwarder (C) ──┘
~~~

The mux fans every air reception to the medium clients and every successful
local transmission to every client except its sender, so client C never
receives its own emissions. The local transmissions it does see come from
the other clients. UMSH frames fail the version check. A raw MeshCore frame
sent by the ULCP host in shared-medium mode is already on the air from this
radio, so client C records it in its duplicate table and does not forward
it, just as a MeshCore repeater ignores repeats of a frame it has heard.

The device-domain snapshot already carries `dev_key`, the forwarding master,
and both the derived UMSH region codes and original region strings. Extend it
with the MeshCore enable, region policy, and region names, and with the link-quality
thresholds if it does not already carry them, and publish it to both
engines. It never carries
private key material. The present
`DEV_SYNC` is a single-consumer `Signal`; do not add a second consumer to it.
Either fan the snapshot out inside the existing sync task or replace the
transport with an explicit latest-value broadcast/watch primitive, as the
same module already does for `ADVERT_POLICY`.

## Infrastructure-mode behavior

Do not branch on or reject `PROP_MAC_BACKHAUL` in the MeshCore engine. Client C
is a medium client, so the existing mux topology supplies the behavior:

- air receptions go to both on-device forwarding engines, not directly to
  the backhauled ULCP session;
- a MeshCore frame retransmitted by client C is copied to the session and can
  cross the existing raw-frame bridge;
- at the far device, the session's backhaul handoff is delivered to the
  medium clients, including client C, instead of being transmitted directly;
  and
- client C applies MeshCore duplicate, path, region, and scheduling policy
  before the frame reaches that segment's air.

Thus the infrastructure carries MeshCore frames without understanding them,
which is the same layer boundary it uses for UMSH. Each bridged device
appends its own hash to a flood path, so a bridge crossing counts as two hops
in MeshCore paths, which is accurate for the two transmissions involved.

A frame delivered over the backhaul carries no radio measurement. This
matters only for a direct TRACE whose next hop is the far device, which must
append some SNR value for the bridge link; see the decisions below.

## Implementation increments

### 1. Independent radio accounting

Neither item gates the increments below; both are UMSH work in their own
right and can land before, alongside, or after the engine.

- Switch the duty ledger and the radio runner's frame-time estimate to the
  existing preamble-aware airtime helper. Until then the forwarder's
  retransmit window is a constant 24 symbol times short, which changes
  nothing about interoperability.
- Confirm that quarter-dB packet SNR reaches `RxInfo` through the UMSH SNR
  change already in progress, with round-to-nearest conversions in both
  directions. Direct TRACE forwarding is the one MeshCore behavior that
  depends on it; until it lands, traces through the forwarder report
  whole-decibel SNR.

Gate: airtime tests at 32- and 16-symbol preambles across the shipping
spreading factors, and an SNR round-trip test over the full quarter-dB range.

### 2. Interoperability vectors

- Derive wire-level vectors from the tagged sources: duplicate hashes
  including TRACE, transport keys and codes including the `0000`/`ffff`
  mapping, flood path append for each hash size, direct-route strip, the
  replacement ACK and multipart-ACK case, TRACE SNR append, and ADVERT
  signature acceptance and rejection.
- Every derivation involved is plain SHA-256, HMAC-SHA256, byte shuffling,
  or Ed25519, so the vectors can be generated with any standard library
  from the tagged sources' definitions, or taken from captured traffic. No
  compiled MeshCore oracle is needed.
- Commit the vectors with the source commit and generation command.

Gate: vectors cover every route type, payload type, and path hash size, plus
malformed lengths and reserved path modes.

### 3. Implement the pure forwarding engine

- Add the safe parser and serializer, duplicate table, bounded queue, region
  derivation and the three region policies, flood limits, and
  payload-specific routing.
- Add ADVERT verification.
- Keep all management callbacks absent and assert that no code path
  originates a management response or advertisement, and that the engine's
  only identity input is a public key.
- Implement the retransmit delay with injected clock, RNG, and airtime.

Gate: the engine reproduces every interoperability vector. Property-based
tests feed arbitrary byte strings to the parser and assert bounded,
panic-free behavior.

### 4. Add ULCP state without activating firmware forwarding

- Allocate the capability and property identifiers in the ULCP index.
- Add get/set validation, persistence, reset/clear behavior, admin reachability
  policy, describe-table rows, web-debugger names, mobile bindings, and CLI
  access for all three properties, following existing device-domain
  properties.
- Refuse the MeshCore enable for a reserved-prefix identity, and add a terse
  explanation of the unavailable option in the app, CLI, and web debugger.
- Extend the link-quality threshold descriptions to MeshCore floods.
- Extend `DevDomainSnapshot` and solve its single-consumer publication path.
- Define the gates and the reserved-prefix rule in `ulcp-device.md`; keep the
  implementation plan itself out of the normative mdBook once the feature
  ships.

Gate: ULCP device tests cover defaults, invalid values, save/restore from new
and old snapshots, factory reset, master/subfeature gating, the
reserved-prefix refusal, and identity replacement leaving both enables
unchanged, including replacement with a reserved-prefix key while MeshCore
forwarding is enabled.

### 5. Integrate the third radio client

- Add the client task to `umsh-ulcp-runtime` behind a firmware feature, and
  its bundle and spawn to the board manifests that enable it in both
  workspaces.
- Route its transmits through the existing mux, CAD gate, and duty-gated
  radio with no change to their contracts, applying the MAC's backoff rule
  to every `CadTimeout`.
- Ensure both protocol parsers receive air, local-transmit, and backhaul
  frames and reject the other protocol version.

Gate: engine and mux tests cover the link-quality gates on measured MeshCore
floods, their exemption for direct and unmeasured frames, a gate-rejected
copy followed by a forwarded stronger copy, simultaneous UMSH and MeshCore
sends, busy backoff and abandonment under the MAC's rule, duty refusals
shedding, full virtual queues, and no self-forwarding. Existing UMSH MAC
tests pass unmodified.

### 6. Prove interoperability on hardware

- Place a UMSH forwarder between unmodified MeshCore v1.17.1 companions with
  no other repeater in range. Confirm that messages flow in both directions,
  that advertisements propagate, that companions learn and use direct routes
  through the forwarder, and that traces through it complete.
- Repeat with an unmodified MeshCore repeater alongside, confirming that
  duplicates terminate and that neither repeater systematically starves the
  other.
- Confirm scoped floods with matching and nonmatching regions, an empty
  region set, a MeshCore name differing from the companion's only in case,
  and one-, two-, and three-byte path hashes. Repeat the matching,
  nonmatching, and unscoped cases under each of the three region policies
  and confirm the table under Region policy.
- Run contention tests while the UMSH node is transmitting and confirm that
  MeshCore frames wait, retry, and drop as specified, without disturbing UMSH
  delivery.
- Run two UMSH bridge participants in backhaul mode. Confirm a MeshCore frame
  heard on one RF segment crosses the existing infrastructure, is accepted by
  the far MeshCore forwarder, and reaches the other RF segment only after
  MeshCore policy. Confirm duplicates terminate.
- Clear each enable in turn and prove that only the other protocol still
  forwards.
- Set a minimum RSSI and SNR between two MeshCore companions' signal levels
  and confirm that only the stronger companion's floods are forwarded.
- Replace the device identity, reboot, and confirm that both forwarders run
  under the new key; repeat with a reserved-prefix key and confirm that only
  UMSH forwarding resumes.
- Record release firmware flash/static-RAM and stack-headroom deltas for
  every board that includes the forwarder, and confirm that boards without
  it are unchanged.

Gate: MeshCore companions interoperate through the forwarder in every case
above, bridge operation requires no MeshCore-specific configuration, and
ordinary UMSH forwarding and ULCP behavior regressions remain green.

## Acceptance criteria

The feature is ready only when all of the following are true:

- The upstream commit the wire behavior follows is named in code, vectors,
  and release notes.
- The default is off; the radio and the MeshCore switch must both be on
  before MeshCore forwarding occurs, whatever the UMSH repeater switch says.
- The MeshCore switch cannot be turned on while the identity has a reserved
  MeshCore prefix, MeshCore forwarding never runs under such an identity, and
  clients explain why.
- A replaced identity takes effect for both forwarders at the next boot, with
  both enables unchanged.
- The link-quality thresholds gate measured flood forwarding in both
  protocols.
- The forwarder performs no private-key operation; its only identity input
  is the public key.
- No second identity, MeshCore ACL, contact/channel store, management service,
  scheduled advertisement, or management reply exists.
- Every route and payload class matches the interoperability vectors,
  including negative and malformed cases.
- MeshCore region keys derive from `PROP_MESHCORE_REGIONS` alone, with the
  `#` supplied, and the UMSH region list does not affect MeshCore
  forwarding.
- MeshCore transmits use UMSH's CAD gate, busy backoff rule, airtime
  estimate, RNG, and shared duty ledger, and the UMSH MAC is unchanged.
- The only ULCP additions are the enable, the region policy, the region
  list, and the counters; every MeshCore tunable is a constant at its
  baseline default.
- Each region policy forwards and drops exactly as its row in the Region
  policy table says, for unscoped, matching, and unmatched floods.
- `PROP_MAC_BACKHAUL` neither disables nor special-cases the forwarder, and a
  two-segment bridge hardware test passes.
- Firmware size and RAM remain inside the established release margin of
  every board that includes the forwarder, and boards without it are
  unchanged.

## Risks and decisions to resolve before implementation

1. **TRACE SNR across the backhaul:** a direct TRACE forwarded from a
   backhaul delivery has no measured SNR for the bridge link. The
   recommendation is to append the maximum value, `127` (+31.75 dB), so trace
   tools show the bridge as an excellent link, rather than `0` dB, which reads
   as a marginal one. Preserving SNR end to end would not help, because the
   bridge link is not a radio link.
2. **Receive-gate strikes:** until the runner's receive gate uses a deadline,
   three refusals during one reception let the next transmit, from any
   client, tear it down. A third client makes that more likely. The deadline
   work is tracked separately and is not a prerequisite.
3. **Upstream quirks:** match quirks that shape valid frames on the wire, such
   as hashing only payload type and payload for ordinary packets, hashing the
   two-byte in-memory `path_len` for TRACE, comparing only the first
   transport code, and excluding transport codes from retransmit-delay
   airtime. Do not carry forward behavior that is a bug, such as unsafe
   handling of malformed input or forcing a transmit over a reception in
   progress.
