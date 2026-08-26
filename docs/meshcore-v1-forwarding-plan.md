# MeshCore v1 Forwarding—Research and Implementation Plan

Add an optional, autonomous MeshCore v1 forwarder to the ordinary UMSH
firmware. It shares the radio, device identity, forwarding master switch,
regional policy, and duty ceiling with the UMSH node, but it implements
MeshCore's forwarding state machine independently and exposes its own ULCP
configuration.

This document is a plan, not a protocol specification. None of the proposed
ULCP identifiers or behavior is implemented yet.

## Compatibility baseline

The implementation target is the MeshCore `repeater-v1.17.1` release, commit
[`d92964352441e53b93e8667b802e04f6e072b39e`](https://github.com/meshcore-dev/MeshCore/tree/d92964352441e53b93e8667b802e04f6e072b39e),
released [August 14, 2026](https://blog.meshcore.io/2026/08/14/release-1-17-1).
The same commit is tagged for the companion and room server, so every
conformance fixture must name both the commit and the `repeater-v1.17.1`
behavior being modeled. MeshCore is MIT-licensed; copied or substantially
ported source must retain its copyright and license notice.

“Exact” in this plan means that, for the same valid MeshCore v1 frame,
identity, forwarding configuration, receive metadata, clock, random words,
and channel-busy results, UMSH makes the same drop/forward decision, produces
the same wire frame, and reaches the same scheduled transmit attempts in the
same order as the baseline repeater. It also means preserving the baseline's
bounded tables, queue selection, and drop behavior.

It does not mean reproducing C++ out-of-bounds reads on malformed input. The
Rust parser must reject truncated or structurally invalid frames safely.
Nor can two stacks sharing one half-duplex radio promise the same wall-clock
transmit instant as an otherwise-idle standalone repeater. A UMSH transmit is
real channel occupancy. The MeshCore state machine must observe it as busy and
run the same CAD-failure backoff and forced-transmit rule it would use for any
other sustained activity.

The baseline must remain pinned until a deliberate compatibility review moves
it. Following MeshCore `main` would make timing and routing behavior change
without a UMSH release decision.

Primary source references:

- [packet constants and route/type encoding](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/Packet.h)
- [packet parsing and duplicate hash input](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/Packet.cpp)
- [payload-specific routing behavior](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/Mesh.cpp)
- [receive delay, queues, busy retry, and airtime budget](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/Dispatcher.cpp)
- [repeater defaults, region filter, loop detection, and delays](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/examples/simple_repeater/MyMesh.cpp)
- [flood-limit policy](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/helpers/RoutingPolicy.h)
- [duplicate-table sizes and replacement](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/helpers/SimpleMeshTables.h)
- [region-name and transport-code derivation](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/helpers/RegionMap.cpp)
  and [transport key calculation](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/helpers/TransportKeyStore.cpp)
- [radio activity, CAD, preamble, and packet scoring](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/helpers/radiolib/RadioLibWrappers.cpp)
- [32-packet pool and queue selection](https://github.com/meshcore-dev/MeshCore/blob/repeater-v1.17.1/src/helpers/StaticPoolPacketManager.cpp)

## Goals

- Forward MeshCore v1 traffic as the pinned MeshCore repeater does, including
  parsing, duplicate suppression, path mutation, payload-specific behavior,
  priority, randomized delay, CAD retry, and airtime budgeting.
- Keep `PROP_MAC_REPEATER_ENABLED` as the device-wide autonomous-forwarding
  master. Clearing it disables both UMSH forwarding and MeshCore forwarding.
  MeshCore additionally has its own opt-in enable, which defaults to false.
- Use the UMSH device identity's Ed25519 public key as the MeshCore repeater
  identity. Never create or persist a second identity.
- Use the strings in `PROP_MAC_REPEATER_REGIONS` as the common regional
  policy, deriving UMSH and MeshCore codes independently.
- Work in ordinary shared-medium and `PROP_MAC_BACKHAUL` infrastructure modes
  without a mode exclusion, mode-specific toggle, or MeshCore-aware bridge.
- Keep all MeshCore owner, ACL, contact, channel, advertisement scheduling,
  discovery, clock, telemetry, command, serial/BLE management, and firmware
  update mechanisms out of scope.

## Non-goals

- Acting as a MeshCore companion, room server, owner-managed repeater, or
  MeshCore application endpoint.
- Exposing MeshCore management commands through ULCP.
- Originating MeshCore advertisements, discovery responses, telemetry,
  messages, or region-management replies.
- Sharing UMSH peer or channel tables with MeshCore. Only the device identity
  and regional forwarding policy are shared.
- Applying UMSH-only forwarding controls such as
  `PROP_MAC_REPEATER_DEFAULT_REGION`, `PROP_MAC_REPEATER_MIN_RSSI`, or
  `PROP_MAC_REPEATER_MIN_SNR` to MeshCore packets. Doing so would not match a
  MeshCore repeater.
- Translating UMSH packets to MeshCore or MeshCore packets to UMSH.

## Research findings

### The protocols can be separated before parsing

Both protocols already use the same private LoRa physical layer in the
shipping firmware. MeshCore v1 has version bits `00`; current UMSH has version
bits `11`. Every received raw frame can therefore be fanned to both engines,
which reject the other protocol before doing forwarding work. No heuristic or
radio-mode switch is needed.

The current MeshCore-US PHY is 910.525 MHz, SF7, 62.5 kHz, CR 4/5, explicit
header, CRC, normal IQ, and the private sync word. Those settings can be
shared. MeshCore v1.17.1 derives a 32-symbol preamble at SF7–SF8 and a
16-symbol preamble at SF9–SF12. The existing fixed SF7 MeshCore-compatible
radio profile now transmits 32 symbols. Its hardware-tested RX settings remain
unchanged at 8 symbols on SX126x and 16 on LR1110. Forwarding integration must
derive the TX value from the active spreading factor rather than assuming the
fixed profile; changing RX acquisition settings is not part of this plan.

### Exact forwarding is payload-aware

MeshCore does not blindly rebroadcast every syntactically valid v1 frame.
The baseline behavior includes:

- flood and transport-flood forwarding for ACK, PATH, REQ, RESPONSE, TXT,
  ANON_REQ, GRP_DATA, GRP_TXT, and valid ADVERT packets;
- direct forwarding only when the first route entry matches this device's
  one-, two-, or three-byte public-key prefix;
- removing the matching first entry from an ordinary direct route;
- appending this device's public-key prefix to a flood path;
- consuming a direct ACK and constructing a replacement ACK on the remaining
  path while preserving its complete payload, including the multipart-ACK
  special case;
- appending quarter-dB SNR to a direct TRACE and using its special path
  interpretation and priority;
- accepting only zero-hop direct CONTROL packets whose high flag bit is set,
  without forwarding them;
- not flood-forwarding RAW_CUSTOM, MULTIPART, unknown, or reserved payload
  types; and
- forwarding an ADVERT only after verifying its Ed25519 signature, and never
  forwarding the device's own advertisement.

Consequently, an opaque packet copier would not be compatible.

### A small cryptographic boundary is necessary

Ordinary forwarded messages remain opaque: the forwarder has no MeshCore
contacts or channel secrets and does not decrypt their payloads. Two baseline
decisions nevertheless require cryptography:

1. ADVERT signature verification is a condition of forwarding.
2. A valid ANON_REQ addressed to this device is decrypted and marked
   do-not-retransmit. This prevents an owner/login request for the repeater
   from being flooded onward. The bare forwarder must perform only the
   destination validation needed to consume such a request, then discard it
   without answering or creating MeshCore management state.

Dropping every ANON_REQ with the same one-byte destination hash is not an
acceptable shortcut because it would drop collisions that the MeshCore
repeater forwards after authentication fails. Existing Ed25519, Curve25519,
SHA-256, and AES building blocks may be reusable, but their byte conventions
must first pass MeshCore-generated vectors. This is compatibility processing,
not a MeshCore management facility.

With an empty MeshCore contact and channel database, ordinary addressed REQ,
RESPONSE, TXT, and group payloads cannot be recognized as local. That is the
intended bare-forwarder model: it matches a repeater with no configured
MeshCore clients or channels, while ANON_REQ remains the protocol's initial
request path.

### Wire and resource behavior to preserve

- Maximum radio frame: 255 bytes. Parsed payload storage is bounded to 184
  bytes and the encoded path to 64 bytes.
- The path header's upper two bits select one-, two-, or three-byte hashes;
  mode 3 is rejected. Its lower six bits are the entry count.
- Duplicate identity is the first eight bytes of
  `SHA256(payload_type || payload)`. TRACE instead hashes
  `payload_type || path_len_le16 || payload`: on the pinned little-endian
  targets, `path_len_le16` is the encoded one-byte path header followed by a
  zero byte because the baseline stores it in a `uint16_t` and hashes both
  in-memory bytes.
- The repeater keeps one cyclic table of 160 eight-byte packet hashes. ACKs
  use the same hash as other payloads; the earlier separate four-byte ACK ring
  is not part of v1.17.1.
- The simple repeater has a shared 32-packet pool covering delayed receive,
  queued transmit, and the packet currently being processed. Exhaustion and
  full queues drop the new work.
- At most one due delayed inbound packet is processed per dispatcher pass.
  The next due outbound packet is the lowest numeric priority, with insertion
  order breaking ties.
- Ordinary direct traffic has priority 0. Flood priority is the path count
  after appending this repeater. Direct TRACE has priority 5.
- There is no TTL beyond path capacity, the three configured flood limits,
  duplicate suppression, region filtering, and optional loop detection.

The implementation should model these limits explicitly rather than replace
them with unbounded host collections in tests and different firmware limits
in production.

### Regions are shared as strings, not codes

For every stored `PROP_MAC_REPEATER_REGIONS` item that does not begin with
`$`, derive a MeshCore public transport key as follows:

1. Use the stored UTF-8 bytes exactly. Prepend `#` unless the first byte is
   already `#`.
2. Take the first 16 bytes of SHA-256 over that byte string as the transport
   key.
3. For each candidate packet, compute HMAC-SHA256 over
   `payload_type || payload` and take its first two bytes as the transport
   code. Preserve the MeshCore wire byte order; map `0000` to `0001` and
   `ffff` to `fffe`.
4. Compare only the packet's first transport code, as the baseline does.

UMSH region derivation is case-insensitive, while MeshCore's derivation uses
the exact spelling. Changing only capitalization can therefore change the
MeshCore forwarding scope without changing UMSH's scope. A literal such as
`0x1234` is still a MeshCore public region name and derives from `#0x1234`;
the UMSH literal-code interpretation must not leak into MeshCore.

A name beginning with `$` is a MeshCore private region. Its transport key is
loaded from MeshCore's keystore rather than derived from the name. The bare
forwarder deliberately has no such keystore, so a `$` item contributes no
MeshCore transport key; it must never be transformed into `#$name`. This does
not change how the same stored string participates in UMSH region policy.

An empty region list retains UMSH's unrestricted behavior. For MeshCore it
allows unscoped FLOOD packets through the wildcard policy, but a scoped
TRANSPORT_FLOOD has no configured transport key to match and is dropped.
The forwarder never inserts, removes, or rewrites transport codes.

### Timing behavior to preserve

All airtime inputs must use the active LoRa configuration and MeshCore's
derived transmit preamble: 32 symbols at SF7–SF8 and 16 symbols at SF9–SF12.
The fixed SF7 radio profile now transmits 32 symbols, but the generic airtime
helper still assumes eight and the request path cannot yet derive 32/16 from
an arbitrary active SF. Neither is an exact substitute for the per-frame
calculation required by the forwarder.

This airtime defect already affects UMSH independently of MeshCore
forwarding. Both current airtime helpers use a rounded 12-symbol preamble term
derived from an eight-symbol preamble. On the fixed SF7 profile they therefore
under-price every 32-symbol-preamble transmission by approximately 24 symbol
times in the shared duty ledger and scheduler hint. Correct the shared
calculation as prerequisite radio-accounting work, with an explicit preamble
argument, rather than hiding the fix inside the MeshCore engine.

Baseline repeater defaults are:

| Setting | Default | Required behavior |
|---|---:|---|
| Receive-delay base | 0.0 | Disabled; process a received flood immediately |
| Flood TX delay factor | 0.5 | `t = trunc(airtime(path_bytes + payload_len + 2) * factor)`, then uniform integer delay `0..5t` inclusive |
| Direct TX delay factor | 0.3 | Same calculation; the tagged source is authoritative even where older documentation says 0.2 |
| Hardware CAD | Off | Do not run a new hardware CAD scan before TX by default |
| Busy retry | — | Randomly choose 120, 240, or 360 ms after an in-progress receive, configured interference, enabled CAD, or local-radio occupancy reports busy |
| Forced transmit | 4 s | After continuous busy duration exceeds 4, attempt without CAD |
| Airtime factor | 1.0 | One-hour bucket with a 50% maximum budget |
| Overall flood maximum | 64 | Applies to every flood |
| Unscoped flood maximum | 64 | Additional limit for unscoped FLOOD packets |
| Advertisement flood maximum | 8 | Additional limit for ADVERT packets |
| Loop detection | Off | Optional thresholds below |
| Extra ACKs | 0 | Do not create redundant multipart ACKs |
| Interference threshold | 0 | RSSI activity check disabled |
| AGC reset interval | 0 | Periodic reset disabled |

When a nonzero receive-delay base is configured, compute the packet score
exactly from SNR threshold and frame length. SF7 through SF12 thresholds are
−7.5, −10, −12.5, −15, −17.5, and −20 dB. Below threshold the score is zero;
otherwise it is
`clamp(((snr - threshold) / 10) * (1 - frame_len / 256), 0, 1)`.
The delay is
`trunc((base^(0.85 - score) - 1) * received_frame_airtime)`, processed
immediately below 50 ms and capped at 32 seconds.

Loop detection counts occurrences of this device's selected hash in the
received flood path. Maximum prior occurrences for hash sizes one/two/three
are 4/2/1 in minimal mode, 2/1/1 in moderate mode, and 1/1/1 in strict mode.

MeshCore's random helper consumes a 32-bit word and uses modulo reduction.
UMSH policy requires a cryptographic RNG, so the forwarder should consume
ChaCha20 output seeded through the existing hardware-entropy path but retain
MeshCore's `word % span` mapping. A test-injected random-word source makes
event-for-event comparison possible without requiring two independently
seeded devices to produce the same random sequence.

The three flood limits are cumulative: reject a flood when its received path
count is greater than or equal to any limit applicable to that packet.

The baseline's internal airtime budget is separate from UMSH's
`PROP_PHY_DUTY_LIMIT`. Preserve the MeshCore one-hour bucket for MeshCore
transmits only, then apply the existing shared UMSH duty ledger as an outer
ceiling across all radio clients. Existing UMSH policy sheds a transmit that
the shared duty ledger refuses rather than waiting for the budget to refill;
MeshCore must follow that outer policy too. A duty refusal is not channel
activity, must not advance the four-second CAD-busy timer, and can never be
bypassed by the forced-transmit path. This policy constraint is not a reason
to silently delete MeshCore's own inner budget behavior.

## Proposed ULCP surface

Reserve a new `CAP_MESHCORE_FORWARDER` capability, tentatively capability 51,
requiring `CAP_REPEATER`. Allocate the following persisted device-domain
properties tentatively from 4872 onward. The numbers are proposals until the
ULCP index and normative specification are updated during implementation.

| Property | Type | Default | Purpose |
|---|---|---:|---|
| `PROP_MESHCORE_FORWARDING_ENABLED` | BOOL | false | MeshCore-specific opt-in |
| `PROP_MESHCORE_RX_DELAY_BASE` | UINT16, thousandths | 0 | MeshCore `rxdelay` base, 0.000–20.000 |
| `PROP_MESHCORE_FLOOD_TX_DELAY_FACTOR` | UINT16, thousandths | 500 | MeshCore flood `txdelay`, 0.000–2.000 |
| `PROP_MESHCORE_DIRECT_TX_DELAY_FACTOR` | UINT16, thousandths | 300 | MeshCore direct `direct.txdelay`, 0.000–2.000 |
| `PROP_MESHCORE_FLOOD_MAX` | UINT8 | 64 | Overall received flood path limit, 0–64 |
| `PROP_MESHCORE_UNSCOPED_FLOOD_MAX` | UINT8 | 64 | Additional unscoped-flood path limit, 0–64 |
| `PROP_MESHCORE_ADVERT_FLOOD_MAX` | UINT8 | 8 | Additional advertisement path limit, 0–64 |
| `PROP_MESHCORE_LOOP_DETECT` | UINT8 enum | 0 | Off, minimal, moderate, or strict |
| `PROP_MESHCORE_AIRTIME_FACTOR` | UINT16, thousandths | 1000 | MeshCore airtime factor, 0.000–9.000 |
| `PROP_MESHCORE_CAD_ENABLED` | BOOL | false | Run MeshCore's optional hardware CAD scan before TX |

Conversion from thousandths to binary32 and every subsequent expression must
be checked against the C++ baseline. Golden tests must cover all shipped
defaults and representative non-defaults. If exact conversion cannot be made
portable across the supported embedded targets, store the three factor
properties as canonical IEEE-754 binary32 bits instead; do not quietly use a
different numeric model.

The effective gates are:

~~~text
UMSH forwarding     = PHY enabled AND MAC_REPEATER_ENABLED
MeshCore forwarding = PHY enabled AND MAC_REPEATER_ENABLED
                      AND MESHCORE_FORWARDING_ENABLED AND identity ready
~~~

The existing `NODE_ACTIVE` check stops UMSH beacon and advertisement
origination when the running key no longer matches live `PROP_DEV_KEY`; it
does not disable UMSH repeater forwarding, whose enable is currently applied
unconditionally. Preserve that behavior unless a separate, deliberate UMSH
policy change is approved.

For MeshCore, `identity ready` means that the running forwarder's
public/private identity matches live `PROP_DEV_KEY`. This new engine must fail
closed because its identity is load-bearing for direct-route matching,
own-advertisement suppression, and ANON_REQ self-consumption. A live identity
replacement disables MeshCore forwarding until reboot activates the newly
stored private key, without changing current UMSH forwarding behavior.

Clearing `PROP_MAC_REPEATER_ENABLED` must have the same effect as MeshCore's
`disable_fwd`, not tear down and recreate the engine. This matters because the
baseline still performs parsing and some duplicate bookkeeping while
forwarding is disabled. Clearing the MeshCore-specific enable may stop its
task completely and clear volatile state; this distinction must be specified
and tested.

No new MeshCore region property is needed. `PROP_MAC_REPEATER_REGIONS` is the
single shared source of region strings. The existing default-region and link
quality gates remain UMSH-only.

All ten proposed properties are saved. `SAVED_SCHEMA` currently has 31 rows
and uses one `u32` as its duplicate-detection bitmask, enforced by a
compile-time assertion. Consequently, even two new saved properties break
the build, and the complete surface exceeds the representation substantially.
The implementation must expand that tracking representation before extending
the schema; packing unrelated MeshCore settings into one opaque property
merely to avoid this limit would be the wrong interface tradeoff. Snapshot
encode, decode, reset, clear, restore ordering, and older-snapshot
compatibility all need tests.

## Architecture

Create a new `no_std` library crate, tentatively
`crates/umsh-meshcore-forwarder`, containing only the compatibility engine:

- safe MeshCore v1 parser and serializer;
- packet and path mutation;
- payload-specific decision state machine;
- duplicate/ACK rings and the fixed 32-packet pool;
- region-key and transport-code calculation;
- receive, retransmit, CAD-retry, priority, and airtime-budget scheduling;
- injected clock, RNG-word source, identity operations, and radio adapter;
  and
- counters useful for tests and eventual diagnostics, without defining new
  management behavior.

Keep firmware wiring in the shared nRF52840 firmware and the ESP32 workspace,
not in the protocol engine. Add a third virtual radio client after the ULCP
session and UMSH device node:

~~~text
ULCP session (client A) ─┐
UMSH device node (B) ────┼── radio mux ── shared duty gate ── LoRa radio
MeshCore forwarder (C) ──┘
~~~

Every air reception and successful local transmission is already fanned to
the medium clients. The MeshCore client must ignore `RxOrigin::LocalTx` after
using it for duplicate awareness, so it never recursively forwards its own
emission. As with the UMSH client, exact handling should be driven by frame
identity rather than by assuming all local transmissions belong to itself.

The current mux leaves a second client's TX request queued while another
client owns the radio. That is not MeshCore busy-channel behavior. Extend the
mux/radio contract so a due MeshCore request can observe local-radio occupancy
as a busy result immediately. Receiving a preamble or packet is always busy;
an additional hardware CAD scan occurs only when
`PROP_MESHCORE_CAD_ENABLED` is true, matching v1.17.1's default-off setting.
The MeshCore scheduler then chooses 120, 240, or 360 ms and, after more than
four seconds of continuous busy results, issues a forced request. Preserve
fair arbitration for simultaneous clear-channel requests, but do not let
fairness replace either protocol's own contention state machine.

The device-domain snapshot already carries `dev_key`, the forwarding master,
and both the derived UMSH region codes and original region strings. Extend it
with MeshCore configuration and publish it to both engines. The present
`DEV_SYNC` is a single-consumer `Signal`; do not add a second consumer to it.
Either fan the snapshot out inside the existing sync task or replace the
transport with an explicit latest-value broadcast/watch primitive.

The radio request path must support MeshCore's SF-derived 32/16-symbol TX
preamble without changing the bytes or timing of unrelated UMSH profiles or
the existing per-radio RX settings. The fixed SF7 TX baseline is already
aligned at 32 symbols, but a per-request
packet-parameter override is still preferable to repeatedly mutating global
radio state. The airtime APIs should gain an exact per-frame calculation
accepting the selected preamble length, header mode, CRC, spreading factor,
bandwidth, and coding rate. Both MeshCore delay calculations and its internal
duty bucket need the same result the radio configuration produces.

Any shared PHY-profile catalog must likewise derive or store the TX preamble
per row: 32 for SF7–SF8 and 16 for SF9–SF12. A single MeshCore preamble
constant cannot correctly describe a table spanning those spreading factors.

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
which is the same layer boundary it uses for UMSH. The bridge currently does
not preserve radio SNR in a backhaul transmit. This is harmless with the
MeshCore v1.17.1 default receive-delay base of zero. If a nonzero receive delay
is exposed, define and test backhaul scoring explicitly—preferably by
preserving the received link metadata end to end—rather than manufacturing a
radio measurement. This is the only identified non-default tuning issue for
transparent infrastructure operation.

## Implementation increments

### 1. Freeze an executable conformance oracle

- Vendor no production C++ code yet. Instead, build a host-only fixture tool
  from the exact tagged MeshCore sources under their MIT notice.
- Budget this as substantial work: the tagged implementation is
  Arduino-oriented, so the host fixture needs narrow stubs for the Arduino,
  RadioLib, clock, RNG, and persistence surfaces used by the forwarding path.
- Make clock values, received SNR/RSSI, channel-busy answers, and RNG words
  deterministic inputs.
- Record output wire frames, scheduled deadlines, priorities, table changes,
  budget changes, and drops.
- Commit compact golden vectors plus the source commit and generation command.
  Cover every route and payload type, all path hash sizes, malformed lengths,
  duplicates, pool exhaustion, region matches, loop modes, timing boundaries,
  CAD retries, the four-second force boundary, and 32-bit millisecond wrap.

Gate: the oracle reproduces selected frames observed between two unmodified
  MeshCore `repeater-v1.17.1` instances.

### 2. Implement the pure forwarding engine

- Add the safe parser/serializer, fixed resource model, duplicate tables,
  region derivation, and payload-specific routing.
- Add ADVERT verification and the minimal ANON_REQ self-consumption path.
- Keep all management callbacks absent or no-op and assert that no code path
  originates a management response or scheduled advertisement.
- Implement timing with injected clock, RNG words, and exact airtime inputs.

Gate: Rust results match every oracle vector event for event. Property-based
tests feed arbitrary byte strings to the parser and assert bounded, panic-free
behavior.

### 3. Add ULCP state without activating firmware forwarding

- Allocate the capability and final property identifiers in the ULCP index.
- Add get/set validation, persistence, reset/clear behavior, admin reachability
  policy, describe tables, web-debugger names, mobile bindings, and CLI access
  following existing device-domain properties.
- Expand saved-state duplicate tracking beyond 32 schema entries.
- Extend `DevDomainSnapshot` and solve its single-consumer publication path.
- Define master-gate semantics in `ulcp-device.md`; keep the implementation
  plan itself out of the normative mdBook once the feature ships.

Gate: ULCP device tests cover defaults, invalid values, save/restore from new
and old snapshots, factory reset, master/subfeature gating, and identity
replacement, including MeshCore's fail-closed result without silently changing
UMSH repeater forwarding.

### 4. Integrate the third radio client and contention contract

- Add client C and its task to every shipping nRF52840 firmware and the ESP32
  workspace.
- Extend radio arbitration so due MeshCore work receives immediate busy
  feedback rather than hidden queueing.
- Generalize the already-aligned SF7 TX preamble into MeshCore's SF-derived
  32/16-symbol TX selection and add exact per-length airtime calculation
  without changing RX acquisition or unrelated UMSH packet parameters.
- Put MeshCore's internal budget inside the existing combined duty gate.
- Ensure both protocol parsers receive air, local-transmit, and backhaul
  frames and reject the other protocol version.

Gate: deterministic mux tests cover simultaneous UMSH/MeshCore sends, fair
clear-channel arbitration, MeshCore busy retry/force behavior, combined duty,
full virtual queues, and no self-forwarding.

### 5. Prove ordinary and infrastructure operation on hardware

- On an otherwise-idle UMSH device, compare received-to-retransmit timing,
  wire bytes, and routing decisions against an unmodified MeshCore v1.17.1
  repeater across flood, scoped flood, direct, ACK, TRACE, and ADVERT cases.
- Run contention tests while the UMSH node is transmitting and confirm the
  MeshCore scheduler observes busy and follows its retry sequence.
- Run two UMSH bridge participants in backhaul mode. Confirm a MeshCore frame
  heard on one RF segment crosses the existing infrastructure, is accepted by
  the far MeshCore forwarder, and reaches the other RF segment only after
  MeshCore policy. Confirm duplicates terminate.
- Clear `PROP_MAC_REPEATER_ENABLED` and prove that neither protocol forwards;
  restore it and prove that only individually enabled protocols resume.
- Verify case-sensitive MeshCore versus case-insensitive UMSH region vectors,
  an empty region set, nonmatching scoped floods, and one-/two-/three-byte
  identity path hashes.
- Record release firmware flash/static-RAM and stack-headroom deltas for every
  board. Treat the classic-ESP32 Heltec V2 as the explicit worst-case gate:
  the packet pool, hash table, crypto, and third task must fit its existing
  margins, as well as every other shipping target.

Gate: all conformance cases pass against the pinned release, bridge operation
requires no MeshCore-specific configuration, and ordinary UMSH forwarding and
ULCP behavior regressions remain green.

## Acceptance criteria

The feature is ready only when all of the following are true:

- The exact upstream commit and compatibility contract are visible in code,
  tests, and release notes.
- The default is off; both the master forwarding switch and MeshCore switch
  must be on before MeshCore forwarding occurs.
- No second identity, MeshCore ACL, contact/channel store, management service,
  scheduled advert, or management reply exists.
- Every supported payload and route class matches oracle decisions and wire
  mutation, including negative and malformed cases.
- Delay, priority, random mapping, CAD retry, forced transmit, queue/pool
  behavior, duplicate replacement, loop detection, and internal airtime
  budget match the baseline under deterministic inputs.
- MeshCore region codes derive from the existing region strings and do not
  reuse UMSH's derived two-byte codes; `$` private-region names produce no
  MeshCore key without a keystore.
- `PROP_MAC_BACKHAUL` neither disables nor special-cases the forwarder, and a
  two-segment bridge hardware test passes.
- UMSH and MeshCore airtime together remain bounded by the shared duty ledger.
- Firmware size and RAM remain inside every board's established release
  margin.

## Risks and decisions to resolve before implementation

1. **ANON_REQ compatibility:** confirm with captured v1.17.1 traffic that the
   repository's Ed25519-to-shared-secret and MAC/decrypt primitives reproduce
   MeshCore exactly. If not, add a narrowly licensed compatibility primitive;
   do not omit the self-request rule.
2. **Numeric tuning representation:** prove the proposed thousandths encoding
   reproduces binary32 scheduling at all accepted values or switch the ULCP
   representation before allocating identifiers.
3. **Backhaul metadata with nonzero `rxdelay`:** either preserve SNR across the
   infrastructure or specify a deterministic non-radio score. The default-zero
   configuration already works without this extension.
4. **Radio occupancy API:** select an interface that reports another local
   client's in-flight TX as busy without coupling the pure MeshCore engine to
   the firmware mux.
5. **Identity private-key format:** verify that the stored UMSH seed/key form
   produces precisely the MeshCore public identity and shared-secret behavior
   without retaining an extra expanded private-key copy.
6. **Upstream quirks:** golden vectors, not prose recollection, decide behavior.
   Preserve observable valid-frame quirks such as hashing only payload type and
   payload for ordinary packets, hashing the two-byte in-memory `path_len` for
   TRACE, comparing only transport code zero, and excluding transport-code
   bytes from retransmit-delay airtime. Fix only memory-unsafe malformed-input
   behavior.
