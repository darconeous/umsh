# Companion Radio → ULCP — Transition Plan

Collapse the "companion radio" and "repeater" concepts into a single per-board
firmware image in which the difference is **configuration, not code**, and
rename the control protocol to reflect what it actually is: the **UMSH Local
Control Protocol (ULCP)** — the local, out-of-band link used to commission and
manage a UMSH device, as distinct from in-band node management over the mesh.

Status: **increments 1–7 landed; increment 8 (the rename) partially landed.**

Everything below is retained as written — it is the reasoning, not a
checklist — with a status note per increment recording what was decided
where the plan asked for a decision. See "Implementation status" at the
end for what remains.

Decisions the plan deferred to implementation, all recorded in their
increments below: `CMD_RST` regenerates a cleared device identity
(increment 3); a snapshot records the identity it was taken under and a
restore withholds the PHY enable when it does not match (increment 3);
Wio Tracker L1 is parked with a bringup harness and no shipping image
(increment 7); `companion-cli-*` survives per board as that harness
(increment 7).

## Why

The code is already most of the way here and the naming is now actively
misleading.

- Role is already a runtime flag. `advertised_identity()` in
  `firmware/nrf52-tracker/src/device_node.rs:178` flips between
  `NodeRole::Repeater` and `NodeRole::Tracker` from an atomic reconciled out of
  the device-domain snapshot. There is no compile-time repeater/companion fork
  anywhere in the tree.
- `PROP_MAC_REPEATER_ENABLED` is persisted **device-domain** state, deliberately
  independent of any attached host (`crates/umsh-ulcp-device/src/session.rs:302`).
- The spec already describes the device identity as existing for "repeater or
  bridge behavior" and already frames `CMD_SAVE` as the thing that "arms an
  unattended repeater across power cycles"
  (`docs/protocol/src/companion-radio-full.md:914`).

What remains is finishing the trajectory, removing the assumptions that only
made sense when "attached to a phone" was the normal state, and renaming.

Doing this now costs approximately nothing: nothing is fielded beyond bench
devices. The cost grows monotonically from here.

## Scope

**In scope:** one shipping image per board covering both tethered and repeater
use; volatile host domain and unconditional host re-provisioning; always-present device
identity; identity role and mobility properties; BLE pairing-policy correction
and bond-store unification; snapshot format replacement; the ULCP rename.

**Out of scope (deferred, deliberately):**

- **Forwarding fairness.** `TxPriority` keeps its current ordering —
  `ImmediateAck` (0), `Forward` (1), `Retry` (2), `Application` (3)
  (`crates/umsh-mac/src/send.rs:382`). Deferred because anticipated traffic
  levels do not warrant it, **not** because local control is unaffected by it.
  The coupling is real and this plan is what creates it: once forwarding and
  tethering coexist in one image on one device, a busy relay's forwarded
  traffic outranks its attached host's own sends *and* their retransmissions,
  out of a single duty budget. ULCP *control frames* are immune — they travel
  over BLE/USB and never enter `umsh-mac::TxQueue` — but what they cause is not:
  enabling the PHY, joining a channel and requesting a beacon all produce MAC
  traffic that queues like any other. Host data is likewise not immune. Revisit
  when a repeater is also somebody's daily phone radio. Deferred
  with it: reprioritization, bounded-fairness scheduling, reserved queue slots,
  confirmation-timer changes, and forwarding-drop accounting.
- **Host-provisioning atomicity** (decision 7). Provisioning writes the live
  host domain one property at a time and an interrupted sequence leaves a
  mixture; the hazard is bounded in increment 4 and accepted. The shape to
  revisit, recorded so it need not be re-derived:

  Two command identifiers — the command octet is fully allocated at 0–15
  (`crates/umsh-ulcp/src/frame.rs:65`) and 16–255 are free, so
  `CMD_HOST_BEGIN` and `CMD_HOST_COMMIT` cost nothing but their numbers. Between
  them, ordinary `CMD_PROP_SET`/`CMD_PROP_INSERT` frames addressed to
  host-domain properties apply to a **candidate** domain that starts empty
  rather than to the live one; the live domain keeps filtering, queueing,
  ack-delegating and forwarding against the old state until commit, since
  suspending it would negate decision 5. Commit reconciles candidate into live
  per decision 17 and is the only observable transition. Abort, detach and a
  bounded timeout discard the candidate; a second host opening a transaction
  gets `BUSY`; reads report the live domain throughout. A host-key change makes
  the commit a rebuild rather than a reconcile, since pairwise material derives
  from the host identity and a replay window established under the old key is
  meaningless under the new one.

  The candidate carries **provisioned values only, never per-entry runtime
  state**: its peer table is shaped like the snapshot's
  (`[Option<items::PeerKeyEntry>; MAX_PEER_KEYS]`, `session.rs:1003`, 64 octets
  an entry), not like the live `PeerKeyTable`, whose `PeerSlot` carries a
  ~320-octet `ReplayWindow` that is never persisted and would be meaningless to
  stage. Windows are attached by the commit. Generalized: **the candidate holds
  what a snapshot would hold** — roughly 800 octets at the current table size.

  Three things the shape leaves open: what a partial transaction commits (a
  candidate that starts empty makes `BEGIN`/`COMMIT` a domain-replacement
  primitive, unless untouched properties are tracked and passed through); how
  abort is encoded (a third identifier, a `BEGIN` while one is open, or a flag
  on `COMMIT`); and what a non-transactional host-property write does while a
  transaction is open.
- **Peer-table scale.** `MAX_PEER_KEYS` stays 8 and the fixed
  `[Option<PeerSlot>; MAX_PEER_KEYS]` array stays as it is. The target is 100+
  peers, at which point that mechanism is replaced outright — **nothing in this
  plan should treat 8 as a durable premise.** When it happens the binding
  constraint will be *replay state, not key material*: a `PeerSlot` is 64 octets
  of provisioned keys plus a ~320-octet `ReplayWindow` dominated by
  `Deque<RecentMic, 9>` (`crates/umsh-crypto/src/replay.rs:45`), so a hundred
  peers is ~6.4 KB of provisioned values against ~32 KB of live windows, on a
  256 KB budget that already holds a 37 KB `Mac`. The questions there are
  MIC-cache depth and whether a window is allocated per known peer or per
  recently active peer. Per-item provisioning is chosen to survive that change,
  as is the candidate-holds-what-a-snapshot-holds rule recorded above should the
  transaction ever be built; decision 6's cost argument is not, and is scoped
  accordingly.
- **Bond revocation.** No command or property removes a specific bond. Note
  that a full store is not a failure state — it evicts (decision 11) — so the
  gap is narrower than it sounds: an administrator displaced by eviction
  re-enrolls through pairing mode. Removing a *specific* bond while keeping the
  others still requires a local wipe gesture or `CMD_FACTORY_RESET`.
- ACLs for in-band management; fleet telemetry and management UI in the iOS app;
  `PROP_IDENT_LOCATION` and the rest of the device-behavior property range
  (71–95); bridged mode; pager-class devices, which keep their own image.

## Design decisions

1. **"Single image" means one image per *board*, not one image overall.**
   Different BSPs, flash layouts, and a separate Xtensa workspace remain. What
   collapses is the *role* axis: the build matrix goes from boards × roles to
   boards.

2. **Role is configuration, not a mode.** No device-side role enum gating
   behavior. Any "profile" concept is a host-side preset that expands into
   properties.

3. **Four independent dimensions.** Primary advertised role; mobile versus
   fixed; forwarding enabled; tethered versus standalone. A mobile repeater and
   a fixed tracker must both be representable. **Tethering does not appear in
   node identity at all** — it is a transient local relationship, not a durable
   mesh-visible characteristic.

4. **Commissioning ≠ tethering.** Configuring a device's device domain must not
   claim its host domain. One phone administering ten repeaters must not write
   `PROP_HOST_KEY` on any of them.

5. **The host domain is volatile across reboot, not across disconnect.** A
   detached radio keeps filtering, queueing and ACKing for its host while
   powered — that is the entire value of the host domain. It forgets on power
   cycle.

6. **Host state is re-provisioned unconditionally on every tethered attach**,
   not re-provisioned on a detected reboot and not reconciled by comparison.
   Write `PROP_HOST_KEY` and every host table in full, every time.

   Comparison cannot work here: key tables read back in lossy form only —
   `PROP_HOST_CHANNEL_KEYS` returns channel identifiers and
   `PROP_HOST_PEER_KEYS` returns peer public keys, with key material never read
   back (`crates/umsh-ulcp-device/src/session.rs:3039`). An administrator can
   replace a peer's `K_enc`/`K_mic` without changing anything observable, so no
   digest over the readable surface can detect it. Adding a digest *over* the
   secret state would mean deriving a readable value from key material, which is
   worse than the problem.

   Rewriting costs little beyond the frames, because the device side reconciles
   rather than rebuilds (decision 17): peers already present keep their key
   material *and* the state keyed to their identity. That "little" is scoped to
   the current table size — see the peer-table scale note under Out of scope,
   which is where the boot-generation skip below stops being an optimization and
   starts being the normal path.

   **Removals still come from comparison, and that is not a contradiction.**
   Membership is readable even though key material is not, so the host `GET`s
   the digest list, `REMOVE`s the entries its desired set omits, and `INSERT`s
   every desired entry unconditionally — including entries the device already
   reports, whose key material it cannot verify. This is the shape `provision()`
   already has (`umsh/src/companion_radio.rs:1555`); the change is dropping the
   `if !current_peers.contains(...)` guard on the insert side while keeping the
   removal loop. What decision 6 rules out is *skipping a write* because the
   readable surface looks right, not *reading* the readable surface at all.

   Unconditional rewriting is strictly stronger than reboot detection: it
   handles partial provisioning, another administrator having intervened, and
   future firmware behavior changes, without depending on any signal being
   trustworthy. The state usually survives the disconnect (decision 5), so the
   rewrite is usually redundant — that is the point. Correctness must not depend
   on detecting the cases where it is not. A boot generation or reset indication
   may be used to *skip* the rewrite as an optimization, never to decide
   correctness.

7. **Host provisioning is a sequence of ordinary property writes, and its
   atomicity is deferred.** The host domain spans five properties:
   `PROP_HOST_KEY`, channel keys, peer keys, RX filters, auto-ack. Written one at
   a time, an interrupted sequence leaves a detached radio operating
   autonomously on a mixture of old and new state. **This plan accepts that**
   and provisions with the frames that already exist — `CMD_PROP_SET`,
   `CMD_PROP_INSERT`, `CMD_PROP_REMOVE` against the live domain, no staging, no
   new commands.

   The exposure is genuinely narrow, which is what makes the deferral
   reasonable rather than merely convenient — see "Scope of the interruption
   hazard" in increment 4 for why it reduces to one case: re-provisioning a
   still-powered, already-provisioned radio under an unchanged host key. An
   interrupted attempt leaves the device forwarding on its device domain and is
   repaired by the next attach, which rewrites everything unconditionally
   (decision 6). Nothing in this plan may depend on provisioning being atomic.

   Two constraints survive the deferral and are **not** optional:

   - **provisioning is per-item, never whole-table**, because a full peer table
     does not fit in a frame. Increment 4 has the arithmetic, and it is a frame
     limit rather than an atomicity argument, so deferring staging does not
     relax it.
   - **the device side reconciles rather than rebuilds** (decision 17), so
     re-provisioning preserves per-peer replay baselines.

   Deferred with it: `CMD_HOST_BEGIN`/`CMD_HOST_COMMIT`, the candidate host
   domain, and the questions that shape carries — what a partial transaction
   commits, how abort is encoded, and what a non-transactional write does while
   a transaction is open. Sketched under Out of scope so the design is not lost.

   Note that increment 2's snapshot restore **still stages**, for an unrelated
   reason: a malformed option arriving late in a decode must not leave the
   device half-configured, and unlike a mid-provisioning disconnect, a corrupt
   snapshot is exactly the case that occurs. That staging is local to the
   restore path — a decoded value assigned on success — not a protocol
   mechanism, and the two no longer share machinery.

8. **A device identity always exists.** Generated on first boot if absent;
   regenerated by `CMD_CLEAR`. Never a commissioning step the user performs.

9. **`PROP_IDENT` is served by an asynchronous signing effect**, following the
   established deferred-property-read pattern (`Effect::SampleRssi` /
   `respond_rssi`, `Effect::SampleBattery` / `respond_battery`). A read emits
   `SignIdentity { tid }`; firmware signs the canonical nonce-free payload and
   completes with `respond_identity_blob()`. Caching is a later optimization if
   signing cost proves material — it is not required, and it would impose real
   coherence work across device key, role, mobility, repeater state, name, and
   every future identity field.

10. **One canonical unsigned identity-payload builder, two framings.** The
    Identity Request response shares the builder but cannot be the same object:
    it carries a request nonce and is authenticated by the enclosing unicast
    rather than a detached signature
    (`crates/umsh-node/src/identity_responder.rs:6`).

11. **A successful pairing against a full bond store evicts the
    least-recently-used bond. This is settled.** The store holds four bonds
    (`MAX_BONDS`, `crates/umsh-journal-store/src/ble.rs:9`). When it is full, the
    fifth successful pairing does **not** fail: the least-recently-used bond is
    removed and the new one is stored. Enrollment is never refused for lack of
    space, on either platform, ever.

    This is the behavior `upsert_bond` was written for, it is what
    `docs/companion-ble-plan.md:1265` already specifies, and the only reason it
    does not happen today is the capacity term in `pairing_enabled` — an
    oversight, corrected in increment 1. Any future change that reintroduces
    refuse-when-full is a regression, not a hardening.

    "Least recently used" is only meaningful if use is recorded, so `touch_bond`
    on every bonded reconnect is part of the rule, not an optimization. A store
    that never touches is insertion-ordered and evicts the wrong bond — see
    increment 1 on the Heltec V3 side.

    What makes this safe is that enrollment requires **physical presence** and
    that the victim of an eviction is always the *least-recently-used* bond.
    Pairing mode is the gate (OOB excepted), and it is armed in exactly two
    ways: automatically at boot while no bond exists, or — once bonded — by a
    deliberate local gesture, which on the boards with a power button is a
    shutdown followed by a multi-second hold to power back on. Bonds therefore
    cannot be churned remotely, and the only bond an eviction can take is the
    one that has gone longest without connecting — an administrator in regular
    use is never the candidate. Anyone able to arm pairing mode is holding the
    device, at which point the bond store is not the boundary that matters.

    The failed-attempt lockout is a separate, additional gate and survives the
    correction — see increment 1 for the exact predicate. It is per-power-cycle
    and applies only where a PIN is configured; the same physical-possession
    argument bounds its denial-of-service surface, since reaching the pairing
    window at all requires the local gesture.

12. **The snapshot payload is an option list, not a positional record.** Use the
    existing `umsh-core::options` codec, keyed by ULCP property identifier, so
    the format evolves by allocating numbers rather than by migrating. Scoped to
    the snapshot payload only: the counter, identity, and BLE bond journals keep
    their compact fixed encodings, because their constraint is write
    amplification rather than schema evolution.

    **Apply order is local schema metadata, never derived from the identifier.**
    Property numbers were not allocated with ordering in mind, and decision 16
    forbids renumbering them.

13. **Only forward compatibility is supported.** New firmware must read old
    snapshots painlessly: an absent option takes its documented default.
    Firmware rollback is explicitly **not** supported, so no criticality
    encoding is needed — an older image reading a newer snapshot is out of
    scope, and downgrading and then saving is destructive by design. Unknown
    options are skipped.

14. **A rejected snapshot falls back to the previous generation, and rejection
    is never silent.** Two mechanisms, in that order of importance.

    The scenario that motivates this — a deployed repeater that comes back deaf
    and non-forwarding — is precisely the one with nobody attached, so a
    ULCP-visible status reaches no one and a local indication
    (`umsh-ux-tracker` LED or buzzer) tells only whoever is standing there.
    Neither keeps the repeater forwarding. **Falling back to the last snapshot
    that does decode** is the only mechanism that does, and the journal already
    holds one: it is two-page, multi-record, newest-generation-wins.

    Reporting remains necessary — silently running on generation N−1 is its own
    trap — but it is the second line, not the first. An unreadable snapshot must
    still be distinguishable from no snapshot.

15. **Protocol version stays 6.0.** No existing clients require backward
    compatibility; firmware and hosts move together.

16. **The rename preserves the wire.** Every numeric property, command, and
    capability identifier and every BLE service and characteristic UUID keeps
    its current value. Changing UUIDs would break bonded devices for no benefit.

17. **A whole-table `SET` reconciles; it does not rebuild.** Setting
    `PROP_HOST_PEER_KEYS` to a table means "insert the entries the value adds,
    remove the entries the value omits, leave the entries present in both
    **untouched**" — not "build a fresh table and swap it in."

    Call that operation **reconcile**, and use the word consistently. It is a
    replacement at the level of the entry *set* and a preservation at the level
    of per-entry *state*. "Merge" is avoided deliberately: it suggests the
    omitted entries survive, and they do not.

    This is load-bearing rather than stylistic, because a `PeerSlot` carries
    the peer's `ReplayWindow` alongside its key material
    (`crates/umsh-ulcp-device/src/session.rs:663`) and today's handler does
    swap the table (`self.host.peer_keys = table`, `session.rs:2587`). Under
    decision 6 that would reset every peer's replay baseline on every attach,
    many times a day, where the documented resync path assumes reboot frequency
    (`companion-radio-full.md:235`). Reconcile semantics preserve exactly what the
    per-item path preserves today: `PeerKeyTable::insert` already leaves the
    window untouched when the public key matches, and
    `peer_key_replacement_preserves_replay_baseline` pins it.

    Scoped to tables whose entries carry state keyed by identity rather than by
    the provisioned value. `ChannelKeyTable` entries hold only the key and its
    derived identifier (`session.rs:612`), so a swap there is observably
    identical to a reconcile and needs no change; `PROP_HOST_RX_FILTERS`
    likewise. The rule matters for peers, and for anything later given
    per-entry state.

## Increments

Ordered so the conceptual and safety-critical changes land before the mechanical
sweep — doing the rename first means editing the same chapters twice.

Dependencies are not strictly sequential. Increments 1, 2, 3, 5 and 7 are
independent of each other; **4 depends on 2** for the snapshot format; **6
depends on 2 and 3**; **8 comes last** because it touches everything. Increment
2's restore staging is local to increment 2 — with decision 7 deferred, nothing
in increment 4 builds on it. Increment 1 documents an authorization model that only
becomes true in increment 5 — say so in the text rather than letting the spec
read as though it already holds.

Current names (`companion`, `NCP`) are used throughout for current code and
current chapters. Increment 8 renames them; until then they are what the tree
actually says.

### 1. BLE pairing policy, bond store unification, administrative authorization

Two defects in the admission predicate, two divergences in the bond store
underneath it, and an authorization model that has never been written down. They
belong in one increment because the store defects only become reachable once the
predicate is corrected.

The predicate today (`crates/umsh-ulcp-runtime/src/ble_security.rs:13`):

```rust
bond_count < bond_capacity && (pairing_mode || (pin_configured && !locked_out))
```

**A configured PIN must not bypass pairing mode — and lockout must survive the
correction.** `companion-radio-ble.md` requires pairing mode for configured-PIN
pairing — a PIN selects LESC Passkey Entry, it does not authorize enrollment —
with OOB as the only exception. The implementation still allows the bypass, and
the test at :133 asserts the old behavior.

Dropping the `pin_configured` disjunct *naively* is wrong: it reduces the
predicate to `pairing_mode` alone, which silently discards `locked_out` and
violates the normative requirement to reject all further pairing attempts after
the failure limit until power cycle (`companion-radio-ble.md:293`). The non-OOB
predicate is:

```rust
pairing_mode && (!pin_configured || !locked_out)
```

Lockout is conditioned on `pin_configured` deliberately. Its purpose is to stop
LESC Passkey Entry bit-leak probing, and there is no passkey to leak under Just
Works, where the pairing-mode gesture is the entire trust decision. Gating the
unauthenticated path on the same counter would hand an in-range attacker a
denial of service: three failed confirm values during the window and the
legitimate user cannot pair until power cycle.

**Capacity must not gate pairing; a full store evicts LRU** (design decision
11). `bond_count < bond_capacity` is an unconditional pre-SMP gate, so a full
store currently refuses new pairings on both platforms and `upsert_bond`'s LRU
eviction branch is unreachable through normal pairing. This was an oversight.
Remove the capacity term so enrollment at capacity proceeds and evicts the
least-recently-used entry. Update the test at :138–:140, which currently pins
the refuse-when-full behavior, to assert eviction-when-full instead.

Both platforms call the shared policy — nRF at
`firmware/nrf52-tracker/src/main.rs:1254`, Heltec V3 at
`firmware-esp32/firmware/heltec-v3/src/main.rs:521` — so both
corrections land once, in one function, with the tests updated alongside.

**Unify the bond stores.** With eviction reachable again, the divergence becomes
load-bearing rather than cosmetic:

- **Overflow.** The nRF NCP routes through the shared helpers (`upsert_bond` at
  `main.rs:635`). The Heltec V3 NCP hand-rolls `add_bond` with
  `bonds.push(...).map_err(|_| ())?`
  (`firmware-esp32/firmware/heltec-v3/src/ble_store.rs:255`),
  copied from `ble-spike-heltec-v3`.
- **Ordering.** Heltec has no `touch_bond` at all, so its list is
  insertion-ordered. Adopting `upsert_bond` alone would give it eviction that
  evicts the *wrong* bond; `touch_bond` must also be wired into its reconnect
  path, matching `main.rs:1919`.

The `umsh-journal-store` dependency is already present on the Heltec side, so
the change is small. Verification needs the espup toolchain and a Heltec V3 on
the bench.

**State the authorization model**, which increment 5 makes load-bearing. Once
administrative attach no longer claims `PROP_HOST_KEY`, the effective rule is
**"any retained secure BLE bond may administer the device."** Document:

- enrollment — requires pairing mode, i.e. physical presence: armed
  automatically at boot only while no bond exists, and thereafter only by the
  board's local re-arm gesture (decision 11)
- full-store behavior — LRU eviction on enrollment
- revocation — deferred; note the gap explicitly
- **that USB possession confers equivalent authority.** Writing this down
  records the status quo rather than granting anything new: the runtime already
  attaches every transport with `session.attach(true)` — "the wired transport by
  physical possession, BLE because the companion GATT service refuses any access
  outside an encrypted LESC-bonded link"
  (`crates/umsh-ulcp-runtime/src/driver.rs:446`) — so a wired host already
  satisfies `require_secure_link()` (`session.rs:2811`) and can write device
  keys. The rule currently lives only in that comment.
- that nRF and Heltec now share identical rules

**Reconcile all three documents, which currently disagree.** The predicate
appears in three places and no two of them say the same thing:

| Source | Pairing mode required with PIN? | Capacity a term? |
|---|---|---|
| `companion-radio-ble.md:293` | yes (normative) | not mentioned |
| `companion-ble-plan.md:1265` | **no** — states `pairing_mode \|\| (pin_configured && !locked_out)` | no — states LRU eviction |
| `ble_security.rs:13` | **no** | **yes** — refuses when full |

`companion-ble-plan.md:1265` is right about eviction and wrong about the PIN
bypass; it also claims the lockout "is the gate" while writing a predicate in
which lockout applies only on the bypass path it should not have. Update it to
the predicate above. The spec chapter is already correct on pairing mode and
needs only the bond-overflow policy sentence: the eviction language at
`companion-ble-plan.md:388` and `:573` concerns the RX queue, not bonds, and the
de facto specification for bonds is the `upsert_bond` doc comment. State
decision 11 normatively so the unification has something to follow.

### 2. Snapshot payload becomes an option list

The snapshot payload is hand-rolled and positional: a `Writer`/`Reader` pair
emitting fields in fixed order behind `SNAPSHOT_VERSION = 3`, rejecting on
version mismatch (`session.rs:1099`) and on any trailing bytes
(`if reader.at != bytes.len()`, `session.rs:1201`). Every field addition is a
format break by construction, and a break **silently discards saved repeater
enablement and PHY-enabled state**: a firmware update would quietly disarm a
deployed repeater, which comes back deaf and non-forwarding, with recovery
requiring physical BLE proximity.

Replace the payload encoding with the option codec already used for the packet
wire format (`crates/umsh-core/src/options.rs`: `OptionEncoder`/`OptionDecoder`,
CoAP-style delta-length, u16 numbers), keyed by ULCP property identifier. The
snapshot becomes "the saved value of each saved property," which removes a
parallel numbering space and makes adding a savable property a one-line change.

Forward compatibility then falls out of the encoding, which is the only
direction that matters (decision 13):

- new firmware, old snapshot — missing option, apply the documented default
- adding a field — allocate a number; older images are not a consideration
- removing a field — retire the number, never reuse (this is how increment 4
  drops the host domain with no migration code)
- reordering — meaningless in a keyed format

**Apply order comes from an explicit schema table, not from the identifier.**
Ascending-number application would fail: `PHY_ENABLED = 32` precedes
`PHY_FREQ = 35`, `TX_POWER = 37` and `LORA_BW`/`SF`/`CR`/`SW` at 39–43
(`crates/umsh-ulcp/src/ids.rs:24`), so it would enable the PHY *before*
configuring it. Define a static table mapping each saved property to an
`apply_phase` rank: keys and PHY configuration precede the things that depend on
them, and `PHY_ENABLED` applies last. This is local metadata, which is
sufficient — only firmware that knows a property needs to order it.

Note that property identifiers are `u32` in `ids.rs` and reach 4864, while
`OptionEncoder::put` takes a `u16` number. Everything fits; the narrowing should
be deliberate rather than incidental.

**Scope boundary.** This changes only the payload inside a `proto` record. The
journal layer is already content-agnostic — "the journal knows nothing about its
contents" (`crates/umsh-journal-store/src/proto.rs:3`) — so two-page rotation,
CRC, commit-word-last and newest-generation-wins are untouched, and write
frequency is unaffected. The counter, identity, and BLE bond journals keep their
compact fixed encodings. A TLV encoding on the counter map would be actively
wrong: it inflates every entry on a path written once per 128 secured frames
(`COUNTER_PERSIST_BLOCK_SIZE`, `crates/umsh-mac/src/coordinator.rs:44`) to buy
schema flexibility that format has no use for.

Flash wear is not a concern for the snapshot specifically: saving is an operator
action, and the spec already guarantees that nothing is written when properties
change. Increment 4 shrinks the payload further by removing the host domain.

Deliverables:

- the option-list payload encoder/decoder, and the property-number allocation
- **the `apply_phase` schema table**, with ordering constraints expressed as data
  rather than as encoder discipline
- **no migration — but keep a format discriminator.** Legacy v3 positional
  payloads are not decoded: the fielded population is five bench devices and
  they are re-provisioned by hand. The payload still needs a leading format
  byte, because a v3 payload fed to the option decoder does not reliably *fail*
  — its first byte, `0x03`, reads as a well-formed option header (delta 0,
  length 3) — so without a discriminator a stale snapshot mis-decodes into a
  plausible-looking domain instead of being rejected. Reject anything that is
  not the current format, through the same non-silent path below.
- **a persisted form for write-only key material.** Channel and peer keys have no
  GET form (lossy readback only), so "snapshot = property list" is an organizing
  principle, not a literal identity.
- **restore into a candidate domain, committed atomically.** This is *not* the
  deferred transaction of decision 7 and does not depend on it: it is local to
  the restore path, needs no new commands, and exists for a hazard that has no
  "assume it does not happen" escape — a malformed option arriving late in a
  decode must not leave the device half-configured, and a corrupt snapshot is
  precisely the case that occurs. Not the live SET
  path literally: device channel-key writes sit behind `require_secure_link()`
  (`session.rs:2591`, with the test `identity_and_dev_channel_writes_require_a_
  secure_link`), and at boot there is no authenticated attached link. Decode and
  validate every option into a candidate domain using the *shared value
  validators*, bypassing transport authorization, then commit in one step and
  emit the required effects. This preserves the existing "no state is modified on
  error" contract, which a late malformed option would otherwise violate. Most
  key-bearing setters already have the right shape — `HOST_CHANNEL_KEYS`,
  `HOST_PEER_KEYS` and `DEV_CHANNEL_KEYS` all build a local table and assign only
  on success (`session.rs:2561`, `:2576`, `:2590`). The outliers are
  `HOST_RX_FILTERS` (`:2555`) and `DEV_PEERS` (`:2607`), which assign a parse
  result directly, so part of this is aligning those rather than a rewrite.
- **fall back to the previous committed generation on payload rejection.**
  Record-level recovery already exists — `consider_record`
  (`crates/umsh-journal-store/src/proto.rs:150`) keeps the newest valid record
  and ignores corrupt or uncommitted ones — but payload-level rejection has no
  equivalent, so a record whose CRC is fine and whose options do not decode
  takes the device to a bare boot while an older, readable generation sits in
  the journal. On rejection, re-scan for the newest committed record older than
  the rejected one and try that. Re-scanning rather than retaining a runner-up
  keeps the mount path's "never buffers a second copy" discipline
  (`proto.rs:67`) intact, and mount cost is paid once per boot. **Bound the
  walk**: a systematically undecodable payload — a firmware bug rather than
  corruption — otherwise re-walks the whole journal on every boot. Stop after a
  small fixed number of generations and boot bare, reported.
- **make rejection non-silent** — a status, or `PROP_SAVED` distinguishing
  "none" from "unreadable", plus the local indication of decision 14. With the
  fallback above, what this reports is "running on generation N−1", which is
  both more actionable and more urgent than "something was wrong." Note that
  `PROP_SAVED` is a bool today (`self.saved.is_some()`, `session.rs:3029`), so
  this is a deliberate *semantic* change to an existing property — the one
  exception to increment 8's "identifiers and meanings unchanged," and cheap
  only because protocol version 6.0 has no clients to break (decision 15).

### 3. Device identity always exists

- Generate the device keypair at first boot when the identity journal is empty,
  from the hardware TRNG, and persist it immediately.
- **Reconcile the reset paths, which currently contradict the invariant.** The
  spec says `CMD_CLEAR` erases the device identity private key and that "Live
  (in-RAM) state is unaffected" (`companion-radio-full.md:441`). Decide and write
  normatively:
  - **`CMD_CLEAR` + `CMD_RST`** is the real gap. `CMD_RST` is a protocol reset,
    not a reboot, so nothing triggers first-boot generation and the device sits
    identityless until power-cycled. Either regenerate immediately on `CMD_CLEAR`
    (changing the "live state unaffected" contract) or regenerate on `CMD_RST`
    (keeping it). State which.
  - **`CMD_FACTORY_RESET` needs no change.** It reboots, so first-boot generation
    fires, and "indistinguishable from one that has never been provisioned"
    (`:526`) still holds — a never-provisioned device also auto-generates.
  - **What `CMD_CLEAR` reports if regeneration persistence fails**, since it must
    now write as well as erase.
- Specify ordering and error semantics for regeneration. Interruption is
  self-healing because first-boot generation covers it, so this is a
  documentation-and-ordering task rather than an invariant hazard.
- Delete the "dormant unless a device identity exists at boot" branch in
  `device_node.rs` — the node always exists; the only question is whether it is
  transmitting.
- `PROP_DEV_PRIVATE_KEY` stays as a write path, for restoring a known repeater
  identity onto replacement hardware. This does not reopen identity as a
  commissioning step (design decision 8): the device already has a working
  identity when the write arrives, and installing a specific one is recovery,
  not setup. Note the consequence — a device generates and persists a key before
  anyone installs one, so a replacement briefly holds a throwaway identity. On
  a device with no snapshot it never reaches the mesh, because the PHY defaults
  to disabled (`DeviceDomain::post_reset`, `session.rs:311`); that default is
  load-bearing for this invariant, and the next bullet is the path where it
  does not apply.
- **Restore must not outrun key installation.** The snapshot carries
  `PROP_PHY_ENABLED`, but the identity lives in its own journal, so restoring a
  saved device domain onto replacement hardware *before* writing
  `PROP_DEV_PRIVATE_KEY` brings the PHY up under the auto-generated throwaway
  key — advertising as the repeater the snapshot describes, under the wrong
  identity. The post-reset default does not cover this path, because the
  snapshot overrides it. Require key installation to precede `CMD_RESTORE`, or
  have restore leave the PHY disabled when the restored domain expects an
  identity that is not installed. State which.

### 4. Volatile host domain

The largest behavioral change, and a net simplification. Depends on increment 2.

- `CMD_SAVE` snapshots the **device domain only**. Host-domain configuration
  (`PROP_HOST_KEY`, channel keys, peer keys, RX filters, auto-ack) is never
  persisted and takes its documented post-reset values at boot.
- The Host Replacement durable wipe disappears: `PROP_HOST_KEY` writes no longer
  need the `WipeHostDomain` effect (`session.rs:169`), removing a deferred
  transaction from the firmware effect set.
- `CMD_RESTORE` loses its host-domain clause, including the "if the snapshot's
  host key differs from the live one" special case
  (`companion-radio-full.md:471`).
- Host side implements unconditional whole-table re-provisioning per design
  decision 6, in `UlcpDevice` (`umsh/src/companion_radio.rs:856`),
  `umsh-ulcpctl`, and the iOS path. This replaces the current
  compare-then-patch logic in `provision()` (`companion_radio.rs:1486`), which
  exists to avoid re-sending secrets the NCP already holds — a concern that
  disappears once the device side reconciles.
- Device side adopts reconcile semantics for `PROP_HOST_PEER_KEYS`
  (decision 17), so re-provisioning preserves per-peer replay baselines and only
  a reboot restarts them. Without this, decision 6 resets every baseline on every
  attach.
- **No staging transaction.** Provisioning writes the live host domain with the
  existing property frames (decision 7); atomicity is deferred, and the hazard
  it would cover is bounded below.

**Why provisioning is per-item, not whole-table.** This is a frame limit, not an
atomicity argument, so it holds regardless of the decision 7 deferral. Nothing in
the tree sends a whole peer table today — the shipped host path inserts and
removes one peer at a time (`umsh/src/companion_radio.rs:1569`) — so what follows
is a constraint on the *literal* reading of decision 6, not a latent defect being
repaired.

It is a hard constraint on that reading, and the binding number is not the one
it looks like. The ceiling is `driver::FRAME_IN_MAX = 300`
(`crates/umsh-ulcp-runtime/src/driver.rs:45`), not the 512-octet GATT
reassembly bound: both transports funnel through
`FrameBuf = heapless::Vec<u8, 300>`, the BLE path staging its reassembled frame
into one (`firmware/nrf52-tracker/src/main.rs:2079`) and the serial path
decoding straight into `hdlc::Decoder<FRAME_IN_MAX>` (`main.rs:2464`). A
`PeerKeyEntry` is 64 octets (`crates/umsh-ulcp/src/items.rs:57`), so with a
header octet, a command octet and the PUI-encoded property number, a whole-table
`SET` stops fitting at the **fifth** peer (323 against 300); the full eight-entry
table is 515. There is no transport-dependent divergence — the cliff is the same
on USB-CDC and BLE — but there is a worse property: the drop is **silent**. An
oversized frame reassembles correctly and dies at the staging step with a debug
log and no status frame, so the host times out rather than seeing `NOMEM`.
Whatever else changes, that drop should become a visible status.

Raising the ceiling is the alternative, and it does not survive the roadmap.
`MAX_PEER_KEYS` is 8 today (`crates/umsh-ulcp-device/src/session.rs:607`) and
the target is 100+; a hundred-entry table is 6400 octets, which no frame size
carries. **Per-item provisioning is therefore the permanent shape, not a
workaround for a small buffer.** For the record, the mechanical cost of a raise
is smaller than it first appears — the SAR header is two bits of state with no
length field (`crates/umsh-ulcp/src/gatt.rs:16`), so there is no wire
encoding to re-verify — but it is a normative spec change
(`docs/protocol/src/companion-radio-ble.md:146` fixes 512 octets) and roughly 19
frame-sized buffers per NCP image make it real RAM. Neither is worth spending on
a mechanism with a known replacement.

So decision 6's "in full, every time" is a claim about **semantics** — the host
asserts the complete desired domain and never reasons about what the device
already holds — not about frame shape. It is delivered as a `GET` of the digest
list, a `REMOVE` per omitted entry, and an unconditional `INSERT` per desired
entry.

**Scope of the interruption hazard.** Worth stating precisely, because it is
narrower than it first appears. A `PROP_HOST_KEY` write to a *different* key
already wipes the whole host domain behind a durable transaction
(`session.rs:2444`), and writing the *same* key is idempotent with no side
effects (`:2447`); after this increment the host domain is empty at boot. So a
mixture of old and new state can only arise when re-provisioning a
still-powered, already-provisioned radio under an unchanged host key — not on
the reboot-recovery path that motivates the increment. **This is the whole of
what decision 7's deferral accepts**, and an interrupted attempt leaves the
device forwarding on its device domain, repaired by the next attach's
unconditional rewrite.

**Do not reach for the PHY as the guard.** With staging deferred, this is the
tempting wrong fix, so it is worth ruling out explicitly. Disabling
`PROP_PHY_ENABLED` around provisioning looks like a cheap substitute and is not:
`PROP_PHY_ENABLED` is device-domain saved state, so tethered host provisioning
would mutate the device domain — the mirror of design decision 4, one increment
before increment 5 codifies that separation. On a forwarding repeater it stops
forwarding for the whole mesh rather than for this host. And leaving it disabled
after a failed attempt turns a walk-away into an outage recoverable only by a
physical revisit — to perform the local re-arm gesture of decision 11. If
it ships anyway as a stopgap, it **MUST** be bounded: on expiry the device
re-enables the PHY with the host domain empty, the state it would have had after
a reboot.

Tests should interrupt after each property write and assert the resulting state
— *documenting* the mixture rather than asserting it away, since atomicity is
deferred. What they pin is that every interruption point is recoverable by a
subsequent full re-provision, which is the property decision 6 actually relies
on.

This aligns the host domain with the state already surrounding it: replay
baselines already restart on reboot with a documented resync path
(`companion-radio-full.md:235`).

**Note the limit of the safety argument.** Volatile storage makes a
two-radios-one-host-identity misconfiguration self-healing rather than sticky.
It does not prevent a phone from provisioning two powered-on radios in
succession. The "one active tether at a time" invariant still lives on the host.

### 5. Administrative attach vs tethered attach

- Spec: name the two relationships in `companion-radio.md` and state that
  administrative attach touches only the device domain.
- Host workflow: an attach mode that never writes `PROP_HOST_KEY` and never
  provisions host keys or filters. `attach_existing` already never writes PHY
  configuration (`umsh/src/bin/umsh_ulcpctl.rs:656`); this extends the same
  discipline to the host domain.
- `umsh-mobile-core`: distinct API surfaces, so the iOS app models "my radio"
  (exactly one, tethered) and "radios I administer" (N, device-domain only) as
  different object types with different lifecycles. Do not let one list serve
  both.

**Regenerate the UniFFI surface in this increment**, rather than batching it with
increment 8's rename. Batching would save one regeneration at the cost of being
unable to test the administrative/tethered separation until after a large
mechanical sweep. Regeneration is cheap; testability is not.

### 6. Identity properties

- `PROP_IDENT` (read): the complete signed node identity blob, served through
  the `SignIdentity { tid }` / `respond_identity_blob()` effect pair per design
  decision 9. Canonical contents are nonce-free and timestamp-free.
- `PROP_IDENT_ROLE` (get/set): the `ROLE` byte.
- `PROP_IDENT_MOBILE` (get/set): the `MOB` capability bit — mobile versus fixed,
  which is orthogonal to tethered versus standalone.
- No `PROP_IDENT_CAPS`. The remaining bits are derived from firmware facts and
  live configuration.
- **Resolve the role/forwarding conflict.** Today `device_node.rs:178` derives
  *both* role and capabilities from the repeater flag, and the spec says
  enabling repetition advertises `NodeRole::Repeater`
  (`companion-radio-full.md:905`). An independently writable `PROP_IDENT_ROLE`
  contradicts that. Define defaults and migration behavior for the four
  dimensions in design decision 3.
- Share the canonical unsigned payload builder with the Identity Request
  responder per design decision 10.
- `docs/protocol/src/node-identity.md:32`: rename role value 3 from
  "Tracker/Companion-Radio" to **"Tracker"**.
- Allocate from the reserved 71–95 device-behavior range. No snapshot work is
  needed: increment 2 made saving these a matter of allocating option numbers.

### 7. Firmware image consolidation

Per-board disposition, to be completed before any CLI image is retired:

| Board | MCU | NCP image | CLI image | Transports | Flash/RAM (of budget) | Disposition |
|---|---|---|---|---|---|---|
| T-1000E | nRF52840 | yes | yes | BLE, USB-CDC | 605/117 KiB (756/256) | NCP ships; CLI retired |
| T-Echo | nRF52840 | yes | yes | BLE, USB-CDC | 617/126 KiB (756/256) | NCP ships; CLI retired |
| SenseCAP Solar | nRF52840 | yes | yes | BLE, USB-CDC | TBD | NCP ships; CLI retired |
| Heltec V3 | ESP32-S3 | yes | yes | BLE, UART | TBD | NCP ships; CLI retired |
| Wio Tracker L1 | nRF52840 | **none** | yes | USB-CDC | TBD | **undecided — see below** |

**Wio Tracker L1 is the open hole.** There is no `wio-tracker-l1`,
and bringup reached Phases 0–1 only (USB-CDC, heartbeat, safety primitives).
Retiring its CLI image as written would leave the board with no image at all.
Decide: build the NCP image, or park the board and say so explicitly.

Remaining deliverables:

- fill in the TBD size figures and name a validation target per board
- retire `companion-cli-*` from the product matrix, keeping the CLI pattern as a
  per-board bringup harness — it is currently the only thing exercising the
  non-BLE path and the natural tool for a new board before BLE stands up — or
  fold the console into the single image behind a feature
- update the Makefile targets, `docs/firmware-architecture.md`, and CLAUDE.md's
  repository layout

### 8. Rename to ULCP

Mechanical, last, in one sweep. ~157 files currently mention "companion"
(`.rs`/`.md`/`.toml`/`.swift`/`.lua`).

**"ULCP" names only the protocol**, so renaming to it alone leaves the two
*actors* unnamed — and "NCP" is an actor noun today. The work is separating the
layers that "companion radio" and "NCP" currently blur, which is why one of them
is retired and the other is kept:

| Layer | Today | After |
|---|---|---|
| the protocol | companion radio protocol, CRP | **ULCP** |
| the controlled actor | companion radio, NCP | **device** |
| the controlling actor | host | **host** (unchanged) |
| the attach relationship | (unnamed) | **tethered** vs **administrative** (increment 5) |
| how a device is deployed | companion radio, repeater | **companion radio**, **repeater** (kept) |

**"NCP" is retired outright rather than renamed.** It is a Spinel borrow —
Network Co-Processor — and it names the exact assumption this plan removes: a
co-processor is subordinate to a processor, and after increment 4 the device runs
autonomously with no host at all. A pole-mounted repeater is not a co-processor
to anything. There is also no need to coin a replacement, because the codebase
already carries the right pair: the property namespace is `PROP_DEV_*` versus
`PROP_HOST_*`, the session holds a `DeviceDomain` beside a host domain, and
increment 5 splits attach into administrative and tethered. **Host and device are
already the two sides of ULCP** — "NCP" is a third name for a thing that has one.

**"Companion radio" is kept, demoted from actor to deployment.** It is not a
competing name for the protocol actor the way "NCP" is — it is the name of a way
a device is *used*, and it sits alongside "repeater" as one of a small set of
recognizable deployments. Both are well understood outside this project, and
decision 2 already has the slot for them: role is configuration, and "any
'profile' concept is a host-side preset that expands into properties." These are
those presets. Collapsing the build matrix removes the compile-time fork, not the
vocabulary — a companion radio and a repeater are the same image holding
different property values, and naming those points in the configuration space is
useful precisely because the code no longer distinguishes them.

The line to hold is **where each word is allowed to appear**:

- **normative prose says "device."** "The companion radio **MUST**" would state
  a requirement that appears not to bind a repeater, which is the failure mode
  "the NCP **MUST**" has today. Every requirement in the spec binds the device,
  in every deployment.
- **deployment discussion says "companion radio" or "repeater"** — the
  configuration presets, the iOS onboarding copy, the increment 7 board matrix,
  and anything describing intent rather than obligation.

Increment 5 gives the same split a home in the API: if its
"my radio" versus "radios I administer" separation produces two host-side types,
**companion radio is the right name for the tethered one** — it is the object
that models exactly that deployment.

Mappings:

- **Spec:** `companion-radio.md` → `ulcp.md`, `-minimal` → `ulcp-minimal.md`,
  `-full` → `ulcp-full.md`, `-ble` → `ulcp-ble.md`; `SUMMARY.md` alongside. In
  prose, every normative "the NCP **MUST**" becomes "the device **MUST**" — the
  bulk of the sweep, and the reason this increment is last.
- **Crates:** `umsh-companion` → `umsh-ulcp` (shared wire format);
  `umsh-companion-ncp` → `umsh-ulcp-device` (the sans-I/O device session);
  `umsh-companion-runtime` → `umsh-ulcp-runtime` (unambiguously device-side —
  there is no host runtime crate); `umsh-app-companion-cli` →
  `umsh-app-ulcp-cli`; `umsh-companionctl` → `umsh-ulcpctl`.
- **Host-side types:** `CompanionRadio` (`umsh/src/companion_radio.rs`) →
  `UlcpDevice`, since today it is the general handle to any device and is used
  for administration as much as for tethering. **If increment 5 splits it**, the
  tethered half may take `UlcpDevice` back — at that point the name would be
  accurate rather than vestigial.
- **BLE:** "Companion Link Service" → "ULCP GATT Service". The existing
  `SERVICE_UUID` / `FRAME_IN_UUID` / `FRAME_OUT_UUID` symbol names are already
  neutral and keep both their names and their values.
- **`PROP_NCP_VERSION` → `PROP_DEV_VERSION`**, not `PROP_ULCP_VERSION`. It
  carries the *device firmware* version string, and the protocol version is a
  separate property already (`PROTOCOL_VERSION`, id 1
  (`crates/umsh-ulcp/src/ids.rs:17`)), so a ULCP-flavored name would assert
  the wrong thing. `DEV_VERSION` also matches the `DEV_KEY`/`DEV_NAME`/`DEV_PEERS`
  neighbours it sits with. Numeric identifier stays 2.
- **Firmware directories** depend on increment 7 and should land with it: once
  the role axis collapses and `companion-cli-*` retires, `companion-ncp-<board>`
  has nothing to disambiguate against and becomes `firmware/<board>`. If a
  console image survives as a bringup harness, it is `firmware/<board>-console`.
- **iOS: keep the `UMSHMobileCore` package and module name.** That package spans
  mesh, chat, identity, and persistence as well as local-control integration;
  renaming it would misname the broader mobile facade. Rename only the
  device/ULCP-specific symbols and files.
- **Unchanged:** all numeric property, command, capability and status
  identifiers, and all BLE UUIDs (decision 16).

Acronym note: bare "LCP" collides with PPP's Link Control Protocol, in the same
conceptual neighborhood. **ULCP** costs one character and removes the ambiguity.

Watch for the one collision this creates: "device" is already load-bearing in
`DeviceDomain`, `PROP_DEV_*` and "device identity", which is *why* it is the
right word — but prose that previously distinguished "the NCP" from "the device
identity" now has to lean on "the device's identity" or rephrase. The spec sweep
should read for that rather than substitute blindly.

## Open questions

1. **Wio Tracker L1 disposition** (increment 7).
2. **The pairing re-arm gesture, per board.** The window opens automatically at
   boot only while no bond exists; re-arming a bonded device is a deliberate
   local gesture, and the boards do not all have the same one. Name it per
   board, and for any board without a power button to hold, say what stands in
   for it. This is a documentation gap, not a design gap: increment 1 makes
   pairing mode strictly required, and the gesture is what keeps that from
   being a field-recovery problem.

## Related, sequenced after this work

Fleet management needs a **read** path before a **write** path. "Which repeaters
have I commissioned, are they alive, what is their battery and duty" is the first
thing the iOS app will want, and the answer arrives over the mesh, not over BLE.
That is telemetry from the periodic identity broadcast plus in-band queries, and
it has far weaker authorization requirements than reconfiguration. Repeater
*observability* can therefore ship well before repeater *administration* over the
air — and observability is what makes a commissioned fleet feel real.

## Implementation status

### Landed

**Increment 1 — BLE pairing policy, bond store, authorization.**
`pairing_enabled` is now `pairing_mode && (!pin_configured || !locked_out)`
with the capacity term removed entirely; the Heltec V3 bond store routes
through `upsert_bond`/`touch_bond` and drops LRU-evicted bonds from the
live trouble table like the nRF side. `ulcp-ble.md` gained
normative bond-overflow rules and an Administrative Authorization
section; `companion-ble-plan.md`'s predicate was corrected.

**Increment 2 — snapshot payload is an option list.** Format byte 4 plus
a `umsh-core::options` block keyed by ULCP property identifier, driven by
`SAVED_SCHEMA` with an `ApplyPhase` per row so apply order is data rather
than identifier order. Absent options take documented defaults; unknown
numbers are skipped; repeated single-valued properties are rejected.
Values pass the same validators the live setters use, factored out for
the purpose. Boot walks back up to `SNAPSHOT_FALLBACK_LIMIT` older
generations through `DeviceEnv::older_snapshot`, and `PROP_SAVED` became a
UINT8 distinguishing none / current / fallback / unreadable end to end
(device, `umsh`, `umsh-mobile-core`, iOS).

**Increment 3 — device identity always exists.** Generated from the
hardware TRNG at first boot and persisted before anything observes its
absence; nRF bias correction enabled for all key material. `CMD_CLEAR` +
`CMD_RST` regenerates rather than leaving the device identityless — the
`CMD_CLEAR` "live state unaffected" contract is preserved. The device
node's transmit gate became key equality rather than presence, which also
closes the pre-existing hole where installing a new `PROP_DEV_PRIVATE_KEY`
left the node signing as the old identity. A snapshot records
`PROP_DEV_KEY` as provenance and a restore under a different identity
withholds the PHY enable, making the replacement-hardware ordering safe
rather than merely documented.

**Increment 4 — volatile host domain.** Property numbers 96–100 are
retired from the snapshot schema; `Effect::WipeHostDomain`,
`respond_host_wipe` and `encode_wiped_snapshot` are gone and a
`PROP_HOST_KEY` change is one assignment. `PROP_HOST_PEER_KEYS`
whole-table `SET` reconciles (`PeerKeyTable::reconcile`), preserving
replay windows. `provision()` writes everything unconditionally, removing
only what the readable digest lists say is unwanted.

**Increment 5 — administrative vs tethered attach.** `AttachMode` on the
host handle, `UlcpDevice::attach_administrative`, and a guard that refuses
host-domain writes; `umsh-ulcpctl` attaches administratively for every
command but `provision`. `MobileUlcpSession::administrative()` refuses
`claim`. Spec: "Two Kinds of Attach" in `ulcp.md`.

**Increment 6 — identity properties.** `PROP_IDENT` (71) served through
`Effect::SignIdentity` / `respond_identity_blob`, `PROP_IDENT_ROLE` (72,
empty = derive), `PROP_IDENT_MOBILE` (73), `CAP_IDENT` (41). Role and
forwarding are separated: the `REP` capability bit tracks live forwarding,
the role is configuration. `NodeIdentityProfile::to_payload` is now the
one canonical builder, used by the Identity Request responder, the
solicited advertisement, and the `PROP_IDENT` read.

**Increment 7 — image consolidation.** Sizes measured and recorded in
`docs/firmware-architecture.md`; Wio Tracker L1 parked explicitly;
`companion-cli-*` retained as per-board bringup harnesses and excluded
from the shipping matrix.

**Increment 8 — rename, partial.** Landed: crate renames
(`umsh-ulcp`, `umsh-ulcp-device`, `umsh-ulcp-runtime`,
`umsh-app-ulcp-cli`, `umsh-ulcp-web-engine`); `umsh::ulcp::UlcpDevice`;
`umsh-ulcpctl`; `PROP_NCP_VERSION` → `PROP_DEV_VERSION`; every `Ncp*`
identifier retired in favor of `Device*`; firmware directories
(`firmware/<board>` and `firmware/<board>-console`) with deprecated
Makefile aliases for the old flash targets; `umsh-mobile-core`'s module
and UniFFI symbols.

**Spec chapters (2026-07-26).** `ulcp.md` (title "Local Control Protocol
(ULCP)"), `ulcp-minimal.md`, `ulcp-full.md`, `ulcp-ble.md`; `SUMMARY.md`
retitled alongside. The prose sweep is complete: every normative "the NCP
**MUST**" is now "the device **MUST**", the protocol is named ULCP
throughout, "Companion Link Service" became "ULCP GATT Service" (anchor
`#ulcp-gatt-service`), and "companion radio" survives only in deployment
discussion, as intended. Repo-wide references to the old chapter
filenames were rewritten (this plan's pre-rename `file:line` citations
excepted, deliberately). Numeric identifiers and BLE UUIDs untouched.
mdBook builds clean.

**Dissector and planning docs (2026-07-26).** `ulcp.lua` swept
(proto/filter names `umsh.companion.*` → `umsh.ulcp.*`, protocol column
`UMSH-ULCP`, directions Host → Device / Device → Host; wire decoding
untouched) and the silently broken `require("companion")` in `umsh.lua`
fixed to `require("ulcp")`; `dissectors/README.md` updated. Planning
docs renamed (`docs/companion-*` → `docs/ulcp-*`), and completed plans
moved to `docs/archive/` (the four ULCP plans, `firmware-storage-plan`,
and the five finished/parked board bringup plans — Wio Tracker L1's
stays active as the forward roadmap); references to archived plans were
removed from code comments, Cargo/Makefile/memory.x comments, and living
docs rather than repointed. UX book swept (only four hits were protocol
terminology; "companion app/phone/radio" as UX/deployment language
stays). Host workspace `cargo check` clean.

**Firmware straggler symbols (2026-07-26).** The live identifiers the
increment-8 rename missed are gone: `CompanionServer`/`CompanionService`
→ `UlcpServer`/`UlcpService` (with the `companion:` GATT field now
`ulcp:`) across the techo/heltec-v3 mains and all three BLE spikes;
`ble-spike-heltec-v3/src/companion.rs` → `ulcp.rs` with its `Companion`
responder renamed `UlcpResponder` (this fixed a real breakage — the
spike's `mod ulcp;` was already renamed but the file and use sites were
not, so the crate did not compile); `NCP_VERSION` →
`DEV_VERSION` and `COMPANION_TX_QUEUE_CAPACITY` → `ULCP_TX_QUEUE_CAPACITY`.
Device-visible strings updated too: BLE names drop the suffix
(`"UMSH T-Echo NCP"` → `"UMSH T-Echo"`, likewise T-1000E/Solar), USB
product strings say `UMSH Radio`, and `dev_version` values drop the
`-ncp-` segment (`umsh-ncp-techo` → `umsh-techo`). NCP prose in those
mains swept. Compile-checked from each firmware directory: techo,
t1000e, sensecap-solar, ble-spike-techo (nRF) and heltec-v3,
ble-spike-heltec-v3, ble-spike-heltec-v2 (ESP32) — all clean.

**Rust prose and host stragglers (2026-07-26).** The ~560 residual
companion/NCP mentions are gone from the Rust tree, manifests, web
debugger, README, CLAUDE.md, and Makefile comments. The sweep also
caught live identifiers the earlier audit had miscounted as prose:
the umbrella re-export `umsh::companion` → `umsh::ulcp_wire` (the plain
`ulcp` name is taken by the host-client module), `HostToNcp` →
`HostToDevice` in the host trace, capture, and debugger-engine
direction enums (the engine's serde tag feeds the debugger UI, so
`shell.js`/`style.css` moved with it — fixing the already-stale
`.ncp_to_host` CSS rule), the debugger's `sim-ncp` feature →
`sim-device` and `SimulatedNcp` → `SimulatedDevice` (wasm-bindgen JS
name included), and `umsh-capture`'s capture layer `companion` → `ulcp`
(`--capture=companion` still accepted as an undocumented alias). Test
fixtures renamed (`Test UMSH NCP` → `Test UMSH Device`, `sim-ncp/0.1` →
`sim-dev/0.1`, etc.). README's stale advertised-name instructions
corrected to the new `UMSH T-Echo`/`UMSH T-1000E`. What deliberately
remains: "companion radio" as the deployment name for the tethered
device, `flash-companion-*` Makefile targets (already just aliases for
the canonical `flash-<board>` targets), and `umsh-mobile-core`'s
UniFFI-exposed `Companion*`/`companion_*` symbols, which must move
together with the Swift rename and binding regeneration. Fixed in
passing: four pre-existing compile errors in `ulcp_hw_validate.rs` and
`ulcp_full_protocol.rs` from earlier-increment API drift (`sync.saved`
became `Option<SavedSnapshot>`, `ProvisionReport::changed()` was
removed, `Effect::SignIdentity` was unhandled) — nothing had run
`cargo check --all-targets` with the tokio features since. Verified:
workspace check `--all-targets` clean, `umsh` + `umsh-ulcp` +
`umsh-ulcp-device` + `umsh-mobile-core` + web-engine test suites green,
techo/heltec-v3/ble-spike-heltec-v3 firmware re-checked from their own
directories. (Known pre-existing, unrelated: `--all-features` cannot
*link* host examples because `embassy-support` + `tokio-support`
collide on the embassy timer-queue symbol; `cargo check` doesn't
surface it.)

**Swift and UniFFI surface (2026-07-26).** `umsh-mobile-core`'s last
UniFFI-exposed companion symbols renamed (`CompanionRawTransmit*` →
`UlcpRawTransmit*`, `companion_factory_reset` → `ulcp_factory_reset`,
plus the private `ulcp_refresh_properties`/`ulcp_operation_error`
helpers) and the bindings regenerated via
`scripts/ios/build-mobile-core.sh` — the committed
`UMSHMobileCore.swift` had been stale since before the
`MobileCompanionSession` → `MobileUlcpSession` rename. iOS app swept:
`CompanionToolbarItem` → `RadioToolbarItem` (file, struct, pbxproj),
`companionSession` → `ulcpSession`,
`RadioConnectionError.companionNotFound` → `.radioNotFound`,
`companionGattSegments` → `ulcpGattSegments`, and all protocol-level
companion/CRP/NCP prose and log/problem strings moved to ULCP/device
terms; "companion radio" stays wherever it is the user-facing
deployment name (UI copy, and the persisted `companion_radio`
system-role value is wire/DB data, untouched per decision 16). The
Settings "Protocol tier" value `Full companion` is now `Full ULCP`.
Fixed in passing: `RadioSnapshot.swift` referenced the FFI
`SavedSnapshotRecord` without importing `UMSHMobileCore` — same
earlier-increment drift class as the host examples; nothing had built
the app since. Verified: bindings regenerated clean (one deployment-name
doc comment remains), xcframework rebuilt, `umsh-mobile-core` tests
green, and the app builds for the iOS simulator.

**Spec restructure (2026-07-26).** The minimal and full chapters are
merged into one spec under `ulcp.md`: `ulcp-core.md` (framing, command
grammar, property model, state classes, attach/sync, provisioning
security, and the status/reset/capability registries) plus one subchapter
per subsystem — `ulcp-radio.md`, `ulcp-transport.md`, `ulcp-device.md`,
`ulcp-saved-state.md`, `ulcp-host.md` — each carrying its own
capabilities, commands, and properties. `ulcp-conformance.md` replaces the
minimal/full split with a conformance statement (what every device
implements, what is capability-gated, and what is required of hosts), and
`ulcp-index.md` lists every command, property, stream, status code, reset
code, capability, and enumerated value with a link to its definition.
`ulcp.md`'s four capability groups became the five subsystems, matching
the chapters.

The 81 bare `(#anchor)` cross-references, which rendered as literal text
and would have been silently wrong across files, are now real markdown
links; a link checker over `docs/protocol/src` reports zero broken
intra-book links in the ULCP chapters. Two substantive corrections fell
out of the merge: the property-allocation table gave host domain 96–127,
which collides with `STR_PHY_RAW` at 113 — it is now 96–111 host domain,
112–127 streams, with the extended ranges (4608–4863, 4864–5119)
documented — and the reset-code list now names `STATUS_RESET_RESTORED`
among the codes emitted in normal operation. `PROP_IFACE_TYPE` in the old
property table is `PROP_INTERFACE_TYPE` everywhere, matching the code.

`ulcp-minimal.md` and `ulcp-full.md` remain in the book, each opening
with a note pointing at the chapters that replaced it.

### Remaining

- **Hardware validation.** Nothing here has been on a bench. The
  BLE pairing correction (increment 1) needs both an nRF board and a
  Heltec V3; the snapshot format, first-boot identity generation, and the
  volatile host domain all need a power-cycle test on real hardware.
