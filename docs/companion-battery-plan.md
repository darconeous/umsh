# Companion Radio Battery Capability — Implementation Plan

Add implementation support for `CAP_BATTERY` (39) and `PROP_BATTERY` (69)
from `docs/protocol/src/companion-radio-full.md`: a single read-only
property whose value is a battery status snapshot — a field-flags octet
followed by the fields the platform supports (voltage `UINT16_LE` mV,
level `UINT8` percent, charge state PUI) — or an empty value when the
platform reports nothing.

Status: **Drafted and revised 2026-07-18 (single snapshot property,
sample-on-request, platform-abstracted readings). Increments 1–4
implemented same day; all host-side gates green. Increment-5 hardware
acceptance passed same day on both boards over USB and BLE — T-1000E
flags `0b101` with live sampling proven (consecutive reads return
different millivolt values), rapid post-boot reads sample on demand,
restore leaves telemetry live; T-Echo empty value displayed as
unsupported everywhere. Remaining: the charge-state transition
observation (unplug/replug the T-1000E charger and watch
Discharging/Charging/Charged follow), which needs an operator.**

Same-day follow-up: the `no-ble` diagnostic build now has working
persistence. MPSL, the shared flash driver, and every journal mount in
both images (the flash driver needs only the MPSL timeslot scheduler,
not the BLE controller); `no-ble` skips just the SDC/Trouble
construction. The stub `ProtoStore` and the fail-closed persistence
carve-outs are gone. Hardware-verified on the T-1000E: the `no-ble`
image restored the saved snapshot, identity, and provisioning, and
committed a new snapshot write; the production image then read that
snapshot back — journal compatibility in both directions.

## Goals

- Make the shared wire vocabulary, NCP session, host API, simulators, tools,
  and hardware firmware agree on the new identifiers and the snapshot
  encoding.
- Preserve the spec's distinction between **battery-powered operation** and
  **measurement support**: `CAP_BATTERY` asserts the former; an empty value
  (or an absent field) asserts only that reporting is unsupported.
- Sample at request time. A `GET` performs a measurement; the NCP never
  serves a cached reading, so there is no staleness window, no validity
  flag, and no boot-ordering race to manage.
- Keep exactly one owner per measurement path. The protocol asks the
  existing board power owner for a reading; it never touches the ADC, the
  sensor rail, or the charger pins itself.
- Abstract the readings per platform. The session and the shared firmware
  see one "sample the battery" operation returning optional fields; which
  fields exist, and how each is produced, is platform policy. In
  particular, level is not assumed to derive from voltage — a fuel-gauge
  platform may report level without reporting voltage at all.
- Keep battery state live and read-only. It must not enter the saved-state
  snapshot, host domain, device provisioning, or reset/restore machinery.
- Fail closed. A supported field that cannot currently be measured fails
  the `GET` with `STATUS_FAILURE`; empty and absent-field forms are
  reserved exclusively for unsupported reporting.

## Non-goals

- Deriving a percentage from battery voltage. Neither current NCP board has
  a fuel-gauge-backed percentage implementation ready to expose.
- Inventing charger state for hardware that cannot distinguish all three
  protocol states.
- Persisting battery readings or using them to change the existing
  low-battery shutdown policy.
- Adding a BLE Battery Service. The snapshot remains a companion-radio
  property carried over the existing USB or BLE frame transport.
- Emitting unsolicited battery updates in the first increment. The spec
  allows them but does not require them; ordinary `GET` responses are
  sufficient for initial support, and the host already retains generic
  unsolicited property events for a later increment.

## Current state and constraints

### Shared protocol vocabulary

`crates/umsh-companion/src/ids.rs` currently ends the device property block
at `PROP_DEV_NAME = 68` and the full capability block at
`CAP_DEV_NAME = 38`. `crates/umsh-companion/src/describe.rs` supplies the
shared property and capability names used by native traces and tools. Both
need the new constants before any implementation can avoid private numeric
literals.

There is no shared snapshot type or charge-state type today. Both belong in
`umsh-companion`, not in a board crate or the allocating host adapter,
because no-std NCP code, host code, simulators, and tools must all encode
and reject malformed values identically (reserved flag bits, field order,
exact length).

### NCP session engine

`crates/umsh-companion-ncp/src/session.rs` is the authoritative property
dispatcher. Its current shape matters:

- `PROP_CAPS` is a hard-coded list in `encode_prop`; every `SessionConfig`
  currently advertises the same capability set.
- `known_prop`, `encode_prop`, and the read-only arm of `apply_prop_set`
  each carry an explicit property list.
- Dynamic RSSI already has the exact machinery battery needs: the session
  emits `Effect::SampleRssi { tid }`, the peripheral's owner performs the
  measurement, and the firmware completes the pending transaction with
  `Session::respond_rssi(tid, Result, emit)`, where `Err` becomes
  `STATUS_FAILURE`. Battery mirrors this deferred-completion pattern; it is
  the established way for a property read to reach hardware the session
  does not own.
- Saved snapshots serialize configuration from the device and host domains;
  dynamic read-only state is not serialized.
- `SessionConfig` is `Copy` and has four active construction sites: the
  session unit tests, the adapter-free host integration simulator, the web
  debugger simulator, and the shared T-Echo/T-1000E firmware.

### Hardware sources

The T-1000E's power monitor (`crates/umsh-bsp-t1000e/src/power.rs`) is the
sole owner of the SAADC, the gated sensor rail, and the charger/VBUS
inputs, and it enforces the critical-battery shutdown policy. Each
iteration gates the rail, settles 5 ms, samples, computes `battery_mv`,
classifies a five-way UX `BatteryState` from voltage + VBUS + the
active-low charge-status pin, and sleeps 30 s or until a power/charger
edge. The protocol path must route requests **to** this task rather than
sampling beside it; serviced on demand, the monitor's normal iteration
already produces everything the snapshot needs:

- voltage: the computed `battery_mv`;
- charge state: `BatteryCharging` -> `Charging`, `BatteryCharged` ->
  `Charged`, and `BatteryOnly`/`BatteryLow`/`BatteryCritical` ->
  `Discharging`; and
- level: unsupported (absent), because no fuel-gauge percentage exists and
  the host must not infer one from voltage.

The T-Echo is battery powered, so it should advertise `CAP_BATTERY`. Its
hardware reference identifies a battery ADC on P0.04, but also records that
the reading is unreliable with USB power and that charger state is exposed
by a dedicated LED rather than an MCU-readable status signal. The
conservative first implementation therefore reports no fields: `GET`
answers with an empty value. Enabling T-Echo voltage later requires
hardware validation of the 2x divider conversion and a defined response
while USB is present; charge state remains unsupported until all three
states can be distinguished honestly.

### Host and tools

`umsh/src/companion_radio.rs` has capability-gated synchronization, typed
property accessors, and a raw `PropEvent` queue for unsolicited updates.
`sync` hard-fails on any property error, which is why battery must **not**
join `NcpSync`: a transient `STATUS_FAILURE` from a measurement would
otherwise abort attach/provision workflows. Battery is live telemetry, not
configuration the host reconciles — it belongs in a dedicated accessor.
`umsh-companionctl info`, the hardware validator, and the browser debugger
(`tools/companion-web-debugger/engine`, catalog + typed decoder + shared
real-session simulator) all need to understand the new code and encoding or
they will show raw bytes.

## Target model

Two levels of optionality, mirroring the spec:

1. `SessionConfig::battery == None`: the device is not battery powered;
   `CAP_BATTERY` is absent and `PROP_BATTERY` is unknown
   (`STATUS_PROP_NOT_FOUND`).
2. `SessionConfig::battery == Some(BatteryFields { voltage, level,
   charge_state })`: the device advertises `CAP_BATTERY` and recognizes the
   property. The field set is fixed for the life of the session and
   determines the flags octet of every response.

A `GET` then behaves as follows:

- no fields supported: the session answers immediately with an empty value
  (no effect emitted, no sampling; the T-Echo path);
- one or more fields supported: the session defers the transaction and
  emits `Effect::SampleBattery { tid }`. The firmware obtains a measurement
  from the platform's battery source and completes with
  `Session::respond_battery(tid, Result<BatteryStatus, ()>, emit)`:
  `Ok(snapshot)` encodes the flags octet and present fields;
  `Err` completes with `STATUS_FAILURE`.

The platform abstraction sits behind the effect: the shared firmware main
routes `SampleBattery` to a per-board async sample operation returning a
`BatteryStatus` with optional fields. On the T-1000E that operation is a
request/reply channel into the existing monitor task; a future fuel-gauge
board would answer with level and charge state and no voltage; a
mains-powered board simply configures `battery: None`. The session
validates that a completed snapshot's populated fields exactly match the
configured `BatteryFields`, upholding the spec's flags-stability rule no
matter what a platform source returns.

On the host:

- no `CAP_BATTERY` -> no battery surface;
- capability present, empty value -> `BatteryStatus` with every field
  `None`;
- a snapshot -> exact strict decode (reserved bits zero, length matches
  flags, level <= 100, known charge-state code);
- `STATUS_FAILURE` and malformed values remain errors, never `None`.

## Design decisions

| Decision | Choice | Rationale |
|---|---|---|
| Property shape | One snapshot property with a field-flags octet | One query = one measurement event; voltage and charge state are coherent; fewer samples than per-field properties; natural unit for later unsolicited updates |
| Read path | Sample on request via `Effect::SampleBattery` + `respond_battery`, mirroring RSSI | Properties report measurements, not caches; removes staleness, validity flags, and boot races; the deferred-completion machinery already exists |
| Ownership | Requests are serviced by the existing board power owner (T-1000E: request/reply into the monitor task) | The monitor stays the sole SAADC/rail/charger-pin owner; rail timing, calibration, and shutdown policy live in exactly one place |
| Platform abstraction | Snapshot type + strict codec in `umsh-companion`; sampling behind one per-board async operation; five-way -> three-way charge mapping in board glue | Boards differ in what they can measure and how (ADC, fuel gauge, none); the session and shared main stay platform-blind; the BSP gains no companion-protocol dependency |
| Unsupported reporting | Empty value (no fields) or absent field (flag clear) | Exactly matches the spec; no numeric value is sacrificed |
| Temporary unavailability | `STATUS_FAILURE` for the whole `GET` | A snapshot is one measurement event; empty/absent stay reserved for unsupported |
| Concurrent requests | May share one in-flight measurement | Spec-sanctioned coalescing; a guard against redundant rail cycles, not a cache |
| T-1000E fields | Voltage + charge state; no level | Voltage-to-percent would be a new fuel model, not a measured property |
| T-Echo fields | None (empty value) | Capability truthfully asserts battery operation without publishing known-unreliable or unknowable telemetry |
| Host surface | Typed `battery_status()` accessor; **not** part of `NcpSync` | Telemetry, not configuration; keeps a measurement hiccup from failing `sync` and the attach workflows built on it |
| Initial update behavior | Query-only | Compliant with the spec's `MAY`; no new event source in `ncp_task` before a consumer exists |
| Saved state | No battery involvement anywhere | Live read-only state must survive neither save nor restore as data |

## Implementation increments

### 1. Shared identifiers and snapshot codec

Update `crates/umsh-companion`:

- Add `PROP_BATTERY = 69` and `CAP_BATTERY = 39` in `ids.rs`.
- Add the property mnemonic and `BATTERY` capability name to `describe.rs`.
- Add no-std `BatteryChargeState` (codes 0/1/2, strict conversion from a
  decoded PUI) and `BatteryStatus { voltage_mv: Option<u16>,
  level_percent: Option<u8>, charge_state: Option<BatteryChargeState> }`
  with `encode` and strict `decode`, exported from `lib.rs`. Decode must
  reject reserved flag bits, a length that does not match the flags, level
  above 100, an unknown charge-state code, and a PUI that does not consume
  the remainder. Do not use the UX tracker's five-way `BatteryState` as the
  wire enum: its low/critical states are presentation policy, not charge
  states.
- Unit-test identifiers, names, every flags combination round-tripping,
  each rejection case, and the empty (no-fields) form. Add
  frame-description coverage so both the empty value and a snapshot are
  described readably rather than treated as malformed.

### 2. Sample-on-request NCP property handling

Update `crates/umsh-companion-ncp/src/session.rs`:

- Add `BatteryFields { voltage, level, charge_state }` and
  `battery: Option<BatteryFields>` to `SessionConfig` (still `Copy`).
- Advertise `cap::BATTERY` only when `battery` is `Some`; make
  `PROP_BATTERY` known only under that capability.
- `GET` with no supported fields answers empty immediately. Otherwise
  defer the transaction and emit `Effect::SampleBattery { tid }`, exactly
  parallel to `Effect::SampleRssi`.
- Add `respond_battery(tid, Result<BatteryStatus, ()>, emit)`: `Ok`
  encodes flags + fields; `Err` completes `STATUS_FAILURE`. Reject (as
  `STATUS_FAILURE`, with a debug assertion) a snapshot whose populated
  fields do not exactly match the configured `BatteryFields`, so the
  advertised flags can never vary between reads.
- Add the property to the read-only handling so `SET`, `INSERT`, and
  `REMOVE` fail consistently without changing state; without the
  capability it stays `STATUS_PROP_NOT_FOUND`.
- Keep battery out of `DeviceDomain`, `SavedState`, snapshot encoding,
  restore, reset defaults, and host-replacement handling. Pending battery
  transactions follow the same session-reset discard rules as pending RSSI.

Session unit tests must cover:

- capability absent: no advertised code, property unknown;
- capability present, no fields: empty success, no effect emitted;
- mixed fields: effect emitted; completion encodes exact flags, exact
  little-endian voltage, bounded level, exact PUI charge state;
- completion with `Err`: `STATUS_FAILURE`, never an empty value;
- completion with mismatched fields: `STATUS_FAILURE`;
- mutation rejected; unknown without capability;
- reset/save/restore untouched by battery, and a pending battery `GET`
  across reset behaves like pending RSSI; and
- capability dependency/order assertions include `CAP_BATTERY` without
  changing protocol version 6.0.

### 3. Platform battery sources and firmware profiles

Define the per-platform sample operation in the shared firmware main: one
async function per board profile returning `Result<BatteryStatus, ()>`,
selected the same way the boards' other peripherals are. The
`SampleBattery` effect handler calls it and completes the session
transaction; if a request arrives while one is in flight, share the result.

For the T-1000E:

- Add a request/reply channel serviced by `run_battery_monitor` in
  `crates/umsh-bsp-t1000e/src/power.rs`: a request wakes the monitor,
  which runs its normal iteration (gate rail, settle, sample, classify,
  publish UX state, evaluate shutdown policy) and replies with
  `(battery_mv, BatteryState)`. The monitor remains the sole SAADC and
  rail owner; no second timer, ADC read, or rail sequence exists.
- Map the five-way reply to the three-way protocol charge state in the
  firmware glue (not in the BSP, which must not depend on the companion
  crates), and answer `BatteryStatus { voltage_mv: Some(mv),
  level_percent: None, charge_state: Some(state) }`.
- Configure `battery: Some(BatteryFields { voltage: true, level: false,
  charge_state: true })`.
- A genuine sampling failure replies `Err` and surfaces as
  `STATUS_FAILURE`. No boot readiness gate is needed: a `GET` that arrives
  before the monitor's first scheduled tick simply triggers a sample.

For the T-Echo:

- Configure `battery: Some(BatteryFields::NONE)`; the session answers
  empty without emitting the effect, so no sampling path is needed in this
  increment.
- Record a follow-up hardware gate before enabling voltage: compare P0.04
  readings against a meter on battery and USB, confirm the 2x divider
  formula, and decide whether USB-connected reads should fail or can
  report true battery terminal voltage. Do not infer charge state solely
  from VBUS or the ADC.

Update every non-hardware `SessionConfig` construction explicitly:

- the NCP unit-test profile exercises a mixed field matrix;
- `umsh/tests/companion_full_protocol.rs` services the effect with all
  three fields populated; and
- the browser simulator advertises the capability and services the effect
  with stable, human-recognizable values.

### 4. Typed host and inspection surfaces

Update `umsh/src/companion_radio.rs`:

- Add `battery_status() -> Result<Option<BatteryStatus>,
  CompanionRadioError>`: `Ok(None)` when `CAP_BATTERY` is absent;
  otherwise one `GET` decoded with the shared strict codec (empty value ->
  all-`None` fields). `STATUS_FAILURE` and malformed values are errors.
- Do **not** add battery to `NcpSync` or fetch it during `sync`.
- Leave `PropEvent` generic; a later unsolicited-update increment needs no
  transport changes.

Update user-facing tools:

- Teach `umsh-companionctl` the `BATTERY` capability name and have `info`
  call `battery_status()`, printing each absent field as `unsupported`
  rather than `disconnected` or zero, and an all-absent snapshot as
  `battery: unsupported reporting`.
- Include a battery read in `companion_hw_validate`'s dump and add a
  focused battery validation phase.
- Add `PROP_BATTERY` to the web debugger's Device group, capability-gated
  by `CAP_BATTERY`, decoding empty, flags, voltage, percent, and charge
  state into distinct human-readable presentations. No typed editor.
- Update the debugger simulator effect/config handling and tests so the
  property can be inspected without hardware.

### 5. Verification and hardware acceptance

Run the host-side gates after each increment:

~~~sh
cargo test -p umsh-companion
cargo test -p umsh-companion-ncp
cargo test -p umsh --test companion_full_protocol
cargo test -p umsh-companion-web-engine
git diff --check
mdbook build docs/protocol
~~~

Build all shared firmware variants so the new `SessionConfig` field and
effect matching cannot drift:

~~~sh
make build-companion-ncp-techo
make build-companion-ncp-t1000e
cd firmware/companion-ncp-t1000e && cargo build --release --features no-ble
~~~

T-1000E hardware gate, over both USB and BLE:

1. Confirm `PROP_CAPS` contains `CAP_BATTERY`.
2. Confirm a `GET` returns flags `0b101` with a two-byte voltage in a
   physically plausible range that tracks a meter closely enough for the
   board's existing ADC calibration, and no level field.
3. Confirm sampling is live, not cached: two `GET`s inside one 30-second
   monitor period straddling a charger plug/unplug must show the charge
   state (and the charging voltage elevation) change immediately.
4. With external power removed, confirm `Discharging` across normal, low,
   and critical UX classifications.
5. Connect power while actively charging and confirm `Charging`; allow
   charge completion (or use a known-full battery) and confirm `Charged`.
6. Confirm a `GET` issued immediately after boot succeeds by sampling on
   demand; a true sampling failure must surface as `STATUS_FAILURE`, never
   an empty value or absent field.
7. Save, change battery conditions, and restore; confirm restore does not
   roll the reported snapshot back.
8. Confirm protocol reads do not perturb the monitor's shutdown policy
   (low-count behavior) beyond running its normal iteration early.

T-Echo hardware gate, over USB and BLE:

1. Confirm `PROP_CAPS` contains `CAP_BATTERY`.
2. Confirm a `GET` succeeds with a zero-length value.
3. Confirm tools display it as `unsupported`, never zero, depleted,
   disconnected, or malformed.

Finally rerun the existing companion probe and full-protocol
synchronization checks to ensure the extra capability does not disturb
older hosts, transport arbitration, saved-state restoration, radio
operation, or queue handling.

## Deferred follow-ups

- **Unsolicited updates:** if a mobile client needs push updates, publish a
  snapshot on charge-state transitions (the monitor's existing
  power/charger edge wakeups already provide the trigger) and
  threshold/rate-limit voltage-driven changes. Reuse TID-zero
  `CMD_PROP_IS` carrying the same snapshot encoding; do not invent a new
  transport notification.
- **T-Echo voltage:** enable only after the meter/USB validation above
  proves a truthful terminal-voltage reading and its availability rules.
- **Battery level:** add only for a platform whose battery source has a
  real fuel-gauge/board model with a defined estimate. Do not silently
  introduce an OCV lookup table as protocol policy.
- **Disconnected battery:** keep the spec's current rule: absent means
  unsupported. If product requirements need an explicit presence
  indication, add that as a separate protocol decision rather than
  overloading the snapshot.
