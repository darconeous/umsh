# ULCP battery diagnostics proposal

Status: implemented, 2026-09-14. This document records the approved design;
the normative definitions are in
[ULCP Device Domain](protocol/src/ulcp-device.md#battery-diagnostics).
Properties 4944–4956 are allocated without an additional capability.

Expose the readings on the Pager's Settings → Battery pages as individually
readable Device Domain properties. A client can select the values it needs and
fetch them together with `CMD_PROP_MULTI_GET`, over USB or Node Management.
Readings within that request come from one battery acquisition pass.

The motivating case is a charge estimate that stayed near 60% and then jumped
to 100%. Recording current, remaining/full capacity, charger completion, and
the gauge's full flag together would help identify what changed. A percentage
jump alone does not establish that the gauge calibrated successfully.

## Existing behavior

- [`PROP_BATTERY` (69)](protocol/src/ulcp-device.md#prop-battery) already exposes
  voltage, percentage, and charger state. Its existing encoding and behavior
  remain unchanged; clients need no new scalar aliases for those three fields.
- [`CMD_PROP_MULTI_GET`](protocol/src/ulcp-core.md#cmd-prop-multi-get) fetches
  several properties in one exchange. It preserves request order, including
  individual failures, but does not currently promise a shared measurement
  event across different properties.
- [Node Management](protocol/src/app-node-management.md#exchanges) carries
  those same commands to an authorized device over the radio. Remote reads
  are request/response exchanges; unsolicited updates are not carried there.
- The Pager's current diagnostic source is
  [`power.rs`](../crates/umsh-pager-peripherals/src/power.rs), and the visible
  fields are defined in
  [`screen.rs`](../crates/umsh-ux-display-tracker/src/screen.rs).
  Its one-second UI cache is useful for rendering, but is not sufficient for
  ULCP's sample-on-request contract or per-property failure reporting.

Separate properties permit small monitoring sets—for example, current and
percentage alone. Bundling the entire diagnostic surface into one property
would not save a round trip over `MULTI_GET` and would force clients to fetch
fields they do not need.

## Protocol additions

### Property allocation and discovery

These properties are optional extensions to `CAP_BATTERY`; no new capability
is allocated. A device may implement any subset, subject to the raw-format
dependency below. Clients discover support by fetching the properties:
unsupported properties return `STATUS_PROP_NOT_FOUND`.

Individual reads do not require `CAP_CMD_MULTI` and must work on a local
device without multi-command support. Remote access uses the existing
`CAP_ADMIN` prerequisites and authorization rules. Properties 4944–4956 are
allocated in the property registry.

All new properties are single-value, read-only, Device Domain properties.
**Asynchronous updates: No.** Monitoring uses explicit reads; existing
`PROP_BATTERY` notifications retain their current behavior.

| ID | Property | Non-empty value | Meaning |
|---:|---|---|---|
| 4944 | `PROP_BATTERY_CURRENT` | Minimal signed LE integer, 1–4 octets, mA | Signed battery current: positive into the battery, negative out, zero is a valid reading. |
| 4945 | `PROP_BATTERY_REMAINING_CAPACITY` | Minimal unsigned LE integer, 1–4 octets, mAh | Gauge's current remaining-capacity estimate. |
| 4946 | `PROP_BATTERY_FULL_CAPACITY` | Minimal unsigned LE integer, 1–4 octets, mAh | Gauge's current estimate of capacity at full charge. |
| 4947 | `PROP_BATTERY_DESIGN_CAPACITY` | Minimal unsigned LE integer, 1–4 octets, mAh | Design capacity configured in the gauge or board profile. |
| 4948 | `PROP_BATTERY_EXT_POWER_PRESENT` | `BOOL` | External power detected by the platform, such as USB/VBUS, a DC input, or solar input; this does not imply battery charging or identify the source. |
| 4949 | `PROP_BATTERY_PRESENT` | `BOOL` | Battery detected by hardware. |
| 4950 | `PROP_BATTERY_GAUGE_FULL` | `BOOL` | Gauge's full-charge indication, independent of charger completion. |
| 4951 | `PROP_BATTERY_GAUGE_INITIALIZED` | `BOOL` | Gauge initialization has completed; this does not assert successful capacity learning or calibration. |
| 4952 | `PROP_BATTERY_GAUGE_SMOOTHING` | `BOOL` | Gauge is currently applying smoothing to its reported capacity. |
| 4953 | `PROP_BATTERY_CHARGE_VOLTAGE_REQUEST` | Tagged voltage request, below | Gauge's requested charging voltage, distinct from measured voltage and the charger's configured voltage limit. |
| 4954 | `PROP_BATTERY_GAUGE_FORMAT` | `PUI` | Identifies the interpretation of the two raw status properties. |
| 4955 | `PROP_BATTERY_GAUGE_STATUS` | Minimal unsigned LE integer, 1–4 octets | Raw gauge battery-status flags, interpreted using the format identifier. |
| 4956 | `PROP_BATTERY_GAUGE_OPERATION_STATUS` | Minimal unsigned LE integer, 1–4 octets | Raw gauge operation-status flags, interpreted using the format identifier. |

### Compact value encodings

Senders **MUST** use the fewest octets that represent each new integer value.
The property value's existing length supplies the width; no additional width
prefix or continuation bits are added to these signed or unsigned LE integers.
This applies equally to individual reads and entries in a multi-get response.

- **Signed current:** little-endian two's complement, with a signed 32-bit
  range. Reuse the encoding of
  [`PROP_IDENT_ALTITUDE`](protocol/src/ulcp-device.md#prop-ident-altitude),
  requiring minimal output here. One octet covers −128 through 127; two cover
  −32768 through 32767; three cover −8388608 through 8388607. Keep a sign octet
  when removing it would change the value's sign.
- **Unsigned capacities, voltage, and raw flags:** little-endian with an
  unsigned 32-bit range. Remove high zero octets, retaining one octet for zero.
  One octet covers 0–255, two 0–65535, and three 0–16777215. Bit 7 of the last
  octet is ordinary data, not a sign or continuation bit.
- **Booleans:** exactly one octet, `00` or `01`.
- **Gauge format and voltage discriminator:** retain PUI encoding, using its
  shortest form. Format 1 and either defined discriminator occupy one octet.

Receivers accept integer widths of one through four octets, sign-extending
current and zero-extending unsigned values, including padded representations.
Senders must not emit that padding. More than four octets is malformed. An
empty property value remains unavailable; numeric zero is `00`, never empty.
False likewise represents an actual indication, never an unavailable reading.

Examples below show value bytes in hexadecimal, in transmission order:

| Value | Bytes | Octets |
|---|---|---:|
| Current −100 mA | `9C` | 1 |
| Current −200 mA | `38 FF` | 2 |
| Current −128 / −129 mA | `80` / `7F FF` | 1 / 2 |
| Current 127 / 128 mA | `7F` / `80 00` | 1 / 2 |
| Current 0 mA or capacity 0 mAh | `00` | 1 |
| Capacity 200 mAh | `C8` | 1 |
| Capacity 1500 mAh | `DC 05` | 2 |
| Raw operation flags `0x00A6` | `A6` | 1 |

Capacities are charge quantities in mAh, not energy in mWh. No host should
replace the reported percentage with a ratio it calculates from capacities;
it may display that ratio separately for diagnosis.

The charge-voltage-request value begins with a PUI discriminator:

| Code | Following bytes | Meaning |
|---:|---|---|
| 0 | Minimal unsigned LE integer, 1–4 octets, mV | A specific voltage request. |
| 1 | None | Request the charger's maximum voltage. |

For code 0, all remaining bytes encode the voltage: one through four are
required, with the compact unsigned rules above. Code 0 without a voltage or
with more than four voltage octets is malformed. Code 1 has no following bytes;
any trailing bytes are malformed. A 4200 mV request is `00 68 10` (three octets
total), and a maximum-voltage request is `01` (one octet).

An empty property value means unavailable, as below. Unknown discriminators
are malformed. This avoids exposing a hardware
sentinel as an implausibly large voltage. Reading this property never applies
the request to the charger.

### Support, availability, and errors

Use existing ULCP status codes with explicit meanings:

| Condition | Response to a new property read |
|---|---|
| This hardware/firmware does not implement the property | `STATUS_PROP_NOT_FOUND`. |
| Field implemented, but no meaningful value in the observed state | Successful `CMD_PROP_IS` with an empty value. |
| Acquisition attempted and failed, including an I2C error or timeout | `STATUS_FAILURE`. |
| A valid measurement or indication exists | Successful `CMD_PROP_IS` containing the typed value. |

For example, an initializing gauge may report `GAUGE_INITIALIZED=false`
while its capacity estimate is empty. A detected battery removal is
`BATTERY_PRESENT=false`; dependent measurements may then be empty. A missing
presence detector is `STATUS_PROP_NOT_FOUND`, not false. A failed read must
not masquerade as battery removal, initialization, or an empty successful
measurement.

There is no separate support-discovery table: clients can discover individual
support with their first multi-get and omit `STATUS_PROP_NOT_FOUND` fields
from subsequent polls. That result is fixed for a firmware/hardware
configuration; rediscover after reconnecting or updating firmware.
An empty value or acquisition failure does not mean unsupported and must not
cause the client to drop that property from future polls.

Within a multi-get, each result occupies its normal position. A failed gauge
read need not suppress a successful external-power reading from the charger.
Correlated fields that depend on the failed read all report failure.
`PROP_BATTERY` retains its existing rules, including its own failure behavior;
the new properties do not redefine its empty or omitted-field meanings.

Mutations (`SET`, `INSERT`, `REMOVE`) return `STATUS_INVALID_ARGUMENT` for
implemented properties and `STATUS_PROP_NOT_FOUND` for unsupported properties.
Reads do not unseal, reset,
calibrate, configure, or otherwise change the gauge or charger.

### Shared acquisition within a multi-get

Define a battery read group containing `PROP_BATTERY` and properties
4944–4956. A device implementing any of the new properties follows these rules
for the supported members of that group. Unsupported members retain their
`STATUS_PROP_NOT_FOUND` results and require no acquisition:

1. A single-property read acquires the requested live reading when serviced.
2. A multi-get containing battery-group properties acquires all requested
   live battery values in one pass when that group is serviced. All occurrences
   of those properties, including duplicate keys, use that pass's results.
3. Only the requested measurements and their dependencies need to be read.
   Reading external-power presence alone must not require successful gauge communication.
4. Semantic flags and raw status words come from the same register reads.
   The device must not reread a status word separately for each derived flag.
5. The sample is scoped to that request. It is discarded on completion,
   cancellation, or session reset; an unrelated later read must not reuse it.
   Concurrent requests may share an acquisition that is already in flight.

This is a battery-group guarantee, not general multi-get atomicity. Registers
are often read sequentially and may update internally during acquisition; one
pass does not promise a hardware-latched, simultaneous sample. Board adapters
should use available latching or bounded consistency checks where required by
their gauge, and report failure if they cannot obtain a usable result.

Metadata such as gauge format may come from the fixed board configuration.
Read-only design capacity may be configured or learned inside the gauge; it
must not be confused with a writable ULCP setting. Battery values are excluded
from saved state, and save/restore does not roll telemetry back.

Node Management retransmissions retain the existing at-most-once semantics:
retrying an exchange returns its retained response, rather than taking a new
sample. A new monitoring poll is a new exchange with a new token. Any cursor
continuations read the retained response from that same acquisition.

### Raw gauge formats and the Pager mapping

Initially allocate format `1` to the TI BQ27220: `GAUGE_STATUS` contains
BatteryStatus (`0x0A`) and `GAUGE_OPERATION_STATUS` contains OperationStatus
(`0x3A`), each represented as a compact unsigned integer. A BQ27220 raw word
therefore occupies one or two octets, with its high zero octet omitted.
Format `0` is reserved;
other formats need a documented allocation before a device emits them.
Raw-register implementations must also implement `GAUGE_FORMAT`.

Clients can show unknown format identifiers and raw words as numbers, while
continuing to use the generic measurements and flags. They must not decode
unknown raw formats as BQ27220 bits. Raw flag bits are opaque protocol data;
reserved hardware bits are preserved rather than rejected by the ULCP codec.

The Pager adapter uses current (`0x0C`), remaining (`0x10`), full (`0x12`),
design (`0x3C`), and requested voltage (`0x30`). BatteryStatus supplies presence
(bit 3) and full (bit 9); OperationStatus supplies initialized (bit 5) and
smoothing (bit 6). Requested voltage `0xffff` maps to request code 1.
These mappings follow the [BQ27220 technical reference manual,
sections 2.7–2.10 and 2.23–2.28](https://www.ti.com/lit/ug/sluubd4/sluubd4.pdf).

On the Pager, external-power presence maps to USB/VBUS detection by the BQ25896;
charger state also comes from the BQ25896. Preserve the
distinction between charger completion, gauge full, and 100% state of charge.
Their disagreement is useful diagnostic information.

## Monitoring over USB and radio

Both transports use the same property definitions and codecs. Add a client
watch operation that selects properties and repeatedly issues a multi-get;
fall back to sequential gets on local devices without `CAP_CMD_MULTI`, clearly
marking that those values are not a shared sample.

Suggested client defaults are one poll per second over USB and one per minute
over radio. These are tool defaults, not protocol sampling requirements.
Allow an explicit interval override. Keep one exchange outstanding per remote
device, wait for completion before scheduling the next, and back off after
timeouts or duty-limit failures instead of accumulating queued polls. A fresh
register read cannot make the gauge update faster than its own sample rate.

No new subscription command, session setting, telemetry broadcast, or remote
push mechanism is needed. Radio reads use the existing authorized Node
Management path and do not claim the remote device's local host session.

The complete Pager set is `PROP_BATTERY` plus the thirteen new properties.
Reply size depends on the values. For example, with all fields available,
current −100 mA, all three capacities 1500 mAh, a 4200 mV voltage request,
format 1, and raw status/operation words `0x4268`/`0x00A6`, the new values
occupy 19 octets. Their thirteen entries add 39 octets of key/length framing.
With 2 frame/command octets and 7 for the existing battery entry, the complete
ULCP reply is **67 octets**. The ordinary three-octet Node Management envelope
brings that to **70**, excluding payload type and mesh carriage/security
overhead. The same values padded to the original four-octet integer widths
would consume 86 octets including that envelope.

For the BQ27220's signed 16-bit current and unsigned 16-bit capacities, voltage,
and status words, the complete successful reply is at most 69 ULCP octets
(72 with that envelope). Across the 32-bit ranges, with format 1,
the maximum remains 83 ULCP octets (86 with that envelope). Both fit the current
180-octet management budget. Smaller selections reduce both response size and
hardware reads.

CLI usage:

```sh
# Include supported diagnostic properties in the existing battery report.
umshctl --port /dev/cu.usbmodem101 info battery

# JSON Lines carries units, availability, and timestamps.
umshctl --port /dev/cu.usbmodem101 battery --watch --interval 1s --json

# Select a smaller set, with a bounded run for recording or diagnostics.
umshctl --port /dev/cu.usbmodem101 battery --watch --count 30 --properties battery,battery-current,battery-ext-power-present --json

# The same operation against an authorized remote node.
umshctl --port /dev/cu.usbmodem101 --node NODE_KEY battery --watch --interval 60s --json

# Generic get syntax with the diagnostic property names.
umshctl --port /dev/cu.usbmodem101 get battery battery-current battery-remaining-capacity battery-full-capacity
```

Watch output records host receipt time, exchange duration, and each value's
support/availability/error state. Receipt time is not claimed to be the exact
device measurement time. A timeout produces a gap/error record; it must not
silently repeat the previous successful values as current. Replayed responses
belong to their original logical poll, not a second sample.

## Implementation

1. **Specification and codecs.** Add the property
   definitions, raw-format allocation, and battery-group rule to Device Domain;
   update the property index and conformance cases. Add constants,
   names, value descriptions, and the tagged voltage-request codec in
   `crates/umsh-ulcp`. Reuse `sint` for current and add a shared minimal-width
   unsigned codec for capacities, voltage, and raw flags. Ensure property
   descriptions and client decoders preserve variable widths rather than
   treating these as fixed-width `INT32_LE`/`UINT32_LE` values. This is an
   additive property extension under protocol 6.0.
2. **Session and runtime.** Extend the existing deferred battery-read machinery
   in `crates/umsh-ulcp-device/src/session.rs` and
   `crates/umsh-ulcp-runtime/src/driver.rs` with requested-field selection and
   per-field results. Retain one result set in the active multi-get context;
   do not key a global cache by TID, since remote requests all carry TID zero.
   Clear it on every completion and cancellation path. Reuse the same dispatch
   for USB and authorized Node Management.
3. **Pager source.** Keep the battery task as the I2C owner. Service protocol
   requests immediately through it, distinguishing unsupported, unavailable,
   and failed fields before making UI-friendly optional values. Derive the
   screen, ordinary battery snapshot, and diagnostics from this shared source.
   Preserve the one-second low-battery safety cadence; host reads must not
   advance its consecutive-low counter or wake the display.
4. **Host tools.** Add typed access and partial-result handling, extend
   `umshctl info battery`, and add the selected-field watch command. Update the
   web debugger and simulator to decode each property. Share these codecs with
   mobile clients; a new iOS screen can follow separately.
5. **Other boards.** Devices implementing only `PROP_BATTERY` remain unchanged.
   Add individual properties to another board only after validating its sources;
   do not infer gauge flags, external-power presence, or capacity from unrelated
   readings. Unsupported properties return `STATUS_PROP_NOT_FOUND`.

## Acceptance checks

- Check identifier collisions and exact encodings, including the examples
  above, every signed/unsigned width boundary, and 32-bit limits. Verify minimal
  sender output and receiver acceptance of sign-/zero-extended padded values.
  Cover zero/false versus empty, maximum-voltage requests, unknown raw formats,
  malformed lengths, and value-dependent multi-get byte budgets. Confirm that
  current −100 uses one octet and −200 two inside multi-get entries too.
- Test devices with none, some, and all of the new properties, acquisition failures,
  battery removal, initialization, and recovery. Multi-get failures must stay
  in their request positions while independent successful fields remain usable.
  Verify discovery omits only not-found properties from later polls, retains
  temporarily unavailable or failed readings, and runs again after reconnect.
- Verify one acquisition for a battery multi-get, including duplicate keys
  and intervening non-battery properties; a later request must acquire again.
  Exercise cancellation, reset, concurrent local/remote requests, and token
  retries without cross-session sample leakage.
- Confirm old `PROP_BATTERY` encodings and notifications remain compatible,
  mutations are rejected, and telemetry never enters saved-state snapshots.
- On the Pager, compare the screen and USB results under steady conditions,
  then observe charging, completion, USB removal, and battery operation. Record
  a percentage correction if it recurs; do not manufacture one by resetting or
  reprogramming the gauge.
- Repeat selected-field and full reads through a second radio using authorized
  Node Management. Verify token replay returns the same sample, a new poll
  samples again, unauthorized sources remain rejected, and no unsolicited
  diagnostic packets are transmitted.
- Build affected firmware and check stack/resource budgets. Verify monitoring
  leaves display attention, shutdown, and low-battery protection working.

## Scope boundary

This proposal covers the existing Battery menu readings and the tooling needed
to monitor them. Charger configuration writes, calibration commands, cycle
count, temperature, state-of-health estimates, and multi-pack addressing are
separate additions. It makes the observed behavior measurable without choosing
a battery calibration or charging-policy change in advance.

## Validation record

Verified on the attached Pager over USB: all thirteen properties are readable,
full and design capacity remain 1500 mAh, and repeated JSON monitoring returns
live current, voltage, capacity, and flags in one multi-get. A raw three-property
response used two octets for current, two for 1500 mAh design capacity, and one
for operation flags `0xA6`. The user confirmed that the Battery screen, wheel,
and Backspace remain responsive. Startup retained the gauge profile and loaded
the saved identity/settings/bond journals.

Automated checks cover compact widths and the 67-octet example reply, partial
failures, unsupported versus unavailable values, register dependency selection,
duplicate properties, session cleanup, and radio token replay with a fresh
sample on a new token. Pager and T-Echo release builds and the ULCP documentation
build pass. Physical over-radio comparison with a second device, charging
transitions, and battery-removal fault testing remain hardware qualification
work; the radio binding was verified with the real protocol engines in simulation.
