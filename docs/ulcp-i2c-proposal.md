# ULCP I2C bus access proposal

Status: implemented and hardware-validated on the Pager, over USB and over the
mesh, 2026-09-16. This document
records the approved design; the normative definitions are in
[ULCP I2C Bus Access](protocol/src/ulcp-i2c.md). Capability 60, commands
25–27, properties 4960–4961, and status codes 24–26 are allocated.

Let a host issue raw I2C transactions to a device's peripherals over ULCP:
from the tethered host over USB, BLE, or TCP, and from a listed administrator
over Node Management. Every recent hardware investigation—gauge calibration on
the Pager, PMIC rails on the T-Beam Supreme, sensor bring-up—has meant editing
firmware, reflashing, and reading logs to look at one register. With this
extension it is a `umshctl i2c read` on the bench, and the same command against
a node nobody can walk to.

## Existing behavior

- Every board with a shared bus keeps it behind an `embassy-sync` mutex
  (`Mutex<CriticalSectionRawMutex, I2c<'static, Async>>`) and hands each
  driver an `I2cDevice` handle. The Pager's battery, keyboard, motion, and RTC
  tasks share one bus this way; the T-Beam Supreme's PMU bus is the same type.
  The nRF boards' single bus (the Wio Tracker's OLED) is owned outright by its
  display driver, and the T-1000E constructs no bus at all.
- The ULCP device runtime routes every board coupling through the
  [`DeviceEnv`](../crates/umsh-ulcp-runtime/src/driver.rs) trait, with
  commands becoming `Effect` variants the session stages and the driver
  completes through `Session::respond_*`. `Effect` is `Copy`, so a command
  with variable data stages it in a session-owned buffer.
- [Node Management](protocol/src/app-node-management.md#exchanges) carries
  one frame per exchange with no continuation for anything but multi-value
  reads, and answers a retransmitted token from its retained response.
- esp-hal's `I2c::transaction` implements the embedded-hal 1.0 contract
  (repeated START on a direction change, consecutive same-direction
  operations merged, one STOP), holds a wake lock for the transfer, chunks
  long operations through its FIFO, and resets the controller when its
  future is dropped.

## Protocol additions

One new subsystem chapter, [I2C Bus Access](protocol/src/ulcp-i2c.md), with
its own capability. Nothing in it is saved or session state.

### Capability

`CAP_I2C` (60), requiring nothing, gating everything below. A device
advertises it when it offers at least one bus.

### Properties

Both are Multiple-Value, Constant, with item length prefixes, Get only; a
mutation is `STATUS_INVALID_ARGUMENT`. Identifiers 4960–4975 are reserved for
the subsystem.

- `PROP_I2C_BUSES` (4960): `BUS | SPEED_KHZ (u16 LE) | MAX_DATA (u16 LE) |
  MAX_OPS | NAME (UTF-8)`. `MAX_DATA` bounds the sum of octets written and
  read in one transfer; `MAX_OPS` the operation count.
- `PROP_I2C_DEVICES` (4961): `BUS | ADDR | NAME (UTF-8)`. What the firmware
  was built knowing is on the bus, so a host can annotate a scan and warn
  before writing to the charger.

### Commands

- `CMD_I2C_TRANSFER` (25, Host→Device): `BUS | ADDR | OP...`, each operation
  `KIND (0 write, 1 read) | LEN (PUI) | [data]`. One transaction with
  embedded-hal semantics. Answered by `CMD_I2C_RESULT` carrying the
  concatenated read data.
- `CMD_I2C_SCAN` (27, Host→Device): `BUS [| FIRST | LAST]`, default
  0x08–0x77. One-octet read probes; answered by `CMD_I2C_RESULT` listing the
  acknowledging addresses.
- `CMD_I2C_RESULT` (26, Device→Host): only ever a reply, shaped by the request.

### Status codes

`STATUS_NO_DEVICE` (24) for an unacknowledged address, `STATUS_NACK` (25) for
a refused data octet, `STATUS_BUS_ERROR` (26) for the bus itself, including
the device's own deadline. Everything else reuses existing codes:
`PARSE_ERROR`, `INVALID_ARGUMENT` (limits, address range, empty operations),
`ITEM_NOT_FOUND` (unknown bus), `NOMEM` (result would not fit the reply,
judged before the bus is touched), `INVALID_STATE` (rail off), `BUSY` (bus
lock or a held peripheral), `UNIMPLEMENTED` (no `CAP_I2C`).

### Node Management

Both commands are permitted from a listed administrator, reads and writes.
`CMD_I2C_RESULT` joins the Response frame kinds. Since a Response is never
continued, the device refuses with `STATUS_NOMEM` any result that would exceed
the reply budget (the payload less the envelope, about 164 octets). The chapter
states what the retained-response rule means for writes: a write that resets
the node is never confirmed, and a lost Response leaves the write's effect
indeterminate, so an administrator reads the register back rather than
retransmitting.

### Sharing the bus

The device serializes transactions, not procedures. Its own drivers keep the
bus between commands, and a host's multi-step procedure can be interleaved
with firmware traffic to the same peripheral; a sequence that must not be
interleaved goes in one transfer. A device may protect its own procedures by
answering `STATUS_BUSY` for the peripheral they hold, including to a scan
whose range covers it, and must not hold the bus against its own drivers for
a host's benefit.

## Implementation

1. **Wire crate.** `crates/umsh-ulcp` gains the identifiers, the three status
   codes, the three commands, an `i2c` module (operation iterator with
   validation, request and item codecs, frame encoders), and human-readable
   descriptions for the debugger and umshctl.
2. **Session.** `SessionConfig` carries the two constant tables. A transfer or
   scan is validated whole—parse, limits, bus, and the `NOMEM` pre-check
   against the binding's reply budget—then staged in a session-owned buffer
   sized for the largest request within the limits, and completed through
   `respond_i2c`. The refusal ordering is what the status table promises: a
   refused request has never touched the bus.
3. **Runtime.** `DeviceEnv::i2c_transfer` and `i2c_scan` default to
   `STATUS_UNIMPLEMENTED`. Behind the `i2c` feature, an HAL-agnostic glue
   module carves read operations out of the result buffer, walks a scan
   range, maps HAL error kinds to statuses, and offers `guarded_transfer` and
   `guarded_scan`: a bounded wait for the bus mutex (`BUSY`), a reservation
   checked after the mutex is acquired, and a deadline on the transaction
   (`BUS_ERROR`). The result buffer is a static, not a stack local, because
   the device task's frame is shared across ESP32 images with little headroom.
4. **Pager.** The one real hook. Bus 0 at 400 kHz with the session's ceilings
   (255 octets, 16 operations); the six known peripherals listed. The battery
   task publishes the gauge's address through a drop guard around
   `ensure_stock_capacity` and `inspect_configuration`, the two
   multi-transaction procedures in the firmware; every other board advertises
   no bus. The T-Beam Supreme's PMU bus is the same type and can follow with
   one table entry.
5. **Host side.** The Tokio client gains `i2c_buses`, `i2c_devices`,
   `i2c_transfer`, and `i2c_scan`, all `Ok(None)` without the capability, with
   a longer wait for the reply than a property read. `umshctl i2c` offers
   `buses`, `devices`, `scan`, `read`, `write`, and `xfer`, annotates scans from
   the peripheral table, and warns before writing to a listed address. The
   simulated device carries a register file at 0x50; the dissector decodes the
   three commands and flags a result going the wrong way.

## Acceptance checks

- Codec round trips and every refusal in the status table, in the wire crate
  and the session, including the largest requests the limits admit and a
  result refused for size before the bus.
- Fake-bus tests of the glue: operation carving, error mapping, scan
  skipping and aborting; and the reservation race in the order that defeats a
  check-before-lock implementation—a transfer parked on the mutex sees a
  reservation published meanwhile and is refused with zero bus operations,
  then succeeds once the reservation clears; likewise a scan covering the
  address. A transaction that never completes is `BUS_ERROR` and releases
  the mutex.
- End to end against the real session: local round trip through the client,
  an administrator's transfer across a simulated mesh, an oversize read
  refused with `NOMEM` over the binding, and a retransmitted write answered
  from the retained response with the simulated bus's execution counter
  still at one.
- Every ESP32 board manifest and the nRF image type-check; the Pager builds.

## Scope boundary

One bus on one board. SMBus block transfers, 10-bit addressing, clock
speed selection, and bus recovery commands are separate additions, as is a
mobile client. The Wio Tracker's display bus stays owned by its driver; the
T-Beam Supreme's PMU bus is a follow-up table entry. The spec makes the
interleaving limitation explicit rather than promising a host an exclusive
session, and documents the indeterminacy of a node-resetting write over the
mesh rather than papering over it.

## Validation record

Automated: wire-crate, session, runtime (with `i2c`), simulator, umbrella
protocol and mesh tests, Node Management binding tests, umshctl unit tests, and
the dissector suite all pass; the Pager, Heltec V3, T-Beam Supreme, Heltec V2,
and T-1000E images type-check.

Hardware, on the attached Pager over USB: `i2c buses` and `i2c devices` report
the table; `i2c scan 0` finds every chip the
[hardware notes](hardware/lilygo-t-lora-pager-hardware.md) list, including the
ES8311 codec and the DRV2605 haptic driver, which nothing in the firmware
drives and which are now in the table so a scan is fully annotated;
`i2c read 0 0x55 2 --reg 08` returns `4110`, the same 4161 mV the gauge driver
reports through `battery`. A read of an absent address is `STATUS_NO_DEVICE`
and the next transaction succeeds. Twenty-five consecutive scans left the clock
correct and a battery multi-get answering in 298 ms, so the firmware's own bus
users were not starved. A 254-octet read (the limit, since `MAX_DATA` bounds
the sum and the register write takes one) came back whole: no `FifoExceeded` on
the read path, and the write path shares the same chunking helper.

Two results are worth keeping in mind. A *write* to an absent address is
`STATUS_NACK`, not `STATUS_NO_DEVICE`: esp-hal estimates the reason from the
transmit FIFO's read pointer, which has already advanced past the address octet
by the time a write NACKs. The chapter says what that means for a host.

Over the mesh, from a second radio with `--node`: the bus table, the same gauge
register (4160 mV, one millivolt off the reading taken over USB a minute
earlier), and a full annotated scan all came back, and a 200-octet read was
refused with `STATUS_NOMEM` in words rather than going silent.
