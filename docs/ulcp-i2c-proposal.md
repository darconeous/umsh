# ULCP I2C bus access proposal

Status: implemented on all nine device boards through the `ulcp-i2c`
feature. The original Pager implementation was hardware-validated over USB
and the mesh on 2026-09-16; the BSP migration, shared display buses, and newly
enabled nRF buses still need bench verification. This document
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
  tasks share one bus this way; both T-Beam Supreme buses and the Heltec
  display buses use the same arrangement.
  The Wio OLED shares its controller the same way; the other nRF buses
  are initialized for host access. The nRF shared handles use
  `ThreadModeRawMutex`, matching their thread-mode executor.
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
- `PROP_I2C_DEVICES` (4961): `BUS | ADDR | NAME (UTF-8)`. The firmware's
  peripheral table, queried explicitly with `umshctl i2c devices`.

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
4. **Board capability.** Each device image's board feature enables
   `ulcp-i2c`, forwarding to the runtime and its BSP. The shared tracker uses
   `board::i2c::{BUSES, Buses}` and `Buses::devices()` on ESP32;
   the BSP owns bus selection, deadlines,
   and procedure reservations. The Pager keeps its 400 kHz bus and eight
   peripheral entries, with its gauge reservation held around configuration
   inspection. The Heltec V2 and V3 expose their 400 kHz OLED bus, shared by
   the display and host through per-transaction device handles. The T-Beam
   Supreme exposes sensor/display bus 0 at 400 kHz and PMU/RTC bus 1 at
   100 kHz. Sensor access checks ALDO1 and holds the PMU bus through the
   transaction so a rail change cannot race the check. Display controllers
   are constructed and their supplies enabled before the session starts.
   Consecutive reads and writes are coalesced before reaching the HAL.
   Writes use a bounded 255-byte scratch buffer so the nRF HAL never sees
   adjacent operations with the same direction. BSPs
   assert at compile time that both tables fit the session's property
   buffer. The T-Beam checks the maximum possible startup inventory against
   the same 272-byte capacity.
5. **Host side.** The Tokio client gains `i2c_buses`, `i2c_devices`,
   `i2c_transfer`, and `i2c_scan`, all `Ok(None)` without the capability, with
   a longer wait for the reply than a property read. `umshctl i2c` offers
   `buses`, `devices`, `scan`, `read`, `write`, and `xfer`. Scans print the
   responding addresses; commands issue only the requested operation,
   without capability preflights, peripheral-table lookups, or warnings
   about listed addresses. Unsupported operations use the device's refusal
   response. The
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

The configured buses on all nine device boards are exposed. A board
whose only peripheral is its OLED still supports a real scan; the device
table names that display. The T-Beam identifies its sensor population and
caches the observed inventory at startup, as described below. QMC6309 at
0x7C requires an explicit
`--first 0x7c --last 0x7c`, outside the unchanged default scan range.

SMBus block transfers, 10-bit addressing, clock speed selection, and bus
recovery commands are separate additions, as is a mobile client. No protocol
identifiers or wire formats change with the board capability refactor.

The nRF device images expose the following buses, all at 100 kHz:

| Board | ULCP bus | SDA / SCL | Known devices |
|---|---|---|---|
| T-Echo | 0 (TWIM0) | P0.26 / P0.27 | PCF8563 0x51, BME280 0x77; BHI260 0x28 and DRV2605 0x5A on Plus |
| T-1000E | 0 (TWIM1) | P0.26 / P0.27 | QMA6100P, 0x12 or 0x13 by address strap |
| SenseCAP Solar | 0 (TWIM0) | P0.09 / P0.10 | Grove expansion; no fixed device inventory |
| Wio Tracker L1 | 0 (TWIM0) | P0.06 / P0.05 | SH1106 OLED 0x3D |
| Wio Tracker L1 | 1 (TWIM1) | P1.12 / P1.11 | Grove expansion; no fixed device inventory |
| XIAO nRF52 kit | 0 (TWIM0) | D6/P1.11 / D7/P1.12 | Expansion; no onboard I2C devices |

T-Echo uses its existing peripheral power-up, which also powers the I2C
pull-ups. T-1000E powers the accelerometer through P1.07 before exposing its
bus and turns that rail off at shutdown. Both possible QMA6100P addresses
are annotations, not a claim that two devices are fitted; they follow the
[driver's address definitions](https://github.com/meshtastic/QMA6100P_Arduino_Library/blob/main/src/QMA6100P.h).
Solar enables embassy-nrf's `nfc-pins-as-gpio` feature for the Grove pins;
its initialization clears the NFC pin configuration in UICR and resets once
if needed. XIAO uses the currently unused D6/D7 pads, leaving NFC alone;
those pads are consequently unavailable for a future GNSS UART without
changing this pin assignment. External expansion peripherals need suitable
I2C pull-ups.

Wio's radio moves from SPIM1 to SPIM2, keeping the same pins, to free TWIM1
for Grove. Its OLED driver takes a shared bus handle in the device image;
the console harness can still give it an owned controller. Shutdown paths
park the newly claimed bus pins alongside the other peripheral signals.

The spec makes the
interleaving limitation explicit rather than promising a host an exclusive
session, and documents the indeterminacy of a node-resetting write over the
mesh rather than papering over it.

## T-Beam startup inventory

The T-Beam constructs its inventory once after ALDO1 is enabled, before
starting the ULCP session. Discovery checks only the six supported sensor
addresses, with a 500 ms total deadline. Sensor identification reads
chip-ID registers without configuring measurements:

- BME280: register `0xD0` must return `0x60`, at `0x76` or `0x77`.
  [Bosch datasheet](https://www.bosch-sensortec.com/media/boschsensortec/downloads/datasheets/bst-bme280-ds002.pdf)
- QMC6310U/N: register `0x00` must return `0x80`, at `0x1C` or `0x3C`.
  [QST datasheet](https://www.qstcorp.com/upload/pdf/202202/%EF%BC%88%E5%B7%B2%E4%BC%A0%EF%BC%8913-52-17%20QMC6310%20Datasheet%20Rev.C%281%29.pdf)
- QMC6309: register `0x00` must return `0x90`, at `0x7C`.
  [QST datasheet](https://www.qstcorp.com/upload/pdf/202512/7A7DE8DCC625401FBB333322DD87E567.pdf)

The OLED address selection prefers `0x3D`. It checks the defined SH1106
idle-status bits, then requires successful display initialization within
200 ms before naming the entry. The resulting initialized driver is handed
to the display task. At `0x3C`, a value of `0x80` could also mean a busy
panel; without a panel at `0x3D`, this ambiguous result stays unknown and
is not sent display initialization commands.
[SH1106 datasheet, Read Status](https://www.pololu.com/file/0J1813/SH1106.pdf)

The PMIC entry reuses the chip-ID validation in power bring-up; the RTC
entry reuses the successful startup clock read, including an invalid or
unset clock. Missing peripherals are omitted. A responding candidate with
an unrecognized ID, ambiguous status, or failed panel initialization is
labeled `Unknown I2C device`. A discovery timeout preserves completed
observations. This is identification of the board's supported populations,
not general identification of arbitrary expansion devices.

### Protocol effect

No identifiers, item encodings, or commands change. `PROP_I2C_DEVICES`
is still read-only and fixed for the running firmware session, but its
T-Beam value is rebuilt on each boot and can reflect hardware changes or
startup failures. Reading the property only encodes the cached slice;
`read`, `write`, `xfer`, and `scan` still perform no inventory query or
identification. Other boards retain their existing tables.

## Known nRF recovery limitation

The shared nRF controller waits for STOPPED after embassy-nrf 0.11's early
error return. Without that wait, a scan can start its next address while
the preceding NACK's STOP is still pending, causing a spurious bus error.
The wrapper distinguishes a pending STOP from one the HAL already consumed,
resumes a suspended operation before stopping it, and keeps the mutex and
buffers borrowed throughout the bounded wait. An unconfirmed stop resets
the device rather than returning those buffers. Display and host users
share this wrapper; no HAL fork or dependency patch is introduced.

Cancellation recovery remains deferred. Dropping an unfinished HAL future
bypasses its return path and the wrapper's error completion. A host deadline
can therefore still leave DMA active against released buffers. The follow-up
is a cancellation guard that resumes a suspended transfer, stops it, confirms
STOPPED synchronously within a hard bound, and resets without returning if
shutdown cannot be confirmed. Hardware qualification remains pending.

## Validation record

Startup inventory and nRF scan recovery, 2026-09-16:

- Five T-Beam inventory tests pass, covering population/address variants,
  absent and unknown devices, ambiguous OLED status, failed initialization,
  interrupted discovery, and the encoded inventory size.
- Four nRF STOP-completion tests pass, covering delayed completion,
  completion already consumed by the HAL, suspended transfers, and the
  bounded failure path.
- All four ESP32 device images type-check with host I2C enabled. T-Beam
  also type-checks with host I2C disabled, and Heltec V3 with Wi-Fi enabled.
- T-Beam and Pager release builds and stack checks pass. Main-stack space
  / largest frame / required reserve, in bytes: T-Beam 45,036 / 24,000 /
  8,192; Pager 54,956 / 21,840 / 32,768.
- All five nRF device images link in release mode with the shared
  STOP-completion wrapper: Wio Tracker L1, T-Echo, T-1000E, SenseCAP Solar,
  and XIAO nRF52.
- Formatting checks and the protocol book build pass. No hardware was
  available; startup identification and repeated nRF scans still need
  hardware confirmation. Cancellation recovery remains deferred.

Board capability refactor, 2026-09-16:

- Wire-crate, session, and runtime tests pass with `i2c`, including
  consecutive reads, consecutive writes, mixed operations, combined read
  capacity, and table-size validation against the property encoder.
- All four ESP32 device images type-check both with host I2C enabled and
  with its board-feature forwarding temporarily removed. Heltec V2 uses
  `ESP_HAL_CONFIG_MIN_CHIP_REVISION=100`. The Heltec V3 console harness also
  type-checks with the shared display handle.
- All five nRF device images type-check both with host I2C enabled and
  with its board-feature forwarding temporarily removed. The Wio console
  harness also type-checks with its owned display controller.
- All five nRF device images link in release mode with host I2C enabled.
- Pager, Heltec V3, and T-Beam Supreme release builds pass after write
  coalescing, including their stack checks. Main-stack space / largest frame
  / required reserve, in bytes: Pager 54,972 / 21,840 / 32,768;
  Heltec V3 90,396 / 29,456 / 8,192; T-Beam 45,148 / 21,600 / 8,192.
- The protocol book builds with `make docs`.
- No boards were available for this refactor's hardware checks. Boot,
  register reads, scan/display coexistence, and the T-Beam's population and
  rail-off checks remain pending. The earlier Pager results below do not
  qualify the revised images.

Original implementation, automated: wire-crate, session, runtime (with
`i2c`), simulator, umbrella protocol and mesh tests, Node Management binding
tests, umshctl unit tests, and the dissector suite all pass; the Pager,
Heltec V3, T-Beam Supreme, Heltec V2, and T-1000E images type-check.

Original implementation, hardware on the Pager over USB: `i2c buses` and
`i2c devices` report the table; `i2c scan 0` finds every chip the
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
