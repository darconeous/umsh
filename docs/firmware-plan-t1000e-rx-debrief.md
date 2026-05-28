# Phase 2.5 LR1110 RX Bringup — Debrief

Status at the end of this session: **RX still not working.** The LR1110
chip is alive and in continuous-RX mode, but it never reports a complete
packet (RxDone / HeaderError / CrcError) despite firing preamble-detection
IRQs in correlation with real MeshCore-US transmissions on the air.

This document captures everything learned so the next person picking this
up — likely future-me — can skip the dead ends and start from the actual
question: *why does the chip detect preambles but never advance to
sync-word / header validation?*

## The setup

- Board: Seeed SenseCAP T1000-E (nRF52840 + LR1110, sealed unit, internal
  battery, no SWD)
- Firmware crate: [firmware/companion-cli-t1000e/](firmware/companion-cli-t1000e/)
- Forked lora-phy: `~/Projects/lora-rs`, branch `umsh/lr1110-rf-switch-config`
  - `[patch.crates-io]` in [Cargo.toml](Cargo.toml) redirects `lora-phy` to
    this fork
- Target on-air parameters (confirmed by the user, matches existing
  `umsh-radio-sx126x::meshcore_us_params`):
  - 910.525 MHz / SF7 / BW62.5 kHz / CR 4/5
  - Private sync word 0x12
  - CRC on, IQ standard, explicit header
- Reference RX device: T-Echo running `firmware/hello-techo` —
  **decodes the same MeshCore-US traffic successfully** at exactly these
  parameters using the SX126x lora-phy backend.

## What works on the T1000-E firmware

- Phase 1: USB-CDC, WDT, panic capture, all DFU rescue paths
- Phase 2: button task (long-press + triple-tap), shutdown task,
  System OFF + GPIO wake
- LR1110 chip enumerates (`get_version` returns `hw=0x22 chip_type=Lr1110 fw=0x0307`)
- LR1110 init succeeds: post-init status reads `mode=Rx cmd=Ok errors=0x0000`
- DIO1 (P1.01) actually toggles when the chip raises IRQs (verified via a
  PAC-based watcher task)
- Preamble-detect IRQs (`IrqMask::PreambleDetected`, bit 4) fire **only**
  when a MeshCore device is actually transmitting nearby — confirming the
  chip's front-end is real
- Long-press → power-off works (after fixes documented below)
- Triple-tap → DFU works
- Short-press wakes from System OFF

## What does NOT work

`lora.rx()` (or our equivalent polling-via-`process_irq_event` loop)
**never** returns a successful packet. The IRQ status register, when
sampled during a real TX burst, contains only `PreambleDetected` (bit 4)
plus `Error` (bit 23, see open issue below). It never contains:

- `SyncWordHeaderValid` (bit 5) — chip never confirmed a matching sync word
- `RxDone` (bit 3)
- `HeaderError` (bit 6)
- `CrcError` (bit 7)
- `Timeout` (bit 10) — expected, we're in continuous RX

This is a *very specific* failure mode: the chip locks onto the preamble
chirps and then gives up before sync word validation. It does not produce
the chain of events that LoRa receivers normally generate when they
encounter a packet with mismatched sync word, mismatched CR, or other
configuration drift (those usually yield HeaderError or CrcError).

## Pin map (verified)

From `/tmp/meshcore-check/variants/t1000-e/variant.cpp` Arduino-pin →
nRF52840-port mapping, plus `variant.h` LR1110 defines:

| LR1110 signal | nRF52840 pin |
|---|---:|
| SCK     | P0.11 |
| NSS/CS  | P0.12 |
| MISO    | P1.08 |
| MOSI    | P1.09 |
| BUSY    | P0.07 |
| DIO1 (IRQ) | P1.01 |
| RESET   | P1.10 |
| (RF switch DIO5-8: internal LR1110 pins, driven via SetDioAsRfSwitch) | — |
| (TCXO control: DIO3, internal, 1.6 V) | — |

All matches what `firmware/companion-cli-t1000e/src/main.rs` configures.

## Things that mattered along the way

### `use_dcdc = true` breaks USB on this hardware

Bisected: enabling the LR1110's internal DCDC regulator
(`SetRegMode(DCDC)`) coupled noise into the shared 3V3 rail and caused
the nRF52840's USB-CDC enumeration to flap rapidly between "available"
and "unavailable" on the host (heartbeat blinks, buttons respond — purely
a USB-stack symptom). The T1000-E module **does not expose the LR1110's
BST pin / external inductor** required for DCDC. Use LDO mode
unconditionally on this board. Documented in
[docs/t1000e-hardware.md](docs/t1000e-hardware.md).

Our lora-phy fork now always sends `SetRegMode` explicitly rather than
relying on the chip's post-reset default — because the LR1110's regulator
config can persist across warm resets, and an earlier "stuck DCDC" state
from a previous firmware can carry over.

### lora-phy's `get_status()` had a 1-byte alignment bug

`Lr1110::get_status` used `intf.read(&[], ...)` which is the
command-response read path that discards the first byte (the chip's
echo of stat1 during the command write phase). For a *direct* read with
no command, the chip returns `[stat1, stat2, irq0..irq3]` starting at
byte 0 — `intf.read()` was throwing away the real stat1 and shifting
everything by one byte. Fixed to use `direct_read()`.

The first time we used the buggy `get_status()`, we saw `mode=Sleep
cmd=Fail` and almost went on a wild goose chase. After the fix,
`mode=Rx cmd=Ok` — the actual chip state.

### CRC / Header errors were silently swallowed

lora-phy's `Lr1110::get_irq_state` in the `Receive(_)` arm did:

```rust
if IrqMask::CrcError.is_set(irq_flags) || IrqMask::HeaderError.is_set(irq_flags) {
    debug!("CRC or Header error");
}
```

— a `debug!` log that goes nowhere when defmt is a no-op (our case),
and then falls through to checking `PreambleDetected` and returning
`PreambleReceived`. **So a packet that the chip received but failed to
decode looked identical to "we detected a preamble".** Patched to
return `RadioError::CrcError` / `RadioError::HeaderError` instead.

After the patch: we still never see these errors in our scenario — the
chip really does stop at preamble detection, *before* the header is even
attempted.

### LR1110 IRQ output (DIO9 / DIO11) → nRF P1.01 wiring confirmed

We initially suspected the IRQ pin wasn't wired or wasn't being driven.
We added a `dio1_watch_task` that polls `embassy_nrf::pac::P1.in_().read().pin(1)`
every 2 ms (bypasses Embassy ownership of the pin). It does see edges
when the chip raises IRQ — confirming the wiring and the
`SetDioIrqParams(IRQ1=mask, IRQ2=mask)` flow lora-phy sends.

So interrupt-driven RX works at the GPIO/wiring level. The chip just
isn't raising the right *kind* of IRQ.

### PR #428 (lora-rs/lora-rs): pre-command BUSY check

[https://github.com/lora-rs/lora-rs/pull/428](https://github.com/lora-rs/lora-rs/pull/428)
fixes a real bug — both `SpiInterface` and `Lr1110SpiInterface` only
waited for BUSY *after* each SPI op, but the SX1261/2 datasheet and
LR1121 user manual require a BUSY wait *before* each command too. On
fast MCUs the next command races into the BUSY-assertion window and is
silently dropped.

We cherry-picked this into our lora-phy fork (commit `6a2df29`). It did
not fix our RX problem, but it's likely silently helping with other
intermittent issues we'd otherwise blame on noise.

### embassy `wait_for_high/low` leaves SENSE bits set → wake-from-System-OFF

When embassy-nrf's GPIO `wait_for_high/wait_for_low` future is in-flight,
the corresponding pin's `PIN_CNF.SENSE` is set. If we enter System OFF
with SENSE still active on a pin that matches its sense level, DETECT
fires immediately and the chip wakes — observable as "instant reboot on
long-press". We tristate the radio's DIO1 and BUSY pins (plus the SPI
bus pins for tidiness) in `shutdown_task` to clear the SENSE bits.

### Button-still-held bug

Even after tristating the radio pins, the device kept "rebooting on
long-press" — because the button itself was still held HIGH when
`shutdown_task` configured `WakeSense::High` on P0.06. DETECT matched
immediately. Fix: `button_task` waits for the button to be released
**before** signalling `SHUTDOWN_SIGNAL`. Documented in-line in
`button_task` for posterity.

### LR1110 RESET → drive LOW for power-down

Currently shutdown drives the LR1110's RESET pin (P1.10) LOW before
tristating the other radio pins. This holds the chip in reset (minimal
current, no DIO output). Added `drive_pin_low(port, pin)` helper to
`umsh-bsp-nrf52840::system_off`.

## Things tried that did not help

These each cost time and produced no improvement in RX:

1. **Switching between polling and interrupt-driven RX.** Both showed
   the same chip-side behavior (preambles fire, no progression).
2. **Adding `clear_errors()` + `clear_all_irq()` before `SetRx`.** Did
   not change preamble behavior. *Also* destabilised USB (still
   unexplained — there is something fragile about extra SPI calls in
   this init path that we don't understand yet).
3. **Setting `SetRegMode(LDO)` explicitly.** No change.
4. **Standby + re-prepare-for-RX after each HeaderError** (mirroring
   MeshCore's `CustomLR1110::getPacketLength()` workaround). Doesn't
   trigger anyway because we never get HeaderError.
5. **Verifying every individual SPI command's `Stat1.command_status`
   via a `checked_write_command` helper.** Every command lora-phy sends
   reports `cmd=Ok`. So nothing is being silently rejected.
6. **Changing to MeshCore "example" defaults (915 MHz / SF10 / BW250).**
   The user corrected us: their on-air params really are 910.525 MHz /
   SF7 / BW62.5 — these example defaults are not the US preset.

## Open questions / leads to chase

### Why preambles fire but no SyncWordValid

This is the central mystery. Both lora-phy and RadioLib send the same
`SetLoRaSyncWord(0x12)`. The opcode (`0x022B`) is correct. The chip
reports `cmd=Ok` after that write. Yet the chip never validates a sync
word.

Hypotheses, ranked by plausibility:

1. **The chip's sync-word matcher really doesn't see 0x12 even after
   the command lands.** Possibly a LR1110 firmware-version-specific
   quirk in 0x0307. RadioLib has been verified on T1000-E, but maybe
   on a different chip firmware revision.
2. **Some other config we set is silently overriding the sync word.**
   Worth a careful diff of every SPI byte sent in init vs RadioLib's
   exact byte stream.
3. **Hardware:** the user's specific T1000-E unit might have a damaged
   RX front-end, OR the antenna network is mismatched at our frequency
   such that we hear only intermod / preamble-shaped energy. Cannot be
   software-reproduced without an SDR or a known-good firmware on this
   exact unit.
4. **The "preambles" we see are not real LoRa preambles.** With
   `rx_boost=true` and a strong local TX, the chip's preamble detector
   could be triggering on intermod / image energy rather than the real
   packet. Worth testing with `rx_boost=false`.

### `Error` IRQ bit 23 stays set persistently

After every `process_irq_event` clear, the very next `get_status` read
shows `irq=0x00800000` (bit 23 = `Error`). But `get_errors()` returns
`0x0000`. So the chip's *Error IRQ summary bit* is set without any
underlying error condition. This is unexpected — `Error` is supposed to
mirror the `GetErrors()` register.

Possibilities:
- A real error did happen but `GetErrors` was already cleared
- The Error bit is being set in response to some routine command
- An LR1110 firmware quirk

### USB instability returns intermittently

We bisected once cleanly: `use_dcdc=true` → USB flaps; `use_dcdc=false`
→ stable. But across this session USB has gone in and out of stability
between builds whose differences shouldn't affect USB — for instance
adding/removing two `lora.radio_kind_mut().clear_*()` calls.

This is likely some accumulated chip state that we can't reset from
software (sealed unit, can't power-cycle the LR1110 separately from
the nRF). The clearest signal that we've hit it: heartbeat keeps
blinking at perfect regularity *while USB enumeration flaps*. CPU is
fine; chip is doing something weird that's coupling into 3V3.

A full battery-down power cycle would be the diagnostic — not
possible on this sealed unit.

## State of the lora-phy fork

`~/Projects/lora-rs`, branch `umsh/lr1110-rf-switch-config`. One
committed change on top of upstream main:

- `6a2df29 phy: pre-command BUSY check before each SPI op` (cherry-pick
  of upstream PR 428)

Plus *uncommitted* changes (intentionally kept for diagnosis, not yet
PR-worthy):

- `lr1110::Config::rf_switch: Option<RfSwitchConfig>` — board-specific
  DIO5–8 RF switch table. Required for the T1000-E and any board that
  isn't the lora-phy STM32WBA test board.
- `LoRa::radio_kind_mut()` — expose the inner `RadioKind` for
  chip-specific operations (`get_version`, `get_status`,
  `clear_errors`, etc.). Documented as use-sparingly.
- `Lr1110::get_status()` — use `direct_read` instead of `read` (1-byte
  alignment fix). Without this every chip-state diagnostic is garbage.
- `Lr1110::init_system()` — always send `SetRegMode` (LDO if
  `use_dcdc=false`, DCDC if `true`) instead of skipping the command
  when DCDC isn't requested. Protects against persistent stuck-in-DCDC
  state from a previous firmware.
- `RadioError::HeaderError` / `RadioError::CrcError` variants added;
  `Lr1110::get_irq_state` returns them (also for sx126x) instead of
  swallowing with `debug!`.
- `Lr1110::checked_write_command` helper — `write_command` + immediate
  `get_status`, returns `Err(OpError(opcode_low_byte))` if the chip's
  `Stat1.command_status` is `Fail`. Used in `init_lora`,
  `set_modulation_params`, `set_packet_params` for early failure
  detection.

Upstreaming candidates (in priority order):
1. `get_status` direct_read fix — clear correctness bug.
2. PR #428 BUSY-race fix is already upstream as a PR; just needs merge.
3. `RfSwitchConfig` addition to `lr1110::Config` — clean, additive,
   per the user's design hint.
4. `CrcError` / `HeaderError` surfacing — small breaking API change,
   useful diagnostics.
5. `radio_kind_mut()` accessor — small API addition, very useful.

## Useful diagnostic scaffolding currently in the firmware

These are not Phase 2.5's final state but are great to have when you
next sit down to debug:

- `dio1_watch_task` — polls P1.01 via PAC, prints level transitions.
  Tells you if the chip's IRQ pin is actually being driven.
- `[chip] version` / `[chip] post-init` / `[chip] post-SetRx` /
  `[chip] errors` lines in `radio_task` — read the chip's actual state
  via SPI, not just trust that commands "returned Ok".
- `[chip] idle` line every ~10 s during silence — confirms the chip is
  still in `ChipMode::Rx` and what its IRQ register looks like.
- `[radio] preambles=N` throttled log (every 50 preambles) — shows
  whether preambles are firing at all.
- `[radio] header_err=N`, `[radio] CRC err #N` — would fire if the
  chip ever validated a sync word and decoded into header phase.
- Custom `HardFault` handler that captures the exception frame into
  the panic slot and resets via `gpregret::reset_to_app()`. With the
  marker prefix, any "PREV PANIC:" line tells you whether you had a
  Rust panic vs HardFault.

## Suggested first moves next session

In order of "most likely to break the deadlock":

1. **Validate hardware**: temporarily flash MeshCore firmware on this
   exact T1000-E unit and confirm it can RX MeshCore traffic. If not,
   the hardware is the issue and no software change can fix it. If
   yes, the gap is something our firmware does differently.
2. **TX from T1000-E to T-Echo**: do a minimal TX-only firmware that
   transmits a known packet. If T-Echo decodes it, the LR1110 SPI /
   RF switch / antenna path is good in at least one direction.
3. **SDR capture**: use an RTL-SDR (cheap) to capture the actual
   on-air bytes when MeshCore TXes and our T1000-E "receives". Decode
   manually. Confirms what sync word / CR / SF / preamble length the
   TX is actually emitting at the moment we're listening.
4. **Diff every SPI byte we send vs RadioLib**: instrument both
   firmwares (or capture SPI on a logic analyser) and compare command
   streams byte for byte. The chip IS responding `cmd=Ok` so we can't
   blame a rejected command — but some byte we're sending may be
   getting interpreted differently.
5. **Try `rx_boost=false`**: if "preambles" are actually intermod /
   noise rather than real preambles, disabling boost should drop the
   rate. If the rate is unchanged (still only fires during real TX),
   it's real signal.
6. **Try public sync word (0x34, `enable_public_network=true`)**: rule
   out sync word entirely. If we still see only preambles (no
   advance) regardless of sync word value, the chip's sync-word stage
   isn't actually being reached / isn't checking.

## Plan-doc cross-reference

Phase 2.5 was an insertion between Phase 2 (power/DFU safety) and
Phase 3 (CLI plumbed) — see
[docs/firmware-plan-t1000e.md](docs/firmware-plan-t1000e.md) section
"Phasing". This document describes only the **RX bringup** subset of
Phase 2.5; the rest of the LR1110 path (TX, MAC integration, runner
task) was not attempted. The phase remains incomplete.
