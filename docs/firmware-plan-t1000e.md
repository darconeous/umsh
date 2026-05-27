# T1000E Companion-Radio CLI Firmware Plan

First firmware target for the UMSH project: a USB-CDC virtual-serial CLI on the
Seeed Studio SenseCap T1000E. Establishes the workspace structure (Approach A:
BSP + App + thin Binary) and the safety contract for power and DFU that every
subsequent firmware will inherit.

## Assumptions to verify (before any code)

1. **MCU:** nRF52840.
2. **Bootloader:** Adafruit nRF52 UF2 bootloader at `0xF4000`, app at `0x26000`
   (Meshtastic flavor) or `0x1000` (vanilla, no SoftDevice). T1000E almost
   certainly ships with the Meshtastic-compatible variant — confirm by reading
   flash before touching it.
3. **Radio:** Semtech LR1110 over SPI (LoRa only on this board — GNSS is a
   separate chip, see below). DIO3 drives a 1.6 V TCXO; DIO is used as RF
   switch. Driver: `lr11xx-rs` or a minimal one over `embedded-hal-async` SPI.
4. **GNSS:** AG3335 / Airoha module on UART1 (RX P0.14, TX P0.13, 115200 baud),
   with multi-pin power sequencing (main enable, RTC backup enable, reset,
   sleep/RTC interrupts, RESETB).
5. **Accelerometer:** QMA6100P over I²C (SDA P0.26, SCL P0.27), interrupt P1.02.
6. **No BLE in the initial firmware**, but the flash layout is preserved for a
   future SoftDevice (see [BLE future-proofing](#ble-future-proofing)). The
   region `0x1000`–`0x26000` stays empty for now; the app runs from `0x26000`
   to match the stock bootloader's expectations.

Full pin map and a firmware-derived block diagram live in
[t1000e-hardware.md](t1000e-hardware.md). That document is the source of truth
for pinouts and what we know about the power architecture; this plan only
references the bits that drive architectural decisions.

The bootloader assumption is the only one that can brick the device if wrong.
**First task is reading the existing flash via SWD/J-Link, not flashing
anything.**

## Workspace shape (additions only)

This firmware follows the BSP / UX / App / Binary layering documented in
[firmware-architecture.md](firmware-architecture.md). For T1000E
specifically we add:

```
crates/
  umsh-bsp-nrf52840/        # chip-BSP (USB clock, GPREGRET, sys_off,
                            #   1200-baud + escape rescue watchers)
  umsh-bsp-t1000e/          # board-BSP (pinout, LR1110 wiring, AG3335,
                            #   QMA6100P, panic-persist for now)
  umsh-ux-tracker/          # UX mechanism for tracker-class boards:
                            #   button FSM, LED heartbeat, buzzer
                            #   melodies, power intents, low-battery
  umsh-app-companion-cli/   # app-specific policy: button-event ↔ action
                            #   mapping, CLI commands, MAC integration
firmware/
  companion-cli-t1000e/     # binary glue
```

Why the layers split this way:

- **`umsh-ux-tracker`** is the mechanism layer for any board in the
  tracker class (single-button + single-LED + piezo buzzer + USB-CDC +
  battery). A future T1000-E repeater firmware would use the same
  `ButtonFsm`, `LedEngine`, and `BuzzerEngine` — only the *mapping* of
  button events to actions would differ.
- **The chip-BSP layer** exists because Solar P1 is also nRF52840 — both
  boards will share `umsh-bsp-nrf52840` for chip-level concerns
  (including the USB-CDC rescue watchers, which are tied to the Adafruit
  nRF52 bootloader) and only differ at the board-BSP layer.
- **`PanicSlot` lives in `umsh-bsp-t1000e` for now**, even though the
  framing itself is chip-agnostic. It'll get promoted to
  `umsh-bsp-nrf52840` or a dedicated crate when Solar P1 (or another
  consumer) appears.

See [Adding a new board](firmware-architecture.md#adding-a-new-board) and
[Adding a new firmware type](firmware-architecture.md#adding-a-new-firmware-type)
for the generalized recipes.

## Crate responsibilities

### `umsh-bsp-nrf52840` (chip-level, board-agnostic)

- `init_clocks()` — HFXO start, LF source select.
- `usb_driver()` — `embassy-nrf` USB peripheral wrapper.
- `gpregret` module — `enter_dfu_uf2() -> !`, `enter_dfu_serial() -> !`,
  `reset_to_app() -> !`. ✅ Implemented and hardware-verified on T-Echo.
- `system_off` module — ✅ Implemented in `crates/umsh-bsp-nrf52840/src/system_off.rs`.
  Key API:
  - `tristate_pin(port, pin)` — sets `PIN_CNF = 0x02` (input-disconnected, no
    pull, SENSE disabled). Call on every peripheral signal pin before sleeping.
  - `configure_wake(WakePin { port, pin, sense })` — sets SENSE bits only,
    preserving DIR/INPUT/PULL/DRIVE. `WakeSense::Low` for active-low buttons
    (T-Echo, pull-up); `WakeSense::High` for active-high buttons
    (T1000-E P0.06, pull-down).
  - `power_off(&[WakePin]) -> !` — configures SENSE on each wake pin then
    writes `POWER.SYSTEMOFF = 1`. Diverges.
  - **Critical gotcha (proven on T-Echo):** embassy's async GPIO layer
    (`Input::wait_for_high/low`) writes `PIN_CNF SENSE` bits that stay set
    until the wait completes. Any peripheral task mid-wait when `power_off` is
    called will have SENSE configured, causing an immediate DETECT wake from
    System OFF. Fix: call `tristate_pin` on *every* peripheral signal pin
    (including radio DIO and BUSY) before calling `power_off`.
- `RngBackend`, `FlashCounterStore`, `FlashKeyValueStore` — implementations of
  the `umsh-hal` traits using nRF52840 NVMC / `sequential-storage`.
  ✅ Implemented and hardware-verified on T-Echo (Phases 3–6 of T-Echo plan).

### `umsh-bsp-t1000e` (board-level)

- `Board::init()` — owns the embassy `Peripherals`, sets up pins, returns a
  struct of typed resources:
  - `radio: Lr1110<Spi, Cs, Busy, Reset, Irq>` — LoRa only (SCK P0.11,
    CS P0.12, MISO P1.08, MOSI P1.09, RESET P1.10, IRQ P1.01, BUSY P0.07)
  - `gnss: Ag3335<Uart, Enables>` — AG3335 on UART1 (RX P0.14, TX P0.13,
    115200) with power-sequencing pins (EN P1.11, RESET P1.15, VRTC_EN P0.08,
    SLEEP_INT P1.12, RTC_INT P0.15, RESETB P1.14)
  - `accel: Qma6100p<I2c, Int>` — I²C (SDA P0.26, SCL P0.27), INT P1.02
  - `button: ButtonInput` — P0.06, **active-high** with pull-down; DETECT
    sense-high for System OFF wake
  - `led: LedOutput` — P0.24, active-high
  - `buzzer: BuzzerOutput` — PWM P0.25, enable P1.05
  - `temp: NtcAdc` — P0.31 (AIN7), requires sensor rail
  - `light: LightAdc` — P0.29 (AIN5), requires sensor rail
  - `vbat: BatteryAdc` — P0.02 (AIN0) with 2:1 divider; requires sensor rail
    enabled during sample
  - `power_inputs: PowerInputs` — VBUS detect P0.05, charger status P1.03
    (active-low), USB-power via `nrfx_power_usbstatus_get()` equivalent
  - `rails: SwitchedRails` — gates for sensor rail (P1.06), accel rail
    (P1.07), temp/lux sensor enable (P0.04), GNSS pins as above
  - `usb: UsbDriver` — via 4-pin magnetic pogo connector

The `SwitchedRails` abstraction matters. The T1000-E has no PMIC; power
discipline is "enable rail → use peripheral → disable rail" implemented as
GPIO toggles. The BSP must expose these as RAII-style guards so app code can't
forget to disable a rail it enabled, and so that `enter_system_off()` can
reliably drop every rail before sleeping.
- Implements `umsh::Platform` by composing the chip-level pieces.
- Board-specific pin map lives in this crate only; nobody else hardcodes pins.

### `umsh-app-companion-cli` (firmware logic, `no_std + alloc`)

- Owns the embassy task topology:
  - `cli_task` — runs `umsh_cli::CliSession::run` over the USB-CDC adapter.
  - `mac_task` — runs `umsh::node::Host` poll loop.
  - `button_task` — runs the press FSM. **High priority.**
  - `shutdown_task` — waits on `SHUTDOWN_SIGNAL`, performs the ordered
    shutdown sequence (flush counters → LED/buzzer farewell → tristate all
    peripheral pins → drop rails → `power_off`). Mirrors the pattern
    proven on T-Echo.
  - `led_task` — visual feedback; owns the heartbeat (see [LED behavior](#led-behavior)).
  - `gnss_task` — duty-cycled GNSS fix acquisition (only when GPS is enabled).
- `UsbCdcCliIo` — wraps `embassy-usb` CDC-ACM read/write halves to implement
  `CliInput`/`CliOutput`.
- Power-off is wired via the `umsh_hal::PowerControl` trait (✅ implemented).
  `CliSession<…, PowerSignaler>` calls `PowerSignaler::request_power_off()`
  which signals `SHUTDOWN_SIGNAL`. This replaces the `PowerIntent` channel
  described in earlier drafts of this plan — the `PowerControl` trait is
  simpler and already tested on the T-Echo.
- DFU entry remains a separate path through `umsh-bsp-nrf52840::gpregret`
  (not via `PowerControl`) since it's a one-way diverging reset, not a
  coordinated shutdown.
- App-specific CLI commands (`location`, `silence`, `gnss on|off`, `/poweroff`,
  `dfu`, `reboot`) plug into `umsh-cli`'s command dispatch. `/poweroff` and
  `/off` are already implemented in `umsh-cli`. ✅

### `firmware/companion-cli-t1000e` (binary)

```rust
#[embassy_executor::main]
async fn main(spawner: Spawner) -> ! {
    let board = umsh_bsp_t1000e::Board::init();
    umsh_app_companion_cli::run(spawner, board).await
}
```

That's the whole binary. Linker script, `memory.x`, `.cargo/config.toml`, and
the `probe-rs` chip/connect config live here.

## The safety contract — power on / off / DFU

This is the load-bearing part. Defense in depth, multiple independent paths to
each operation.

### Power ON

| Path | Always works? |
|---|---|
| Hardware reset (RST pin if exposed) | Yes |
| Button wakes from System OFF (DETECT latched on GPIO) | Yes, hardware-only |
| USB plug-in wakes from System OFF | Yes (if VBUS detection enabled in BSP) |

No firmware involvement once we're off. The button-DETECT setup happens in
`power_off` *before* we cut to System OFF — wake source is armed by hardware
before firmware stops running. T1000-E button (P0.06, active-high, pull-down)
uses `WakeSense::High`; the T-Echo (P1.10, active-low, pull-up) uses
`WakeSense::Low`. Both are supported by `system_off::configure_wake`.

### Low-battery shutdown (firmware-enforced)

The T1000-E has no I²C PMIC and no confirmed hardware undervoltage cutoff —
protection of the Li-ion cell is firmware's responsibility. Mirror the
Meshtastic behavior: sample battery voltage periodically (via P0.02 with the
sensor rail enabled during the read), and when ≥10 consecutive samples are
below ~3.1 V *and* USB is not powering the board, send a `PowerOff` intent.
This becomes an additional path into `enter_system_off()` from `power_task`,
independent of the button. Hysteresis on USB-powered state prevents flapping
during charge transients.

### Power OFF (long-press 5 s)

| Path | Failure mode it survives |
|---|---|
| `button_task` detects long-press → sends `PowerOff` intent | Normal path |
| `button_task` independently calls `enter_system_off` if intent channel is full | CLI session hung |
| Hardware watchdog (WDT, 8 s) reboots → app re-reads button at boot, treats "still held" as forced off | App is fully wedged |
| Bootloader double-tap reset → DFU → user reflashes | App can't even boot |

`button_task` runs from its own embassy task, drives an independent embassy
timer, and *does not depend on the CLI or MAC tasks being alive*. Its only
output is the intent channel — and if the channel is full, it calls the BSP
poweroff helper directly. The MAC's `Host` poll loop is *not* in the critical
path.

### DFU entry

The Adafruit nRF52 UF2 bootloader recognizes the following `POWER.GPREGRET`
values on reset:

| GPREGRET | Mode |
|---|---|
| `0x57` | UF2 mass-storage (drag-and-drop `.uf2` file) |
| `0x4e` | Serial / CDC DFU |
| `0xA8` | BLE OTA |

The BSP exposes two entry points rather than one, since the two common DFU
modes serve different audiences:

- `bsp::enter_dfu_serial() -> !` — sets `0x4e`, enters serial/CDC DFU mode.
  Device stays enumerated as a USB CDC serial device and speaks the Nordic
  serial DFU protocol (SLIP-encoded HCI). Required by the web flasher
  (`flasher.meshcore.co.uk` via WebSerial) and `adafruit-nrfutil --touch 1200`.
  WebSerial cannot talk to a mass-storage device, so this mode is mandatory for
  browser-based flashing.
- `bsp::enter_dfu_uf2() -> !` — sets `0x57`, enters UF2 mass-storage mode.
  Device appears as a USB drive; drag a `.uf2` file onto it. Convenient for
  manual flashing but unusable from WebSerial.

Note: **the Adafruit nRF52 bootloader does not implement 1200-baud detection
itself** — that logic must live in the firmware. If our firmware doesn't handle
it, the web flasher and `adafruit-nrfutil --touch 1200` both fail silently.

Trigger paths:

| Path | GPREGRET | Notes |
|---|---|---|
| **1200-baud touchless reset** | `0x4e` | Host opens USB CDC at 1200 baud then drops DTR; USB-CDC task detects `SET_LINE_CODING` change and calls `bsp::enter_dfu_serial()` — this is how `flasher.meshcore.co.uk` (WebSerial) and `adafruit-nrfutil --touch 1200` trigger DFU |
| CLI command `dfu` | `0x57` | Sends `EnterDfu` intent → `power_task` calls `bsp::enter_dfu_uf2()`; convenient for manual drag-and-drop |
| CLI command `dfu serial` | `0x4e` | As above but calls `bsp::enter_dfu_serial()` |
| Serial rescue escape | `0x4e` | USB-CDC RX hook (below the CLI parser) watches for e.g. `\x03\x03\x03dfu\r` and calls `bsp::enter_dfu_serial()` directly |
| **Hardware RESET circuit + bootloader double-tap** | — | The T1000-E has a discrete circuit (RC + supervisor or similar) that pulses the nRF52840 RESET pin when VBUS rises **while** the button is held. Connect USB with button held → RESET → bootloader → no magic yet → app boots. Disconnect → reconnect with button still held → RESET again (within the bootloader's ~500 ms double-tap window) → bootloader sees double-tap magic → DFU. Works across all firmwares (Meshtastic, MeshCore, ours) because it is entirely hardware + bootloader. "Do it quickly / may need multiple tries" = timing against the double-tap window. **We do not need to implement this in firmware. Do not reconfigure P0.18 (RESET) or modify UICR reset-pin settings.** |
| **Button held at boot** | `0x4e` | App startup: read button (P0.06, pull-down) before embassy tasks start; if HIGH, call `enter_dfu_serial()`. Defense-in-depth for soft-reset scenarios (WDT reset, `NVIC_SystemReset()`) where the hardware RESET pulse path is not involved. ~10 ms pull-down settle via `cortex_m::asm::delay`. |

**The 1200-baud touchless reset is the most important path to get right.**
Implement it inside the USB-CDC task as a `SET_LINE_CODING` control-request
handler: when the host sets the baud rate to 1200 and DTR subsequently drops,
call `bsp::enter_dfu_serial()` immediately. This runs below `UsbCdcCliIo` and
below the rescue escape — no cooperation from the CLI session required.

The rescue escape covers the case where the CLI parser is locked up (panicked
task, deadlocked channel, mis-parsed input mode). Implement as a small state
machine in the USB-CDC read task before bytes reach the CLI: three Ctrl-Cs
reset parser state, and `dfu\r` after that triggers DFU.

### Invariants we never break

The T1000E is factory-sealed: **no SWD access**, no way to recover from a
bricked bootloader. These invariants exist because violating them produces a
permanently dead device.

1. The firmware **never writes to the bootloader region** (`0xF4000`+) or the
   MBR (`0x000000`). There is no J-Link rescue path; corrupting either of
   these bricks the device forever.
2. The firmware **never disables the WDT** once started.
3. The firmware **never holds the button GPIO** in a way that prevents DETECT
   from latching, since the bootloader's double-reset detection (our last
   software-recovery path) depends on the device being reachable across
   resets.
4. `bsp::enter_dfu_*()` and `bsp::enter_system_off()` are the *only* functions
   that touch GPREGRET / enter SystemOff. They live in the BSP; the app only
   sends intents.
5. Panics route to a `panic-persist`-style handler that writes the panic
   message to retained RAM (UICR-backed or `noinit` section) and sets a "last
   run panicked" flag. The next boot reads it back and surfaces it over the
   CLI rather than silently overwriting. `panic-probe`/RTT is unavailable
   here because there is no SWD probe.

## Recovery constraints (no SWD)

The case is sealed and the SWD pads are unreachable without destructive
disassembly. The only ways to get bytes into or out of the device are:

- **USB CDC** (via the magnetic pogo connector) — our primary I/O.
- **BLE** (eventually, when added) — secondary I/O.
- **UF2 mass-storage DFU** — bootloader-mediated, drag-and-drop flashing.
- **Serial DFU** — bootloader-mediated, `adafruit-nrfutil` or WebSerial.
- **Bootloader double-reset detection** — hardware-level last resort, runs
  before any app code; user double-taps the magnetic-cable connection or
  triggers a reset through some other path.

Consequences for development:

- **No RTT logging.** All logs go over USB CDC. Phase 1 should bring up a
  log stream early (potentially a second CDC interface, see open question 4)
  so that subsequent phases have visibility.
- **No `probe-rs run`.** The flash loop is always: build → UF2-convert →
  copy to mass-storage drive. Slower than SWD-based dev; we should make
  this a one-command `just flash` recipe to minimize friction.
- **Panic visibility requires reboot.** A panic disconnects USB; the user
  must wait for the bootloader to come back, then the new app reads retained
  RAM and prints the previous panic over USB CDC. Phase 2 should build this
  early — without it, every panic is a black box.
- **No way to verify our bootloader assumption by reading flash.** Phase 0
  inspects `INFO_UF2.TXT` from the UF2 drive instead, which the Adafruit
  bootloader auto-generates with bootloader name, version, board ID, and the
  app flash range.
- **Bootloader replacement is not an option.** Even if a newer Adafruit
  bootloader exists, flashing it requires SWD. We work with what's on the
  device.

This is why the safety contract above is so paranoid about defense-in-depth:
every "this could be the last reachable channel" scenario must actually have
a working escape. A device that goes dark with no SWD recovery is e-waste.

## BLE future-proofing

BLE isn't in the initial firmware, but it's wanted later (likely for phone
companion / provisioning). A few decisions now keep that path cheap:

- **Flash layout.** `memory.x` explicitly reserves `0x1000`–`0x26000` for a
  future SoftDevice. App always starts at `0x26000`. This matches what the
  stock T1000E bootloader already expects, so no relayout / re-flash dance
  later.
- **Peripheral discipline.** Don't claim peripherals that a SoftDevice would
  later take back: `RADIO`, `TIMER0`, `RTC0`, `RNG`, `CCM`, `AAR`, the highest
  PPI channels, and the top two interrupt priorities. Embassy's default time
  driver uses `RTC1`, which is fine. Route RNG through a BSP trait so the
  backend can switch from raw `nrf-hal` RNG to SoftDevice-mediated RNG without
  touching app code.
- **No on-chip radio use.** LR1110 (LoRa) is SPI-attached and unrelated to the
  nRF's on-chip 2.4 GHz `RADIO`. Don't use the on-chip radio for anything
  (NFC, ESB, proprietary 2.4 GHz) that would compete with future BLE.
- **BLE stack choice deferred.** Two viable paths when we get there:
  - `nrf-softdevice` — Nordic's SoftDevice blob + Rust bindings. Mature, fits
    the reserved slot exactly, but proprietary and restricts peripheral
    access.
  - `trouble-host` — pure-Rust BLE host atop `embassy-nrf`'s raw radio.
    Future-aligned with embassy, no blob, keeps full peripheral ownership,
    but less battle-tested. Would leave the reserved slot empty.

  Pick at the time. The discipline above keeps both doors open.

## Button events

Single button, no display, so press semantics are the entire UX. The
`button_task` resolves raw GPIO edges into one of five events using debounce
and inter-press timeouts:

| Event | Detection rule | Action |
|---|---|---|
| `single` | Released after < 250 ms hold, no second press within 400 ms | Broadcast a location advertisement (with fix if GNSS has one, otherwise note "no fix") |
| `double` | Two `single`-shaped presses within 400 ms of each other, no third within 400 ms | Toggle silence (disables buzzer; LED is unaffected) |
| `triple` | Three `single`-shaped presses within 400 ms of each other | Toggle GNSS power (`gnss_task` parked when off) |
| `long` | Held continuously ≥ 5 s | `enter_system_off()` |

Timings are starting points and will need tuning on real hardware.

Long-press detection runs from an independent timer and is allowed to fire
mid-click-sequence: once the button has been held continuously for 5 s, the
device powers off regardless of which short-press state we're in. This means
the user can't accidentally cancel a power-off by accumulating clicks while
holding.

## LED behavior

The LED is the only visual feedback channel on this board, so it doubles as a
"device is alive" indicator and an event channel. **The LED is never suppressed
by silence mode** — silence only affects the buzzer.

- **Power-on sequence.** One long flash (1 s) immediately on boot, before the
  MAC or CLI are up. Paired with a rising melody on the buzzer (see
  [Buzzer behavior](#buzzer-behavior)).
- **Heartbeat.** ~50 ms flash every 2 s while the device is running. Always
  active — never suppressed. Cheap on battery (~25 ms LED-on per 2 s ≈ 1.25%
  duty) and the clearest signal that the firmware is alive; if it stops, the
  watchdog will reboot shortly.
- **Event flashes** — short distinct patterns layered on top of the heartbeat
  rhythm: e.g. quick double-blink on outgoing location advert, slow pulse
  while GNSS is acquiring a fix.
- **Power-off sequence.** Three short flashes just before `enter_system_off()`.
  Paired with a falling melody on the buzzer.
- **Driven by `led_task`** with its own embassy timer. Other tasks send
  `LedEvent`s over a channel; `led_task` arbitrates between sequences and the
  heartbeat. The heartbeat timer runs independently of MAC/CLI activity.

The heartbeat is only meaningful if `led_task` itself is scheduled. As a
secondary liveness check, `button_task` (which runs at higher priority) is the
ultimate "device responds to input" indicator — the heartbeat tells you the
async runtime is making progress, the button tells you the device is at all
reachable.

## Buzzer behavior

Silent mode disables the buzzer but never the LED. The T1000E has a real
buzzer (P0.25, enable P1.05). The buzzer driver and melody sequencing are
stubbed to a no-op in the initial phases — the hardware interface is defined
now so wiring it up later doesn't touch app logic.

- **Power-on.** Rising melody (short ascending tone sequence). Suppressed in
  silent mode.
- **Power-off.** Falling melody (short descending tone sequence). Suppressed in
  silent mode.
- **Silent toggle.** No audible confirmation (since we're toggling into/out of
  silence, a sound on entering silence would be annoying and a sound on
  entering silence would go unheard).
- **All other events** — TBD as behaviors are added.

## Phasing

Each phase ends in a flashable, demonstrable artifact.

### Phase 0 — Bootloader reconnaissance (no SWD) ✅

Triggered UF2 mode on a stock T1000-E, mounted `/Volumes/T1000-E`, read
`INFO_UF2.TXT`, and confirmed the app start address by scanning the first-block
target address in `CURRENT.UF2`.

| Fact | Value |
|---|---|
| Bootloader | Seeed fork UF2 0.9.1-5-g488711a |
| Board-ID | `nRF52840-T1000-E-v1` |
| SoftDevice | **S140 7.3.0** (same as Wio Tracker L1) |
| App flash start | **`0x00027000`** (confirmed by UF2 block scan; `memory.x` pre-assumption of `0x26000` was wrong) |
| App flash length | **820K** (to bootloader at `0xF4000`) |
| UF2 family ID | **`0x28860057`** (Seeed VID `0x2886` \| T1000-E PID `0x0057`) |
| Bootloader mount | `/Volumes/T1000-E` |

`memory.x`, `scripts/flash.py`, and the `Makefile` `flash-companion-cli-t1000e`
target have been updated with the confirmed values.

**Gate:** ✅ flash layout and UF2 family ID confirmed; proceed to Phase 1.

### Phase 1 — "Hello USB-CDC" ✅

Embassy USB-CDC echo on the T1000-E, hardware-verified. Mirrors the T-Echo /
Wio Tracker pattern with these board-specific differences:

- LED P0.24, active-HIGH (set_high = on; opposite of T-Echo P0.14)
- Button P0.06, active-HIGH with pull-down (boot-time DFU check uses `is_high()`)
- No peripheral power-enable rail
- USB IDs: 0x2886:0x0057 (Seeed T1000-E)
- Heap allocator NOT needed (no MAC/CLI in Phase 1)

**Non-obvious gotcha worth recording (one full debug session):**
`CdcAcmRescue::read_packet()` returns `Ok(0)` immediately when DTR is LOW.
A read task that does `loop { read_packet().await }` without first calling
`wait_connection().await` busy-loops the executor and starves heartbeat,
causing a WDT reset every 8 s. Symptom: LED solid on (heartbeat ran once)
+ ~8 s reboot loop. Fix: nested-loop pattern (outer `wait_connection`,
inner `read_packet` until Ok(0)/Err, then back to outer).

**Flashing on T1000-E without UF2 mass-storage:** the user-button-held bootloader
entry path only exposes serial DFU (`/dev/tty.usbmodem*`). UF2 mass-storage
mode requires the hardware "connect USB twice while holding button" path. For
iterating on firmware during bringup, use `adafruit-nrfutil dfu serial`:

```
arm-none-eabi-objcopy -O ihex <elf> <out.hex>
adafruit-nrfutil dfu genpkg --dev-type 0x0052 --application <out.hex> <out.zip>
adafruit-nrfutil --verbose dfu serial -pkg <out.zip> -p /dev/tty.usbmodem1101 -b 115200
```

The `--dev-type 0x0052` is required (any non-zero value works; the bootloader
ignores it but the tool rejects packages without it).

**Gate:** ✅ USB CDC enumerates on host, banner appears on connect, echo
works, LED blinks at LedEngine default cadence, WDT survives indefinitely.

### Phase 2 — Power/DFU safety primitives ✅

Button task (`ButtonFsm` over P0.06) plus a shutdown task that tri-states the
LED and enters System OFF with the button armed as the wake source.
Hardware-verified.

| Action | Trigger | Path |
|---|---|---|
| Power off | Long-press ≥ 5 s | `button_task` → `SHUTDOWN_SIGNAL` → `shutdown_task` → `power_off([WakePin { P0.06, High }])` |
| Wake | Press button while off | DETECT-high on P0.06 (hardware-only) |
| DFU (UF2) | Triple-tap | `button_task` → `enter_dfu_uf2()` |
| DFU (serial) | Button held at boot | `main()` button check → `enter_dfu_serial()` |
| DFU (UF2) | 1200-baud touch | `CdcAcmRescue` → `enter_dfu_uf2()` |
| DFU (UF2) | Ctrl-C×3 + `dfu\r` | `CdcAcmRescue` → `enter_dfu_uf2()` |
| DFU (UF2) | Hardware double-USB-connect | Discrete RESET circuit + bootloader (no firmware involvement) |

The BSP pieces were already implemented and hardware-verified before Phase 2:

- `gpregret` module (`enter_dfu_uf2`, `enter_dfu_serial`, `reset_to_app`) ✅
- `system_off` module (`tristate_pin`, `configure_wake`, `power_off`) ✅
- `CdcAcmRescue` (1200-baud touch + Ctrl-C×3 `dfu\r` escape) ✅
- `ButtonFsm` in `umsh-ux-tracker::button` ✅

Phase 2 just wired them together for the T1000-E:

- **Button task.** Owns `Input<P0.06, Pull::Down>`, races GPIO edges against
  `ButtonFsm::next_deadline()` so the FSM gets both `on_edge` and `poll` calls
  at the right times. Translates `ButtonEvent::Long` → `SHUTDOWN_SIGNAL` and
  `ButtonEvent::Triple` → diverging `enter_dfu_uf2()`. The same `Input` is
  re-used after the boot-time DFU check (created once, then handed to the
  task — claims the peripheral exactly once).
- **Shutdown task.** Waits on `SHUTDOWN_SIGNAL`, then `tristate_pin(P0.24)`
  (LED — kills heartbeat's drive into the LED pin via direct PIN_CNF write,
  no need to coordinate ownership with the heartbeat task), then `power_off`.
  `tristate_pin` operates via PAC writes so it works regardless of which
  Embassy task still "owns" the pin.
- **Button wake.** P0.06 is active-high with pull-down → `WakeSense::High`.
  We do *not* tristate it in shutdown — that would clear the SENSE bits
  `power_off` is about to set.

Phase 2 only owns the LED and the button. Future phases must extend the
shutdown tristate list as they bring up the radio, GNSS, accelerometer, and
buzzer. The pins to add (deferred until those drivers exist):

- LR1110 SPI bus: SCK P0.11, MOSI P1.09, MISO P1.08, CS P0.12
- LR1110 control: RST P1.10, IRQ P1.01, BUSY P0.07
- AG3335 UART: TX P0.13, RX P0.14
- Accelerometer I²C: SDA P0.26, SCL P0.27
- Plus any rail-gated ADC pins.

The `SwitchedRails` RAII guards (when introduced in the board BSP) will drop
the rails themselves; the tristate calls cover the signal lines separately.

**Don't forget the LR1110 IRQ/BUSY pins** once the radio is up. Embassy's
async GPIO writes `PIN_CNF SENSE` for any `wait_for_high/low` that is
in-flight. An un-tristated IRQ or BUSY pin with SENSE still set will fire
DETECT and immediately wake the chip from System OFF — this exact bug was
observed and fixed on the T-Echo with DIO1 (P0.20).

**Note on the "connect USB twice while holding button" path:** hardware +
bootloader, not firmware. A discrete circuit on the T1000-E pulses the
nRF52840 RESET pin when VBUS rises with the button held, making two quick
USB connections look like a double-tap reset to the bootloader. Works
regardless of what firmware is running. Do not try to replicate it in
software and do not touch P0.18 (RESET) or the UICR reset-pin configuration.

**Gate:** ✅ long-press powers off, short-press wakes, triple-tap enters UF2
DFU. Hardware double-connect rescue path remains available because firmware
never touches the RESET pin.

### Phase 3 — CLI plumbed

Bring up `umsh-cli` over USB-CDC with the rescue escape preserved. No MAC yet.

`/poweroff` and `/off` commands are already implemented in `umsh-cli` via the
`PowerControl` trait (✅). Wire `PowerSignaler` (a unit struct implementing
`PowerControl` that fires a static `SHUTDOWN_SIGNAL`) into `CliSession::new`.
Spawn a `shutdown_task` that waits on the signal and runs the shutdown sequence.

`/dfu` and `/reboot` are T1000-E-specific CLI extensions not yet in the generic
CLI — add them as app-specific commands in `umsh-app-companion-cli`.

**Gate:** user gets a prompt, can run `/help`, `/dfu`, `/poweroff` from a host
terminal.

### Phase 4 — MAC + LR1110

Implement the LR1110 driver, wire `umsh::node::Host`. CLI exposes node-level
operations (peer list, send, etc.). No GNSS, no button advertisement.

**Gate:** two T1000Es can exchange a packet via the CLI.

### Phase 5 — GNSS + button UX

AG3335 GNSS driver (UART NMEA, with the multi-pin power sequencing —
EN/RESET/VRTC_EN/SLEEP_INT/RTC_INT/RESETB), location advertisements,
single/double/triple click semantics, LED feedback.

**Gate:** pressing the button broadcasts a fix; double-press silences;
triple-press toggles GNSS.

### Phase 6 — Persistence

Frame counters and identity in flash via `sequential-storage`. The full
storage stack is already implemented and hardware-verified on T-Echo and
Wio Tracker (T-Echo Phases 3–6):

- **Identity** — Ed25519 secret key persisted to NVMC on first boot;
  loaded on subsequent boots. Generated from the hardware TRNG
  (`embassy_nrf::rng::Rng` with bias correction). Never falls back to
  FICR-seeded PRNG.
- **Peer registry** — per-peer records keyed by 32-byte public key.
  Record layout: `[alias_len (1B) | alias slot (16B) | NodeIdentityPayload bytes]`.
  Alias (locally chosen) is separate from the remote-chosen name.
- **Channel keys** — stored by channel name, restored at boot via
  `CliSession::register_channel`.
- **TX frame counter** — persisted in blocks of 128 to bound flash wear.
  Loaded at boot via `mac.load_persisted_counter`. Auto-serviced from
  `Mac::next_event`.
- **RX per-peer counters** — replay-window baseline persisted similarly.
  Loaded at boot via `MacHandle::load_all_persisted_rx_counters`.
  Auto-serviced from `Mac::next_event`.
- **Flush on shutdown** — `shutdown_task` calls
  `MacHandle::service_counter_persistence()` before entering System OFF
  to ensure any partial TX block is committed.

Storage key scheme and `sequential-storage` configuration documented in
`docs/firmware-storage-plan.md`.

**Gate:** device retains identity, peer list, channel keys, and replay
counters across power cycles.

## Build / flash recipe

No SWD on T1000E — the loop is always build → UF2 → mass-storage drop, or
build → UF2 → serial DFU via the bootloader.

- `cargo build -p firmware-companion-cli-t1000e --release` (target pinned in
  that crate's `.cargo/config.toml`).
- Convert ELF → UF2 via `uf2conv.py` or `cargo-binutils` + `uf2-tool`; the
  `firmware/` crate `[package.metadata]` carries the bootloader's family-ID
  (recorded in Phase 0).
- `just flash t1000e companion-cli` recipe: builds, converts to UF2, triggers
  1200-baud touchless reset on the device, waits for the UF2 mass-storage
  drive to appear, copies the file, waits for the new firmware to boot. Whole
  cycle should be one command.
- `just monitor t1000e` — opens the USB CDC port at 115200 and pipes through
  to the terminal. Filters/colors `defmt`-over-CDC output if we go that route
  for logging.
- `just dfu t1000e` — sends the 1200-baud touch (or the rescue escape) to
  force the device into DFU without unplugging.
- `just recover` — instructions only (the device must be physically
  double-tapped); we cannot do this from software.

## Open questions before Phase 0

1. **Confirm the bootloader on a stock T1000E** via `INFO_UF2.TXT`. We expect
   the Meshtastic/Adafruit UF2 bootloader with app start at `0x26000`, but
   Phase 0 has to verify before we link the app. There is no SWD escape
   hatch if we guess wrong.
2. **Should the CLI be a single CDC interface, or two CDC interfaces** (one
   for commands, one for log output) so logs don't interleave with command
   responses? Two interfaces is friendlier for tooling and useful for
   surfacing panic dumps separately.
3. **GNSS duty cycle policy** — always-on while powered, or off-by-default
   and only on via triple-click? Big impact on battery life; affects how we
   structure `gnss_task`. The hardware supports a backup-RTC mode
   (`GPS_VRTC_EN`) that may let us keep ephemeris warm while the main GPS
   rail is off — worth exploring.
4. **Battery measurement scheduling.** `getBattMilliVolts()` requires
   enabling the sensor rail (P1.06) before the ADC read. Decide whether to
   keep the rail always-on (simpler, more current draw) or pulse it per
   measurement (Meshcore's approach). Couples to the low-battery shutdown
   path — we need samples often enough to count to 10 consecutive low
   readings in a reasonable window.
