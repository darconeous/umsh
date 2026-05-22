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
- `enter_dfu() -> !` — sets `POWER.GPREGRET = 0x57` then `SCB::sys_reset()`.
  *Single function in the codebase that can put the device in DFU mode.*
- `enter_system_off(wake_pin) -> !` — configures DETECT on the button pin,
  enters System OFF.
- `RngBackend`, `FlashCounterStore`, `FlashKeyValueStore` — implementations of
  the `umsh-hal` traits using nRF52840 NVMC / `sequential-storage`.

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
  - `power_task` — listens for power/DFU intents from any source.
  - `led_task` — visual feedback; owns the heartbeat (see [LED behavior](#led-behavior)).
  - `gnss_task` — duty-cycled GNSS fix acquisition (only when GPS is enabled).
- `UsbCdcCliIo` — wraps `embassy-usb` CDC-ACM read/write halves to implement
  `CliInput`/`CliOutput`. Hooks `embedded-io-async` to the existing CLI
  `serial` feature.
- Defines a `PowerIntent` enum (`PowerOff`, `EnterDfu`, `Reboot`) sent over an
  `embassy_sync::Channel` to `power_task`.
- App-specific CLI commands (`location`, `silence`, `gnss on|off`, `poweroff`,
  `dfu`, `reboot`) plug into `umsh-cli`'s command dispatch.

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
`enter_system_off` *before* we cut to System OFF — wake source is armed by
hardware before firmware stops running.

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
| Adafruit bootloader double-reset | — | Hardware-detected by bootloader, independent of app |
| Long-press + button-held-at-boot recovery | `0x4e` | App startup logic: button held at reset for >2 s jumps to serial DFU |

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

### Phase 0 — Bootloader reconnaissance (no SWD)

Since the case is sealed, we can't read flash directly. Instead, characterize
the bootloader through the channels it exposes:

- Trigger UF2 mode (double-tap the magnetic connector or use the stock
  firmware's DFU path). Inspect `INFO_UF2.TXT` on the mass-storage drive — it
  reports bootloader name, version, board ID / UF2 family ID, and the app
  flash range (start/end addresses). This tells us where to link the app and
  what UF2 family ID to embed.
- Verify that 1200-baud touchless reset works with the **stock firmware**
  using `adafruit-nrfutil --touch 1200` and the MeshCore web flasher. If it
  does, the stock firmware implements the line-coding hook — we'll need to
  reproduce that behavior. If it doesn't, only double-reset works for entering
  DFU from a running app.
- Verify the bootloader's double-reset detection by physically toggling power
  twice quickly. This is our ultimate recovery path; confirm it works now,
  before we ever flash custom firmware.
- Record the USB VID/PID, CDC interface count, and any other USB descriptors
  the stock firmware presents — useful for diagnosing our own enumeration
  later.

**Gate:** we have a written record of the bootloader version, app flash range
(from `INFO_UF2.TXT`), UF2 family ID, and confirmed that both UF2 drag-drop
and double-reset recovery work on the unmodified device.

### Phase 1 — "Hello USB-CDC"

New crates created but mostly empty. Binary: embassy-nrf USB CDC echo. No
umsh. Flash via UF2.

**Gate:** USB CDC enumerates on host, echoes characters.

### Phase 2 — Power/DFU safety primitives

Add `bsp::enter_dfu()`, `bsp::enter_system_off()`, GPREGRET helpers, the
USB-CDC rescue escape, the WDT setup, and a *minimal* button task that handles
long-press-off and triple-tap-DFU. No umsh yet, no CLI.

**Gate:** user can poweroff with long-press, wake with short-press, enter DFU
via serial escape, and the device is recoverable via double-reset even after a
forced panic.

### Phase 3 — CLI plumbed

Bring up `umsh-cli` over USB-CDC with the rescue escape preserved. Stub `dfu`,
`poweroff`, `reboot` commands. No MAC yet.

**Gate:** user gets a prompt, can run `help`, `dfu`, `poweroff` from a host
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

Frame counters and identity in flash via `sequential-storage`.

**Gate:** device retains identity and replay counters across power cycles.

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
