# Seeed Wio Tracker L1 / L1 Pro Bringup Firmware Plan

A second `nRF52840 + SX1262` bringup, riding on everything we proved
out with the T-Echo. The primary motivation is **getting a second
UMSH node on the air**: the T-Echo's "MAC: 0" counter cannot advance
until a second UMSH-speaking radio exists, and the Wio Tracker L1 Pro
is the closest thing to "same hardware as the T-Echo, different
package" in the device pile.

This plan deliberately reuses the T-Echo phasing where it applies and
shortens or skips phases where the chip-level work is already done.

See [seeed-wio-tracker-l1-pro-hardware.md](seeed-wio-tracker-l1-pro-hardware.md)
for the hardware reference. See
[firmware-plan-techo.md](firmware-plan-techo.md) for the precedent
this plan rides on. See
[firmware-architecture.md](firmware-architecture.md) for the BSP /
UX / App / Binary layering.

## Why this device, why now

- **Same MCU + radio as the T-Echo.** Identical embassy stack,
  identical UF2 bootloader posture, identical `lora-phy` + `umsh-radio-sx126x`
  pipeline. The Phase 0–2 work from the T-Echo carries over almost
  unchanged.
- **Recoverable.** Like the T-Echo, the Wio Tracker is not
  factory-sealed. SWD is broken out; a brick is recoverable. This is
  important because we *are* going to learn things about this board's
  pinout that the hardware reconstruction may have gotten wrong.
- **Forcing function for "second node".** Phase 6 of the T-Echo plan
  ended at "MAC: 0, no second UMSH node to receive from." This plan
  is the thing that flips that counter.
- **Doesn't replace T1000-E work.** The T1000-E is the eventual
  production tracker target; the Wio Tracker is a step in the same
  direction (tracker-class device with GNSS + battery + radio) on
  cheaper recoverable hardware.

## Scope (in / out)

**In scope.** A binary that, when flashed via UF2 onto a stock-bootloader
Wio Tracker L1 / L1 Pro:

- enumerates as a USB-CDC serial device,
- responds to the 1200-baud touchless reset and the
  `\x03\x03\x03dfu\r` escape rescue (reused from `umsh-bsp-nrf52840`),
- captures panics into retained RAM and surfaces them over USB-CDC on
  the next boot (reused from `umsh-bsp-nrf52840`),
- blinks the user LED (D11 / P1.01) as a slow heartbeat,
- initializes the SH1106 OLED display and writes a boot banner
  ("UMSH bringup" + git short SHA + "MAC: N"),
- initializes the SX1262 on the Wio Tracker's pin map and drives the
  external RXEN line so RX actually works,
- runs the full `Mac<P>` coordinator with the same minimal capacity
  used on the T-Echo, increments and displays a count of authenticated
  UMSH packets.

**Out of scope** for this bringup:

- GNSS (Quectel L76K / UART1 + standby pin) — wired, not driven.
- Joystick / trackball + user button — wired, not driven.
- Grove / external I²C — not initialized.
- QSPI flash (P25Q16H) — not used. Persistent identity and
  flash-backed CounterStore are a later phase.
- Buzzer (D12 / P1.00) — not driven.
- Battery measurement (D16 ADC + D30 enable) — not driven.
- Solar / charger introspection — not exposed by hardware in a way
  firmware can read.
- E-ink variant (D31–D36 on SPI1) — Pro is the OLED variant; the
  e-ink panel is a separate board we don't have.
- BLE — never in this binary.

## Why this is not on `umsh-app-companion-cli` / `umsh-ux-tracker`

A bringup binary's job is to expose exactly the peripherals on the
path and nothing else. The intent is to **validate the hardware
reconstruction** — pinout, peripheral choice, RXEN behavior — on a
recoverable board, not to ship a real application.

Once this bringup is at parity with what the T-Echo has today
(USB-CDC + safety primitives + display + radio + MAC), the actual
next step for this board is wiring up **`umsh-app-companion-cli`**
on top, not "design a new UX class." The Wio Tracker L1 Pro is the
first device we have where landing the companion-CLI app on real
hardware is the obvious follow-up.

For Phase 0–4 we use these existing pure-logic pieces directly:

| Module | Source |
|---|---|
| `LedEngine` (heartbeat on D11) | `umsh-ux-tracker` |
| `TouchlessResetWatcher`, `EscapeWatcher`, `CdcAcmRescue` | `umsh-bsp-nrf52840` |
| `PanicSlot` (retained-RAM framing) | `umsh-bsp-nrf52840` (promoted during T-Echo Phase 2) |

## Workspace additions

```
crates/
  umsh-bsp-wio-tracker-l1/     board-BSP: pin map, peripheral handles
firmware/
  hello-wio-tracker-l1/        binary glue with its own minimal main()
```

The chip-BSP (`umsh-bsp-nrf52840`) is reused unchanged. The radio
crate (`umsh-radio-sx126x`) is reused, possibly with a small addition
for the external RXEN line (see Phase 3).

Workspace `members` adds the two new crates; `default-members` adds
only `umsh-bsp-wio-tracker-l1` (same pattern as `umsh-bsp-techo`).

The BSP crate name follows the family naming convention — the same
crate works for the L1 (OLED, no case), L1 Pro (OLED + case + battery),
and L1 Lite (no display) variants, because they share the pin map.
The e-ink variant (`L1 e-ink`) would warrant a separate BSP crate (or
a feature flag) because its SPI1 e-ink path is mutually exclusive
with several OLED-side pins.

## Hardware assumptions to verify in Phase 0

Most of these come from the hardware reconstruction, which is
firmware-derived (Meshtastic + MeshCore variant files), not from a
confirmed schematic. Phase 0 verifies the load-bearing ones on the
actual board.

1. **MCU:** nRF52840.
2. **Bootloader:** Adafruit nRF52 UF2 bootloader. App start almost
   certainly `0x26000` (Meshtastic / MeshCore layout with the
   SoftDevice slot reserved). **Confirm via `INFO_UF2.TXT`** on the
   mass-storage drive when the bootloader is active. The Board-ID
   and UF2 family ID strings tell us whether `memory.x` matches.
3. **Radio:** SX1262 on the primary SPI bus.
   - SCK=P0.30, MISO=P0.03, MOSI=P0.28, CS=P1.14
   - DIO1=P0.07, RESET=P1.07, BUSY=P1.10
   - DIO3 TCXO at 1.8 V; DIO2 as RF switch (handled by lora-phy).
   - **RXEN=P1.08** is an *additional* external GPIO not present on
     the T-Echo. MeshCore drives this; we have to figure out whether
     "always high" works or whether it has to toggle with TX/RX.
4. **OLED:** SH1106 at I²C address `0x3D`, on SDA=P0.06 / SCL=P0.05.
5. **User LED for heartbeat:** D11 / P1.01, active-high.
6. **Peripheral power:** unlike the T-Echo's P0.12, no single
   board-wide peripheral-power-enable line was found. Initial
   assumption: peripherals are always powered while the board is
   powered. If a peripheral comes up dead, suspect the
   battery-divider enable (D30 / P0.04) or the GNSS standby line
   (D0 / P1.09), neither of which gates the radio or OLED.
7. **Reset / DFU:** Adafruit double-tap-reset is expected to work
   out of the box. 1200-baud touchless reset is something we own
   (it only works once our firmware implements it).

If any of (2), (3), or (4) turn out wrong, the relevant phase pauses
to re-verify against the schematic if we can obtain one, or against
MeshCore source if we cannot.

## Safety contract

Same shape as the T-Echo:

1. Firmware never writes the bootloader region (`0xF4000`+) or the MBR.
2. Firmware never disables the WDT once started.
3. `bsp::enter_dfu_uf2()` and siblings are the only functions that touch
   GPREGRET.
4. The 1200-baud `SET_LINE_CODING` + DTR-drop path and the
   `\x03\x03\x03dfu\r` escape path both trigger `enter_dfu_uf2()` from
   the USB-CDC handler, *below* any CLI parser. Both paths are
   structurally enforced by `CdcAcmRescue` — they cannot be bypassed
   by application code.
5. Panics route to `PanicSlot::capture` and to `SCB::sys_reset()`; the
   next boot reads the slot and prints the previous panic over
   USB-CDC before clearing it.

There is no software power-off in this bringup, and unlike the
T-Echo or T1000-E this is not a corner we're cutting: the Wio
Tracker L1 has a physical power switch, so battery preservation
when the user is "done" is solved by mechanical means. System OFF
sleep on the nRF52840 is not on the path to a shippable battery
life story for this device.

## Phasing

Smaller than the T-Echo phasing because most of the chip-level work
is already done. Each phase ends in a flashable, demonstrable
artifact.

### Phase 0 — Bootloader reconnaissance ✅

Triggered UF2 mode on a stock Wio Tracker L1, mounted `TRACKER L1`,
read `INFO_UF2.TXT`, and cross-referenced against the MeshCore
board JSON and linker script. Full bootloader / flash-layout
details are recorded in
[seeed-wio-tracker-l1-pro-hardware.md](seeed-wio-tracker-l1-pro-hardware.md).

| Fact | Value |
|---|---|
| Bootloader | UF2 Bootloader 0.9.2-dirty (Seeed fork of Adafruit) |
| Board-ID | `TRACKER L1` |
| SoftDevice | **S140 7.3.0** (newer than T-Echo's 6.1.1) |
| App flash start | **`0x00027000`** (not `0x26000`!) |
| App flash end | `0x000F4000` (start of bootloader) |
| App flash size | 820 KiB |
| RAM | 256 KiB from `0x20000000` |
| UF2 family ID | **`0x28861667`** (Seeed VID:PID) |
| USB VID:PID | `0x2886:0x1667` |
| 1200-baud touch | supported |

**Two important deltas from the T-Echo:**

1. **`memory.x` cannot be copy-pasted.** S140 v7.3.0 has a larger
   footprint than v6.1.1, so app start moves from `0x26000` to
   `0x27000`. App length drops from 824 KiB to 820 KiB.

2. **UF2 family ID is Seeed-specific (`0x28861667`), not the
   Adafruit standard (`0xADA52840`).** The Seeed bootloader fork
   uses `VID << 16 | PID` as the family ID. The `uf2-tool` /
   `uf2conv.py` invocation in the flash recipe must specify this
   ID or the bootloader will reject the file.

As on the T-Echo, S140 sits dormant unless `sd_softdevice_enable()`
is called. `embassy-nrf` retains full peripheral ownership and the
full 256 KiB RAM (the SoftDevice's 24 KiB RAM reservation only
applies when enabled).

**Gate:** ✅ assumptions confirmed; `memory.x` and UF2 family ID
recorded; proceed to Phase 1.

### Phase 1 — "Hello USB-CDC" + safety primitives ✅

Single combined phase because the T-Echo already proved out every
step. New workspace members:

- `crates/umsh-bsp-wio-tracker-l1/` — board BSP crate (stub; the
  Phase 1 firmware drives pins inline like `hello-techo` does).
- `firmware/hello-wio-tracker-l1/` — the bringup binary.

The firmware is a stripped-down copy of `hello-techo` with these
changes from the T-Echo version:

- LED pin: `P0.14` (T-Echo blue, active-low) → `P1.01` (Wio user
  LED, active-high). `set_high()` lights it.
- USB IDs: `0x16c0:0x27dd` → `0x2886:0x1667` (Seeed VID:PID).
- USB product string: `"T-Echo Bringup"` → `"Seeed Wio Tracker L1
  Bringup"`.
- `memory.x`: app origin `0x26000` → `0x27000`, length `824K` →
  `820K` (S140 v7.3.0 footprint).
- Dropped the `PIN_POWER_EN` (P0.12) drive — no equivalent on the
  Wio Tracker.
- Phase 1 does not bring up the display, radio, or MAC, so those
  imports, tasks, and the `embedded-alloc` global allocator are
  all absent.

`build.rs`, `panic.rs`, and `.cargo/config.toml` carry over
byte-for-byte (target triple and linker flags are MCU-specific,
not board-specific).

End-to-end verified on hardware:

- `/dev/cu.usbmodem101` enumerates after UF2 flash.
- Boot banner over USB-CDC reads:
  `UMSH hello-wio-tracker-l1 ready.` /
  `Phase 1: USB-CDC echo + heartbeat + safety primitives.`
- Heartbeat LED blinks at the LedEngine cadence.
- 1200-baud touchless reset, escape-sequence DFU, and panic
  capture/replay are all inherited from `umsh-bsp-nrf52840` and
  are structurally enforced by `CdcAcmRescue` — the same tested
  paths used by the T-Echo bringup.

**Gate:** ✅ firmware enumerates, echoes, blinks. Inherited rescue
and panic paths share their hardware-verified status with the
T-Echo Phase 2 work.

### Phase 2 — SH1106 OLED "hello world" ✅

Bring up the OLED display over I²C. The OLED is materially easier
than the T-Echo's e-paper: no busy line, no ~2 s refresh, no
RED-RAM gotcha, no panel-rotation transform.

Hardware wiring:
- TWIM0 (or TWIM1) on SDA=P0.06, SCL=P0.05
- SH1106 at I²C address `0x3D` (note: not the more common `0x3C`)

Driver choice: use the `sh1106` crate (`embedded-graphics`-compatible,
maintained, async I²C support via `embedded-hal-async` in recent
versions). Falling back to a hand-rolled driver if the crate is
unsuitable for embassy is acceptable but unlikely to be needed —
SH1106 is simpler than SSD1681.

Display contents (mirror the T-Echo for visual parity):
- line 1: `UMSH bringup`
- line 2: `<git short SHA>`
- line 3: `MAC: 0` (placeholder until Phase 4)

The OLED, unlike the e-paper, can be redrawn cheaply on every
packet. Throttling is not needed; we can drop the
`DISPLAY_COUNT_SIGNAL` throttle from the T-Echo design and just
redraw on the signal. Adding a small (~50 ms) debounce would still
be cheap insurance against a tight burst making the display
flicker, but is not load-bearing.

Hardware-verified: boots and displays "UMSH bringup" / git SHA /
"MAC: 0" in landscape orientation — no panel-rotation transform
needed (unlike the T-Echo's e-paper). Default orientation with
`0xA1` segment remap and `0xC8` COM scan remapped is correct.

Non-obvious integration notes:
- `sh1106` v0.5.0 depends on `embedded-hal 0.2`, incompatible with
  embassy's embedded-hal 1.0. Rolled a thin inline driver (~120 lines
  of I²C page writes) rather than fighting the version mismatch.
- `Twim` in embassy-nrf 0.10 has no peripheral type parameter (`Twim<'d>`,
  not `Twim<'d, TWISPI0>`). The peripheral is erased at construction.
- `Twim::new` in embassy-nrf 0.10 requires a static DMA scratch buffer
  (`&'static mut [u8]`). Provided via `StaticCell<[u8; 256]>`.
- The `twim` feature flag does not exist in embassy-nrf 0.10; TWIM is
  included with the chip feature.
- `embassy-sync` must be added as a direct dependency for `Signal` and
  `ThreadModeRawMutex`; it is not re-exported by embassy-nrf.

**Gate:** ✅ hardware-verified.

### Phase 3 — SX1262 LoRa radio ✅

Wire `umsh-radio-sx126x` into the firmware with the Wio Tracker's
pin map. The radio crate itself should not need to change for the
common path — the lora-phy `Sx126x` driver takes pins as
constructor arguments and is board-agnostic.

The one new piece is **RXEN**:

| Function | Pin | Notes |
|---|---|---|
| RXEN | D5 / P1.08 | External RF-switch / LNA enable |

The hardware doc and MeshCore source both treat this as a separate
GPIO outside the SX1262's own DIO2-as-RF-switch path. The most
likely topology (no schematic confirmed) is **DIO2 drives a primary
TX/RX SPDT switch** while **RXEN biases an external LNA** on the
RX path. There is also a less common topology where RXEN controls
a second switch in series with the LNA.

**RXEN must be deasserted during TX**, not held high. Holding it
high during a +22 dBm transmit risks:

- LNA-bias topology: TX power couples back through the primary
  switch's finite isolation (~25 dB → roughly −3 dBm into the LNA
  input). Usually within LNA absolute-max ratings, *usually*
  survivable, but not guaranteed.
- LNA-switch topology: TX power routes directly into the LNA
  input via the secondary switch. **Damage.**

MeshCore actively toggles RXEN with TX/RX state, which is the
conservative behavior we should match from the start. The cost of
being wrong is permanent hardware damage; the cost of being safe
is a few extra lines in the radio runner.

Two reasonable implementation strategies:

1. **Toggle in the radio runner.** Drive RXEN high before entering
   RX, low before TX. Smallest delta: pass the RXEN pin through
   `umsh_radio_sx126x::runner` (or a small wrapper) and gate it on
   the existing TX/RX state machine.
2. **lora-phy RF switch API.** lora-phy 3.x has a `RfSwitch` trait
   that boards can implement to drive arbitrary GPIOs around TX/RX
   transitions. Cleanest long-term answer (board-specific switch
   logic lives in board code, not in the radio crate), small API
   addition to `umsh-radio-sx126x`.

**Plan:** start with (1) for first-light because the delta to
`umsh-radio-sx126x` is minimal and contained. Revisit (2) when the
T1000-E bringup forces a second board-specific switch arrangement.

A safety belt worth adding regardless: before any LoRa init, the
firmware should drive RXEN **low** and hold it low until the radio
runner takes ownership. This prevents a brief window at boot where
RXEN floats (or starts high from a default GPIO state) before the
first TX could occur.

The rest of the radio configuration is identical to the T-Echo:
- TCXO via DIO3 at 1.8 V
- DIO2 as RF switch
- DC-DC enabled
- MeshCore US params (910.525 MHz, SF7, BW62.5, CR4-5, sync
  0x1424) — same as the T-Echo so the two boards can hear each
  other immediately

The radio sits on the primary SPI bus on the Wio Tracker (SPIM0 or
SPIM1 depending on peripheral assignment). The T-Echo used SPIM1
("TWISPI1") for the radio and SPIM2 for the e-paper; here, with no
SPI display, we have more flexibility. Suggest SPIM0 for the radio
unless something forces otherwise.

The runner / handle split, the `embassy-sync::Channel`-based bridge,
and the `AtomicWaker` TOCTOU mitigation are all reused unchanged.

Hardware-verified: OLED shows "RX: N" with N increasing as nearby
MeshCore frames arrive on the 910.525 MHz channel. RXEN handling
confirmed correct — no special toggling needed in the runner because
lora-phy drives the `rf_switch_rx` pin automatically via
`GenericSx126xInterfaceVariant`. Passing RXEN as `rf_switch_rx = Some(rxen)` and leaving `rf_switch_tx = None` matches the Wio Tracker's hardware (no separate TX enable pin).

Non-obvious integration notes:
- `rf_switch_rx` in `GenericSx126xInterfaceVariant` is exactly the
  right hook for RXEN — no changes to `umsh-radio-sx126x` required.
- Drive RXEN LOW at boot before handing to lora-phy, so it is not
  asserted during radio init/calibration.
- TWISPI1 is used for the radio SPI (TWISPI0 is taken by the OLED).

**Gate:** ✅ hardware-verified; RX counter advancing.

### Phase 4 — MAC coordinator integration ✅

Wire `Mac<WioTrackerL1Platform>` into the firmware. Mirror the
T-Echo's Phase 6 work line-for-line:

- `WioTrackerL1Platform` with identical associated types to
  `TechoPlatform` (`SoftwareIdentity`, `SoftwareAes`,
  `SoftwareSha256`, `Sx1262Radio`, `EmbassyClock`,
  `TeChoRng`-equivalent FICR-seeded XorShift64, `RamCounterStore`,
  `NullKeyValueStore`).
- `Mac<P, 1, 8, 4, 4, 8, 255, 32>` — same minimal capacity.
- `embedded-alloc` global allocator with a 4 KiB heap (required by
  `umsh-sync` → `extern crate alloc`).
- `mac_task` drives `mac.run(on_event)` and increments a packet
  counter on `MacEventRef::Received`.
- OLED display updates "MAC: N" on every count change.

The non-obvious facts from the T-Echo Phase 6 memo all apply
verbatim:
- `core::ptr::addr_of!(HEAP)` for the heap init pointer.
- `umsh-hal` must be a direct firmware dep.
- Build from the firmware directory, not workspace root.
- Default MAC const generics overflow RAM.

Hardware-verified: boots and displays "MAC: 0". MeshCore frames on
the same channel are received and silently dropped by the parser.

`WioTrackerPlatform` associated types are identical to `TechoPlatform`
in `firmware/hello-techo` — same software crypto, same FICR-seeded
XorShift64 RNG, same no-op stubs for CounterStore/KeyValueStore. The
`WioMac` capacity alias matches: `Mac<WioTrackerPlatform, 1, 8, 4, 4, 8, 255, 32>`.

The MAC counter stays at 0 because neither device transmits yet.
Phase 5 (packet generation) is the next step.

Non-obvious integration facts carry over verbatim from T-Echo Phase 6:
- `embedded-alloc` (4 KiB heap) required even with no runtime alloc.
- Default MAC const generics overflow RAM; minimal values are essential.
- `core::ptr::addr_of!(HEAP)` required for heap init (`static_mut_refs`).
- `umsh-hal` must be a direct dep; `umsh-mac` doesn't re-export `Clock` etc.
- Build from the firmware directory, not workspace root.

**Gate:** ✅ boots, displays "MAC: 0", USB banner confirms MAC is
running. Counter stays at 0 pending Phase 5 packet generation.

### Phase 5+ (future, not part of this bringup)

The real follow-up after Phase 4 is **`umsh-app-companion-cli`**
on this hardware — the first time the companion CLI runs on a real
radio rather than over loopback / desktop transports. That work
needs several pieces that are deliberately stubbed in this bringup:

1. **Packet generation / TX path exercised.** Until something
   actually transmits, neither device's counter moves. The
   companion-CLI command surface (send text, beacon location,
   etc.) is the natural driver, but a periodic beacon could land
   earlier as a standalone verification.
2. **Persistent identity.** Replace ephemeral
   `SoftwareIdentity::from_secret_bytes(rng)` with a QSPI-backed
   identity. Forces `KeyValueStore` to be real, not `Null`.
   Companion-CLI workflows assume identity persists across
   reboots.
3. **Persistent CounterStore.** Replace `RamCounterStore` with a
   flash-backed implementation. Necessary for replay protection
   to survive reboot.
4. **GNSS bring-up.** UART1 to L76K, NMEA parsing. Location
   broadcasts are part of the companion-CLI feature set.
5. **Buttons + joystick.** Wire user input to the CLI / UX layer.

The right shape of the BSP and UX layering for this device falls
out of doing the companion-CLI integration, not from designing it
speculatively now.

## Build / flash recipe

The two-command workflow is wrapped by Makefile targets at the
workspace root:

```
make build-hello-wio-tracker-l1   # cargo build --release (from the firmware dir)
make flash-hello-wio-tracker-l1   # build + UF2 convert + copy to bootloader volume
```

`flash-hello-wio-tracker-l1` requires the device to already be in
DFU mode: hit the reset button twice quickly, or trigger 1200-baud
touchless reset on `/dev/cu.usbmodem*` (Phase 1 firmware supports
this), or hold the boot button while plugging in. The bootloader
volume mounts at `/Volumes/TRACKER L1` on macOS.

The Makefile delegates to `scripts/flash.py`, which has board
presets covering the per-device differences:

| Aspect | T-Echo (`--board techo`) | Wio Tracker L1 (`--board wio-tracker-l1`) |
|---|---|---|
| App base address | `0x00026000` | `0x00027000` |
| UF2 family ID | `0xADA52840` (Adafruit) | `0x28861667` (Seeed VID:PID) |
| Bootloader mount | `/Volumes/TECHOBOOT` | `/Volumes/TRACKER L1` |
| SoftDevice | S140 v6.1.1 | S140 v7.3.0 |

Direct invocations (when you want to skip the make wrapper):

```
# Build:
cd firmware/hello-wio-tracker-l1 && cargo build --release

# Convert + copy:
scripts/flash.py --board wio-tracker-l1 --copy-default \
  target/thumbv7em-none-eabihf/release/firmware-hello-wio-tracker-l1

# Or split: convert only, copy manually:
scripts/flash.py --board wio-tracker-l1 \
  target/thumbv7em-none-eabihf/release/firmware-hello-wio-tracker-l1
cp target/thumbv7em-none-eabihf/release/firmware-hello-wio-tracker-l1.uf2 \
   "/Volumes/TRACKER L1/"
```

The `cp` step typically reports `Device not configured` on macOS
because the bootloader unmounts the volume the instant the last
UF2 block lands — *before* `cp` can finalize extended attributes.
The flash itself has already succeeded by that point.
`scripts/flash.py` swallows that specific error message; bare `cp`
will surface it but it's not a failure.

The build **must** run from the firmware crate directory (or via
the Makefile target which `cd`s for you), not via
`--manifest-path` from the workspace root. The `.cargo/config.toml`
linker flags are only inherited from the CWD hierarchy; building
from elsewhere silently produces a ~6 KiB ELF with no code
sections.

There is currently no `make monitor-*` target — use `screen
/dev/cu.usbmodem<N> 115200` or `kermit` directly.

## Why this is also a forcing function

A few things will fall out of doing this bringup that we
intentionally did not solve speculatively earlier:

1. **`umsh-bsp-wio-tracker-l1` is the first BSP we write *after*
   knowing what shape it actually wants.** The T-Echo BSP is
   nearly a stub because `hello-techo` does everything inline; we
   can do the same here, or we can take the chance to factor the
   pin map and peripheral handles into the BSP properly. Lean
   toward inline-first, factor later — the third nRF52840 board
   (T1000-E) will tell us what's worth extracting.
2. **External RXEN handling.** The first board with an external
   RF-switch pin separate from DIO2. The eventual abstraction
   (lora-phy `RfSwitch` impl in `umsh-radio-sx126x`?) crystallizes
   only after we have this concrete example.
3. **End-to-end UMSH validation on real hardware.** Phase 4 is
   the first time two devices speak UMSH to each other over LoRa.
   Any latent bugs in the MAC, the crypto path, or the wire format
   surface here.

## Open questions

1. **Which I²C peripheral for the OLED?** TWIM0 vs TWIM1 vs
   sharing with the Grove bus on TWIM2 (P1.11/P1.12). For
   bringup, dedicate one TWIM to the OLED and leave the Grove
   bus uninitialized. TWIM0 is conventional.
2. **`sh1106` crate vs roll-our-own.** Lean toward the crate.
   The T-Echo precedent (rolled own e-paper driver) was driven by
   discovering chip quirks that no existing crate handled
   correctly; SH1106 doesn't have that problem.
3. **Heartbeat LED rate.** Match the T-Echo (50 ms ON / 2 s
   period) for visual consistency between boards on the bench.
4. **Should we drive `BAT_READ` (D30) high during init?** The
   hardware doc warns that Meshtastic does. We aren't reading
   the battery in this bringup, so leaving it floating should be
   fine. Document the warning; revisit if battery measurement
   lands later.
5. **OLED-off behavior on USB disconnect.** The OLED stays
   powered. If we eventually care about idle power, the SH1106
   has a display-off command (`0xAE`); not worth using for
   bringup.
6. **Phase 4 verification choreography.** Bench setup: T-Echo
   running `firmware-hello-techo` on USB power, Wio Tracker
   running `firmware-hello-wio-tracker-l1` on USB power, both
   within antenna range. Initially both will show "MAC: 0"
   because neither transmits. Phase 5 "packet generation" is the
   first thing that actually moves either counter; until then,
   Phase 4 is a *structural* success (both devices boot and run
   the MAC) rather than an *observable* one.
