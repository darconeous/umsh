# LilyGO T-Echo Bringup Firmware Plan

A deliberately minimal "hello-world" firmware for the LilyGO T-Echo,
used as a *stepping stone* before the T1000-E. The T-Echo has the same
chip (nRF52840) and the same Adafruit UF2 bootloader, but it is not
factory-sealed: a stuck device can be opened up and recovered manually
if needed. That makes it a much safer place to:

- prove out the embassy / cargo-binutils / UF2 build & flash workflow,
- validate the safety primitives (1200-baud reset, escape rescue,
  panic-persist, WDT) we will inherit on the T1000-E,
- learn what we get wrong about Adafruit's bootloader behavior,
- exercise an actual non-trivial peripheral driver (e-paper),

before ever pointing this code at a device we can't fully recover.

See [lilygo-techo-hardware.md](lilygo-techo-hardware.md) for the
hardware reference. See
[firmware-architecture.md](firmware-architecture.md) for the BSP / UX /
App / Binary layering this firmware sits inside.

## Scope (in / out)

**In scope.** A binary that, when flashed via UF2 onto a stock-bootloader
T-Echo:

- enumerates as a USB-CDC serial device,
- responds to the 1200-baud touchless reset by entering serial DFU
  (so `flasher.meshcore.co.uk` / `adafruit-nrfutil --touch 1200` /
  the host `just flash` recipe can re-flash without unplugging),
- responds to the `\x03\x03\x03dfu\r` escape sequence the same way,
- blinks the LED with a slow heartbeat,
- captures panics into retained RAM and surfaces them over USB-CDC on
  the next boot,
- initializes the e-paper display and writes a recognizable boot
  message ("UMSH bringup" + git short SHA + a fixed pattern, say) so
  we can visually confirm the firmware is the one we just flashed.

**Out of scope** for this bringup. Each of these is real future work,
just not on the path to "hello world on e-ink":

- LoRa (SX1262) — radio not initialized, MAC not run.
- GNSS (Quectel L76K) — UART not initialized.
- BME280, PCF8563 RTC, BHI260, DRV2605 — I²C not initialized.
- External QSPI flash — not used.
- Buttons (user, touch) beyond what the bootloader handles for reset.
- A real CLI — USB-CDC reads echo back for the bringup, that's it.
- BLE — never in this binary.
- Plus-only back-panel peripherals.

The point is to constrain surface area to what we need to prove the
workflow.

## Why this is not on `umsh-app-companion-cli` / `umsh-ux-tracker`

The T-Echo isn't a tracker-class device:

- E-paper display rather than no display.
- RGB LED (three separate single-color LEDs) rather than one LED.
- No buzzer on the standard board (Plus-only).
- User button **plus** capacitive touch button **plus** reset button,
  rather than a single button.

So `umsh-ux-tracker`'s abstractions (single-button gesture FSM,
single-LED heartbeat, piezo buzzer) only partially apply. The honest
answer is that the T-Echo belongs to a future `umsh-ux-handheld` or
similar class that we will design *when we actually need a real
T-Echo firmware*. For bringup, we don't need that — we just need a
binary that talks to the few peripherals on the path.

Concretely the bringup firmware uses these existing pure-logic pieces
directly, without a UX-class crate in between:

| Module | Source |
|---|---|
| `LedEngine` (heartbeat on the blue LED) | `umsh-ux-tracker` |
| `TouchlessResetWatcher`, `EscapeWatcher` | `umsh-bsp-nrf52840` |
| `PanicSlot` (retained-RAM framing) | `umsh-bsp-t1000e` for now; promote to `umsh-bsp-nrf52840` once T-Echo also consumes it (this firmware is the trigger) |
| Button FSM | not used yet (no button UX in bringup) |
| Buzzer engine | not used (no buzzer on standard T-Echo) |

The lift on `PanicSlot` is the first sign of "this thing should
graduate" — see the comment in
`crates/umsh-bsp-t1000e/src/panic_persist.rs`. We'll do that move as
part of this firmware's work.

## Workspace additions

```
crates/
  umsh-bsp-techo/         board-BSP: pins, peripheral power switch,
                          USB driver, LED, e-paper SPI handles
firmware/
  hello-techo/            binary glue with its own minimal main()
```

The chip-BSP (`umsh-bsp-nrf52840`) is reused unchanged from the T1000-E
side. No new `umsh-app-*` or `umsh-ux-*` crate is created.

Workspace `members` adds the two new crates; `default-members` adds
only `umsh-bsp-techo` (the firmware binary stays in `members` but is
excluded from `default-members`, same pattern as
`firmware/companion-cli-t1000e/`).

## Hardware assumptions to verify in Phase 0

Most of these are already inferred in
[lilygo-techo-hardware.md](lilygo-techo-hardware.md); Phase 0 just
confirms them on the specific board in hand.

1. **MCU:** nRF52840.
2. **Bootloader:** Adafruit nRF52 UF2 bootloader. App start almost
   certainly `0x26000` (Meshtastic / MeshCore layout with the
   SoftDevice slot reserved). Confirm via `INFO_UF2.TXT` on the
   mass-storage drive when the bootloader is active.
3. **Display:** GDEH0154D67 / SSD1681, 200×200, 1.54", B/W. Driven
   over the secondary SPI bus (P0.31 SCLK, P0.29 MOSI, P0.30 CS, P0.28
   DC, P0.02 RESET, P0.03 BUSY, P1.11 backlight enable).
4. **Peripheral power switch:** P0.12, **high = enable**. This must
   be driven high before talking to the display (or LoRa, or GPS).
5. **LED used for heartbeat:** start with the **blue** LED at P0.14,
   active-low. Easy to see and orthogonal to the charger LED.
6. **Reset / DFU:** standard Adafruit double-tap-reset works; expect
   that 1200-baud touchless reset *only* works once we implement it
   in our firmware (the bootloader doesn't do it itself).

If any of (1)–(5) turn out wrong, the plan changes; (6) we own.

## Safety contract

Same shape as the T1000-E plan, scaled down to what this bringup
actually does. Because the T-Echo is recoverable, the invariants are
*less* load-bearing — but we should still treat them as load-bearing
since the goal is to validate the patterns we'll need on the sealed
device.

Invariants:

1. Firmware **never writes the bootloader region** (`0xF4000`+) or
   the MBR.
2. Firmware **never disables the WDT** once started.
3. `bsp::enter_dfu_serial()` and `bsp::enter_dfu_uf2()` are the only
   functions that touch GPREGRET.
4. The 1200-baud `SET_LINE_CODING` + DTR drop path triggers
   `enter_dfu_serial()` from the USB-CDC handler, *below* any CLI
   parser. Same for the Ctrl-C-x3 + `dfu\r` escape.
5. Panics route to `PanicSlot::capture` and to `SCB::sys_reset()`;
   the next boot reads the slot and prints the previous panic over
   USB-CDC before clearing it.

There is no power-off in this bringup. The device runs whenever
USB is connected; that's fine for a bringup target.

## Phasing

Smaller than the T1000-E phasing because the scope is smaller. Each
phase ends in a flashable, demonstrable artifact.

### Phase 0 — Bootloader reconnaissance ✅

Triggered UF2 mode on a stock T-Echo, read `INFO_UF2.TXT` from the
mounted bootloader volume. Findings:

| Fact | Value |
|---|---|
| Bootloader | UF2 Bootloader 0.6.1-2-g1224915 (Adafruit nRF52 UF2) |
| Build date | Oct 13 2021 |
| Model | LilyGo T-Echo |
| Board-ID | `nRF52840-TEcho-v1` |
| SoftDevice | S140 version 6.1.1 (present in flash, not enabled by us) |
| UF2 family ID | `0xADA52840` (Adafruit nRF52840) |
| App flash start | `0x00026000` (after S140) |
| App flash end | `0x000F4000` (start of bootloader) |
| App flash size | 824 KiB |

The Adafruit bootloader + S140 v6 layout matches the assumption baked
into `firmware/hello-techo/memory.x`. We do **not** intend to enable
the SoftDevice; as long as `sd_softdevice_enable()` is never called,
S140 sits dormant and `embassy-nrf` retains full peripheral ownership.
This matches MeshCore's posture on T-Echo when it doesn't need BLE.

The UF2 family ID `0xADA52840` is what the UF2 conversion step in the
`just flash` recipe will embed.

**Gate:** ✅ assumptions confirmed; flash window matches `memory.x`;
proceed to Phase 1.

### Phase 1 — "Hello USB-CDC"

Minimal embassy main: bring up clocks, enumerate USB-CDC, echo
received bytes back. No e-paper, no LED. Establishes the embassy /
embassy-usb / build / UF2 / flash loop.

**Gate:** USB CDC enumerates on host; bytes typed into a terminal are
echoed back.

### Phase 2 — Safety primitives

Add: WDT, retained-RAM `PanicSlot` capture and next-boot report,
`TouchlessResetWatcher` driving `enter_dfu_serial()`, `EscapeWatcher`
for `\x03\x03\x03dfu\r`. The `PanicSlot` module gets promoted from
`umsh-bsp-t1000e` to `umsh-bsp-nrf52840` in this phase (T-Echo is the
second consumer).

**Gate:** force a panic (via a debug CLI command or compile-time
trigger); on reboot the firmware prints the previous panic message
over USB-CDC. Trigger DFU via 1200-baud touch (`adafruit-nrfutil
--touch 1200`) — device drops into serial DFU. Trigger DFU via
`\x03\x03\x03dfu\r` — same. The device is recoverable via at least
three independent software paths plus bootloader double-reset.

### Phase 3 — LED heartbeat

Wire `umsh_ux_tracker::led::LedEngine` to the blue LED (P0.14,
active-low). A heartbeat task drives `tick()` and toggles the GPIO
accordingly.

**Gate:** blue LED blinks ~50 ms every 2 s while the firmware is
running. If the heartbeat stops, we know the runtime has wedged.

### Phase 4 — E-paper "hello world"

Drive peripheral-power-enable high, initialize the e-paper bus (SPI
+ control pins), use `epd-waveshare` to write a fixed image (text
saying "UMSH bringup" + git short SHA, plus a recognizable visual
pattern so we can confirm "this is the firmware we just flashed" at
a glance).

**Gate:** powering up the device with the bringup firmware shows
the boot message on the e-paper, visible without any further host
interaction. This is the milestone the user asked for explicitly.

## Build / flash recipe

Same shape as `firmware/companion-cli-t1000e/`:

- `firmware/hello-techo/.cargo/config.toml` pins
  `thumbv7em-none-eabihf` and (optionally) a probe-rs runner for
  developers with an SWD probe available.
- `firmware/hello-techo/memory.x` mirrors the T1000-E's: `FLASH`
  starting at `0x26000` for 824 KiB, `RAM` at `0x20000000` for 256
  KiB. Confirm in Phase 0.
- Convert ELF → UF2 via `uf2conv.py` (or `cargo-binutils` +
  `uf2-tool`).
- `just flash techo hello` recipe: build, convert, trigger 1200-baud
  touch on the device, wait for the UF2 mass-storage drive, copy.
- `just monitor techo` recipe: opens the USB-CDC port and pipes
  through.

## Why this is also a forcing function

A few things will fall out of doing T-Echo bringup that we
*intentionally* did not solve speculatively earlier:

1. **`PanicSlot` promotion.** Currently in `umsh-bsp-t1000e`; the
   T-Echo bringup is the trigger to move it to `umsh-bsp-nrf52840`
   (or its own crate). The doc comment in `panic_persist.rs` already
   anticipates this.
2. **Capability traits — finally a real shape.** The bringup
   `main.rs` is the first concrete consumer of a board-BSP; the
   actual traits the BSP needs to expose (LED handle, USB-CDC
   handles, e-paper SPI handles, peripheral-power-switch handle)
   become obvious from writing this firmware. Capability traits
   should be designed *here*, not earlier.
3. **`umsh-bsp-nrf52840` actually has to do something.** The chip-BSP
   currently has only `rescue.rs`; this phase forces clock init, USB
   driver setup, GPREGRET helpers, and WDT setup to land for real.
4. **Build/flash workflow validation.** The `just` recipes get
   written and exercised against a real device on a forgiving target
   before we ever point them at the sealed T1000-E.

## Open questions before Phase 0

1. **Which LED to use for the heartbeat?** I lean blue (P0.14) — easy
   to see, distinct from the charger-status red. RGB-combination
   patterns are not worth the complexity for bringup.
2. **Do we use the `epd-waveshare` crate as-is, or wrap it behind a
   thin BSP abstraction?** Lean on `epd-waveshare` directly in the
   binary for bringup; revisit if we end up writing a "real" T-Echo
   firmware that wants different rendering ergonomics.
3. **Should `firmware/hello-techo/` use `defmt`/`defmt-bbq` for
   logging over USB-CDC?** Defmt would be nice (compact, structured)
   but adds toolchain dependencies. For bringup, plain
   `core::fmt::write!` over CDC is enough.
4. **Should the e-paper "hello" include a build timestamp / git SHA?**
   Yes — it's the cheapest way to confirm visually that the flashed
   firmware is the one we just built. `build.rs` can pull `git
   rev-parse --short HEAD` into an env var.
