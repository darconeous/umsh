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
3. `bsp::enter_dfu_uf2()` (and its siblings) are the only functions
   that touch GPREGRET.
4. The 1200-baud `SET_LINE_CODING` + DTR drop path triggers
   `enter_dfu_uf2()` from the USB-CDC handler, *below* any CLI
   parser. Same for the Ctrl-C-x3 + `dfu\r` escape. Both paths are
   structurally enforced by `CdcAcmRescue` — they cannot be bypassed
   by application code.
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

### Phase 1 — "Hello USB-CDC" ✅

Minimal embassy main bringing up clocks, USB-CDC echo, and (because
it was useful for diagnostics) a heartbeat LED. Hit a series of
non-obvious gotchas on the way; all four are now codified in commit
3b98bf13 and worth recording here so the T1000-E side avoids them:

1. **Embassy version unification.** Mixing `embassy-time 0.4` and
   `embassy-time 0.5` in the same binary (transitively via
   `embassy-nrf 0.5` + `embassy-usb 0.6`) put two tick-base
   constants in the link; the registered time driver matched one
   side but `Timer::after` read the other, and `Timer` hung
   forever. Bumping everything to current versions
   (`embassy-nrf 0.10`, `embassy-executor 0.10`, `embassy-usb 0.6`,
   `embassy-time 0.5` with `tick-hz-32_768`) put a single
   `embassy-time` in the tree and fixed it.
2. **`embassy-executor` `embassy-time-driver` feature.** The
   executor needs this to participate in the timer queue protocol;
   without it `Timer::after` is a no-op.
3. **`cortex-m-rt` `set-vtor` feature.** The Adafruit nRF52 UF2
   bootloader hands off via the MBR, which does not reliably leave
   VTOR pointing at the application's vector table. Without
   `set-vtor`, the first interrupt that fires (USBD on
   enumeration, or RTC1's compare match driving `Timer::after`)
   dispatches to the wrong handler and the chip resets in a loop.
   With `set-vtor` cortex-m-rt fixes VTOR at startup and
   interrupts go where they should.
4. **PIN_POWER_EN (P0.12) drive.** The T-Echo schematic ORs
   VBUS-present with PIN_POWER_EN-high to enable the peripheral
   rail. Without driving it explicitly, the LED only works on USB;
   with it high, the LED (and later e-paper / GNSS / LoRa /
   sensors) works on battery too.

End-to-end verified:

- `/dev/cu.usbmodemhello_techo1` enumerates.
- `ioreg` shows `UMSH` / "T-Echo Bringup" / VID `0x16c0` / PID `0x27dd`.
- Boot banner: `UMSH hello-techo: USB-CDC echo ready.`
- Bytes round-trip byte-perfect.
- Heartbeat LED keeps blinking throughout.

**Gate:** ✅ achieved.

### Phase 2 — Safety primitives ✅

Added: WDT (8-second timeout, petted in heartbeat every ~2 s),
retained-RAM `PanicSlot` capture and next-boot USB-CDC report,
`EscapeWatcher` for `\x03\x03\x03dfu\r`, and 1200-baud touchless
reset detection. `PanicSlot` promoted from `umsh-bsp-t1000e` to
`umsh-bsp-nrf52840` (T-Echo is the second consumer, per the plan).
`gpregret` module added to `umsh-bsp-nrf52840` using the embassy-nrf
PAC (`pac::POWER.gpregret()`) and `cortex_m::peripheral::SCB::sys_reset()`.

All four hardware gates verified on device:

- `!panic\r` trigger → next boot printed `[PREV PANIC]: ...` and
  cleared the slot.
- 1200-baud touchless reset (`screen /dev/cu... 1200`, close) →
  TECHOBOOT drive mounted.
- Escape-sequence DFU (`\x03\x03\x03dfu\r`) → TECHOBOOT drive mounted.
- Web flasher DFU round-trip → new firmware running after flash.

Implementation notes:

1. **GPREGRET register address bug.** The first implementation used
   the raw address `0x40000508`, which is `GPREGRET2` (not
   `GPREGRET`). The correct offset for `GPREGRET` is `0x4000051C`.
   The bug was caught diagnostically: a read-back command showed only
   bit 0 ever set regardless of the value written, because a different
   register was being written. Fixed by switching to the PAC:
   `pac::POWER.gpregret().write(|w| w.set_gpregret(value))`, which
   encodes the correct offset automatically. Lesson: never hard-code
   peripheral register addresses when a vendor PAC exists.
2. **NVIC quiesce before GPREGRET write.** Without `cortex_m::interrupt::disable()`
   (CPSID I), an in-flight USB, RTC, or WDT interrupt could steal AHB
   bus cycles between the GPREGRET store and SYSRESETREQ, leaving the
   bootloader to see a stale value. `dsb` alone was not sufficient;
   masking all maskable interrupts is required. Verified empirically.
3. **UF2 mode for all rescue paths.** Both the 1200-baud path and the
   escape-sequence path call `enter_dfu_uf2()` (GPREGRET = 0x57),
   which exposes TECHOBOOT mass-storage *and* a CDC DFU port. Using
   serial-only mode (0x4e) would break the MeshCore web flasher and
   UF2 file drop. There is no reason to offer serial-only as a rescue
   path — it is only exported for completeness.
4. **`CdcAcmRescue<'d, D>` wrapper.** The rescue checks are baked into
   a `Receiver`+`ControlChanged` wrapper in `umsh-bsp-nrf52840` so
   they cannot be bypassed by application code. The application only
   receives a `Sender` (writes) and a `CdcAcmRescue` (reads); the
   inner `Receiver` and `ControlChanged` are not exposed. A future
   developer adding a CLI on top of this cannot accidentally skip the
   1200-baud or escape checks — they fire on every byte by construction.
5. **Rust 2024 `static_mut_refs` hard error.** `&mut *static_mut_ptr`
   is forbidden in edition 2024. `PANIC_REGION` is wrapped in
   `SyncNoinit<T>` (a `UnsafeCell<MaybeUninit<T>>` newtype) and the
   `&mut [u8]` is obtained via `UnsafeCell::get().cast::<u8>()` +
   `slice::from_raw_parts_mut`. This is the intended escape hatch.
6. **`.uninit` section name.** `cortex-m-rt` 0.7.x names the no-load
   retained-RAM section `.uninit` (not `.noinit`). Using `.noinit`
   produces a section with the LOAD flag set, which causes
   `cargo-binutils` to span a ~1 GB gap between flash and RAM when
   converting to UF2. The correct attribute is
   `#[unsafe(link_section = ".uninit")]` (Rust 2024 syntax).
7. **`split_with_control()` for touchless reset.** `CdcAcmClass` has
   no event callback for line-coding changes. `split_with_control()`
   gives a `ControlChanged` future that wakes on any DTR/RTS/baud
   event. A `select` between `read_packet` and `control_changed()`
   detects DTR drop while a read is in flight.
8. **WDT across soft resets.** The nRF52840 WDT keeps running across
   SYSRESETREQ. `embassy_nrf::wdt::Watchdog::try_new` recovers the
   same handles if the config matches, so no re-initialization is
   needed on reboot.

**Gate:** ✅ builds clean; all four hardware rescue paths verified on device.

### Phase 3 — LED heartbeat

Replaced the hand-rolled `Timer::after` timing loop in the heartbeat
task with `LedEngine::tick()` from `umsh-ux-tracker`. The engine
computes the LED state and the absolute next-deadline from a
monotonic millisecond clock (`embassy_time::Instant::now().as_millis()`);
the task sleeps to that deadline with `Timer::at(Instant::from_millis(...))`.

The observable behavior (50 ms ON / 2 s period) is identical to Phase 2.
The difference is that `LedEngine` owns the cadence and exposes
`play(LedSequence, now_ms)` for one-shot overlays — future application
code (power-on flash, location-advert double-blink) can call `play()`
without touching the heartbeat timing.

The WDT pet remains at the top of the loop; it fires on every wake-up
(at most every ~2050 ms), well within the 8 s timeout.

**Gate:** builds clean; observable behavior identical to Phase 2
(hardware-verified there). Hardware re-flash pending user confirmation
before proceeding to Phase 4.

### Phase 5 — SX1262 LoRa radio ✅

New crate `crates/umsh-radio-sx126x` wraps `lora-phy` 3.0.1 and exposes
`Sx1262Radio` which implements `umsh_hal::Radio`. The MAC coordinator can
call `transmit()` and `poll_receive()` without knowing the radio details.

Architecture:
- **`runner()` task** owns the `lora_phy::LoRa<Sx1262>` instance. It
  loops between continuous RX (`RxMode::Continuous`) and TX using
  `embassy_futures::select`. Received frames go into a static `Channel`;
  an `AtomicWaker` fires so `poll_receive` callers wake immediately.
- **`Sx1262Radio`** is a lightweight `&'static Channels` handle that
  implements `umsh_hal::Radio`. `transmit()` sends to the TX channel and
  awaits a `Signal` for the result. `poll_receive()` uses the
  double-check / AtomicWaker pattern to avoid the TOCTOU race.

T-Echo hardware wiring:
- TWISPI1 (SPIM1) at 16 MHz, SPI Mode 0 — per SX1262 datasheet §8.2
- CS=P0.24, SCK=P0.19, MOSI=P0.22, MISO=P0.23
- RST=P0.25, BUSY=P0.17, DIO1=P0.20
- `tcxo_ctrl = Ctrl1V8` (DIO3 → 1.8 V TCXO on the T-Echo module)
- `use_dcdc = true` (T-Echo module has DC-DC converter)
- DIO2 as RF switch is configured internally by lora-phy via
  `SetDIO2AsRfSwitchCtrl` — no CPU GPIO needed
- `lora-phy` unconditionally depends on `defmt 0.3`; a zero-overhead
  noop global logger (`defmt::global_logger` with empty trait impl) is
  defined in `hello-techo/src/main.rs` so the firmware links without
  a debug transport

Default modulation parameters available via the radio crate:
- `default_params()` — SF7 / BW125 / CR4-5 at 915 MHz (generic UMSH default).
- `meshcore_us_params()` — 910.525 MHz / SF7 / BW62.5 / CR4-5 / 16-symbol
  TX preamble / private sync word 0x1424, sourced from MeshCore's
  `CustomSX1262.h` and `platformio.ini`. Used by hello-techo so a T-Echo
  on the bench can hear nearby MeshCore traffic.

**Gate:** ✅ boots without panic; radio init (HW reset + full SX1262
calibration via lora-phy) completes successfully on every boot. The
runner task spins in continuous RX, and the firmware drains received
frames via:

- **`packet_handler_task`** — always-on consumer of `RADIO_CH.rx`.
  Increments a static packet counter, signals the display, and queues a
  pre-formatted `[RX] rssi=… snr=… len=… data=…` print line to a static
  print channel.
- **`run_echo`** — drains the print channel to USB-CDC. When no serial
  client is connected, the print channel fills and oldest lines are
  dropped silently; the counter and display still advance.
- **`display_task`** — re-renders the boot screen with the latest count
  whenever the count-changed signal fires. 5 s throttle caps the visible
  refresh rate (full refresh, ~2 s of flashing per update; proper
  partial refresh on this panel needs RED-RAM previous-frame tracking
  which is deferred).

### Phase 6 — MAC coordinator integration ✅

Wires `Mac<TechoPlatform>` into the firmware. `packet_handler_task` is
replaced by `mac_task`, which drives `mac.run(on_event)` and counts only
UMSH-authenticated packets. Display shows "MAC: N"; raw MeshCore frames
on the same frequency are received and silently dropped by the parser.

**`TechoPlatform` associated types:**

| Type | Impl |
|------|------|
| `Identity` | `SoftwareIdentity` (ephemeral, regenerated on boot) |
| `Aes` / `Sha` | `SoftwareAes` / `SoftwareSha256` |
| `Radio` | `Sx1262Radio<ThreadModeRawMutex, 4, 2>` |
| `Clock` | `EmbassyClock` — `Instant::now()` + `pin!(Timer::at())` for `poll_delay_until` |
| `Rng` | `TeChoRng` — XorShift64 seeded from nRF52840 FICR DEVICEID (chip-unique; not crypto-grade) |
| `CounterStore` | `RamCounterStore` — no-op (session-scoped replay protection only) |
| `KeyValueStore` | `NullKeyValueStore` — always-None |
| `Delay` | `embassy_time::Delay` |

**Capacity:** `Mac<TechoPlatform, 1, 8, 4, 4, 8, 255, 32>` — 1 identity,
8 peers, 4 channels, 4 pending ACKs, 8 TX slots, 255 B frame buffer,
32-entry dup cache. Static footprint ≈ 6 KiB; fits comfortably in the
nRF52840's 256 KiB RAM (total BSS ≈ 107 KiB after Phase 6 additions).

**Non-obvious integration facts:**
- `embedded-alloc` (4 KiB heap) is required even with no runtime alloc:
  `umsh-mac` → `umsh-sync` → `extern crate alloc` forces the linker
  to require a `#[global_allocator]`.
- Default MAC capacity (`IDENTITIES=4`, `PEERS=16`, …) overflows RAM by
  ~52 KiB; minimal const generics are essential on embedded.
- The `static_mut_refs` lint requires `core::ptr::addr_of!(HEAP)` for
  the heap init pointer — `HEAP.as_ptr()` is now denied.
- `umsh-hal` must be a direct firmware dep; `umsh-mac` does not
  re-export `Clock`, `CounterStore`, or `KeyValueStore`.
- Build with `cargo build` from the firmware directory, not with
  `--manifest-path` from the workspace root — the linker flags in
  `.cargo/config.toml` are only picked up from the CWD hierarchy.

**Gate:** ✅ boots, displays "MAC: 0", USB serial shows startup banner.
Count stays at 0 because no second UMSH node is available for packet
generation; parser correctly drops all MeshCore frames on the channel.

### Phase 4 — E-paper "hello world" ✅

Drive peripheral-power-enable high, initialize the e-paper bus (SPI
+ control pins), write a frame buffer using `embedded-graphics` (text
"UMSH bringup" + git short SHA), push it to the SSD1681, and put the
panel in deep sleep. No third-party e-paper crate was used; the driver
is a thin inline module in `main.rs`.

Implementation notes (these cost roughly a full debugging session):

1. **SPIM2 not SPIM3.** SPIM3 on nRF52840 produced a total SPI
   failure — no SCK, no MOSI — on the T-Echo pin assignment. SPIM2
   with the `SPI2` interrupt works. Root cause of SPIM3 failure not
   fully diagnosed (suspected errata or pin-mux conflict with another
   peripheral).
2. **Exact init sequence matters.** The only known-good reference for
   the GDEH0154D67 is `GxEPD2_154_D67` (the library Meshtastic uses).
   Three specific mistakes that each silently broke RAM writes:
   - Cmd `0x01` third byte must be `0x00` (GD=0). Setting GD=1
     mirrored the display scan and confused our own analysis.
   - Cmd `0x11` (data entry mode) must be `0x03` (X+, Y+). Using
     `0x01` (X+, Y−) walked the address counter off the first row
     into undefined rows; the full 5000-byte write appeared to
     "succeed" (BUSY pulsed, no SPI error) but nothing landed.
   - No pre-RAM load cycle. Adding `0x22 [0xB1]` + `0x20` before the
     first RAM write causes the chip to finish in a "disable clock"
     state that silently swallows all subsequent `0x24` (Write B/W
     RAM) data. The only activation step is the post-RAM `0x22 [0xF7]`
     + `0x20` full-refresh trigger.
3. **RED RAM must be cleared.** Prior firmware (Meshtastic) left pixel
   data in the RED RAM. Without explicitly writing the same frame to
   both `0x24` (B/W) and `0x26` (RED), residual red-channel content
   combined with our new B/W frame and old data remained visible.
4. **EasyDMA reads SRAM only.** `&[...]` byte-slice literals in
   release builds may be in `.rodata` (flash). Every short data payload
   (command arguments) is copied to a stack buffer before the
   `spi.write()` call.
5. **Panel is mounted 90° CCW from the chip's scan order.** The
   T-Echo schematic places the flex cable at an edge that rotates the
   natural scan 90° from what a user holding the device expects.
   GxEPD2 compensates with rotation-3: logical pixel `(x, y)` maps to
   chip pixel `(chip_x, chip_y) = (y, HEIGHT−1−x)`. Applied in the
   `EpdFb` `DrawTarget` implementation.

**Gate:** ✅ powering up the device with the bringup firmware shows
"UMSH bringup" and the git short SHA on the e-paper in the correct
orientation, visible without any host interaction.

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
