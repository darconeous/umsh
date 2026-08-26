# UMSH Firmware Architecture

How UMSH firmware is organized across boards and MCU families. This document
captures the conventions; per-board plans capture specifics.

If you are adding a board, this is the document to read first.

## The shape of the problem

UMSH firmware varies along two axes:

- **Firmware type**: the shipping device image, plus a per-board console
  harness used during bringup.
- **Hardware platform**: five boards across two MCU families (nRF52840 and
  ESP32-S3), with more over time.

A crate per (firmware, board) combination explodes combinatorially and
duplicates code. The matrix is instead factored into layers that compose at
the leaves, with one set of shared sources per MCU family.

### One image per board

The *role* axis is gone. There is no separate repeater firmware and no
separate companion-radio firmware: a repeater and a companion radio are the
same image holding different property values, and the difference is
configuration the operator applies over ULCP. What remains per-board is the
BSP, the flash layout, and the target triple.

"Companion radio" and "repeater" stay useful words — they name recognizable
points in the configuration space, and host tooling offers them as presets —
but they no longer name build targets.

### The shipping matrix

| Board | MCU | Shipping image | Transports | Flash/RAM (of budget) | Status |
|---|---|---|---|---|---|
| T-1000E | nRF52840 | `t1000e` | BLE, USB-CDC | 470/137 KiB (756/256) | daily driver |
| T-Echo | nRF52840 | `techo` | BLE, USB-CDC | 478/145 KiB (756/256) | hardware-accepted |
| SenseCAP Solar | nRF52840 | `sensecap-solar` | BLE, USB-CDC | 462/134 KiB (756/256) | hardware-accepted |
| Wio Tracker L1 | nRF52840 | `wio-tracker-l1` | BLE, USB-CDC | 476/136 KiB (756/256) | bringup complete, hw validation open |
| Heltec V3 | ESP32-S3 | `heltec-v3` | BLE, UART | 1298/216 KiB (3008/512) | hardware-accepted |
| Heltec V2 | ESP32 | `heltec-v2` | BLE, UART | 1260/191 KiB (3008/see below) | bringup complete, hw validation open |

For the nRF52840 boards, figures are `text+data` against the application
flash window and `data+bss` against SRAM, from a release build — the two
left-hand columns of `arm-none-eabi-size <elf>`. On the Espressif boards
`size` misleads: esp-hal's linker script fills the leftover DRAM with the
`.stack` section and shadows flash-resident code into NOBITS placeholder
sections, so `data+bss` always reads as roughly the whole DRAM window no
matter what the image allocates. The honest RAM figure there is
`readelf -S` over the real sections (`.data` + `.data.wifi` + `.bss`,
plus `.rwdata_dummy` on the S3, where the D-bus shadows IRAM-resident
code), and that is what the table carries.

The Heltec V2's RAM budget is not one number: esp-hal gives the classic
ESP32 a 128 KiB `dram_seg` for linker-placed statics (192 KiB minus the
BT controller's 64 KiB reservation) plus the ~96 KiB `dram2_seg` past
the ROM data and stack carve-outs, usable only for runtime-claimed
memory. The image places 111.5 KiB of statics in `dram_seg` (16.5 KiB
main-task stack remains) and its 48 KiB heap plus the ~32 KiB
device-node Mac arena in `dram2_seg`. The board's prior on-air failure
is documented in `docs/archive/firmware-plan-heltec-lora32-v2.md`; the
reference unit is a suspected RF defect, so hardware validation starts
from a second unit.

**The Wio Tracker L1 is the OLED variant.** The L1, L1 Pro, and L1 Lite
share a pin map, so one image covers them; the L1 e-ink variant drives a
different panel on SPI1 and is not supported. The board's SoftDevice is
S140 v7.3.0, so its application starts at `0x27000` rather than the
T-Echo's `0x26000` — the one thing in its build that cannot be copied
from a sibling board.

### `*-console` is a bringup harness, not a product

Each board also has a `<board>-console` binary, excluded from the shipping
matrix above. These earn their place for one reason: they are the only thing
exercising the non-BLE path end to end, and they are the natural tool for a
new board before BLE stands up. Treat them as diagnostics — a board with a
working console image and no device image is a board in bringup.

Console binaries compose a BSP with `umsh-app-ulcp-cli`, and each keeps its
own `src/main.rs`; they do not share the shipping sources.

## The layering

```
crates/
  umsh-bsp-<chip>/          (chip-level BSP — peripherals, USB, GPREGRET, …)
  umsh-bsp-<board>/         (board-level BSP — pins, sensors, radios, init)
  umsh-ux-<class>/          (UX mechanism for one device class)
  umsh-ulcp-runtime/        (board-agnostic ULCP device runtime)
  umsh-app-ulcp-cli/        (console-harness app)
firmware/
  nrf52-tracker/src/        (shipping sources shared by all four nRF52840 boards)
  <board>/                  (thin manifest: features + memory.x + target triple)
  <board>-console/          (console binary: own main.rs)
```

- A **BSP crate** owns the messy hardware-specific code: pinout, peripheral
  setup, embassy executor config, USB driver, power management. It implements
  the `umsh::Platform` trait.
- A **UX-class crate** is pure-logic mechanism for a family of devices with
  a similar physical UX. `umsh-ux-tracker` covers boards with one button, one
  LED, one piezo buzzer, USB-CDC, and a battery — providing a button-gesture
  FSM, an LED-heartbeat engine with overlay sequences, a buzzer melody
  sequencer, and a low-battery detector. `umsh-ux-display-tracker` covers
  boards that add a small display and possibly a D-pad (T-Echo, Heltec V3,
  Wio Tracker L1) — providing the on-screen menu, the display-attention
  policy, and the input gate, and borrowing the button recognizer from
  `umsh-ux-tracker` rather than duplicating it. A device class with a speaker
  and keyboard would have its own (totally different) `umsh-ux-handheld`
  crate; sharing app code across UX classes is rarely worthwhile because the
  abstractions don't generalize.
- **`umsh-ulcp-runtime`** holds every part of the ULCP device that has no
  board HAL dependency: the session run loop (`driver`), radio multiplexer,
  transport arbitration, BLE pairing policy, duty gate, journal handling, and
  the device node's persisted counters. Both MCU families consume one copy.
  Its modules are feature-gated (`driver`, `radio`, `counters`,
  `device-node`) so a consumer pulls only what it uses.
- **Shipping sources** live in `firmware/nrf52-tracker/src/`, a directory with
  no manifest of its own. All four nRF52840 board packages point their
  `[[bin]]` at `../nrf52-tracker/src/main.rs`.
- A **board package** under `firmware/<board>/` is a thin manifest. It selects
  exactly one `board-*` feature, owns `memory.x` and `build.rs`, and pins the
  target triple through its `.cargo/config.toml`. It contains no source.

The Espressif images do not share the nRF52840 sources — `firmware-esp32/`
carries its own shipping sources in `firmware/esp32-tracker/src/`, shared
by the Heltec V2 and V3 board packages the same way the nRF boards share
`nrf52-tracker/src/` (thin manifests selecting a `board-*` feature). The
two families share `umsh-ulcp-runtime`, the BSP/UX crates, and the
protocol crates; the boot, transport, and peripheral wiring is
necessarily per-family.

Why a separate UX layer:

- **Mechanism is reusable across images on the same device class.** A board's
  device image uses the same button FSM and LED heartbeat as its console
  harness; only the *mapping* of button events to actions differs.
- **Mechanism belongs outside the app.** If another image on the same board
  would want the code, it belongs in the UX crate, not the app crate. Button,
  LED, and buzzer mechanism is class-mechanism, not policy.

## How board variation is expressed

Two mechanisms, used for different kinds of variation.

**Cargo features, for what silicon is present.** The four nRF52840 board
packages carry an identical feature block; only `default` differs. A
`board-*` feature is a bundle of capability features:

| Board feature | Expands to |
|---|---|
| `board-techo` | `display-epd`, `button-nav`, `system-off-techo`, `led-active-low`, `cap-battery-saadc` |
| `board-t1000e` | `t1000e`, `cap-battery-saadc` |
| `board-sensecap-solar` | `cap-battery-saadc`, `power-button` |
| `board-wio-tracker-l1` | `display-oled`, `button-nav`, `system-off-wio`, `cap-battery-saadc`, `cap-buzzer` |

Capability features name a hardware fact, not a board: `cap-battery-saadc`
(SAADC battery monitor), `cap-buzzer` (a sounder the locate alert can drive),
`display-epd` / `display-oled` (both imply `has-display`, which gates the menu
subsystem), `button-nav`, `system-off-techo` / `system-off-wio`,
`led-active-low`, `lfclk-rc`, `power-button`. A separate set —
`no-ble`, `ble-debug`, `ble-store-fault-inject`, `ble-wipe-on-boot` — selects
diagnostic images that are never shipped.

Features carry their weight on these parts because exclusion has to be
*guaranteed*, not merely likely: the nRF52840 images run at 462–478 KiB of a
756 KiB window and 134–145 KiB of 256 KiB SRAM. A `#[cfg]` guarantees the
T-Echo image contains no OLED driver and no buzzer sequencer; relying on the
optimizer to prove those paths dead does not.

The cost is that only combinations someone actually builds are ever
type-checked. Keep CI building every shipping image, not a representative
subset — a `#[cfg]` arm reachable from one board's feature set alone is
compiled nowhere else.

**`t1000e` is the known wart.** It predates the capability split and still
bundles T-1000E-only capabilities that no other board shares: LR1110 radio,
PWM LED engine, buzzer, sleep/UX-preference state machine, action button, and
that board's System OFF path. It is the most-used feature in the shared
sources. A board that wants one of those capabilities without the others must
unbundle it first; break out a `cap-*` feature at that point rather than
widening `t1000e`.

**Trait defaults, for what behavior varies.** Where shared logic needs
something from the board, `umsh-ulcp-runtime::driver::DeviceEnv` asks for it
through a method, and capability negotiation happens through defaults that
refuse:

```rust
async fn sample_battery(&mut self) -> Result<BatteryStatus, ()> { Err(()) }
async fn older_snapshot(&mut self, out: &mut [u8]) -> Option<usize> { None }
async fn clear_counters(&mut self) {}
fn report_snapshot_rejected(&mut self, fell_back: bool) {}
```

A board with a battery overrides `sample_battery`; a board whose journal
cannot walk back leaves `older_snapshot` alone and rejection is terminal. The
required methods — snapshot and identity persistence, `fill_secret` — have no
default, so a board cannot forget them.

The division is deliberate: `#[cfg]` for whether hardware exists, `DeviceEnv`
for how the board answers a question the shared runtime asks. Behavior that
must compose belongs behind the trait, where the type checker sees every
implementation.

## Crate naming conventions

| Prefix / location | Purpose | Examples |
|---|---|---|
| `crates/umsh-bsp-<chip>/` | Chip-level BSP, board-agnostic. Owns peripherals and patterns any board using that chip needs. | `umsh-bsp-nrf52840`; `umsh-bsp-esp32` (in `firmware-esp32/crates/`) |
| `crates/umsh-bsp-<board>/` | Board-level BSP. Composes a chip-BSP with board-specific pinout, sensors, radios. Implements `Platform`. | `umsh-bsp-t1000e`, `umsh-bsp-techo`, `umsh-bsp-sensecap-solar`, `umsh-bsp-wio-tracker-l1` |
| `crates/umsh-ux-<class>/` | UX-class mechanism. Pure-logic engines shared by every image on every board of that device class. | `umsh-ux-tracker` (button + LED + buzzer + USB-CDC), `umsh-ux-display-tracker` (adds a small display and D-pad) |
| `crates/umsh-ulcp-runtime/` | Board-agnostic ULCP device runtime consumed by every shipping image. | — |
| `crates/umsh-app-<firmware>/` | App policy for a non-shipping image, hardware-agnostic. | `umsh-app-ulcp-cli` |
| `firmware/<board>/` | Shipping board package. Thin manifest, no source. | `firmware/t1000e`, `firmware/techo` |
| `firmware/<board>-console/` | Console harness binary. Own `main.rs`. | `firmware/t1000e-console` |

The chip-BSP / board-BSP split exists because chips get reused across boards.
All four nRF52840 boards share `umsh-bsp-nrf52840` for USB setup, GPREGRET
handling, System OFF entry, and flash-backed storage backends, and differ only
in their board-BSP, which carries the pinout and which sensors are present.

If a chip is only ever used by one board, skip the chip-BSP layer and put
everything in the board-BSP. Splitting pre-emptively is usually worth it once
a second board is known to be coming.

## The Platform trait contract

The `umsh::Platform` trait (defined in `umsh-mac`, re-exported from `umsh`) is
what every BSP implements and what the MAC layer consumes. It is a bundle of
associated types, not methods:

| Type | Bound | Purpose |
|---|---|---|
| `Identity` | `umsh_crypto::NodeIdentity` | Local identity |
| `Aes` | `umsh_crypto::AesProvider` | AES provider |
| `Sha` | `umsh_crypto::Sha256Provider` | SHA/HMAC provider |
| `Radio` | `umsh_hal::Radio` | LoRa transceiver |
| `Delay` | `DelayNs` | Async delay |
| `Clock` | `umsh_hal::Clock` | Monotonic millisecond source |
| `Rng` | `rand::CryptoRng` | Randomness |
| `CounterStore` | `umsh_hal::CounterStore` | Persistent frame counters |
| `KeyValueStore` | `umsh_hal::KeyValueStore` | Persistent K/V (identity, peer cache) |

Route randomness through `Rng` even where the chip RNG could be called
directly: on nRF52840 the RNG peripheral belongs to the SoftDevice controller
at runtime, so the BSP seeds a ChaCha20 CSPRNG from the hardware TRNG at boot.
There is no non-cryptographic RNG anywhere in the tree.

A BSP's `Board::init()` returns a struct implementing `Platform` and typically
exposes additional board resources alongside it — buttons, LEDs, buzzers,
GNSS, accelerometers — beyond what `Platform` requires.

See `crates/umsh-mac/src/lib.rs` and `crates/umsh-hal/` for the exact
definitions; treat those as the source of truth.

## Workspace inclusion rules

**Default: include new firmware in the root workspace.** That keeps
`Cargo.lock` shared and lets CI drive firmware builds through the same
Makefile targets developers use. With `resolver = "2"` and `default-members`
excluding `firmware/*`, host crates and bare-metal firmware coexist fine.

**Exclude into a sibling workspace** when the platform brings its own
toolchain or build system:

| Trigger | Action |
|---|---|
| Requires a vendor Rust fork (Xtensa via `espup`) | Exclude — the root `rust-toolchain.toml` can't be two things. |
| Uses `esp-idf-sys` / `esp-idf-svc` (std-via-newlib) | Exclude — its build script and `sdkconfig` machinery don't play with a unified workspace. |
| Drives builds via non-cargo orchestration (Zephyr, Yocto, IDF CMake) | Exclude — those tools don't respect cargo's view of the workspace. |
| Bare-metal embassy / `rp-hal` / cortex-m HAL on a stock toolchain | **Include.** Just a different target triple. |

`firmware-esp32/` is excluded under the first trigger: the Xtensa targets need
`channel = "esp"`. It is bare-metal `esp-hal`, which would otherwise qualify
for inclusion — the toolchain, not the HAL, is what forces the split. A
RISC-V ESP32 part on the stock toolchain would not need excluding.

An excluded workspace still consumes `crates/*` via path dependencies and
shares source. It has its own `Cargo.toml`-as-`[workspace]` root, its own
`Cargo.lock`, and its own `rust-toolchain.toml`, and lives next to `crates/`
and `firmware/` rather than in a separate repo. `[patch]` tables do not cross
workspace boundaries, so the `lora-phy` and `trouble-host` fork pins are
replicated in both manifests and must move in lockstep.

Because the root build never checks `firmware-esp32/`, a change to a shared
crate can break the ESP32 image invisibly. Build it explicitly
(`make build-heltec-v3`) when touching shared types.

### Required workspace settings

The root `Cargo.toml` enumerates members explicitly rather than globbing, so
adding a crate is a deliberate act:

```toml
[workspace]
resolver = "2"
members = [
    "crates/umsh-core",
    # … every crate, plus:
    "firmware/t1000e",
    "firmware/t1000e-console",
    "tools/ulcp-web-debugger/engine",
    "umsh",
]
default-members = [
    # the same list, minus firmware/*
]
```

`resolver = "2"` prevents feature unification across host-build and
target-build dependencies. `default-members` keeps root-level `cargo build` /
`cargo test` from cross-compiling every firmware on a developer's laptop.

Each `firmware/<name>/` crate needs its own `.cargo/config.toml`:

```toml
[build]
target = "thumbv7em-none-eabihf"

[target.thumbv7em-none-eabihf]
rustflags = [
  "-C", "link-arg=-Tlink.x",
]
```

This is what makes `cargo build` *inside the firmware directory* pick up the
right target and link script. Building with `--manifest-path` or `-p` from the
root silently drops these flags and yields a broken ELF — always build from
inside the crate, which is what the Makefile does.

Firmware crates also need a `build.rs` that copies `memory.x` into `OUT_DIR`
and adds it to the link search path. The shipping packages' `build.rs`
additionally exports `GIT_DESCRIBE`, which `PROP_DEV_VERSION` reports.

## Building and flashing

Use the Makefile. It builds each firmware from inside its own directory and
converts the ELF with the board's UF2 base address and family ID; hand-rolled
`objcopy` / `uf2conv` / `espflash` invocations get these wrong.

- `make build-<board>` / `make flash-<board>` — shipping image
- `make build-<board>-console` / `make flash-<board>-console` — bringup harness

nRF52840 firmware **only links in `--release`**; dev builds overflow flash.
`cargo check` is fine at any profile. Flashing requires the device in DFU mode
(1200-baud touch, double-tap reset, or hold-boot-while-plugging). ESP32 flashes
through the ROM serial bootloader and rewrite the partition table.

CI drives the same Makefile targets, so a target that works locally works
there.

## Adding a board

If the chip is new, you also need a chip-BSP. Otherwise just a board-BSP.

1. **(If new chip)** Create `crates/umsh-bsp-<chip>/`. Owns USB driver setup,
   clock init, retained-RAM access (panic capture, GPREGRET-style DFU
   mechanisms), flash-backed storage, and low-power mode entry.
2. **Create the board-BSP** at `crates/umsh-bsp-<board>/`. Owns the pinout,
   on-board peripherals, and a `Board::init()` returning a struct that
   implements `Platform`.
3. **Document the board** with a hardware reconstruction or schematic summary
   under [`docs/hardware/`](hardware/), similar to
   [t1000e-hardware.md](hardware/t1000e-hardware.md). Do this before writing
   board code, not after.
4. **Decide which UX class the board belongs to.** If it matches an existing
   class, reuse it. If not, see [Adding a UX class](#adding-a-ux-class).
5. **Add the `board-*` feature** to the shared feature block, expressed as
   existing `cap-*` features wherever possible. Add a new `cap-*` feature only
   for a hardware fact none of them covers, and replicate the whole block
   across all sibling board packages so they stay identical.
6. **Create the board package** at `firmware/<board>/`: `Cargo.toml` with
   `default = ["board-<board>"]` and `[[bin]].path` pointing at the shared
   sources, plus `memory.x`, `build.rs`, and `.cargo/config.toml`. Confirm the
   application base address against the board's SoftDevice version rather than
   copying a sibling's.
7. **Register it** in root `members` but not `default-members`.
8. **Add Makefile targets** (`build-<board>`, `flash-<board>`) and a
   `scripts/firmware_image.py` entry for the UF2 family ID and base address.
9. **Add it to the CI matrix** — both the shipping image and the console
   harness.

A board on a new MCU family that cannot share the existing sources needs its
own `firmware/<family>/src/` (or its own sibling workspace, per the inclusion
rules) and should consume `umsh-ulcp-runtime` rather than forking the runtime.

## Adding a UX class

A new UX class is warranted when the board's physical interface differs enough
that existing mechanism crates don't apply: a board with a screen, speaker, and
keyboard cannot meaningfully reuse `umsh-ux-tracker`'s single-LED heartbeat or
piezo melody sequencer.

1. **Create the crate** at `crates/umsh-ux-<class>/`. `no_std`, pure logic, no
   embassy, no I/O, no hardware dependencies. Provides the mechanism engines
   for that class — input recognition, output sequencing.
2. **Write unit tests** for every engine with synthetic time and synthetic
   inputs. This is the layer with the most test leverage, and the only one
   that tests cheaply on the host.
3. **Reuse across classes where the mechanism is genuinely the same.**
   `umsh-ux-display-tracker` borrows the button recognizer from
   `umsh-ux-tracker` instead of duplicating it.
4. **Refit board-BSPs** that target the new class.

## Why this doc exists

This doc is the contract. Per-board plans and hardware documents cover what is
specific to one device — the safety contract, the button UX, the pin map — and
inherit the conventions defined here. If a per-board plan and this doc
disagree, this doc wins.
