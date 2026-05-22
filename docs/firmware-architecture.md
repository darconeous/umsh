# UMSH Firmware Architecture

How UMSH firmware is organized across multiple firmware types and hardware
platforms. This document captures the conventions; per-firmware plans (e.g.
[firmware-plan-t1000e.md](firmware-plan-t1000e.md)) capture specifics.

If you are adding a new firmware type or a new board, this is the document to
read first.

## The shape of the problem

UMSH firmware lives on a 2-D matrix:

- **Firmware types**: companion-radio CLI, repeater, UART debug CLI, … (more
  over time).
- **Hardware platforms**: Seeed SenseCap T1000E, Seeed SenseCap Solar P1,
  Lilygo T-Deck, … (more over time).

A naive "one crate per (firmware, platform) combination" approach explodes
combinatorially and duplicates code. We instead factor the matrix into three
kinds of crates that compose at the leaves.

## The BSP / App / Binary triad

```
crates/
  umsh-bsp-<chip>/          (chip-level BSP — peripherals, USB, GPREGRET, …)
  umsh-bsp-<board>/         (board-level BSP — pins, sensors, radios, init)
  umsh-app-<firmware>/      (firmware logic, generic over a Platform)
firmware/
  <firmware>-<board>/       (~30 LOC binary: glues one BSP and one App)
```

- A **BSP crate** owns the messy hardware-specific code: pinout, peripheral
  setup, embassy executor config, USB driver, power management. It implements
  the `umsh::Platform` trait (and any board-capability traits, see
  [App portability](#app-portability)).
- An **App crate** is `no_std`, hardware-agnostic, and generic over a
  Platform. It defines the firmware's behavior — what tasks run, what the
  CLI does, how the device responds to inputs.
- A **Binary crate** is the leaf. It picks one BSP and one App, calls
  `Bsp::init()`, and hands the resources to `App::run()`. It owns the linker
  script, target triple, and flashing config — nothing else.

Adding a new firmware type → one new app crate plus one new binary per board
it targets. Adding a new board → one new board-BSP (and possibly one new
chip-BSP) plus one new binary per app it should run.

## Crate naming conventions

| Prefix / location | Purpose | Examples |
|---|---|---|
| `crates/umsh-bsp-<chip>/` | Chip-level BSP, board-agnostic. Owns peripherals and patterns that any board using that chip needs. | `umsh-bsp-nrf52840`, `umsh-bsp-esp32s3` |
| `crates/umsh-bsp-<board>/` | Board-level BSP. Composes a chip-BSP with board-specific pinout, sensors, radios. Implements `Platform`. | `umsh-bsp-t1000e`, `umsh-bsp-solar-p1`, `umsh-bsp-tdeck` |
| `crates/umsh-app-<firmware>/` | Firmware logic, hardware-agnostic. Generic over the resources the app needs. | `umsh-app-companion-cli`, `umsh-app-repeater`, `umsh-app-uart-cli-debug` |
| `firmware/<firmware>-<board>/` | Binary glue crate. Pinned to a target triple. | `firmware/companion-cli-t1000e`, `firmware/repeater-t1000e`, `firmware/repeater-tdeck` |

The chip-BSP / board-BSP split exists because we expect chips to be reused
across boards. T1000E and Solar P1 are both nRF52840, so they share
`umsh-bsp-nrf52840` for USB setup, GPREGRET handling, System OFF entry, and
flash-backed storage backends — and only differ in `umsh-bsp-t1000e` vs
`umsh-bsp-solar-p1`, which carry the pinouts and which sensors are present.

If a chip is only ever used by one board, you can skip the chip-BSP layer
and put everything in the board-BSP. But splitting it pre-emptively is
usually worth it once you know a second board is coming.

## The Platform trait contract

The `umsh::Platform` trait (defined in `umsh-mac`, re-exported from `umsh`)
is what every BSP must implement and what every App consumes. It bundles the
resources the MAC layer needs:

- `Radio` — a LoRa transceiver behind the [`umsh_hal::Radio`] async trait.
- `Clock` — a monotonic-millisecond source.
- `Rng` — randomness (route through this even on platforms where you "could"
  call the chip RNG directly, so future BLE stacks can substitute a
  SoftDevice-mediated RNG without app changes).
- `CounterStore` — persistent frame-counter storage.
- `KeyValueStore` — persistent K/V for identity, peer cache, etc.

A BSP's `Board::init()` returns a struct that implements `Platform` (and
typically exposes additional board resources alongside — buttons, LEDs,
buzzers, GNSS, accelerometers — that go beyond what `Platform` requires).

See [`crates/umsh-mac/`] and [`crates/umsh-hal/`] for the exact trait
definitions; treat those as the source of truth.

## App portability

Apps differ in what board resources they need. A repeater only needs a
radio and an LED. A companion-radio CLI also needs a USB interface, a
button, a buzzer, and a GNSS module. We want compile-time enforcement that
an app and a board are compatible — feature-flag matrices are an anti-pattern
here.

The recommended pattern is **trait-bounded App entry points**:

```rust
// In umsh-app-companion-cli:
pub async fn run<B>(spawner: Spawner, board: B) -> !
where
    B: Platform + HasButton + HasLed + HasBuzzer + HasGnss + HasUsbCdc,
{
    // ...
}
```

The BSP's board struct implements the capability traits it actually has.
A binary crate trying to combine an incompatible app and board will fail
to compile, with a clear error pointing at the missing trait.

Capability traits live in the umbrella `umsh` crate (or a dedicated
`umsh-bsp-traits` crate as the trait list grows). Keep them small and
single-purpose: `HasButton`, `HasLed`, `HasBuzzer`, `HasGnss`, etc., rather
than one giant `HasEverything` trait.

We will discover the right granularity for these traits by writing the first
two or three apps. Don't over-design the capability vocabulary in advance.

## Workspace inclusion rules

**Default: include the new firmware in the main workspace.** That keeps
`Cargo.lock` shared, lets `cargo check -p firmware-xxx` work from any
directory, and lets CI matrix over firmware crates with `-p <name>`. With
`resolver = "2"` (already set) and `default-members` excluding `firmware/*`,
mixing host-tooling crates and bare-metal firmware in one workspace works
fine in modern Cargo.

**Exclude into a sibling workspace** when the platform brings its own
opinionated build system or toolchain:

| Trigger | Action |
|---|---|
| Uses `esp-idf-sys` / `esp-idf-svc` (std-via-newlib) | Exclude — `esp-idf-sys`'s build script and `sdkconfig` machinery don't play with a unified workspace. Lesson learned from the `rust-lumanoi` project. |
| Requires a vendor Rust fork (Xtensa via `espup`) | Exclude — root `rust-toolchain.toml` can't be two things. |
| Drives builds via non-cargo orchestration (Zephyr, Yocto, IDF CMake) | Exclude — those tools don't respect cargo's view of the workspace. |
| Bare-metal embassy / `esp-hal` / `rp-hal` / cortex-m HAL | **Include.** Just a different target triple. |

An excluded firmware still consumes `crates/*` via path deps and shares
source — it just has its own `Cargo.toml`-as-`[workspace]` root and its own
`Cargo.lock`. The convention is to put it next to `crates/` and `firmware/`,
e.g. `firmware-esp-idf/`, rather than in a separate repo.

### Required workspace settings

The root `Cargo.toml` needs:

```toml
[workspace]
resolver = "2"
members = [
    "crates/*",
    "umsh",
    "firmware/*",
]
default-members = [
    "crates/*",
    "umsh",
]
```

`resolver = "2"` prevents feature unification across host-build and
target-build dependencies. `default-members` keeps root-level
`cargo build` / `cargo test` from trying to cross-compile every firmware
on a developer's laptop.

Each `firmware/<name>/` crate needs its own `.cargo/config.toml`:

```toml
[build]
target = "thumbv7em-none-eabihf"   # or whatever the chip needs

[target.thumbv7em-none-eabihf]
runner = "probe-rs run --chip nRF52840_xxAA"
rustflags = ["-C", "link-arg=-Tlink.x"]
```

This is what makes `cargo build -p firmware-xxx` (or `cargo build` inside
the firmware crate) pick up the right target and runner without affecting
sibling crates.

## Adding a new firmware type

To add a new firmware type (e.g. `repeater`) to an existing board (e.g.
T1000E):

1. **Create the app crate** at `crates/umsh-app-repeater/`. `no_std` with
   `alloc` if needed, depends on `umsh-core`, `umsh-mac`, `umsh-node` (or
   just `umsh-mac` for a thin app like a pure repeater). Defines its
   public entry point:
   ```rust
   pub async fn run<B>(spawner: Spawner, board: B) -> !
   where B: Platform + HasLed,  // whatever capabilities you need
   ```
2. **Add the app crate to the workspace `members`** (not
   `default-members`, since it's `no_std` and most workspace lint configs
   are host-oriented; though depending on your setup it can be in
   `default-members` if it builds on host for tests).
3. **Create the binary crate** at `firmware/repeater-t1000e/`. ~30 LOC
   `main.rs`:
   ```rust
   #[embassy_executor::main]
   async fn main(spawner: Spawner) -> ! {
       let board = umsh_bsp_t1000e::Board::init();
       umsh_app_repeater::run(spawner, board).await
   }
   ```
4. **Write the binary crate's `.cargo/config.toml`** with the target
   triple and runner (see [Required workspace settings](#required-workspace-settings)).
5. **Write the binary crate's `memory.x`** (or reuse the chip-BSP's).
6. **Add the binary crate to workspace `members` but NOT
   `default-members`.**
7. **Add a `justfile` recipe** for flashing: `just flash t1000e repeater`.

## Adding a new board

If the chip is new, you also need a chip-BSP. Otherwise just a board-BSP.

1. **(If new chip)** Create `crates/umsh-bsp-<chip>/`. Owns: USB driver
   setup, clock init, retained-RAM access (for panic capture + DFU
   GPREGRET-style mechanisms), flash-backed storage, low-power mode entry.
   Provides chip-agnostic helpers that any board using this chip will need.
2. **Create the board-BSP** at `crates/umsh-bsp-<board>/`. Owns: pinout,
   on-board peripherals (sensors, radios, indicators), `Board::init()`
   function that returns a struct implementing `Platform` and any
   capability traits the board supports.
3. **Document the board** with a hardware reconstruction or schematic
   summary alongside the BSP, similar to
   [t1000e-hardware.md](t1000e-hardware.md).
4. **For each app that should run on this board**, follow the
   "Adding a new firmware type" recipe to create the binary crate.

## What lives in CLAUDE.md / why this doc exists

This doc is the contract. Per-firmware plans (e.g.
[firmware-plan-t1000e.md](firmware-plan-t1000e.md)) document the things
*specific to that firmware* — the safety contract for that particular
device, the button UX, the phasing for that build — and inherit the
conventions defined here. If a per-firmware plan and this doc disagree,
this doc wins.
