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

## The BSP / UX / App / Binary layering

```
crates/
  umsh-bsp-<chip>/          (chip-level BSP — peripherals, USB, GPREGRET, …)
  umsh-bsp-<board>/         (board-level BSP — pins, sensors, radios, init)
  umsh-ux-<class>/          (UX mechanism for one device class)
  umsh-app-<firmware>/      (app-specific policy, generic over Platform + UX class)
firmware/
  <firmware>-<board>/       (~30 LOC binary: glues one BSP, one UX, one App)
```

- A **BSP crate** owns the messy hardware-specific code: pinout, peripheral
  setup, embassy executor config, USB driver, power management. It implements
  the `umsh::Platform` trait (and any board-capability traits, see
  [App portability](#app-portability)).
- A **UX-class crate** is pure-logic mechanism for a family of devices with
  a similar physical UX. For example, `umsh-ux-tracker` covers boards with
  one button, one LED, one piezo buzzer, USB-CDC, and a battery — providing
  a button-gesture FSM, an LED-heartbeat engine with overlay sequences, a
  buzzer melody sequencer, and a low-battery detector. A device class with
  a screen + speaker + keyboard would have its own (totally different)
  `umsh-ux-handheld` crate; sharing app code across UX classes is rarely
  worthwhile because the abstractions don't generalize.
- An **App crate** is `no_std`, hardware-agnostic, and generic over a
  Platform plus a UX class. It defines *policy* on top of the UX
  mechanism: which button event maps to which action, which CLI commands
  exist, how the MAC layer integrates with the user-facing surface.
- A **Binary crate** is the leaf. It picks one BSP and one App (which
  implicitly picks a UX class via the App's bounds), calls `Bsp::init()`,
  and hands the resources to `App::run()`. It owns the linker script,
  target triple, and flashing config — nothing else.

Why a separate UX layer:

- **Mechanism is reusable across apps on the same device class.** A
  T1000-E repeater firmware uses the same button FSM and LED heartbeat as
  the T1000-E companion-radio CLI; only the *mapping* of button events to
  actions differs.
- **App code is portable across boards of the same class.** A companion-CLI
  app written against `umsh-ux-tracker` runs on T1000-E and Solar P1
  identically — both boards implement the tracker class.
- **Putting class-specific mechanism in the app crate couples them
  forever.** Discovered exactly this mistake during the first scaffolding
  pass: button / LED / buzzer mechanism initially lived in
  `umsh-app-companion-cli`, but it's all class-mechanism that belongs in
  a UX crate. The rule that fell out: if a future repeater firmware on
  the same board would want this code, it belongs in the UX crate, not
  the app crate.

Adding a new firmware type → one new app crate plus one new binary per board
it targets. Adding a new board → one new board-BSP (and possibly one new
chip-BSP) plus one new binary per app it should run. Adding a new device
class → one new UX-class crate plus the apps that target it.

## Crate naming conventions

| Prefix / location | Purpose | Examples |
|---|---|---|
| `crates/umsh-bsp-<chip>/` | Chip-level BSP, board-agnostic. Owns peripherals and patterns that any board using that chip needs. | `umsh-bsp-nrf52840`, `umsh-bsp-esp32s3` |
| `crates/umsh-bsp-<board>/` | Board-level BSP. Composes a chip-BSP with board-specific pinout, sensors, radios. Implements `Platform`. | `umsh-bsp-t1000e`, `umsh-bsp-solar-p1`, `umsh-bsp-tdeck` |
| `crates/umsh-ux-<class>/` | UX-class mechanism. Pure-logic engines shared by every app on every board of that device class. | `umsh-ux-tracker` (single button + single LED + piezo buzzer + USB-CDC), future `umsh-ux-handheld`, `umsh-ux-headless` |
| `crates/umsh-app-<firmware>/` | App-specific policy, hardware-agnostic. Generic over a Platform and a UX class. | `umsh-app-companion-cli`, `umsh-app-repeater`, `umsh-app-uart-cli-debug` |
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
T1000E) of a class that already has a UX crate:

1. **Create the app crate** at `crates/umsh-app-repeater/`. `no_std`,
   depends on `umsh-mac` (or `umsh-node` if higher-level needed) and on
   the UX-class crate (`umsh-ux-tracker`). Defines its public entry
   point:
   ```rust
   pub async fn run<B>(spawner: Spawner, board: B) -> !
   where B: Platform + HasLed,  // whatever capabilities you need
   ```
2. **Add the app crate to the workspace `members`** (not necessarily to
   `default-members`, depending on whether it builds host-side for tests).
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

If the target board is a *new device class* (no existing `umsh-ux-<class>`
crate), do that first — see [Adding a new UX class](#adding-a-new-ux-class).

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
3. **Decide which UX class the board belongs to.** If it matches an
   existing class, the board-BSP implements that class's capability
   traits. If it does not, see
   [Adding a new UX class](#adding-a-new-ux-class).
4. **Document the board** with a hardware reconstruction or schematic
   summary alongside the BSP, similar to
   [t1000e-hardware.md](t1000e-hardware.md).
5. **For each app that should run on this board**, follow the
   "Adding a new firmware type" recipe to create the binary crate.

## Adding a new UX class

A new UX class is warranted when the board's physical user-interface
substrate differs enough from existing classes that the existing
mechanism crates don't apply: e.g. a board with a screen + speaker +
keyboard cannot meaningfully reuse `umsh-ux-tracker`'s single-LED
heartbeat or piezo-tone melody sequencer.

1. **Create the UX-class crate** at `crates/umsh-ux-<class>/`. `no_std`,
   pure logic, no embassy / no I/O / no hardware deps. Provides the
   mechanism engines for that class (input event recognition, output
   sequencing, etc.).
2. **Define the capability traits** the class expects board-BSPs to
   implement, alongside the engines. Keep them small and orthogonal.
3. **Write unit tests** for every engine with synthetic time and
   synthetic inputs — this is the layer with the most test leverage.
4. **Refit any board-BSPs that target the new class** to implement the
   capability traits.
5. **Write apps for the class.** Apps targeting the new class go in
   their own `umsh-app-<firmware>-<class>` or just
   `umsh-app-<firmware>` crates as appropriate (apps targeting only one
   class don't need the suffix; apps with both tracker- and
   handheld-class variants might).

## What lives in CLAUDE.md / why this doc exists

This doc is the contract. Per-firmware plans (e.g.
[firmware-plan-t1000e.md](firmware-plan-t1000e.md)) document the things
*specific to that firmware* — the safety contract for that particular
device, the button UX, the phasing for that build — and inherit the
conventions defined here. If a per-firmware plan and this doc disagree,
this doc wins.
