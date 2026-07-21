# Heltec WiFi LoRa 32 V2 Firmware Plan

> **Status (2026-07-21): parked after Phase 2 — possibly defective
> reference unit; no second unit available to disambiguate.** Phases 0–1 are hardware-complete (toolchain,
> safety floor, BLE spike, full board I/O). Phase 2 wired the SX1276
> through lora-phy and is code-complete, but the only available unit
> failed on-air validation with a consistent three-way signature:
> TX frames reach an adjacent LR1110 listener at a healthy −29 dBm
> yet demodulate at SNR −1 dB with near-deterministic payload
> corruption; RX is deaf to strong local traffic (only −114…−128 dBm
> frames at SNR ≈ −11 ever decode); and the idle noise floor measures
> ≈ −102 dBm, ~24 dB above thermal for BW 62.5 kHz. Digital health is
> fine (RegVersion, IRQs, TxDone). The register file was dump-verified
> byte-for-byte against a RadioLib/MeshCore node, and the measured
> carrier offset (FEI) was only +5.8 kHz. The leading hypothesis is a
> defective RF section / reference oscillator (reciprocal mixing
> would explain all three symptoms at once), but with a single unit
> and no independent RF instrumentation this is unproven — an
> unmodeled board-level cause is not ruled out. The debugging
> yielded four real sx127x driver fixes
> now in the lora-rs fork (exact PLL-step rounding for fractional
> carriers, errata 2.3 manual-IF programming, AGC-auto parity with
> RadioLib, and a real HF-band image calibration replacing a no-op) —
> worth upstreaming regardless. Everything through Phase 2, including
> the diagnostic firmware (register dump, per-frame FEI, periodic
> noise-floor print), is committed and ready if another V2 unit ever
> materializes. The ESP32 workspace, esp-rtos generation choices, and
> the BSP layering carry forward to the Heltec **V3** port
> (ESP32-S3 + SX1262), which supersedes this effort.

The first non-nRF52840 UMSH target: classic ESP32 (dual Xtensa LX6)
plus an SX1276/SX1278 radio and an SSD1306 OLED. The device posture
is a battery-powered tracker with a screen — closest in spirit to the
T-Echo — and the end goal is the full **companion radio over BLE**
(the `companion-ncp` firmware class), not just a bringup listener.

See [heltec-lora32-v2-hardware.md](heltec-lora32-v2-hardware.md) for
the hardware reference. See
[firmware-architecture.md](firmware-architecture.md) for the BSP /
UX / App / Binary layering and the workspace-inclusion decision
table. See [firmware-plan-techo.md](firmware-plan-techo.md) and
[firmware-plan-wio-tracker-l1.md](firmware-plan-wio-tracker-l1.md)
for the phasing precedent this plan adapts.

## Why this device, why now

- **First proof that UMSH's layering survives a chip change.**
  Everything above the BSP line — `umsh-mac`, `umsh-node`,
  `umsh-companion-ncp`, `umsh-radio-loraphy`, `umsh-ux-tracker`,
  HDLC framing, the CRP session — is supposed to be chip-agnostic.
  Until a second architecture exists, that's a claim, not a fact.
- **First SX127x radio.** `umsh-radio-loraphy` is generic over
  `lora_phy::RadioKind`, and the local `../lora-rs` checkout ships an
  `sx127x` driver (`sx1276.rs`, `sx1272.rs`). This board turns the
  "any lora-phy chip works" claim into tested reality.
- **Paves the road to the T-Lora Pager.** The
  [LilyGO T-Lora Pager](lilygo-t-lora-pager-hardware.md) is
  ESP32-S3-based; the toolchain, `esp-hal`/embassy integration,
  BLE-controller work, and flash-storage backend built here carry
  over nearly wholesale.
- **Unbrickable.** The ESP32 ROM serial bootloader (via the CP2102,
  with DTR/RTS auto-entry) cannot be overwritten by application
  firmware. Bring-up risk is lower than any nRF board we've done.

## Hardware deltas vs. the nRF fleet (what actually changes)

| Concern | nRF52840 boards | Heltec V2 |
|---|---|---|
| MCU / toolchain | Cortex-M4F, stock Rust | Xtensa LX6, **`espup` Rust fork required** |
| Radio | SX1262 / LR1110 (BUSY + DIO1) | SX1276/78 (no BUSY; discrete DIO0/DIO1, RF switch radio-driven) |
| BLE controller | `nrf-sdc` + `nrf-mpsl` | `esp-radio` (esp-wifi) HCI controller + `trouble-host` |
| Host link | native USB CDC-ACM | **no native USB** — CP2102 UART bridge on UART0 |
| Flash / boot | UF2 bootloader, `memory.x`, GPREGRET DFU | esptool/espflash, partition table, GPIO0 strap |
| Storage | `sequential-storage` on NVMC | `sequential-storage` on `esp-storage` (SPI NOR data partition) |
| RNG | always-on TRNG (`Nrf52840Rng`) | HW RNG **only truly random while RF subsystem is enabled** |
| Power off | System OFF (~µA) | none — deep sleep only, board floor ≈ 800 µA |
| Display | SSD1681 e-paper / SH1106 | SSD1306 128×64 I²C, powered from switchable `Vext` |

## Workspace placement

Per the decision table in
[firmware-architecture.md](firmware-architecture.md): classic ESP32
requires the Xtensa Rust fork via `espup`, and the root
`rust-toolchain.toml` can't be two things → **exclude**. New sibling
workspace:

```
firmware-esp32/
  rust-toolchain.toml        # channel = "esp"
  Cargo.toml                 # its own [workspace] + Cargo.lock
  crates/
    umsh-bsp-esp32/          # chip BSP (features: esp32, later esp32s3)
    umsh-bsp-heltec-lora32-v2/
  firmware/
    hello-heltec-v2/         # Phase 0–2 bringup binary
    ble-spike-heltec-v2/     # Phase 4 spike (mirrors ble-spike-techo)
    companion-ncp-heltec-v2/ # Phase 5 deliverable
```

Notes:

- Shared crates (`umsh-hal`, `umsh-mac`, `umsh-radio-loraphy`,
  `umsh-companion-ncp`, `umsh-ux-tracker`, …) come in as path deps
  (`../crates/...`). The `[patch.crates-io]` for
  `lora-phy`/`lora-modulation` → `../../lora-rs` and the audited
  `trouble-host` fork must be **replicated** in this workspace's root
  manifest (patches don't cross workspace boundaries).
- The BSP crates live in the sibling workspace, not `crates/`, so
  esp-hal's embassy-driver version constraints never enter the root
  `Cargo.lock`. Cost: they aren't host-checked by root-workspace CI;
  acceptable while there's one consumer. Revisit if pure-logic code
  accumulates in them (it shouldn't — that belongs in `umsh-ux-*`).
- `umsh-bsp-esp32` mirrors esp-hal's chip feature-gating
  (`esp32` now, `esp32s3` when the Pager lands) so the chip-generic
  parts — storage backend, RNG wrapper, deep-sleep helper, panic
  capture — are written once.
- Target triple `xtensa-esp32-none-elf`; per-firmware
  `.cargo/config.toml` with an `espflash`-based runner. Makefile gets
  `build-*`/`flash-*` targets that `cd` into the firmware crate
  (same pattern and same reason as the nRF targets) and drive
  `espflash` over the CP2102 port instead of `scripts/flash.py`/UF2.

## Version-pinning spike (do this before believing the plan)

The single most version-sensitive unknown is the stack
**esp-hal + esp-hal-embassy + esp-radio (BLE) + trouble-host on
classic ESP32/Xtensa**. esp-radio has a scheduler requirement
(esp-preempt/esp-rtos lineage) whose interaction with the embassy
executor has churned across releases, and our `trouble-host` is a
pinned audited fork. Phase 0 therefore starts with a
throwaway spike that compiles and runs: embassy executor + one timer
task + esp-radio BLE advertising via `bt-hci` `ExternalController` +
trouble. Whatever exact versions that spike proves are the versions
the whole plan pins. If trouble's fork rev predates the
`ExternalController` seam it needs, that fork-rebase work surfaces
here, not in Phase 4.

## Scope (in / out)

**In scope** (end state, after all phases):

- `companion-ncp-heltec-v2`: full CRP companion radio, reachable over
  **BLE** (CompanionService GATT, pairing/bonding) and over the
  CP2102 **UART** (HDLC-framed, replacing USB-CDC),
- on-board device node (identity journal, counters, duty ledger) as
  on the nRF NCP firmware,
- SSD1306 status UI + single button + LED via `umsh-ux-tracker`,
- battery telemetry (GPIO13 ADC ÷3.2 divider) surfaced through
  CAP_BATTERY,
- deep-sleep-based `PowerControl` with button wake.

**Out of scope:**

- Wi-Fi, in any form. BLE-only radio coexistence.
- OTA/app-partition update schemes. `espflash` over the CP2102 is
  the only update path for now (the ROM loader makes this safe).
- The 433 MHz SX1278 variant. Plan targets the 863–928 MHz SX1276
  board; the low-band variant should only need modulation params.
- Precision battery gauging. ESP32 ADC nonlinearity means we ship
  coarse buckets (the `umsh-ux-tracker::battery` classifier), not
  calibrated percentages.
- The optional 32.768 kHz crystal (GPIO32/33). Assume unpopulated;
  use the internal RC for RTC timekeeping unless bring-up proves
  otherwise.

## Phases

### Phase 0 — toolchain, hello, safety floor

- `espup` toolchain install documented in the workspace README;
  sibling workspace scaffolded as above.
- `hello-heltec-v2`: embassy executor up, heartbeat blink on GPIO25,
  log banner (git describe) on UART0.
- RWDT watchdog armed, petted by the heartbeat task (same 8 s / 2 s
  posture as nRF).
- Panic capture: panic message into RTC slow RAM (survives reset,
  analog of `panic_persist.rs`), reported on next boot over UART0.
- The version-pinning spike (above) runs inside this phase.
- **No rescue machinery needed.** There is no UF2/1200-baud/GPREGRET
  equivalent to port — `espflash` + DTR/RTS auto-download-mode is
  the rescue path, and firmware can't break it.
- Boot-strap discipline: GPIO0/2/5/12/15 are strapping pins; the BSP
  must not reconfigure them before boot completes beyond what the
  hardware doc's §14 sequence prescribes (GPIO12 especially).

Exit: board blinks, prints, survives panic + WDT reset, reflashables
in one `make flash-hello-heltec-v2`.

### Phase 1 — board I/O

- `Vext` control (GPIO21, active high) as an owned BSP primitive —
  it gates **both** the OLED supply and the battery divider, so it
  must be a shared handle, not two independent pins.
- SSD1306 via the `ssd1306` crate (I²C SDA=4, SCL=15, addr 0x3C,
  reset GPIO16, full Vext-up → reset-pulse → init sequence from
  hardware doc §5.3; re-init required after any Vext power cycle).
  UI code stays `embedded-graphics` `DrawTarget`-shaped, matching
  the T-Echo/Wio precedent — no new display abstraction.
- Button GPIO0 (active low, external pull-up) through
  `umsh_ux_tracker::button::ButtonFsm`; LED GPIO25 (active high)
  through `LedEngine`.
- Battery: enable GPIO21, settle, multi-sample GPIO13, ×3.2,
  `umsh_ux_tracker::battery` classification. GPIO13 is ADC2 — the
  documented conflict is with **Wi-Fi**, which we never enable, but
  Phase 4 must re-verify that the BLE controller leaves ADC2 usable;
  fallback is sample-before-radio-init at boot plus
  sample-on-request gaps, and CAP_BATTERY is already
  single-snapshot sample-on-request, so the protocol shape absorbs
  this.

Exit: banner + battery bucket on OLED, button/LED behave, Vext
off/on round-trip re-inits the display.

### Phase 2 — SX1276 on the air

- Wire `lora_phy::sx127x` (Sx1276 variant) from `../lora-rs`:
  SPI SCK=5/MOSI=27/MISO=19/NSS=18, reset GPIO14, DIO0=26 as the
  `await_irq` pin (GPIO35/DIO1 input-only, wire but treat as spare).
  SX127x has no BUSY pin and the board's RF switch is driven by the
  radio's RXTX output, so `wait_on_busy`/`enable_rf_switch_*` are
  no-ops in the `InterfaceVariant`.
- Verify `RegVersion == 0x12` on boot; surface on OLED/UART.
- PA_BOOST path, OCP 120 mA, start at low TX power.
- **Sync-word mapping check:** `meshcore_us_params` carries the
  SX126x-encoded sync word 0x1424; the SX127x register takes the
  single-byte form (0x12). Verify what `ncp_runner`/`runner` hand to
  `init_lora` for an sx127x `RadioKind` and add the mapping if the
  driver doesn't already do it. Wrong sync word here fails silently
  as "no packets", so do this before blaming RF.
- Acceptance mirrors T-Echo Phase 5: MeshCore US listener with
  packet count on the OLED, then a `umsh-radio-loraphy` `runner`
  exchanging UMSH frames with a T-Echo.

Exit: authenticated UMSH RX/TX against an nRF board, counts on
screen.

### Phase 3 — Platform impl, storage, MAC over UART

- **Refactor (root workspace, before the port):** lift the
  `sequential-storage` map logic out of
  `umsh-bsp-nrf52840::flash_store` into a chip-agnostic module
  generic over `embedded_storage_async::nor_flash::NorFlash`
  (same key schema: `id.sk`, `peer:`, `ch:`, `mac.tx/rx:`,
  `ux.tracker`). nRF keeps thin aliases; behavior on existing boards
  must not change.
- Back it with `esp-storage` over a dedicated 64 KB data partition
  declared in the espflash partition table (8 MiB flash leaves
  ample room; partition table replaces the `memory.x` +
  hand-pinned-address scheme, which is strictly an improvement).
  Note the same executor-stall caveat as NVMC: esp-storage
  suspends flash cache during writes; keep writes batched exactly as
  the MAC already does (`COUNTER_PERSIST_BLOCK_SIZE`).
- **RNG policy:** the ESP32 `RNG_DATA` register is only true-random
  while the RF subsystem is clocked. Per the no-non-crypto-RNG rule,
  the BSP's `CryptoRng` must be constructible only after esp-radio
  init (type-state or runtime assert), and identity generation
  happens strictly after that point. Until Phase 4 lands, bringup
  binaries enable the RF clock solely to harvest entropy, or defer
  identity work.
- `HeltecV2Platform` / `HeltecV2Mac`: `SoftwareAes/Sha/Identity`,
  `embassy_time::Delay`, embassy `Clock`, the new store views,
  `LoraphyRadio` — same shape as `TechoPlatform`.
- CLI firmware milestone: `umsh-cli` session over **UART0** with
  HDLC framing where the nRF boards use USB-CDC (`umsh-companion`'s
  HDLC is transport-agnostic). ROM-bootloader boot text precedes
  firmware output on UART0; HDLC resync handles it, but the host
  tooling must tolerate leading garbage.

Exit: persistent identity + counters across reboot, CLI parity with
`companion-cli-wio-tracker-l1`.

### Phase 4 — BLE

- Promote the Phase 0 spike into `ble-spike-heltec-v2`:
  esp-radio BLE controller → `bt-hci` `ExternalController` →
  `trouble-host`, advertising + connectable GATT echo.
- **Refactor (root workspace):** `proto_store.rs` / `ble_store.rs` /
  `counter_map.rs` journals currently write through
  `nrf_mpsl::Flash`; make them generic over `NorFlash` (the MPSL
  flash type already implements it) so bond/identity/counter
  journals are portable. Again: techo/t1000e behavior unchanged.
- Port the `CompanionService` GATT definition (`frame_in` write /
  `frame_out` notify, encrypted) and `ble_security.rs` pairing
  policy verbatim — they are trouble-level, not controller-level.
  ESP32 is BLE 4.2: LESC is supported; verify the pairing UX
  (PIN display on OLED) against `umsh-companionctl`.
- No MPSL means no MPSL-coordinated flash: BLE and `esp-storage`
  writes contend for the flash cache instead. Keep journal writes
  short and off the hot path; measure connection stability during
  writes (this is the Phase 4 equivalent of the nRF 85 ms-stall
  lore).
- Re-verify ADC2 battery sampling with the controller live.

Exit: `umsh-companionctl` attaches over BLE (attach_existing),
bonded, surviving reconnects, with the radio listener still running.

### Phase 5 — companion NCP

- **Refactor (root workspace):** the NCP binary logic lives in
  `firmware/companion-ncp-techo/src/main.rs` (~3.9 k lines) with
  board `#[cfg]`s — it cannot be shared across a workspace boundary
  as-is. Extract the transport/board-agnostic modules
  (`counter_map`, `duty_gate`, `transport_policy`, `radio_mux`,
  `device_node` glue, the now-generic journals) into a shared crate
  (working name `umsh-companion-ncp-fw`), leaving the nRF main as
  wiring. This is the largest refactor in the plan and the nRF NCP
  firmware must pass its existing hardware acceptance afterward
  **before** the ESP32 port consumes the crate.
- `companion-ncp-heltec-v2` main: heartbeat, `ncp_runner` with the
  SX1276, BLE app task, UART session task (in place of the USB
  tasks), device node bring-up, OLED/button/LED UI tasks.
- Acceptance: the increment-9-style matrix against a T-Echo peer —
  delegated acks, coalescing, overflow, lossless drain — over both
  BLE and UART attach; `umsh-companionctl` full command sweep.

Exit: feature parity with `companion-ncp-t1000e` minus
board-specifics (no buzzer, no GNSS), hardware-proven.

### Phase 6 — power posture

- `PowerControl::request_power_off` maps to ESP32 **deep sleep**
  (there is no hard off): radio to sleep mode, OLED off + GPIO16
  low, Vext low, counters/journals flushed, BLE controller deinit,
  wake on EXT0 (GPIO0 low).
- Wake pins and pulls configured explicitly per hardware doc §13.2;
  measure actual sleep current and record it (expect the ~800 µA
  board floor, i.e. "days, not months" — this is a documented board
  property, not a firmware bug to chase).
- Brownout behavior on battery: verify the protected-cell assumption
  and the boot behavior at low VBAT; there is no fuel gauge and no
  charger telemetry, so the UX truthfully shows voltage-derived
  buckets only.

## Risks, ranked

1. **esp-radio + embassy + trouble version lattice** (mitigated by
   the Phase 0 spike; everything else waits on its pins).
2. **NCP main.rs extraction** — big refactor with two working
   hardware targets that must not regress (mitigated: land it in the
   root workspace with nRF acceptance re-run before the port uses
   it).
3. **SX127x driver maturity in lora-phy** — sx126x/lr1110 paths are
   battle-tested here; sx127x is not. Sync-word encoding, IRQ-mask
   handling, and CAD behavior (`CadPolicy` in `TxOptions`) all need
   explicit verification.
4. **RNG entropy gating** — easy to get silently wrong; enforce
   "no CryptoRng before RF init" in the type system, not in prose.
5. **Flash-write vs BLE latency without MPSL** — measure early in
   Phase 4.
6. **ADC2 availability under BLE** — fallback already designed
   (boot-time + on-request sampling).
7. **Clone-board variance** (OLED address, charge current, crystal
   population) — bring-up checklist in the hardware doc §16 covers
   it; firmware fails soft when the OLED probe misses.

## Open questions (decide before the relevant phase, not now)

- Whether `umsh-bsp-esp32` should eventually host-compile-check in
  root CI via a stub feature, or whether sibling-workspace CI is
  enough.
- Whether the UART companion transport should reuse the exact
  USB-CDC session framing or grow a distinct transport id in the
  CRP dev/host state domains.
- Whether the T-Lora Pager port (ESP32-S3, native USB!) should jump
  the queue after Phase 4, since it removes the UART awkwardness and
  shares everything else.
