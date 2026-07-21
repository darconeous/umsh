# Heltec WiFi LoRa 32 V3 Firmware Plan

The successor port to the parked
[Heltec V2 effort](firmware-plan-heltec-lora32-v2.md): ESP32-S3FN8
(dual Xtensa LX7, 8 MiB in-package flash, no PSRAM) plus an SX1262
with a 32 MHz TCXO and an SSD1306 OLED. The device posture is
unchanged — a battery-powered tracker with a screen, ending at the
full **companion radio over BLE** (`companion-ncp` firmware class).

See [heltec-lora32-v3-hardware.md](heltec-lora32-v3-hardware.md) for
the hardware reference (§15 startup sequence, §16 suggested board
definition, §17 bring-up checklist, §18 known ambiguities). See
[firmware-architecture.md](firmware-architecture.md) for the BSP /
UX / App / Binary layering. The V2 plan is the direct structural
precedent; this plan states only what changes.

## Why this device, why now

- **The V2 effort is parked** (possibly defective only unit, no
  second unit to disambiguate) but proved out everything
  chip-generic: the `firmware-esp32` sibling workspace, the espup
  toolchain, the esp-hal git pin, the esp-rtos/embassy generation,
  the panic-capture/WDT safety floor, and the BSP layering. The V3
  inherits all of it and swaps only the chip feature and the board
  crate.
- **The radio risk goes away.** The SX1262 rejoins the
  battle-tested sx126x driver path used by the T-Echo — the exact
  driver, `InterfaceVariant` shape, and sync-word behavior that
  already exchange UMSH frames on hardware. None of the V2's sx127x
  archaeology applies.
- **Still paves the road to the T-Lora Pager.** The Pager is also
  ESP32-S3; the S3 target triple, esp-radio-on-S3 BLE work, and
  flash-storage backend built here carry over wholesale — more
  directly than the classic-ESP32 work would have.
- **Unbrickable**, same as V2: the ROM serial loader via the CP2102
  with DTR/RTS auto-entry cannot be overwritten by application
  firmware.

## Hardware deltas vs. the V2 (what actually changes)

| Concern | Heltec V2 (parked) | Heltec V3 |
|---|---|---|
| MCU / target | Xtensa LX6, `xtensa-esp32-none-elf` | Xtensa LX7, **`xtensa-esp32s3-none-elf`** (same espup toolchain) |
| Chip-rev floor | `ESP_HAL_CONFIG_MIN_CHIP_REVISION=100` required | not applicable — remove/scope the override |
| Radio | SX1276, no BUSY, RXTX-driven switch | **SX1262**: BUSY=13, DIO1=14, DIO2 RF switch, **DIO3 1.8 V TCXO**, reset GPIO12 |
| Radio driver | sx127x (freshly fixed, unproven on air) | sx126x — hardware-proven on T-Echo |
| SPI / control pins | SCK 5 / MOSI 27 / MISO 19 / NSS 18 | SCK 9 / MOSI 10 / MISO 11 / NSS 8 |
| OLED | SDA 4 / SCL 15 / reset 16 | SDA 17 / SCL 18 / reset 21 (still SSD1306 @ 0x3C, still Vext-powered) |
| `Vext` | GPIO21, **active high** | GPIO36, **ACTIVE LOW** |
| Button / LED | GPIO0 / GPIO25 | GPIO0 / GPIO35 (both same polarity as V2) |
| Battery ADC | GPIO13 on **ADC2** (radio conflict), ÷3.2, no cal scheme | GPIO1 on **ADC1** (no conflict), ÷4.9, S3 has esp-hal ADC calibration |
| Battery divider gate | shared with Vext | dedicated GPIO37, **polarity revision-dependent** (V3.2: high=on) |
| Flash | 8 MB external SPI NOR | 8 MiB in-package |
| Host link | CP2102 on UART0 (GPIO1/3) | CP2102 on UART0 (**GPIO43/44**); native USB present on 19/20 but not routed to the connector |
| Sleep floor | ≈ 800 µA board floor | < 10 µA claimed — deep sleep is actually worth engineering |

Everything else in the V2 delta table (espup toolchain, esp-radio +
trouble BLE, espflash + partition table, `sequential-storage` on
`esp-storage`, RF-gated TRNG, deep-sleep-only power model) is
unchanged and already proven or planned.

## Workspace placement

Extend the existing `firmware-esp32` sibling workspace — no new
workspace, no new toolchain:

```
firmware-esp32/
  crates/
    umsh-bsp-esp32/               # gains an `esp32s3` feature
    umsh-bsp-heltec-lora32-v2/    # stays, parked
    umsh-bsp-heltec-lora32-v3/    # new
  firmware/
    hello-heltec-v3/              # Phase 0–2 bringup binary
    ble-spike-heltec-v3/          # Phase 4 spike (if the V2 spike
                                  #   doesn't port trivially)
    companion-ncp-heltec-v3/      # Phase 5 deliverable
```

Notes:

- `umsh-bsp-esp32` was designed for this: chip-generic code (panic
  capture, RNG wrapper, storage backend, deep-sleep helper) grows
  `esp32s3` feature-gating mirroring esp-hal's. Anything that turns
  out to be chip-specific gets split, not `#[cfg]`-riddled.
- The existing `[patch.crates-io]` esp-hal-family git pin (rev
  `fbd054ad…`) already contains the esp32s3 support; the same rev
  must serve both chips. If the S3 needs a newer rev, the V2 crates
  move with it (they only need to keep compiling — the board is
  parked).
- The workspace `.cargo/config.toml` carries only chip-agnostic
  settings; every firmware (V2 and V3) selects its own target triple
  in a per-firmware `.cargo/config.toml` and must be built from
  inside its own directory. The V2's ancient-silicon
  `ESP_HAL_CONFIG_MIN_CHIP_REVISION = "100"` override lives only in
  the V2 firmware configs — the key is chip-agnostic and, left at
  workspace level, would reject typical ESP32-S3 silicon (rev v0.x;
  the esp-hal default floor is 0 for everything but classic esp32).
- Makefile gains `flash-hello-heltec-v3` etc., same
  cd-into-crate + espflash pattern, `ESPFLASH_PORT` override as
  before.

## Version-pinning spike (much smaller this time)

The V2 Phase 0 spike answered the hard question — esp-hal +
esp-rtos + esp-radio + bt-hci 0.9 + trouble-fork all coexist at the
pinned rev. The residual unknown is only **"does the same lattice
hold with the `esp32s3` features"**: LX7 codegen, esp-rtos
`start(timg0, sw_int)` on S3, and the S3 BLE controller through
`ExternalController`. Expected to be a compile-and-run check, not a
research project. Do it first anyway; if the pinned rev fails on
S3, moving the pin is a whole-workspace event and everything waits
on it.

## Scope (in / out)

**In scope** (end state): identical to the V2 plan —
`companion-ncp-heltec-v3` with CRP over BLE (CompanionService GATT,
pairing/bonding) and over the CP2102 UART (HDLC-framed), on-board
device node, SSD1306 + button + LED via `umsh-ux-tracker`,
CAP_BATTERY telemetry, deep-sleep `PowerControl` with button wake.

**Out of scope:**

- Wi-Fi, in any form. BLE-only radio coexistence.
- OTA/app-partition updates; espflash over the CP2102 is the update
  path.
- The LF (470–510 MHz) RF variant. Plan targets the HF board.
- Native-USB support (GPIO19/20). Not routed to the connector on
  stock boards; do not commit those pins, per hardware doc §13.3.
- Pre-V3.2 battery-divider polarity auto-detection. The BSP takes
  the revision as a build-time choice defaulting to **V3.2**
  (GPIO37 high = divider on); earlier revisions documented as
  unsupported until one shows up. (Hardware doc §11.6 sketches a
  probe strategy if this ever needs revisiting.)
- MeshCore's 80 MHz CPU-clock economy mode. Run at default clocks
  until Phase 6 measures whether it matters.

## Phases

### Phase 0 — port the safety floor

Nothing new is designed here; the V2 Phase 0 deliverables are
re-targeted:

- `umsh-bsp-esp32` gains the `esp32s3` feature; RTC-RAM panic
  capture, RWDT arming, and the software-reset path re-verified on
  S3 (RTC fast RAM persistence + `#[ram(unstable(rtc_fast,
  persistent))]` semantics should be identical; trust nothing until
  the PRG-button panic hook round-trips on hardware).
- `hello-heltec-v3`: embassy up via `#[esp_rtos::main]` +
  `esp_rtos::start`, heartbeat blink on GPIO35, banner on UART0
  (GPIO43/44 — expect ROM boot text ahead of it).
- The S3 spike (above) runs here, including BLE
  advertise/connect/pair from a phone if cheap to include.
- Strapping discipline per hardware doc §13.1: GPIO0 (button — same
  posture as V2), GPIO3/45/46 untouched by the BSP.
- Confirm 8 MiB flash detection and pick the partition table
  (app + 64 KB data partition for Phase 3, same as the V2 plan).

Exit: blinks, prints, survives panic + WDT reset, BLE spike
advertises, `make flash-hello-heltec-v3` works.

### Phase 1 — board I/O

- **`Vext` (GPIO36, ACTIVE LOW)** as the owned BSP primitive. The
  polarity is the single most likely V2-habit bug in this port —
  encode it inside `vext::Vext` so no caller ever sees the raw
  level. Note the board pull-up defaults Vext off until firmware
  drives the pin low (hardware doc §10.4).
- SSD1306 (I²C SDA=17, SCL=18, addr 0x3C, reset GPIO21): the V2
  BSP's `display` module ports with pin changes only — same
  Vext-up → settle → reset-pulse → init sequence (hardware doc
  §5.3), same re-init-after-Vext-cycle rule, same
  `embedded-graphics` `DrawTarget` shape.
- Button GPIO0 (active low) through `ButtonFsm`; LED GPIO35 (active
  high) through `LedEngine`. Quad-click panic hook and triple-click
  TX hook conventions carry over from the V2 hello.
- Battery (`BatterySampler`): drive GPIO37 **high** (V3.2), settle
  several ms, discard first conversion, median-of-N on GPIO1
  (ADC1 ch 0), ×4.9 nominal, then GPIO37 low to kill divider
  current (hardware doc §11.4). Use the esp-hal S3 ADC
  **calibration scheme** (curve-fitting) — a real improvement over
  the V2's uncalibrated nominal scale; still ship coarse buckets,
  not percentages. No radio-ownership conflict: ADC1 is free of the
  classic ADC2/RF entanglement, so the V2's
  sample-before-radio-init contortions are dropped.

Exit: banner + battery bucket on OLED, button/LED behave, Vext
off/on round-trip re-inits the display, GPIO37 verified in both
states with a multimeter on the divider.

### Phase 2 — SX1262 on the air

The T-Echo precedent applies almost verbatim; this is the phase the
V3 exists to de-risk.

- BSP `radio` module: `GenericSx126xInterfaceVariant` with SPI
  SCK=9 / MOSI=10 / MISO=11 / NSS=8, reset GPIO12, BUSY=13,
  DIO1=14. Unlike MeshCore (which declares reset unconnected —
  hardware doc §4.3 calls this driver policy, not hardware truth)
  we drive GPIO12 for a real reset pulse, then wait for BUSY low.
- sx126x `Config`: chip `Sx1262`, **TCXO control `Ctrl1V8` on
  DIO3** — this is mandatory, not tuning; a crystal-configured init
  will start flaky or not at all (hardware doc §4.7). DIO2 as RF
  switch control. `rx_boost` on (MeshCore parity). Respect the
  MeshCore reference current limit (140 mA) if the driver exposes
  it.
- No sync-word work: lora-phy's single-byte 0x12 expands to
  0x14/0x24 inside the sx126x driver (unit-tested in lora-rs);
  interop with both SX126x and LR11xx peers is proven.
- Start at low TX power (the 22 dBm MeshCore default is a ceiling,
  not a starting point); U.FL antenna attached before any TX.
- Acceptance mirrors T-Echo Phase 5 and reuses the V2 diagnostic
  habits where cheap: MeshCore US listener with packet count + RSSI
  on the OLED against the live local MeshCore traffic, then a
  `umsh-radio-loraphy` `runner` exchanging authenticated UMSH
  frames with the T-1000E/T-Echo. With the known-healthy driver
  path, on-air failure here points at the unit, not the software —
  the V2 register-dump/FEI toolkit exists in the repo history if it
  comes to that.

Exit: authenticated UMSH RX/TX against an nRF board, counts on
screen, RSSI/SNR sane at bench range.

### Phase 3 — Platform impl, storage, MAC over UART

Unchanged from the V2 plan except names; the two root-workspace
refactors it prescribes are still the actual work:

- Lift the `sequential-storage` map logic out of
  `umsh-bsp-nrf52840::flash_store` into a chip-agnostic module
  generic over `NorFlash`; back it with `esp-storage` on the 64 KB
  data partition. Same flash-cache-suspension caveat; keep writes
  batched as the MAC already does.
- RNG policy unchanged: the S3 TRNG is only true-random with the RF
  subsystem clocked — `CryptoRng` constructible only after
  esp-radio init, enforced in types.
- `HeltecV3Platform` / `HeltecV3Mac` in the T-Echo/V2 shape.
- CLI milestone: `umsh-cli` session over UART0 with HDLC framing;
  host tooling already tolerates ROM-loader leading garbage.

Exit: persistent identity + counters across reboot, CLI parity with
`companion-cli-wio-tracker-l1`.

### Phase 4 — BLE

As the V2 plan, S3 controller instead of classic:

- Promote the spike into `ble-spike-heltec-v3`; port
  `CompanionService` GATT + `ble_security.rs` pairing (PIN on OLED)
  verbatim — they are trouble-level.
- Root-workspace refactor: journals (`proto_store` / `ble_store` /
  `counter_map`) generic over `NorFlash`, nRF behavior unchanged.
- Measure BLE connection stability during flash writes (no MPSL
  arbitration; the esp-storage cache-suspension stall is the analog
  of the nRF 85 ms lore).
- Battery sampling under a live controller should be a non-issue on
  ADC1 — verify once and drop the V2's fallback machinery.

Exit: `umsh-companionctl` attaches over BLE (attach_existing),
bonded, surviving reconnects, radio listener still running.

### Phase 5 — companion NCP

Identical to the V2 plan: the big root-workspace extraction of the
board-agnostic NCP modules out of `companion-ncp-techo/src/main.rs`
into a shared crate (nRF hardware acceptance re-run **before** the
ESP32 port consumes it), then `companion-ncp-heltec-v3` wiring:
heartbeat, `ncp_runner` with the SX1262, BLE app task, UART session
task, device node, OLED/button/LED UI.

Acceptance: the increment-9-style matrix against an nRF peer —
delegated acks, coalescing, overflow, lossless drain — over both
BLE and UART attach; full `umsh-companionctl` sweep.

Exit: feature parity with `companion-ncp-t1000e` minus
board-specifics (no buzzer, no GNSS), hardware-proven.

### Phase 6 — power posture

Worth more effort than on the V2: the board claims a < 10 µA sleep
floor, so deep sleep can actually deliver tracker-grade battery
life instead of "days, not months".

- `PowerControl::request_power_off` → deep sleep with the hardware
  doc §14.2 shutdown ladder: SX1262 to (cold) sleep with TCXO off,
  IRQ routing disarmed, GPIO21 low, **GPIO36 high** (Vext off),
  GPIO37 low (divider off), LED off, BLE deinit, explicit wake-pin
  pulls, EXT wake on GPIO0 low.
- Choose SX1262 warm vs. cold sleep intentionally
  (latency-vs-current, hardware doc §14.4); cold is the default
  for a user-initiated "off".
- Measure actual sleep current at the battery connector with USB
  disconnected (the CP2102 is USB-powered and poisons the
  measurement otherwise). Record the number; the < 10 µA claim is
  configuration-dependent marketing until measured.
- Decide here whether the 80 MHz clock economy is worth adopting
  for the awake state.

## Risks, ranked

1. **The pinned esp-hal rev on esp32s3** — expected fine (same
   repo, same generation), but it gates everything; the Phase 0
   spike settles it in a day. Moving the pin drags the parked V2
   crates along.
2. **NCP main.rs extraction** (unchanged from V2 plan, Phase 5) —
   the largest refactor, with two working hardware targets that
   must not regress.
3. **Vext / GPIO37 polarity traps** — active-low Vext is the
   opposite of the V2 habit, and GPIO37 flips meaning across board
   revisions. Both are encoded once in the BSP and verified with a
   meter in Phase 1; the risk is a silent dark-OLED /
   nonsense-battery debug session if skipped.
4. **Flash-write vs. BLE latency without MPSL** — measure early in
   Phase 4.
5. **Board revision / clone variance** — charger, battery polarity,
   OLED address, RF matching (hardware doc §18.5–18.6). Identify
   the physical revision from silkscreen before Phase 1 and record
   it in the bring-up notes.
6. **TCXO misconfiguration masquerading as RF failure** — after the
   V2 experience, be deliberate: if Phase 2 RF looks sick, the
   *first* check is TCXO config and BUSY behavior, which the sx126x
   driver surfaces cleanly, before any unit-defect theorizing.

## Open questions (decide before the relevant phase, not now)

- ~~Whether the V2's `ESP_HAL_CONFIG_MIN_CHIP_REVISION` workspace
  env override affects esp32s3 builds~~ — settled in Phase 0: it
  does (the key is chip-agnostic), so the override moved into the
  V2 firmware configs and the workspace config is chip-neutral.
- ~~Whether `ble-spike-heltec-v3` is needed as a separate binary~~ —
  settled in Phase 0: separate binary; the V2 spike is board-generic
  except the LED pin and chip features, so a copy was cheaper than a
  feature switch.
- Whether the UART companion transport reuses the exact USB-CDC
  session framing or grows a distinct transport id in the CRP
  dev/host state domains (inherited verbatim from the V2 plan,
  still open).
- Whether the T-Lora Pager port should jump the queue after
  Phase 4 — it shares the S3 toolchain and BLE work and has native
  USB, removing the UART awkwardness.
