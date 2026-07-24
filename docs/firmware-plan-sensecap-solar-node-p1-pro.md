# SenseCAP Solar Node P1-Pro Bringup Firmware Plan

The fourth `nRF52840 + SX1262`-class board, riding on everything proved
out on the T-Echo, Wio Tracker L1, and T1000-E. The motivation is
different from the earlier bringups: this is the first **solar-autonomous
outdoor router-class node**. The end state is not a bench toy — it is a
`companion-ncp` build acting as an always-on autonomous UMSH device node
(beacon, duty ledger, Advertisement/Identity Request responder) on a roof
or pole, recharging itself.

See [sensecap-solar-node-p1-pro-hardware.md](sensecap-solar-node-p1-pro-hardware.md)
for the hardware reconstruction. See
[firmware-plan-wio-tracker-l1.md](firmware-plan-wio-tracker-l1.md) for the
closest precedent (same MCU, same radio chip, same Seeed UF2 bootloader
family, external RXEN). See
[firmware-architecture.md](firmware-architecture.md) for the BSP / UX /
App / Binary layering.

## Why this device

- **Same MCU + radio pipeline as three proven boards.** nRF52840 +
  SX1262 over `lora-phy` `GenericSx126xInterfaceVariant` — the radio
  path is byte-for-byte the Wio Tracker L1 configuration (external
  RXEN, DIO2-as-RF-switch, DIO3 TCXO at 1.8 V) on different pins.
- **First permanently-deployed node.** Everything so far has been a
  handheld/bench device. The P1-Pro's 4×18650 pack + 5 W panel +
  IPX6 enclosure make it the first device where the *autonomous
  device-node* work (beacon, duty ledger, System OFF recovery)
  earns its keep unattended.
- **Recoverable.** XIAO nRF52840 Plus with the Seeed UF2 bootloader;
  USB-C is accessible. Same double-tap-reset / 1200-baud-touch /
  UF2-drag recovery posture as the Wio Tracker.
- **Exercises the low-battery story for real.** The T1000-E has
  battery monitoring; this board *needs* the full loop — protective
  System OFF, LPCOMP solar-recovery wake, dawn-cycling hysteresis —
  because nobody is there to push a button.

## Naming

MeshCore calls the variant `sensecap_solar`; we follow suit with the
short board name **`sensecap-solar`** (the BSP covers the P1 and
P1-Pro, which are believed to differ only in GNSS module and battery
pack — open question 16 in the hardware doc):

```
crates/umsh-bsp-sensecap-solar/        board BSP
firmware/companion-cli-sensecap-solar/ bringup + CLI binary
firmware/companion-ncp-sensecap-solar/ the real deliverable (later phase)
```

Workspace `members` adds all three; `default-members` adds only the
BSP crate (same pattern as the other boards — firmware binaries build
from their own directory so `.cargo/config.toml` applies).

## Pin map (resolved)

The hardware reconstruction left logical pins 11, 12, 20, and 21–26
unresolved to physical GPIOs. Meshtastic's
`variants/nrf52840/seeed_solar_node/variant.cpp` `g_ADigitalPinMap`
resolves them. Combined map, in the neutral naming from the hardware
doc:

| Const | Logical | nRF pin | Notes |
|---|---:|---|---|
| `GNSS_STANDBY_OR_WAKE` | 0 | P0.02 | polarity unverified |
| `RADIO_DIO1` | 1 | P0.03 | |
| `RADIO_RESET` | 2 | P0.28 | |
| `RADIO_BUSY` | 3 | P0.29 | |
| `RADIO_CS` | 4 | P0.04 | |
| `RADIO_RXEN` | 5 | P0.05 | drive LOW at boot, then `rf_switch_rx` |
| `GNSS_UART_TX` | 6 | P1.11 | MCU TX → L76K RX |
| `GNSS_UART_RX` | 7 | P1.12 | MCU RX ← L76K TX, NMEA 9600 |
| `SPI_SCK` | 8 | P1.13 | radio SPI |
| `SPI_MISO` | 9 | P1.14 | radio SPI |
| `SPI_MOSI` | 10 | P1.15 | radio SPI |
| `LED_A` | 11 | **P0.15** | "User LED" — **white, active-high** (confirmed 2026-07-23) |
| `LED_B` | 12 | **P0.19** | "Breathing LED" — **blue, active-high** (confirmed); MeshCore uses it as TX LED |
| `USER_BUTTON` | 13 | P1.01 | active-low, use internal pull-up |
| `GROVE_SDA` | 14 | P0.09 | NFC pin — NFCT must be off / UICR NFCPINS cleared for GPIO use |
| `GROVE_SCL` | 15 | P0.10 | NFC pin, ditto |
| `BATTERY_ADC` | 16 | P0.31 / AIN7 | |
| `GNSS_RESET_CANDIDATE` | 17 | P1.03 | leave as input until verified |
| `GNSS_ENABLE` | 18 | P1.05 | likely active-high, verify |
| `BATTERY_DIVIDER_ENABLE_N` | 19 | P0.14 | active-low per MeshCore, verify |
| `USER_BUTTON_2` | 20 | **P1.07** | second mechanical button (nothing capacitive on the board); presumed active-low, verify |
| QSPI SCK/CS/IO0–3 | 21–26 | P0.21, P0.25, P0.20, P0.24, P0.22, P0.23 | P25Q16H, reserved, unused (NV store is internal NVMC) |

Note the Meshtastic *comment* discrepancy the hardware doc flagged
(pin 12 "P1.15") is resolved: the actual pin map says P0.19; the
comment in `variant.h` was wrong, the one in `variant.cpp` is
self-consistent.

The BSP hard-codes `P0_xx`/`P1_xx` embassy-nrf pins directly; the
Arduino logical numbers appear only in doc comments.

## Hardware assumptions to verify in Phase 0

1. **Bootloader:** Seeed UF2 fork, product string `XIAO-BOOT`,
   USB `0x2886:0x0059`. Expected UF2 family ID **`0x28860059`**
   (Seeed convention: `VID << 16 | PID`, as proven on the Wio
   Tracker and T1000-E). **Confirm via `INFO_UF2.TXT`.**
2. **SoftDevice / layout:** S140 v7.3.0, app start `0x27000`,
   bootloader at `0xF4000`, settings at `0xFF000` — i.e. `memory.x`
   should be byte-identical to t1000e/wio-tracker-l1 (app
   `0x27000..0xE4000`, NV store `0xE4000..0xF4000`). Confirm app
   start from `INFO_UF2.TXT` before first flash.
3. **Bootloader volume name:** unknown (`XIAO-BOOT`? `SOLARNODE`?).
   Record for `scripts/flash.py`.
4. **Radio pins** as tabled above — strongly corroborated
   (MeshCore + Meshtastic agree), treat as confirmed.
5. **LED colors and polarity** on P0.15 / P0.19 — verify by toggling
   (Phase 1). Both firmwares say active-high.
6. **Battery divider gate polarity** (P0.14) — MeshCore says
   active-low; verify by watching the ADC respond (Phase 2).

If (1) or (2) turn out wrong, stop and re-derive from the actual
`INFO_UF2.TXT` before flashing anything.

## Scope (in / out)

**In scope** for this bringup program:

- USB-CDC + `CdcAcmRescue` + panic capture (chip BSP, unchanged),
- heartbeat + LED/button identification,
- calibrated battery measurement (SAADC + gated divider),
- SX1262 on this pin map, RX + TX at MeshCore US params,
- full companion-CLI app at parity with the other boards
  (persistent identity + counters in the standard NV region),
- companion-NCP build joining the shared NCP main.rs shape,
- low-battery System OFF + LPCOMP solar-recovery wake.

**Out of scope:**

- GNSS beyond power-off. The L76K needs net-new UART/NMEA plumbing
  (no board currently has any); it is **Phase 7, explicitly
  deferrable** — a solar router node doesn't need a fix to do its
  job. Until then GNSS is held powered-down (`GNSS_ENABLE`
  inactive) to save its quiescent draw.
- Grove connector — not initialized. (If used later, remember the
  NFC-pin caveat on P0.09/P0.10.)
- QSPI flash — reserved, untouched. NV storage stays on internal
  NVMC at `0xE4000..0xF4000` per the storage decision.
- Charger/solar introspection — the CN3165 is autonomous and
  exposes nothing; the red/green/yellow LEDs are hardware-driven.
  Firmware infers "charging likely" only from battery-voltage
  trend and (for USB) `POWER.usbregstatus`.
- PWR button (`P1.07`) UX beyond polarity verification — Phase 1
  confirmed it is the **"PWR"** button (soft, active-low), not a plain
  extra button. No power UX is wired to it in this bringup; the
  commanded-off / wake behavior is Phase 6 work.
- Temperature-qualified charging — impossible from firmware; the
  0–50 °C charge window is the hardware's problem (or an
  operational restriction). Documented, not implemented.

## Safety contract

Identical to the Wio Tracker / T1000-E:

1. Never write the bootloader region (`0xF4000`+) or MBR.
2. Never disable the WDT once started.
3. `bsp::enter_dfu_uf2()` and siblings are the only GPREGRET writers.
4. 1200-baud touch and `\x03\x03\x03dfu\r` escape both live below the
   CLI parser, structurally enforced by `CdcAcmRescue`.
5. Panics → `PanicSlot::capture` → `SCB::sys_reset()`; replayed over
   USB-CDC on next boot.
6. **Board-specific:** `RADIO_RXEN` (P0.05) is driven LOW before any
   radio init and stays low until lora-phy owns it. Pin 17
   (`GNSS_RESET_CANDIDATE`) is never driven — input only — until
   hardware characterization says otherwise. First TX at low power
   (−9 dBm bench convention);
   22 dBm only after current/power measurement (Phase 3 gate).

Unlike the Wio Tracker there IS a software power story here: the
enclosure power switch may cut power outright (unverified), but the
low-battery path must work without any human present, so System OFF +
LPCOMP is load-bearing (Phase 6).

## Phasing

Each phase ends in a flashable, demonstrable artifact. Bench-required
steps are marked 🔧.

### Phase 0 — Bootloader reconnaissance 🔧

Double-tap reset on a stock P1-Pro, mount the bootloader volume, read
`INFO_UF2.TXT`. Record:

- Board-ID / product string,
- SoftDevice version (expect S140 7.3.0),
- app start address (expect `0x27000`),
- UF2 family ID (expect `0x28860059`),
- volume mount name.

Then add the `sensecap-solar` preset to `scripts/flash.py` `BOARDS`
and the Makefile targets (`build-/flash-companion-cli-sensecap-solar`,
mirroring the wio ones, plus `.PHONY`).

Also confirm whether the unit ships with Meshtastic factory firmware
and whether anything must be preserved (expected answer: no — we
overwrite the app region, bootloader + SoftDevice stay).

**Gate:** `INFO_UF2.TXT` facts recorded; flash.py + Makefile entries
match reality.

### Phase 1 — Hello USB-CDC + safety primitives + GPIO identification 🔧

New workspace members:

- `crates/umsh-bsp-sensecap-solar/` — pin map + `platform.rs`
  (`SensecapSolarPlatform`, copy of `WioTrackerPlatform` verbatim:
  software crypto, `LoraphyRadio`, `EmbassyClock`, `Nrf52840Rng`,
  NVMC counter/KV stores) + `power.rs` stub.
- `firmware/companion-cli-sensecap-solar/` — binary, started as a
  stripped copy of `companion-cli-wio-tracker-l1` (no OLED — this
  board has no display; status goes over USB-CDC and the two LEDs):
  - `memory.x`: copy from t1000e (origin `0x27000`, 756K, NV region
    excluded),
  - `build.rs`, `panic.rs`, `.cargo/config.toml`: byte-for-byte,
  - USB IDs `0x2886:0x0059`, product string
    `"SenseCAP Solar Node Bringup"`.

Phase 1 firmware content: heartbeat on `LED_B`/P0.19 (the
"breathing" LED), CDC echo, `CdcAcmRescue`, panic replay, plus a
small interactive GPIO-identification mode over CDC:

- commands to toggle P0.15 and P0.19 individually → record which is
  blue, which is white, and polarity;
- report `USER_BUTTON` (P1.01, pull-up) edges;
- report `USER_BUTTON_2` (P1.07, pull-up) edges and confirm its
  polarity;
- `GNSS_ENABLE` held inactive, pin 17 never driven.

**Gate:** enumerates, echoes, blinks; LED color map and button
behavior recorded back into the hardware doc; rescue paths verified
(they're the same tested chip-BSP code, but this is the first boot on
this board — prove the escape hatch before anything ambitious).

**Phase 1 results (confirmed 2026-07-23, in-hand P1-Pro):**

- Firmware enumerates as VID 0x2886 / PID 0x0059, product
  "SenseCAP Solar Node Bringup"; CDC echo + `?`/`1`/`2`/`h` all work.
- **LED_A (P0.15) = white, active-high.** **LED_B (P0.19) = blue,
  active-high** (the heartbeat/breathing LED). Both lit when driven HIGH.
- **USER_BUTTON (P1.01) = active-low** (LOW pressed, HIGH released, on
  the internal pull-up).
- **P1.07 is the "PWR" button** — not a generic second button. Active-low
  (LOW pressed, HIGH released). It is a **soft momentary button**: the
  MCU kept running through the press, so PWR does *not* hard-cut the MCU
  rail. This partially answers open question 4 and is directly relevant
  to the Phase 6 power story (PWR likely drives commanded System OFF /
  wake, T1000-E-style). Note there may still be a separate hardware
  slide switch on the enclosure — not yet characterized.
- GNSS_ENABLE (P1.05) held low; P1.03 and the battery-divider gate
  (P0.14) left untouched, as designed.

### Phase 2 — Battery measurement + calibration 🔧

Port the T1000-E `run_battery_monitor` pattern
(`crates/umsh-bsp-t1000e/src/power.rs`) into
`umsh-bsp-sensecap-solar/src/power.rs` with this board's wiring:

- SAADC on AIN7/P0.31, 12-bit, internal 0.6 V ref, GAIN1_6 (known
  nRF configuration — deliberately *not* copying either the
  MeshCore 3.0×3.0 or Meshtastic 3.3×3.3 formula, which disagree
  by 21%);
- divider gate on P0.14, **active-low assumed**: drive low →
  ≥10 ms settle → sample → drive high (confirm the high state
  actually disconnects the divider by watching the ADC float/drop);
- calibration per the hardware doc procedure: multimeter vs ADC
  code at ~4.15 / 3.9 / 3.7 / 3.4 V, fit slope + offset, record the
  constants in the BSP with the measurement date;
- VBUS presence via `POWER.usbregstatus` (same as T1000-E);
- reuse `umsh_ux_tracker::battery::classify` + `LevelEstimator`
  with TX-load sag correction.

The consecutive-low-sample protective shutdown from the T1000-E
carries over but its threshold stays disarmed (log-only) until
Phase 6 establishes the calibrated shutdown/recovery pair.

**Gate:** calibrated `Vbattery = code × slope + offset` recorded;
divider gate polarity confirmed; divider quiescent current measured
(or bounded) in both gate states.

### Phase 3 — SX1262 radio 🔧

Byte-for-byte the Wio Tracker L1 radio bring-up on new pins. In
`main.rs`:

- SPI on TWISPI1 @ 16 MHz: SCK P1.13, MISO P1.14, MOSI P1.15,
  CS P0.04 (`ExclusiveDevice`);
- `GenericSx126xInterfaceVariant::new(reset=P0.28, dio1=P0.03,
  busy=P0.29, rf_switch_rx=Some(P0.05), rf_switch_tx=None)`;
- `Config { chip: Sx1262, tcxo_ctrl: Some(Ctrl1V8), use_dcdc: true,
  rx_boost: true }` — matches MeshCore's boosted-RX choice;
- RXEN driven LOW at boot before lora-phy takes it (Wio Tracker
  lesson: lora-phy toggles `rf_switch_rx` correctly on its own; the
  boot clamp just closes the init window);
- `meshcore_us_params(&mut lora)` so it can hear the existing bench
  fleet immediately;
- MeshCore's extra 10 ms post-reset settle before first radio use is
  cheap insurance — keep it.

TX power ladder: first TX at −9 dBm point-blank (bench convention),
verify against a T-Echo/T1000-E peer (peer promiscuous + warm-up TX,
per the Heltec bench notes), then step toward +22 dBm while watching
battery-bus sag with the Phase 2 monitor. MeshCore's 140 mA current
limit is a policy we can adopt if sag looks bad; note lora-phy's
default OCP and set explicitly if needed.

Optionally mirror MeshCore's use of `LED_B` as a TX blink — it's the
designated "mesh heartbeat" LED anyway.

**Gate:** RX counter advances on bench traffic; two-way UMSH frame
exchange with an existing node; 22 dBm TX verified within supply
sag limits (or backed off and the chosen limit recorded).

### Phase 4 — Companion-CLI parity

Bring the binary up to full `companion-cli-wio-tracker-l1` parity:
`Mac<SensecapSolarPlatform>` coordinator, persistent identity +
counter journal in the standard NV region, `umsh-app-companion-cli`
over USB-CDC. All of this is copy-adapt; nothing here is new
engineering. This is also where `companionctl` should work against
the board over serial.

**Gate:** provision/identity/save/restore/clear via `companionctl`
over USB serial; identity + counters survive reboot; bench node
exchanges authenticated frames.

### Phase 5 — Companion-NCP (the real deliverable)

`firmware/companion-ncp-sensecap-solar/` joining the shared NCP
main.rs shape (per the T-Echo/T1000-E unification — this is the
second test, after T1000-E, that the `NcpEnv` hook set is actually
board-portable). Board hooks:

- `sample_battery` → Phase 2 monitor (CAP_BATTERY single-snapshot);
- `request_attention`/`clear_attention` → `LED_A`;
- `note_transmit_load` → battery `LevelEstimator` sag correction;
- snapshot/identity/counters → standard NVMC regions;
- BLE attach with LESC/PIN pairing as on T1000-E. One wrinkle: no
  display, so the pairing PIN cannot be shown on-device. Options:
  fixed provisioned PIN set over USB during commissioning (PIN is
  already a companionctl-settable property), or accept
  Just-Works-grade pairing for this device class. **Decision
  needed at phase start; lean provisioned-PIN** — it exists
  already and a deployed roof node pairs rarely.

Device-node behavior (beacon, duty ledger, Advertisement Request
responder) comes along for free from the device-node milestone.

**Gate:** the standing NCP hardware gate (UART a–e, RF autonomy
matrix, BLE attach) passes on this board; iOS app connects, sees
CAP_BATTERY, exchanges traffic.

### Phase 6 — Low-battery System OFF + solar recovery 🔧

The board-specific power story, modeled on MeshCore's but with our
calibrated numbers:

- **User/commanded off:** radio sleep, GNSS off, LEDs off, divider
  gate high (disconnected), button (P1.01) armed low-level sense,
  System OFF.
- **Low-battery off:** as above, but divider gate left LOW and
  LPCOMP armed on AIN7 with the recovery threshold; button wake
  optional (include it — a human with a USB cable should always
  win).
- **Recovery boot policy:** on LPCOMP/button wake, re-measure with
  the calibrated Phase 2 path; require shutdown-threshold +
  recovery margin, sustained for N seconds, before starting the
  radio/NCP; otherwise return to System OFF. This is the
  dawn-cycling defense — a single comparator crossing under
  intermittent light must not boot-loop the node.
- Verify P0.31 remains LPCOMP-usable in System OFF and measure
  System OFF floor current with divider enabled vs disabled (the
  divider draw is the price of the recovery wake — quantify it
  against 4×3350 mAh).

Thresholds start conservative (shutdown near 3.3 V, recovery near
3.6–3.7 V calibrated) and are recorded in the BSP, not inlined.

Watch the post-DFU POWER-INTEN gotcha: the boot-time disarm in the
shared main covers it, and this board must go through the same path.

**Gate:** induced low-battery shutdown on the bench (adjustable
supply), unattended recovery on voltage rise, no boot cycling under a
slowly-ramped supply.

### Phase 7 — GNSS (deferred, net-new)

First UART NMEA GNSS in the codebase — no existing pattern to copy:

- UARTE on MCU TX P1.11 / RX P1.12 @ 9600, `GNSS_ENABLE` P1.05
  asserted (verify polarity — implied active-high), standby P0.02
  exercised per L76K datasheet, P1.03 held input unless reset proves
  necessary;
- minimal NMEA subset (RMC/GGA) into a `no_std` parser (evaluate
  `nmea0183`-class crates vs a small hand parser — decide when we
  get here);
- duty-cycled fixes (GNSS is the biggest optional load on the solar
  budget; a static node needs a position rarely — acquire, cache,
  power off);
- position feeds whatever the identity/advertisement layer wants
  (location encoding per the identity docs, including the
  location-privacy guidance).

**Gate:** NMEA sentences on P1.12 at 9600; a cached fix survives
GNSS power-off; measured energy per fix recorded.

## Build / flash recipe

Same two-command workflow as the other boards, pending Phase 0
confirmation of the family ID and volume name:

```
make build-companion-cli-sensecap-solar
make flash-companion-cli-sensecap-solar
```

`scripts/flash.py` preset (**confirmed Phase 0, 2026-07-23**):

| Aspect | Confirmed value |
|---|---|
| App base address | `0x00027000` (S140 v7.3.0 SD size) |
| UF2 family ID | **`0x28860044`** — from the on-device `CURRENT.UF2`; NOT VID:PID |
| SoftDevice | S140 v7.3.0 |
| Bootloader mount | **`/Volumes/SENSECAP`** |
| Bootloader | UF2 Bootloader 0.9.2-OTAFIX2.2-BP1.3 |
| Board-ID | `nRF52840-SeeedSenseCAPSolarP1-v1` (Model: "Seeed Solar Node P1") |

> **Family-ID gotcha:** the earlier guess `0x28860059` (VID<<16 | PID)
> was wrong. This board's bootloader uses `0x28860044`; a UF2 with the
> wrong family ID is silently ignored. The value was read directly from
> the family-ID field of the bootloader's own `CURRENT.UF2` dump. The
> stock app enumerates as VID 0x2886 / PID 0x0059 ("XIAO nRF52840"), and
> that PID is unrelated to the UF2 family ID.
>
> **Rescue-path note:** the stock factory app does **not** honor the
> Arduino 1200-baud-touch → DFU convention (a 1200-baud touch resets it
> but it reboots straight back into the app). Double-tap RESET reliably
> enters the bootloader (the bootloader itself watches for it). Our
> firmware's `CdcAcmRescue` restores the 1200-baud-touch and
> `\x03\x03\x03dfu\r` escape paths.

All the standing rules apply: release builds only, build from the
firmware directory (the Makefile `cd`s for you), UF2 via flash.py not
manual uf2conv, no shell redirection against `/dev/cu.usbmodem*`.

## Open questions

1. **P1 vs P1-Pro electrical identity** (hardware doc Q16) — the BSP
   assumes one pin map for both; revisit if a P1 (non-Pro) unit ever
   misbehaves.
2. **BLE pairing UX without a display** (Phase 5) — provisioned PIN
   vs Just-Works; lean provisioned-PIN.
3. **Grove power switching** — assumed always-on with the main rail;
   matters only if a Grove sensor is ever attached to a solar budget.
4. **Does the enclosure power switch cut the MCU rail outright?**
   Determines whether "user off" via System OFF is ever reachable in
   practice, or only the low-battery path matters.
5. **LPCOMP threshold granularity** — LPCOMP references are coarse
   (n/8 or n/16 of VDD); the exact recovery voltage depends on the
   divider ratio measured in Phase 2. May need to accept a wider
   recovery band than ideal.
