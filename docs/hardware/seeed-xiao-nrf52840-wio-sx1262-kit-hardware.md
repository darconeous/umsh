# Seeed Studio XIAO nRF52840 & Wio-SX1262 Kit Hardware Reconstruction

This document summarizes the hardware architecture, pinout, power behavior, and
firmware-relevant details of the Seeed Studio **XIAO nRF52840 & Wio-SX1262 Kit
for Meshtastic** (SKU 102010710).

It is intended to be both human-readable and useful as implementation context
for an automated coding agent adding UMSH support.

Unlike the other board documents in this directory, this one is **not** purely a
firmware-level reconstruction: Seeed publishes complete schematics for both
halves of the kit, and both were read directly for this document. Where a claim
is schematic-backed it is marked as such, and it overrides any firmware
definition that disagrees.

Sources, in decreasing authority:

1. `Wio-SX1262 for XIAO V1.0` schematic (Seeed, KiCad 8 plot)
2. `Seeed Studio XIAO nRF52840 v1.1` schematic (Seeed; the *Sense* drawing,
   which is a superset of the plain board)
3. Seeed's XIAO nRF52840 wiki, including its errata-grade FAQ entries
4. Meshtastic's `seeed_xiao_nrf52840_kit` variant
5. MeshCore's `xiao_nrf52` variant and board class

**Almost nothing here has been validated on hardware by this project.** Except
where a dated hardware note says otherwise, every "confirmed" below means
confirmed *against the schematic*, not confirmed on a bench.

A UMSH BSP and a shipping firmware image now exist — `crates/umsh-bsp-xiao-nrf52`
and `firmware/xiao-nrf52`, built from this document on 2026-08-03 — but **none of
it has been run on the board**. It compiles and packs to a UF2 whose family and
address extent are verified against the probe results below; everything past that
is the bring-up checklist at the end of this document, which is entirely open.
The build is deliberately headless (no button profile) and does not implement
GNSS, QSPI deep power-down, or the LPCOMP recovery wake.

Two schematic-versus-reality discrepancies **were** found by physical
inspection of a retail kit (2026-08-03), and they run in opposite directions:

- **K1, the user button on the radio carrier, is not populated, and neither is
  its R2 pull-up.** Both footprints are there and bare, so a user can add a
  button by hand — but `P0.02` has no external pull, and the internal one is
  mandatory for anyone who does.
- **U7, the 2 MB QSPI flash, *is* populated**, despite the schematic marking it
  `DNP`.

The lesson is that this drawing's `DNP` annotations carry no information in
either direction. Do not use them to predict what is on the board.

The **bootloader and flash layout were also read off a retail unit** the same
day, and they contradict what the upstream metadata implies — see
[Bootloader, SoftDevice, and flash layout](#bootloader-softdevice-and-flash-layout).
In short: the kit ships the *Sense* bootloader config (`XIAO-SENSE`, UF2 family
`0x28860045`), the app base is `0x27000`, and the UF2-writable window **ends at
`0xEA000`**, not `0xED000`.

## What is actually in the kit

| Item | Detail |
|---|---|
| Kit SKU | 102010710 |
| Controller | Seeed **XIAO nRF52840** (the plain board, SKU 5201 — *not* the Sense, and *not* the Plus) |
| Radio carrier | **Wio-SX1262 for XIAO** (standalone SKU 113010003) |
| GNSS | **Not included.** Seeed's L76K GNSS Module for XIAO (SKU 5864) is a separate purchase that stacks on the same header |
| Battery | Not included; connects to the XIAO's `BAT+`/`BAT-` pads |
| Pre-flashed firmware | Meshtastic |
| Kit dimensions | Seeed's own pages give both "21 × 17.8 mm" (the XIAO footprint) and "8 × 22 × 23 mm"; neither is a stack height, so treat both as approximate |

Seeed's specification table for the kit:

| Parameter | Value |
|---|---|
| MCU | Nordic nRF52840, Cortex-M4F, 64 MHz |
| Radio | Semtech SX1262, 862–930 MHz |
| Wireless | Bluetooth 5.0 / NFC |
| Input voltage | USB-C 5 V; battery 4.2 V |
| Battery charging current | 50 mA / 100 mA (firmware-selectable) |
| Standby power | < 5 µA |
| Operating temperature | −40 °C to 65 °C |
| Memory | 256 KB RAM, 1 MB internal flash, **2 MB external QSPI flash** |
| Onboard buttons | **Reset only.** Seeed's table refers to the XIAO; the radio carrier's user-button footprint ships unpopulated (see [Buttons](#buttons-and-wake-behavior)) |
| Onboard LEDs | one 3-in-one RGB user LED, one charge LED |

The two boards mate through the XIAO's standard 2×7 2.54 mm through-hole
header; the kit ships as two boards plus pin headers and is soldered by the
user. There is no board-to-board connector on this variant (that is the XIAO
ESP32S3 kit — see [Pinout variants](#pinout-variants-do-not-mix-them)).

## Relationship to the SenseCAP Solar Node P1-Pro

This is the most useful starting point for a UMSH port, because UMSH already has
a working BSP for the Solar Node (`crates/umsh-bsp-sensecap-solar`) and the two
designs share the same controller family and the same radio module.

**Identical between the two boards:**

- The `D0`–`D10` logical-to-physical pin map (both are XIAO-pinout boards):
  `P0.02, P0.03, P0.28, P0.29, P0.04, P0.05, P1.11, P1.12, P1.13, P1.14, P1.15`.
- The entire SX1262 pinout: NSS `D4`, DIO1 `D1`, RESET `D2`, BUSY `D3`,
  RXEN `D5`, SCK `D8`, MISO `D9`, MOSI `D10`; DIO2 as RF switch; DIO3 TCXO at
  1.8 V; no TXEN.
- Battery sensing: `P0.31`/AIN7 read through a gated 1 MΩ / 510 kΩ bridge whose
  low side is `P0.14`.
- GNSS UART: MCU TX `P1.11`, MCU RX `P1.12`, L76K at 9600 baud.
- S140 v7.3.0, application base `0x27000` (confirmed on both), bootloader
  settings at `0xFF000`.

**Different:**

| Area | XIAO kit | SenseCAP Solar Node P1-Pro |
|---|---|---|
| Controller module | XIAO nRF52840 | XIAO nRF52840 **Plus** (more pins broken out) |
| User LEDs | one common-anode RGB, **active-low**, `P0.26`/`P0.06`/`P0.30` | two discrete LEDs, **active-high**, `P0.15` (white) / `P0.19` (blue) |
| Buttons | one, on the radio carrier, `D0`/`P0.02` | two, `P1.01` (PWR) and `P1.07` (USR) |
| Charger | TI **BQ25100**, 50/100 mA, firmware-visible status and current select | **CN3165** solar charger, ~0.99 A, fully autonomous, no firmware interface |
| GNSS power | none — the L76K is permanently powered; only standby (`D0`) is controllable | `P1.05` GPS_EN, `P1.03` reset candidate |
| Grove / I²C | no Grove; I²C must be borrowed from `D6`/`D7` or the NFC pins | dedicated Grove on `P0.09`/`P0.10` |
| External flash | 2 MB P25Q16H QSPI, on the XIAO itself | 2 MB P25Q16H QSPI, on the XIAO itself (same) |
| UF2 family / DFU volume | **`0x28860045`** / `XIAO-SENSE` (Sense bootloader config on plain hardware) | `0x28860044` / `SENSECAP` |

**One correction that propagates back to the Solar Node BSP.** UMSH's
`umsh-bsp-sensecap-solar` uses `DIVIDER_MICRO = 10_631`, derived from MeshCore's
"1M, 512k divider bridge" comment. The Seeed schematic shows the low-side
resistor is **510 kΩ 1 %**, not 512 kΩ, and Meshtastic's variant agrees
(`R17=1M, R18=510k`). The correct nominal constant is therefore:

```text
VBAT_mV = raw * (3600 * 1510 / 510) / 4096 = raw * 10659 / 4096
```

That is +0.26 % against the current value — well inside 1 % resistor tolerance,
so it is not a bug, but the XIAO kit BSP should use 10 659 and the Solar Node
constant is worth revisiting if that board is ever bench-calibrated.

## Architecture overview

```text
                USB-C 5 V ──┐
                            v
                    +---------------+
                    | BQ25100       |──> BAT pads ──> 1S Li-ion (user supplied)
                    | 50/100 mA     |         │
                    | ISET: P0.13   |         │  1M / 510k gated divider
                    | ~CHG: P0.17   |         └──> P0.31 (AIN7), low side P0.14
                    +---------------+
                            │
                    +---------------+
                    | XIAO nRF52840 |
                    | 32.768 kHz XO |
                    | DC/DC fitted  |
                    | 2 MB QSPI     |
                    | RGB LED (A-C) |
                    | RESET (P0.18) |
                    +---------------+
                       │        │
        SPI + 5 GPIO   │        │  D6 (TX) / D7 (RX), unconnected on the carrier
                       v        v
            +----------------------+    +------------------+
            | Wio-SX1262 carrier   |    | L76K GNSS (opt.) |
            |  U1 Wio-SX1262       |    |  UART 9600       |
            |  K1 footprint -> D0  |    |  STANDBY -> D0   |
            |  (NOT POPULATED)     |    +------------------+
            +----------------------+
```

`D0` is the one contended net on this board — but only for someone who solders
the missing switch. As shipped there is no user button anywhere in the kit, and
`D0` belongs to the GNSS module alone. See
[D0 and the missing button](#d0-and-the-missing-button).

## Pinout variants — do not mix them

Meshtastic's `variant.h` supports four different pinouts behind preprocessor
flags. Only the first applies to this kit; the others exist for adjacent
products and for a legacy DIY build, and every one of them moves the radio.

| | NSS | DIO1 | BUSY | RESET | RXEN | Button | GNSS UART | I²C |
|---|---|---|---|---|---|---|---|---|
| **XIAO nRF52840 kit (this doc)** | D4 | D1 | D3 | D2 | D5 | D0 (footprint only) | D6/D7 | NFC pins (D30/D31) |
| XIAO kit, `_i2c` build | D4 | D1 | D3 | D2 | D5 | D0 (footprint only) | NFC pins | D6/D7 |
| Wio-SX1262 30-pin B2B (ESP32S3 kit) | D3 | D0 | D1 | D2 | D4 | D5 | D6/D7 | NFC pins |
| Legacy DIY `xiao_ble` (E22 etc.) | D0 | D1 | D2 | D3 | D7 | — | NFC pins | D4/D5 |

A UMSH image built for the wrong column will not talk to the radio at all, and
in the legacy case will drive `D0` (a net with a button to ground) as chip
select.

## Reconstructed pin map

Both firmware trees ship a `g_ADigitalPinMap` array, and the two arrays are
**byte-for-byte identical**. The schematic confirms every entry that is brought
out to a header. This table is therefore high-confidence throughout.

| Function on this kit | Arduino pin | nRF52840 pin | Source / notes |
|---|---:|---:|---|
| SX1262 DIO1 | 1 | `P0.03` | schematic J1.2; both firmwares |
| SX1262 RESET | 2 | `P0.28` | schematic J1.3; **10 kΩ pull-up to 3V3 on the carrier** |
| SX1262 BUSY | 3 | `P0.29` | schematic J1.4 |
| SX1262 NSS / CS | 4 | `P0.04` | schematic J1.5; 22 Ω series |
| SX1262 RXEN (`RF_SW1`) | 5 | `P0.05` | schematic J1.6; **no pull-up** |
| SPI SCK | 8 | `P1.13` | schematic J2.6; 22 Ω series |
| SPI MISO | 9 | `P1.14` | schematic J2.5; 22 Ω series |
| SPI MOSI | 10 | `P1.15` | schematic J2.4; 22 Ω series |
| GNSS standby / optional user button | 0 | `P0.02` | schematic: K1 to GND + R2 10 kΩ pull-up. **Neither is fitted on retail boards** — no external pull, internal pull-up required if used as an input |
| UART TX (to GNSS RX) | 6 | `P1.11` | not connected on the carrier; free |
| UART RX (from GNSS TX) | 7 | `P1.12` | not connected on the carrier; free |
| RGB LED — red | 11 | `P0.26` | schematic: common anode, 2.2 kΩ, **active-low** |
| RGB LED — blue | 12 | `P0.06` | schematic: common anode, 2.2 kΩ, **active-low** |
| RGB LED — green | 13 | `P0.30` | schematic: common anode, 10 kΩ, **active-low** |
| Battery divider low side (`READ_BAT`) | 14 | `P0.14` | **drive LOW or leave input; never drive HIGH** |
| IMU power (`6D_PWR`) | 15 | `P1.08` | Sense-only; absent on this kit |
| IMU I²C SCL | 16 | `P0.27` | Sense-only; absent on this kit |
| IMU I²C SDA | 17 | `P0.07` | Sense-only; absent on this kit |
| IMU INT1 | 18 | `P0.11` | Sense-only; absent on this kit |
| PDM mic power | 19 | `P1.10` | Sense-only; absent on this kit |
| PDM CLK | 20 | `P1.00` | Sense-only; absent on this kit |
| PDM DATA | 21 | `P0.16` | Sense-only; absent on this kit |
| Charge-current select (`HICHG`) | 22 | `P0.13` | LOW → 100 mA, HIGH/input → 50 mA |
| Charge status (`~CHG`) | 23 | `P0.17` | BQ25100 open-drain; LOW = charging. **Read only** |
| QSPI SCK | 24 | `P0.21` | reserved |
| QSPI CSN | 25 | `P0.25` | reserved |
| QSPI IO0 (DI) | 26 | `P0.20` | reserved |
| QSPI IO1 (DO) | 27 | `P0.24` | reserved |
| QSPI IO2 (WP) | 28 | `P0.22` | reserved |
| QSPI IO3 (HOLD) | 29 | `P0.23` | reserved |
| NFC1 | 30 | `P0.09` | NFC pad; GPIO use needs UICR `NFCPINS` cleared |
| NFC2 | 31 | `P0.10` | NFC pad; ditto |
| Battery ADC | 32 | `P0.31` / AIN7 | schematic `P0.31_AIN7_BAT` |
| RESET | — | `P0.18` | dedicated reset button K1 on the XIAO, 10 kΩ + 100 nF |
| LF crystal | — | `P0.00` / `P0.01` | 32.768 kHz, 10 pF loading caps |

Analog channel assignment from the schematic, in case ADC inputs are ever needed
on the header pins: `P0.02`=AIN0, `P0.03`=AIN1, `P0.04`=AIN2, `P0.05`=AIN3,
`P0.28`=AIN4, `P0.29`=AIN5, `P0.31`=AIN7. On this kit all of AIN1–AIN5 are
consumed by the radio, so only `D0` (AIN0) is even nominally free, and it is the
button.

### Two small errors in the upstream pin maps

- Meshtastic's `variant.cpp` comments `D32` as "P0.10 (VBAT)". The array value
  is `31`, which is correct; the comment is a copy-paste of the line above.
  MeshCore's identical array comments it correctly as `P0.31`.
- MeshCore's `variant.h` declares a second SPI bus at
  `PIN_SPI1_MISO (25) / PIN_SPI1_MOSI (26) / PIN_SPI1_SCK (29)`. Those logical
  pins are QSPI CSN, QSPI IO0 and QSPI IO3. The definitions are inherited from
  Seeed's stock variant and are inert as long as nothing instantiates SPI1, but
  a UMSH port must not treat them as a spare bus.

## LoRa radio

### Device and wiring

The radio is a Semtech SX1262 inside Seeed's `Wio-SX1262` module (U1 on the
carrier). From the carrier schematic:

| U1 pin | Signal | Net | Header | XIAO pin |
|---:|---|---|---|---|
| 1 | `RF_SW1` | `LORA_RF_SW1` | J1.6 | D5 / `P0.05` |
| 2 | `MISO` | `LORA_SPI_MISO` via R4 22 Ω 1 % | J2.5 | D9 / `P1.14` |
| 3 | `MOSI` | `LORA_SPI_MOSI` via R5 22 Ω 1 % | J2.4 | D10 / `P1.15` |
| 4 | `SCK` | `LORA_SPI_SCK` via R6 22 Ω 1 % | J2.6 | D8 / `P1.13` |
| 5 | `RST` | `LORA_RST`, **R1 10 kΩ pull-up to 3V3** | J1.3 | D2 / `P0.28` |
| 6 | `NSS` | `LORA_SPI_NSS` via R3 22 Ω 1 % | J1.5 | D4 / `P0.04` |
| 7 | `GND1` | GND | — | — |
| 8 | `VCC` | +3V3 (from the XIAO's 3V3 pin), 100 nF bulk | J2.3 | — |
| 9 | `ANT` | marked no-connect on the carrier — RF is handled inside the module | — | — |
| 10 | `GND2` | GND | — | — |
| 11 | `BUSY` | `LORA_BUSY` | J1.4 | D3 / `P0.29` |
| 12 | `DIO1` | `LORA_DIO1` | J1.2 | D1 / `P0.03` |

Header mapping, for anyone tracing the physical board: J1 is the XIAO's left
column (`D0, D1, D2, D3, D4, D5, D6`, with J1.7/`D6` unpopulated) and J2 is the
right column (`5V, GND, 3V3, D10, D9, D8, D7`, with J2.7/`D7` unpopulated).
**`D6` and `D7` carry no signal on the radio carrier** — they are the pins the
GNSS module or an I²C peripheral uses.

Two consequences worth designing around:

- **RESET idles released.** The 10 kΩ pull-up means the SX1262 comes out of
  reset on its own; a high-impedance MCU pin does not hold the radio down. UMSH
  should still drive RESET as a push-pull output and perform an explicit reset
  at init, but must not assume "pin not yet configured" equals "radio held in
  reset".
- **RXEN idles undefined.** There is no pull on `RF_SW1`. Before the MCU
  configures `P0.05` the RX path enable is floating, so configure it early and
  drive it deterministically.

The `ANT` no-connect means the carrier's schematic does not route an external
antenna; the RF output is on the module. Seeed advertises the kit as having "an
integrated antenna design". Whether the shipping carrier presents an IPEX/u.FL
connector or an on-board antenna should be confirmed by looking at the physical
board before any TX testing.

### RF-switch configuration

Both firmware trees configure the radio identically, and Seeed's module
documentation corroborates the TCXO arrangement:

- DIO2 as the TX-side RF-switch control (`SX126X_DIO2_AS_RF_SWITCH`)
- no TXEN GPIO (`SX126X_TXEN = RADIOLIB_NC`)
- a separate RX enable on `D5`
- DIO3 as the TCXO supply at **1.8 V**

MeshCore additionally sets, as policy rather than as hardware facts:

- current limit 140 mA (`SX126X_CURRENT_LIMIT`)
- boosted RX gain (`SX126X_RX_BOOSTED_GAIN`)
- maximum TX power 22 dBm (`LORA_TX_POWER`)
- the **red** LED (`P_LORA_TX_LED = 11`) as a transmit indicator, and a 10 ms
  settle delay in `begin()` before touching the radio

Meshtastic sets none of these explicitly for this variant.

### UMSH initialization order

1. Configure SPI (`P1.13`/`P1.14`/`P1.15`) and NSS (`P0.04`).
2. Configure DIO1 (`P0.03`), BUSY (`P0.29`), RESET (`P0.28`), RXEN (`P0.05`).
3. Drive RESET low, release, honor the SX1262 startup delay.
4. Configure DIO3 to supply 1.8 V to the TCXO, and allow TCXO startup.
5. Configure DIO2 as the RF-switch control. Leave TXEN unconnected.
6. Drive RXEN according to the module's expected receive state.
7. Start at a conservative current limit and verify 22 dBm against regional
   limits and the supply before trusting it — the kit is powered from a single
   cell through the XIAO's 3V3 regulator, and 22 dBm TX current is significant
   relative to that path.

The 22 Ω series resistors on the SPI lines are for signal integrity. They do not
change the protocol but they do add a pole with the trace/pin capacitance;
if SPI misbehaves above a few MHz, lower the clock before suspecting anything
else.

## D0 and the missing button

The Wio-SX1262 for XIAO schematic shows, on `D0` / `P0.02`:

- **K1**, a TS-1188E tactile switch, one pole to GND and one to `D0`
- **R2**, a 10 kΩ 5 % pull-up from `D0` to 3V3

**Neither part is populated on retail boards** (confirmed by inspection of a
kit, 2026-08-03). The switch footprint is present and bare and can be wired up
by hand; the pull-up is absent as well.

That combination has two consequences that shape everything below:

1. **`P0.02` has no external pull of any kind.** It idles floating, not high.
   Any UMSH build that treats it as an input — with or without a button
   fitted — must enable the **internal** pull-up. A floating input with the
   nRF52840's input buffer connected sits near mid-rail and burns current
   through the buffer, which on a board chasing a < 5 µA standby figure is not
   a rounding error. On a stock kit with no button and no GNSS, `P0.02` should
   be left as a **disconnected** input.
2. **`D0` is the designated user-button pin, optionally.** The footprint is
   there for exactly this purpose, so UMSH should treat "user button on
   `P0.02`, active-low, internal pull-up" as a supported board profile that
   users opt into with a soldering iron — not as something the firmware
   pretends exists.

So the contention Meshtastic warns about —

> the user button is activated on `D0`. The button conflicts with the official
> GNSS module, so caution is advised

— **does not exist on a stock kit**. `D0` is free, and it belongs to the L76K's
standby pin. The warning applies only to someone who solders the missing
switch, which the Meshtastic DIY variant's README actively encourages
("it's nice to be able to gracefully shutdown a node by holding it down for
5 seconds").

If K1 *is* fitted, the hazard is concrete: firmware driving `D0` high to bring
the GNSS out of standby, while the user presses the switch, shorts an MCU output
straight to ground. nRF52840 pins survive it — drive strength is limited — but
it is out of spec and it draws real current. In that configuration GNSS and the
button are mutually exclusive, and the choice must be build-time.

The two upstream firmwares already sit on opposite sides of that fork, and
neither is right for stock hardware:

- **Meshtastic (default kit build):** keeps GNSS, defines **no** `BUTTON_PIN`.
  This matches the shipping board exactly. `BUTTON_PIN D0` appears only in the
  `_i2c` build, which relocates GNSS to the NFC pins.
- **MeshCore:** drops GNSS entirely (`-UENV_INCLUDE_GPS`) and uses `D0` as
  `PIN_BUTTON1` / `PIN_USER_BTN` with `INPUT_PULLUP` and
  `USER_BTN_PRESSED = LOW`. On a stock kit **that button does not exist**, so
  MeshCore's hold-to-power-off gesture is unreachable and its System OFF has no
  armed wake source (see [Buttons](#buttons-and-wake-behavior)). Its runtime
  `INPUT_PULLUP` is right for a retrofitted switch; its System OFF arming is
  not — see below.

### What this costs UMSH

The kit as shipped has **no user input at all** beyond the XIAO's reset button.
Every UX pattern the other UMSH boards rely on is unavailable:

- no hold-to-power-off,
- no press-to-wake from System OFF,
- no hold-at-boot force-pairing ceremony (the T-1000E / Solar Node gesture),
- no single-button menu or acknowledgement input.

A UMSH build for this board must therefore be **headless**: configuration and
control come over USB-CDC (ULCP) or BLE, and any "power off" is either a reboot
or a one-way System OFF escapable only by reset or by attaching USB.

If a button is wanted, K1's footprint is the intended place for it, and `D0`
is clean through reset — the bootloader's own DFU inputs are `P0.18` (RESET)
and `P0.03`, not `P0.02` — so a hold-at-boot gesture would work on a modified
board. That should be an explicitly separate board profile, not the default.

## GNSS

The L76K GNSS Module for XIAO is a separate purchase. When fitted:

| Signal | XIAO pin | nRF52840 pin |
|---|---|---|
| MCU UART TX → GNSS RX | D6 | `P1.11` |
| MCU UART RX ← GNSS TX | D7 | `P1.12` |
| Standby / wake | D0 | `P0.02` (free on a stock kit — the button is unpopulated) |

Baud rate 9600; both firmwares use a 50 ms GNSS worker interval.

Unlike the SenseCAP Solar Node, **there is no GNSS power-enable and no GNSS
reset line on this kit**. The plain XIAO has no spare pins for them. The module
is powered whenever the 3V3 rail is up, and standby via `D0` is the only power
management available. A UMSH GNSS build must budget for the L76K's continuous
acquisition current, or drive standby aggressively and accept warm-start
latency.

### Serial direction naming

The SenseCAP Solar Node document warns at length about `GPS_TX` / `GPS_RX` alias
confusion. That ambiguity **does not exist here** — both trees agree and
Meshtastic comments the direction explicitly:

```c
#define GPS_TX_PIN D6 // This is data from the MCU
#define GPS_RX_PIN D7 // This is data from the GNSS module
#define PIN_SERIAL1_TX GPS_TX_PIN
#define PIN_SERIAL1_RX GPS_RX_PIN
```

and MeshCore's `PIN_SERIAL1_TX (6)` / `PIN_SERIAL1_RX (7)` matches. The Seeed
schematic settles it independently: the XIAO's own net names are
`P1.11_TX_D6` and `P1.12_RX_D7`, MCU-centric. Configure MCU TX on `P1.11` and
MCU RX on `P1.12`.

## Battery measurement

### Topology (schematic-confirmed)

```text
BAT ──[ R17  1 MΩ 1% ]──┬──[ R18  510 kΩ 1% ]── P0.14  (READ_BAT / low side)
                        │
                        └── P0.31 / AIN7      (ADC tap)
```

Divider ratio = (1 MΩ + 510 kΩ) / 510 kΩ = **2.9608**. Both firmwares round this
to 3.0 (+1.3 %); MeshCore's inline comment calls the low-side resistor "512k",
which is where UMSH's Solar Node constant came from.

### The P0.14 rule

The schematic carries an explicit instruction — *"Set P0.14 to output Sink only
to enable BAT voltage read"* — and Seeed's wiki FAQ (Q3) states the consequence:

> When P0.14 is set HIGH, the battery voltage reading path is disabled and P0.31
> may reach the input voltage limit of 3.6 V, posing a risk of damaging the
> P0.31 pin. To safely read battery voltage, set P0.14 LOW (to enable the
> reading path) and then read the ADC value on P0.31. We recommend that users
> always keep P0.14 set LOW when reading battery voltage, and avoid setting
> P0.14 HIGH during battery charging.

The arithmetic behind it: with `P0.14` driven to 3.3 V and a 4.2 V cell, the tap
sits at 3.3 + 0.9 × 510/1510 = **3.60 V**, exactly at the `VDD + 0.3` absolute
maximum. The current involved is under a microamp, so this is a
long-term-reliability concern rather than an instant failure, but it is Seeed's
own documented rule and UMSH should follow it.

**MeshCore complies.** It drives `VBAT_ENABLE` low in `initVariant()` and never
raises it during normal operation; `initiateShutdown` raises it only on a
user-requested (non-low-voltage) System OFF, when the cell is by definition not
being charged.

**Meshtastic does not.** `battery_adcDisable()` executes
`digitalWrite(ADC_CTRL, !ADC_CTRL_ENABLED)` — i.e. it drives `P0.14` **HIGH**
after every battery read, which is precisely the state Seeed says to avoid. This
is a genuine defect in the shipping Meshtastic build for this board, and UMSH
should not copy the gating pattern.

The cost of complying is small: with the divider permanently enabled the
quiescent draw is 4.2 V / 1.51 MΩ ≈ **2.8 µA**. That is not nothing against the
board's "< 5 µA standby" figure, so it is tempting to look for an "off" state —
but there isn't one. The three possibilities, for a 4.2 V cell at VDD = 3.3 V:

| `P0.14` state | Voltage at `P0.31` | Current | Verdict |
|---|---:|---:|---|
| driven LOW | 1.42 V | 2.8 µA | safe; the intended state |
| driven HIGH | 3.60 V | 0.6 µA | exactly at the `VDD + 0.3` absolute maximum; Seeed says don't |
| disconnected input | 4.2 V (clamps into the ESD diode) | ~0.3 µA | **worst** — well past absolute maximum |

High-Z is the intuitive "disconnect" and it is the wrong answer: with no path
through R18, the tap floats to the full cell voltage and is held down only by
`P0.31`'s protection diode. UMSH should keep `P0.14` **driven LOW at all
times**, exactly as Seeed instructs, and treat 2.8 µA as the price of the
design.

MeshCore's comment justifying the LOW state quotes "3 mA" of divider current.
That is off by a factor of 1000 (the network is 1.5 MΩ, not 1.5 kΩ) and its
inline voltage arithmetic does not evaluate to the number it states. The
conclusion is right; the numbers are not.

### ADC configuration — the two firmwares are consistent, not contradictory

The SenseCAP document flags a ~21 % scaling disagreement between the two
implementations. On *this* board there is no such conflict — each firmware pairs
its own reference constant with its own `analogReference()` call:

| | MeshCore | Meshtastic |
|---|---:|---:|
| Resolution | 12 bit | 10 bit (`BATTERY_SENSE_RESOLUTION_BITS`) |
| SAADC reference | `AR_INTERNAL_3_0` — 0.6 V ref, gain 1/5 → **3.0 V** full scale | never calls `analogReference()`; framework default `AR_INTERNAL` — 0.6 V ref, gain 1/6 → **3.6 V** full scale, matching `architecture.h`'s `AREF_VOLTAGE 3.6` |
| Multiplier | 3.0 | 3 |
| Result | `raw × 3.0 × 3.0 / 4.096` mV | `raw × 3 × (1000 × 3.6 / 1024)` mV |

Both read about **1.3 % high** — the error is the shared 3.0-vs-2.9608 divider
rounding, not any disagreement between the two implementations. A 4.20 V cell
reads 4.26 V under either. There is nothing to arbitrate.

### Recommended UMSH scaling

Use `embassy-nrf`'s default single-ended SAADC config (12-bit, `Gain1_6`, 0.6 V
internal reference → 3.6 V full scale), matching the existing Solar Node and
T-1000E BSPs:

```text
Vpin_mV = raw * 3600 / 4096
VBAT_mV = Vpin_mV * 1510 / 510
        = raw * (3600 * 1510 / 510) / 4096
        = raw * 10659 / 4096
```

A 4.2 V cell reads `raw ≈ 1614`; a 3.3 V cell reads `raw ≈ 1268`. Full-scale
3.6 V at the pin corresponds to 10.66 V at the cell, so there is enormous
headroom and no risk of clipping. Bench calibration should still be done before
the constant is trusted for a protective cutoff.

### Low-voltage protection

MeshCore's `NRF52_POWER_MANAGEMENT` support for this board defines:

- boot lockout at **3300 mV** (`PWRMGT_VOLTAGE_BOOTLOCK`) — refuses to boot
  below it
- LPCOMP input AIN7 / `P0.31` (`PWRMGT_LPCOMP_AIN 7`)
- LPCOMP reference selection `2` = 3/8 VDD (`PWRMGT_LPCOMP_REFSEL`)

With the true 2.9608 ratio, the 3/8-VDD threshold corresponds to a cell voltage
of VDD × 0.375 × 2.9608 — about **3.67 V at VDD = 3.3 V**, or 3.33 V at
VDD = 3.0 V. MeshCore's own comment estimates 3.38–3.71 V using the rounded
multiplier. Note the strong VDD dependence: this is a relative comparator, so
the recovery threshold moves with the rail.

The shutdown path is the standard one:

- **low-voltage / boot-protect off** — leave `P0.14` LOW (divider live), arm
  LPCOMP on AIN7, enter System OFF, wake when the cell recovers.
- **user-requested off** — `P0.14` HIGH, no LPCOMP, wake on the `D0` button.

That second case is the one place MeshCore does drive `P0.14` high. It is the
least-bad of the two non-LOW options (0.6 µA and exactly at the absolute
maximum, versus high-Z's 4.2 V on the pin), and no charge current is flowing —
but it is still outside Seeed's stated rule. A UMSH implementation that wants
the 2.8 µA back on a user-requested System OFF should treat it as a deliberate,
documented deviation, not as the default.

## Charging

The charger is a TI **BQ25100** (schematic reference U2). Seeed's specification
table names it "BQ25101" while linking the BQ25100 datasheet; Meshtastic's
variant comments say "BQ25101" and its pin-map comment says "BQ25100". Treat
BQ25100 as authoritative — that is what the schematic shows.

Firmware-visible interface:

**Charge current select — `P0.13` (D22, `HICHG`).** The ISET pin has a fixed
2.7 kΩ to ground plus a second 2.7 kΩ that `P0.13` can pull to ground. Driving
`P0.13` LOW puts the two in parallel (1.35 kΩ) and doubles the charge current.

| `P0.13` | ISET | Charge current |
|---|---|---|
| output LOW | 1.35 kΩ | 100 mA |
| output HIGH or input | 2.7 kΩ | 50 mA |

Both firmwares drive it LOW at init for 100 mA, and Seeed's wiki documents the
same convention. UMSH should make this a build/config choice keyed to the actual
cell — 100 mA is a sensible default for anything above ~500 mAh but is a 1C-plus
rate for a small cell.

**Charge status — `P0.17` (D23, `~CHG`).** The BQ25100's open-drain status
output. It shares a node with the red charge LED (3V3 → 2.2 kΩ → LED →
`P0.17`), so the LED and the MCU see the same signal.

- LOW → charging in progress (LED lit)
- HIGH → not charging, or charge complete

Meshtastic models this as `EXT_CHRG_DETECT (23)` with
`EXT_CHRG_DETECT_VALUE LOW`; MeshCore names the same pin `BAT_NOT_CHARGING (23)`
with the comment "LOW when charging". They agree.

`P0.17` must be configured as an **input only** — driving it fights the
charger's open-drain output and the LED. Note also that it cannot distinguish
"battery full" from "no input power"; combine it with the nRF52840's own VBUS
detection (`POWER->USBREGSTATUS`) to tell those apart, exactly as the Solar Node
BSP does.

**Temperature qualification: none.** The schematic ties the `TS` pin to VSS
through a fixed 10 kΩ with the note "NTC: Disable Temp sense function". There is
no battery thermistor, and firmware cannot inhibit charging on temperature.
Since the kit ships without a cell, the pack's own protection circuitry — if any
— is entirely the user's responsibility.

## LEDs

The XIAO carries **one common-anode RGB LED** (schematic reference RGB6) plus a
separate red charge LED that is not under MCU control.

| Color | Arduino pin | nRF52840 pin | Series resistor |
|---|---:|---:|---:|
| Red | 11 | `P0.26` | 2.2 kΩ |
| Blue | 12 | `P0.06` | 2.2 kΩ |
| Green | 13 | `P0.30` | 10 kΩ |

All three are **active-low** (`LED_STATE_ON = 0`): the common anode sits on 3V3,
so driving the pin low lights the segment. Seeed's wiki says the same in plain
language: "The LED turns ON when we give a LOW signal ... this LED is controlled
by a common anode."

This is the **opposite polarity** to the SenseCAP Solar Node's discrete
active-high LEDs, and it is an easy way to ship a board that appears
inverted-but-working.

There is no color-naming dispute on this board — both firmwares assign the same
three pins to the same three colors, and the schematic net names
(`P0.26_USER_RED`, `P0.06_USER_BLUE`, `P0.30_USER_GREEN`) confirm them. The one
wrinkle: Seeed's own pin table hedges blue as "13/12" and green as "12/13",
because the Seeed *mbed* core and the Adafruit core number them differently.
Both Meshtastic and MeshCore use the Adafruit numbering, which is the one that
matches `g_ADigitalPinMap`. A bare-metal UMSH port should ignore the logical
numbers entirely and use `P0.26` / `P0.06` / `P0.30`.

The 10 kΩ on green versus 2.2 kΩ on red and blue means green is markedly dimmer
at the same duty cycle; any UMSH LED policy that mixes colors should compensate.

Firmware role assignments differ and are pure policy:

- MeshCore: red (`P_LORA_TX_LED = 11`) as the TX indicator, blue as the status
  LED (`PIN_STATUS_LED`), red also as `PIN_LED` / `LED_BUILTIN`.
- Meshtastic: green (`PIN_LED1`) becomes `LED_POWER`, blue `PIN_LED2`, red
  `PIN_LED3`; all three are explicitly turned off in `initVariant()`.

## Buttons and wake behavior

**A stock kit has exactly one button: RESET** on the XIAO (`P0.18`, 10 kΩ
pull-up and a 100 nF cap, beside the USB-C connector). It is not readable as a
GPIO in the application — `P0.18` is configured as `nRESET` via UICR
`PSELRESET`. The radio carrier's K1 footprint ships bare.

### System OFF has no button wake

This is the practical consequence, and it shapes the whole power design. The
nRF52840 can leave System OFF via GPIO `DETECT`, LPCOMP, an NFC field, the
reset pin, or VBUS detection. On a stock kit that leaves:

| Wake source | Available? | Notes |
|---|---|---|
| Reset button | yes | the reliable one; a cold boot either way |
| USB attach (VBUS) | yes | plugging in wakes the board |
| LPCOMP on AIN7 | yes | battery-recovery wake, as MeshCore configures it |
| NFC field on `P0.09`/`P0.10` | yes, in principle | untested; conflicts with using those pads for I²C |
| GPIO `DETECT` on a button | **no**, unless K1 is retrofitted | see the retrofit profile below |

So System OFF on this board is close to "off until someone touches it
physically". That is fine for a shelf state and wrong for a
hold-to-sleep/press-to-wake UX. A UMSH port should:

- treat System OFF as a shipping/storage state entered by command (ULCP or BLE),
  not by gesture;
- keep the LPCOMP low-battery path, since it is the one *autonomous* wake and
  the one that matters for an unattended node;
- not present a "power off" affordance in the UI that a user cannot undo without
  the reset button or a cable.

### The retrofit profile: K1 fitted

The K1 footprint is the intended place for a user button, and soldering one in
is a reasonable thing to expect of a user who wants one. UMSH should support it
as an explicit board profile. Wiring, from the Meshtastic DIY README: with the
carrier oriented so the radio chip is at the bottom and the mounting hole at the
top, the **left** side of the switch goes to `GND` and the **right** side to the
pad on `D0`. Reversing it can connect `GND` to a supply rail.

In that profile:

- **The internal pull-up is mandatory**, not belt-and-braces. R2 is not fitted,
  so nothing else holds `P0.02` high. Configure `INPUT_PULLUP` (nRF52840
  internal pull is nominally 13 kΩ, giving ~250 µA while the button is held —
  acceptable for a momentary press).
- Treat the button as active-low; debounce in firmware, since a bare mechanical
  switch with no hardware RC will bounce freely.
- Wait for release before entering System OFF, then arm `P0.02` as a
  `SENSE_LOW` GPIO-`DETECT` wake source — **with the pull-up retained**.
- Expect wake from System OFF to be a cold boot, not a resume.

> **Do not copy MeshCore's System OFF arming verbatim on this board.**
> `XiaoNrf52Board::powerOff()` calls
> `nrf_gpio_cfg_sense_input(..., NRF_GPIO_PIN_NOPULL, NRF_GPIO_PIN_SENSE_LOW)`.
> Dropping the pull is correct only where an external pull-up exists — and on
> this carrier R2 is absent. With `NOPULL` and no external pull, `P0.02` floats
> into a `SENSE_LOW` detector: the board will wake spuriously, or immediately,
> and will draw current doing it. Use `NRF_GPIO_PIN_PULLUP` here.
> (MeshCore's runtime `pinMode(PIN_USER_BTN, INPUT_PULLUP)` in `begin()` is
> fine; it is only the shutdown path that drops the pull.)

Double-tap RESET remains the universal escape hatch into the bootloader in every
configuration.

### Bootloader button inputs

The Adafruit-derived bootloader defines `BUTTON_DFU = P0.18` (the reset pin) and
`BUTTON_DFU_OTA = P0.03` ("Button 2 is defined as D1 from expansion board").
`P0.03` is **`D1` = the SX1262's DIO1 line** on this kit, which the radio drives.

This is inert in practice: `main.c` requires *both* buttons for OTA
(`_ota_dfu = button_pressed(BUTTON_DFU) && button_pressed(BUTTON_DFU_OTA)`), and
`BUTTON_DFU` is the reset pin, which cannot read as pressed while the
application is running. But it is worth knowing that the bootloader samples a
radio signal at boot, in case an unusual bootloader build ever behaves oddly.

## QSPI flash

A **P25Q16H, 2 MB (16 Mbit)** QSPI flash sits on the XIAO itself:

| Signal | Arduino pin | nRF52840 pin |
|---|---:|---:|
| SCK | 24 | `P0.21` |
| CSN | 25 | `P0.25` |
| IO0 (DI) | 26 | `P0.20` |
| IO1 (DO) | 27 | `P0.24` |
| IO2 (WP) | 28 | `P0.22` |
| IO3 (HOLD) | 29 | `P0.23` |

These six pins are reserved and must not be repurposed.

**The flash is populated** (confirmed by inspection, 2026-08-03), despite the
published `v1.1` schematic labelling U7's value field `DNP`. Everything except
that annotation agrees: Seeed's specification lists "2 MB onboard Flash", the
wiki text repeats it, both firmware trees define
`EXTERNAL_FLASH_DEVICES P25Q16H`, and MeshCore ships `QSPIFLASH=1` companion
builds for this exact board. The `DNP` is a stale value field — the same
drawing marks the (genuinely unpopulated) header footprints the same way, and
conversely leaves the carrier's unpopulated K1 unmarked. Treat that field as
noise on this drawing.

MeshCore actively uses the flash for its companion-radio filesystem builds;
Meshtastic's kit variant has the entire QSPI block **commented out** and uses
internal flash only. If UMSH follows its existing pattern (sequential-storage on
internal NVMC), the QSPI flash is simply unused — but it should still be left
in deep power-down rather than floating, since an unconfigured QSPI flash
drawing standby current will dominate the board's < 5 µA figure.

## Clock, power, and USB

**32.768 kHz crystal — confirmed present.** The schematic shows X1 across
`P0.00/XL1` and `P0.01/XL2` with 10 pF loading capacitors, and both firmware
trees define `USE_LFXO`. UMSH can use `lfclk-xtal` with confidence; there is no
need for the `lfclk-rc` fallback that the Wio Tracker L1 required.

**DC/DC regulators fitted.** The schematic shows the `DCC` / `DCCH` / `VDDH`
inductor network populated, and MeshCore derives its board class from
`NRF52BoardDCDC`. Enable the nRF52840 REG0/REG1 DC/DC converters.

**USB.** Native nRF52840 USB on a USB-C connector with 5.1 kΩ CC pulldowns. VBUS
is visible to the MCU through the USB regulator status register, which is the
only input-power indication the board has beyond the charger's `~CHG` line.

**NFC pins.** `P0.09` and `P0.10` are the NFC antenna pads. Using them as GPIO
(which Meshtastic's default kit build does, for I²C) requires
`CONFIG_NFCT_PINS_AS_GPIOS` — on bare metal that means clearing `UICR.NFCPINS`,
a persistent write that requires a UICR erase and a reset to take effect. A UMSH
port that does not need I²C should leave them alone.

## I²C and expansion

There is no dedicated I²C bus on this kit. The three options, in the order the
upstream firmwares chose them:

| Build | I²C pins | Cost |
|---|---|---|
| Meshtastic, default | `D30`/`D31` = `P0.09`/`P0.10` (NFC pads) | forfeits NFC; needs the UICR write |
| Meshtastic, `_i2c` | `D6` (SDA) / `D7` (SCL) | forfeits GNSS UART |
| MeshCore | `D6` (**SCL**) / `D7` (**SDA**) | forfeits GNSS UART |

Note the last two disagree on which of `D6`/`D7` is SDA. Neither is "correct":
the nRF52840 TWIM peripheral can assign either function to either pin, `D6`/`D7`
are unconnected on the radio carrier, and there is no board-level convention to
appeal to. It only matters for matching whatever peripheral is physically wired.
If UMSH ever grows I²C on this board it should pick one and document it, and it
should expect third-party accessories built for either firmware to need a swap.

MeshCore also declares `PIN_LSM6DS3TR_C_POWER (15)` and the PDM microphone pins,
inherited from the Sense variant. **The kit's XIAO nRF52840 has neither the IMU
nor the microphone** — those pins (`P1.08`, `P0.27`, `P0.07`, `P0.11`, `P1.10`,
`P1.00`, `P0.16`) are simply unrouted. They are not available as expansion GPIO
either, since the plain XIAO does not break them out.

## Bootloader, SoftDevice, and flash layout

### Confirmed on hardware (2026-08-03, retail kit in DFU mode)

Read from the mounted DFU volume's `INFO_UF2.TXT` and by parsing the
bootloader's own `CURRENT.UF2`:

| Parameter | Value |
|---|---|
| Bootloader | `UF2 Bootloader **0.6.1**` (lib/nrfx 2.0.0, tinyusb 0.10.1-293-gaf8e5a90), dated **Nov 12 2021** |
| Model | `Seeed XIAO nRF52840` |
| **Board-ID** | **`Seeed_XIAO_nRF52840_Sense`** |
| **Volume label** | **`XIAO-SENSE`** (macOS mounts `/Volumes/XIAO-SENSE`) |
| SoftDevice | `S140 version 7.3.0` |
| **UF2 family ID** | **`0x28860045`** — read from the family-ID field of `CURRENT.UF2` |
| UF2-writable window | **`0x01000` – `0xEA000`** (3728 blocks × 256 B payload) |
| Application base | **`0x27000`** — the pre-flashed Meshtastic image's vector table is there (SP `0x20040000`, reset `0x00072149`); `0x26000` holds SoftDevice tail data, not a vector table |

**The retail kit ships the *Sense* bootloader configuration on plain XIAO
nRF52840 hardware.** The earlier caution in this document — that this had been
"reported in the wild" — is confirmed. The board-specific family is therefore
`0x28860045`, **not** the `0x28860044` that UMSH uses for the SenseCAP Solar
Node, and the volume is `XIAO-SENSE`, not `XIAO-BOOT`.

Note also that this is a **2021-vintage 0.6.1 bootloader** — it predates the
`OTAFIX`/`BP` builds seen on the Solar Node and the T-Echo, and it is old enough
that its behavior should not be assumed to match those boards'.

### Family-ID acceptance and the flash ceiling, verified by experiment

Three single-block UF2 files were copied to the DFU volume on the unit above
(2026-08-03). Each was self-contained (`numBlocks = 1`), because
`flash_nrf5x_flush()` only runs once `numWritten >= numBlocks` — a rejected
block never advances that counter, so a mixed file would never commit. The
target was `0xC0000`, inside the 176 KB of blank flash above the pre-flashed
Meshtastic image (which ends at `0x0BDE00`), so nothing in use was disturbed.

Probes 1 and 3 deliberately used the **same target address** with different
family IDs, making them a controlled A/B: whichever tag is present at `0xC0000`
afterwards identifies the family the bootloader honored.

| Probe | Family | Address | `cp` result | DFU volume after | Outcome |
|---|---|---|---|---|---|
| 1 | `0x28860044` (our SenseCAP preset) | `0xC0000` | **exit 0, no error** | still mounted | **ignored** |
| 2 | `0xADA52840` | **`0xEA000`** | **exit 0, no error** | still mounted | **ignored** — above `USER_FLASH_END` |
| 3 | `0xADA52840` | `0xC0000` | failed *only* on extended attributes: `Device not configured` | **gone** | **accepted** — flushed and reset mid-copy |

Read back from `CURRENT.UF2` after re-entering DFU:

```text
0xC0000: 554d53482d54332d47454e455249432d4144413532383430 ffffffffffffffff
         U  M  S  H  -  T  3  -  G  E  N  E  R  I  C  -  A  D  A  5  2  8  4  0
0xC0100: ffffffffffffffffffffffffffffffff        (next block, untouched)
```

Reading the results together:

- **The generic `0xADA52840` family is accepted, and its bytes reach flash.**
  Probe 3's tag is present byte-exact, with `FF` padding after it and the
  adjacent block untouched. It was also the only probe to reach the completion
  path — `numWritten >= numBlocks` → `flash_nrf5x_flush()` → reset — which tore
  the USB mass-storage device down before macOS could write the file's extended
  attributes. That `cp` error *is* the success signature. The board then
  re-enumerated running Meshtastic, so the write did not disturb the existing
  application.
- **`0x28860044` is silently ignored on this unit.** Probe 1 copied with **exit
  status 0 and no error of any kind**, and `0xC0000` holds probe 3's tag, not
  probe 1's — at the same address, so this is not an inference. Nothing in the
  copy path distinguishes a rejected family from a real flash; a script that
  checks only the copy's exit status will report a flash that never happened.
- **`USER_FLASH_END` is `0xEA000`, empirically.** Probe 2 used the *accepted*
  family and still did nothing, because `in_app_space()` excludes it. The 40 KB
  reserve is real, not just a source-code inference. (`0xEA000` is also past the
  end of `CURRENT.UF2`, so the region cannot even be read back through the
  bootloader — consistent with it being outside the app window.)

One artifact remains on the unit: 256 bytes of tag text at `0xC0000`, in flash
that no firmware uses. Any future UF2 flash that covers that page erases it.

### Flash map (confirmed by probe 2; consistent with the 0.6.1 sources)

`uf2cfg.h` defines `USER_FLASH_END = BOOTLOADER_REGION_START -
DFU_APP_DATA_RESERVED`, and `linker/nrf52840.ld` puts the bootloader at
`0xF4000`. The observed `0xEA000` end-of-dump therefore pins
`DFU_APP_DATA_RESERVED` at `0xA000` (40 KB):

```text
0x00000 - 0x01000   MBR                                    (4 KB)
0x01000 - 0x27000   SoftDevice S140 7.3.0                  (152 KB)
0x27000 - 0xEA000   Application                            (798,720 B / 780 KB)   <- UF2 writes here
0xEA000 - 0xF4000   DFU app-data reserve                   (40 KB)   <- UF2 never writes or erases
0xF4000 - 0xFD800   Bootloader                             (38 KB)
0xFD800 - 0xFE000   Bootloader config                      (2 KB)
0xFE000 - 0xFF000   MBR params page                        (4 KB)
0xFF000 - 0x100000  Bootloader settings                    (4 KB)
```

Two consequences for UMSH:

- **The application must end at `0xEA000`, not `0xED000`.** `write_block` gates
  every write on `in_app_space(addr)` — `USER_FLASH_START <= addr <
  USER_FLASH_END` — and blocks above `0xEA000` are simply not applied. An image
  linked past that boundary is **silently truncated**, with the UF2 copy
  reporting success. Meshtastic's linker script (`LENGTH = 0xEA000 - 0x27000`)
  is exactly right; **MeshCore's (`LENGTH = 0xED000 - 0x27000`) overruns the
  writable window by 12 KB**, as does its 811,008-byte
  `board_upload.maximum_size`.
- **`0xEA000` – `0xF4000` survives reflashing.** UF2 neither writes nor erases
  it. That makes it attractive for persistent state, and it is exactly what
  Meshtastic exploits for its warm-node-store ring at `0xEA000`–`0xED000`. If
  UMSH follows its usual convention of a 64 KB store at the top of the app
  window, that store must sit **below** `0xEA000` (i.e. `0xDA000`–`0xEA000`)
  and will be erased by every UF2 flash — or be moved deliberately into the
  reserve, accepting that the region is nominally the Adafruit core's.

### Other parameters

| Parameter | Value | Source |
|---|---|---|
| Bootloader settings | `0xFF000` | both board JSONs; confirmed by the linker script |
| Max application size | 811 008 B (MeshCore) / 815 104 B (Meshtastic) | board JSONs — **both exceed the 798 720 B writable window** |
| USB VID / PID (app) | `0x2886` / `0x0044` | MeshCore board JSON, bootloader `board.h` |
| USB product string | `XIAO nRF52840` | MeshCore board JSON |
| 1200-baud touch | supported | both board JSONs |

### UF2 family ID

The Adafruit bootloader accepts **two** family IDs for an application image
(`src/usb/uf2/ghostfat.c`, `write_block`):

```c
#define CFG_UF2_BOARD_APP_ID  ((USB_DESC_VID << 16) | USB_DESC_UF2_PID)
#define CFG_UF2_FAMILY_APP_ID 0xADA52840   // generic nRF52840

switch (bl->familyID) {
  case CFG_UF2_BOARD_APP_ID:   // board-specific app
  case CFG_UF2_FAMILY_APP_ID:  // family app
```

For the two Seeed XIAO bootloader configurations:

| Bootloader board config | UF2 PID | Board-specific family | Volume label | Board-ID |
|---|---|---|---|---|
| `xiao_nrf52840_ble` (plain) | `0x0044` | **`0x28860044`** | `XIAO-BOOT` | `nRF52840-SeeedXiao-v1` |
| `xiao_nrf52840_ble_sense` | `0x0045` | **`0x28860045`** | `XIAO-SENSE` | `nRF52840-SeeedXiaoSense-v1` |

**The observed retail kit is the second row** — `XIAO-SENSE` / `0x28860045`.
`0x28860044` is what UMSH uses for the SenseCAP Solar Node, whose rebuilt
bootloader carries the *plain* XIAO's USB IDs; that remains good corroboration
that the Solar Node is XIAO-derived, but it does **not** transfer to this kit.

The `write_block` switch above is present verbatim at the `0.6.1` tag this unit
runs, and both branches were exercised on hardware (see
[the probe results](#family-id-acceptance-and-the-flash-ceiling-verified-by-experiment)).
So:

- **Pack UMSH images for this board with the generic `0xADA52840`** —
  **verified accepted** on this unit. It works on every Adafruit-derived
  nRF52840 bootloader regardless of which Seeed board config was flashed, which
  matters here precisely because Seeed ships the Sense config on plain
  hardware. The board-specific `0x28860045` would also work on this unit but
  buys nothing and breaks on any unit that shipped `XIAO-BOOT`.
- **A UF2 with the wrong family is silently ignored** — **verified**: the copy
  returns success with no error, the volume stays mounted, and nothing is
  written. Nothing in the copy path distinguishes it from a real flash. If a
  flash appears to succeed but the board comes back running the old image,
  check the family before anything else.

`scripts/flash.py`'s existing `sensecap-solar` preset (base `0x27000`, family
`0x28860044`) **was tested against this kit and failed silently** — probe 1
above. The `xiao-nrf52` preset added on 2026-08-03 carries the working values:

```python
"xiao-nrf52": {
    "base": 0x27000,
    "family": 0xADA52840,          # generic nRF52840 — tolerates XIAO-BOOT and XIAO-SENSE
    "mount": "/Volumes/XIAO-SENSE",  # retail units; XIAO-BOOT if re-bootloadered
    "description": "Seeed XIAO nRF52840 + Wio-SX1262 Kit",
},
```

Because the mount name varies with the installed bootloader, `--copy-default`
is less reliable here than on the other boards; `--copy-to` with the observed
volume, or a plain drag-and-drop, is safer. `make flash-xiao-nrf52` uses
`--copy-default` and will need one of those fallbacks on an `XIAO-BOOT` unit.

### Do not trust Meshtastic's board metadata for this kit

Meshtastic's `boards/` directory contains two relevant and mutually inconsistent
JSON files, neither of which describes real hardware:

- `boards/seeed_xiao_nrf52840_kit.json` declares hwids `0x2886` / **`0x0166`**
  and `usb_product: "XIAO-BOOT"` — but no PlatformIO env selects it.
- `boards/xiao_ble_sense.json`, which the kit's env *does* select
  (`board = xiao_ble_sense`), declares Adafruit hwids `0x239A` / `0x810B` and
  `extra_flags: -DARDUINO_MDBT50Q_RX`. Those are a Raytac module's identifiers,
  copy-pasted.

Neither file's USB IDs can be used to derive a UF2 family. MeshCore's
`seeed-xiao-afruitnrf52-nrf52840` board JSON (`0x2886`/`0x8044` bootloader,
`0x2886`/`0x0044` app) matches the actual bootloader source and is the one to
believe.

### Seeed's OTA warning

The kit's wiki page carries an explicit caution:

> Please `don't use NRF-OTA` to update the firmware, it may cause the device to
> be completely dead.

UMSH has no OTA path on nRF52 today, so this is informational — but it argues
against ever adding one for this board without recovering-by-SWD as a fallback.
The SWD pads (TP1 GND, TP2 RESET, TP3 SWDCLK, TP5 SWDIO) are on the underside of
the XIAO and are the only guaranteed recovery route.

## Firmware implementation discrepancies

| Topic | Meshtastic | MeshCore | Recommended UMSH treatment |
|---|---|---|---|
| `g_ADigitalPinMap` | identical | identical | Schematic-confirmed. Treat as settled. |
| Radio pins | D4/D1/D3/D2/D5 + D8/D9/D10 | same | Schematic-confirmed. |
| RF switch | DIO2 switch, RXEN D5, no TXEN, DIO3 = 1.8 V | same | Schematic-corroborated. |
| Radio RESET idle | not addressed | not addressed | 10 kΩ pull-up on the carrier; radio is *not* held in reset by a floating pin. |
| GNSS | enabled; UART D6/D7, standby D0 | **removed** (`-UENV_INCLUDE_GPS`) | Optional module. On a stock kit D0 is uncontended, so GNSS is free to use it. |
| User button | **none** in the default build; D0 only in `_i2c` | D0, `INPUT_PULLUP`, active-low, System OFF wake source | Neither K1 nor R2 is fitted. Meshtastic matches the shipping board; MeshCore's button does not exist on retail hardware. Offer it as an opt-in retrofit profile. |
| System OFF wake arming | n/a | `nrf_gpio_cfg_sense_input(..., **NOPULL**, SENSE_LOW)` | **Wrong for this carrier** — R2 is absent, so `NOPULL` leaves the pin floating into a low detector. Use `PULLUP`. |
| External flash | QSPI block commented out; unused | `EXTERNAL_FLASH_USE_QSPI`, `QSPIFLASH=1` | Part is fitted (confirmed). Reserve the pins; deep power-down if unused. |
| I²C | NFC pins `P0.09`/`P0.10` (default) or D6=SDA/D7=SCL | D6=**SCL**/D7=**SDA** | Arbitrary; pick one and document it. NFC pins need a UICR write. |
| Battery divider gate | drives `P0.14` **HIGH** between reads | keeps `P0.14` **LOW** | Follow MeshCore/Seeed: hold `P0.14` LOW at all times. High-Z is worse than HIGH, not better. |
| ADC reference | framework default `AR_INTERNAL`, 3.6 V FS, 10-bit | `AR_INTERNAL_3_0`, 3.0 V FS, 12-bit | Both self-consistent. Use embassy-nrf's `Gain1_6` default at 12-bit. |
| ADC multiplier | 3 (comment: `R17=1M, R18=510k`) | 3.0 (comment: "1M, 512k") | True ratio is 2.9608. Use `raw × 10659 / 4096`. |
| Charge current | `HICHG` LOW → 100 mA | same | Schematic-confirmed; make it configurable. |
| Charge detect | `EXT_CHRG_DETECT 23`, LOW = charging | `BAT_NOT_CHARGING 23`, LOW = charging | Agree. Input-only. |
| LED pins/colors | 11=red, 12=blue, 13=green, active-low | identical | Schematic-confirmed. No dispute on this board. |
| LED roles | green = `LED_POWER` | red = TX indicator, blue = status | Policy. Pick per UMSH UX. |
| SPI1 | not defined | `PIN_SPI1_*` = 25/26/29, **collides with QSPI** | Do not expose a second SPI on those pins. |
| App flash window | `LENGTH = 0xEA000 - 0x27000` | `LENGTH = 0xED000 - 0x27000` | Meshtastic is right. The bootloader's `USER_FLASH_END` is `0xEA000` (confirmed); anything above is silently not written. |
| Low-voltage protection | none in the variant | bootlock 3300 mV + LPCOMP AIN7 refsel 2 | Adopt after calibration; note the threshold tracks VDD. |
| `PIN_A2` | redefined to 32 (VBAT) | left at 2 (D2) | Irrelevant on this kit — D2 is the radio reset. |
| `D32` comment | says "P0.10" (wrong; value is 31) | says "P0.31" (right) | Value is `P0.31`/AIN7. |

## Recommended initial UMSH board definition

A bare-metal UMSH BSP should name physical pins, not Arduino logical numbers.
The logical column is retained only for cross-referencing the upstream trees.

```rust
// Radio — Wio-SX1262 carrier (schematic Wio-SX1262 for XIAO V1.0)
// logical D1/D2/D3/D4/D5, D8/D9/D10
pub const RADIO_DIO1:  Pin = P0_03;
pub const RADIO_RESET: Pin = P0_28; // 10 kΩ pull-up on the carrier
pub const RADIO_BUSY:  Pin = P0_29;
pub const RADIO_CS:    Pin = P0_04;
pub const RADIO_RXEN:  Pin = P0_05; // RF_SW1; no pull, drive deterministically
pub const SPI_SCK:     Pin = P1_13;
pub const SPI_MISO:    Pin = P1_14;
pub const SPI_MOSI:    Pin = P1_15;
// DIO2 = RF switch, DIO3 = TCXO @ 1.8 V, no TXEN

// GNSS (optional L76K module) — no power-enable, no reset on this board
pub const GNSS_UART_TX: Pin = P1_11; // MCU TX
pub const GNSS_UART_RX: Pin = P1_12; // MCU RX
pub const GNSS_STANDBY: Pin = P0_02;

// User button: absent on a stock kit — the Wio-SX1262 carrier's K1 footprint
// is bare, and so is its R2 pull-up. Same pin as GNSS_STANDBY above, so the
// two profiles are mutually exclusive.
//
//   feature "user-button": K1 soldered in by the user.
//     P0.02 is an active-low input and MUST use the INTERNAL pull-up —
//     there is no external one. Arm System OFF wake as SENSE_LOW *with*
//     the pull-up retained.
//   otherwise: leave P0.02 as a DISCONNECTED input. A floating input with
//     the buffer connected wastes current against the <5 µA budget.
#[cfg(feature = "user-button")]
pub const USER_BUTTON: Pin = P0_02; // active-low, internal pull-up required

// RGB LED — common anode, ACTIVE LOW
pub const LED_RED:   Pin = P0_26; // 2.2 kΩ
pub const LED_BLUE:  Pin = P0_06; // 2.2 kΩ
pub const LED_GREEN: Pin = P0_30; // 10 kΩ — noticeably dimmer

// Battery: BAT -[1M]- P0.31 -[510k]- P0.14
pub const BATTERY_ADC:        Pin = P0_31; // AIN7
pub const BATTERY_DIVIDER_LO: Pin = P0_14; // drive LOW or leave input; NEVER high
pub const DIVIDER_MICRO: u32 = 10_659;     // raw * 10659 / 4096 = mV, Gain1_6 12-bit

// Charger (BQ25100)
pub const CHARGE_CURRENT_HI: Pin = P0_13; // LOW = 100 mA, HIGH/input = 50 mA
pub const CHARGE_STATUS_N:   Pin = P0_17; // input only; LOW = charging

// External QSPI flash (P25Q16H, 2 MB) — reserved
pub const QSPI_SCK: Pin = P0_21;
pub const QSPI_CSN: Pin = P0_25;
pub const QSPI_IO0: Pin = P0_20;
pub const QSPI_IO1: Pin = P0_24;
pub const QSPI_IO2: Pin = P0_22;
pub const QSPI_IO3: Pin = P0_23;

// NFC pads — GPIO use requires UICR NFCPINS cleared
pub const NFC1: Pin = P0_09;
pub const NFC2: Pin = P0_10;

// Free on the header, unconnected on the radio carrier: P1_11, P1_12 (if no GNSS)
```

Clock and power configuration: `lfclk-xtal` (32.768 kHz crystal fitted), DC/DC
enabled, native USB.

## Hardware bring-up checklist for UMSH

### Phase 0: identify the unit — **done 2026-08-03**

Completed for one retail kit; repeat on any unit whose provenance differs, since
the volume name and family ID depend on which bootloader Seeed loaded.

- ~~Read `INFO_UF2.TXT`~~ → 0.6.1 (Nov 2021), Board-ID
  `Seeed_XIAO_nRF52840_Sense`, volume `XIAO-SENSE`, S140 7.3.0.
- ~~Parse the family-ID field of `CURRENT.UF2`~~ → **`0x28860045`**. The 0.6.1
  sources confirm `0xADA52840` is accepted as well.
- ~~Confirm the application base~~ → **`0x27000`**, from the pre-flashed image's
  vector table (SP `0x20040000`).
- ~~Determine the writable window~~ → `0x01000`–**`0xEA000`**.
- ~~Confirm `0xADA52840` is accepted and `0x28860044` is not~~ → both
  confirmed by direct probe; see
  [the probe results](#family-id-acceptance-and-the-flash-ceiling-verified-by-experiment).
- Still open: the 1200-baud touch path against the *stock* Meshtastic app. A
  bare `stty -f /dev/cu.usbmodem… 1200` did **not** enter DFU, but that is not
  a fair test — it may not drive DTR the way the touch convention expects.
  Retest with a proper open/close before concluding anything. Double-tap RESET
  is known to work.
- Still open: confirm UMSH's `CdcAcmRescue` restores both the touch and the
  `\x03\x03\x03dfu\r` escape once a UMSH image runs on this board.

### Phase 1: non-destructive GPIO identification

- Boot with the radio and GNSS untouched.
- Drive `P0.26`, `P0.06`, `P0.30` low one at a time; confirm red / blue / green
  and confirm active-low. Confirm the green segment's reduced brightness.
- `P0.02` has no external pull (K1 and R2 both absent). Confirm the standby
  current penalty of leaving it as a connected floating input versus a
  disconnected one, and make "disconnected" the default in the no-button, no-GNSS
  configuration.
- Read `P0.17` with and without USB attached; confirm LOW while charging and
  that the red charge LED tracks it. Never drive this pin.
- Confirm `P0.18` is not readable as GPIO (it is `nRESET`).

### Phase 2: battery measurement

- Measure the cell externally with a trusted meter.
- With `P0.14` driven LOW, sample AIN7 at 12-bit / `Gain1_6` / 0.6 V reference.
- Check `raw × 10659 / 4096` against the meter at ~4.15 V, 3.9 V, 3.7 V, 3.4 V
  and fit a slope/offset if the residual exceeds ~1 %.
- Measure system current with `P0.14` LOW and confirm the ~2.8 µA divider draw
  against the board's < 5 µA standby claim.
- **Do not** drive `P0.14` high, or leave it high-Z, as part of this experiment.
- Validate a conservative low-battery cutoff and the LPCOMP recovery threshold,
  remembering that a 3/8-VDD reference moves with the rail.

### Phase 3: radio

- Initialize per the ordering above; confirm BUSY and DIO1 behave.
- Confirm the RESET pull-up: with `P0.28` configured as an input, verify the
  radio still responds.
- Verify RX with RXEN driven, then TX at low power first.
- Measure current and connector power before enabling 22 dBm; confirm the 3V3
  rail holds up under TX on battery alone.
- Confirm SPI integrity through the 22 Ω series resistors at the intended clock.
- Confirm nothing on the LED pins interferes with the radio.

### Phase 4: GNSS (only if the L76K is fitted)

- On a stock kit `P0.02` is uncontended and may be driven freely. Only a
  carrier with K1 soldered in requires the never-drive-high rule.
- Receive NMEA on `P1.12` at 9600 baud.
- Characterize standby polarity and timing on `P0.02`, and measure acquisition
  and standby current (there is no power-enable to fall back on).

### Phase 5: flash and expansion

- Read the QSPI JEDEC ID and confirm it is a P25Q16H; record erase-block and
  page-program sizes.
- If unused, confirm the part can be put into deep power-down and measure the
  standby delta.
- If I²C is needed, decide between the NFC pads (and the UICR write) and
  `D6`/`D7`, and confirm the UICR change survives a reset and a DFU.

### Phase 6: power

- Confirm System OFF entry, and confirm which wake sources actually work with
  no button available: reset, USB attach (VBUS), LPCOMP on AIN7, and — if it is
  ever worth the NFC pads — an NFC field.
- Confirm the charge-current select actually changes charge current.
- Measure standby against Seeed's < 5 µA claim with the divider, QSPI flash, and
  radio all accounted for.

## Open questions requiring hardware confirmation

1. Does the stock Meshtastic app honor the 1200-baud touch? An `stty`-only
   attempt did not enter DFU, but the method is suspect. (Everything else about
   this unit — identity, family-ID acceptance, app base, and the writable
   window — is resolved on hardware.)
2. Does the Wio-SX1262 carrier present an IPEX/u.FL connector or an on-board
   antenna? The `ANT` pin is a schematic no-connect.
3. What is the fitted resistor tolerance's real contribution to battery error —
   is the nominal `10659` good enough for a protective cutoff without a fit?
4. What is the L76K's exact standby polarity and wake timing on `D0`, and its
   current draw with no power-enable available?
5. Does the RGB LED's green segment need duty compensation to look balanced
   against red and blue?
6. Does NFC-field wake from System OFF actually work here, and is it worth
   forfeiting `P0.09`/`P0.10` for? On a stock buttonless board it is the only
   *contactless* way back from System OFF.
7. How much standby current does the QSPI flash contribute when left
   unconfigured, versus in deep power-down? And how much does a connected
   floating `P0.02` cost, given there is no external pull?
8. Does the kit's shipping Meshtastic image leave `P0.14` driven high on
   handover (it drives it high after every battery read), and does that matter
   for a board sitting on a charger before it is reflashed?
9. If K1 is retrofitted, is `P0.02` clean through reset for a hold-at-boot
   gesture, given that the bootloader samples `P0.03` (the radio's DIO1) as an
   OTA input? And does a bare switch with no hardware debounce need a longer
   software debounce than the other UMSH boards use?

## Source references

### Seeed Studio

- Kit product page:
  https://www.seeedstudio.com/XIAO-nRF52840-Wio-SX1262-Kit-for-Meshtastic-p-6400.html
- Kit wiki (SKU 102010710):
  https://wiki.seeedstudio.com/xiao_nrf52840&_wio_SX1262_kit_for_meshtastic/
- XIAO nRF52840 wiki (pin tables, battery FAQ Q3, charge-current control):
  https://wiki.seeedstudio.com/XIAO_BLE/
- **Wio-SX1262 for XIAO V1.0 schematic** (radio carrier, K1 button, pull-ups):
  https://files.seeedstudio.com/products/113010003/Wio-SX1262%20for%20XIAO%20V1.0.pdf
- **XIAO nRF52840 v1.1 schematic** (BQ25100, divider, RGB LED, crystal, QSPI):
  https://files.seeedstudio.com/wiki/XIAO-BLE/Seeed-Studio-XIAO-nRF52840-Sense-v1.1.pdf
- Wio-SX1262 module datasheet:
  https://files.seeedstudio.com/products/SenseCAP/Wio_SX1262/Wio-SX1262_Module_Datasheet.pdf
- L76K GNSS Module for XIAO:
  https://www.seeedstudio.com/L76K-GNSS-Module-for-Seeed-Studio-XIAO-p-5864.html

### Meshtastic

- Variant directory:
  https://github.com/meshtastic/firmware/tree/develop/variants/nrf52840/seeed_xiao_nrf52840_kit
- Pin and peripheral definitions (all four pinout columns):
  https://github.com/meshtastic/firmware/blob/develop/variants/nrf52840/seeed_xiao_nrf52840_kit/variant.h
- Physical pin map:
  https://github.com/meshtastic/firmware/blob/develop/variants/nrf52840/seeed_xiao_nrf52840_kit/variant.cpp
- PlatformIO definition (`board = xiao_ble_sense`):
  https://github.com/meshtastic/firmware/blob/develop/variants/nrf52840/seeed_xiao_nrf52840_kit/platformio.ini
- ADC gating behavior (`battery_adcEnable` / `battery_adcDisable`):
  https://github.com/meshtastic/firmware/blob/develop/src/Power.cpp
- nRF52 `AREF_VOLTAGE` default:
  https://github.com/meshtastic/firmware/blob/develop/src/platform/nrf52/architecture.h
- DIY stacked variant README (documents the carrier button):
  https://github.com/meshtastic/firmware/blob/develop/variants/nrf52840/diy/seeed-xiao-nrf52840-wio-sx1262/README.md

### MeshCore

- Variant directory:
  https://github.com/meshcore-dev/MeshCore/tree/main/variants/xiao_nrf52
- Pin definitions and power-management thresholds:
  https://github.com/meshcore-dev/MeshCore/blob/main/variants/xiao_nrf52/variant.h
- Board class (battery read, System OFF, TX LED):
  https://github.com/meshcore-dev/MeshCore/blob/main/variants/xiao_nrf52/XiaoNrf52Board.cpp
- PlatformIO radio and I²C configuration:
  https://github.com/meshcore-dev/MeshCore/blob/main/variants/xiao_nrf52/platformio.ini

### Bootloader

The shipping unit runs the **`0.6.1`** tag; links below are to `master` unless
noted, and `uf2cfg.h` / `ghostfat.c` were additionally checked at `0.6.1` (the
`write_block` family switch and `USER_FLASH_END` definition are unchanged).

- Flash regions (`BOOTLOADER_REGION_START = 0xF4000`, MBR params `0xFE000`,
  settings `0xFF000`), at the shipping tag:
  https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/0.6.1/linker/nrf52840.ld
- `USER_FLASH_END`, family IDs, and `in_app_space` gating, at the shipping tag:
  https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/0.6.1/src/usb/uf2/uf2cfg.h
  https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/0.6.1/src/usb/uf2/ghostfat.c
- Plain XIAO board config (USB IDs, volume label):
  https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/master/src/boards/xiao_nrf52840_ble/board.h
- Sense board config:
  https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/master/src/boards/xiao_nrf52840_ble_sense/board.h
- UF2 family-ID derivation and accepted families:
  https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/master/src/usb/uf2/uf2cfg.h
  https://github.com/adafruit/Adafruit_nRF52_Bootloader/blob/master/src/usb/uf2/ghostfat.c

## Bottom line

The kit is the cleanest nRF52840 + SX1262 combination in this directory: the
radio pinout is confirmed by a published schematic rather than inferred, the two
firmware trees agree on every pin, the LED colors are unambiguous, the LF
crystal is real, and the battery divider values are printed on the drawing.

Almost all of the UMSH work is already done in
`crates/umsh-bsp-sensecap-solar` — the radio wiring and the battery sense path
are identical, and only the LED polarity, the button arrangement, and the
charger interface differ.

The genuine risks are:

- **There is no user input as shipped.** The carrier's button footprint is
  bare, so out of the box the only physical control is the XIAO's reset button:
  no hold-to-power-off, no press-to-wake, no hold-at-boot force-pairing, and no
  GPIO wake from System OFF. The **default** UMSH profile for this board is a
  headless node driven over ULCP or BLE. K1 is easy to retrofit and should be a
  supported opt-in profile — but it lands on `D0`, so it is mutually exclusive
  with GNSS, and with R2 also absent it depends entirely on the internal
  pull-up (which MeshCore's System OFF path drops).
- **The `P0.14` rule.** Hold the divider's low side LOW at all times — driving
  it high puts `P0.31` at its absolute maximum and leaving it floating puts
  `P0.31` past it. The shipping Meshtastic build drives it high after every
  read, so it is not a reference implementation for the battery path.
- **Bootloader identity and the flash ceiling** — both settled by direct probe.
  Retail kits ship the *Sense* bootloader on plain hardware (`XIAO-SENSE`,
  family `0x28860045`), and UMSH's existing `0x28860044` preset **was tested and
  silently did nothing**: the copy reported success and no bytes were written.
  Pack with the generic `0xADA52840`, which was verified accepted. The
  UF2-writable window ends at **`0xEA000`**, not `0xED000` — also verified —
  so an over-long image is truncated with no error, and any NV store placed "at
  the top of the app window" must sit below that line.
- **Power budget.** There is no power switch, no load switch, and no way to cut
  the GNSS module's supply. Deep-sleep behavior on this board is entirely a
  firmware discipline problem.
- **The schematic's `DNP` annotations are noise.** The QSPI flash is marked
  `DNP` and is fitted; the carrier's K1 is unmarked and is not. Confirm
  populated parts by looking at the board.
