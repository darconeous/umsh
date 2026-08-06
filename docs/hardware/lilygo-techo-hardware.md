# LilyGO T-Echo Hardware Reconstruction

This document summarizes what can be inferred about the LilyGO T-Echo hardware from the official LilyGO repository, Meshtastic firmware, and MeshCore firmware.

Unlike the Seeed T1000-E, the T-Echo does have an official schematic PDF available in the LilyGO repository. However, where LilyGO README pin tables conflict with Meshtastic/MeshCore operational firmware definitions, this document uses the firmware-confirmed pins:

- Official schematic: <https://github.com/Xinyuan-LilyGO/T-Echo/blob/main/schematic/T-Echo_Schematic.pdf>
- Official LilyGO T-Echo repository: <https://github.com/Xinyuan-LilyGO/T-Echo>

The conclusions here are still written as a **firmware-and-documentation-level reconstruction**, not as a fully audited schematic review.

## High-level hardware blocks

The LilyGO T-Echo is an nRF52840-based LoRa/GNSS/e-paper device. The public LilyGO documentation and firmware sources indicate these major blocks:

- Nordic nRF52840 MCU
- Semtech SX1262 LoRa radio
- Quectel L76K GNSS receiver
- 1.54 inch 200×200 e-paper display, GDEH0154D67 / SSD1681 class
- PCF8563 RTC on I²C
- BME280 environmental sensor on I²C
- External QSPI flash, either MX25R1635F or ZD25WQ16B depending on hardware variant / supply
- Li-ion battery, 850 mAh for standard T-Echo, 2400 mAh for T-Echo Plus
- USB-C input for power / charging / firmware upload
- Fixed 500 mA battery charge current
- RGB status LED plus separate charger-status red LED
- User button, reset button, and capacitive touch button
- Shared I²C expansion/back-panel peripherals on T-Echo Plus:
  - DRV2605 haptic driver at 0x5A
  - BHI260 smart IMU at 0x28
  - Buzzer on P0.06
  - Haptic / back-panel enable on P0.08

## Important version note

The T-Echo and T-Echo Plus appear to share the same primary pinout, but the Plus adds a back-panel board with extra peripherals: DRV2605 haptic driver, BHI260 IMU, buzzer, and a larger battery.

This document primarily describes the standard T-Echo main board and calls out Plus-only items separately.

## Pin-source policy

The tables below use the firmware-confirmed mapping from Meshtastic and MeshCore as the operational source of truth. LilyGO README values are included only when they agree with firmware or describe non-GPIO product behavior such as battery capacity, charger LED behavior, display model, or I²C addresses.

Known LilyGO README pin-table conflicts handled in this document:

- P0.13: the schematic names it `PWR_EN` — the peripheral rail's actual
  gate node — and hardware behavior confirms it (see the power-control
  section). The Meshtastic/MeshCore variant files call it the red LED
  channel; treat that as wrong for this pin.
- E-paper SPI MOSI: use P0.29 from firmware, not the README's conflicting display-MOSI entry.

## Reconstructed pin map

### Main MCU / board

| Function | nRF52840 pin | Arduino pin | Firmware names | Notes |
|---|---:|---:|---|---|
| Peripheral power on | P0.12 | 12 | `PIN_POWER_EN`, `PIN_PWR_EN` | Schematic: `PWR_ON`. One term of the `VDD_POWR` gate only — does **not** feed the SX1262 branch, and VBUS ORs with it. MeshCore turns this low in `powerOff()`; the Meshtastic "controls power for all peripherals" comment overstates it. See the power-control section. |
| Peripheral power enable | P0.13 | 13 | schematic `PWR_EN`; misnamed `LED_RED`/`PIN_LED3` in variant files | The master gate: sole supply gate for the SX1262, AND-term for `VDD_POWR`, and the only input that turns the rail off while VBUS is present. **Hardware-confirmed 2026-08-06:** left floating (its MCU reset state), the rail can half-collapse — L76K browned-up, PPS pull-up faintly lighting the internal blue LED. Driven low alongside P0.12 everything collapses; no red LED lights, in either state. Drive both low at shutdown. |
| Battery ADC | P0.04 | 4 | `BATTERY_PIN`, `PIN_A0`, `PIN_VBAT_READ` | Battery voltage sense input. |
| User button | P1.10 | 42 | `PIN_BUTTON1`, `BUTTON_PIN`, `PIN_USER_BTN` | Active low. |
| Reset button | P0.18 | 18 | `PIN_BUTTON2` in Meshtastic; reset in LilyGO docs | LilyGO describes this as reset / DFU button. Meshtastic notes the bootloader configures it as a regular GPIO. |
| Touch button | P0.11 | 11 | `PIN_BUTTON_TOUCH`, `TP_SER_IO`, `PIN_BUTTON2` in MeshCore | Firmware-confirmed touch-button input. Polarity differs by firmware abstraction; verify behavior in the button driver before relying on edge polarity. |
| Blue LED | P0.14 | 14 | `LED_BLUE`, `PIN_LED1` | RGB LED blue channel. Active low in firmware. |
| Green LED | P0.15 | 15 | `LED_GREEN`, `PIN_LED2` | RGB LED green channel. Active low in firmware. |
| Red LED | unverified | — | `LED_RED`, `PIN_LED3` in variant files point at P0.13 | P0.13 is `PWR_EN`, not an LED (confirmed: driving it low lights nothing). If a red MCU channel exists at all it may be the README's P1.03; unverified. |
| GNSS 1PPS LED | driven by L76K | — | — | Internal blue LED on the module's 1PPS pin through 1 kΩ (schematic). A faint steady glow when "off" means the peripheral rail has not fully collapsed — see P0.13. |
| Charger-status LED | not MCU-controlled | — | — | Separate red LED controlled by charger circuit: on = charging, blink = battery fault/not connected, off = full. |

### LoRa / SX1262

| Function | nRF52840 pin | Arduino pin | Firmware names | Notes |
|---|---:|---:|---|---|
| SX1262 SPI MOSI | P0.22 | 22 | `PIN_SPI_MOSI`, `P_LORA_MOSI` | LoRa SPI bus. |
| SX1262 SPI MISO | P0.23 | 23 | `PIN_SPI_MISO`, `P_LORA_MISO` | LoRa SPI bus. |
| SX1262 SPI SCK | P0.19 | 19 | `PIN_SPI_SCK`, `P_LORA_SCLK` | LoRa SPI bus. |
| SX1262 CS/NSS | P0.24 | 24 | `SX126X_CS`, `LORA_CS`, `P_LORA_NSS` | LoRa chip select. |
| SX1262 reset | P0.25 | 25 | `SX126X_RESET`, `P_LORA_RESET` | LoRa reset. |
| SX1262 busy | P0.17 | 17 | `SX126X_BUSY`, `P_LORA_BUSY` | LoRa busy. |
| SX1262 DIO1 | P0.20 | 20 | `SX126X_DIO1`, `P_LORA_DIO_1` | Interrupt line. |
| SX1262 DIO2 | internal to module | — | `SX126X_DIO2_AS_RF_SWITCH` | Used by module for RF switch control. |
| SX1262 DIO3 | P0.21 / internal TCXO control | 21 | `SX1262_DIO3`, `PIN_TXCO` | Used to power/control TCXO; firmware sets 1.8 V TCXO voltage. |

Meshtastic comments say DIO2 is internally wired to the module’s RF switch, and DIO3 is used as an SX1262 output for TCXO power, so the main CPU should not treat DIO3 as a normal GPIO output.

MeshCore sets:

- `SX126X_DIO2_AS_RF_SWITCH=true`
- `SX126X_DIO3_TCXO_VOLTAGE=1.8`
- `SX126X_CURRENT_LIMIT=140`
- `SX126X_RX_BOOSTED_GAIN=1`

LilyGO’s README recommends setting a conservative SX1262 current limit and gives an example using `radio.setCurrentLimit(80)`.

### E-paper display

| Function | nRF52840 pin | Arduino pin | Firmware names | Notes |
|---|---:|---:|---|---|
| Display MOSI / SDI | P0.29 | 29 | `PIN_EINK_MOSI`, `DISP_MOSI`, `PIN_SPI1_MOSI` | Firmware-confirmed e-paper SPI MOSI. |
| Display MISO | P1.07 | 39 / firmware index 39; MeshCore macro value 38 | `PIN_SPI1_MISO`, `DISP_MISO` | Dummy/unused MISO for the e-paper SPI bus; e-paper normally does not need MISO. Do not confuse this with display MOSI. |
| Display SCLK | P0.31 | 31 | `PIN_EINK_SCLK`, `DISP_SCLK`, `PIN_SPI1_SCK` | Firmware-confirmed e-paper SPI clock. |
| Display CS | P0.30 | 30 | `PIN_EINK_CS`, `DISP_CS` | E-paper chip select. |
| Display busy | P0.03 | 3 | `PIN_EINK_BUSY`, `DISP_BUSY` | E-paper busy input. |
| Display DC | P0.28 | 28 | `PIN_EINK_DC`, `DISP_DC` | Data/command. |
| Display reset | P0.02 | 2 | `PIN_EINK_RES`, `DISP_RST` | E-paper reset. |
| Display backlight / enable | P1.11 | 43 | `PIN_EINK_EN`, `DISP_BACKLIGHT` | Meshtastic says this is really just backlight power. It is unusual for e-paper, but the board has this control line. |

Display details from LilyGO:

- Model: GDEH0154D67
- Resolution: 200×200
- Size: 1.54 inch
- Driver IC: SSD1681
- 2 s full refresh
- 0.26 s partial refresh
- Black/white display

Meshtastic includes a shutdown-specific detail: before powering off, it sets e-paper CS, DC, reset, and busy pins to inputs to avoid leakage current.

### GNSS / GPS

| Function | nRF52840 pin | Arduino pin | Firmware names | Notes |
|---|---:|---:|---|---|
| **GPS TX → MCU RX** | **P1.09** | 41 | `GPS_RX_PIN`, `PIN_GPS_TX`, `PIN_SERIAL1_TX` | **Measured.** Data from L76K to nRF52840, despite the pin names. |
| **GPS RX ← MCU TX** | **P1.08** | 40 | `GPS_TX_PIN`, `PIN_GPS_RX`, `PIN_SERIAL1_RX` | **Measured.** Data from nRF52840 to L76K. |
| GPS PPS | P1.04 | 36 | `PIN_GPS_PPS` | PPS input. LilyGO table gives P1.4 / Arduino 36. Never observed to toggle; not used. |
| GPS wakeup / standby | P1.02 | 34 | `PIN_GPS_STANDBY`, `GPS_EN` | High wakes, low sleeps. Confirmed: the module stops transmitting within a second of the pin going low. Quectel HW design: internally pulled up — **floating means awake**, so it must be actively driven low to sleep. |
| GPS reset | P1.05 | 37 | `PIN_GPS_REINIT`, `PIN_GPS_RESET` | Active low, held >100 ms. Quectel HW design: `RESET_N` internally pulled up to 3.3 V, "leave N/C if unused" — tri-stating releases it. Do **not** park it driven low: on USB the module stays powered regardless of the PWR pins, and a powered module held in reset is its worst state (and lights the 1PPS LED via its pull-up). |

**The UART direction is the reverse of what the pin names suggest.** The
upstream variant files name these from the *module's* point of view in
one macro and the *MCU's* in another, and the two disagree; the
`PIN_SERIAL1_RX`/`PIN_SERIAL1_TX` pair in particular reads backwards.
Measured on hardware by sampling each candidate pin against the internal
pull-down while the module was awake: **P1.09 is the line carrying NMEA**,
driven high at idle and showing ~350 edges in 60 ms of traffic. P1.08 was
undriven under every standby/reset combination.

The same ambiguity is flagged for the SenseCAP Solar's L76K — see
[`sensecap-solar-node-p1-pro-hardware.md`](sensecap-solar-node-p1-pro-hardware.md#gnss)
— so treat the direction as unverified on any board carrying this module
until it has been sampled.

The GNSS baud rate differs by firmware convention:

- Meshtastic variant defines a 50 ms GPS thread interval but does not define baud rate in the variant file excerpt.
- MeshCore sets `GPS_BAUD_RATE=9600`.

9600 is correct and is what UMSH uses.

### Observed behavior

Confirmed on hardware 2026-08-04 with the UMSH firmware:

- The module emits NMEA continuously at ~730 B/s once woken — GGA, GSA,
  GSV and RMC — and reaches a 3D fix indoors near a window (15 satellites
  used of 17 in view, HDOP giving a ~4.5 m accuracy estimate).
- Driving P1.02 low stops the stream: the byte counter freezes, which is
  what makes `PROP_GNSS_ENABLED` a real power control rather than a
  reporting switch.
- The module shares the P0.12 peripheral rail with the e-paper, the LoRa
  module and the sensors, so it cannot be unpowered independently. Its
  internal clock and ephemeris therefore survive a disable — a re-enable
  is a warm start — but not a shutdown.

### I²C bus

| Function | nRF52840 pin | Arduino pin | Notes |
|---|---:|---:|---|
| I²C SDA | P0.26 | 26 | Shared I²C bus. |
| I²C SCL | P0.27 | 27 | Shared I²C bus. |
| PCF8563 IRQ | P0.16 | 16 | RTC interrupt. |

Known I²C addresses from LilyGO documentation:

| Device | Address | Variant |
|---|---:|---|
| BME280 | 0x77 | T-Echo / Plus |
| PCF8563 RTC | 0x51 | T-Echo / Plus |
| DRV2605 haptic driver | 0x5A | T-Echo Plus back panel |
| BHI260 smart IMU | 0x28 | T-Echo Plus back panel |

### External QSPI flash

| Function | nRF52840 pin | Arduino pin | Firmware names |
|---|---:|---:|---|
| QSPI SCLK | P1.14 | 46 | `PIN_QSPI_SCK` |
| QSPI CS | P1.15 | 47 | `PIN_QSPI_CS` |
| QSPI IO0 / MOSI | P1.12 | 44 | `PIN_QSPI_IO0` |
| QSPI IO1 / MISO | P1.13 | 45 | `PIN_QSPI_IO1` |
| QSPI IO2 / WP | P0.07 | 7 | `PIN_QSPI_IO2` |
| QSPI IO3 / HOLD | P0.05 | 5 | `PIN_QSPI_IO3` |

LilyGO warns that the flash chip may be either MX25R1635FZUIL0 or ZD25WQ16B depending on availability. Meshtastic uses `MX25R1635F`; MeshCore’s variant file contains both `ZD25WQ16BUIGR` and `MX25R1635F` definitions, with the latter appearing later in the file and therefore likely overriding the earlier macro in normal preprocessing.

### T-Echo Plus back-panel peripherals

| Function | nRF52840 pin | Arduino pin | Notes |
|---|---:|---:|---|
| DRV2605 enable | P0.08 | 8 | Plus-only back-panel enable. |
| DRV2605 SDA/SCL | P0.26 / P0.27 | 26 / 27 | Shared I²C. |
| BHI260 SDA/SCL | P0.26 / P0.27 | 26 / 27 | Shared I²C. |
| BHI260 IRQ | NC | NC | No interrupt pin connected per README. |
| Buzzer | P0.06 | 6 | Plus-only buzzer. |

## Power architecture

### USB-C and charging

The official LilyGO README lists:

- USB-C input voltage: 4.8 V to 5.5 V
- Charge current: 500 mA fixed
- Battery voltage: 3.7 V
- Battery capacity: 850 mAh for T-Echo, 2400 mAh for T-Echo Plus
- Charge temperature: 0°C to 60°C

The charger appears to be mostly autonomous. The README describes charging status through a **dedicated charger-status LED**, not through MCU-readable charger-status pins:

| Charger LED state | Meaning |
|---|---|
| Constantly lit | Charging |
| Blinking | Battery not connected or faulty |
| Off | Fully charged |

The README also warns that battery ADC readings are inaccurate while USB is plugged in and says that an ADC-derived voltage greater than 4200 mV can be used as an indication that USB is connected.

The README further warns that a USB-A to USB-C cable is required for power, and that with a USB-C to USB-C cable the supply may refuse to power the device. That implies the USB-C port likely lacks full USB-C CC sink negotiation / pull-down behavior, or at least LilyGO does not consider C-to-C behavior reliable.

### RGB LED pins

Confirmed channels, active-low:

```text
Blue  → P0.14 / Arduino 14
Green → P0.15 / Arduino 15
```

An earlier revision of this document sided with the Meshtastic/MeshCore
variant files and called P0.13 the red channel "definitively". The
schematic names P0.13 `PWR_EN`, and hardware agrees: driving it low
lights no LED and gates the peripheral rail (see the power-control
section). This is a case where every firmware inherited the same wrong
pin table — it went unnoticed because driving P0.13 high as "LED off"
also happens to enable the rail. Whether a red MCU-driven channel exists
elsewhere (the README's P1.03?) is unverified; the red LED normally seen
on this board is the hardware-driven charger LED.

### Firmware-visible charger interface

I found no evidence in the Meshtastic or MeshCore T-Echo board definitions of an I²C PMIC or MCU-readable charger status pins comparable to the T1000-E’s `CHARGE_STA` / `CHARGE_DONE` pins.

The firmware primarily sees:

- battery voltage through `BATTERY_PIN` / P0.04,
- USB power indirectly through voltage behavior or nRF USB state,
- charger status only visually through the charger LED, not apparently through firmware.

### Peripheral power enable

Meshtastic defines:

```c
#define PIN_POWER_EN (0 + 12)
```

with the comment:

```c
// Controls power for all peripherals (eink + GPS + LoRa + Sensor)
```

MeshCore defines the same basic line as:

```c
#define PIN_PWR_EN (12)
```

and drives it low in `powerOff()` before entering nRF52 System OFF.

The schematic tells a fuller story than either firmware: power is
controlled by a *pair* of nets, `PWR_ON` (P0.12) and `PWR_EN` (P0.13 —
the pin the variant files misname `LED_RED`), and they gate two
different things (schematic-derived; the interconnection is non-obvious
to read):

```text
SX1262 supply = PWR_EN
VDD_POWR      = PWR_EN AND (PWR_ON OR VBUS)
```

`VDD_POWR` is the peripheral rail — GNSS, sensors, e-ink, and the I²C
pull-ups. The PCF8563 RTC is **not** on `VDD_POWR` and is untouched by
both PWR pins — it keeps time through every power state short of a dead
battery, which is what makes it the board's clock across a power cycle.
Consequences of the gating:

- `PWR_EN` is the master gate on battery: low, and both the radio and
  the rail are unpowered no matter what `PWR_ON` says.
- `PWR_EN` high with `PWR_ON` low is a radio-only state: SX1262 powered,
  peripheral rail down (and e-paper retains its image unpowered).
- **The VBUS term is not actually gated by `PWR_EN`** — the schematic
  reads as though it is, but hardware disagrees (observed 2026-08-06):
  with *both* pins driven low in System OFF, the L76K stays powered on
  USB (its 1PPS LED can light) and goes fully dark on battery with the
  identical pin state. The USB-side feed reaches the module downstream
  of the `PWR_EN` element, exact path untraced. Practical rule: on USB
  the GNSS module is powered *no matter what firmware does*, so its
  off-state must be a valid state for a powered module (Standby via
  WAKEUP low, reset released) — not just safe levels for a dead one.
- Consequently the SX1262 branch is the one PWR_EN provably kills in
  every case; the pre-fix floating `PWR_EN` left the radio sitting on a
  soft rail in POR limbo through the entire off state, which was the
  real battery drain — the GNSS LED was only the visible symptom.

Hardware-confirmed: a floating `PWR_EN` (its MCU reset state) is not a
solid level — it can half-enable the chain, leaving `VDD_POWR` partially
up with the L76K browned-out and its 1PPS pull-up faintly lighting the
module's internal blue LED. Both pins driven low fully collapse the
rail; the nRF52840 remains powered either way so it can wake from
System OFF.

Neither Meshtastic nor MeshCore ever drives P0.13 low: both hold it
*high* through their off state as "red LED off". Per the truth table
that leaves the **SX1262 powered indefinitely while "off"**, and on USB
(VBUS ≡ `PWR_ON`) their off state keeps the whole peripheral rail up as
well. Their dark 1PPS LED on battery comes from `PWR_ON` floating low
dropping `VDD_POWR`, not from a deliberately deeper off state.

### Device “off” behavior

The device does not appear to hard-disconnect the battery from the whole board under firmware control. “Off” is best understood as:

1. Turn off LEDs and display backlight / leakage paths.
2. Disable the peripheral power rail: P0.12 **and** P0.13 low.
3. Enter nRF52840 System OFF using `sd_power_system_off()`.
4. Wake by button / reset / USB/bootloader behavior depending on bootloader and pin configuration.

MeshCore’s `powerOff()`:

- turns RGB LEDs off by driving active-low LED lines high,
- turns display backlight low,
- drives `PIN_PWR_EN` low,
- calls `sd_power_system_off()`.

Meshtastic’s variant-specific shutdown handler sets e-paper control pins to input before shutdown to reduce leakage.

## Battery voltage measurement

The battery ADC is on P0.04 / Arduino pin 4.

### Divider / multiplier

There is a notable discrepancy across sources:

- Meshtastic T-Echo variant uses `ADC_MULTIPLIER = 2.0`.
- MeshCore `TechoBoard.h` explicitly says the battery divider is 150 kΩ + 150 kΩ, so the divider ratio is 0.5 and the compensation factor is 2.0.
- MeshCore `variant.h` also contains `ADC_MULTIPLIER = 4.90F`, which appears inconsistent with its own `TechoBoard.h` and with Meshtastic.

My interpretation: for normal battery measurement, the operational divider compensation is **2.0×**, corresponding to a half-voltage divider. The 4.90× macro in MeshCore’s variant file may be unused, stale, or inherited from another board definition. It should not be trusted without checking which code path actually uses it.

MeshCore’s board helper defines:

```c
VBAT_MV_PER_LSB   = 3000 mV / 4096
VBAT_DIVIDER      = 0.5
VBAT_DIVIDER_COMP = 2.0
REAL_VBAT_MV_PER_LSB = 2.0 * 3000 / 4096
```

So the formula is:

```text
battery_mV = raw_adc * 2.0 * 3000 / 4096
```

### The reference term does not carry over to our firmware

That `3000 mV / 4096` assumes the SAADC is running at a 3.0 V full scale.
Our firmware uses `embassy-nrf`'s default single-ended configuration —
12-bit, `Gain1_6`, 0.6 V internal reference — which puts full scale at
**3.6 V** at the pin. The divider is a hardware fact and is unchanged;
only the reference term differs:

```text
battery_mV = raw_adc * 2.0 * 3600 / 4096
           = raw_adc * 7200 / 4096
```

This is the constant `umsh-bsp-techo::power::DIVIDER_MICRO` carries.
Copying the 3000-based figure into a build using our SAADC settings would
under-read the pack by 17 %.

Unlike the T-1000E and SenseCAP Solar boards, this divider has no gate
pin: the 300 kΩ leg sits across the pack permanently and draws ~12 µA
regardless of firmware state.

## Low-battery cutoff / battery protection

There are two different levels to consider.

### Firmware-level low battery behavior

Meshtastic’s generic power manager can trigger low-battery deep sleep when battery voltage falls below the bottom of its open-circuit-voltage table for repeated readings. The T-Echo variant does not define a custom OCV table in the board file excerpt, so it likely uses Meshtastic’s generic defaults unless overridden elsewhere.

MeshCore companion-radio builds define:

```ini
-D AUTO_SHUTDOWN_MILLIVOLTS=3300
```

for T-Echo companion-radio environments. That means MeshCore builds may shut down around 3.3 V depending on the selected firmware target.

### Hardware battery protection

The LilyGO README does not prove an MCU-controlled hardware cutoff. It gives charging limits and charger LED states, but does not identify a fuel gauge, battery protector, or PMIC interface.

The battery pack or charger/power-path circuit may include Li-ion protection or undervoltage lockout, but the firmware-level evidence only proves:

- battery voltage measurement,
- a fixed-current charger,
- peripheral power switching,
- nRF52 System OFF.

Without reviewing the schematic symbol-by-symbol or identifying the charger/protection IC, do not assume the MCU can hard-disconnect the battery from the system.

## Display power / leakage behavior

The e-paper display has a few special power considerations:

- It has a “backlight” / enable pin at P1.11 / Arduino 43, even though e-paper itself is reflective.
- Meshtastic says `PIN_EINK_EN` is “really just backlight power.”
- Meshtastic’s `variant_shutdown()` sets e-paper CS, DC, reset, and busy pins to input because otherwise there is leakage current.
- This suggests that even when the main peripheral rail is disabled, attached display pins can back-power or leak unless tri-stated.

For lowest sleep current, firmware should:

1. Put the display into its own sleep mode if supported.
2. Disable display/backlight power.
3. Tri-state e-paper control pins.
4. Disable the peripheral power rail.
5. Enter nRF52 System OFF.

## RTC and wake behavior

The PCF8563 RTC is on the shared I²C bus at address 0x51, with IRQ on P0.16.

Per the schematic it is **not** powered from `VDD_POWR` and is controlled
by neither PWR pin — it keeps time through every power state including
full shutdown, which is what makes it the board's clock across a power
cycle. Note the asymmetry this creates: the RTC itself survives a rail
collapse, but its I²C bus doesn't — the pull-ups are on `VDD_POWR`, so
the RTC is unreachable (not dead) while the rail is down.

The presence of a dedicated RTC interrupt line means firmware can potentially use the RTC for timed wakeups, depending on how the nRF GPIO sense and System OFF wake sources are configured.

## BME280 environmental sensor

The BME280 is on shared I²C address 0x77. MeshCore enables it for the T-Echo with:

```ini
-D ENV_INCLUDE_BME280=1
-D TELEM_BME280_ADDRESS=0x77
```

Meshtastic’s T-Echo variant defines the shared I²C pins but does not list the BME280 address in the variant header excerpt.

## Firmware source comparison

### LilyGO official repository

The official README is useful for:

- product variants,
- display details,
- I²C addresses,
- battery capacity,
- charge current,
- charger LED behavior,
- battery-life measurements,
- schematic PDF link.

It should **not** be treated as the authoritative source for all GPIO assignments. Where its pin table conflicts with Meshtastic or MeshCore board definitions, this document uses the firmware-confirmed mapping.

### Meshtastic

Meshtastic is the best source for:

- actual operational pin names,
- e-paper shutdown leakage handling,
- `PIN_POWER_EN` meaning,
- LoRa DIO2/DIO3 semantics,
- GPS control semantics,
- battery ADC setup,
- LED active polarity,
- QSPI flash setup.

### MeshCore

MeshCore is useful as an independent cross-check for:

- LoRa pin definitions,
- GPS baud and enable/reset pin use,
- e-paper display class selection,
- BME280 telemetry enable/address,
- power-off implementation,
- battery ADC formula,
- auto-shutdown threshold in companion-radio builds.

## Mental block diagram

```text
USB-C
   ├── USB D+/D- → nRF52840 USB / bootloader / serial
   └── 5 V input → fixed-current Li-ion charger, 500 mA
                  ├── Li-ion battery, 850 mAh or 2400 mAh Plus
                  └── charger LED:
                       on = charging
                       blink = battery absent/fault
                       off = full

Li-ion battery
   └── divider → nRF P0.04 / AIN, likely 150k/150k, 2× compensation

nRF52840
   ├── P0.12 → peripheral power enable
   │          ├── e-paper display
   │          ├── SX1262 LoRa radio
   │          ├── L76K GNSS
   │          └── sensors
   ├── SPI bus 0 → SX1262
   ├── SPI bus 1 → e-paper display
   ├── QSPI → external flash
   ├── UART1 → L76K GNSS
   ├── I²C → PCF8563 RTC + BME280 + Plus back-panel devices
   ├── GPIO → RGB LED, buttons, touch button, GPS reset/wake, display control
   └── System OFF sleep, with peripheral rail disabled for low power
```

## Practical firmware notes

- Power gating: SX1262 = `PWR_EN` (P0.13); `VDD_POWR` = `PWR_EN` ∧ (`PWR_ON` (P0.12) ∨ VBUS). Drive **both** low at shutdown — P0.13 floating can leave the chain half-alive, and on USB only P0.13 turns the rail off. P0.13 is not the red LED, whatever the variant files say. The PCF8563 is on neither gate.
- Do not assume USB-C to USB-C powering works reliably; LilyGO explicitly warns that USB-A to USB-C may be required.
- Do not treat charger status as firmware-visible unless you verify a charger IC/status pin in the schematic.
- Use the charger LED for human-visible charge state.
- Battery ADC can be wrong while USB is plugged in, so a sample taken on USB is not a resting cell voltage.
- LilyGO suggests treating battery voltage above 4.2 V as a likely USB/charging indication. That heuristic is unnecessary here: `POWER.usbregstatus.vbusdetect` reports the true VBUS pin state directly, and this board charges only from USB. Note it has to be *polled* — the `POWER` USB interrupts are unavailable to firmware sharing the `CLOCK_POWER` vector with MPSL.
- For the battery ADC, use the 2× compensation path used by Meshtastic and MeshCore’s `TechoBoard` helper, but pair it with your own SAADC's full-scale voltage rather than MeshCore's 3000 mV — see [Battery voltage measurement](#battery-voltage-measurement). Treat the 4.90× MeshCore variant macro as stale/inapplicable unless proven otherwise in the active code path.
- Put e-paper control pins into high impedance before deep sleep to avoid leakage.
- DIO2 on the SX1262 is used internally for RF switching; DIO3 is used for TCXO power at 1.8 V.
- T-Echo Plus adds back-panel peripherals on the same I²C bus; code should tolerate missing DRV2605/BHI260 devices on non-Plus boards.
- If using external QSPI flash, account for possible chip substitution between MX25R1635F and ZD25WQ16B.

## Source references

- LilyGO official T-Echo repository: <https://github.com/Xinyuan-LilyGO/T-Echo>
- LilyGO official README: <https://github.com/Xinyuan-LilyGO/T-Echo/blob/main/README.MD>
  - Note: the README appears to contain stale/incorrect GPIO assignments in at least the RGB LED and display sections; this document uses firmware-confirmed GPIO mappings.
- LilyGO official schematic PDF: <https://github.com/Xinyuan-LilyGO/T-Echo/blob/main/schematic/T-Echo_Schematic.pdf>
- Meshtastic T-Echo variant header: <https://github.com/meshtastic/firmware/blob/master/variants/nrf52840/t-echo/variant.h>
- Meshtastic T-Echo variant implementation: <https://github.com/meshtastic/firmware/blob/master/variants/nrf52840/t-echo/variant.cpp>
- Meshtastic generic power management: <https://github.com/meshtastic/firmware/blob/master/src/Power.cpp>
- MeshCore T-Echo variant: <https://github.com/meshcore-dev/MeshCore/blob/main/variants/lilygo_techo/variant.h>
- MeshCore T-Echo board implementation: <https://github.com/meshcore-dev/MeshCore/blob/main/variants/lilygo_techo/TechoBoard.h>
- MeshCore T-Echo board startup/battery read: <https://github.com/meshcore-dev/MeshCore/blob/main/variants/lilygo_techo/TechoBoard.cpp>
- MeshCore T-Echo PlatformIO configuration: <https://github.com/meshcore-dev/MeshCore/blob/main/variants/lilygo_techo/platformio.ini>
