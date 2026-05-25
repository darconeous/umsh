# Seeed Wio Tracker L1 / L1 Pro Hardware Reconstruction

This document summarizes what can be inferred about the Seeed Wio Tracker L1 family, especially the **Wio Tracker L1 Pro**, from Meshtastic documentation, Meshtastic firmware, MeshCore firmware, and community firmware repositories.

The most important naming detail is that **“L1 Pro” appears to be the OLED L1 packaged with a case and integrated battery**, while **“L1 e-ink” is a separate display variant**. The pinout and firmware support overlap substantially, so this document covers the L1 Pro/OLED board and notes the e-ink variant where relevant.

## Schematic

- Schematic: <https://files.seeedstudio.com/wiki/SenseCAP/Meshtastic/Wio_Tracker_L1_Pro_SCH_PDF.pdf>

Known official/resource links:

- Meshtastic device documentation: <https://meshtastic.org/docs/hardware/devices/seeed-studio/wio-series/wio-tracker-l1/>
- Meshtastic docs source: <https://github.com/meshtastic/meshtastic/blob/master/docs/hardware/devices/seeed-studio/wio-series/wio-tracker-l1.mdx>
- Seeed wiki link referenced by Meshtastic: <https://wiki.seeedstudio.com/get_started_with_meshtastic_wio_tracker_l1/>
- Seeed wiki link referenced by MeshCore board metadata: <https://wiki.seeedstudio.com/wio_tracker_l1_node/>
- Seeed product link referenced by Meshtastic board metadata: <https://www.seeedstudio.com/Wio-Tracker-L1-p-6477.html>

## Bootloader, SoftDevice, and flash layout

These values are **directly verified** from an in-hand Wio Tracker L1 in DFU mode (`INFO_UF2.TXT` on the mounted `TRACKER L1` volume) and cross-referenced against the MeshCore board JSON and linker script.

| Fact | Value | Source |
|---|---|---|
| Bootloader | UF2 Bootloader 0.9.2-dirty (Seeed fork of Adafruit nRF52 bootloader) | `INFO_UF2.TXT` |
| Model | Seeed TRACKER L1 | `INFO_UF2.TXT` |
| Board-ID | `TRACKER L1` | `INFO_UF2.TXT` |
| SoftDevice | **S140 7.3.0** | `INFO_UF2.TXT`, MeshCore `platformio.ini` |
| MBR + SoftDevice region | `0x00000000` .. `0x00027000` (156 KiB) | S140 v7 layout |
| App region | `0x00027000` .. `0x000F4000` (820 KiB) | Bootloader at 0xF4000 |
| MeshCore app window | `0x00027000` .. `0x000ED000` (792 KiB) | MeshCore `nrf52840_s140_v7.ld` (leaves 28 KiB for internal FS) |
| MeshCore "extra FS" window | `0x00027000` .. `0x000D4000` (692 KiB max) | `nrf52840_s140_v7_extrafs.ld`, `board_upload.maximum_size = 708608` |
| Bootloader region | `0x000F4000` .. `0x000FF000` | Standard Adafruit nRF52 layout |
| Bootloader settings | `0x000FF000` .. `0x00100000` | MeshCore board JSON `settings_addr` |
| RAM | `0x20000000` .. `0x20040000` (256 KiB) | nRF52840 |
| RAM reserved for S140 (if enabled) | `0x20000000` .. `0x20006000` (24 KiB) | MeshCore `nrf52840_s140_v7.ld` RAM origin |

**Critical difference from the LilyGO T-Echo:** the T-Echo ships with S140 v6.1.1, so its app starts at `0x26000`. The Wio Tracker L1 ships with S140 v7.3.0, so its app starts at `0x27000`. **`memory.x` cannot be copy-pasted between the two boards.**

As long as `sd_softdevice_enable()` is never called, S140 sits dormant and the application has full control of all peripherals and the full RAM region (no need to reserve the 24 KiB the SoftDevice would otherwise need).

### UF2 family ID

The Seeed bootloader uses its own UF2 family ID convention: **family ID = USB VID concatenated with PID**.

- VID: `0x2886` (Seeed Studio)
- PID: `0x1667` (Wio Tracker L1 primary) or `0x1668` (variant)
- Resulting family ID: **`0x28861667`** (or `0x28861668`)

This is **not** the Adafruit nRF52840 family ID (`0xADA52840`) used by the LilyGO T-Echo. UF2 files generated for the Wio Tracker L1 must embed `0x28861667` or the bootloader will reject them.

The family ID is not registered in <https://github.com/microsoft/uf2/blob/master/utils/uf2families.json>; it is a Seeed-private convention.

### USB identifiers

| Field | Value |
|---|---|
| VID | `0x2886` (Seeed Studio) |
| PID | `0x1667` (primary), `0x1668` (variant) |
| Bootloader product string | "Seeed Wio Tracker L1" |
| 1200-baud touch reset | supported (`use_1200bps_touch: true`) |

### Source references for bootloader / flash layout

- MeshCore board JSON: <https://github.com/meshcore-dev/MeshCore/blob/main/boards/seeed-wio-tracker-l1.json>
- MeshCore S140 v7 linker script: <https://github.com/meshcore-dev/MeshCore/blob/main/boards/nrf52840_s140_v7.ld>
- MeshCore S140 v7 extra-FS linker script: <https://github.com/meshcore-dev/MeshCore/blob/main/boards/nrf52840_s140_v7_extrafs.ld>
- MeshCore Wio Tracker L1 PlatformIO config: <https://github.com/meshcore-dev/MeshCore/blob/main/variants/wio-tracker-l1/platformio.ini>

## Product family / variants

Meshtastic describes the Wio Tracker L1 Series as a compact, low-power Meshtastic device using:

- nRF52840 MCU
- SX1262 LoRa transceiver
- 862–930 MHz LoRa frequency range
- L76K GNSS module
- optional displays:
  - L1 Lite: no display
  - L1: 1.3-inch OLED
  - L1 e-ink: 2.13-inch e-ink
  - L1 Pro: OLED display, case, and integrated battery

Meshtastic also lists these connectors/features:

- USB-C
- U.FL / IPEX LoRa antenna connector
- Battery connector
- Grove connector
- Solar panel connector
- 30-pin OLED display FPC connector
- 24-pin e-ink display FPC connector
- SWD interface

## High-level hardware blocks

The firmware-visible hardware appears to be:

- Nordic nRF52840 MCU
- Semtech SX1262 LoRa radio
- L76K / L76KB GNSS module
- OLED display variant:
  - SH1106 OLED at I²C address `0x3D`
- E-ink display variant:
  - 2.13-inch e-ink display on a second SPI bus
- P25Q16H QSPI flash
- USB-C for power / flashing
- 3.7 V Li-ion battery input
- Solar panel input
- Battery voltage measurement through an ADC divider
- Battery-divider/read-enable control line
- One main user LED and a second firmware-visible LED/buzzer-related pin
- Buzzer on D12 / P1.00
- User/program button
- Five-way joystick / trackball style input:
  - up
  - down
  - left
  - right
  - press
- Grove expansion I²C bus
- SWD debugging/programming

## Pin-source policy

The tables below use the **operational firmware mapping** as the source of truth. The Meshtastic `variant.cpp` file gives the most useful logical-to-physical mapping because it maps D-numbered board pins to nRF52840 port pins.

Some comments in the Meshtastic `variant.h` file appear stale or inconsistent with the `g_ADigitalPinMap[]` table. Where there is a conflict, this document uses the actual `g_ADigitalPinMap[]` numeric values.

The nRF52840 Arduino-style flattened pin numbering is interpreted as:

```text
0..31    → P0.00..P0.31
32..63   → P1.00..P1.31
```

So, for example:

```text
33 → P1.01
46 → P1.14
```

## Reconstructed logical-to-physical pin map

This is the core mapping derived from the Meshtastic `g_ADigitalPinMap[]`.

| Logical pin | nRF52840 pin | Function / comment |
|---:|---:|---|
| D0 | P1.09 | GNSS wakeup / standby / enable |
| D1 | P0.07 | SX1262 DIO1 interrupt |
| D2 | P1.07 | SX1262 reset |
| D3 | P1.10 | SX1262 busy |
| D4 | P1.14 | SX1262 chip select / NSS |
| D5 | P1.08 | LoRa switch / RX enable |
| D6 | P0.27 | GNSS TX line as wired to board logic |
| D7 | P0.26 | GNSS RX line as wired to board logic |
| D8 | P0.30 | SPI SCK for SX1262 |
| D9 | P0.03 | SPI MISO for SX1262 |
| D10 | P0.28 | SPI MOSI for SX1262 |
| D11 | P1.01 | User LED / LoRa TX LED |
| D12 | P1.00 | Buzzer |
| D13 | P0.08 | User / program button |
| D14 | P0.06 | OLED I²C SDA in firmware |
| D15 | P0.05 | OLED I²C SCL in firmware |
| D16 | P0.31 | Battery ADC input |
| D17 | P1.11 | Grove / external I²C line, firmware uses as SCL |
| D18 | P1.12 | Grove / external I²C line, firmware uses as SDA |
| D19 | P0.21 | QSPI SCK |
| D20 | P0.25 | QSPI CS |
| D21 | P0.20 | QSPI IO0 |
| D22 | P0.24 | QSPI IO1 |
| D23 | P0.22 | QSPI IO2 |
| D24 | P0.23 | QSPI IO3 |
| D25 | P1.04 | Joystick / trackball up |
| D26 | P0.12 | Joystick / trackball down |
| D27 | P0.11 | Joystick / trackball left |
| D28 | P1.03 | Joystick / trackball right |
| D29 | P1.05 | Joystick / trackball press |
| D30 | P0.04 | Battery read / battery-divider enable control |
| D31 | P0.13 | E-ink SPI SCK, e-ink variant |
| D32 | P0.14 | E-ink reset, e-ink variant |
| D33 | P0.15 | E-ink SPI MOSI, e-ink variant |
| D34 | P0.16 | E-ink DC, e-ink variant |
| D35 | P0.17 | E-ink busy, e-ink variant |
| D36 | P0.19 | E-ink CS, e-ink variant |
| D37 | not confirmed in Meshtastic map | MeshCore uses this as dummy/unused SPI1 MISO |

## LoRa / SX1262

| Function | Logical pin | nRF52840 pin | Firmware names | Notes |
|---|---:|---:|---|---|
| SPI SCK | D8 | P0.30 | `PIN_SPI_SCK`, `P_LORA_SCLK` | LoRa SPI clock. |
| SPI MISO | D9 | P0.03 | `PIN_SPI_MISO`, `P_LORA_MISO` | LoRa SPI MISO. |
| SPI MOSI | D10 | P0.28 | `PIN_SPI_MOSI`, `P_LORA_MOSI` | LoRa SPI MOSI. |
| CS / NSS | D4 | P1.14 | `SX126X_CS`, `P_LORA_NSS` | LoRa chip select. |
| DIO1 | D1 | P0.07 | `SX126X_DIO1`, `P_LORA_DIO_1` | Interrupt line. |
| Reset | D2 | P1.07 | `SX126X_RESET`, `P_LORA_RESET` | Reset line. |
| Busy | D3 | P1.10 | `SX126X_BUSY`, `P_LORA_BUSY` | Busy input. |
| RX enable / RF switch control | D5 | P1.08 | `SX126X_RXEN` | MeshCore uses RX enable; TX enable is not connected. |
| TX enable | NC | NC | `SX126X_TXEN = RADIOLIB_NC` | No separate TX enable pin in firmware. |
| DIO2 RF switch | internal / radio-side | — | `SX126X_DIO2_AS_RF_SWITCH` | Required for RF switch behavior. |
| DIO3 TCXO | radio-side | — | `SX126X_DIO3_TCXO_VOLTAGE = 1.8` | Used for TCXO power/control. |

MeshCore configures the SX1262 with:

- TX power default: 22 dBm
- current limit: 140 mA
- RX boosted gain enabled
- DIO2 as RF switch
- DIO3 TCXO voltage: 1.8 V

Meshtastic explicitly comments that `SX126X_DIO2_AS_RF_SWITCH` is necessary or TX power will be lost.

## GNSS / GPS

The board uses a Quectel L76K / L76KB GNSS module.

| Function | Logical pin | nRF52840 pin | Firmware names | Notes |
|---|---:|---:|---|---|
| GNSS standby / wake / enable | D0 | P1.09 | `PIN_GPS_STANDBY`, `PIN_GPS_EN` | Standby/wakeup control line. |
| GNSS TX / MCU RX path | D6 | P0.27 | `GPS_TX_PIN`, `PIN_SERIAL1_TX` in Meshtastic naming | Watch direction carefully; Meshtastic comments say this is data from the MCU in one place. |
| GNSS RX / MCU TX path | D7 | P0.26 | `GPS_RX_PIN`, `PIN_SERIAL1_RX` in Meshtastic naming | Watch direction carefully; firmware names are board-signal names, not always “MCU perspective.” |
| GNSS baud rate | — | — | `GPS_BAUDRATE`, `GPS_BAUD_RATE` | 9600 baud. |

The Meshtastic and MeshCore variants both indicate L76K/L76KB GNSS and 9600 baud.

### GPS serial-direction caution

The naming around `GPS_TX_PIN` and `GPS_RX_PIN` is potentially confusing. In Meshtastic:

```c
#define GPS_TX_PIN D6
#define GPS_RX_PIN D7
#define PIN_SERIAL1_RX GPS_RX_PIN
#define PIN_SERIAL1_TX GPS_TX_PIN
```

So for firmware work, use the framework-provided `PIN_SERIAL1_RX` and `PIN_SERIAL1_TX` definitions rather than trying to infer direction from the bare `GPS_TX_PIN` / `GPS_RX_PIN` labels.

## OLED display / L1 Pro display

The L1 Pro uses the OLED variant according to Meshtastic’s product-family docs: “L1 Pro (with OLED display, case and battery).”

Firmware identifies the OLED as an SH1106 display at I²C address `0x3D`.

| Function | Logical pin | nRF52840 pin | Firmware names | Notes |
|---|---:|---:|---|---|
| OLED SDA | D14 | P0.06 | `PIN_WIRE_SDA` in OLED/L1 builds | Main I²C bus SDA for OLED. |
| OLED SCL | D15 | P0.05 | `PIN_WIRE_SCL` in OLED/L1 builds | Main I²C bus SCL for OLED. |
| OLED address | — | — | `DISPLAY_ADDRESS = 0x3D` | SH1106 OLED I²C address. |
| OLED reset | NC / -1 | — | `PIN_OLED_RESET = -1` | MeshCore sets OLED reset to `-1`. |

In MeshCore, the default WioTrackerL1 build uses `SH1106Display`.

## E-ink display variant

The L1 e-ink is a separate variant with a 2.13-inch e-ink display. Meshtastic and MeshCore both have e-ink-capable pin definitions.

| Function | Logical pin | nRF52840 pin | Firmware names | Notes |
|---|---:|---:|---|---|
| E-ink SPI SCK | D31 | P0.13 | `PIN_EINK_SCLK`, `PIN_SPI1_SCK` | E-ink SPI clock. |
| E-ink SPI MOSI | D33 | P0.15 | `PIN_EINK_MOSI`, `PIN_SPI1_MOSI` | E-ink SPI MOSI. |
| E-ink CS | D36 | P0.19 | `PIN_EINK_CS`, `PIN_DISPLAY_CS` | E-ink chip select. |
| E-ink busy | D35 | P0.17 | `PIN_EINK_BUSY`, `PIN_DISPLAY_BUSY` | Busy input. |
| E-ink DC | D34 | P0.16 | `PIN_EINK_DC`, `PIN_DISPLAY_DC` | Data/command. |
| E-ink reset | D32 | P0.14 | `PIN_EINK_RES`, `PIN_DISPLAY_RST` | Reset line. |
| E-ink enable | D14 in Meshtastic e-ink variant | P0.06 | `PIN_EINK_EN` | Marked “unused” in Meshtastic e-ink variant. |
| E-ink MISO | NC / dummy | — | `PIN_SPI1_MISO = -1` or dummy D37 | E-ink does not normally need MISO. |

The e-ink firmware uses `SPI_INTERFACES_COUNT = 2`, with LoRa on the primary SPI bus and e-ink on SPI1.

## QSPI flash

The board exposes P25Q16H QSPI flash.

| Function | Logical pin | nRF52840 pin | Firmware names |
|---|---:|---:|---|
| QSPI SCK | D19 | P0.21 | `PIN_QSPI_SCK` |
| QSPI CS | D20 | P0.25 | `PIN_QSPI_CS` |
| QSPI IO0 | D21 | P0.20 | `PIN_QSPI_IO0` |
| QSPI IO1 | D22 | P0.24 | `PIN_QSPI_IO1` |
| QSPI IO2 | D23 | P0.22 | `PIN_QSPI_IO2` |
| QSPI IO3 | D24 | P0.23 | `PIN_QSPI_IO3` |

Meshtastic’s `initVariant()` sets QSPI CS as an output and drives it high during initialization.

## Buttons / joystick / trackball

| Function | Logical pin | nRF52840 pin | Firmware names | Notes |
|---|---:|---:|---|---|
| User/program/back button | D13 | P0.08 | `CANCEL_BUTTON_PIN`, `PIN_BUTTON1`, `PIN_BACK_BTN` | Meshtastic uses as cancel/program button; MeshCore uses as back/menu button. |
| Joystick up | D25 | P1.04 | `TB_UP`, `PIN_BUTTON2`, `JOYSTICK_UP` | Input pullup in MeshCore. |
| Joystick down | D26 | P0.12 | `TB_DOWN`, `PIN_BUTTON3`, `JOYSTICK_DOWN` | Input pullup in MeshCore. |
| Joystick left | D27 | P0.11 | `TB_LEFT`, `PIN_BUTTON4`, `JOYSTICK_LEFT` | Input pullup in MeshCore. |
| Joystick right | D28 | P1.03 | `TB_RIGHT`, `PIN_BUTTON5`, `JOYSTICK_RIGHT` | Input pullup in MeshCore. |
| Joystick press | D29 | P1.05 | `TB_PRESS`, `PIN_BUTTON6`, `JOYSTICK_PRESS`, `PIN_USER_BTN` | Input pullup in MeshCore. |

Meshtastic defines `HAS_TRACKBALL = 1` and `TB_DIRECTION = FALLING`, implying the trackball/joystick lines are active-low or falling-edge signaled.

MeshCore configures all six button pins as `INPUT_PULLUP`.

## LEDs and buzzer

| Function | Logical pin | nRF52840 pin | Firmware names | Notes |
|---|---:|---:|---|---|
| User LED / TX LED | D11 | P1.01 | `PIN_LED`, `PIN_LED1`, `LED_GREEN`, `P_LORA_TX_LED` | Active high. MeshCore turns it on before TX and off after TX. |
| Secondary LED / blue LED / buzzer-adjacent pin | D12 | P1.00 | `PIN_LED2`, `LED_BLUE`, `PIN_BUZZER` | Meshtastic names D12 as LED2 in one section and buzzer in another; MeshCore defines `PIN_BUZZER=12` for companion-radio builds. |
| Buzzer | D12 | P1.00 | `PIN_BUZZER` | PWM output. |

The practical firmware mapping is:

```text
D11 / P1.01 → user/TX LED, active high
D12 / P1.00 → buzzer output
```

There is some naming overlap because Meshtastic’s L1 variant initially defines `PIN_LED2 (12)` and later defines `PIN_BUZZER D12`. Treat D12 as the buzzer unless you verify your exact board revision has a second LED on that signal.

## I²C buses and expansion

The firmware exposes two I²C buses.

### Main OLED I²C bus

| Function | Logical pin | nRF52840 pin | Notes |
|---|---:|---:|---|
| SDA | D14 | P0.06 | OLED SDA. |
| SCL | D15 | P0.05 | OLED SCL. |

The OLED display is at address `0x3D`.

### Grove / external I²C bus

| Function | Logical pin | nRF52840 pin | Notes |
|---|---:|---:|---|
| SDA | D18 | P1.12 | Firmware uses this as `PIN_WIRE1_SDA`. |
| SCL | D17 | P1.11 | Firmware uses this as `PIN_WIRE1_SCL`. |

There is a comment inconsistency in Meshtastic’s `variant.cpp`: it labels D17 as `GROVESDA` and D18 as `GROVESCL`, but both Meshtastic and MeshCore operational macros use D18 as SDA and D17 as SCL. This document follows the macros, not the stale comments.

MeshCore companion BLE builds route environmental sensor pins to this Grove bus:

```text
ENV_PIN_SDA = PIN_WIRE1_SDA
ENV_PIN_SCL = PIN_WIRE1_SCL
```

## Battery voltage measurement

Battery voltage is measured on:

```text
D16 / P0.31 → VBAT ADC
```

Firmware configuration:

```c
BATTERY_PIN = PIN_VBAT = D16
AREF_VOLTAGE = 3.6
ADC_MULTIPLIER = 2.0
ADC_RESOLUTION = 12
```

MeshCore’s battery read formula is:

```c
return (adcvalue * ADC_MULTIPLIER * AREF_VOLTAGE) / 4.096;
```

With `ADC_MULTIPLIER = 2.0` and `AREF_VOLTAGE = 3.6`, this corresponds to:

```text
battery_mV = raw_adc * 2.0 * 3.6 / 4.096
```

which is equivalent to:

```text
battery_mV ≈ raw_adc * 1.7578125
```

That implies a half-voltage divider and a 3.6 V ADC reference.

### Battery read enable / divider enable

There is a separate control line:

```text
D30 / P0.04 → BAT_READ / VBAT_ENABLE
```

Meshtastic initializes this as an output and drives it high:

```c
pinMode(BAT_READ, OUTPUT);
digitalWrite(BAT_READ, HIGH);
```

This strongly suggests D30 enables the battery measurement path, likely by enabling the resistor divider or related analog front-end. MeshCore defines `VBAT_ENABLE = 30` but the board helper excerpt I found does not drive it during `begin()` or `getBattMilliVolts()`.

Practical interpretation:

- D16/P0.31 is the ADC measurement input.
- D30/P0.04 probably enables or biases the battery measurement divider.
- If battery readings are wrong in custom firmware, ensure D30 is configured the same way Meshtastic does.

## Power architecture

Meshtastic’s device documentation says the Wio Tracker L1 supports **triple power input**:

- USB-C fast charging
- Solar
- 3.7 V Li-ion battery

The firmware-visible power-management details are much more limited than on boards with explicit PMIC definitions.

### What firmware definitely exposes

Firmware exposes:

- battery ADC input on D16/P0.31,
- battery-read/divider-enable line on D30/P0.04,
- nRF52840 System OFF sleep,
- possibly USB/DFU behavior through the bootloader,
- no obvious I²C PMIC or charger-status interface in the variant files.

MeshCore’s `powerOff()` implementation for WioTrackerL1 simply calls:

```c
sd_power_system_off();
```

It does not explicitly disable a peripheral power rail.

This is different from the LilyGO T-Echo, where firmware drives a peripheral power-enable pin low before system-off. On Wio Tracker L1, I did not find an equivalent general `PIN_POWER_EN` for all peripherals.

### Likely “off” behavior

The firmware “off” state is best understood as:

1. nRF52840 enters System OFF.
2. Any peripherals that are not separately powered down may remain powered depending on hardware design.
3. Wake behavior depends on configured GPIO sense, reset/bootloader behavior, USB, and possibly button wiring.
4. Battery/charger/solar power-path behavior is handled by onboard analog/power circuitry, not by a firmware-controlled PMIC interface.

Without a schematic, I would not assume:

- firmware can hard-disconnect the battery,
- firmware can configure charge current,
- firmware can query charger status,
- firmware can disconnect all peripherals from power.

## Low-battery shutdown

Meshtastic’s e-ink variant defines a custom OCV array:

```c
#define OCV_ARRAY 4200, 3876, 3826, 3763, 3713, 3660, 3573, 3485, 3422, 3359, 3300
```

The bottom value is 3300 mV. In Meshtastic’s generic power system, the bottom of the OCV table is commonly used as the low-battery threshold for repeated low readings while not externally powered.

The OLED/non-e-ink Meshtastic variant excerpt I found did not define the custom OCV array, so it may use generic defaults unless overridden elsewhere.

MeshCore exposes user-facing battery shutdown threshold settings in the companion UI, including:

```text
OFF / 3300 / 3400 / 3500 / 3600 mV
```

This means there is definitely **firmware-level** low-battery shutdown support, but I did not find evidence of a firmware-controlled **hardware** battery cutoff.

## RTC / wall-clock time

I did not find a board-specific dedicated RTC chip definition in the Wio Tracker L1 variant headers.

MeshCore creates:

```c
VolatileRTCClock fallback_clock;
AutoDiscoverRTCClock rtc_clock(fallback_clock);
```

and calls:

```c
rtc_clock.begin(Wire);
```

This means MeshCore can use an RTC if it discovers one on the I²C bus, but falls back to a volatile clock otherwise.

Practical interpretation:

- The board definitions do not prove an onboard always-powered RTC.
- Wall-clock retention across System OFF should not be assumed unless you verify a real RTC on the board or attach one over I²C/Grove.
- GNSS can restore time after a fix, and firmware can maintain volatile time while running, but that is not the same as persistent wall-clock time while “off.”

## Displays and Pro/e-ink distinction

The product-family naming matters:

- **L1 Lite**: no display.
- **L1 / L1 Pro**: OLED display path, SH1106 at `0x3D`.
- **L1 e-ink**: separate SPI e-ink display path.

The L1 Pro is described by Meshtastic as the OLED variant with case and integrated battery, not the e-ink variant. If you have a “Pro” unit with an OLED, use the OLED/I²C pin map. If your unit has a 2.13-inch e-ink display, use the e-ink/SPI1 pin map.

## Mental block diagram

```text
USB-C input
   ├── nRF52840 USB / UF2 / DFU bootloader path
   └── charger / power-path circuitry
          ├── 3.7 V Li-ion battery
          ├── solar input path
          └── system power rails

Li-ion battery
   ├── charger / solar power path
   └── divider / gated sense path
          ├── D30 / P0.04 → battery-sense enable / BAT_READ
          └── D16 / P0.31 → battery ADC

nRF52840
   ├── SPI0 → SX1262 LoRa
   │      ├── DIO1 interrupt
   │      ├── BUSY
   │      ├── RESET
   │      ├── RF switch / RX enable
   │      └── TCXO via DIO3 at 1.8 V
   ├── UART1 → L76K GNSS
   │      └── standby/wakeup control
   ├── I²C0 → SH1106 OLED at 0x3D
   ├── I²C1 → Grove / expansion sensors
   ├── QSPI → P25Q16H external flash
   ├── GPIO → user LED, buzzer, user button, joystick/trackball
   ├── SPI1 → optional 2.13-inch e-ink display
   └── System OFF sleep
```

## Practical firmware notes

- Use Meshtastic/MeshCore logical D-pin definitions rather than stale comments.
- For L1 Pro/OLED, the display is SH1106 on I²C address `0x3D` using D14/D15.
- For L1 e-ink, use the SPI1 e-ink pins D31–D36.
- Use D16/P0.31 for battery ADC.
- Drive D30/P0.04 high as Meshtastic does if battery measurement does not work.
- Use D11/P1.01 as the active-high user/TX LED.
- Use D12/P1.00 as the buzzer output.
- Treat joystick/trackball inputs as pullup/active-low/falling-edge signals.
- Do not assume an onboard RTC unless verified.
- Do not assume firmware-visible charger status or PMIC control.
- Do not assume System OFF cuts power to all peripherals.

## Source references

- Meshtastic Wio Tracker L1 docs source: <https://github.com/meshtastic/meshtastic/blob/master/docs/hardware/devices/seeed-studio/wio-series/wio-tracker-l1.mdx>
- Meshtastic Wio Tracker L1 board metadata: <https://github.com/meshtastic/firmware/blob/master/boards/seeed_wio_tracker_L1.json>
- Meshtastic Wio Tracker L1 OLED variant header: <https://github.com/meshtastic/firmware/blob/master/variants/nrf52840/seeed_wio_tracker_L1/variant.h>
- Meshtastic Wio Tracker L1 OLED variant implementation: <https://github.com/meshtastic/firmware/blob/master/variants/nrf52840/seeed_wio_tracker_L1/variant.cpp>
- Meshtastic Wio Tracker L1 e-ink variant header: <https://github.com/meshtastic/firmware/blob/master/variants/nrf52840/seeed_wio_tracker_L1_eink/variant.h>
- Meshtastic Wio Tracker L1 e-ink variant implementation: <https://github.com/meshtastic/firmware/blob/master/variants/nrf52840/seeed_wio_tracker_L1_eink/variant.cpp>
- Meshtastic Wio Tracker L1 PlatformIO config: <https://github.com/meshtastic/firmware/blob/master/variants/nrf52840/seeed_wio_tracker_L1/platformio.ini>
- MeshCore Wio Tracker L1 board metadata: <https://github.com/meshcore-dev/MeshCore/blob/main/boards/seeed-wio-tracker-l1.json>
- MeshCore Wio Tracker L1 variant header: <https://github.com/meshcore-dev/MeshCore/blob/main/variants/wio-tracker-l1/variant.h>
- MeshCore Wio Tracker L1 board helper: <https://github.com/meshcore-dev/MeshCore/blob/main/variants/wio-tracker-l1/WioTrackerL1Board.h>
- MeshCore Wio Tracker L1 board startup: <https://github.com/meshcore-dev/MeshCore/blob/main/variants/wio-tracker-l1/WioTrackerL1Board.cpp>
- MeshCore Wio Tracker L1 target: <https://github.com/meshcore-dev/MeshCore/blob/main/variants/wio-tracker-l1/target.cpp>
- MeshCore Wio Tracker L1 PlatformIO config: <https://github.com/meshcore-dev/MeshCore/blob/main/variants/wio-tracker-l1/platformio.ini>
- Community Wio Tracker L1 e-ink notes: <https://github.com/mvacoss/Meshtastic-on-Wio-Tracker-L1>
- Community MeshCore Wio Tracker L1 Pro firmware: <https://github.com/sosprz/Meshcore-Wio-Tracker-L1-Pro>
