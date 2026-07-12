# LilyGo T-LoRa Pager Hardware Reference

**Purpose:** Firmware-porting reference for the LilyGo T-LoRa Pager / T-LoRa-Pager platform.

**Status:** Best-effort, source-derived reference. Treat the **Meshtastic `tlora-pager` variant** as the primary authority for pin assignments. Treat LilyGoLib and the schematic as secondary cross-checks. MeshCore does not appear to have a T-LoRa Pager-specific variant in the searched public source tree; it only has nearby LilyGo variants such as T-Deck, so MeshCore is not used as a pinout authority here except as a contrast point.

**Most important caveat:** LilyGo now publishes a schematic named `schematic/T-Lora Pager V1.0 SCH 25-06-13.pdf` in `Xinyuan-LilyGO/LilyGoLib`, but this reference prioritizes firmware pin definitions. The schematic should still be inspected manually before doing electrical work, especially for the top expansion connector and charger/power-path details.

## Sources consulted

Primary:

- Meshtastic `variants/esp32s3/tlora-pager/platformio.ini`
- Meshtastic `variants/esp32s3/tlora-pager/variant.h`
- Meshtastic `src/input/TLoraPagerKeyboard.cpp`
- Meshtastic `src/Power.cpp` / `src/power.h`

Secondary:

- LilyGoLib `src/LilyGo_LoRa_Pager.cpp`
- LilyGoLib `src/LilyGo_LoRa_Pager.h`
- LilyGoLib `docs/lilygo-t-lora-pager.md`
- LilyGoLib `schematic/T-Lora Pager V1.0 SCH 25-06-13.pdf`
- MeshCore `variants/lilygo_tdeck/*` as a nearby but different platform

## Board identity and build assumptions

Meshtastic identifies this as:

- Hardware model slug: `T_LORA_PAGER`
- Architecture: `esp32-s3`
- Actively supported: yes
- Support level: `1`
- Display name: `LILYGO T-LoRa Pager`
- Partition scheme: 16 MB
- Requires DFU: yes
- MUI/device UI enabled

Meshtastic builds the target using PlatformIO board `t-deck-pro`, with a dedicated `variants/esp32s3/tlora-pager` source/include directory. Do not assume the T-Deck Pro pinout is the same; the T-LoRa Pager variant overrides many pins.

LilyGo’s Arduino documentation identifies the Arduino board as `LilyGo-T-LoRa-Pager`, with a 16 MB flash partition scheme and selectable radio module revisions.

## Radio variants

LilyGo documentation lists the following selectable board/radio revisions:

- `Radio-SX1262` — sub-GHz LoRa
- `Radio-SX1280` — 2.4 GHz LoRa
- `Radio-CC1101` — sub-GHz FSK/GFSK/ASK/OOK family
- `Radio-LR1121` — sub-GHz + 2.4 GHz LoRa
- `Radio-SI4432` — sub-GHz ISM

Meshtastic’s `tlora-pager` variant declares support macros for:

- `USE_SX1262`
- `USE_SX1268`
- `USE_SX1280`
- `USE_LR1121`

Meshtastic does **not** list CC1101 or SI4432 in the `tlora-pager` variant. LilyGoLib does have conditional construction paths for SX1262, SX1280, CC1101, LR1121, and SI4432. This is a real source discrepancy: LilyGo’s library/docs are broader than Meshtastic’s currently-declared variant.

## ESP32-S3 direct pin map

Authoritative source for this table: Meshtastic `variants/esp32s3/tlora-pager/variant.h`.

### TFT display: ST7796

| Signal | ESP32-S3 GPIO | Notes |
|---|---:|---|
| `TFT_CS` / `ST7796_CS` | 38 | Display chip select |
| `ST7796_RS` / DC | 37 | Display data/command |
| `ST7796_SDA` | `MOSI` | Uses global SPI MOSI alias |
| `ST7796_SCK` | `SCK` | Uses global SPI SCK alias |
| `ST7796_MISO` | `MISO` | Uses global SPI MISO alias |
| `ST7796_RESET` | -1 | No direct reset GPIO in Meshtastic variant |
| `ST7796_BUSY` | -1 | Not used |
| `ST7796_BL` / `TFT_BL` | 42 | Display backlight |
| SPI host | `SPI2_HOST` | Meshtastic display host |
| SPI frequency | 75 MHz | `SPI_FREQUENCY` |
| SPI read frequency | 16 MHz | `SPI_READ_FREQUENCY` |
| Logical width | 222 | `TFT_WIDTH` |
| Logical height | 480 | `TFT_HEIGHT` |
| X offset | 49 | `TFT_OFFSET_X` |
| Y offset | 0 | `TFT_OFFSET_Y` |
| Rotation offset | 3 | `TFT_OFFSET_ROTATION` |

Meshtastic display build flags use `LGFX_SCREEN_WIDTH=222`, `LGFX_SCREEN_HEIGHT=480`, and `DISPLAY_SIZE=480x222` for landscape-mode UI. This is not a typo: the panel is treated as 222×480 at the driver level, with the UI configured as 480×222 landscape.

**Touch:** No touchscreen support is apparent in the Meshtastic `tlora-pager` variant. The variant has no touch-controller pins or touch driver flags. LilyGoLib initialization also initializes display, keyboard, rotary, haptic, GPS, LoRa, SD, NFC, RTC, sensor, audio codec, fuel gauge, and charger, but not a touch controller. Treat the screen as **non-touch** unless the schematic or a later hardware revision proves otherwise.

### LoRa / radio SPI bus

| Signal | ESP32-S3 GPIO | Notes |
|---|---:|---|
| `LORA_SCK` | 35 | Radio SPI SCK |
| `LORA_MISO` | 33 | Radio SPI MISO |
| `LORA_MOSI` | 34 | Radio SPI MOSI |
| `LORA_CS` / NSS | 36 | Radio chip select |
| `LORA_RESET` | 47 | Radio reset |
| `LORA_DIO0` | -1 | Not connected for SX126x module |
| `LORA_DIO1` / IRQ | 14 | SX126x/LR1121 IRQ |
| `LORA_DIO2` / BUSY | 48 | SX126x/LR1121 BUSY |
| `LORA_DIO3` | macro only | Comment says not connected on PCB, but internally used on TTGO SX1262 for TCXO enable |

Radio aliases in Meshtastic:

| Radio family | CS/NSS | IRQ/DIO1 | BUSY | RESET | Extra notes |
|---|---:|---:|---:|---:|---|
| SX126x | 36 | 14 | 48 | 47 | `SX126X_DIO2_AS_RF_SWITCH`, `SX126X_DIO3_TCXO_VOLTAGE=3.0` |
| SX128x | 36 | 14 | 48 | 47 | Same control pins |
| LR1121/LR11x0 | 36 | 14 | 48 | 47 | `LR11X0_DIO3_TCXO_VOLTAGE=3.0`, `LR11X0_DIO_AS_RF_SWITCH` |

LilyGoLib’s LoRa init for LR1121 sets an RF switch table using LR11x0 DIO5/DIO6 and sets TCXO voltage to 3.0 V. For SX126x, Meshtastic declares DIO2-as-RF-switch and 3.0 V TCXO.

### GPS / GNSS

| Signal | ESP32-S3 GPIO | Notes |
|---|---:|---|
| `GPS_RX_PIN` | 4 | ESP32 RX, GPS TX |
| `GPS_TX_PIN` | 12 | ESP32 TX, GPS RX |
| `PIN_GPS_PPS` | 13 | PPS input |
| Baud | 38400 | Default |

LilyGoLib initializes GPS on `Serial1` at 38400 baud.

### Rotary encoder and boot button

| Signal | ESP32-S3 GPIO | Notes |
|---|---:|---|
| `ROTARY_A` | 40 | Rotary encoder A |
| `ROTARY_B` | 41 | Rotary encoder B |
| `ROTARY_PRESS` | 7 | Encoder push button |
| `BUTTON_PIN` | 0 | ESP32 boot/user button |

Meshtastic build flags also declare:

- `INPUTDRIVER_ROTARY_TYPE=1`
- `INPUTDRIVER_ROTARY_UP=40`
- `INPUTDRIVER_ROTARY_DOWN=41`
- `INPUTDRIVER_ROTARY_BTN=7`
- `ENABLE_ROTARY_PULLUP`
- `ENABLE_BUTTON_PULLUP`
- `ROTARY_BUXTRONICS`

LilyGoLib only allows wake from the boot button and rotary button in its `checkWakeupPins()` helper.

### SD card

| Signal | ESP32-S3 GPIO | Notes |
|---|---:|---|
| `SDCARD_CS` / `SPI_CS` | 21 | SD card chip select |
| `SPI_MOSI` | `MOSI` | Shared SPI alias in Meshtastic variant |
| `SPI_SCK` | `SCK` | Shared SPI alias in Meshtastic variant |
| `SPI_MISO` | `MISO` | Shared SPI alias in Meshtastic variant |
| `SD_SPI_FREQUENCY` | 75 MHz | Meshtastic variant value |

The SD card has additional power/detect control through the XL9555 expander: `EXPANDS_SD_DET`, `EXPANDS_SD_PULLEN`, and `EXPANDS_SD_EN`.

### Keyboard

| Function | Pin / bus | Notes |
|---|---:|---|
| Keyboard controller | I2C | TCA8418 keyboard controller |
| `KB_INT` | 6 | Keyboard interrupt |
| `KB_BL_PIN` | 46 | Keyboard backlight PWM/output |
| Matrix size | 4 rows × 10 columns | Meshtastic keyboard driver |
| Number of logical keys | 31 | Meshtastic keyboard driver |

Meshtastic implements a T-LoRa Pager-specific TCA8418 keyboard driver. It defines a 4×10 matrix, 31 logical keys, a tap map for qwerty-style input, right-shift and symbol modifiers, haptic feedback, and keyboard backlight control via GPIO46.

LilyGoLib’s own keymap is also 4×10 and maps the main rows to qwerty letters, symbols, and space/backspace-like functions. This agrees with Meshtastic at the high level, though the exact higher-level input behavior differs.

### Haptic driver

| Function | Interface | Notes |
|---|---|---|
| Haptic driver | I2C | DRV2605 |
| Power enable | XL9555 `EXPANDS_DRV_EN` bit 0 | Secondary power control |

Meshtastic declares `HAS_DRV2605`. LilyGoLib initializes DRV2605 at I2C address 0x5A, selects library 1, internal trigger mode, and ERM mode.

### Audio codec / speaker amplifier

| Signal | ESP32-S3 GPIO | Notes |
|---|---:|---|
| `DAC_I2S_MCLK` | 10 | ES8311 MCLK |
| `DAC_I2S_BCK` | 11 | I2S BCLK |
| `DAC_I2S_WS` | 18 | I2S word-select/LRCLK |
| `DAC_I2S_DOUT` | 45 | ESP32 data out to codec |
| `DAC_I2S_DIN` | 17 | Codec data in to ESP32 |
| Codec I2C | `Wire` | ES8311 on I2C |
| Amplifier enable | XL9555 `EXPANDS_AMP_EN` bit 1 | Secondary power control |

Meshtastic’s variant-specific late init configures an ES8311 codec with I2C and I2S pins, line input, all outputs, 16-bit samples, 44 kHz rate, and 75% volume.

### NFC

| Signal | ESP32-S3 GPIO | Notes |
|---|---:|---|
| `NFC_INT` | 5 | NFC interrupt |
| `NFC_CS` | 39 | NFC SPI chip select |
| NFC power enable | XL9555 `EXPANDS_NFC_EN` bit 5 | Secondary power control |

LilyGoLib uses an ST25R3916 NFC frontend on SPI and constructs `RfalRfST25R3916Class nfc_hw(&SPI, NFC_CS, NFC_INT)`.

### IMU / sensor hub

| Function | Interface | Notes |
|---|---|---|
| BHI260AP | I2C | Bosch sensor hub / IMU |
| Sensor interrupt | not assigned in Meshtastic `variant.h` | LilyGoLib uses `SENSOR_INT`, but the Meshtastic variant only declares `HAS_BHI260AP` |

LilyGoLib initializes BHI260AP over I2C, temporarily increases I2C to 1 MHz for sensor initialization, loads Bosch firmware, sets axis remap, and attaches `SENSOR_INT` rising-edge interrupt. The Meshtastic variant does not expose the BHI interrupt pin in the lines inspected, so confirm against schematic or upstream code before relying on interrupts.

### RTC

| Function | Interface / address | Notes |
|---|---|---|
| PCF85063 RTC | I2C, address 0x51 | Meshtastic variant defines `PCF85063_RTC 0x51` |

LilyGoLib initializes PCF85063, reads hardware clock, disables clock output (`CLK_LOW`), and attaches an interrupt to `RTC_INT`. The Meshtastic variant declares the RTC address but not a direct `RTC_INT` pin in the inspected `variant.h`.

## I2C bus

Meshtastic aliases:

| Signal | Value |
|---|---|
| `I2C_SDA` | `SDA` |
| `I2C_SCL` | `SCL` |

The actual numeric values of `SDA` and `SCL` are inherited from the PlatformIO/Arduino board definition (`t-deck-pro`) unless overridden elsewhere. Do not hard-code them without checking the board package or compiled preprocessor output.

Devices known or likely on the main I2C bus:

| Device | Role | Source confidence |
|---|---|---|
| BQ25896 | Li-Ion charger / power-path / PPM | High: Meshtastic `HAS_PPM`, LilyGoLib `PowersBQ25896` |
| BQ27220 | Battery fuel gauge | High: Meshtastic `HAS_BQ27220`, LilyGoLib `GaugeBQ27220` |
| XL9555 | I/O expander | High: Meshtastic `USE_XL9555`, LilyGoLib initializes at 0x20 |
| TCA8418 | Keyboard controller | High: Meshtastic keyboard driver |
| DRV2605 | Haptic driver | High: Meshtastic `HAS_DRV2605`, LilyGoLib init |
| PCF85063 | RTC | High: Meshtastic address define |
| BHI260AP | IMU/sensor hub | High: Meshtastic `HAS_BHI260AP`, LilyGoLib init |
| ES8311 | Audio codec | High: Meshtastic audio init |

## XL9555 I/O expander map

Authoritative source: Meshtastic `tlora-pager` variant.

| XL9555 bit | Name | Function |
|---:|---|---|
| 0 | `EXPANDS_DRV_EN` | Haptic driver enable |
| 1 | `EXPANDS_AMP_EN` | Audio amplifier enable |
| 2 | `EXPANDS_KB_RST` | Keyboard reset |
| 3 | `EXPANDS_LORA_EN` | Radio power/enable |
| 4 | `EXPANDS_GPS_EN` | GPS power/enable |
| 5 | `EXPANDS_NFC_EN` | NFC power/enable |
| 7 | `EXPANDS_GPS_RST` | GPS reset |
| 8 | `EXPANDS_KB_EN` | Keyboard power/enable |
| 9 | `EXPANDS_GPIO_EN` | External/GPIO power enable; exact connector behavior needs schematic confirmation |
| 10 | `EXPANDS_SD_DET` | SD card detect |
| 11 | `EXPANDS_SD_PULLEN` | SD pull-up enable |
| 12 | `EXPANDS_SD_EN` | SD card power/enable |

LilyGoLib initializes the XL9555 at I2C address `0x20`, sets many of these lines as outputs, and generally drives power-enables high during initialization. During sleep it drives many expander outputs low, ends SPI/Wire/Serial1, disables backlight, and places many ESP32 pins into open-drain/reset states.

## Battery, charger, and power management

### Charger / power-path IC

Meshtastic declares:

- `HAS_PPM 1`
- `XPOWERS_CHIP_BQ25896`

LilyGoLib’s `LilyGoLoRaPager` contains:

- `PowersBQ25896 ppm`
- `GaugeBQ27220 gauge`

LilyGoLib initializes the charger/power-path manager using the main I2C bus:

```cpp
ppm.init(Wire, SDA, SCL);
ppm.resetDefault();
ppm.setChargeTargetVoltage(4288);
ppm.setChargerConstantCurr(704);
ppm.enableMeasure();
```

Interpretation:

- The ESP32-S3 talks to the BQ25896 over I2C, not through dedicated status GPIOs in the Meshtastic variant.
- LilyGoLib configures a charge target of 4288 mV and a constant-current charge current of 704 mA.
- The firmware can enable/disable measurement through the BQ25896 library.
- No dedicated `PG`, `STAT`, `INT`, `CE`, or OTG pin is exposed by Meshtastic’s `tlora-pager` variant. Such pins may exist electrically, but they are not part of the authoritative Meshtastic pinout reviewed here.

### Fuel gauge

Meshtastic declares:

- `HAS_BQ27220 1`
- `BQ27220_DESIGN_CAPACITY 1500`
- `BQ27220_I2C_SDA SDA`
- `BQ27220_I2C_SCL SCL`

LilyGoLib initializes the BQ27220 fuel gauge on the same I2C bus and sets design/full-charge capacity to 1500 mAh.

### Low-battery cut-off

There are two distinct questions:

1. **Does firmware attempt to protect the battery?** Yes. Meshtastic’s generic power code tracks battery voltage and triggers a low-battery event after repeated low readings. The default Li-Ion open-circuit-voltage table bottoms out at 3100 mV. If a device has a battery, is not USB-powered, and reports below the bottom OCV entry for more than 10 readings, Meshtastic triggers `EVENT_LOW_BATTERY`, which leads toward sleep/shutdown behavior.

2. **Is there a hardware low-battery disconnect that prevents all drain?** Not proven from the firmware alone. The presence of BQ25896 and BQ27220 gives charger/power-path and fuel-gauge functionality, but the reviewed firmware does not prove that the board has a dedicated battery-protection FET or a hard low-voltage disconnect that fully isolates the cell. Assume Meshtastic provides a **software low-voltage sleep mechanism**, not a guaranteed hardware cut-off, unless confirmed in the schematic or by measuring the board.

Practical porting implication: implement a conservative low-battery policy yourself. Do not rely on deep sleep alone as a complete Li-Ion protection mechanism unless the hardware schematic confirms cell protection.

### Power button / hard off

No conventional PMU power-button pin is exposed in the Meshtastic `tlora-pager` variant. Inputs available for wake/control are the ESP32 boot button (`GPIO0`) and rotary press (`GPIO7`).

LilyGoLib’s sleep helper explicitly says the T-LoRa-Pager allows wake sources from the boot button and rotary button. It powers down/disables many peripherals before ESP32 deep sleep, but this is still an ESP32 sleep state, not necessarily a true battery disconnect.

## External/top expansion connector

This is the least certain area.

What the firmware says:

- Meshtastic defines `EXPANDS_GPIO_EN` on XL9555 bit 9, suggesting some external GPIO/expansion power-enable domain.
- LilyGoLib contains an optional nRF24 external-module object:

```cpp
nRF24 nrf24 = new Module(44 /* CS */, 9 /* IRQ */, 43 /* CE */);
```

This strongly suggests that at least GPIO44, GPIO9, and GPIO43 are intended for some external RF/expansion use, likely exposed on or routed to an expansion connector/module interface. However, the reviewed firmware does **not** provide a full top-connector pinout: power pins, ground pins, SPI mapping, I2C exposure, voltage levels, and mechanical pin order need schematic confirmation.

Porting recommendation:

- Treat the expansion connector pinout as **not fully resolved** from firmware alone.
- Use the published LilyGo schematic to verify connector numbering and electrical constraints.
- If writing firmware before schematic verification, avoid driving GPIO43/44/9 or `EXPANDS_GPIO_EN` until you know what is attached.

## Sleep / wake behavior

LilyGoLib sleep behavior:

- Disables BQ25896 measurement before sleep and re-enables it after light sleep.
- Sleeps radio.
- Ends keyboard, SD, display, GPS serial, SPI, Wire, and Serial in deep sleep path.
- Disables power domains for haptic, GPS, speaker/amp, NFC, keyboard, SD, and radio through XL9555 or sensor-expander paths.
- Configures wake from timer, boot button (`GPIO0`), and/or rotary button (`GPIO7`) depending on requested wake source.

Meshtastic generic power behavior:

- Reads battery presence, USB power, charge state, voltage, and battery percent through the selected battery/PMU abstraction.
- Triggers low-battery behavior after repeated readings below the bottom of the OCV table while not USB-powered.
- Uses deep sleep for shutdown on ESP32-class devices.

## Known discrepancies / uncertain points

| Topic | Meshtastic / MeshCore authority | LilyGo / other source | Recommendation |
|---|---|---|---|
| Radio variants | Meshtastic `tlora-pager` declares SX1262, SX1268, SX1280, LR1121 | LilyGo docs/source also list CC1101 and SI4432 | For Meshtastic-derived ports, support the Meshtastic set first. Add CC1101/SI4432 only after checking LilyGoLib and hardware revision. |
| PlatformIO board | Meshtastic uses `board = t-deck-pro` | Device is not physically a T-Deck Pro | Do not inherit T-Deck Pro pins blindly; use `tlora-pager/variant.h`. |
| Touch screen | No Meshtastic touch config found | LilyGoLib also does not initialize touch | Treat as non-touch. |
| Battery cut-off | Meshtastic implements software low-voltage sleep threshold | Hardware schematic may reveal more | Do not assume hard battery disconnect until schematic confirms it. |
| I2C pin numbers | Meshtastic uses `SDA`/`SCL` aliases, not numeric literals | LilyGoLib also uses `SDA`/`SCL` | Check preprocessed board definitions or schematic for final numeric GPIOs. |
| Top expansion connector | Not fully specified by Meshtastic | LilyGoLib has nRF24 pins 44/9/43 and schematic likely has connector | Treat full connector pinout as unresolved pending schematic inspection. |
| BHI260AP/RTC interrupt pins | LilyGoLib uses `SENSOR_INT` and `RTC_INT` symbols | Meshtastic variant lines inspected do not define numeric values | Verify in schematic or board package before using interrupts. |

## Minimal bring-up checklist for a new firmware port

1. Start with the Meshtastic `tlora-pager` pinout, not T-Deck/T-Deck Pro.
2. Bring up I2C first and scan for BQ25896, BQ27220, XL9555, TCA8418, DRV2605, PCF85063, BHI260AP, and ES8311.
3. Initialize XL9555 at `0x20`; keep uncertain/external domains disabled until needed.
4. Bring up display as ST7796 on SPI2 with CS=38, DC=37, BL=42, logical size 222×480, offset X=49.
5. Bring up keyboard through TCA8418 with interrupt GPIO6 and backlight GPIO46.
6. Bring up rotary GPIO40/41 with press GPIO7.
7. Bring up radio on its dedicated SPI bus: SCK=35, MISO=33, MOSI=34, CS=36, RST=47, IRQ=14, BUSY=48.
8. Bring up GPS on RX=4, TX=12, PPS=13, 38400 baud.
9. Bring up SD card only after confirming CS=21 and XL9555 SD enable/detect behavior.
10. Implement conservative battery-voltage sleep behavior; do not rely on hardware cut-off unless confirmed.
11. Leave top expansion pins alone until the schematic connector pinout is verified.

## Direct source links

- Meshtastic platform: <https://github.com/meshtastic/firmware/blob/master/variants/esp32s3/tlora-pager/platformio.ini>
- Meshtastic pinout: <https://github.com/meshtastic/firmware/blob/master/variants/esp32s3/tlora-pager/variant.h>
- Meshtastic keyboard driver: <https://github.com/meshtastic/firmware/blob/master/src/input/TLoraPagerKeyboard.cpp>
- Meshtastic power handling: <https://github.com/meshtastic/firmware/blob/master/src/Power.cpp>
- Meshtastic power header / OCV defaults: <https://github.com/meshtastic/firmware/blob/master/src/power.h>
- LilyGoLib T-LoRa Pager implementation: <https://github.com/Xinyuan-LilyGO/LilyGoLib/blob/master/src/LilyGo_LoRa_Pager.cpp>
- LilyGoLib T-LoRa Pager header: <https://github.com/Xinyuan-LilyGO/LilyGoLib/blob/master/src/LilyGo_LoRa_Pager.h>
- LilyGo T-LoRa Pager docs: <https://github.com/Xinyuan-LilyGO/LilyGoLib/blob/master/docs/lilygo-t-lora-pager.md>
- LilyGo schematic directory: <https://github.com/Xinyuan-LilyGO/LilyGoLib/tree/master/schematic>
- LilyGo T-LoRa Pager schematic: <https://github.com/Xinyuan-LilyGO/LilyGoLib/blob/master/schematic/T-Lora%20Pager%20V1.0%20SCH%2025-06-13.pdf>
- MeshCore nearby T-Deck platform, not T-LoRa Pager: <https://github.com/meshcore-dev/MeshCore/tree/main/variants/lilygo_tdeck>
