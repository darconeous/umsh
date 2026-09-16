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

- `Radio-SX1262`—sub-GHz LoRa
- `Radio-SX1280`—2.4 GHz LoRa
- `Radio-CC1101`—sub-GHz FSK/GFSK/ASK/OOK family
- `Radio-LR1121`—sub-GHz + 2.4 GHz LoRa
- `Radio-SI4432`—sub-GHz ISM

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

### Shared SPI bus and LoRa

The display, SX1262, SD card, and NFC frontend share SCK=35, MOSI=34,
and MISO=33. They need separate chip selects and one serialized bus, not
independent SPI controllers. UMSH uses SPI2 with 16 MHz radio transactions
and 40 MHz display transactions. Display transfers are bounded to four
landscape rows, with the bus released between transactions.

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

2. **Can firmware disconnect the battery from the system?** Yes. Schematic sheet 1 routes the BQ25896 `SYS` output to the main and peripheral regulators. Its internal BATFET can disconnect the battery from SYS in shipping mode. Battery-connected circuitry still draws residual current; this is not a zero-current isolation of the cell. This hardware capability does not establish whether another firmware's low-battery path uses it.

Practical porting implication: implement a conservative low-battery policy yourself. Do not rely on deep sleep alone as a complete Li-Ion protection mechanism unless the hardware schematic confirms cell protection.

### Power button / hard off

The dedicated **Power Key** (S3 on schematic sheet 1) connects `PWR_KEY` to the BQ25896 **QON** input. It is distinct from the ESP32 boot button (`GPIO0`) and rotary press (`GPIO7`), which are software inputs and possible ESP32 deep-sleep wake sources.

LilyGoLib’s sleep helper allows boot-button and rotary-button wake from ESP32 deep sleep. Full battery power-off instead requires BQ25896 `REG09.BATFET_DIS=1`. Clearing `BATFET_DLY` requests immediate disconnection. QON or a newly attached USB supply exits shipping mode; an existing USB supply can continue powering SYS. See the [BQ25896 datasheet, sections 9.2.10 and 9.4.10](https://www.ti.com/lit/ds/symlink/bq25896.pdf).

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

## UMSH display-tracker implementation

The `firmware-tlora-pager` image targets the **SX1262** version. It shares
the ESP32 tracker runtime and enables PSRAM, Wi-Fi, and the bridge client in
normal builds. Build with `make build-tlora-pager`; upload with
`make flash-tlora-pager ESPFLASH_PORT=/dev/cu.usbmodem101` (substitute the
actual port). The flash target uses native-USB bootloader entry and a watchdog
reset after uploading, then exits. If the board remains
in the ROM downloader, tap RESET with BOOT released.

The 480×222 landscape screen uses the existing tracker menus. Turn the wheel
to move, press it to select, and use keyboard **Backspace** to return or
cancel. BOOT held for four seconds requests shutdown. Other keyboard keys
have no navigation action; text composition, audio, haptics, SD, NFC, and
expansion features are deferred. Backspace is TCA8418 raw FIFO key **30**,
not the zero-based matrix index `0x1D`.

While the screen is visible or dimming, both edges of GPIO40 and GPIO41
interrupt the CPU. The ISR validates each quadrature transition and queues
one event per complete detent; display rendering never samples A/B. Invalid
transitions cancel an incomplete step, and reversals/bounce cancel without
acceleration.

After successful display-off, the input coordinator transfers A/B from the
ISR to wake-enabled level waits, each armed opposite its current level.
Owned wake guards cover boot, interactive operation, and mode transitions;
the dark-screen guard is released only after both wake waits have been polled
and armed. Wheel activity restores interrupt capture before rendering and
consumes the incomplete wake cycle through the next both-high detent. Later
detents are queued until the display is ready. The wake path cannot recover
edges that occurred during CPU wake latency; human-speed qualification is
required.

Wheel press and BOOT use independent wake-enabled level waits and 15 ms
stable-level debounce deadlines. A gesture retains its initial wake/splash
disposition through bounce and release. Held Select and Backspace do not
repeat. BOOT retains its four-second shutdown hold and no short-press action.
Keyboard IRQ handling drains the TCA8418 FIFO without idle polling. Three
failed recovery attempts quarantine the keyboard until the next display wake;
the wheel and BOOT remain independent. Full power-off is unchanged.

Input wake handling permits automatic light sleep only with the screen fully
dark. USB, active GNSS, and enabled wireless drivers may independently keep
the CPU awake. LoRa IRQ and enabled motion IRQ already use wake-enabled level
waits; CPU wake alone does not imply screen wake.

The panel shares DMA-backed SPI2 with the radio. The monochrome framebuffer
and last-transferred frame reside in PSRAM; synchronization objects, DMA
descriptors, and transfer buffers stay in internal RAM. Only changed four-row
stripes are transmitted, and history advances after a successful transfer.
The controller's portrait offset becomes landscape Y=49.
The internal heap is 111 KiB, leaving room for the nested startup
calls as well as DMA state. The board's stack check requires another 32 KiB
beyond its largest individual function frame; a smaller reserve missed an
on-device startup stack overflow during bring-up.
AW9364 brightness uses short pulses across its 16 levels, not PWM; keyboard
illumination follows screen activity.

The XL9555 leaves unused domains disabled. GNSS uses the runtime enable
setting and UART1 RX=4/TX=12 at 38400 baud. Disabling GNSS cancels RX, powers
down the receiver, and leaves a disconnected, blocking UART TX half owning
the UART clocks. RX's wake lock is released. The pinned HAL's light-sleep
entry suspends every UART; releasing the initialized UART's last clock owner
can stall its register-update handshake. Reopening GNSS replaces the parked
TX owner under a temporary wake guard and restores interrupt-driven RX.
PCF85063 retained time uses its
own register layout, with oscillator-stop, invalid dates, and implausible
epochs reported as unknown. The unused RTC clock output is disabled.

Battery telemetry is sampled each second. The selected charger profile is
4.192 V / 704 mA, with charge termination explicitly enabled at **192 mA**
(the nearest hardware setting to 200 mA). The BQ27220 taper threshold is
**220 mA**. Full detection also requires voltage and accumulated-charge
conditions across two taper windows; it is not an instantaneous 220 mA switch.
The narrow margin above the charger cutoff requires charging-cycle qualification,
including component tolerances. Startup
preserves the precharge, recharge, safety-timer, and JEITA settings, disables
the register watchdog, and verifies the current/voltage/termination profile
before enabling charge. A failed readback leaves charging disabled. The
inherited and verified REG04–07 values are retained in an internal
`pager charger-init` diagnostic until the first USB response.
See [BQ25896 REG05/REG07](https://www.ti.com/lit/ds/symlink/bq25896.pdf) and
[BQ27220 taper qualification, section 4.9.47](https://www.ti.com/lit/ug/sluubd4a/sluubd4a.pdf).

Startup checks the BQ27220 design capacity and taper current. The selected
**1800 mAh** design capacity is a user estimate pending cell qualification;
LilyGO's documented stock value is 1500 mAh. A mismatched design updates both
design and initial full capacity to 1800 mAh in one RAM transaction. A mismatched
taper setting updates only that parameter. Both are verified, and configuration
mode is entered only when needed. When design already matches, learned full
capacity is retained, including during a taper-only correction. Reading taper
RAM requires temporary full access and security quiet periods, adding about
nine seconds to a normal startup; the original access state is restored.
This hard-coded profile is a temporary development override. The intended
production behavior is to trust factory-programmed battery parameters rather
than overwrite them at boot; the direct I2C management interface is separate work.
Calibration,
other profile parameters, and OTP are untouched. The check runs every boot
because gauge RAM can return to the 3000 mAh default after loss of gauge
power, such as battery removal without another supply. Normal shipping-mode
power-off does not remove gauge power: U16's BAT supply connects to VBAT at
the battery connector, upstream of the BQ25896's switched SYS output, so the
gauge retains RAM while the battery remains connected and supplies sufficient
voltage.
Configuration waits are bounded and feed the startup watchdog; exit and
original-access-mode restoration are attempted on errors. The boot log reports
corrected/retained capacities or a configuration failure. An absent gauge or
invalid telemetry sample reports unknown, never a fabricated zero.

Settings → Battery provides read-only Charge, Capacity, and Fuel gauge pages,
refreshed once per second. They show voltage, signed current (positive into the
cell), charge percentage, charger state, USB power, remaining/full/design
capacity, the gauge's requested charging voltage, and its full/present/initialized/
smoothing flags with raw status words. A charging-voltage request of `0xffff`
is displayed as “maximum.” These reads do not provision or reset the gauge.
To investigate a percentage jump, compare all three pages before and after the
jump; charger completion and the gauge's full flag are separate observations.
The same source serves the optional
[ULCP battery diagnostics](../protocol/src/ulcp-device.md#battery-diagnostics).
Reads select their required registers, retain per-property failures, and share
one acquisition across a multi-get. Periodic UI/safety reads and host reads
share a maximum of two acquisition passes per second; host requests do not
advance the low-battery counter or extend display attention. Use
`umshctl info battery` for a report or `umshctl battery --watch --json` for
monitoring, with an explicit USB port or authorized remote-node selection.
Use `umshctl battery --gauge-telemetry --watch --json` to monitor the BQ27220's
raw coulomb count, configured and internal temperatures, average current/power,
time-to-empty/full estimates (including standby and maximum-load estimates),
cycle count, state of health, and requested charging current. The combined
[`PROP_BATTERY_GAUGE_TELEMETRY`](../protocol/src/ulcp-device.md#prop-battery-gauge-telemetry)
uses sealed standard-command reads, needs no unlock delay, and is acquired only
when requested. It preserves sentinels and raw bits; the CLI labels unavailable
times and supplies Celsius conversions. These additional reads do not run during
ordinary background battery sampling. The gauge's raw coulomb count clears on
gauge-recognized full charge; it is useful for examining the SOC discrepancy,
but is not an uninterrupted lifetime counter.

USB qualification on 2026-09-16: three consecutive full battery-group reads
including telemetry completed in 36, 33, and 33 ms. Cycle count was 2; raw
coulomb count was −22 mAh (register bits 65514, `0xFFEA`); configured and internal temperature were
28.75 °C; state of health was 91%. The gauge remained initialized and sealed
(`OperationStatus=0x00A6`), with design/FCC still 1500/1372 mAh and the full flag
clear at 100% SOC. Saved settings and identity survived the automatic restart.
The coulomb count is interpreted as signed two's complement; it is not a
remaining-capacity estimate. JSON also preserves the original unsigned register bits.

AveragePower scaling needs further qualification: raw readings 16/15/14
accompanied average current 39/36/34 mA at 4132 mV, suggesting a factor of ten
relative to the manual's stated mW unit. The property preserves register values
and documents TI's unit; do not treat this field as a verified board-power
measurement. No inferred scale correction is applied. Host tests cover compact
encoding, standard-command-only reads, independent property failures, and
Node Management replay; an actual over-radio telemetry exchange remains untested.

Use `umshctl battery --gauge-config` to explicitly acquire the BQ27220 RAM
configuration, or `umshctl get battery-gauge-config` to read it alone. JSON
output includes every raw field and its units. The configuration property is
excluded from ordinary battery polling and the Battery submenu. Inspection
temporarily enters full access, validates memory-block addresses/checksums,
and restores the original access state before returning; it never enters configuration-update mode,
writes parameter data, or resets the gauge. The battery task finishes cleanup
even if the USB/radio requester disconnects. Learned capacity is preserved.
Security-key sequences require four seconds without addressing the gauge before
each sequence. Explicit inspection therefore pauses ordinary gauge sampling for
about nine seconds; other peripherals and input handling continue operating.
The wire layout is documented under
[`PROP_BATTERY_GAUGE_CONFIG`](../protocol/src/ulcp-device.md#prop-battery-gauge-config).
Ten consecutive valid battery-only readings at or below 3.1 V request
shutdown. The shutdown path stops radio and motion activity, blanks the
display, turns off peripheral domains, stops charger measurements, and
requests immediate BQ25896 battery disconnection. On battery, SYS falls and
the wheel cannot wake the unpowered ESP32; the dedicated Power Key or newly
attached USB restores power. Disconnect-command errors are logged and retried
three times. If power remains (for example, with USB connected), the existing
deep-sleep fallback releases bus outputs and retains BOOT and wheel wake.
Startup reconnects the battery path before enabling charging, including when
a USB-powered restart retained the disconnect bit. Pending journal writes are
synchronous on the shared executor; frame counters are persisted before
transmission. Residual power-off current still needs measurement.

The fitted 16 MB flash initially uses the existing 4 MB UMSH image layout,
including the data partition at `0x300000`. Normal flashing retains its
identity, settings, and bond journals. Additional flash is unused.

### Input sleep qualification

Build the measurement image with
`make build-tlora-pager ESP32_CARGO_FLAGS='--offline --features input-qualification'`
and use the same flags with `flash-tlora-pager` to upload it. This feature does
not enable BLE debugging or change radio, GNSS, or charger settings.

The image uses existing periodic battery acquisitions to retain a fixed-size
summary in RAM. With USB unplugged and the screen dark and armed, it allows
30 seconds to settle, then collects at least 300 readings spanning at least
five minutes. Reconnect USB, close other serial clients, and run
`python3 scripts/pager_input_power.py /dev/cu.usbmodem101` (using the actual
port). The helper sends read-only ULCP NOPs and captures the `pager input-power:`
ASCII summary before the framed response; ordinary ULCP clients discard that
ASCII text. It includes
signed mean/minimum/maximum current, sample count, elapsed time, and the count
of acquisitions preceded by no active wake lock. `complete=false` identifies
an interrupted measurement. The unlocked count measures sleep eligibility,
**not actual sleep residency**. A reset loses the retained measurement.

Compare the same board/settings on battery before and after the change,
with Bluetooth, Wi-Fi, motion wake, and GNSS disabled and LoRa reception
enabled; repeat with LoRa disabled. Verify actual sleep with a current trace,
then test slow/fast wheel turns in both directions, every starting phase,
bounce, input during rendering and sleep entry, simultaneous inputs, held
BOOT shutdown, USB insertion/removal, LoRa receive, and enabled motion wake.
Record measured currents and qualification results before claiming a power
target or complete hardware validation.

### Qualification status

The sleep-compatible input policy has host coverage for transition races,
shutdown precedence, wake consumption, every encoder starting phase, bounce,
held presses, and keyboard FIFO behavior. The user confirmed that the input
sleep/wake behavior works on the Pager. Sustained input stress testing and
comparative current measurements remain pending.

The GNSS-enabled-to-disabled sleep failure reported a watchdog reset. UART
parking addresses the initialized-but-unclocked UART sleep handshake; its
firmware build and stack check pass, as do 50 GNSS host tests. The corrected
image boots and completes two GNSS on/off cycles over USB with identity and
test settings retained. The user subsequently confirmed that the reported
GNSS-off sleep reboot no longer occurred in the battery-only retest. This
confirms the reported reproduction, not long-term sleep reliability or a
measured power reduction.

The initial upload has run on an attached Pager: the user confirmed the
screen, corrected wheel direction, Select, and Backspace, and USB ULCP returned the correct board model,
capabilities, battery voltage/state of charge, and a plausible retained RTC
time. GNSS can
be enabled and reports acquisition status; a satellite fix is not yet
confirmed. USB statistics show transmitted and received LoRa packets, and
the identity key survived ordinary reflashing. Full radio interoperability
and reception while continuously scrolling still need qualification.
The user confirmed substantially faster scrolling with DMA and changed-stripe
updates. The corrected memory budget boots successfully, and native-USB
entry followed by the watchdog reset returns automatically to USB ULCP.
The stock gauge-capacity correction was verified on the attached Pager:
design/full readings changed from 3000/2872 mAh to 1500/1500 mAh, and a
subsequent reboot logged retained capacity without entering configuration.
RAM address selection needs the 10 ms settling delays used by LilyGo's
driver; the shorter bus-free interval alone left the old values intact.
Gauge-power-loss recovery and long-term capacity learning still need physical
qualification.

The configuration snapshot was read over USB on 2026-09-16 without changing
the gauge parameters. It reported 1500 mAh design and 1372 mAh learned full
capacity, CEDV configuration `0x102A` (`FCC_LIMIT=0`, smart-charger learning,
EDV compensation enabled), a 100 mA taper current, and fixed EDV0/1/2 values
of 3031/3385/3501 mV. The discharge coefficients matched the reference
manual's ROM defaults. Thus a design-capacity ceiling does not explain this
device's low learned capacity; the cell's discharge model still needs
qualification. Charger initialization read REG04–07 as `[0B, 13, 5A, 8D]`
before applying the termination fix, confirming the inherited **256 mA** cutoff
was above the gauge's **100 mA** taper threshold. Readback after the change was
`[0B, 10, 5A, 8D]`: **64 mA** cutoff, with fast-charge current, voltage, safety
timer, and JEITA settings retained. The gauge returned to sealed state (`0x00A6`
OperationStatus), and identity, saved settings, and learned capacity survived
the diagnostic uploads and reads.
With the corrected cutoff, USB monitoring observed current taper from 274 mA
through the old cutoff and below 100 mA. After about 13 minutes, the gauge
asserted full naturally at 91 mA (92 mA average) and 4190 mV, and
`RawCoulombCount` changed from −58 mAh (register bits 65478) to zero. Six successive samples retained
the full flag and zero counter. No gauge reset or parameter change was used;
design/FCC remained 1500/1372 mAh. This verifies full-charge recognition, not
the accuracy of learned capacity or the cell's discharge model. Charger
termination at the final 64 mA cutoff was not observed in this test.

The temporary 1800/220/192 profile was read back over USB on 2026-09-16:
design/FCC 1800/1800 mAh, gauge taper 220 mA, and charger REG04–07
`[0B, 12, 5A, 8D]` (704 mA fast charge, 192 mA termination, 4192 mV).
Comparing all 48 gauge configuration fields with the prior snapshot showed
only design capacity, full capacity, and taper current changed. The gauge
was sealed afterward. Live signed telemetry decoded register 65532 as −4 mAh.
The capacity migration reinitialized the gauge: FCC was seeded at 1800 mAh
and cycle count changed from 2 to 0. A subsequent automatic hardware restart
retained 1800/1800 mAh and the −4 mAh counter, with identical charger registers,
identity, and the user's enabled BLE/Wi-Fi/GNSS settings. Host tests also verify
that a matching profile never enters configuration mode and that a taper-only
change preserves learned FCC. A USB `reboot` request did not demonstrate an MCU
restart in this session; the restart qualification used the flash target's
automatic watchdog reset instead.
The cell was already charged, so a fresh full-detection/termination cycle with
the narrower 220/192 mA margin remains unqualified. The earlier 100/64 mA
test does not establish that the new pair leaves enough qualification time.

Three consecutive explicit configuration requests, with one second between
responses and subsequent requests, returned identical complete snapshots in
9.3–9.8 seconds each after adding the security quiet periods. Ordinary scalar
polling resumes afterward. The normal build passes the 32 KiB stack reserve;
radio-management replay and duplicate-read behavior are covered by host tests.

Remaining hardware acceptance checks:

- Confirm one step per detent under sustained load, nested menus, and
  confirmation cancellation.
- Confirm dim/wake consumption, splash timing, full panel edges, and backlight
  levels on the physical display.
- Exercise GNSS fixes and power cycling, RTC writeback/retention, USB removal,
  charging transitions, and battery-only boot.
- Exercise BLE pairing/reconnect, Wi-Fi association/DHCP/reconnect, bridge
  traffic, and bidirectional LoRa traffic while continuously scrolling.
- On battery, confirm shutdown drops the system rails, wheel/BOOT cannot
  restart the device, and the dedicated Power Key restores power. Also check
  USB-powered sleep, USB removal after shutdown, USB reconnection, residual
  current, and identity/settings/bond retention after ordinary reflashing.

## Minimal bring-up checklist for a new firmware port

1. Start with the Meshtastic `tlora-pager` pinout, not T-Deck/T-Deck Pro.
2. Bring up I2C first and scan for BQ25896, BQ27220, XL9555, TCA8418, DRV2605, PCF85063, BHI260AP, and ES8311.
3. Initialize XL9555 at `0x20`; keep uncertain/external domains disabled until needed.
4. Bring up display as ST7796 on SPI2 with CS=38, DC=37, BL=42, logical size 222×480, offset X=49.
5. Bring up keyboard through TCA8418 with interrupt GPIO6 and backlight GPIO46.
6. Bring up rotary GPIO40/41 with press GPIO7.
7. Bring up radio on the shared SPI bus: SCK=35, MISO=33, MOSI=34, CS=36, RST=47, IRQ=14, BUSY=48. Keep display/SD/NFC chip selects inactive during radio transactions.
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
