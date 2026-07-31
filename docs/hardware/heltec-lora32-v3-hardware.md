# Heltec WiFi LoRa 32 V3 Hardware Reference

This document describes the **Heltec WiFi LoRa 32 V3 family**, with particular attention to the currently common **V3.2** revision, at the level needed to port and maintain UMSH firmware.

It is intended to be readable by both humans and software agents. It combines:

- Heltec's product documentation and V3/V3.1/V3.2 schematics
- Heltec's hardware revision log and pin map
- MeshCore's current `heltec_v3` build configuration
- Espressif ESP32-S3 documentation
- Semtech SX1262 documentation

Where revisions or sources disagree, the discrepancy is called out explicitly.

> **Important identification warning**
>
> This document is for the **WiFi LoRa 32 V3/V3.1/V3.2**, built around an **ESP32-S3FN8** and **SX1262**. It is not applicable to the V2, which uses the original ESP32 and SX1276/SX1278, or to the newer V4 family. The V3.2 power and battery-sensing circuitry differs meaningfully from earlier V3 boards even though the external pinout is largely unchanged.

---

## 1. Executive summary

The Heltec WiFi LoRa 32 V3 is a compact development board containing:

- Espressif ESP32-S3FN8, dual-core Xtensa LX7, up to 240 MHz
- 8 MiB embedded flash in the ESP32-S3FN8 package
- No external PSRAM on the normal V3
- Semtech SX1262 LoRa transceiver
- 32 MHz temperature-compensated radio reference oscillator
- 0.96-inch 128×64 monochrome OLED
- CP2102 USB-to-UART bridge
- USB Type-C connector
- Single-cell Li-ion/LiPo connector and linear charger
- Automatic USB/battery source selection
- Switchable 3.3 V `Vext` rail
- Battery-voltage measurement circuit
- User/program button on GPIO0
- Reset button
- User/status LED on GPIO35
- U.FL/IPEX LoRa antenna connector
- Onboard 2.4 GHz Wi-Fi/BLE antenna
- Two rows of 18 through-hole header positions

The critical UMSH pin assignments are:

| Function | ESP32-S3 GPIO |
|---|---:|
| SX1262 SPI SCK | 9 |
| SX1262 SPI MOSI | 10 |
| SX1262 SPI MISO | 11 |
| SX1262 NSS/CS | 8 |
| SX1262 reset | 12 |
| SX1262 BUSY | 13 |
| SX1262 DIO1 interrupt | 14 |
| OLED SDA | 17 |
| OLED SCL | 18 |
| OLED reset | 21 |
| User/program button | 0 |
| User/status LED | 35 |
| `Vext` control | 36, active low |
| Battery ADC input | 1 |
| Battery-divider control | 37 |
| CP2102 UART TX from ESP32 | 43 |
| CP2102 UART RX into ESP32 | 44 |

MeshCore uses the same radio, OLED, LED, button, and `Vext` assignments. It intentionally configures the radio reset as unused even though the board schematic connects SX1262 `NRESET` to GPIO12.

---

## 2. Hardware revisions

The name “V3” covers several board revisions that are externally very similar.

### 2.1 V3

The original V3 introduced:

- ESP32-S3FN8 in place of the original ESP32
- SX1262 in place of SX1276
- USB Type-C in place of Micro-USB
- a lower-power board design
- a temperature-compensated LoRa reference oscillator

### 2.2 V3.1

Heltec's revision log states that V3.1:

- removed the ideal-diode section
- increased spacing between the 2.4 GHz RF section and crystal
- changed the USB-C implementation to support C-to-C cables

The GPIO sequence and external power pins remained unchanged.

### 2.3 V3.2

V3.2 made the most firmware-relevant changes:

- `Vext` generation changed to a separately switched LDO
- charger changed from TP4054 to LGS4056H
- battery-voltage detection circuitry changed
- GPIO37 must be driven **high** to enable battery measurement
- layout and component-placement changes were made

The external header pinout remains the same, but power-control behavior must be revision-aware.

### 2.4 Determining the revision

Look for a revision marking on the PCB silkscreen, normally near the top edge or antenna area. A board marked `V3.2` should use the V3.2 battery-control behavior documented below.

When firmware cannot know the revision, it should either:

- expose a board-revision configuration option, or
- probe battery behavior carefully and retain the detected polarity, or
- target V3.2 explicitly and document that earlier revisions are unsupported.

---

## 3. MCU and memory

### 3.1 ESP32-S3FN8

The board uses Espressif's ESP32-S3FN8:

- dual Xtensa LX7 cores
- maximum clock: 240 MHz
- 2.4 GHz 802.11b/g/n Wi-Fi
- Bluetooth Low Energy 5-class controller; no Bluetooth Classic
- vector instructions useful for DSP and some cryptographic workloads
- native USB 2.0 full-speed OTG peripheral
- 8 MiB in-package flash
- no normal external PSRAM population

MeshCore deliberately compiles its Heltec V3 target for an 80 MHz CPU clock to reduce power consumption:

```ini
-D ESP32_CPU_FREQ=80
```

UMSH does not need to copy this choice, but it is a useful low-power operating point.

### 3.2 Flash

The `FN8` suffix indicates 8 MiB of flash integrated into the MCU package. Firmware should use a partition table appropriate for 8 MiB.

### 3.3 No PSRAM

The ordinary V3 has no PSRAM. This matters for UMSH because the ESP32-S3 radio stacks, display buffer, cryptographic state, packet queues, and OTA support all compete for internal RAM.

Do not assume that a framework reporting an ESP32-S3 implies PSRAM is present.

### 3.4 Crystals

The board includes:

- 40 MHz ESP32-S3 main crystal
- 32.768 kHz low-frequency crystal for RTC use
- 32 MHz radio reference oscillator for the SX1262

The LoRa oscillator is controlled from SX1262 DIO3 and is configured by MeshCore as a 1.8 V TCXO supply.

---

## 4. LoRa radio subsystem

### 4.1 SX1262 interface

| SX1262 signal | ESP32-S3 GPIO | MeshCore definition |
|---|---:|---|
| NSS / CS | 8 | `P_LORA_NSS=8` |
| SCK | 9 | `P_LORA_SCLK=9` |
| MOSI | 10 | `P_LORA_MOSI=10` |
| MISO | 11 | `P_LORA_MISO=11` |
| NRESET | 12 | MeshCore uses `RADIOLIB_NC` |
| BUSY | 13 | `P_LORA_BUSY=13` |
| DIO1 | 14 | `P_LORA_DIO_1=14` |

Unlike the V2's SX127x, the SX1262 requires a BUSY handshake. The host must not issue a new command while BUSY is asserted.

### 4.2 MeshCore radio configuration

MeshCore currently uses:

```ini
-D P_LORA_DIO_1=14
-D P_LORA_NSS=8
-D P_LORA_RESET=RADIOLIB_NC
-D P_LORA_BUSY=13
-D P_LORA_SCLK=9
-D P_LORA_MISO=11
-D P_LORA_MOSI=10
-D USE_SX1262
-D LORA_TX_POWER=22
-D SX126X_DIO2_AS_RF_SWITCH=true
-D SX126X_DIO3_TCXO_VOLTAGE=1.8
-D SX126X_CURRENT_LIMIT=140
-D SX126X_RX_BOOSTED_GAIN=1
```

This establishes several important board behaviors:

- DIO2 controls the external RF switch.
- DIO3 powers or controls the 1.8 V TCXO.
- DIO1 is the sole host-visible radio interrupt.
- The nominal requested transmit power is 22 dBm.
- Radio current limiting is configured to 140 mA.
- boosted receive gain is enabled.

### 4.3 Reset discrepancy

The Heltec schematic connects SX1262 `NRESET` to GPIO12. MeshCore nevertheless declares the reset pin as not connected.

This should be interpreted as a MeshCore driver choice, not as proof that GPIO12 is physically disconnected. UMSH may use GPIO12 for hardware reset.

A typical reset sequence is:

```text
1. Configure GPIO12 as an output.
2. Drive it low for at least 100 microseconds.
3. Drive it high.
4. Wait until BUSY on GPIO13 becomes low.
5. Continue radio initialization.
```

Follow the SX1262 datasheet and chosen driver library for exact timing.

### 4.4 DIO1 behavior

SX1262 DIO1 is a configurable interrupt line. Firmware chooses which IRQ sources are routed to it, commonly:

- TX done
- RX done
- preamble detected
- sync/header events
- CRC error
- RX timeout
- CAD done/detected

GPIO14 should be configured as an input. Interrupt polarity and edge behavior should match the radio's IRQ configuration and driver assumptions.

### 4.5 BUSY behavior

GPIO13 is driven by SX1262 BUSY.

Firmware must:

- wait for BUSY low before issuing commands
- wait for BUSY low after wakeup or reset
- ensure that SPI transactions and NSS timing comply with SX1262 requirements
- provide a timeout so a hardware fault does not deadlock the firmware forever

### 4.6 DIO2 RF switch control

The external antenna switch is controlled by SX1262 DIO2 rather than an ESP32-S3 GPIO. Firmware should issue `SetDio2AsRfSwitchCtrl` through the radio driver.

Do not attempt to reserve a separate MCU pin for TX/RX switching.

### 4.7 DIO3 TCXO control

The 32 MHz reference is powered/controlled from DIO3. MeshCore configures it for 1.8 V.

The initialization order must include TCXO control before radio calibration and normal operation. A generic SX1262 driver configured for a crystal oscillator rather than a TCXO may fail to start reliably or show poor frequency accuracy.

### 4.8 Frequency variants

Heltec commonly sells:

| Variant | RF range | Typical regions |
|---|---|---|
| LF | approximately 470–510 MHz | CN470 and related low-band use |
| HF | approximately 863–928 MHz | EU868, IN865, US915, AU915, AS923, KR920 |

A board's matching network and antenna must match its RF variant. Do not assume the HF board is suitable for 433 MHz simply because the SX1262 silicon supports a broad frequency range.

### 4.9 Antenna precautions

- Attach a correctly tuned LoRa antenna before transmitting.
- The U.FL/IPEX connector is the LoRa antenna connection.
- The onboard metal/spring antenna is for Wi-Fi and BLE.
- U.FL connectors have limited mating life and are mechanically fragile.
- Requested 22 dBm is not necessarily the exact conducted power at the connector.
- Regional power, duty-cycle, dwell-time, and channel rules still apply.

---

## 5. OLED display

### 5.1 Electrical interface

| OLED signal | ESP32-S3 GPIO |
|---|---:|
| SDA | 17 |
| SCL | 18 |
| Reset | 21 |
| Power | `Vext` |

MeshCore confirms:

```ini
-D PIN_BOARD_SDA=17
-D PIN_BOARD_SCL=18
-D DISPLAY_CLASS=SSD1306Display
```

### 5.2 Controller and address

The display is a 128×64 monochrome OLED normally operated as SSD1306-compatible at 7-bit I2C address `0x3C`.

A bring-up implementation should probe `0x3C`, but clone boards may differ.

### 5.3 OLED reset

GPIO21 is the OLED reset line.

Recommended startup:

```text
1. Enable Vext by driving GPIO36 low.
2. Wait for the switched rail to stabilize.
3. Drive GPIO21 low.
4. Wait several milliseconds.
5. Drive GPIO21 high.
6. Initialize I2C on GPIO17/GPIO18.
7. Initialize the display controller.
```

### 5.4 OLED depends on Vext

The OLED supply is connected to `Vext`. Disabling `Vext` removes OLED power.

After re-enabling `Vext`, the display must be reset and reinitialized; retaining only the framebuffer in RAM is not sufficient.

---

## 6. Buttons, reset, and bootloader behavior

### 6.1 PRG/user button

The user/program button connects GPIO0 to ground.

| Function | GPIO | Active level |
|---|---:|---|
| User/program button | 0 | Low |

GPIO0 is also a boot-strapping pin. Holding it low during reset selects the ROM download boot mode.

At runtime it may be used as an active-low user button.

### 6.2 Reset button

The reset switch pulls `CHIP_PU` / `EN` low and resets the ESP32-S3.

### 6.3 Automatic serial flashing

The CP2102's DTR and RTS signals feed the usual transistor auto-reset circuit controlling GPIO0 and `CHIP_PU`. `esptool` can normally enter the ROM serial loader automatically.

Manual fallback:

```text
1. Hold PRG/BOOT.
2. Press and release RESET.
3. Release PRG/BOOT.
4. Retry the upload.
```

### 6.4 GPIO0 caveat

External circuitry must not force GPIO0 low during reset unless download mode is desired.

---

## 7. User/status LED

The onboard white user LED is driven from GPIO35.

| Function | GPIO | Polarity |
|---|---:|---|
| User/status LED | 35 | Active high |

MeshCore uses it as the LoRa TX indicator:

```ini
-D P_LORA_TX_LED=35
```

GPIO35 is exposed on the header but is electrically loaded by the onboard LED and resistor.

---

## 8. USB and serial interfaces

### 8.1 USB Type-C

The primary connector is USB Type-C and provides:

- 5 V input power
- CP2102 serial programming/debugging
- automatic reset/download control

V3.1 and later include the required Type-C configuration resistors for proper C-to-C cable operation.

### 8.2 CP2102 UART

| UART0 signal | ESP32-S3 GPIO | CP2102 side |
|---|---:|---|
| U0TXD | 43 | CP2102 RXD |
| U0RXD | 44 | CP2102 TXD |

These pins are also exposed on the header. External circuitry can interfere with flashing and console operation.

### 8.3 Native ESP32-S3 USB pins

The ESP32-S3 native USB signals are:

| Native USB signal | GPIO |
|---|---:|
| D- | 19 |
| D+ | 20 |

The schematic shows optional, normally unpopulated links between these pins and the USB connector data lines. In the standard assembly, the Type-C connector is routed to the CP2102, not directly to native USB.

Therefore:

- Do not assume USB CDC/JTAG works through the connector without board modification.
- GPIO19 and GPIO20 remain exposed and usable unless the optional links are fitted.
- Soldering those links can create contention with the CP2102 unless the routing is modified correctly.

### 8.4 Boot messages

The ROM and bootloader can print on UART0. UMSH should expect startup output on GPIO43 unless console output is disabled.

---

## 9. Battery, charging, and source selection

### 9.1 Battery connector

The board uses a 2-pin 1.25 mm connector for a single-cell 3.7 V nominal Li-ion/LiPo battery.

Verify polarity on the physical board and battery cable. Small two-pin battery connectors are not universally polarized the same way across vendors.

### 9.2 V3/V3.1 charger

Earlier V3 schematics show a TP4054 linear charger with an approximately 2 kΩ programming resistor, implying a substantially higher nominal charge current than the V2's 10 kΩ configuration.

Exact current depends on the installed compatible charger and resistor tolerance and should be measured for product use.

### 9.3 V3.2 charger

V3.2 uses an LGS4056HDA charger. The schematic shows:

- USB-derived 5 V input
- single-cell battery output
- hardware charge-status output
- charge LED
- no charger telemetry connection to the ESP32-S3

The ESP32-S3 cannot directly distinguish charging, complete, and fault states through a GPIO in the published design.

### 9.4 Charge LED

The orange charge LED is controlled by the charger hardware, not by GPIO35.

The nearby white LED is the firmware-controlled GPIO35 LED.

### 9.5 USB/battery source selection

The board automatically powers the 3.3 V system rail from USB or battery. This is implemented with discrete MOSFET/diode circuitry rather than a firmware-controlled PMIC.

Consequences:

- The board can operate while charging.
- There is no firmware-controlled hard shutdown.
- There is no coulomb counter or fuel-gauge IC.
- Battery state must be inferred from voltage.
- System load affects charger behavior and observed battery voltage.

### 9.6 Battery protection caveat

Heltec describes battery-management and overcharge protection, but the board schematic does not replace the need for a protected cell in a product design.

Prefer a protected single-cell pack and do not depend exclusively on firmware for undervoltage protection.

---

## 10. `Vext` power rail

### 10.1 Purpose

`Vext` is a switchable 3.3 V rail used by:

- the onboard OLED
- the two `Ve` header pins
- optional low-power external sensors

### 10.2 Control pin and polarity

GPIO36 controls `Vext`.

| GPIO36 | Vext state |
|---:|---|
| Low | On |
| High or high-impedance with pull-up | Off |

Thus `Vext` control is **active low**.

MeshCore declares:

```ini
-D PIN_VEXT_EN=36
```

Board support code must still know the active-low polarity.

### 10.3 V3.2 implementation

V3.2 uses a separate CE6260B33M LDO for `Vext`. GPIO36 controls a transistor stage that enables the LDO when GPIO36 is driven low.

This isolates the switched external rail more cleanly from the main 3.3 V rail than the earlier MOSFET-only implementation.

### 10.4 Startup default

The control circuit includes a pull-up so `Vext` tends to default off until firmware actively drives GPIO36 low.

Firmware that initializes the display must enable `Vext` before touching the OLED.

### 10.5 Current limit

Heltec literature commonly describes `Vext` as suitable for low-power external sensors. Treat it as a modest auxiliary rail, not a general-purpose high-current supply.

Large loads can cause regulator heating or system brownout and should use a separate regulator.

---

## 11. Battery voltage measurement

### 11.1 ADC pin

Battery voltage is measured on GPIO1, which is ESP32-S3 ADC1 channel 0.

This is an improvement over the V2's ADC2-based measurement because ADC1 does not have the classic ESP32 ADC2/Wi-Fi ownership conflict.

### 11.2 Divider ratio

The V3.2 schematic uses:

- 390 kΩ upper resistor
- 100 kΩ lower resistor

The ideal divider ratio is:

```text
VADC = VBAT × 100k / (390k + 100k)
     = VBAT / 4.9

VBAT = VADC × 4.9
```

At 4.2 V battery voltage, the ideal ADC voltage is approximately 0.857 V.

A small series resistor between the divider node and GPIO1 does not materially change the DC ratio.

### 11.3 ADC control pin

GPIO37 enables the battery divider.

For **V3.2**:

| GPIO37 | Battery divider |
|---:|---|
| High | Enabled |
| Low | Disabled |

Heltec's hardware-update log explicitly states that V3.2 requires GPIO37 to be pulled high for voltage detection.

Earlier V3/V3.1 circuitry is reported to use the opposite control polarity. This is the most important revision-specific firmware difference.

### 11.4 Recommended V3.2 reading sequence

```text
1. Configure GPIO37 as output.
2. Drive GPIO37 high.
3. Wait several milliseconds for the high-impedance divider and ADC input to settle.
4. Discard the first ADC conversion.
5. Take multiple samples from GPIO1.
6. Median-filter or average them.
7. Convert the calibrated ADC result to voltage.
8. Multiply by the calibrated divider factor, nominally 4.9.
9. Drive GPIO37 low when finished to eliminate divider current.
```

### 11.5 ADC accuracy caveats

The divider source impedance is high. ESP32 ADC accuracy is affected by:

- sampling capacitor settling
- ADC attenuation selection
- chip-to-chip reference variation
- ADC nonlinearity
- RF noise
- USB/charger state
- battery load at the moment of measurement
- resistor tolerance

For useful battery telemetry:

- use Espressif ADC calibration APIs
- take multiple samples
- allow settling time
- calibrate the multiplier against a multimeter
- measure with known USB-connected and battery-only states
- map voltage to state-of-charge using a Li-ion discharge curve rather than linearly from 3.0 to 4.2 V

Community firmware often uses an empirical multiplier somewhat different from the ideal 4.9 because of ADC and resistor tolerances.

### 11.6 Revision-safe strategy

A firmware image supporting both pre-V3.2 and V3.2 can test both GPIO37 polarities while comparing GPIO1 against a plausible battery range. It should avoid rapid switching and should reject readings that imply impossible battery voltage.

An explicit board-revision setting is more deterministic.

---

## 12. Header pin map

### 12.1 Orientation

The following tables match Heltec's pin-map drawing with the USB connector at the bottom and the OLED facing the viewer.

Header numbers increase from bottom to top.

Before designing a carrier PCB, verify orientation against the physical board and continuity-test critical pins.

### 12.2 Header J2 — right side in Heltec's front-view diagram

| J2 pin | Signal | Notes |
|---:|---|---|
| 1 | GND | Ground |
| 2 | 5 V | USB/raw 5 V rail |
| 3 | `Ve` | Switched `Vext` 3.3 V |
| 4 | `Ve` | Switched `Vext` 3.3 V |
| 5 | GPIO44 | U0RXD, connected to CP2102 TXD |
| 6 | GPIO43 | U0TXD, connected to CP2102 RXD |
| 7 | `CHIP_PU` | Reset/enable |
| 8 | GPIO0 | User/boot button |
| 9 | GPIO36 | Active-low `Vext` control |
| 10 | GPIO35 | Onboard white LED |
| 11 | GPIO34 | General-purpose GPIO |
| 12 | GPIO33 | General-purpose GPIO |
| 13 | GPIO47 | General-purpose GPIO; MeshCore GPS RX default |
| 14 | GPIO48 | General-purpose GPIO; MeshCore GPS TX default |
| 15 | GPIO26 | General-purpose GPIO; MeshCore GPS enable default |
| 16 | GPIO21 | OLED reset |
| 17 | GPIO20 | Native USB D+ capability |
| 18 | GPIO19 | Native USB D- capability |

### 12.3 Header J3 — left side in Heltec's front-view diagram

| J3 pin | Signal | Notes |
|---:|---|---|
| 1 | GND | Ground |
| 2 | 3.3 V | Main unswitched 3.3 V rail |
| 3 | 3.3 V | Main unswitched 3.3 V rail |
| 4 | GPIO37 | Battery-divider control; V3.2 active high |
| 5 | GPIO46 | Strapping/input caveats |
| 6 | GPIO45 | Strapping input; use carefully |
| 7 | GPIO42 | JTAG MTMS capability |
| 8 | GPIO41 | JTAG MTDI capability |
| 9 | GPIO40 | JTAG MTDO capability |
| 10 | GPIO39 | JTAG MTCK capability |
| 11 | GPIO38 | General-purpose GPIO |
| 12 | GPIO1 | Battery ADC input |
| 13 | GPIO2 | ADC1/touch-capable GPIO |
| 14 | GPIO3 | ADC1/touch-capable GPIO; strapping caveat |
| 15 | GPIO4 | ADC1/touch-capable GPIO |
| 16 | GPIO5 | ADC1/touch-capable GPIO |
| 17 | GPIO6 | ADC1/touch-capable GPIO |
| 18 | GPIO7 | ADC1/touch-capable GPIO |

### 12.4 Onboard functions not exposed as free pins

| GPIO | Board function |
|---:|---|
| 0 | User/boot button |
| 1 | Battery ADC |
| 8 | SX1262 NSS |
| 9 | SX1262 SCK |
| 10 | SX1262 MOSI |
| 11 | SX1262 MISO |
| 12 | SX1262 reset |
| 13 | SX1262 BUSY |
| 14 | SX1262 DIO1 |
| 17 | OLED SDA |
| 18 | OLED SCL |
| 21 | OLED reset |
| 35 | Onboard LED |
| 36 | `Vext` control |
| 37 | Battery-divider control |
| 43 | CP2102 UART TX from MCU |
| 44 | CP2102 UART RX into MCU |

### 12.5 Good expansion candidates

The least-conflicted bidirectional GPIOs are generally:

- GPIO2
- GPIO4
- GPIO5
- GPIO6
- GPIO7
- GPIO26
- GPIO33
- GPIO34
- GPIO38
- GPIO39
- GPIO40
- GPIO41
- GPIO42
- GPIO47
- GPIO48

With caveats:

- GPIO3, GPIO45, and GPIO46 are strapping-related pins.
- GPIO19/20 may be reserved for future native USB use.
- GPIO39–42 overlap JTAG signals.
- MeshCore reserves GPIO47/48/26 for an optional GPS by convention, though no GPS is onboard.
- External circuitry must respect 3.3 V logic levels.

---

## 13. ESP32-S3 pin restrictions

### 13.1 Strapping pins

Relevant ESP32-S3 strapping pins include GPIO0, GPIO3, GPIO45, and GPIO46.

External loads must not force incompatible levels during reset.

GPIO0 is intentionally used by the boot button.

### 13.2 Input limitations

Unlike the original ESP32, the ESP32-S3 does not have the same GPIO34–39 input-only block. The exposed S3 GPIOs are generally bidirectional where supported by the package, but strapping, USB, JTAG, and onboard connections still constrain their safe use.

### 13.3 Native USB

GPIO19 and GPIO20 are the S3's native USB pins. Even though the standard board routes the connector through CP2102, applications should avoid committing these pins if native USB modification or a future board revision is anticipated.

### 13.4 JTAG

GPIO39–42 carry default JTAG functions. They can normally be used as GPIO when JTAG is not required, but attached hardware may interfere with debugging.

### 13.5 ADC

GPIO1–7 provide ADC1 channels and capacitive-touch functions. GPIO1 is already loaded by the battery divider.

---

## 14. Low-power behavior

### 14.1 Manufacturer claim

Heltec contrasts the V3 with the V2 by advertising board sleep current below 10 µA, compared with roughly 800 µA for V2.

This is an optimistic configuration-dependent figure. Actual sleep current depends on:

- V3 revision
- OLED and `Vext` state
- SX1262 sleep configuration
- TCXO state
- GPIO pull states
- charger and battery circuitry
- attached peripherals
- USB cable presence
- ESP32-S3 RTC-domain configuration

### 14.2 Required shutdown steps

Before ESP32-S3 deep sleep, UMSH should:

1. Put the SX1262 into its lowest suitable sleep mode.
2. Ensure the TCXO is off through the radio sleep configuration.
3. Disable radio IRQ routing as needed.
4. Drive GPIO21 low if appropriate for the unpowered OLED.
5. Drive GPIO36 high to disable `Vext`.
6. Drive GPIO37 low on V3.2 to disable the battery divider.
7. Turn off the GPIO35 LED.
8. Disable Wi-Fi and BLE.
9. Configure wake pins and pulls explicitly.
10. Ensure external peripherals do not back-power the board through GPIOs.
11. Enter ESP32-S3 deep sleep.

### 14.3 USB effect

The CP2102 is powered from USB. Sleep-current measurements intended to represent battery operation should be taken with USB disconnected and current supplied through the battery input.

### 14.4 Radio sleep retention

SX1262 supports warm and cold sleep variants. Warm sleep can retain more configuration and wake faster but may consume more current. UMSH should choose intentionally based on latency and battery-life goals.

---

## 15. Recommended startup sequence

```text
1. Drive GPIO35 low to keep the LED off.
2. Drive GPIO36 high to keep Vext off during initial setup.
3. For V3.2, drive GPIO37 low to keep the battery divider off.
4. Configure SX1262 NSS GPIO8 high before enabling SPI.
5. Configure GPIO13 BUSY and GPIO14 DIO1 as inputs.
6. Optionally reset SX1262 using GPIO12.
7. Initialize SPI on SCK=9, MOSI=10, MISO=11.
8. Configure the SX1262 for:
   - DIO2 RF-switch control,
   - DIO3 1.8 V TCXO control,
   - the correct frequency band,
   - legal output power and regional parameters.
9. Route desired IRQs to DIO1 and attach the GPIO14 interrupt.
10. If using the OLED:
    a. drive GPIO36 low,
    b. wait for Vext,
    c. pulse GPIO21 low/high,
    d. initialize I2C on GPIO17/GPIO18,
    e. initialize the SSD1306-compatible controller.
11. Configure GPIO0 as an active-low button input.
12. Perform battery measurement using the correct GPIO37 polarity for the board revision.
13. Start Wi-Fi/BLE only after deterministic board bring-up is complete.
```

---

## 16. Suggested UMSH board definition

```rust
pub const BOARD_NAME: &str = "Heltec WiFi LoRa 32 V3";

pub const LORA_SCK: i32 = 9;
pub const LORA_MOSI: i32 = 10;
pub const LORA_MISO: i32 = 11;
pub const LORA_NSS: i32 = 8;
pub const LORA_RESET: i32 = 12;
pub const LORA_BUSY: i32 = 13;
pub const LORA_DIO1: i32 = 14;

pub const LORA_DIO2_CONTROLS_RF_SWITCH: bool = true;
pub const LORA_DIO3_TCXO_VOLTAGE: f32 = 1.8;

pub const OLED_SDA: i32 = 17;
pub const OLED_SCL: i32 = 18;
pub const OLED_RESET: i32 = 21;

pub const USER_BUTTON: i32 = 0;
pub const USER_BUTTON_ACTIVE_LOW: bool = true;

pub const STATUS_LED: i32 = 35;
pub const STATUS_LED_ACTIVE_HIGH: bool = true;

pub const VEXT_ENABLE: i32 = 36;
pub const VEXT_ACTIVE_LOW: bool = true;

pub const BATTERY_ADC: i32 = 1;
pub const BATTERY_ADC_CONTROL: i32 = 37;
pub const BATTERY_DIVIDER_RATIO: f32 = 4.9;

// V3.2 only. Earlier V3 revisions may use the opposite polarity.
pub const BATTERY_ADC_CONTROL_ACTIVE_HIGH: bool = true;

pub const UART0_TX: i32 = 43;
pub const UART0_RX: i32 = 44;
```

The implementation should model these shared-resource constraints:

- OLED requires `Vext` enabled.
- GPIO36 is active-low power control, not a free expansion pin.
- GPIO37 battery-control polarity is revision-dependent.
- GPIO1 is electrically loaded by the battery divider.
- GPIO35 is loaded by the user LED.
- GPIO43/44 are shared with CP2102.
- GPIO19/20 have native USB significance.
- GPIO0 affects boot mode.

---

## 17. Bring-up checklist

### 17.1 Identification

- Confirm V3, V3.1, or V3.2 silkscreen.
- Confirm ESP32-S3FN8.
- Confirm SX1262.
- Confirm LF or HF RF variant.
- Attach a correct antenna before transmission.

### 17.2 Flashing and console

- Verify CP2102 enumeration.
- Verify UART boot output on GPIO43/44.
- Test automatic bootloader entry.
- Test manual PRG + RESET fallback.
- Confirm 8 MiB flash and partition layout.

### 17.3 Basic GPIO

- Verify GPIO0 reads low when pressed.
- Verify GPIO35 LED is active high.
- Verify GPIO36 low enables `Ve`/OLED power.
- Verify GPIO36 high disables `Ve`.

### 17.4 OLED

- Enable Vext.
- Reset through GPIO21.
- Scan GPIO17/GPIO18 I2C.
- Expect address 0x3C.
- Draw a test pattern.
- Disable Vext and confirm the display powers down.

### 17.5 Battery

- Verify connector polarity.
- Measure charge current.
- Confirm orange hardware charge LED behavior.
- Confirm board revision.
- On V3.2, drive GPIO37 high and read GPIO1.
- Compare calculated voltage with a multimeter.
- Calibrate the nominal 4.9 multiplier.
- Confirm GPIO37 low removes divider current.
- Test protected-cell low-voltage behavior.

### 17.6 LoRa

- Verify BUSY changes state during reset/commands.
- Reset through GPIO12 or validate reset-free initialization.
- Confirm SPI communication.
- Configure DIO3 TCXO at 1.8 V.
- Configure DIO2 RF-switch control.
- Verify DIO1 TX-done and RX-done interrupts.
- Start at reduced TX power.
- Validate frequency and output power with suitable equipment.

### 17.7 Low power

- Put SX1262 to sleep.
- Disable Vext.
- Disable battery divider.
- Turn off LED, Wi-Fi, and BLE.
- Enter deep sleep.
- Disconnect USB.
- Measure current at the battery connector.

---

## 18. Known ambiguities and discrepancies

### 18.1 MeshCore does not use GPIO12 reset

The schematic connects GPIO12 to SX1262 reset, while MeshCore declares reset as not connected. UMSH may use GPIO12; this difference should be treated as driver policy.

### 18.2 Battery-control polarity changed

V3.2 requires GPIO37 high to enable battery measurement. Earlier V3 revisions are documented by community and earlier reference code as using the opposite polarity.

A single hard-coded behavior cannot safely represent every V3 revision.

### 18.3 `Vext` naming can obscure polarity

Frameworks commonly expose a `Vext` pin constant without encoding polarity. On this board, GPIO36 low means `Vext` on.

### 18.4 Native USB is present in the MCU but not normally routed

ESP32-S3 supports native USB on GPIO19/20, but the standard connector is routed to CP2102. Optional schematic links do not mean those links are fitted.

### 18.5 Charger and power circuitry differ by revision

Do not infer V3.2 charger current or battery behavior from an original V3 schematic, and do not infer original V3 behavior from the V3.2 schematic.

### 18.6 Clone boards

Compatible-looking clones may differ in:

- battery polarity
- charger IC/current
- OLED controller/address
- Vext behavior
- RF oscillator and matching network
- flash package
- LED polarity
- sleep current

Validate the actual hardware during bring-up.

---

## 19. Source hierarchy

For hardware decisions, use this priority:

1. Electrical measurements on the exact board revision
2. Correct Heltec schematic for that revision
3. Heltec revision-specific pin map and hardware update log
4. Known-working firmware definitions such as MeshCore
5. Espressif and Semtech component documentation
6. Generic framework defaults and community examples

---

## 20. Primary references

- Heltec WiFi LoRa 32 V3 product page  
  <https://heltec.org/project/wifi-lora-32-v3/>

- Heltec current WiFi LoRa 32 documentation  
  <https://wiki.heltec.org/docs/devices/open-source-hardware/esp32-series/lora-32/wifi-lora-32-v3/>

- Heltec V3 hardware update log  
  <https://docs.heltec.org/en/node/esp32/wifi_lora_32/hardware_update_log.html>

- Heltec V3.1 schematic  
  <https://resource.heltec.cn/download/WiFi_LoRa_32_V3/HTIT-WB32LA%28F%29_V3.1_Schematic_Diagram.pdf>

- Heltec V3.2 schematic  
  <https://resource.heltec.cn/download/WiFi_LoRa_32_V3/WiFi_LoRa_32_V3.2_Schematic_Diagram.pdf>

- Heltec V3.2 product manual and pin map  
  <https://resource.heltec.cn/download/WiFi_LoRa_32_V3/HTIT-WB32LA_V3.2.pdf>

- MeshCore Heltec V3 configuration  
  <https://github.com/meshcore-dev/MeshCore/blob/main/variants/heltec_v3/platformio.ini>

- PlatformIO Heltec V3 board documentation  
  <https://docs.platformio.org/en/latest/boards/espressif32/heltec_wifi_lora_32_V3.html>

- Espressif ESP32-S3 datasheet  
  <https://www.espressif.com/sites/default/files/documentation/esp32-s3_datasheet_en.pdf>

- Espressif ESP32-S3 hardware design guidelines  
  <https://www.espressif.com/sites/default/files/documentation/esp32-s3_hardware_design_guidelines_en.pdf>

- Semtech SX1262 product page and datasheet  
  <https://www.semtech.com/products/wireless-rf/lora-connect/sx1262>

---

## 21. Compact machine-readable summary

```yaml
board:
  manufacturer: Heltec Automation
  model: WiFi LoRa 32 V3
  revisions:
    - V3
    - V3.1
    - V3.2
  preferred_reference_revision: V3.2
  aliases:
    - Heltec LoRa 32 V3
    - heltec_wifi_lora_32_V3
    - HELTEC_LORA_V3

mcu:
  part: ESP32-S3FN8
  architecture: Xtensa LX7
  cores: 2
  max_clock_hz: 240000000
  flash_bytes: 8388608
  psram: false
  wifi: 802.11bgn_2_4GHz
  bluetooth: BLE
  native_usb:
    d_minus: 19
    d_plus: 20
    connected_to_primary_connector_by_default: false

radio:
  part: SX1262
  spi:
    nss: 8
    sck: 9
    mosi: 10
    miso: 11
  reset: 12
  busy: 13
  dio1: 14
  dio2_function: rf_switch_control
  dio3_function: tcxo_control
  tcxo_voltage: 1.8
  reference_frequency_hz: 32000000
  antenna_connector: U.FL
  meshcore_nominal_tx_power_dbm: 22

display:
  type: monochrome_oled
  width: 128
  height: 64
  controller_compatible: SSD1306
  expected_i2c_address: 0x3c
  i2c:
    sda: 17
    scl: 18
  reset: 21
  powered_by: Vext

user_io:
  button:
    gpio: 0
    active_level: low
    shared_with_bootstrap: true
  led:
    gpio: 35
    active_level: high

vext:
  voltage: 3.3
  enable_gpio: 36
  active_level: low
  powers_oled: true
  exposed_header_name: Ve

battery_measurement:
  adc_gpio: 1
  adc_unit: ADC1
  adc_channel: 0
  upper_resistor_ohms: 390000
  lower_resistor_ohms: 100000
  nominal_multiplier: 4.9
  control_gpio: 37
  v3_2_control_active_level: high
  pre_v3_2_control_active_level: low

serial:
  uart: 0
  tx_gpio: 43
  rx_gpio: 44
  bridge: CP2102
  connector: USB_Type_C
  auto_bootloader_control: true

optional_meshcore_gps_convention:
  rx_gpio: 47
  tx_gpio: 48
  enable_gpio: 26
  gps_onboard: false

constraints:
  strapping_gpio:
    - 0
    - 3
    - 45
    - 46
  jtag_gpio:
    - 39
    - 40
    - 41
    - 42
  native_usb_gpio:
    - 19
    - 20
  revision_sensitive_gpio:
    - 37
```
