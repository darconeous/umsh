# LILYGO T-Beam Supreme Hardware Reference

This document describes the **LILYGO T-Beam Supreme** at the level needed to port and maintain UMSH firmware, with primary attention to the **ESP32-S3 + SX1262** versions currently sold for 433/868/915/920-ish MHz operation.

It is intended to be readable by both humans and software agents. It combines:

- LILYGO's current T-Beam Supreme product page and hardware documentation
- LILYGO's `LilyGo-LoRa-Series` board definitions and example source
- Meshtastic's current `tbeam-s3-core` target
- MeshCore's current `lilygo_tbeam_supreme_SX1262` target and board helper
- the published LILYGO V3.0/V3.1 schematic resources (as references)
- ESP32-S3, SX1262, AXP2101, GNSS, display, RTC, and sensor behavior relevant to firmware

Where hardware revisions or software sources disagree, the discrepancy is called out explicitly.

> **Important identification warning**
>
> “T-Beam” names several substantially different LILYGO products. This document is for the **T-Beam Supreme / T-Beam S3 Supreme**, built around the **ESP32-S3** and **AXP2101**. It is not applicable to the older ESP32-based T-Beam boards.
>
> The Supreme is also sold with different radio and GNSS populations. This document gives the complete board-level information that is common to the Supreme family, but the initial UMSH radio target should be the **SX1262 variant**. The **LR1121** version needs a different radio driver and additional RF-switch handling. LILYGO also currently lists a 144–148 MHz product option; do not assume that its RF path is electrically equivalent to the normal sub-GHz SX1262 versions.

---

## 1. Executive summary

The T-Beam Supreme is a feature-rich ESP32-S3 LoRa/GNSS board containing:

- Espressif **ESP32-S3FN8**, dual-core Xtensa LX7, up to 240 MHz
- **8 MiB flash**
- **8 MiB external QSPI PSRAM**
- Semtech **SX1262** LoRa transceiver on the SX1262 product variant
- optional **LR1121** radio on another product variant
- selectable **L76K** or **u-blox MAX-M10-series** GNSS module
- **AXP2101** PMIC with software-controlled peripheral rails and battery telemetry
- 1.3-inch **SH1106**, 128×64 monochrome OLED
- **BME280** environmental sensor
- **QMI8658** six-axis IMU
- one of **QMC6310U**, **QMC6310N**, or **QMC6309** magnetometers depending on board revision/population
- battery-backed I2C RTC, treated by LILYGO's example software, Meshtastic, and MeshCore as a **PCF8563 at 0x51**
- microSD/TF card socket
- 3.7 V single-cell / 18650 battery support and charging
- native ESP32-S3 USB through USB-C
- BOOT, RESET, and PMIC POWER buttons
- GNSS PPS LED and PMIC charge LED
- an M.2-style expansion interface and an external power/header interface

### 1.1 The Supreme is a carrier, and the Core is the module

The **T-Beam S3 Core** is an M.2-form-factor module carrying the ESP32-S3 and the AXP2101. The **T-Beam S3 Supreme** is a carrier board with a Core seated in its M.2 slot. Meshtastic's hardware model for this product is `LILYGO_TBEAM_S3_CORE` for exactly that reason.

This matters for the power topology and is easy to get backwards. The PMIC is on the *module*, so the M.2 supplies are rails the module **exports to the carrier**, not rails the board provides to a card it hosts. On the Supreme carrier nothing consumes them.

It also fixes where board-specific decisions belong: which exported rails are wanted is a property of the carrier, so it lives in the board-support crate, not in the PMIC driver. A different carrier is a new BSP with a different rail table.

The critical UMSH assignments for the **SX1262 version** are:

| Function | ESP32-S3 GPIO | Notes |
| --- | ---: | --- |
| SX1262 SCK | 12 | Dedicated radio SPI bus |
| SX1262 MOSI | 11 | Dedicated radio SPI bus |
| SX1262 MISO | 13 | Dedicated radio SPI bus |
| SX1262 NSS / CS | 10 | Active low |
| SX1262 RESET | 5 | Active low |
| SX1262 BUSY | 4 | Radio output, host input |
| SX1262 DIO1 IRQ | 1 | Radio interrupt |
| Sensor/display I2C SDA | 17 | OLED, BME280, magnetometer |
| Sensor/display I2C SCL | 18 | OLED, BME280, magnetometer |
| PMU/RTC I2C SDA | 42 | AXP2101 + RTC |
| PMU/RTC I2C SCL | 41 | AXP2101 + RTC |
| AXP2101 IRQ | 40 | Active-low interrupt output |
| GNSS UART RX at ESP32 | 9 | Receives GNSS TX |
| GNSS UART TX at ESP32 | 8 | Drives GNSS RX |
| GNSS PPS | 6 | Also drives physical PPS LED |
| L76K wake/control | 7 | L76K population only |
| SD/IMU shared SPI SCK | 36 | Separate from LoRa SPI |
| SD/IMU shared SPI MOSI | 35 | Separate from LoRa SPI |
| SD/IMU shared SPI MISO | 37 | Separate from LoRa SPI |
| SD CS | 47 | |
| QMI8658 CS | 34 | |
| QMI8658 INT | 33 | |
| RTC INT | 14 | |
| BOOT/user button | 0 | Active low; also a strapping pin |
| External UART TX | 43 | LILYGO labels `Uart1 TX` |
| External UART RX | 44 | LILYGO labels `Uart1 RX` |

The single most important architectural difference from a simpler ESP32-S3 LoRa board such as the Heltec LoRa 32 V3 is the **AXP2101 PMIC**: the LoRa radio, GNSS, display/sensors, SD card, and expansion rails are not merely passive 3.3 V loads. Firmware must initialize the PMIC and enable the required rails before probing the corresponding peripherals.

---

## 2. Product variants and hardware revisions

### 2.1 Radio variants

LILYGO documents two normal Supreme radio populations:

- **SX1262** — the variant relevant to the first UMSH port
- **LR1121** — a different Semtech transceiver supporting sub-GHz and 2.4 GHz operation

The LILYGO store currently exposes SX1262-oriented frequency choices including 433, 868, 915, and 920 MHz, as well as a 144–148 MHz option. LILYGO's newer documentation describes the ordinary SX1262 family as 433/868/915/923 MHz.

The SX1262 silicon itself has a broad tuning range, but **the board RF matching network, filtering, and supplied antenna are frequency-specific**. UMSH must not infer hardware-band compatibility only from what frequency the SX1262 can be programmed to synthesize.

For a first implementation, treat each sold RF population as a hardware SKU and enforce the appropriate UMSH regulatory region/frequency plan.

### 2.2 GNSS variants

LILYGO sells the board with either:

- **L76K**, or
- **u-blox MAX-M10-series** GNSS (product listings often simply say `UBLOX`; current LILYGO documentation names MAX-M10S).

Both use the same main UART pins. GPIO7 is specifically documented as the **L76K wake-up/control** line and should not be assumed to have the same function on the u-blox population.

### 2.3 V3.0 and V3.1

LILYGO publishes separate V3.0 and V3.1 schematic files. Its older hardware notes explicitly call out these V3.1 changes:

1. magnetometer changed to **QMC6309**
2. an onboard **BMS** was added
3. a BME280 address-selection resistor was added, permitting `0x76` or `0x77`
4. an OLED address-selection resistor was added, permitting `0x3C` or `0x3D`

LILYGO also notes that the GNSS PPS LED is **blue on V3.0** and **red on V3.1**.

This means an implementation should not use OLED or magnetometer address as an implicit board-revision test. Probe devices by address/type instead.

### 2.4 Magnetometer/display production populations

LILYGO documents at least these combinations on the sensor I2C bus:

| Magnetometer | Magnetometer address | Normal SH1106 address |
| --- | ---: | ---: |
| QMC6310U | `0x1C` | `0x3C` |
| QMC6310N | `0x3C` | `0x3D` |
| QMC6309 | `0x7C` | `0x3C` by default; V3.1 can be strapped |

The reason the QMC6310N population uses display address `0x3D` is straightforward: QMC6310N itself occupies `0x3C`.

**UMSH should probe `0x3C` and `0x3D` for the SH1106 rather than hard-code one address.**

### 2.5 Recommended hardware identity policy

The board name alone is not enough to identify all electrically relevant details. A robust UMSH board abstraction should model at least:

- radio type: SX1262 vs LR1121
- RF hardware band/SKU
- GNSS type: L76K vs u-blox
- display address discovered at runtime (`0x3C` or `0x3D`)
- magnetometer type/address discovered at runtime
- BME280 address (`0x77` normally; possibly `0x76`)

The first UMSH target can deliberately support only `radio = SX1262`, while still probing the other variable peripherals.

---

## 3. MCU, flash, PSRAM, and USB

### 3.1 ESP32-S3FN8

The Supreme uses the **ESP32-S3FN8**:

- dual Xtensa LX7 cores
- up to 240 MHz
- 2.4 GHz 802.11 b/g/n Wi-Fi
- Bluetooth 5-class BLE controller; no Bluetooth Classic
- native USB 2.0 full-speed peripheral
- 8 MiB in-package flash

LILYGO's documented Arduino configuration uses:

- board: `ESP32S3 Dev Module`
- flash: 8 MB, QIO at 80 MHz
- PSRAM: QSPI PSRAM
- USB CDC on boot: enabled
- USB mode: CDC and JTAG

UMSH should use an ESP32-S3 flash/partition layout sized for 8 MiB and enable the external PSRAM when appropriate.

### 3.2 PSRAM

Unlike the ordinary Heltec LoRa 32 V3 reference platform, the T-Beam Supreme has **8 MiB PSRAM**.

This can materially reduce pressure on internal SRAM for:

- packet queues
- UI frame/state
- GNSS parsing buffers
- OTA staging metadata
- filesystem caches
- network stacks

However, DMA buffers and latency-sensitive structures may still need internal/DMA-capable memory. Do not blindly move SPI or radio DMA buffers into PSRAM.

### 3.3 Native USB

LILYGO's supported Arduino setup explicitly uses the ESP32-S3's native USB CDC/JTAG path. Therefore UMSH should preserve GPIO19/GPIO20 for native USB unless it intentionally gives up USB connectivity.

Normal manual ROM-loader recovery is the familiar ESP32-S3 sequence:

1. hold BOOT
2. assert/release RESET
3. release BOOT
4. reconnect/retry flashing

The BOOT button is GPIO0 and affects the reset strap state.

---

## 4. SX1262 LoRa subsystem

### 4.1 Physical interface

For the SX1262 Supreme, LILYGO and Meshtastic agree on the following assignments:

| SX1262 signal | ESP32-S3 GPIO | Direction from ESP32 | UMSH role |
| --- | ---: | --- | --- |
| NSS / CS | 10 | output | SPI chip select |
| SCK | 12 | output | SPI clock |
| MOSI | 11 | output | SPI host → radio |
| MISO | 13 | input | SPI radio → host |
| NRESET | 5 | output | active-low radio reset |
| BUSY | 4 | input | command/wakeup handshake |
| DIO1 | 1 | input | radio IRQ |

These pins form a **dedicated radio SPI bus**. They are not the same bus as the SD card and QMI8658.

### 4.2 Cross-check against Meshtastic

Meshtastic's current `variants/esp32s3/tbeam-s3-core/variant.h` defines:

```c
#define LORA_RESET 5
#define LORA_DIO1 1
#define LORA_DIO2 4
#define SX126X_CS 10
#define SX126X_DIO1 1
#define SX126X_BUSY 4
#define SX126X_RESET 5

#define LORA_SCK 12
#define LORA_MISO 13
#define LORA_MOSI 11
#define LORA_CS 10
```

Here `LORA_DIO2=4` is legacy/naming abstraction around the SX126x **BUSY** pin; it should not be interpreted as the physical SX1262 DIO2 pin.

Meshtastic also specifies:

```c
#define SX126X_DIO2_AS_RF_SWITCH
#define SX126X_DIO3_TCXO_VOLTAGE 1.8
```

That is implementation-relevant even though DIO2 and DIO3 are not connected to ESP32 GPIOs: they are configured *inside the SX1262*.

### 4.3 Cross-check against MeshCore

MeshCore's `TBeamBoard.h` contains the correct Supreme-specific radio pin set:

```c
#define P_LORA_DIO_1   1
#define P_LORA_NSS     10
#define P_LORA_RESET   5
#define P_LORA_BUSY    4
#define P_LORA_SCLK    12
#define P_LORA_MISO    13
#define P_LORA_MOSI    11
```

However, the current Supreme `platformio.ini` also contains a stale-looking set of classic T-Beam-style radio definitions (`NSS=18`, `SCK=5`, `MISO=19`, `MOSI=27`, etc.). Those are inconsistent with the Supreme hardware and with MeshCore's own `TBeamBoard.h`.

**Do not copy the `platformio.ini` legacy-looking radio pin values into UMSH.** The Supreme-specific values above are the correct ones and agree with LILYGO and Meshtastic.

### 4.4 BUSY behavior

The SX1262 BUSY line is GPIO4. Firmware must:

- wait for BUSY low before commands when required by the SX1262 protocol
- wait for BUSY low after reset/wakeup
- use timeouts so a broken or unpowered radio does not hang boot forever

Remember that the radio's **ALDO3 PMIC rail must be enabled first**. A permanently high/low or nonsensical BUSY signal during bring-up may simply mean the radio is not powered.

### 4.5 Reset

GPIO5 drives SX1262 reset. A conservative bring-up sequence is:

1. enable the radio power rail
2. allow the rail to settle
3. assert NRESET low
4. release NRESET high
5. wait for BUSY to deassert
6. initialize SPI and radio configuration

Use the exact timing requirements from the SX1262 driver/datasheet.

### 4.6 DIO1

GPIO1 is the sole host-visible radio interrupt in the normal SX1262 design. The firmware should route the needed SX1262 IRQ sources to DIO1 and attach the ESP32 interrupt accordingly.

Likely IRQ uses include:

- RX done
- TX done
- timeout
- CRC error
- CAD completion/detection
- preamble/header events if needed by UMSH's receive-state logic

### 4.7 DIO2 RF switch and DIO3 TCXO

The RF-switch role is well supported by the upstream implementations:

- Meshtastic explicitly enables **SX1262 DIO2 as RF-switch control**.
- LILYGO's factory-test source explicitly calls `setDio2AsRfSwitch(true)` for the SX1262 path.

These are SX1262 internal DIO functions, not ESP32 GPIO assignments. UMSH should explicitly configure DIO2 as the RF-switch control rather than assuming a library default or looking for separate ESP32 TX/RX-enable pins.

The **DIO3 TCXO voltage is an actual upstream-source inconsistency**:

- LILYGO's bundled RadioLib declares the SX1262 `begin()` default as **1.6 V**.
- LILYGO's T-Beam Supreme SX1262 PingPong example calls `radio.begin(freq)` without overriding that argument, so the manufacturer example uses **1.6 V**.
- Current MeshCore's Supreme target does not define `SX126X_DIO3_TCXO_VOLTAGE`; its `CustomSX1262` therefore also falls back to **1.6 V**.
- Meshtastic explicitly defines `SX126X_DIO3_TCXO_VOLTAGE` as **1.8 V** for this board.

Both 1.6 V and 1.8 V therefore have upstream precedent. The reviewed text documentation does not unambiguously identify the populated TCXO's required supply voltage. For an initial UMSH port, **1.6 V is the closest match to LILYGO's own current example**, but the value should be a board constant and validated on physical V3.0/V3.1 hardware. Meshtastic's 1.8 V setting is a known alternative if testing shows it preferable.

Do **not** select 0 V / crystal mode merely to make initialization succeed unless physical-board validation establishes that a particular population actually uses an XTAL rather than a DIO3-powered TCXO.

### 4.8 Transmit power

LILYGO's SX1262 example uses **22 dBm** output power. MeshCore also sets `LORA_TX_POWER=22`.

Treat 22 dBm as the board/radio maximum requested setting, not a universally legal UMSH setting. Actual permitted power depends on:

- regulatory region
- modulation/bandwidth mode
- antenna gain
- applicable Part 15/ETSI/etc. rules
- the actual RF SKU and matching network

### 4.9 Frequency variants and antenna

LILYGO currently sells multiple RF populations. The firmware should not allow an arbitrary software region to silently turn a 915 MHz hardware SKU into a 433 MHz device.

For UMSH it is preferable to represent the hardware band explicitly, then validate the requested region/channel plan against it.

Always attach an appropriate antenna before transmitting.

---

## 5. AXP2101 power-management subsystem

### 5.1 PMU interface

The AXP2101 is central to this board.

| Signal | Value |
| --- | --- |
| I2C bus | PMU/RTC bus |
| SDA | GPIO42 |
| SCL | GPIO41 |
| 7-bit address | `0x34` |
| IRQ | GPIO40 |

The PMU bus is separate from the OLED/sensor bus.

### 5.2 Power-channel map

Reading the channel map against the schematic, rather than against what other firmware happens to enable:

| AXP2101 channel | Load on the Supreme carrier |
| --- | --- |
| DCDC1 / DC1 | ESP32-S3 core supply — **do not casually reconfigure/disable** |
| DCDC2 | unused |
| DCDC3 | exported to the carrier's M.2 slot — unused |
| DCDC4 | exported to the carrier's M.2 slot — unused |
| DCDC5 | exported to the carrier's M.2 slot — unused |
| ALDO1 | BME280 + SH1106 OLED + QMC6309 magnetometer |
| ALDO2 | **unused** |
| ALDO3 | LoRa radio |
| ALDO4 | GNSS |
| BLDO1 | SD card |
| BLDO2 | external pin/header rail — unused |
| DLDO1, DLDO2 | unused |
| CPUSLDO | not traced |
| VBACKUP | pin left floating |

Remember §1.1 when reading the M.2 entries: those are the Core module's outputs *to* the carrier.

Two of these disagree with what the other stacks do, and the schematic wins:

- **ALDO2 powers nothing.** LILYGO's own code and MeshCore both bring it up — MeshCore labels it the QMC6310U rail — and Meshtastic's comment goes further, claiming it "cannot be turned off" and that it supplies the PCF8563. That comment is in a branch shared with the T-Watch S3, which is the likely source of the RTC claim. On this carrier the magnetometer, BME280, and OLED are all on ALDO1.
- **VBACKUP's pin is floating**, so the backup-battery charger has nothing to charge. This also explains §17.2: GNSS hot-start depends on the battery because the backup domain is fed from the cell, not through the PMIC's backup charger.

UMSH therefore enables ALDO1/ALDO3/ALDO4 at 3.3 V and switches every other reachable channel off explicitly, so none of them is left at a reset default nobody chose. The exceptions are DCDC1, which no type in the driver can name, and CPUSLDO, whose load has not been traced — an output nobody has followed is not one to switch off blind.

Both LILYGO's current example code and MeshCore configure the peripheral rails to roughly 3.3 V before enabling them, with DCDC4 handled according to the AXP2101 voltage API/range in the older helper code. MeshCore additionally powers BLDO2, DCDC4, and DCDC5 out to the headers; UMSH does not.

### 5.3 Critical warning: PMU initialization is prerequisite hardware initialization

On this board, a failed I2C probe does **not** necessarily mean a peripheral is absent.

Before probing:

- LoRa: enable ALDO3
- GNSS: enable ALDO4
- OLED/BME/magnetometer: enable ALDO1
- SD: enable BLDO1

LILYGO's code also power-cycles ALDO1, ALDO2, and BLDO1 for about 250 ms on a cold boot to avoid devices holding/occupying buses during initialization. MeshCore copied the same strategy. UMSH cycles ALDO1 and BLDO1 only: the point of the cycle is to make a device that latched onto a bus let go, and ALDO2 has nothing behind it to let go.

A UMSH port should preserve that behavior unless testing establishes that a simpler sequence is safe across V3.0/V3.1 populations.

### 5.4 Recommended UMSH PMU bring-up

A safe initial sequence is:

1. initialize the PMU I2C controller on SDA42/SCL41
2. probe AXP2101 at `0x34`
3. initialize the AXP2101 driver
4. **never disable DCDC1**, which supplies the ESP32-S3
5. on cold boot, consider disabling ALDO1/BLDO1 briefly as LILYGO and MeshCore do
6. configure required rails to 3.3 V
7. enable ALDO3 before radio access
8. enable ALDO4 before GNSS access
9. enable ALDO1 before sensor/display I2C access
10. enable BLDO1 before SD access
11. switch off every channel the carrier does not consume, rather than leaving it at its reset default
12. configure charge current/target voltage
13. enable battery/VBUS/system measurement ADCs if telemetry is desired
14. clear stale PMU IRQ status before enabling desired IRQs

### 5.5 PMU interrupt

GPIO40 is the AXP2101 interrupt line. LILYGO examples configure it as an input with pull-up and use a falling-edge ISR.

Useful events can include:

- VBUS insertion/removal
- battery insertion/removal
- charge start/complete
- PMIC power-key events

UMSH does not need all of them initially, but it should clear latched PMU status correctly when using the IRQ.

### 5.6 PMIC power key

The physical POWER button is connected to the AXP2101's power-key input, not to an ordinary ESP32 GPIO.

Therefore:

- power-key events are PMU events
- long-press shutdown timing is PMU-configurable
- software should not invent an ESP32 GPIO for the POWER button

MeshCore currently configures a 4-second PMIC power-off press time. LILYGO documentation/examples have used different/default timings. This is **software policy**, not a pinout difference.

---

## 6. Battery, charging, and power telemetry

### 6.1 Battery

The board is designed for a **single-cell 3.7 V nominal Li-ion/18650** battery.

LILYGO explicitly notes that GNSS backup/hot-start behavior depends on the battery being present.

### 6.2 Charging

The AXP2101 provides battery charging. LILYGO's documentation describes programmable charging, and both LILYGO reference code and MeshCore currently select:

- constant-current charge setting: **500 mA**
- charge target: **4.2 V**

A UMSH port can reasonably use 500 mA as the known-working default, provided the intended battery is suitable for that current.

Do not raise the charge current merely because the PMIC supports a larger programmable range.

### 6.3 Battery voltage and state

There is no need for the Heltec-style external resistor-divider ADC calculation. The AXP2101 can report battery/system/VBUS voltage directly.

MeshCore's `TBeamBoard::getBattMilliVolts()` simply returns the PMU battery-voltage reading.

For state-of-charge percentage, keep in mind that PMIC-reported percentage may require learning/calibration and should not be treated as a precision measurement immediately after first boot.

### 6.4 Charge LED

The charge LED is controlled through/by the PMU charge logic. LILYGO's code configures the AXP2101 charging LED mode rather than treating it as a general GPIO LED.

Do not assign a generic UMSH status LED to it unless deliberately controlling the corresponding PMIC function.

### 6.5 Battery thermistor (TS)

The TS pin is **populated** on this board, per the schematic.

Both other stacks disable TS measurement — MeshCore in its Supreme branch with the comment that it is not used, Meshtastic unconditionally for every AXP2101 board. The unconditional form reads like a default that was never revisited, and on a single-cell 18650 a charger with working thermal protection is worth having, so UMSH enables the channel instead.

One question remains open, and a populated footprint does not answer it: a TS footprint is often fitted with a plain fixed resistor rather than an NTC, purely so the charger sees a valid mid-range reading and does not fold back. Both populations report a plausible temperature at room temperature. The distinguishing test is whether the reading **moves** — warm the cell by hand for a minute and watch successive values. Tracking ambient means a real NTC and real protection; a steady value means a stand-in resistor, in which case enabling the channel is harmless but buys nothing.

Two further transcription items are unproven and should be settled on hardware:

- the TS result register address, inferred from the regular two-register-per-channel spacing of that ADC block rather than read off a datasheet page
- whether the part gates the charger's *response* to TS separately from the ADC channel enable

Until both are settled, treat the reading as raw counts. UMSH does not convert it to a temperature or display it.

---

## 7. GNSS subsystem

### 7.1 UART electrical mapping

The effective ESP32-side UART assignment is:

| Function | GPIO |
| --- | ---: |
| ESP32 RX, receives GNSS TX | **9** |
| ESP32 TX, drives GNSS RX | **8** |
| GNSS PPS | **6** |
| L76K wake/control | **7** |

LILYGO reference code uses:

```c
#define GPS_RX_PIN 9
#define GPS_TX_PIN 8
#define GPS_EN_PIN 7
#define GPS_PPS_PIN 6

SerialGPS.begin(GPS_BAUD_RATE, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
```

with `GPS_BAUD_RATE = 9600` in the Supreme example.

Meshtastic uses the same host-side interpretation: `GPS_RX_PIN=9`, `GPS_TX_PIN=8`, and passes those directly as the ESP32 UART RX/TX pins.

### 7.2 Apparent MeshCore RX/TX discrepancy is mostly naming

MeshCore's Supreme `platformio.ini` defines:

```text
PIN_GPS_RX=8
PIN_GPS_TX=9
PIN_GPS_EN=7
```

At first sight this contradicts LILYGO and Meshtastic. But MeshCore later configures Arduino `Serial1` as:

```c
Serial1.setPins(PIN_GPS_TX, PIN_GPS_RX);
```

For ESP32 Arduino, the first argument is the UART receive pin and the second is transmit. Thus the resulting electrical assignment is still:

- UART RX = `PIN_GPS_TX` = GPIO9
- UART TX = `PIN_GPS_RX` = GPIO8

In other words, MeshCore's macro names are effectively written from the **GNSS-module signal perspective**, while LILYGO/Meshtastic use the **host UART perspective**.

UMSH should avoid this ambiguity entirely. Prefer names such as:

```text
GNSS_UART_HOST_RX = 9
GNSS_UART_HOST_TX = 8
```

or explicitly annotate both endpoint directions.

### 7.3 GNSS power

GNSS main power is supplied by **AXP2101 ALDO4** at 3.3 V in LILYGO and MeshCore initialization.

GPIO7 should not be used as a substitute for the PMIC rail. It is a GNSS control/wake signal on the L76K population.

### 7.4 L76K versus u-blox

The board may contain either receiver.

UMSH should initially implement a generic NMEA path and, if it sends vendor-specific configuration messages, select them only after detecting/configuring the GNSS type.

Particular cautions:

- GPIO7 wake/control is documented only for L76K
- u-blox binary UBX commands should not be sent blindly to an L76K
- L76K-specific commands should not be assumed on u-blox
- default baud may be changed by previous firmware, so an optional baud-probe/recovery path is useful

### 7.5 PPS and PPS LED

GPIO6 carries the GNSS PPS signal and is also wired to the board's PPS indicator LED.

LILYGO states that the PPS LED cannot be independently disabled because it follows the PPS signal directly. V3.0 uses a blue PPS LED and V3.1 uses a red one.

Therefore GPIO6 is **not a free user LED pin** and must be configured as a GNSS PPS input if PPS is used.

MeshCore's current `platformio.ini` contains `P_LORA_TX_LED=6`, which would be suspicious on this hardware. Its `TBeamBoard` deliberately excludes the LoRa-TX-LED callbacks for the Supreme, so the current board helper does not intentionally toggle GPIO6 for radio TX. UMSH should simply model GPIO6 as PPS, never as a LoRa LED.

---

## 8. The two I2C buses

The Supreme uses two independent logical I2C buses.

### 8.1 Sensor/display bus

| Signal | GPIO |
| --- | ---: |
| SDA | 17 |
| SCL | 18 |

Devices can include:

| Device | Normal 7-bit address |
| --- | ---: |
| SH1106 OLED | `0x3C` or `0x3D` |
| QMC6310U | `0x1C` |
| QMC6310N | `0x3C` |
| QMC6309 | `0x7C` |
| BME280 | `0x77`, optionally `0x76` on selectable/modded boards |

This bus must not be probed before the PMIC sensor/display rails are enabled.

### 8.2 PMU/RTC bus

| Signal | GPIO |
| --- | ---: |
| SDA | 42 |
| SCL | 41 |

| Device | 7-bit address |
| --- | ---: |
| AXP2101 | `0x34` |
| RTC | `0x51` |

### 8.3 Arduino `Wire` naming is not portable board truth

Do not encode `Wire` versus `Wire1` as part of the hardware model.

Different firmware sources assign those Arduino objects differently:

- MeshCore explicitly uses `Wire` for GPIO17/18 and `Wire1` for GPIO42/41.
- Meshtastic's Arduino board variant maps default Arduino `Wire` pins to GPIO42/41 while separately defining the sensor I2C pins as 17/18 for its board code.

The hardware fact is only that the board has the **17/18 sensor bus** and the **42/41 PMU/RTC bus**. In ESP-IDF/Rust, either hardware I2C controller can be routed to either pin pair.

---

## 9. SH1106 OLED

### 9.1 Interface

The display is a 1.3-inch, 128×64 monochrome **SH1106** on the sensor I2C bus:

- SDA = GPIO17
- SCL = GPIO18
- address = `0x3C` or `0x3D`
- supply = PMIC-controlled sensor/display rail, primarily ALDO1 in current LILYGO documentation/code

No separate ESP32 display-reset GPIO is identified in the current Supreme pin map; power cycling/reinitialization is the practical board-level reset mechanism.

### 9.2 Address detection

Probe both candidate addresses.

Recommended logic:

1. enable ALDO1/required sensor rail
2. initialize the 17/18 I2C bus
3. determine magnetometer population if useful
4. probe `0x3C`
5. probe `0x3D`
6. initialize SH1106 at the address that corresponds to an actual display

Be aware that `0x3C` may be the **QMC6310N magnetometer**, not the OLED. Merely receiving an ACK at `0x3C` is not enough to conclude that the display lives there.

If both `0x3C` and `0x3D` ACK, the likely QMC6310N population has:

- magnetometer = `0x3C`
- OLED = `0x3D`

### 9.3 Meshtastic and MeshCore handling

Meshtastic identifies the display as SH1106 but its board-level variant does not encode a single immutable address, which is appropriate for the production variation.

MeshCore's Supreme build currently sets `DISPLAY_ADDRESS=0x3D`, but its current `SH1106Display::begin()` probes that address and then automatically tries the other address (`0x3C`) if necessary. This was important because earlier hard-coded handling caused blank-display reports on some Supreme populations.

UMSH should implement address probing from the beginning.

---

## 10. BME280 environmental sensor

The onboard BME280 is on the GPIO17/18 sensor I2C bus.

- normal/default address: `0x77`
- alternate selectable address: `0x76` on boards/revisions with the address-selection provision

LILYGO's V3.1 notes explicitly add a BME280 address-selection resistor.

MeshCore's current target is internally inconsistent in a harmless-but-confusing way:

- `platformio.ini` selects telemetry BME280 address `0x77`
- `TBeamBoard.h` contains an `I2C_BME280_ADD 0x76` constant
- its debug scanner recognizes both `0x76` and `0x77`

For UMSH, probe `0x76` and `0x77`; prefer chip-ID validation over address assumption.

---

## 11. Magnetometer

The magnetometer is revision/population-dependent:

| Part | Address |
| --- | ---: |
| QMC6310U | `0x1C` |
| QMC6310N | `0x3C` |
| QMC6309 | `0x7C` |

All are on the GPIO17/18 I2C bus.

For basic UMSH radio support, magnetometer support can be deferred. However, the probe logic still matters because the magnetometer address determines whether `0x3C` is available to the OLED.

A future sensor driver should identify the actual part rather than treating all QMC variants as register-compatible without verification.

---

## 12. QMI8658 IMU and SD card SPI bus

### 12.1 Shared peripheral SPI bus

The QMI8658 and SD card use a second SPI bus that is independent of the LoRa radio:

| Signal | GPIO |
| --- | ---: |
| SCK | 36 |
| MOSI | 35 |
| MISO | 37 |
| SD CS | 47 |
| QMI8658 CS | 34 |
| QMI8658 interrupt | 33 |

This topology allows radio traffic and sensor/storage traffic to be managed as separate SPI peripherals/controllers.

If UMSH puts them on distinct ESP32 SPI hosts, simultaneous operations are easier to schedule. If framework limitations cause them to share a controller abstraction, per-device locking still needs to preserve CS state and settings.

### 12.2 Meshtastic comment typo

Meshtastic's current `pins_arduino.h` comments refer to **QMI8653** on this shared SPI bus, while LILYGO documentation and the actual board family identify the IMU as **QMI8658**. Treat the Meshtastic comment as a typo, not a different Supreme IMU population.

### 12.3 SD power

The microSD/TF card is powered from **AXP2101 BLDO1**. Enable BLDO1 before initializing the card.

LILYGO and MeshCore both power-cycle this rail during cold initialization as part of avoiding bus-peripheral startup problems.

---

## 13. RTC

### 13.1 Interface

The RTC is on the PMU/RTC I2C bus:

| Function | Value |
| --- | --- |
| SDA | GPIO42 |
| SCL | GPIO41 |
| address | `0x51` |
| interrupt | GPIO14 |

### 13.2 Device-name inconsistency in LILYGO documentation

LILYGO's newer documentation is internally inconsistent:

- its feature list/product table names **PCF85063ATL**
- its I2C address table names **PCF8563** at `0x51`

LILYGO's older Supreme hardware document links a PCF8563 datasheet and calls the RTC PCF8563. Meshtastic explicitly configures a PCF8563 RTC at `0x51`. MeshCore also treats the device as PCF8563-compatible/autodetected.

For UMSH, the safe implementation guidance is:

1. assume an RTC exists at `0x51`
2. use a driver only after confirming which register model is actually populated on supported boards, or use a compatible probe abstraction
3. do not make obscure chip-specific alarm/clock assumptions solely from the newer marketing table

Basic time read/write is likely straightforward, but alarm/interrupt behavior should be validated on physical hardware before depending on it.

### 13.3 RTC interrupt

GPIO14 is the published RTC interrupt line. It can be useful as a low-power wake source, but alarm polarity/open-drain behavior should be configured according to the actual RTC driver and board pull-up network.

---

## 14. Buttons and LEDs

### 14.1 BOOT/user button

GPIO0 is the BOOT button.

- active low at runtime
- also an ESP32-S3 boot strapping pin
- holding it low across reset enters the ROM download path

It can be used as the normal UMSH user button after boot.

### 14.2 RESET

The reset button resets the ESP32-S3 through its enable/reset circuitry. It is not a general GPIO input.

### 14.3 POWER

The POWER button is the AXP2101 PMIC key, discussed above. Handle it via PMU events/policy.

### 14.4 PPS LED

The PPS LED follows GNSS PPS on GPIO6. It is not independently controllable.

### 14.5 Charge LED

The charge LED is managed by the AXP2101 charge LED function. It is not a normal ESP32 user LED.

### 14.6 No ordinary free status LED

Unlike the Heltec LoRa 32 V3, do not assume the Supreme has a convenient dedicated GPIO-driven user/status LED. UMSH UI/status should primarily use the OLED or deliberately choose an exposed GPIO/external LED.

---

## 15. External UART and expansion pins

LILYGO's current pin map exposes:

| Function | GPIO |
| --- | ---: |
| external UART TX | 43 |
| external UART RX | 44 |

These are separate from the GNSS UART pins 8/9.

LILYGO associates GPIO43/44 with its QWIIC/expansion presentation. Exact connector use should be verified against the intended carrier/accessory before assigning alternate functions.

The Core module also exports PMIC-controlled power rails through the expansion interfaces, notably BLDO2 and the DCDC3/DCDC4/DCDC5 M.2 supplies (§1.1). Nothing on the Supreme carrier consumes them, so UMSH switches them off; a carrier that does want one wants explicit ownership and a voltage chosen on purpose, not a generic always-on 3.3 V pin.

---

## 16. ESP32-S3 pin caveats

### 16.1 GPIO0

GPIO0 is a strapping pin and the BOOT button. External loads must not force it low during reset unless ROM download mode is intended.

### 16.2 Native USB

GPIO19/GPIO20 are the ESP32-S3 native USB pins. The documented Supreme toolchain uses native USB CDC/JTAG. Do not allocate them to application peripherals if USB is required.

### 16.3 JTAG and GPIO39–42

ESP32-S3 default JTAG functions overlap GPIO39–42. On the Supreme:

- GPIO40 = PMU IRQ
- GPIO41 = PMU/RTC SCL
- GPIO42 = PMU/RTC SDA

That already consumes most of this group. Debug configuration must not remap or electrically fight those board functions.

### 16.4 GPIO1

GPIO1 is SX1262 DIO1. Do not treat it as a spare ADC/touch GPIO simply because the ESP32-S3 peripheral matrix permits that function.

### 16.5 Peripheral matrix flexibility does not make onboard pins free

The ESP32-S3 can route many peripheral signals through the GPIO matrix. Nevertheless, every pin in the critical tables above is physically connected to board hardware and must remain reserved unless the associated device is intentionally disabled and electrical loading is understood.

---

## 17. Low-power behavior

The Supreme offers considerably more power-control opportunity than a board with fixed peripheral rails because the AXP2101 can shut down large peripheral groups.

Before ESP32-S3 deep sleep, a battery-oriented UMSH implementation should consider:

1. put SX1262 into the chosen sleep mode
2. ensure DIO3/TCXO and RF-switch state are appropriate for sleep
3. disable LoRa ALDO3 if wake-on-radio is not required and the restart cost is acceptable
4. stop GNSS and disable ALDO4 when location is not needed
5. disable OLED/sensor rails when no display/sensor activity is needed
6. unmount/idle SD and disable BLDO1 when appropriate
7. disable Wi-Fi/BLE as required
8. configure GPIO pulls to avoid back-powering unpowered peripherals
9. select wake sources such as BOOT, RTC INT, timer, or radio DIO1 according to the use case
10. enter ESP32-S3 deep sleep

### 17.1 Wake-on-radio tradeoff

MeshCore has code to use SX1262 DIO1 as an ESP32 deep-sleep wake source. If UMSH wants the same behavior, **the radio power rail must remain on** and the SX1262 must be configured in a state capable of generating the intended DIO1 event.

This has a higher standby cost than completely removing radio power, so it should be a deliberate operating mode.

### 17.2 GNSS backup

LILYGO notes that GNSS backup power/hot-start capability depends on the installed battery. Removing the battery may make every GNSS startup effectively colder/slower even when USB is used to power the board.

---

## 18. Source comparison and discrepancies

This section summarizes the most important cross-source findings for an implementation agent.

### 18.1 Pinout comparison

| Function | LILYGO | Meshtastic | MeshCore effective behavior | Conclusion for UMSH |
| --- | --- | --- | --- | --- |
| LoRa SCK | 12 | 12 | 12 in `TBeamBoard.h` | **12** |
| LoRa MOSI | 11 | 11 | 11 in `TBeamBoard.h` | **11** |
| LoRa MISO | 13 | 13 | 13 in `TBeamBoard.h` | **13** |
| LoRa CS | 10 | 10 | 10 in `TBeamBoard.h` | **10** |
| LoRa RESET | 5 | 5 | 5 in `TBeamBoard.h` | **5** |
| LoRa BUSY | 4 | 4 | 4 in `TBeamBoard.h` | **4** |
| LoRa DIO1 | 1 | 1 | 1 in `TBeamBoard.h` | **1** |
| Sensor I2C SDA/SCL | 17/18 | 17/18 | 17/18 | **17/18** |
| PMU I2C SDA/SCL | 42/41 | 42/41 | 42/41 | **42/41** |
| PMU IRQ | 40 | 40 | 40 | **40** |
| ESP GNSS RX/TX | 9/8 | 9/8 | 9/8 after `setPins()` | **9/8** |
| GNSS PPS | 6 | 6 | build has stale TX-LED=6 but board helper avoids using it | **6 PPS only** |
| L76K wake | 7 | 7 | 7 | **7** |
| shared SPI SCK/MOSI/MISO | 36/35/37 | 36/35/37 | 36/35/37 | **36/35/37** |
| SD CS | 47 | 47 | 47 (helper macro has a spelling typo) | **47** |
| IMU CS/INT | 34/33 | 34/33 | 34/33 | **34/33** |
| RTC INT | 14 | 14 | 14 | **14** |
| BOOT | 0 | 0 | 0 | **0** |

### 18.2 MeshCore stale radio defines

MeshCore's Supreme `platformio.ini` contains classic/older T-Beam-looking `P_LORA_*` values that conflict with LILYGO and Meshtastic. MeshCore's Supreme-specific `TBeamBoard.h` contains the correct values and its target uses that board helper.

Treat the `TBeamBoard.h` Supreme definitions as the relevant MeshCore pinout evidence. Do not copy the stale values.

### 18.3 GNSS naming discrepancy

LILYGO/Meshtastic say host `RX=9`, `TX=8`.

MeshCore names the macros `PIN_GPS_RX=8`, `PIN_GPS_TX=9`, but passes them to `Serial1.setPins()` in the opposite order, yielding host RX=9/TX=8. This is a naming-convention mismatch, not an electrical mismatch.

### 18.4 Display-address variation

LILYGO explicitly documents `0x3C` and `0x3D` populations.

MeshCore has historically had blank-display problems because of this variation. Current MeshCore source now probes its configured SH1106 address and the alternate address. UMSH should probe both from day one.

### 18.5 BME280 address variation

LILYGO defaults to `0x77`, with `0x76` selectable on newer hardware. MeshCore source contains constants for both in different places. Probe both.

### 18.6 RTC part-name discrepancy

Current LILYGO marketing documentation names PCF85063ATL in one table but PCF8563 in its I2C table; older LILYGO docs and both community firmware projects treat it as PCF8563 at `0x51`.

Do not make chip-specific alarm assumptions without validation. The pin/address facts are much better established than the marketing part name.

### 18.7 IMU typo

Meshtastic has a comment saying QMI8653; LILYGO consistently documents QMI8658. Use **QMI8658**.

### 18.8 PMIC channel mapping is strongly corroborated

LILYGO reference code and MeshCore independently agree on the firmware-critical rails:

- ALDO4 GNSS
- ALDO3 radio
- ALDO1 sensors/display
- BLDO1 SD
- BLDO2 external header
- DCDC3/4/5 M.2

This mapping should be considered high-confidence for the rails that carry a load.

It says nothing about the rails that do not. Both stacks *enable* ALDO2, and MeshCore additionally enables BLDO2, DCDC4, and DCDC5; none of that establishes a load, and the schematic shows none. Agreement between two firmwares is evidence about what they do, not about what the board is — see §5.2.

### 18.9 Old LILYGO `DC1` sensor-power note conflicts with current code

An older LILYGO hardware-documentation note says that devices on the GPIO17/18 I2C bus need their sensor power supply connected to **DC1**. That statement conflicts with the newer power-channel table and with both LILYGO's current reference code and MeshCore:

- **DCDC1/DC1 is the ESP32-S3 core supply** and should not be reconfigured or disabled.
- **ALDO1** powers the BME280, OLED, and magnetometer — the whole GPIO17/18 sensor population (§5.2).

Treat the older `DC1` sentence as a documentation error or stale wording. UMSH must not repurpose or cycle DCDC1 while running.

### 18.10 MeshCore display behavior changed recently

Current MeshCore `SH1106Display.cpp` (modified August 2026 in the checked source) explicitly probes `DISPLAY_ADDRESS` and the alternate address. Older issue reports describing a permanently hard-coded address may therefore describe earlier releases rather than current `main`.

For UMSH implementation, copy the robust *idea* (probe), not a version-specific fixed address.

### 18.11 TCXO voltage differs between upstream projects

LILYGO's current SX1262 example and current MeshCore both arrive at a **1.6 V** DIO3 TCXO setting through RadioLib defaults, while Meshtastic explicitly selects **1.8 V**. This is not a pinout disagreement, but it is a board-configuration disagreement that can affect radio initialization and oscillator operation.

UMSH should keep the TCXO voltage explicit and board-specific rather than inheriting a radio-library default. Start with 1.6 V to match the manufacturer example, then validate on physical boards; retain 1.8 V as the Meshtastic-proven comparison point.

---

## 19. Recommended startup sequence for UMSH

A deterministic initial implementation should bring the board up in roughly this order:

1. **Basic ESP32-S3 setup**
   - initialize logging/native USB as needed
   - keep BOOT GPIO0 as input/high unless intentionally entering download mode

2. **PMU/RTC I2C**
   - initialize I2C on SDA42/SCL41
   - probe AXP2101 at `0x34`
   - initialize PMU IRQ GPIO40 if used

3. **AXP2101 rails**
   - do not disturb DCDC1
   - on a true cold boot, reproduce the LILYGO/MeshCore brief ALDO1/BLDO1 power-cycle unless testing justifies removing it
   - configure ALDO3 = 3.3 V for radio
   - configure ALDO4 = 3.3 V for GNSS
   - configure ALDO1 = 3.3 V for onboard sensors/display
   - configure BLDO1 = 3.3 V for SD if needed
   - switch off ALDO2, BLDO2, DCDC2–5, and DLDO1/2 explicitly
   - configure charge current (known-working default 500 mA) and 4.2 V target
   - enable PMU ADC measurements used by telemetry, TS included (§6.5)

4. **LoRa SPI and SX1262**
   - initialize SCK12/MOSI11/MISO13, CS10
   - configure RESET5, BUSY4, DIO1=1
   - reset the radio
   - configure DIO3 TCXO using the selected board constant (start with 1.6 V per LILYGO/RadioLib; Meshtastic uses 1.8 V)
   - configure DIO2 RF-switch control
   - apply hardware-region-valid frequency and legal TX power
   - route radio IRQs to DIO1

5. **Sensor/display I2C**
   - initialize SDA17/SCL18 only after sensor/display rails are powered
   - scan/probe relevant addresses
   - determine SH1106 address 0x3C/0x3D
   - optionally identify BME280 and magnetometer population

6. **GNSS**
   - ensure ALDO4 is on
   - configure host UART RX9/TX8, typically starting at 9600 baud
   - configure GPIO6 as PPS input if used
   - use GPIO7 only according to L76K behavior/detection
   - detect generic NMEA first before issuing vendor-specific commands

7. **IMU / SD**
   - initialize the second SPI bus SCK36/MOSI35/MISO37
   - keep both CS lines inactive before bus startup
   - QMI8658 CS34, INT33
   - SD CS47; enable BLDO1 before card init

8. **RTC**
   - probe `0x51` on the 42/41 bus
   - configure GPIO14 if RTC alarms/wakeup are used

9. **Application services**
   - bring up Wi-Fi/BLE/UI/storage only after board resources have deterministic owners and power state

This sequence deliberately brings **power management before peripheral probing**. Reversing those steps is one of the easiest ways to misdiagnose the Supreme as having missing hardware.

---

## 20. Suggested UMSH board definition

The exact Rust/board abstraction should match the existing UMSH architecture, but the hardware constants should be equivalent to the following:

```rust
pub const BOARD_NAME: &str = "LILYGO T-Beam Supreme SX1262";

// SX1262 dedicated SPI
pub const LORA_SCK: i32 = 12;
pub const LORA_MOSI: i32 = 11;
pub const LORA_MISO: i32 = 13;
pub const LORA_NSS: i32 = 10;
pub const LORA_RESET: i32 = 5;
pub const LORA_BUSY: i32 = 4;
pub const LORA_DIO1: i32 = 1;

pub const LORA_DIO2_CONTROLS_RF_SWITCH: bool = true;
pub const LORA_DIO3_TCXO_VOLTAGE: f32 = 1.6; // LILYGO/RadioLib + current MeshCore; Meshtastic uses 1.8 V

// Sensor/display I2C
pub const SENSOR_I2C_SDA: i32 = 17;
pub const SENSOR_I2C_SCL: i32 = 18;
pub const OLED_ADDR_CANDIDATES: &[u8] = &[0x3C, 0x3D];
pub const BME280_ADDR_CANDIDATES: &[u8] = &[0x77, 0x76];

// PMU / RTC I2C
pub const PMU_I2C_SDA: i32 = 42;
pub const PMU_I2C_SCL: i32 = 41;
pub const AXP2101_ADDR: u8 = 0x34;
pub const PMU_IRQ: i32 = 40;
pub const RTC_ADDR: u8 = 0x51;
pub const RTC_INT: i32 = 14;

// GNSS -- names are explicitly ESP32-host direction
pub const GNSS_UART_HOST_RX: i32 = 9;
pub const GNSS_UART_HOST_TX: i32 = 8;
pub const GNSS_PPS: i32 = 6;
pub const GNSS_L76K_WAKE: i32 = 7;
pub const GNSS_DEFAULT_BAUD: u32 = 9600;

// SD + IMU shared SPI
pub const PERIPH_SPI_SCK: i32 = 36;
pub const PERIPH_SPI_MOSI: i32 = 35;
pub const PERIPH_SPI_MISO: i32 = 37;
pub const SD_CS: i32 = 47;
pub const IMU_CS: i32 = 34;
pub const IMU_INT: i32 = 33;

pub const USER_BUTTON: i32 = 0;
pub const USER_BUTTON_ACTIVE_LOW: bool = true;

pub const EXT_UART_TX: i32 = 43;
pub const EXT_UART_RX: i32 = 44;
```

The board abstraction also needs **non-pin resources** that are just as important as GPIO constants:

```text
PMU: AXP2101 @ 0x34 on GPIO42/41
radio power rail: ALDO3 @ 3.3 V
GNSS power rail: ALDO4 @ 3.3 V
sensor/display rail: ALDO1 @ 3.3 V
SD power rail: BLDO1 @ 3.3 V
unused, switched off: ALDO2, BLDO2, DCDC2/3/4/5, DLDO1/2
```

Do not bury those relationships in ad-hoc startup code. They are board topology and belong in the hardware definition/board-support layer.

---

## 21. Suggested implementation milestones

For another agent implementing support, a practical order is:

### Milestone 1 — boot + PMU + radio

- add the ESP32-S3 Supreme target/build configuration
- enable 8 MiB flash and 8 MiB PSRAM support
- implement AXP2101 I2C on 42/41
- enable ALDO3
- bring up SX1262 on 12/11/13/10/5/4/1
- configure DIO2 RF switch + explicit DIO3 TCXO voltage (start with 1.6 V; validate against Meshtastic's 1.8 V setting)
- verify TX/RX with UMSH

This is enough for a minimally useful radio node.

### Milestone 2 — button, battery, USB

- GPIO0 active-low user button
- AXP2101 battery/VBUS telemetry
- PMU power-key event behavior if desired
- native USB console/flashing behavior

### Milestone 3 — GNSS

- ALDO4 power control
- UART host RX9/TX8
- generic NMEA parse
- PPS GPIO6
- L76K/u-blox detection and model-specific configuration only where needed

### Milestone 4 — OLED

- enable sensor/display rails
- I2C 17/18
- robust 0x3C/0x3D discovery
- SH1106 driver

### Milestone 5 — onboard sensors/storage

- BME280 0x77/0x76 detection
- magnetometer population detection
- QMI8658 on peripheral SPI
- SD on same SPI with separate CS and BLDO1 power ownership
- RTC at 0x51 / INT14

### Milestone 6 — low power

- explicit PMIC rail shutdown policy
- SX1262 sleep policy
- optional wake on DIO1
- GNSS power/wake policy
- RTC alarm wake
- measurement of actual current in each state

---

## 22. Bring-up validation checklist

An implementation agent should validate the following on physical hardware rather than considering compile success sufficient:

- AXP2101 responds at `0x34` on GPIO42/41
- radio ALDO3 can be toggled and reaches the intended voltage
- SX1262 BUSY changes plausibly after power/reset
- SX1262 can read/write registers and transmit/receive on the correct RF SKU
- DIO1 GPIO1 generates RX/TX IRQs
- radio initializes reliably and frequency behavior is validated with the selected TCXO voltage (1.6 V baseline; compare 1.8 V if needed)
- battery voltage reported by AXP2101 roughly agrees with a multimeter
- with ALDO2 off, the sensor bus and the RTC at `0x51` both still answer — the direct test of §5.2's claim that nothing is on it, against LILYGO, MeshCore, and Meshtastic all enabling it
- with DCDC2–5, BLDO2, and DLDO1/2 off, nothing on the carrier misbehaves
- TS raw counts sit at a plausible steady value, and **move** when the cell is warmed by hand — a value that does not move means a fixed resistor rather than an NTC (§6.5)
- sensor I2C bus does not wedge after cold boot
- SH1106 address is detected correctly on at least two board populations if available
- BME280 is detected at the actual board address
- GNSS NMEA arrives on host RX GPIO9
- GNSS configuration commands leave host TX GPIO8
- PPS appears on GPIO6 after GNSS lock
- L76K wake GPIO7 behavior is tested only on L76K hardware
- SD and QMI8658 coexist correctly on the shared 35/36/37 SPI bus
- RTC responds at `0x51`
- BOOT button does not accidentally trap normal resets in download mode
- deep sleep does not back-power disabled peripheral rails through GPIOs
- wake-on-radio works only when the radio rail/state is intentionally retained

---

## 23. Sources reviewed

Research for this document was performed on **2026-08-25**. Upstream `main`/`master`/`develop` branches may change after that date.

### UMSH reference style

- UMSH hardware documentation directory:  
  https://github.com/darconeous/umsh/tree/main/docs/hardware
- Heltec LoRa 32 V3 hardware reference used as the closest style/architecture reference:  
  https://github.com/darconeous/umsh/blob/main/docs/hardware/heltec-lora32-v3-hardware.md

### LILYGO

- Current T-Beam Supreme product page:  
  https://lilygo.cc/en-us/products/t-beam-supreme
- Current LILYGO documentation page/source:  
  https://github.com/Xinyuan-LilyGO/documentation/blob/master/en/products/t-beam-series/t-beam-supreme/index.md
- Original `LilyGo-LoRa-Series` Supreme hardware document:  
  https://github.com/Xinyuan-LilyGO/LilyGo-LoRa-Series/blob/master/docs/en/t_beam_supreme/t_beam_supreme_hw.md
- Board/source repository:  
  https://github.com/Xinyuan-LilyGO/LilyGo-LoRa-Series
- Supreme SX1262 RadioLib example:  
  https://github.com/Xinyuan-LilyGO/LilyGo-LoRa-Series/blob/master/examples/LoRa/TBeam_S3_Supreme/SX1262_PingPong/SX1262_PingPong.ino
- Common board utility/power initialization source (`utilities.h`, `LoRaBoards.cpp`) in the LILYGO examples
- Published schematic resources:  
  https://github.com/Xinyuan-LilyGO/LilyGo-LoRa-Series/tree/master/schematic/T-Beam-S3-Supreme
  - `T-Beam-S3-Core.pdf`
  - `T-Beam-S3-Supreme-V3.0.pdf`
  - `T-Beam-S3-Supreme-V3.1.pdf`

### Meshtastic

- Repository:  
  https://github.com/meshtastic/firmware
- Supreme target directory:  
  https://github.com/meshtastic/firmware/tree/develop/variants/esp32s3/tbeam-s3-core
- Important files reviewed:
  - `variant.h`
  - `pins_arduino.h`
  - `platformio.ini`
  - `rfswitch.h`
  - `src/gps/GPS.cpp`

The source snapshot returned during research was around commit `8eda86045b12203da23fb39dca12a0a4b5f346a1` for indexed Meshtastic search results.

### MeshCore

- Repository:  
  https://github.com/meshcore-dev/MeshCore
- Supreme target directory:  
  https://github.com/meshcore-dev/MeshCore/tree/main/variants/lilygo_tbeam_supreme_SX1262
- Important files reviewed:
  - `variants/lilygo_tbeam_supreme_SX1262/platformio.ini`
  - `variants/lilygo_tbeam_supreme_SX1262/target.h`
  - `variants/lilygo_tbeam_supreme_SX1262/target.cpp`
  - `src/helpers/esp32/TBeamBoard.h`
  - `src/helpers/esp32/TBeamBoard.cpp`
  - `src/helpers/radiolib/CustomSX1262.h`
  - `src/helpers/sensors/MicroNMEALocationProvider.h`
  - `src/helpers/sensors/EnvironmentSensorManager.cpp`
  - `src/helpers/ui/SH1106Display.cpp`

The source snapshot returned during research was around commit `0679dbeffc504d562d2f09eb072fdc223f8ffc2a` for indexed MeshCore search results.

---

## 24. Final implementation guidance

For an initial UMSH port, the highest-confidence and highest-value path is:

1. target **ESP32-S3 + SX1262** explicitly
2. model the **AXP2101 as a mandatory board component**, not an optional telemetry peripheral
3. use the radio pinout **12/11/13/10/5/4/1**
4. use **DIO2 RF-switch control** and an **explicit DIO3 TCXO voltage**; start with LILYGO's 1.6 V default and validate against Meshtastic's 1.8 V setting
5. use two logical I2C buses: **17/18 sensors** and **42/41 PMU/RTC**
6. name GNSS pins by **host direction**: RX9/TX8
7. probe SH1106 `0x3C`/`0x3D`, BME280 `0x77`/`0x76`, and magnetometer variants instead of hard-coding one production population
8. keep GPIO6 reserved for GNSS PPS, never a generic TX LED
9. keep LoRa SPI separate from the SD/QMI8658 SPI bus
10. defer LR1121-specific support to a separate board/radio variant rather than hiding it behind the SX1262 definition

Those choices align the LILYGO hardware description, LILYGO's working examples, Meshtastic's current target, and the corrected/board-specific portions of MeshCore while avoiding the inconsistencies identified above.
