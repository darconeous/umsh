# Heltec WiFi LoRa 32 V2 Hardware Reference

This document describes the **Heltec WiFi LoRa 32 V2** at the level needed to port and maintain UMSH firmware.

It is intended to be readable by both humans and software agents. It combines:

- Heltec’s published V2 schematic and product documentation
- the Espressif Arduino/PlatformIO board definition
- MeshCore’s `heltec_v2` variant configuration
- ESP32 and SX1276/SX1278 device documentation

Where the sources disagree, the discrepancy is called out explicitly. The schematic should be treated as the highest-authority source for board wiring, while working firmware definitions are useful confirmation of the pins actually used in practice.

> **Important identification warning**
>
> This document is specifically for the original **WiFi LoRa 32 V2**, built around the classic dual-core ESP32 and an SX1276/SX1278-class radio. It is not applicable to the visually similar V3/V4 boards, which use an ESP32-S3 and SX1262 and have substantially different internal wiring and software behavior.

---

## 1. Executive summary

The Heltec WiFi LoRa 32 V2 is a compact development board containing:

- Classic Espressif ESP32, dual-core Xtensa LX6, up to 240 MHz
- 8 MiB external SPI flash
- Semtech SX1276 or SX1278 LoRa transceiver, depending on frequency variant
- 0.96-inch 128×64 monochrome OLED, normally driven as an SSD1306-compatible display
- CP2102 USB-to-UART bridge
- Micro-USB connector
- Single-cell Li-ion/LiPo battery connector
- TP4054 linear battery charger
- 3.3 V regulator and automatic USB/battery source selection
- Switchable external 3.3 V rail named `Vext`
- Battery-voltage measurement circuit
- User/program button on GPIO0
- Reset button
- User/status LED on GPIO25
- U.FL/IPEX LoRa antenna connector
- Fixed onboard 2.4 GHz antenna for Wi-Fi/Bluetooth
- Two rows of 18 through-hole header positions

The critical UMSH pin assignments are:

| Function | ESP32 GPIO |
|---|---:|
| SX127x SPI SCK | 5 |
| SX127x SPI MOSI | 27 |
| SX127x SPI MISO | 19 |
| SX127x NSS/CS | 18 |
| SX127x reset | 14 |
| SX127x DIO0 | 26 |
| SX127x DIO1 | 35 |
| SX127x DIO2 | 34 |
| OLED SDA | 4 |
| OLED SCL | 15 |
| OLED reset | 16 |
| User/program button | 0 |
| LED | 25 |
| Battery ADC | 13 |
| `Vext` and battery-divider enable | 21 |
| USB serial TX from ESP32 | 1 |
| USB serial RX into ESP32 | 3 |

MeshCore uses the same LoRa, OLED, button, and LED assignments, except that it does not currently declare SX127x DIO2.

---

## 2. Board variants and radio type

Heltec sold the V2 in several frequency-specific versions.

| Nominal board variant | Typical radio | Intended range |
|---|---|---|
| 433 MHz / 470–510 MHz | SX1278 or corresponding low-band assembly | 433 MHz and CN470-class use |
| 863–928 MHz | SX1276 | EU868, US915, AU915, AS923, IN865, KR920, etc. |

The PCB-level digital interface is effectively the same between these versions, but the RF matching network and radio population differ.

Do not assume that a board sold as “V2” supports every LoRa frequency. The assembled RF network and antenna must match the intended band.

The current Heltec product page contains a misleading title referring to an SX1262, while its detailed description, specifications, schematic, and established firmware definitions identify the V2 radio as SX1276/SX1278. For this board, the SX127x identification is the credible one.

---

## 3. MCU and memory

### 3.1 ESP32

The board uses the original ESP32 family, not the ESP32-S3.

Relevant properties:

- Dual Xtensa LX6 cores
- Maximum CPU clock: 240 MHz
- Wi-Fi: 2.4 GHz 802.11b/g/n
- Bluetooth Classic and Bluetooth Low Energy 4.2
- 520 KiB total on-chip SRAM at the chip level
- No external PSRAM on the normal V2 board
- Hardware peripherals include SPI, I2C, UART, ADC, DAC, touch sensing, RMT, LEDC PWM, and the ULP coprocessor

The PlatformIO board definition reports:

- MCU: `esp32`
- Flash: 8 MiB
- Flash mode: DIO
- Flash clock: 40 MHz
- CPU clock: 240 MHz
- Upload speed: 460800 baud
- Arduino partition layout: `default_8MB.csv`

### 3.2 External flash

The schematic shows a Winbond `W25Q64`, an 8 MiB SPI NOR flash.

GPIO6 through GPIO11 are used by the ESP32’s flash interface and must not be treated as general-purpose pins, even if a package-level ESP32 reference lists them.

### 3.3 No PSRAM

There is no external PSRAM shown in the schematic or declared by the board definition.

Firmware should therefore be designed around internal RAM constraints. Large receive queues, frame buffers, cryptographic working sets, and Wi-Fi/Bluetooth coexistence can put meaningful pressure on available heap.

---

## 4. LoRa radio subsystem

### 4.1 Radio interface

The onboard SX1276/SX1278 is connected to a dedicated SPI bus assignment:

| SX127x signal | ESP32 GPIO | MeshCore name |
|---|---:|---|
| SCK | 5 | `P_LORA_SCLK` |
| MOSI | 27 | `P_LORA_MOSI` |
| MISO | 19 | `P_LORA_MISO` |
| NSS / CS | 18 | `P_LORA_NSS` |
| NRESET | 14 | `P_LORA_RESET` |
| DIO0 | 26 | `P_LORA_DIO_0` |
| DIO1 | 35 | `P_LORA_DIO_1` |
| DIO2 | 34 | not declared by MeshCore V2 config |

GPIO34 and GPIO35 are input-only ESP32 pins, which is appropriate for SX127x interrupt outputs.

Neither pin has an ESP32-internal pull-up or pull-down. Firmware should not depend on an internal bias resistor on DIO1 or DIO2.

### 4.2 MeshCore radio configuration

MeshCore’s Heltec V2 build uses:

```ini
-D RADIO_CLASS=CustomSX1276
-D WRAPPER_CLASS=CustomSX1276Wrapper
-D P_LORA_DIO_0=26
-D P_LORA_DIO_1=35
-D P_LORA_NSS=18
-D P_LORA_RESET=14
-D P_LORA_SCLK=5
-D P_LORA_MISO=19
-D P_LORA_MOSI=27
-D SX127X_CURRENT_LIMIT=120
-D LORA_TX_POWER=20
```

This confirms the schematic wiring and provides useful initial policy values:

- Requested transmit power: 20 dBm
- Radio current limit setting: 120 mA

The actual legal and usable transmit power depends on:

- regional regulations
- the selected SX127x device
- board losses and RF-switch losses
- antenna gain
- whether the library correctly selects `PA_BOOST`
- the radio’s over-current-protection configuration

Firmware should not blindly assume that a requested 20 dBm produces exactly 20 dBm at the antenna connector.

### 4.3 RF path and antenna switching

The high-band schematic shows an RF switch between the radio and the U.FL antenna connector.

The SX1276 provides separate receive/high-frequency and PA-boost transmit paths. The board combines these through the external RF switch and matching network.

The schematic annotates the switch control as:

- control high: common RF port connected to one branch
- control low: common RF port connected to the other branch
- the selected control signal is driven by the radio’s `RXTX/RFMOD` output

This means RF transmit/receive path selection is handled by the SX127x/radio circuitry rather than by a separate ESP32 GPIO.

### 4.4 DIO behavior

The SX127x DIO pins are not fixed-function interrupts. Their meanings depend on radio mode and the DIO-mapping registers.

Typical LoRa-mode assignments include:

- DIO0: `RxDone`, `TxDone`, or `CadDone`
- DIO1: `RxTimeout`, `FhssChangeChannel`, or `CadDetected`
- DIO2: `FhssChangeChannel` or another mode-dependent signal

UMSH should configure DIO mapping explicitly and should not assume reset-default mappings are suitable.

### 4.5 Antenna precautions

The LoRa antenna connection is a small U.FL/IPEX connector.

Operational cautions:

- Attach a correctly tuned antenna before transmitting.
- Do not use a 2.4 GHz Wi-Fi antenna as the LoRa antenna.
- Avoid repeatedly mating/unmating U.FL connectors; they have limited mechanical life.
- Prevent the pigtail from applying sideways force to the connector.
- Select an antenna appropriate to the actual board frequency variant.

The onboard metal/spring antenna is for ESP32 Wi-Fi and Bluetooth, not LoRa.

---

## 5. OLED display

### 5.1 Electrical interface

The integrated OLED is a 128×64 monochrome display normally treated by firmware as SSD1306-compatible.

| OLED signal | ESP32 GPIO |
|---|---:|
| SDA | 4 |
| SCL | 15 |
| Reset | 16 |
| Power | `Vext` in the published high-band schematic |

MeshCore configures:

```ini
-D PIN_BOARD_SDA=4
-D PIN_BOARD_SCL=15
-D PIN_OLED_RESET=16
-D DISPLAY_CLASS=SSD1306Display
```

### 5.2 Non-default I2C pins

The OLED does **not** use the generic Arduino ESP32 defaults of SDA=21 and SCL=22.

Board-specific firmware must initialize I2C as:

```text
SDA = GPIO4
SCL = GPIO15
```

### 5.3 Reset sequence

GPIO16 is connected to the OLED reset input.

A robust startup sequence is:

1. Ensure the OLED supply rail is enabled.
2. Drive GPIO16 low.
3. Wait at least a few milliseconds.
4. Drive GPIO16 high.
5. Wait for the controller to become ready.
6. Initialize I2C and the display controller.

### 5.4 OLED power and `Vext`

The published 868–915 MHz schematic shows the OLED supply connected to `Vext`, not directly to the always-on 3.3 V rail.

Therefore, firmware that turns off `Vext` should expect the OLED to lose power. Before accessing the OLED after re-enabling `Vext`, repeat the reset and initialization sequence.

Some libraries for Heltec boards automatically enable `Vext`; a standalone UMSH port should not rely on that hidden behavior.

### 5.5 Likely I2C address

Most V2 software uses the OLED at 7-bit address `0x3C`.

Firmware may use `0x3C` as the expected address, but an I2C probe is useful during board bring-up or clone-board support.

---

## 6. Buttons, reset, and bootloader behavior

### 6.1 PRG/user button

The button marked `PRG`, `BOOT`, or `BTN-0` is connected between GPIO0 and ground.

| Function | GPIO | Active level |
|---|---:|---|
| User/program button | 0 | Low |

The board has an external pull-up on GPIO0.

At ordinary runtime, it can be used as an active-low user button.

At reset, GPIO0 is an ESP32 boot-strapping pin:

- GPIO0 high: normal flash boot
- GPIO0 low: serial ROM download mode

Holding the button during reset therefore enters the ESP32 bootloader.

### 6.2 Reset button

The reset button pulls `CHIP_PU` / `EN` low.

This resets the ESP32 and also participates in manual entry to serial download mode.

### 6.3 Automatic USB flashing

The CP2102 exposes DTR and RTS. A transistor network converts them into automatic control of:

- GPIO0
- `CHIP_PU`

`esptool` and compatible IDEs can normally reset the board into download mode without manual button presses.

If automatic reset fails, use the manual sequence:

1. Hold PRG/BOOT.
2. Press and release RESET.
3. Release PRG/BOOT.
4. Start or retry flashing.

### 6.4 GPIO0 application caveat

Because GPIO0 controls boot mode, external hardware connected to it must not force it low during reset unless serial download mode is intended.

For UMSH, it is safest to use GPIO0 only as the onboard button input.

---

## 7. LED

The onboard user LED is connected to GPIO25.

| Function | GPIO | Polarity |
|---|---:|---|
| User/status LED | 25 | Active high |

The schematic shows the ESP32 driving an LED and series resistor to ground, so a high output turns the LED on.

MeshCore also defines:

```ini
-D P_LORA_TX_LED=25
```

This means MeshCore uses the same LED as a transmit activity indicator.

GPIO25 is also one of the ESP32 DAC-capable pins, but the onboard LED load makes it unsuitable for precision analog output unless the LED circuit is accounted for.

---

## 8. Battery, charging, and power-path behavior

### 8.1 Battery connector

The board has a 2-pin, 1.25 mm-pitch battery connector, commonly described by Heltec as `SH1.25-2`.

It is intended for a single-cell 3.7 V nominal Li-ion/LiPo battery.

The schematic labels:

| Connector pin | Signal |
|---|---|
| 1 | `VBAT` |
| 2 | GND |

Verify polarity on the actual board and battery cable before connecting. Small LiPo connectors are not universally wired with the same polarity.

### 8.2 Charger

The board uses a TP4054 linear single-cell charger.

Relevant schematic details:

- Charger input: USB `+5V`
- Charger battery output: `VBAT`
- Programming resistor: 10 kΩ
- Charge-status output drives the red charge LED
- No charger-status signal is routed to the ESP32

A 10 kΩ programming resistor corresponds to a relatively low charge current, approximately 100 mA for the common TP4054 programming relationship. Clone boards or revised assemblies may differ, so current should be measured if it matters.

Firmware cannot directly determine “charging” or “charge complete” from a charger-status GPIO because no such GPIO connection is shown.

### 8.3 Charge LED

The red LED near the USB/power circuitry is controlled by the TP4054 `CHRG` output.

It is hardware-controlled and is not the GPIO25 user LED.

Typical behavior is:

- illuminated while charging
- off or high-impedance when charging terminates or no charger is present

Exact fault/blink behavior depends on the fitted TP4054-compatible part.

### 8.4 Automatic USB/battery source selection

The power path uses:

- a Schottky diode from USB 5 V toward the regulator input
- a P-channel MOSFET between `VBAT` and the regulator input
- USB voltage controlling the MOSFET gate

Conceptually:

- With USB present, USB supplies the 3.3 V regulator and the battery path is isolated.
- Without USB, the P-channel MOSFET turns on and the battery supplies the regulator.
- The TP4054 can charge the battery whenever USB power is present.

This is a simple automatic source-selection arrangement, not a sophisticated power-path-management IC.

Consequences:

- The system can run while charging.
- System load and charge current share the available USB input.
- There is no firmware-controlled hard power-off.
- There is no fuel-gauge IC.
- There is no charger telemetry interface.
- Behavior at deeply discharged battery voltage is primarily determined by the battery protection circuit, regulator dropout, and ESP32 brownout handling.

### 8.5 Battery protection

Heltec describes the board as providing overcharge protection, but the published schematic does not show a complete dedicated cell-protection IC and dual-MOSFET protection stage on the board.

Therefore:

- Do not assume the board itself provides comprehensive cell undervoltage, overcurrent, or short-circuit protection.
- Prefer a protected single-cell battery pack.
- Do not rely on firmware alone to prevent destructive over-discharge.
- Treat “battery management” in product literature as charging, source selection, and voltage sensing unless hardware testing proves more.

### 8.6 Main 3.3 V regulator

The schematic identifies the regulator as `CE6260`.

Its input is the automatically selected USB-or-battery supply and its output is the board’s main 3.3 V rail.

The regulator powers the ESP32, SX127x, flash, and associated logic.

Practical implications:

- The board’s available 3.3 V output current is limited.
- LoRa transmit current, ESP32 Wi-Fi current bursts, OLED load, and external loads all share the regulator.
- Large external loads on `3.3V` or `Vext` can cause brownouts.
- A high-power peripheral should use an appropriately designed separate regulator rather than treating this board as a general-purpose power supply.

---

## 9. Battery voltage measurement and `Vext`

### 9.1 Shared control signal

GPIO21 performs two related board-control functions:

1. Enables the external `Vext` 3.3 V rail.
2. Completes the lower leg of the battery measurement divider.

This shared behavior is important and easy to miss.

### 9.2 Battery ADC circuit

The battery measurement circuit uses:

- 220 kΩ from `VBAT` to GPIO13
- 100 kΩ from GPIO13 to a switched ground
- an N-channel MOSFET controlled by GPIO21 to connect/disconnect that 100 kΩ resistor

When GPIO21 is high:

- the MOSFET turns on
- the divider becomes active
- GPIO13 sees approximately:

```text
VBAT × 100 kΩ / (220 kΩ + 100 kΩ)
= VBAT / 3.2
```

Therefore:

```text
VBAT ≈ VADC × 3.2
```

At a 4.2 V full battery, the ideal ADC input is approximately 1.3125 V.

When GPIO21 is low:

- the lower divider resistor is disconnected from ground
- the battery divider does not continuously waste current
- GPIO13 should not be interpreted as a valid battery reading

### 9.3 `Vext` switch

`Vext` is generated by a P-channel MOSFET high-side switch from the main 3.3 V rail.

GPIO21 controls an N-channel transistor that pulls the P-channel MOSFET gate low.

Therefore:

| GPIO21 | `Vext` | Battery divider |
|---:|---|---|
| Low | Off | Disconnected |
| High | On | Active |

The control is active high from the firmware’s point of view.

### 9.4 Recommended battery-reading sequence

A robust implementation is:

```text
1. Drive GPIO21 high.
2. Wait for Vext and the divider to settle.
3. Take several ADC samples from GPIO13.
4. Average or median-filter the samples.
5. Convert ADC code to calibrated ADC voltage.
6. Multiply by the measured divider ratio, nominally 3.2.
7. Keep GPIO21 high if the OLED or external Vext peripherals are needed;
   otherwise drive it low.
```

The settle delay need not be long, but the high divider impedance and ESP32 ADC sampling behavior justify allowing at least a few milliseconds and discarding the first reading.

### 9.5 ADC calibration caveat

The classic ESP32 ADC is notably nonlinear and has part-to-part reference variation.

Do not use only:

```text
raw / 4095 × 3.3 × 3.2
```

when accurate battery percentage matters.

Prefer:

- ESP-IDF ADC calibration APIs where available
- attenuation selected for the expected ~0–1.4 V ADC input
- per-board calibration against a multimeter
- averaging or median filtering
- a battery-state model appropriate to Li-ion load and chemistry

GPIO13 is on ADC2. On the classic ESP32, ADC2 access conflicts with active Wi-Fi operation. Battery measurements may fail, block, or become unavailable while Wi-Fi owns ADC2, depending on SDK version and API.

UMSH should either:

- sample the battery before starting Wi-Fi,
- temporarily stop Wi-Fi around the ADC2 reading,
- or treat battery telemetry as unavailable during Wi-Fi operation.

---

## 10. USB and serial console

### 10.1 USB implementation

The Micro-USB connector is not connected to a native ESP32 USB peripheral.

It connects to a Silicon Labs CP2102 USB-to-UART bridge.

Functions provided over USB:

- 5 V power input
- firmware download through the ESP32 ROM serial bootloader
- UART console/debugging
- automatic reset/download-mode control through DTR/RTS

### 10.2 UART pins

| UART0 signal | ESP32 GPIO | CP2102 connection |
|---|---:|---|
| TXD | 1 | CP2102 RXD |
| RXD | 3 | CP2102 TXD |

These signals are also exposed on the board headers.

Any external circuit attached to GPIO1/GPIO3 can interfere with:

- boot messages
- flashing
- console output
- serial control protocols

### 10.3 Boot output

The ROM bootloader prints startup information on UART0.

UMSH should expect unsolicited boot text after reset unless logging is disabled through deeper ESP32 configuration.

---

## 11. Header and exposed-pin map

### 11.1 Orientation warning

Heltec documentation, schematic connector numbering, board silkscreen, and third-party pinout images do not always use the same viewing orientation.

The tables below describe the **schematic connector positions** `JP2` and `JP3`, numbered from 1 at the bottom to 18 at the top as drawn in Heltec’s schematic.

Before designing a mating PCB, verify the physical orientation against the actual board.

### 11.2 JP2

| JP2 position | Signal | Notes |
|---:|---|---|
| 18 | GPIO16 | OLED reset |
| 17 | GPIO17 | General-purpose GPIO / UART-capable |
| 16 | GPIO4 | OLED SDA; boot-related caveats; ADC2/touch capable |
| 15 | GPIO2 | ESP32 strapping pin |
| 14 | GPIO15 | OLED SCL; ESP32 strapping pin |
| 13 | GPIO5 | LoRa SCK; ESP32 strapping pin |
| 12 | GPIO18 | LoRa NSS/CS |
| 11 | GPIO23 | Exposed general-purpose GPIO |
| 10 | GPIO19 | LoRa MISO |
| 9 | GPIO22 | Exposed general-purpose GPIO |
| 8 | GPIO0 | User/boot button; strapping pin |
| 7 | `CHIP_PU` | ESP32 enable/reset |
| 6 | UART0 TXD, GPIO1 | USB console output |
| 5 | UART0 RXD, GPIO3 | USB console input |
| 4 | GPIO21 | `Vext` and battery-divider enable |
| 3 | `Vext` | Switched 3.3 V output |
| 2 | +5 V | USB-derived/raw 5 V rail |
| 1 | GND | Ground |

The exact assignment of positions 4–6 should be visually confirmed on the physical board because the dense schematic labeling is easy to misread. The signal set and GPIO functions are certain; connector position interpretation is based on the published schematic.

### 11.3 JP3

| JP3 position | Signal | Notes |
|---:|---|---|
| 18 | GPIO21 | Same net that controls `Vext` and battery divider |
| 17 | GPIO13 | Battery ADC input when GPIO21 is high |
| 16 | GPIO12 | ESP32 strapping pin; use with care |
| 15 | GPIO14 | LoRa reset |
| 14 | GPIO27 | LoRa MOSI |
| 13 | GPIO26 | LoRa DIO0 |
| 12 | GPIO25 | Onboard LED |
| 11 | GPIO32 / `32K_XN` | Connected to optional 32.768 kHz crystal circuit |
| 10 | GPIO33 / `32K_XP` | Connected to optional 32.768 kHz crystal circuit |
| 9 | GPIO35 | LoRa DIO1; input only |
| 8 | GPIO34 | LoRa DIO2; input only |
| 7 | GPIO39 | Input only |
| 6 | GPIO38 | Input only |
| 5 | GPIO37 | Input only |
| 4 | GPIO36 | Input only |
| 3 | 3.3 V | Main unswitched 3.3 V rail |
| 2 | 3.3 V | Main unswitched 3.3 V rail |
| 1 | GND | Ground |

### 11.4 Pins that are not truly free

Many exposed pins are already committed:

| GPIO | Board function |
|---:|---|
| 0 | User/boot button |
| 1 | USB UART TX |
| 3 | USB UART RX |
| 4 | OLED SDA |
| 5 | LoRa SCK |
| 13 | Battery ADC |
| 14 | LoRa reset |
| 15 | OLED SCL |
| 16 | OLED reset |
| 18 | LoRa NSS |
| 19 | LoRa MISO |
| 21 | `Vext` and battery-divider enable |
| 25 | LED |
| 26 | LoRa DIO0 |
| 27 | LoRa MOSI |
| 34 | LoRa DIO2 |
| 35 | LoRa DIO1 |

GPIO32 and GPIO33 are shown connected to a 32.768 kHz crystal circuit. They should not be assumed free without checking whether the crystal is actually populated and whether the firmware uses it.

### 11.5 Best expansion candidates

Depending on application requirements, the least-conflicted exposed pins are generally:

- GPIO17
- GPIO22
- GPIO23
- GPIO36
- GPIO37
- GPIO38
- GPIO39

However:

- GPIO36–GPIO39 are input-only.
- GPIO36–GPIO39 have no internal pull resistors.
- GPIO37 and GPIO38 availability varies by ESP32 module/package and board assembly; verify on the actual board.
- Any analog use should account for ESP32 ADC limitations.
- GPIO22/23 may be the most convenient bidirectional digital expansion pins.

---

## 12. ESP32 pin restrictions relevant to this board

### 12.1 Input-only pins

GPIO34 through GPIO39 are input-only and lack internal pull-up/pull-down resistors.

On this board:

- GPIO34 = SX127x DIO2
- GPIO35 = SX127x DIO1
- GPIO36–39 are exposed inputs

### 12.2 Boot-strapping pins

The classic ESP32 samples several GPIOs during reset.

Relevant exposed/used strapping pins include:

- GPIO0
- GPIO2
- GPIO5
- GPIO12
- GPIO15

External circuits must not drive these to incompatible levels during reset.

GPIO12 deserves particular caution because an incorrect reset-time level can select an incompatible flash supply voltage on some ESP32 configurations and prevent booting.

### 12.3 ADC2 and Wi-Fi

ADC2 channels cannot be used normally while Wi-Fi is active.

This directly affects the onboard battery ADC on GPIO13.

### 12.4 UART0

GPIO1 and GPIO3 are shared with the CP2102 and serial bootloader.

### 12.5 Flash pins

GPIO6 through GPIO11 are reserved for external flash and are not exposed as normal usable header pins.

---

## 13. Low-power behavior

### 13.1 Published sleep figure

Heltec specifies a board sleep current of no better than approximately 800 µA.

This is much higher than the deep-sleep current of the bare ESP32 and is consistent with always-connected board support circuitry such as:

- regulator quiescent current
- CP2102-related leakage or power paths
- charger and source-selection circuitry
- pull-ups and dividers
- OLED/Vext state
- radio standby/sleep state
- clone-board component variations

### 13.2 Required shutdown steps

Before ESP32 deep sleep, UMSH should generally:

1. Put the SX127x into sleep mode.
2. Stop SPI transactions.
3. Turn the OLED display off.
4. Drive GPIO16 low if appropriate.
5. Drive GPIO21 low to disable `Vext` and the battery divider.
6. Disable Wi-Fi and Bluetooth.
7. Configure wake pins and their pulls explicitly.
8. Avoid leaving external peripherals back-powering the board through GPIOs.
9. Enter ESP32 deep sleep.

### 13.3 Expected battery life

This board is suitable for:

- USB-powered nodes
- intermittently battery-powered development
- short-duration portable use
- applications where sub-milliamp sleep is acceptable

It is not ideal for long-lived small-battery or solar nodes compared with modern nRF52/SX1262 platforms.

Actual sleep current should be measured because clone boards and board revisions vary.

---

## 14. Reset and startup state recommendations

A safe early-boot sequence for UMSH is:

```text
1. Configure GPIO21 low immediately unless OLED/Vext is needed.
2. Configure GPIO25 low to keep the LED off.
3. Configure GPIO14 as output and perform the SX127x reset sequence.
4. Configure GPIO18 high before enabling SPI output to deselect the radio.
5. Configure GPIO26, GPIO35, and optionally GPIO34 as inputs.
6. Initialize SPI using SCK=5, MISO=19, MOSI=27.
7. Probe and initialize the SX127x.
8. If using the display:
   a. set GPIO21 high,
   b. delay for rail stabilization,
   c. pulse GPIO16 low/high,
   d. initialize I2C on SDA=4, SCL=15,
   e. initialize the OLED.
9. Configure GPIO0 as active-low input with pull-up.
10. Delay Wi-Fi startup until any required GPIO13 battery reading is complete.
```

Because GPIO5 and GPIO15 are strapping pins, avoid actively driving them to unexpected levels before boot has completed.

---

## 15. Suggested UMSH board definition

A conceptual board definition could contain:

```rust
pub const BOARD_NAME: &str = "Heltec WiFi LoRa 32 V2";

pub const LORA_SCK: i32 = 5;
pub const LORA_MOSI: i32 = 27;
pub const LORA_MISO: i32 = 19;
pub const LORA_NSS: i32 = 18;
pub const LORA_RESET: i32 = 14;
pub const LORA_DIO0: i32 = 26;
pub const LORA_DIO1: i32 = 35;
pub const LORA_DIO2: i32 = 34;

pub const OLED_SDA: i32 = 4;
pub const OLED_SCL: i32 = 15;
pub const OLED_RESET: i32 = 16;

pub const USER_BUTTON: i32 = 0;
pub const USER_BUTTON_ACTIVE_LOW: bool = true;

pub const STATUS_LED: i32 = 25;
pub const STATUS_LED_ACTIVE_HIGH: bool = true;

pub const VEXT_ENABLE: i32 = 21;
pub const VEXT_ACTIVE_HIGH: bool = true;

pub const BATTERY_ADC: i32 = 13;
pub const BATTERY_DIVIDER_RATIO: f32 = 3.2;
pub const BATTERY_ADC_REQUIRES_VEXT_ENABLE: bool = true;
pub const BATTERY_ADC_IS_ADC2: bool = true;
```

The actual UMSH implementation should express pin ownership and shared-resource constraints, particularly:

- OLED requires `Vext`
- battery ADC requires GPIO21 high
- battery ADC conflicts with active Wi-Fi
- GPIO21 cannot be independently used as an ordinary expansion pin
- GPIO25 is physically loaded by the LED
- UART0 is shared with USB
- GPIO34/35 are input-only

---

## 16. Bring-up checklist

### 16.1 Identification

- Confirm silkscreen says V2 or V2.x.
- Confirm MCU is classic ESP32, not ESP32-S3.
- Confirm radio is SX1276/SX1278-class.
- Confirm frequency variant matches the intended band.
- Attach a suitable antenna before RF testing.

### 16.2 Serial and flashing

- Verify CP2102 appears on USB.
- Verify UART boot output.
- Verify automatic reset into download mode.
- If needed, test manual PRG + RESET sequence.
- Confirm 8 MiB flash before choosing partition layout.

### 16.3 GPIO basics

- Verify GPIO25 LED polarity.
- Verify GPIO0 button reads low when pressed.
- Verify GPIO21 high enables `Vext`.
- Verify GPIO21 low disables `Vext`.

### 16.4 OLED

- Enable GPIO21.
- Reset OLED with GPIO16.
- Scan I2C on GPIO4/GPIO15.
- Expect address 0x3C.
- Draw a known test pattern.
- Disable `Vext` and confirm display powers down.

### 16.5 Battery

- Verify connector polarity.
- Measure charging current.
- Confirm red hardware charge LED behavior.
- Enable GPIO21 and read GPIO13.
- Compare computed battery voltage with a multimeter.
- Test ADC behavior before and after Wi-Fi startup.
- Confirm protected-cell behavior at low voltage.

### 16.6 LoRa

- Read SX127x `RegVersion`; SX1276/77/78/79 commonly returns `0x12`.
- Reset radio through GPIO14.
- Verify SPI communication.
- Configure frequency and regional parameters.
- Verify DIO0 interrupt on packet receive and transmit completion.
- Verify DIO1 if the driver depends on receive timeout or CAD.
- Test at low transmit power first.
- Measure frequency accuracy, output power, and receive sensitivity if equipment is available.

### 16.7 Low power

- Put radio to sleep.
- Turn off display and `Vext`.
- Disable Wi-Fi/Bluetooth.
- Enter ESP32 deep sleep.
- Measure current from the battery connector.
- Compare against the expected board-level floor near 800 µA rather than bare-chip figures.

---

## 17. Known ambiguities and discrepancies

### 17.1 Product-page title says SX1262

The current Heltec page title describes the V2 as an SX1262 board. This conflicts with:

- the same page’s detailed feature list
- the same page’s specification table
- the published V2 schematic
- the Arduino variant
- the PlatformIO board support
- the MeshCore V2 configuration
- historical V2 hardware

Treat the title as a product-page error. The V2 uses SX1276/SX1278-class hardware.

### 17.2 Product page mentions USB-C in one section

The same page includes a generic “USB Type C” highlight, while the V2 schematic, product history, and actual boards use Micro-USB.

Treat Micro-USB as correct for the original V2.

### 17.3 Generic Arduino I2C aliases differ

The Espressif Arduino variant declares generic:

```text
SDA = 21
SCL = 22
```

but separately declares the OLED-specific pins:

```text
SDA_OLED = 4
SCL_OLED = 15
```

MeshCore correctly uses GPIO4/GPIO15 for the board display.

The generic Arduino `Wire` defaults must not be mistaken for the OLED wiring.

### 17.4 Header-position interpretation

The board’s usable signal names are clear from the schematic, but connector numbering and view orientation can be confusing.

Verify any mechanical carrier-board footprint against:

- the physical board
- continuity measurements
- the silkscreen
- a known-good carrier footprint

Do not fabricate a mating PCB from this text alone without that final orientation check.

### 17.5 Clone boards

Many compatible-looking boards exist.

Possible clone differences include:

- charger current
- regulator type
- OLED controller/address
- battery connector polarity
- flash size
- crystal population
- RF matching quality
- LED polarity
- sleep current

Firmware should fail gracefully when optional hardware is absent, and hardware-sensitive assumptions should be validated during first-board bring-up.

---

## 18. Source hierarchy

For board-wiring decisions, use this priority:

1. Electrical measurements on the specific board being supported
2. Heltec V2 schematic for the correct frequency variant
3. Known-working firmware definitions
4. Heltec V2 product documentation
5. Generic framework defaults
6. Third-party pinout diagrams and forum posts

The schematic and MeshCore configuration agree on the critical LoRa pins.

---

## 19. Primary references

- Heltec WiFi LoRa 32 V2 product page  
  <https://heltec.org/project/wifi-lora-32v2/>

- Heltec WiFi LoRa 32 V2 868–915 MHz schematic  
  <https://resource.heltec.cn/download/WiFi_LoRa_32/V2/WIFI_LoRa_32_V2%28868-915%29.PDF>

- Heltec WiFi LoRa 32 V2 433/470–510 MHz schematic  
  <https://resource.heltec.cn/download/WiFi_LoRa_32/V2/WiFi_LoRa_32_V2%28433%2C470-510%29.PDF>

- MeshCore Heltec V2 PlatformIO configuration  
  <https://raw.githubusercontent.com/meshcore-dev/MeshCore/refs/heads/main/variants/heltec_v2/platformio.ini>

- Espressif Arduino Heltec V2 variant pins  
  <https://raw.githubusercontent.com/espressif/arduino-esp32/master/variants/heltec_wifi_lora_32_V2/pins_arduino.h>

- PlatformIO Heltec WiFi LoRa 32 V2 board definition  
  <https://raw.githubusercontent.com/platformio/platform-espressif32/develop/boards/heltec_wifi_lora_32_V2.json>

- Espressif ESP32 datasheet  
  <https://documentation.espressif.com/esp32_datasheet_en.pdf>

- Espressif ESP32 GPIO documentation  
  <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/peripherals/gpio.html>

- Espressif ESP32 ADC documentation  
  <https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/peripherals/adc_oneshot.html>

- Semtech SX1276 product and datasheet page  
  <https://www.semtech.com/products/wireless-rf/lora-connect/sx1276>

---

## 20. Compact machine-readable summary

```yaml
board:
  manufacturer: Heltec Automation
  model: WiFi LoRa 32 V2
  aliases:
    - Heltec LoRa 32 V2
    - heltec_wifi_lora_32_V2
    - HELTEC_LORA_V2
  status: phased_out

mcu:
  family: ESP32
  architecture: Xtensa LX6
  cores: 2
  max_clock_hz: 240000000
  flash_bytes: 8388608
  psram: false
  wifi: 802.11bgn_2_4GHz
  bluetooth: "4.2 BR/EDR + BLE"

radio:
  family: SX127x
  high_band_part: SX1276
  low_band_part: SX1278
  spi:
    sck: 5
    mosi: 27
    miso: 19
    nss: 18
  reset: 14
  dio:
    dio0: 26
    dio1: 35
    dio2: 34
  antenna_connector: U.FL
  rf_switch_control: SX127x_RXTX_RFMOD

display:
  type: monochrome_oled
  width: 128
  height: 64
  controller_compatible: SSD1306
  expected_i2c_address: 0x3c
  i2c:
    sda: 4
    scl: 15
  reset: 16
  powered_by: Vext

user_io:
  button:
    gpio: 0
    active_level: low
    shared_with_bootstrap: true
  led:
    gpio: 25
    active_level: high

power:
  usb_connector: micro_usb
  usb_uart: CP2102
  battery:
    chemistry: single_cell_li_ion_lipo
    nominal_voltage: 3.7
    connector: SH1.25-2
    charger: TP4054
    approximate_charge_current_ma: 100
    charge_status_to_mcu: false
  regulator: CE6260
  automatic_usb_battery_selection: true
  firmware_power_off: false

vext:
  voltage: 3.3
  enable_gpio: 21
  active_level: high
  also_enables_battery_divider: true

battery_measurement:
  adc_gpio: 13
  adc_unit: ADC2
  upper_resistor_ohms: 220000
  lower_resistor_ohms: 100000
  nominal_multiplier: 3.2
  requires_gpio21_high: true
  conflicts_with_active_wifi: true

serial:
  uart: 0
  tx_gpio: 1
  rx_gpio: 3
  bridge: CP2102
  auto_bootloader_control: true

constraints:
  input_only_gpio:
    - 34
    - 35
    - 36
    - 37
    - 38
    - 39
  strapping_gpio:
    - 0
    - 2
    - 5
    - 12
    - 15
  flash_gpio_reserved:
    - 6
    - 7
    - 8
    - 9
    - 10
    - 11
```
