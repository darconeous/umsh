# Seeed Studio SenseCAP Solar Node P1-Pro Hardware Reconstruction

This document summarizes the publicly inferable hardware architecture, pinout,
power behavior, and firmware-relevant details of the Seeed Studio SenseCAP Solar
Node P1-Pro.

It is intended to be both human-readable and useful as implementation context for
an automated coding agent adding UMSH support.

The reconstruction is based primarily on:

- Seeed Studio's current product/wiki documentation
- Meshtastic's `seeed_solar_node` board definition
- MeshCore's `sensecap_solar` board definition and board-support code
- The documented behavior of the component modules named by Seeed

No public system schematic was found during this review. Therefore, the pin map
and behavior descriptions below should be treated as a **firmware-level
reconstruction**, not as a verified electrical schematic. Where the two firmware
implementations disagree, the disagreement is called out explicitly.

## High-level hardware blocks

The SenseCAP Solar Node P1-Pro is built around:

- Seeed XIAO nRF52840 Plus controller
  - Nordic nRF52840
  - 64 MHz ARM Cortex-M4F
  - 256 KiB RAM
  - 1 MiB internal flash
  - 2 MiB external QSPI flash
  - Bluetooth Low Energy
  - native USB
- Seeed Wio-SX1262 LoRa module
  - Semtech SX1262
  - nominal maximum transmit power of 22 dBm
  - 862-930 MHz product range
- Seeed XIAO L76K GNSS module
  - GPS
  - GLONASS
  - Galileo according to Seeed's module summary
  - BeiDou B1 is also listed in the P1-Pro antenna specification
- CN3165 solar Li-ion charging controller
  - approximately 0.99 A charge current according to Seeed
  - apparently autonomous; no firmware control or telemetry interface is exposed
- 5 W solar panel
- Four 3350 mAh 18650 NMC cells in the P1-Pro
- One Grove connector
- USB-C for debugging, flashing, and 5 V input
- External LoRa antenna
- Dedicated GNSS antenna
- Two firmware-controlled LEDs
- Additional charger and solar-panel indicator LEDs that appear to be
  hardware-controlled
- Program/user button, touch/user input, reset, and power switching controls
- Outdoor enclosure rated IPX6

Seeed specifies an enclosure size of approximately 191.2 × 201.2 × 42.1 mm.

## Architecture overview

A plausible firmware-level block diagram is:

```text
                           +----------------------+
USB-C 5 V ---------------->|                      |
Solar panel 5 V ---------->| CN3165 charger /     |----> 4 × 18650 battery pack
                           | power path            |           |
                           +----------------------+           |
                                                              v
                                                  +-----------------------+
                                                  | System power rails    |
                                                  +-----------------------+
                                                              |
                    +-----------------------------------------+------------------+
                    |                                         |                  |
                    v                                         v                  v
          +-------------------+                      +----------------+  +----------------+
          | XIAO nRF52840 Plus|<---- SPI ---------->| Wio-SX1262     |  | XIAO L76K     |
          |                   |                      | LoRa radio      |  | GNSS           |
          | BLE / USB         |<---- UART ------------------------------>|                |
          | QSPI flash        |                      +----------------+  +----------------+
          | battery ADC gate  |
          | LEDs / buttons    |<---- I2C/GPIO/UART ---- Grove connector
          +-------------------+
```

The firmware definitions do not show an I2C- or SPI-addressable power-management
IC. Charging appears to be handled independently by the CN3165. The MCU observes
battery voltage but does not appear to configure the charge current, termination
voltage, or solar-input behavior.

## Arduino pin numbering versus nRF52840 pins

The board definitions use Arduino-style logical pin numbers, not raw Nordic GPIO
numbers. Meshtastic includes comments for many of the underlying nRF52840 GPIOs.
The authoritative mapping is the `g_ADigitalPinMap` array in Meshtastic's
`variants/nrf52840/seeed_solar_node/variant.cpp`, which resolves every logical
pin to a physical GPIO; where a `variant.h` comment conflicts with that array,
the array is taken as correct and the conflict is noted.

The logical pins `21` through `26` are dedicated to the external QSPI flash and
should not be treated as general-purpose application pins.

## Reconstructed pin map

| Function | Arduino pin | nRF52840 pin | Meshtastic name | MeshCore name | Confidence / notes |
|---|---:|---:|---|---|---|
| GNSS standby/wakeup | 0 | P0.02 | `PIN_GPS_STANDBY`, `D0` | `PIN_GPS_STANDBY` | High agreement. Active behavior is module-dependent. |
| SX1262 DIO1 interrupt | 1 | P0.03 | `SX126X_DIO1`, `D1` | `P_LORA_DIO_1` | High agreement. |
| SX1262 reset | 2 | P0.28 | `SX126X_RESET`, `D2` | `P_LORA_RESET` | High agreement. |
| SX1262 busy | 3 | P0.29 | `SX126X_BUSY`, `D3` | `P_LORA_BUSY` | High agreement. |
| SX1262 chip select | 4 | P0.04 | `SX126X_CS`, `D4` | `P_LORA_NSS` | High agreement. A Meshtastic comment also mentions I2C SDA, but the active Grove I2C bus is pins 14/15. |
| SX1262 RX enable / RF switch | 5 | P0.05 | `SX126X_RXEN`, `D5` | `SX126X_RXEN` | High agreement. A Meshtastic comment also mentions I2C SCL, but the active Grove I2C bus is pins 14/15. |
| GNSS UART signal | 6 | P1.11 | `GPS_TX_PIN`, `PIN_SERIAL1_TX` | `PIN_SERIAL1_TX`; mapped through `PIN_GPS_RX` | Electrical direction naming is inconsistent; see GNSS section. |
| GNSS UART signal | 7 | P1.12 | `GPS_RX_PIN`, `PIN_SERIAL1_RX` | `PIN_SERIAL1_RX`; mapped through `PIN_GPS_TX` | Electrical direction naming is inconsistent; see GNSS section. |
| SPI clock | 8 | P1.13 | `PIN_SPI_SCK` | `PIN_SPI_SCK` | Shared with SX1262. |
| SPI MISO | 9 | P1.14 | `PIN_SPI_MISO` | `PIN_SPI_MISO` | Shared with SX1262. |
| SPI MOSI | 10 | P1.15 | `PIN_SPI_MOSI` | `PIN_SPI_MOSI` | Shared with SX1262. |
| Firmware-controlled LED A | 11 | P0.15 | `PIN_LED2`, `LED_BLUE` | `LED_WHITE` | **CONFIRMED white, active-high (2026-07-23).** "User LED". |
| Firmware-controlled LED B / TX LED | 12 | P0.19 | `PIN_LED1`, `LED_GREEN` | `LED_BLUE`, `PIN_LED`, `P_LORA_TX_LED` | **CONFIRMED blue, active-high (2026-07-23).** "Breathing"/mesh-heartbeat/TX LED; `variant.h`'s P1.15 comment is wrong; no green LED exists. |
| Program/user button → **power button ("PWR")** | 13 | P1.01 | `BUTTON_PIN`, `D13` | `PIN_BUTTON1`, `PIN_USER_BTN` | **CONFIRMED active-low (2026-07-23)** on internal pull-up. **This is the power button**: hold → System OFF. Matches MeshCore's `PIN_USER_BTN` power choice. **Any press from System OFF reaches the bootloader, not the application** — it cannot wake the node usefully. |
| Grove SDA | 14 | P0.09 | `PIN_WIRE_SDA`, `D14` | `PIN_WIRE_SDA` | High agreement. Pin is also an NFC-capable nRF pin. |
| Grove SCL | 15 | P0.10 | `PIN_WIRE_SCL`, `D15` | `PIN_WIRE_SCL` | High agreement. Pin is also an NFC-capable nRF pin. |
| Battery ADC | 16 | P0.31 / AIN7 | `PIN_VBAT`, `BATTERY_PIN`, `D16` | `BATTERY_PIN` | High agreement on signal and ADC channel. Scaling differs. |
| GNSS reset | 17 | P1.03 | `D17`, comment only | not defined | Meshtastic identifies the signal but does not actively define a GNSS reset macro. MeshCore omits it. |
| GNSS power enable | 18 | P1.05 | `GPS_EN`, `D18` | `GPS_EN` | High agreement. |
| Battery-divider enable | 19 | P0.14 | `BAT_READ`, `D19` | `VBAT_ENABLE` | Active-low in MeshCore. Meshtastic's generic power code must be checked before assuming identical drive behavior. |
| Second user button ("USR") | 20 | P1.07 | `BUTTON_PIN_TOUCH` | `PIN_BUTTON2` | **CONFIRMED active-low, soft momentary (2026-07-23).** Not capacitive despite Meshtastic's `TOUCH` naming. Carries the primary action while running, and is **the only button that powers the node on** — its wake press reaches the application. |
| QSPI SCK | 21 | P0.21 | `PIN_QSPI_SCK` | `PIN_QSPI_SCK` | Dedicated external flash signal. Physical pin from `variant.cpp`. |
| QSPI CS | 22 | P0.25 | `PIN_QSPI_CS` | `PIN_QSPI_CS` | Dedicated external flash signal. Physical pin from `variant.cpp`. |
| QSPI IO0 | 23 | P0.20 | `PIN_QSPI_IO0` | `PIN_QSPI_IO0` | Dedicated external flash signal. Physical pin from `variant.cpp`. |
| QSPI IO1 | 24 | P0.24 | `PIN_QSPI_IO1` | `PIN_QSPI_IO1` | Dedicated external flash signal. Physical pin from `variant.cpp`. |
| QSPI IO2 | 25 | P0.22 | `PIN_QSPI_IO2` | `PIN_QSPI_IO2` | Dedicated external flash signal. Physical pin from `variant.cpp`. |
| QSPI IO3 | 26 | P0.23 | `PIN_QSPI_IO3` | `PIN_QSPI_IO3` | Dedicated external flash signal. Physical pin from `variant.cpp`. |

Logical pins 27-32 exist within the declared `PINS_COUNT = 33`, but neither
firmware implementation assigns them a board-level function. They should not be
used without locating the exact board variant's `g_ADigitalPinMap` and confirming
the PCB routing.

## LoRa radio

### Device

The radio is a Semtech SX1262 packaged as Seeed's Wio-SX1262 module.

Both MeshCore and Meshtastic agree on:

| SX1262 signal | Arduino pin |
|---|---:|
| NSS / CS | 4 |
| DIO1 | 1 |
| RESET | 2 |
| BUSY | 3 |
| RX enable | 5 |
| SPI SCK | 8 |
| SPI MISO | 9 |
| SPI MOSI | 10 |

### RF-switch configuration

Both implementations configure:

- SX1262 DIO2 as an RF-switch control
- no separate TX-enable GPIO
- a separate RX-enable GPIO on logical pin 5
- DIO3 as the TCXO supply
- TCXO voltage of 1.8 V

Meshtastic explicitly comments that DIO2-as-RF-switch is necessary to avoid a
large loss of transmit power.

MeshCore additionally configures:

- current limit: 140 mA
- boosted RX gain
- maximum transmit power: 22 dBm
- logical pin 12 as a transmit indicator LED

These are firmware policy choices rather than additional hardware differences.

### UMSH initialization implications

A UMSH SX1262 driver should configure the radio in this order:

1. Configure the SPI bus and NSS.
2. Configure DIO1, BUSY, RESET, and RXEN.
3. Reset the SX1262.
4. Configure DIO3 to supply 1.8 V to the TCXO.
5. Allow the TCXO startup delay expected by the SX1262.
6. Configure DIO2 as the RF-switch control.
7. Leave TXEN unconnected.
8. Drive RXEN according to the Wio-SX1262 module's expected receive state.
9. Start with a conservative current limit and verify 22 dBm operation against
   regional limits and supply behavior.

MeshCore waits an additional 10 ms during board startup before using the radio.

## GNSS

### Device

The P1-Pro contains a Seeed XIAO L76K GNSS module. Both firmware trees configure
the GNSS UART for:

- 9600 baud
- a 50 ms GNSS worker interval
- UART logical pins 6 and 7
- standby/wakeup on logical pin 0
- module power enable on logical pin 18

Meshtastic additionally identifies logical pin 17 as `GNSS_RESET`, but does not
wire it into the active GNSS macro set. MeshCore does not mention logical pin 17.

### UART direction-name discrepancy

Meshtastic defines:

```c
GPS_TX_PIN     = 6
GPS_RX_PIN     = 7
PIN_SERIAL1_TX = GPS_TX_PIN
PIN_SERIAL1_RX = GPS_RX_PIN
```

MeshCore defines the serial port directly as:

```c
PIN_SERIAL1_RX = 7
PIN_SERIAL1_TX = 6
```

but then aliases:

```c
PIN_GPS_TX = PIN_SERIAL1_RX
PIN_GPS_RX = PIN_SERIAL1_TX
```

This apparent reversal is likely a naming-convention difference:

- one convention names the signal from the GNSS module's perspective;
- the other names the MCU UART operation;
- `GPS_TX` may therefore mean "the pin connected to GNSS TX," which must be MCU RX.

For UMSH, do not rely on the `GPS_TX`/`GPS_RX` alias names. Configure the MCU UART
using the consistently agreed serial mapping:

- MCU UART TX: logical pin 6
- MCU UART RX: logical pin 7

That is also the reading that turned out to be right on the other three
boards in this family — the T-Echo, the T1000-E, and the Wio Tracker L1 —
on each of which `GPS_RX_PIN` is the MCU's RX. **Confirmed here too,
2026-08-05:** UARTE0 with RXD=P1.12 / TXD=P1.11 at 9600 gets sentences
immediately and a 3D fix from cold. Treat it as the family rule.

### Power behavior

`GPS_EN` on logical pin 18 is the only consistently documented main-power
control. Logical pin 0 is described as standby or wakeup.

A conservative UMSH sequence is:

```text
GNSS off:
    GPS_EN = inactive
    GNSS_STANDBY = inactive or high-impedance

GNSS start:
    configure UART pins
    assert GPS_EN
    wait for module power stabilization
    drive/release STANDBY as required by L76K documentation
    begin parsing NMEA at 9600 baud
```

`umsh_bsp_sensecap_solar::gnss` implements exactly that sequence, and both
polarities in it are **confirmed on hardware, 2026-08-05**:

- `GPS_EN` (logical 18 / P1.05) is **active-high**. High powers the
  module; low removes power, taking the backup domain and the ephemeris
  with it.
- Standby (logical 0 / P0.02) is **active-high wake**, the same as the
  T-Echo's identical L76K.

The driver raises the enable, waits 50 ms for the rail, raises standby,
and allows 150 ms before reading. Switching the receiver off over ULCP
drops standby first and then the enable, and the property surface goes
blank as it should rather than merely stopping at the last fix.

Logical pin 17 is left untouched as an input: a rail that can be cut is a
stronger reset than a line whose connection has never been confirmed.

Unlike every other board in this family, this one really can take the
module's power away — and does, because GNSS is its largest discretionary
load. The cost is that nothing here keeps time across an off state: the
backup domain goes with the rail, so the clock comes from the next fix or
a manual set. On a node that will see the sky daily, that is the right
trade.

### The receiver defaults to on

This is the one board in the tree whose post-reset `PROP_GNSS_ENABLED` is
true (`GnssConfig::ALWAYS_ON`). It is a fixed outdoor node with a panel
rather than a pocket tracker on a cell: the load it worries about is the
one it can see coming, and a node that has to be told to find itself after
every reset is the worse failure. Saved state still overrides it in both
directions, and `CMD_RST` returns to it — verified on hardware.

## Battery pack and charging system

### Battery pack

The P1-Pro is specified with:

- four 18650 NMC cells
- 3350 mAh per cell
- Type-C and solar charging
- specified discharge environment: -40 to 60 °C
- specified charging environment: 0 to 50 °C

The public documentation does not state whether the four cells are electrically
in parallel or arranged in a series/parallel topology. The single-cell-oriented
battery ADC voltage range and use of the CN3165 strongly suggest a one-cell
nominal battery bus, likely four cells in parallel, but that remains an inference
until confirmed from the PCB or wiring.

Do not describe the pack as 4S. Firmware expects a normal single-cell Li-ion
open-circuit-voltage range.

### Charger

Seeed identifies the charging-management IC as a CN3165 configured for
approximately 0.99 A.

No charger-control or charger-status GPIO appears in either firmware board
definition. Therefore UMSH should assume:

- solar charging is autonomous;
- USB charging is autonomous;
- firmware cannot set charge current;
- firmware cannot directly distinguish solar charging from USB charging using
  the documented board pins;
- firmware cannot read charger fault, charge-complete, or input-power status
  unless an undocumented signal is found;
- the externally visible red/green charge LEDs and yellow solar LED may be
  connected directly to the charger/power circuit rather than to the nRF52840.

The product documentation mentions:

- two charge-status LEDs;
- one solar-panel-status LED;
- one blue mesh-heartbeat LED;
- one white user-defined LED.

Only two LEDs are defined in firmware, which strongly suggests that the charge
and solar indicators are hardware-driven.

### Battery-voltage measurement

Both implementations agree on:

- battery ADC on logical pin 16;
- underlying nRF pin P0.31 / AIN7;
- 12-bit ADC readings;
- a switched divider controlled by logical pin 19;
- the divider-enable signal is active-low in MeshCore.

MeshCore performs:

```c
digitalWrite(VBAT_ENABLE, LOW);
analogReadResolution(12);
analogReference(AR_INTERNAL_3_0);
delay(10);
adcvalue = analogRead(BATTERY_PIN);
millivolts = adcvalue * 3.0 * 3.0 / 4.096;
```

The expression yields millivolts because a full-scale 12-bit count is 4096.

Meshtastic defines:

```c
BATTERY_SENSE_RESOLUTION_BITS = 12
ADC_MULTIPLIER = 3.3
AREF_VOLTAGE = 3.3
BATTERY_PIN = PIN_VBAT
BAT_READ = 19
```

This is a significant discrepancy:

| Parameter | MeshCore | Meshtastic |
|---|---:|---:|
| ADC reference | 3.0 V | 3.3 V |
| divider/scaling multiplier | 3.0 | 3.3 |
| enable pin | 19, active-low explicitly | 19, polarity not documented in variant |
| ADC pin | 16 / AIN7 | 16 / AIN7 |

The two formulas differ by approximately 21% if interpreted literally:

```text
MeshCore scale: 3.0 × 3.0 = 9.00
Meshtastic scale: 3.3 × 3.3 = 10.89
```

It is possible that Meshtastic's generic nRF ADC code interprets one or both
constants differently from MeshCore. It is also possible that one board
definition is inaccurate.

UMSH should not select either scaling without hardware calibration.

### Recommended UMSH battery calibration procedure

1. Measure the battery bus with a trusted multimeter.
2. Drive logical pin 19 low.
3. Wait at least 10 ms.
4. Read P0.31/AIN7 with a known nRF SAADC reference and gain.
5. Repeat at several battery voltages, ideally near:
   - 4.15 V
   - 3.9 V
   - 3.7 V
   - 3.4 V
6. Fit:
   ```text
   Vbattery = ADC_code × slope + offset
   ```
7. Confirm whether the divider is linear and whether enabling it changes system
   current measurably.
8. Drive pin 19 high after the measurement if that disconnects the divider.
9. Record the calibrated ratio in the UMSH board definition rather than copying
   either firmware's nominal multiplier.

### Low-voltage protection

MeshCore defines:

- boot lockout threshold: 3300 mV
- LPCOMP input: AIN7 / P0.31
- LPCOMP reference selection: `2`, documented in its source as approximately
  3/8 VDD and corresponding to roughly 3.38-3.71 V at the battery input
- low-voltage shutdown with voltage-comparator wake

For a low-voltage or boot-protect shutdown, MeshCore:

1. keeps the battery divider enabled by driving pin 19 low;
2. configures the nRF low-power comparator on AIN7;
3. enters System OFF;
4. wakes when battery voltage rises through the comparator threshold.

For an ordinary user shutdown, it drives pin 19 high before System OFF, avoiding
divider current and comparator wake.

This is a useful model for UMSH, but it is firmware-level battery protection, not
proof of the battery pack's hardware protection circuitry.

The Meshtastic board definition supplies an open-circuit-voltage lookup table:

```text
4200, 3986, 3922, 3812, 3734, 3645, 3527, 3420, 3281, 3087, 2786 mV
```

This table is suitable only as an approximate state-of-charge mapping. Under
solar charge, GNSS load, or LoRa transmit load, terminal voltage can depart
substantially from open-circuit voltage.

## Buttons and wake behavior

### Primary program/user button

Both implementations identify logical pin 13 as the main program/user button.

Meshtastic specifies:

- active low;
- no firmware pull-up request (`BUTTON_ACTIVE_PULLUP = false`), suggesting an
  external pull-up exists.

MeshCore nevertheless configures the pin as `INPUT_PULLUP`, waits for it to be
released before shutdown, and then configures low-level sensing with a pull-up
for System OFF wake.

The practical safe behavior is:

- treat pin 13 as active-low;
- enable an internal pull-up even if the PCB also has an external pull-up;
- wait for button release before entering System OFF;
- arm low-level GPIO sensing before System OFF;
- expect button wake from System OFF to reboot the MCU rather than resume normal
  instruction flow.

### Second user button

Logical pin 20 (P1.07) is named:

- `BUTTON_PIN_TOUCH` by Meshtastic;
- `PIN_BUTTON2` by MeshCore;
- `USER_BUTTON` in the `variant.cpp` pin-map comment.

Despite Meshtastic's `TOUCH` naming, hardware inspection found nothing
capacitive on this board: it is a second mechanical button. Neither reviewed
implementation uses it as the primary power-off or wake pin.

**Confirmed on hardware (2026-07-23, in-hand P1-Pro, via the Phase 1
bringup firmware).** P1.07 reads **active-low** on the internal pull-up
(LOW while pressed, HIGH when released), same as the primary button, and
is a **soft momentary button**: the MCU kept running normally through a
press, so it does **not** hard-cut the MCU rail. (An additional hardware
slide switch on the enclosure, if any, is uncharacterized — see below.)

### Button labels and the wake asymmetry

The labels agree with the pin map: **"PWR" = P1.01**, **"USR" = P1.07**.
P1.01 is the button both reviewed implementations name
`PIN_USER_BTN`/`BUTTON_PIN`, and it is the one that behaves as the power
control.

- **Hold PWR (P1.01) ~1.5 s** → 3× white-LED (LED_A/P0.15)
  acknowledgement → System OFF (verified 2026-07-23: USB drops and stays
  down). Power-off is **PWR-only**; holding USR does nothing.
- **Any press of PWR while the device is in System OFF enters the stock
  bootloader's DFU mode — always** (confirmed 2026-07-27 on an enclosed
  unit). Duration is irrelevant; a bare tap does it. The wake press never
  reaches the application, and escaping the mode requires replacing the
  bootloader.
- **USR (P1.07) is therefore the only usable power-on button.** The
  System OFF teardown arms both pins as GPIO-DETECT wake sources, but
  only the USR path reaches the application.

Two consequences: **P1.01 cannot carry a hold-at-boot gesture**, because
the wake press never arrives; and the operational UX is asymmetric —
**hold PWR to turn off, press USR to turn on.**

**USR is clean through reset (confirmed 2026-07-27).** A held USR press
spanning power-on reaches the application; the bootloader does not
consume it.

### Force-pairing boot gesture (USR / P1.07)

This board has no display menu (the T-Echo re-pairing route) and no
gesture FSM, so a bonded node had no way back into BLE pairing mode
without a USB cable. It uses the T-1000E ceremony, carried by USR:

- **hold USR (P1.07) through power-on, past ~1 s** → BLE pairing mode is
  forced open for this power cycle even when bonds exist;
- acknowledged by **two white blinks on LED_A** (P0.15) the instant the
  threshold is crossed, deliberately distinct from the three that
  acknowledge hold-to-power-off;
- pairing mode itself then shows as the existing `BLE_LED_MODE == 1`
  double blink on LED_B (P0.19).

USR is also the button that powers the node on, so the level at t=0
cannot distinguish the ceremony from an ordinary wake press; only a press
still held at one second counts. There is no collision with the power
button: power-off is PWR-only, and P1.07 is otherwise unused by this
board's firmware while running.

**Hardware-validated 2026-07-27**: a bonded node re-enters pairing mode
via this gesture.

### Reset and enclosure power control

Seeed lists separate power on/off, reset, and user-defined controls. The
firmware-level pin map only clearly exposes the program/user button and the
second button. The external power switch and reset control may act directly on
power or reset circuitry and therefore may not be visible as GPIOs.

## LEDs

The publicly documented user-visible indicators are:

- red: charging;
- green: charged;
- yellow: solar panel / illumination status;
- blue: mesh heartbeat;
- white: user-defined.

The third-party manual source is more explicit about these colors than the
current Seeed wiki, while Seeed's own wiki confirms the same categories but not
all color assignments in parsed text.

Only two LEDs appear in the MCU board definitions:

- logical pin 11;
- logical pin 12.

### Firmware disagreement

MeshCore:

```text
pin 11 = LED_WHITE
pin 12 = LED_BLUE
pin 12 = LoRa TX indicator
active high
```

Meshtastic:

```text
pin 12 = LED_GREEN
pin 11 = LED_BLUE
active high
```

Seeed product documentation indicates that the two firmware-controlled LEDs
should be blue and white, not green and blue. This makes MeshCore's color naming
more plausible, but it should still be physically verified.

The Meshtastic `variant.h` physical-pin comment for logical pin 12 says
`P1.15`, while the same file assigns P1.15 to SPI MOSI on logical pin 10. The
`g_ADigitalPinMap` array in `variant.cpp` settles this: logical pin 11 is
P0.15 (commented "User LED") and logical pin 12 is P0.19 (commented
"Breathing LED"). The P1.15 comment in `variant.h` is wrong. The
"Breathing LED" label on pin 12 is consistent with the product
documentation's blue mesh-heartbeat LED, which further favors MeshCore's
blue/white color naming.

UMSH used neutral names until verified:

```text
LED_A = logical pin 11
LED_B = logical pin 12
```

**Confirmed on hardware (2026-07-23, in-hand P1-Pro, via the Phase 1
bringup firmware).** Driving both pins HIGH lit both LEDs, and direct
visual inspection resolved the color-label discrepancy in MeshCore's
favor:

```text
LED_A = logical pin 11 = P0.15 = WHITE (the user LED), active-high
LED_B = logical pin 12 = P0.19 = BLUE  (the mesh/breathing/TX LED), active-high
```

Both are active-high (lit when the GPIO is driven HIGH), matching both
implementations. Meshtastic's `LED_GREEN` naming is wrong for this
board; there is no green firmware-controlled LED.

A hardware test should identify:

1. which logical pin lights the blue LED;
2. which logical pin lights the white LED;
3. whether either LED is inverted;
4. whether pin 12 is visually appropriate as a transmit indicator;
5. whether the other charger/solar LEDs are entirely hardware-controlled.

## Grove connector

The Grove bus is:

| Grove function | Arduino pin | nRF52840 pin |
|---|---:|---:|
| SDA / GPIO | 14 | P0.09 |
| SCL / GPIO | 15 | P0.10 |
| Power | not firmware-controlled in reviewed files | — |
| Ground | — | — |

Seeed advertises the connector as supporting I2C, GPIO, and UART. The board
definitions configure pins 14 and 15 as the sole I2C bus.

Because P0.09 and P0.10 are the nRF52840 NFC pins, firmware must ensure that the
NFCT peripheral is disabled or that the UICR configuration permits GPIO use.
The Arduino/board support package likely handles this, but a bare-metal UMSH
port must account for it.

UART use over Grove would require repurposing pins 14 and 15 in software. It is
not the same UART used by GNSS.

No switched sensor-power GPIO is exposed in the reviewed definitions. Assume the
Grove power pin remains powered whenever the node's main regulated rail is on,
unless measurement proves otherwise.

## External QSPI flash

Both implementations configure a `P25Q16H` QSPI flash device:

- capacity implied by part number and Seeed specification: 16 Mbit / 2 MiB;
- QSPI SCK: logical pin 21;
- QSPI CS: logical pin 22;
- QSPI IO0: logical pin 23;
- QSPI IO1: logical pin 24;
- QSPI IO2: logical pin 25;
- QSPI IO3: logical pin 26.

The physical nRF52840 GPIO mapping, from `variant.cpp`'s `g_ADigitalPinMap`:
SCK P0.21, CS P0.25, IO0 P0.20, IO1 P0.24, IO2 P0.22, IO3 P0.23.

These pins must be reserved. UMSH can use the flash for settings, logs, OTA
staging, or store-and-forward data, but should first establish:

- erase-block size;
- page-program size;
- deep-power-down support;
- startup state after System OFF;
- whether the bootloader or factory firmware reserves any region.

## nRF52840 clock and power configuration

Both firmware trees define:

- 64 MHz master clock;
- an external 32.768 kHz low-frequency crystal (`USE_LFXO`);
- Nordic S140 SoftDevice-compatible memory layout;
- nRF52840 native USB;
- UF2/nRFutil-style bootloader behavior through the Seeed/Adafruit nRF52 core.

MeshCore uses an `NRF52BoardDCDC` base class, indicating that the nRF52840's
internal DC/DC regulator mode is enabled. UMSH should also enable the nRF52840
DC/DC converter unless board testing reveals a supply constraint.

Meshtastic identifies the board as hardware model 95 and actively supported.

## USB and flashing

Meshtastic's board metadata specifies:

- USB VID/PID pair `0x2886:0x0059`;
- USB product string `XIAO-BOOT`;
- 1200-baud touch reset behavior;
- `nrfutil` upload;
- J-Link, nrfjprog, CMSIS-DAP, ST-Link, and Black Magic-compatible debug/upload
  options in the PlatformIO metadata;
- S140 SoftDevice 7.3.0;
- bootloader settings at `0xFF000`;
- application maximum size of 815,104 bytes in Meshtastic's layout.

MeshCore uses its own linker layouts:

- standard applications: `nrf52840_s140_v7.ld`;
- companion-radio builds with extra filesystem area:
  `nrf52840_s140_v7_extrafs.ld`;
- companion-radio application maximum size: 708,608 bytes.

A UMSH linker script must match the bootloader and SoftDevice actually installed
on the device. Do not assume the whole 1 MiB internal flash is available.

### Confirmed on hardware (2026-07-23, in-hand P1-Pro)

Read from `INFO_UF2.TXT` and by parsing the bootloader's own
`CURRENT.UF2`:

- **Bootloader:** `UF2 Bootloader 0.9.2-OTAFIX2.2-BP1.3`
  (lib/nrfx 2.0.0, tinyusb 0.12.0).
- **Model:** `Seeed Solar Node P1`; **Board-ID:**
  `nRF52840-SeeedSenseCAPSolarP1-v1`.
- **SoftDevice:** S140 7.3.0 → application starts at **`0x27000`**.
- **UF2 family ID:** **`0x28860044`** — read directly from the
  family-ID field of `CURRENT.UF2`. This is **not** `VID<<16 | PID`
  (`0x28860059`); a UF2 packed with the wrong family ID is silently
  ignored by the bootloader. `scripts/firmware_image.py`'s `sensecap-solar`
  preset uses `0x28860044`.
- **Bootloader mass-storage volume name:** **`SENSECAP`** (macOS mounts
  `/Volumes/SENSECAP`). The Meshtastic metadata's `XIAO-BOOT` product
  string above does not match this unit's mounted volume name.
- The **stock factory app does not honor the 1200-baud-touch → DFU**
  convention (a 1200-baud touch resets it, but it reboots straight back
  into the app). **Double-tap RESET** reliably enters the bootloader.
  UMSH firmware's `CdcAcmRescue` restores the 1200-baud-touch and
  `\x03\x03\x03dfu\r` software DFU-entry paths (both verified).
- The stock app enumerates as VID `0x2886` / PID `0x0059`, USB product
  `XIAO nRF52840`, manufacturer `Seeed Studio`.

## System OFF behavior

MeshCore's explicit shutdown path is the best available reference:

1. turn off the white and blue firmware LEDs;
2. wait for the active-low user button to be released;
3. configure the button with pull-up and low-level sense;
4. optionally leave the battery divider enabled and arm LPCOMP for low-voltage
   recovery;
5. enter nRF52840 System OFF.

UMSH should distinguish:

### User-requested off

- GNSS disabled;
- radio put to sleep;
- Grove peripherals quiesced if possible;
- LEDs off;
- battery-divider gate high;
- button armed as low-level wake;
- enter System OFF.

### Low-battery off

- GNSS disabled;
- radio asleep;
- LEDs off;
- battery divider left enabled;
- LPCOMP armed for battery recovery;
- optionally also arm the user button if the intended UX permits manual wake;
- enter System OFF.

### Solar recovery

With the divider and LPCOMP configured correctly, increasing battery voltage can
wake the nRF52840. UMSH should then re-measure battery voltage before fully
booting. A single comparator crossing under intermittent sunlight should not
start GNSS and LoRa immediately if the battery cannot sustain them.

A useful boot policy is:

```text
wake from low-battery System OFF
    -> debounce/re-measure battery
    -> require a recovery margin above shutdown threshold
    -> optionally require the voltage to remain healthy for N seconds
    -> begin normal boot
```

## Thermal and charging considerations

Seeed specifies charging only from 0 to 50 °C, despite allowing discharge from
-40 to 60 °C.

The firmware interfaces reviewed here expose no battery temperature sensor and
no charger-disable control. Therefore the CN3165 circuit or battery pack must be
responsible for any temperature-qualified charging behavior, or the published
charging range may be an operational restriction rather than an electronically
enforced limit.

UMSH cannot safely add temperature-based charge inhibition unless an
undocumented charger-enable path is found.

The enclosure is IPX6, not a claim of immersion resistance. Opening it,
modifying cable glands, or changing antenna feed-throughs may invalidate its
water resistance.

## Firmware implementation discrepancies

### Summary table

| Topic | Meshtastic | MeshCore | Recommended UMSH treatment |
|---|---|---|---|
| Radio pins | SX1262 on 1/2/3/4/5 and SPI 8/9/10 | Same | Treat as confirmed. |
| RF switch | DIO2 switch, RXEN=5, no TXEN, DIO3=1.8 V | Same | Treat as confirmed. |
| GNSS UART | TX=6, RX=7 | serial TX=6, RX=7, but GPS aliases reversed | Use MCU TX=6, MCU RX=7; ignore ambiguous alias names. |
| GNSS enable | 18 | 18 | Treat as confirmed; verify polarity. |
| GNSS standby | 0 | 0 | Treat as confirmed; verify polarity/timing. |
| GNSS reset | pin 17 documented | omitted | Leave unused until verified. |
| Battery ADC | 16 / P0.31 / AIN7 | same | Treat as confirmed. |
| Battery gate | pin 19 | pin 19, explicitly active-low | Start with active-low but verify current and ADC response. |
| ADC reference | 3.3 V constant | internal 3.0 V reference | Calibrate; do not copy blindly. |
| ADC multiplier | 3.3 | 3.0 | Calibrate; possible generic-driver semantic difference. |
| Main button | pin 13, active-low, external pull likely | pin 13, internal pull-up and low-sense wake | Treat as active-low; use pull-up. |
| Touch input | pin 20 | pin 20 | Mechanical second button on P1.07 (nothing capacitive on the board); verify polarity on first use. |
| LED pin 11 | called blue | called white | P0.15 per `variant.cpp` ("User LED"). Use neutral `LED_A` until color tested. |
| LED pin 12 | called green | called blue and LoRa TX | P0.19 per `variant.cpp` ("Breathing LED"). Use neutral `LED_B` until color tested. Product docs and the "Breathing" label favor blue/white pair. |
| LED active level | high | high | Treat as confirmed. |
| External flash | P25Q16H on 21-26 | same | Treat as confirmed. |
| Low-voltage boot lock | not in board header | 3.3 V plus LPCOMP recovery | Adopt only after battery scaling is calibrated. |

## Recommended initial UMSH board definition

The following neutral board-level constants avoid carrying questionable naming
into UMSH:

```rust
pub const RADIO_DIO1: u8 = 1;
pub const RADIO_RESET: u8 = 2;
pub const RADIO_BUSY: u8 = 3;
pub const RADIO_CS: u8 = 4;
pub const RADIO_RXEN: u8 = 5;

pub const GNSS_UART_TX: u8 = 6; // MCU TX
pub const GNSS_UART_RX: u8 = 7; // MCU RX

pub const SPI_SCK: u8 = 8;
pub const SPI_MISO: u8 = 9;
pub const SPI_MOSI: u8 = 10;

pub const LED_A: u8 = 11; // physical color to be verified
pub const LED_B: u8 = 12; // physical color to be verified

pub const USER_BUTTON: u8 = 13; // active low
pub const GROVE_SDA: u8 = 14;
pub const GROVE_SCL: u8 = 15;

pub const BATTERY_ADC: u8 = 16;
pub const GNSS_RESET_CANDIDATE: u8 = 17;
pub const GNSS_ENABLE: u8 = 18;
pub const BATTERY_DIVIDER_ENABLE_N: u8 = 19;
pub const USER_BUTTON_2: u8 = 20; // mechanical button; polarity unverified

pub const QSPI_SCK: u8 = 21;
pub const QSPI_CS: u8 = 22;
pub const QSPI_IO0: u8 = 23;
pub const QSPI_IO1: u8 = 24;
pub const QSPI_IO2: u8 = 25;
pub const QSPI_IO3: u8 = 26;

pub const GNSS_STANDBY_OR_WAKE: u8 = 0;
```

These are Arduino logical pin IDs. A bare-metal Rust implementation should map
them to actual `P0.xx`/`P1.xx` pins using the exact board package pin table
rather than embedding Arduino IDs in low-level drivers.

## Hardware bring-up checklist for UMSH

### Phase 1: non-destructive GPIO identification

- Boot without enabling GNSS.
- Confirm USB serial and reset-to-bootloader behavior.
- Toggle logical pins 11 and 12 separately and record LED colors and polarity.
- Read pin 13 with pull-up and confirm active-low button operation.
- Read pin 20 (second mechanical button) with pull-up and confirm polarity.
- Confirm no unexpected current increase from pin-state choices.
- Do not drive pin 17 until its idle voltage has been measured.

### Phase 2: battery measurement

- Measure battery bus externally.
- Toggle pin 19 high/low and identify which state enables the ADC divider.
- Measure ADC code with known SAADC configuration.
- Measure divider current if practical.
- Calibrate voltage conversion at multiple battery voltages.
- Determine whether P0.31 remains usable by LPCOMP while System OFF.
- Validate a conservative low-battery shutdown and recovery threshold.

### Phase 3: radio

- Initialize TCXO at 1.8 V using DIO3.
- Enable DIO2 RF switching.
- Confirm RX with RXEN behavior.
- Verify transmit at low power first.
- Measure current and radiated/connector power before using 22 dBm.
- Confirm LED_B/pin 12 does not interfere with any shared function.

### Phase 4: GNSS — **done 2026-08-05**

`umsh_bsp_sensecap_solar::gnss`, reached over ULCP as
`PROP_GNSS_ENABLED`. One `umshctl gnss status` settled all three
inferences at once: sentences arrived immediately, GSV reported 8
satellites in view indoors, and a 3D fix followed within a couple of
minutes. UART direction, `GPS_EN` polarity, and standby polarity are all
as assumed — see the GNSS section above.

Also verified: switching the receiver off blanks the property surface,
and `CMD_RST` returns it to this board's on-by-default post-reset value.

Left for a bench with a meter:

- Meter the module rail with GNSS off, to confirm `GPS_EN` low really
  removes power rather than merely idling the module. The property
  behaves correctly either way, so this is a power question, not a
  correctness one.
- Measure cold-start and warm-start current.
- Determine whether pin 17 is necessary for reliable reset. It is held as
  an input today and the rail is used as the reset instead.
- Confirm the clock does *not* survive System OFF here, unlike its
  relatives: cutting the rail takes the L76K's backup domain with it, so
  the board should come back not knowing the time.

### Phase 5: solar and charging

- Observe battery voltage with:
  - USB only;
  - solar only;
  - both inputs;
  - neither input.
- Confirm that red/green/yellow LEDs operate without MCU GPIO control.
- Determine whether USB presence can be sensed through nRF52840 native USB
  registers.
- Determine whether solar-input presence is observable at all.
- Verify that no MCU pin can accidentally disable or disturb charging.
- Characterize boot cycling near dawn and under intermittent shade.

### Phase 6: Grove and flash

- Confirm Grove supply voltage.
- Scan I2C pins 14/15.
- Test GPIO and optional UART remapping.
- Read JEDEC ID from QSPI flash.
- Establish a UMSH partition layout without overwriting bootloader-owned data.

## Open questions requiring hardware or schematic confirmation

1. ~~What are the exact nRF52840 physical GPIO mappings for logical pins 11,
   12, 20, and 21-26?~~ **Resolved** from `variant.cpp` `g_ADigitalPinMap`:
   11 = P0.15, 12 = P0.19, 20 = P1.07, QSPI 21-26 = P0.21 / P0.25 / P0.20 /
   P0.24 / P0.22 / P0.23.
2. Which firmware LED pin is physically blue and which is white?
3. Is the Meshtastic `LED_GREEN` name simply incorrect?
4. What is the true battery-divider ratio?
5. Which SAADC reference/gain combination was intended by Seeed?
6. Is battery-divider enable definitely active-low on all P1/P1-Pro revisions?
7. Are the four 18650 cells connected 1S4P, and does the pack contain individual
   cell fusing or protection?
8. Does the battery pack or charger provide hardware undervoltage cutoff?
9. Does the CN3165 implementation include temperature-qualified charging?
10. Can firmware detect solar-input presence independently of battery voltage?
11. ~~What is the exact function and active polarity of logical pin 20?~~
    **Resolved** 2026-07-23: the "USR" mechanical button on P1.07, active-low
    on an internal pull-up (hardware inspection found nothing capacitive;
    `variant.cpp` comments it `USER_BUTTON`).
12. Is logical pin 17 connected to L76K reset, and what is its required idle
    state?
13. ~~What are the exact active levels and timing requirements of GNSS enable
    and standby/wakeup?~~ **Resolved** 2026-08-05: both active-high, enable
    then 50 ms then standby, sentences within a second. Timing *margins* are
    still unprobed — the delays are generous rather than measured.
14. Is Grove power switched or permanently tied to the main regulated rail?
15. Are any QSPI regions reserved by the factory bootloader or firmware?
16. Are P1 and P1-Pro controller boards electrically identical aside from the
    installed GNSS module and battery pack?

## Source references

### Seeed Studio

- SenseCAP Solar Node introduction and specifications:
  https://wiki.seeedstudio.com/meshtastic_solar_node/
- SenseCAP Solar Node P1-Pro product page:
  https://www.seeedstudio.com/SenseCAP-Solar-Node-P1-Pro-for-Meshtastic-LoRa-p-6412.html
- Seeed announcement:
  https://www.seeedstudio.com/blog/2025/05/21/meet-sensecap-solar-node-the-solar-powered-meshtastic-device-for-reliable-mesh-network-expansion/

### MeshCore

- Variant directory:
  https://github.com/meshcore-dev/MeshCore/tree/main/variants/sensecap_solar
- Pin and peripheral definitions:
  https://github.com/meshcore-dev/MeshCore/blob/main/variants/sensecap_solar/variant.h
- Board class:
  https://github.com/meshcore-dev/MeshCore/blob/main/variants/sensecap_solar/SenseCapSolarBoard.h
- Board startup and power-management behavior:
  https://github.com/meshcore-dev/MeshCore/blob/main/variants/sensecap_solar/SenseCapSolarBoard.cpp
- PlatformIO radio and build configuration:
  https://github.com/meshcore-dev/MeshCore/blob/main/variants/sensecap_solar/platformio.ini

### Meshtastic

- Variant directory:
  https://github.com/meshtastic/firmware/tree/develop/variants/nrf52840/seeed_solar_node
- Pin and peripheral definitions:
  https://github.com/meshtastic/firmware/blob/develop/variants/nrf52840/seeed_solar_node/variant.h
- Physical pin map (`g_ADigitalPinMap`):
  https://github.com/meshtastic/firmware/blob/develop/variants/nrf52840/seeed_solar_node/variant.cpp
- PlatformIO definition:
  https://github.com/meshtastic/firmware/blob/develop/variants/nrf52840/seeed_solar_node/platformio.ini
- Board metadata:
  https://github.com/meshtastic/firmware/blob/develop/boards/seeed_solar_node.json

## Bottom line

The P1-Pro is a relatively straightforward nRF52840 + SX1262 + UART GNSS design
with autonomous solar charging, a gated battery divider, external QSPI flash,
and a Grove interface.

The radio pinout is strongly corroborated between MeshCore and Meshtastic. GNSS
UART and enable pins are also well corroborated once the signal-naming
convention is normalized.

The bring-up program has since closed most of the early uncertainties —
LED colors, button polarities, GNSS sequencing. What remains for UMSH is:

- battery ADC calibration (the divider constant is nominal, not fitted);
- the GNSS reset candidate on P1.03, never driven;
- pack-level and charger-level protection behavior.
