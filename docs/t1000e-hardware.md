# Seeed Studio SenseCAP T1000-E Hardware Reconstruction

This document summarizes what can be inferred about the Seeed Studio SenseCAP T1000-E hardware from the public Meshtastic and MeshCore source trees, in the absence of a public schematic.

The conclusions here are based primarily on firmware board-definition files and power-management code. They should be treated as a **firmware-level reconstruction**, not as a verified schematic.

## High-level hardware blocks

The T1000-E appears to be built around:

- Nordic nRF52840 MCU
- Semtech LR1110 radio
- AG3335 / Airoha GNSS module
- Rechargeable Li-ion battery
- Standalone Li-ion charger, apparently not I²C-controlled
- Magnetic USB charging / USB access through pogo pins
- QMA6100P accelerometer
- Light sensor
- NTC temperature sensor
- Button
- Buzzer
- Green status LED

The public product and firmware documentation describe it as an nRF52840 + LR1110 tracker with GPS/GNSS, battery, magnetic USB charging, button, buzzer, and pogo pins.

## Reconstructed pin map

| Function | nRF52840 pin | Firmware names | Notes |
|---|---:|---|---|
| Battery ADC | P0.02 / AIN0 | `BATTERY_PIN` | Battery voltage divider, `ADC_MULTIPLIER = 2.0`, so likely a 1:1 divider. |
| External / charger detect | P0.05 / AIN3 | `EXT_PWR_DETECT`, comment says `CHARGER_DET` | Detects external charger / VBUS-ish signal. **Observed to remain asserted after cable removal** — see “Hardware-validated power and UX findings”. |
| Charger “charging” status | P1.03 | `EXT_CHRG_DETECT`, comment says `CHARGE_STA` | Active-low charging-status input in Meshtastic. |
| Charge done | P1.04 | commented `EXT_IS_CHRGD`, comment says `CHARGE_DONE` | Present in comments, but not used by Meshtastic. |
| Sensor 3.3 V rail enable | P1.06 | `PIN_3V3_EN` | “Power to Sensors.” |
| Accelerometer 3.3 V rail enable | P1.07 | `PIN_3V3_ACC_EN` | “Power to Acc.” |
| Temp/lux sensor enable | P0.04 | `T1000X_SENSOR_EN_PIN` / `SENSOR_EN` | Separate sensor enable. |
| Button | P0.06 | `BUTTON_PIN` | Active high, pulldown/sense-high behavior. |
| Green LED | P0.24 | `PIN_LED1` / `LED_GREEN` | LED on = high (hardware-validated; see PWM polarity note below). |
| Buzzer PWM | P0.25 | `PIN_BUZZER` | PWM output. |
| Buzzer enable | P1.05 | `BUZZER_EN_PIN` / `BUZZER_EN` | Enable held high when active. |
| I²C SDA/SCL | P0.26 / P0.27 | `PIN_WIRE_SDA`, `PIN_WIRE_SCL` | Used for QMA6100P accelerometer. |
| QMA6100P interrupt | P1.02 | `QMA_6100P_INT_PIN` | Accelerometer interrupt. |
| LR1110 SPI SCK | P0.11 | `LORA_SCK`, `PIN_SPI_SCK` | SPI clock. |
| LR1110 SPI CS | P0.12 | `LORA_CS`, `PIN_SPI_NSS` | SPI chip select. |
| LR1110 SPI MISO | P1.08 | `LORA_MISO`, `PIN_SPI_MISO` | SPI MISO. |
| LR1110 SPI MOSI | P1.09 | `LORA_MOSI`, `PIN_SPI_MOSI` | SPI MOSI. |
| LR1110 reset | P1.10 | `LORA_RESET` | LR1110 reset. |
| LR1110 IRQ | P1.01 | `LORA_DIO1`, `LR1110_IRQ_PIN` | LR1110 interrupt. |
| LR1110 busy | P0.07 | `LORA_DIO2`, `LR1110_BUSY_PIN` | Named DIO2 in Meshtastic, used as busy. |
| GNSS UART RX | P0.14 | `GPS_RX_PIN`, `PIN_SERIAL1_RX` | 115200 baud. |
| GNSS UART TX | P0.13 | `GPS_TX_PIN`, `PIN_SERIAL1_TX` | 115200 baud. |
| GNSS main enable | P1.11 | `PIN_GPS_EN` / `GPS_EN` | Main GPS enable. |
| GNSS reset | P1.15 | `PIN_GPS_RESET` / `GPS_RESET` | GPS reset control. |
| GNSS RTC power enable | P0.08 | `GPS_VRTC_EN` | RTC / backup domain power control. |
| GNSS sleep interrupt | P1.12 | `GPS_SLEEP_INT` | Held high by firmware during normal use. |
| GNSS RTC interrupt | P0.15 | `GPS_RTC_INT` | Normal low, wake by high according to Meshtastic comments. |
| GNSS reset/status output | P1.14 | `GPS_RESETB_OUT` / `GPS_RESETB` | Usually input pullup; MeshCore sometimes drives it low during sleep/off. |
| Temperature ADC | P0.31 / AIN7 | `T1000X_NTC_PIN` / `TEMP_SENSOR` | NTC divider. |
| Light ADC | P0.29 / AIN5 | `T1000X_LUX_PIN` / `LUX_SENSOR` | Firmware maps to 0–100%, not true lux. |

## Charger and battery interface

The charger does **not** appear to be an I²C PMIC. The firmware treats it as a mostly autonomous Li-ion charger with a small number of GPIO status signals:

- `P0.05` is called `CHARGER_DET` in comments and `EXT_PWR_DETECT` in code.
- `P1.03` is called `CHARGE_STA` in comments and `EXT_CHRG_DETECT` in code.
- `P1.04` is called `CHARGE_DONE` in comments and appears as a commented-out `EXT_IS_CHRGD`.
- Battery voltage is measured on `P0.02/AIN0` through an apparent 2:1 ADC scaling path.

Meshtastic defines `EXT_CHRG_DETECT` on P1.03 as active low. The charge-done pin is mentioned but not enabled in the board definition.

The board also defines `NRF_APM`, meaning Meshtastic uses nRF52840 native USB power detection for some USB-powered / charging status decisions. In `Power.cpp`, when `NRF_APM` is enabled, `nrfx_power_usbstatus_get()` is used to determine USB-powered and charging-like state.

### Practical interpretation

The most likely architecture is:

```text
USB magnetic pogo pins
   ├── USB D+/D- → nRF52840 USB / DFU / serial
   └── 5 V input → standalone Li-ion charger
                  ├── Li-ion cell / pack → board power
                  ├── CHARGER_DET → nRF P0.05
                  ├── CHARGE_STA  → nRF P1.03, active low
                  └── CHARGE_DONE → nRF P1.04, apparently unused/commented
```

The nRF52840 likely does **not** program charge current, charge voltage, or charge termination behavior. It appears to only observe charger/external-power state and measure battery voltage.

## Battery voltage measurement

Battery voltage is read using:

- `BATTERY_PIN = P0.02 / AIN0`
- `ADC_MULTIPLIER = 2.0`
- `AREF_VOLTAGE = 3.0`
- 12-bit battery-sense resolution in the T1000-E definitions

The `ADC_MULTIPLIER = 2.0` strongly suggests that the ADC sees roughly half the battery voltage, consistent with a simple 1:1 resistor divider. The firmware then multiplies the ADC-derived voltage by 2.

MeshCore’s `getBattMilliVolts()` turns on `PIN_3V3_EN`, sets the ADC reference to 3.0 V, performs the ADC read, applies the multiplier, then turns `PIN_3V3_EN` off. That suggests the battery measurement path, ADC reference context, or related analog front-end may depend on that switched rail being enabled during measurement.

## Power control

There does not appear to be a separate programmable PMIC used as the main power controller.

Power control is mostly:

1. The nRF52840 entering System OFF / deep sleep.
2. Button wake from System OFF.
3. GPIO-switched sub-rails for sensors, accelerometer, GPS, and buzzer.
4. Firmware-controlled GPS power and reset sequencing.

MeshCore’s `powerOff()` is particularly revealing. It turns off GPS-related pins, buzzer enable, sensor rails, accelerometer rail, and sensor enable. It then configures the button as a wake source and calls `sd_power_system_off()`.

So “off” is probably an nRF52840 System OFF state plus disabled peripheral rails, not a hard mechanical or PMIC-controlled disconnect of the whole board.

## Hardware-validated power and UX findings

The following were established on real hardware during the 2026-07 UMSH UX
bringup. They correct assumptions that the firmware-tree reconstruction above
would otherwise suggest.

### P0.05 is not reliable cable-presence truth

P0.05 (`CHARGER_DET`) **can remain asserted after the magnetic cable is
removed**. Firmware must treat the nRF52840's native
`POWER.USBREGSTATUS.VBUSDETECT` as the authoritative indication of external
power; P0.05 is at most an edge/status hint for re-sampling. For the same
reason P0.05 must not be a System OFF wake source — a stuck-high level defeats
a high-sense DETECT arm. USB insertion wakes the chip from System OFF through
the native VBUS detector, which reports with its own `RESETREAS.VBUS` bit.

### P1.03 charge-status polarity confirmed

`CHARGE_STA` on P1.03 is active-low as Meshtastic documents: low = actively
charging, high = charge complete (or no charger). Validated by driving the
charging “breathing” LED indication from it.

### System OFF wake and early-boot GPIO rules

- Waking from System OFF is a reset, and GPIO configuration returns to its
  reset value: **input buffer disconnected**. The GPIO `IN` register reads 0
  while the buffer is disconnected, so the button **cannot be sampled during
  early boot** to detect the wake cause. With P0.06 as the only SENSE-armed
  pin, `RESETREAS.OFF` alone is the proof of a button wake.
- Arming SENSE for DETECT wake only works on a **connected** input buffer with
  the proper pull. Write the complete `PIN_CNF` (input connect, pull-down,
  SENSE-high for P0.06) at System OFF entry. Read-modify-writing only the
  SENSE bits silently produces an unwakeable device when entered from early
  boot, where the pin is still disconnected and floating.
- The button is active-high: a high level at System OFF entry fires DETECT
  immediately (instant re-wake). Wait for release before entering System OFF.

### LED PWM polarity

P0.24 is active-high, and with the nRF PWM peripheral (embassy-nrf
`SimplePwm`), `DutyCycle::normal(0)` parks the output **high** — a solid-on
LED. Brightness therefore requires `DutyCycle::inverted(duty)` (output high
while the counter is below the duty value). The observable signature of the
wrong mapping is an LED that is solid-on with brief dips where pulses should
be. The buzzer PWM is unaffected: its 50 % waveform is polarity-symmetric.

## Low-battery cutoff

There is definitely a **firmware-level low-battery behavior** in Meshtastic.

For the T1000-E, Meshtastic defines this open-circuit-voltage table:

```c
#define OCV_ARRAY 4190, 4042, 3957, 3885, 3820, 3776, 3746, 3725, 3696, 3644, 3100
```

The bottom value is 3100 mV. Meshtastic’s power code checks whether the measured battery voltage is below the bottom of the OCV table while the device is not USB-powered. If it sees more than 10 consecutive low readings, it triggers `EVENT_LOW_BATTERY`, which leads to deep sleep / shutdown behavior.

That is **not the same thing as a proven hardware undervoltage cutoff**. Without a schematic or charger/protection IC identification, it is not possible to confirm whether the board has an independent hardware cutoff to protect the Li-ion cell.

In practice, there may also be:

- a protected Li-ion cell or pack,
- a charger IC with undervoltage behavior,
- load-disconnect behavior in the power path,

but the firmware alone does not prove those details.

## GNSS / GPS control

The GNSS module is connected over UART1:

- RX: P0.14
- TX: P0.13
- Baud rate: 115200

The firmware uses several control pins:

- `GPS_EN` / `PIN_GPS_EN`: P1.11
- `GPS_RESET` / `PIN_GPS_RESET`: P1.15
- `GPS_VRTC_EN`: P0.08
- `GPS_SLEEP_INT`: P1.12
- `GPS_RTC_INT`: P0.15
- `GPS_RESETB` / `GPS_RESETB_OUT`: P1.14

MeshCore’s start sequence enables GPS power, enables GPS VRTC, manipulates reset, sets sleep/wake pins, and configures `GPS_RESETB` as input pullup.

MeshCore’s sleep/stop sequences turn off or reduce GPS power and sometimes drive `GPS_RESETB` low. This implies the GNSS module has both a main power domain and a backup/RTC domain exposed to firmware.

## Sensors

The device appears to have:

- QMA6100P accelerometer on I²C
- NTC temperature sensor on ADC P0.31
- Light sensor on ADC P0.29

The light sensor reading in MeshCore is mapped to a 0–100% scale, not reported as a calibrated lux value. MeshCore comments explicitly say Seeed’s firmware maps the photocell reading to a percentage rather than lux.

Temperature is calculated from an NTC lookup table and related resistor constants.

## LR1110 radio wiring

The LR1110 is wired over SPI:

| LR1110 signal | nRF52840 pin |
|---|---:|
| SCK | P0.11 |
| CS/NSS | P0.12 |
| MISO | P1.08 |
| MOSI | P1.09 |
| IRQ/DIO1 | P1.01 |
| BUSY | P0.07 |
| RESET | P1.10 |

The firmware defines:

- `USE_LR1110`
- `LR11X0_DIO3_TCXO_VOLTAGE = 1.6`
- `LR11X0_DIO_AS_RF_SWITCH`
- RF switch table handling in MeshCore

### LR1110 built-in geolocation is not used on this board

The LR1110 is a combo part: in addition to the sub-GHz LoRa transceiver, the
silicon contains GNSS and WiFi passive-scanning engines for cloud-assisted
geolocation. **None of that is wired up or used on the T1000-E.** Positioning is
handled entirely by the discrete AG3335 / Airoha GNSS module on UART1 (see the
GNSS / GPS control section); the LR1110 is used purely as a LoRa radio.

A practical consequence: the DIO3-gated 1.6 V TCXO exists only to serve the LoRa
transceiver's frequency reference — it is **not** there to support LR1110 GNSS/WiFi
scanning (which would otherwise be the usual motivation for fitting a TCXO over a
plain crystal on an LR11xx design).

### LR1110 internal regulator: LDO only (no DCDC)

The T1000-E module does **not** populate the external switching inductor
required for the LR1110's internal DCDC regulator (the chip's BST pin appears
unrouted on this board). The LR1110 must therefore be configured in **LDO
mode** — calling `SetRegMode(DCDC)` produces a malfunctioning regulator that
draws noisy switching current on the shared 3V3 rail and disrupts everything
sharing it.

Symptoms of incorrectly enabling DCDC (observed during Phase 2.5 bringup):

- USB-CDC enumeration **flaps rapidly** between "available" and "unavailable"
  on the host while the nRF52840 itself stays running (heartbeat blinks,
  buttons respond). USB has no other obvious failure mode that produces this
  pattern.
- The fault appears immediately after `LoRa::new` runs the
  `SetRegMode(DCDC)` command — bisected by toggling the configuration flag
  with all other init steps held constant.

Reference: MeshCore (RadioLib) calls `setRegulatorLDO()` unconditionally on
this board — it never enables DCDC. Match this in any LR1110-using firmware
for the T1000-E. In `lora-phy` terms: `Config::use_dcdc = false`.

## LR1110 firmware driver quirks

The following behaviors were discovered during Phase 2.5–3 bringup of UMSH firmware on the T1000-E. They are specific to the LR1110 and differ from the SX126x family; treat them as required workarounds for any lora-phy-based LR1110 driver.

### WriteBuffer8 takes no offset

The LR1110 `WriteBuffer` command (`0x0109`) is documented as `[opcode_hi, opcode_lo, data_byte_0, data_byte_1, ...]`. It does **not** have a buffer-offset field before the payload, unlike the SX1262 `WriteBuffer` command (`0x0E offset data...`). The lora-phy abstraction passes an offset byte for both chips; for the LR1110 this prepends a phantom `0x00` byte as the first byte of the transmitted payload. Every packet CRC fails on every receiver, and the root cause is invisible at the RX side. Fix: strip the offset from the LR1110 `WriteBuffer` implementation so the SPI transfer is exactly `[0x01, 0x09, payload_bytes...]`.

### IRQ flag must be cleared explicitly after process_irq_event

`LoRa::process_irq_event()` calls the LR1110 `GetIrqStatus` command with `clear_interrupts = false`. The DIO1 interrupt line therefore **remains asserted** after `process_irq_event` returns. If the next call to `wait_for_irq` relies on a falling/rising edge detect (GPIOTE in edge mode), it will return immediately on every iteration, spinning the CPU and preventing any real RX work. Fix: always call `lora.clear_irq_status().await` immediately after every `process_irq_event` call.

### Preamble length: 16 required (not 8)

The LR1110 requires a preamble length of at least **16** symbols for reliable packet detection with the LoRa modem configured for SF7 / 62.5 kHz / CR 4/5. Using the SX126x default of 8 symbols produces intermittent or zero packet detection. Both the RX and TX packet-parameter structs must use `preamble_length = 16` for interoperability between LR1110 nodes.

SX126x-based boards (T-Echo, Wio Tracker L1) use preamble 8 and work reliably between each other. Cross-chip interoperability requires preamble 16 on both sides, or adapting the SX126x firmware to also use 16 (8 is accepted by SX126x as a receiver when the transmitter uses 16).

### lora.rx()-in-select is unsafe for LR1110

Calling `lora.rx()` inside an `embassy-futures::select` (or any async cancellation boundary) is safe for the SX126x but **not** for the LR1110. The `rx()` future wraps `complete_rx`, which drives the DIO1 wait and then reads the FIFO; if the future is dropped mid-execution the LR1110 radio state machine is left in an undefined state that usually requires a full re-initialization to recover.

Working pattern for the LR1110:

```rust
lora.prepare_for_rx(RxMode::Continuous, &mdltn, &rx_pkt).await;
lora.start_rx().await;
loop {
    match select(lora.wait_for_irq(), tx_channel.receive()).await {
        Either::First(Ok(())) => {
            let result = lora.process_irq_event().await;
            let _ = lora.clear_irq_status().await;  // REQUIRED — see above
            if let Ok(Some(IrqState::Done)) = result {
                let (len, _) = lora.get_rx_result().await?;
                // read FIFO, dispatch packet ...
                lora.start_rx().await;              // re-arm in-place
            }
        }
        Either::Second(tx_req) => {
            lora.prepare_for_tx(...).await;
            lora.tx().await;
            lora.prepare_for_rx(...).await;         // full re-arm after TX
            lora.start_rx().await;
        }
    }
}
```

### HP PA must be used

The T1000-E routes the LR1110 RF output through the high-power (HP) PA path. Selecting the low-power (LP) PA in firmware (`PaSelection::Lp`) produces a significantly weaker signal. Always configure `PaSelection::Hp` and the matching maximum output power (22 dBm).

### Unverified observation: keeping the TCXO warm (StandbyXOSC) seemed to break replies

This is an **observation, not a confirmed finding** — record it as a caution, not as established fact.

While chasing LoRa reliability issues we experimented with resting the LR1110 in `StandbyXOSC` (reference oscillator left running) instead of the default `StandbyRC` (oscillator powered down between operations), with the intent of avoiding the per-operation TCXO warm-up. With that configuration we *appeared* to see the following on the T1000-E:

- It could still **initiate** a ping to an SX126x peer (T-Echo / Wio) and receive the reply.
- But a reply it **transmitted immediately after receiving** a frame did not appear to be decoded by the SX126x receivers.
- Switching back to `StandbyRC` *appeared* to restore two-way operation.

Important caveats:

- We do **not** understand the mechanism. The leading guess — that the short `StandbyRC` warm-up also gives the synthesizer settling time that a fast receive→transmit turnaround needs — is unverified speculation.
- There were **several confounding changes in flight** at the same time (peer-registration timing, a separate `do_tx` TCXO change), so the `StandbyRC` vs `StandbyXOSC` variable was not cleanly isolated beyond a single A/B firmware flip late in the session.
- The diagnosis was end-to-end ping behavior only; there was **no RF measurement** (SDR capture, spectrum, SNR of the failing frames) to confirm what actually went wrong on air.

Practical takeaway for now: prefer `StandbyRC` for the LR1110 on this board, and treat any "keep the oscillator warm" optimization as something that needs proper RF characterization before being trusted.

## Buzzer driver quirks

The T1000-E buzzer is driven by a magnetic driver IC enabled via `P1.05`. The enable pin must be asserted high before PWM is applied. The driver chip requires approximately **20 ms** to energize before the buzzer begins producing audible sound; tones shorter than ~60 ms will be inaudible or nearly silent. Melody notes for the T1000-E should be at least 60–80 ms long.

## What remains unknown without a schematic

The firmware does **not** reveal:

- exact Li-ion charger IC,
- charge current,
- charge voltage,
- charge termination behavior,
- whether the Li-ion cell or pack has its own protection PCB,
- whether there is a hardware undervoltage cutoff independent of firmware,
- exact MOSFET / load-switch topology for switched rails,
- exact regulator topology,
- whether P0.05 is raw VBUS detect, charger-present, or a conditioned charger-detect signal (hardware testing shows it can remain asserted after cable removal, suggesting a conditioned/latching signal rather than raw VBUS),
- whether P1.04 charge-done is populated and connected on all hardware revisions.

## Most likely mental block diagram

```text
Li-ion battery
   └── divider → nRF P0.02 / AIN0

USB magnetic pogo pins
   ├── D+/D- → nRF52840 USB
   └── 5 V → standalone Li-ion charger
             ├── battery
             ├── CHARGER_DET → nRF P0.05
             ├── CHARGE_STA  → nRF P1.03
             └── CHARGE_DONE → nRF P1.04, apparently unused

nRF52840
   ├── SPI → LR1110
   ├── UART1 → AG3335 / Airoha GNSS
   ├── I²C → QMA6100P accelerometer
   ├── ADC → battery, NTC temperature, light sensor
   ├── GPIO enables → sensor rail, accelerometer rail, GPS, buzzer
   ├── USB power detection via nRF USB power hardware
   └── System OFF sleep with button wake
```

## Summary

For firmware purposes, the T1000-E appears to provide:

- battery voltage measurement,
- external power / charger detection,
- charging-state detection,
- possibly charge-done hardware status, though unused in Meshtastic,
- switched power rails for sensors, accelerometer, GPS, and buzzer,
- nRF System OFF “power off” with button wake,
- firmware-level low-battery shutdown around 3.1 V after repeated low readings.

It probably does **not** expose charger configuration to firmware. Without a schematic, charger current, hardware cutoff behavior, and battery-protection topology remain unknown.

## Source references

- Meshtastic T1000-E board definition: https://github.com/meshtastic/firmware/blob/master/variants/nrf52840/tracker-t1000-e/variant.h
- Meshtastic T1000-E variant initialization: https://github.com/meshtastic/firmware/blob/master/variants/nrf52840/tracker-t1000-e/variant.cpp
- Meshtastic power management: https://github.com/meshtastic/firmware/blob/master/src/Power.cpp
- MeshCore T1000-E variant definition: https://github.com/meshcore-dev/MeshCore/blob/main/variants/t1000-e/variant.h
- MeshCore T1000-E board implementation: https://github.com/meshcore-dev/MeshCore/blob/main/variants/t1000-e/T1000eBoard.h
- MeshCore T1000-E board startup: https://github.com/meshcore-dev/MeshCore/blob/main/variants/t1000-e/T1000eBoard.cpp
- MeshCore T1000-E target/GPS/radio implementation: https://github.com/meshcore-dev/MeshCore/blob/main/variants/t1000-e/target.cpp
- MeshCore T1000-E sensor implementation: https://github.com/meshcore-dev/MeshCore/blob/main/variants/t1000-e/t1000e_sensors.cpp
- Meshtastic T1000-E device page: https://meshtastic.org/docs/hardware/devices/seeed-studio/sensecap/card-tracker/
- Seeed MeshCore T1000-E page: https://wiki.seeedstudio.com/sensecap_t1000_e_meshcore/
