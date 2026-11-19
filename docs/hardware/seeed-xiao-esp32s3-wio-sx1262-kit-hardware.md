# Seeed XIAO ESP32S3 + Wio-SX1262 Kit Hardware Reference

This document describes the **Seeed XIAO ESP32S3 + Wio-SX1262 kit** at the
level needed to port and maintain UMSH firmware. It combines:

- Seeed's Wio-SX1262 for XIAO schematic (the 30-pin B2B carrier)
- Seeed's XIAO ESP32S3 wiki and pin tables
- MeshCore's `xiao_s3_wio` variant
- Meshtastic's `seeed_xiao_s3` variant
- Espressif ESP32-S3 documentation

> **Identification warning**
>
> This is not the XIAO nRF52840 kit
> ([`seeed-xiao-nrf52840-wio-sx1262-kit-hardware.md`](seeed-xiao-nrf52840-wio-sx1262-kit-hardware.md)).
> The two carriers share a name and a radio module but not a pinout: this
> kit's carrier mates through the XIAO ESP32S3's 30-pin board-to-board (B2B)
> connector, and its radio lines land on pads that have no D-number.

---

## 1. Summary

- Espressif ESP32-S3R8: dual-core Xtensa LX7, 8 MiB **octal** PSRAM in package
- 8 MiB QIO flash on the XIAO module
- Semtech SX1262 (Wio-SX1262 module) with a 1.8 V TCXO, on the B2B carrier
- One user button (USR) and one green LED on the carrier
- BOOT and RESET buttons, a yellow user LED, and a red charge LED on the XIAO
- Native USB (USB-Serial-JTAG) only; no USB-UART bridge
- Single-cell charger and battery pads on the XIAO; **no battery or VBUS sense**
- Separate antennas: LoRa on the carrier, Wi-Fi/BLE on the XIAO

The kit ships with Meshtastic installed.

## 2. Kit contents

The kit is a XIAO ESP32S3 and a Wio-SX1262 for XIAO carrier joined by the
B2B connector, with the carrier's two 1×7 headers following the XIAO's edge
pads. The radio, USR button, and green LED are reached only through the B2B
connector; the edge pads stay free except where noted in §8.

## 3. MCU and memory

### 3.1 ESP32-S3R8

The R8 has 8 MiB of PSRAM inside the package, wired **octal**. It occupies
GPIO33–37, which are therefore unavailable. UMSH names the interface in the
BSP (`PSRAM_MODE = OctalSpi`) rather than probing for it.

### 3.2 Flash

8 MiB of QIO flash. UMSH uses the shared 4 MB partition layout
(`partitions-umsh.csv`, the `umsh` data partition at `0x300000`), which fits
with room to spare.

## 4. LoRa radio

### 4.1 SX1262 interface

| Signal | GPIO | XIAO label | Notes |
|---|---:|---|---|
| SCK | 7 | D8 | SPI2 |
| MISO | 8 | D9 | |
| MOSI | 9 | D10 | |
| NSS | 41 | B2B only | |
| RESET | 42 | B2B only | 10 kΩ pull-up on the carrier |
| BUSY | 40 | B2B only | |
| DIO1 | 39 | B2B only | IRQ |
| RF_SW1 (RXEN) | 38 | B2B only | RF switch receive side, active high |

The schematic, MeshCore, and Meshtastic agree on every line.

### 4.2 RF switch

The module's RF switch has two controls. DIO2 drives the transmit side
(`SetDio2AsRfSwitchCtrl`), and the host drives the receive side, RF_SW1, from
GPIO38. There is no TXEN. The line is high in receive and low in transmit and
in sleep, the same semantics as lora-phy's generic SX126x interface variant.

UMSH carries this as the `radio-rxen` feature: the shared
`umsh_bsp_esp32::iv` interface variant takes an optional receive-enable
output. ESP32-S3 light sleep keeps the digital pads powered, so the line holds
through a light-sleeping receive.

### 4.3 TCXO and power

DIO3 powers a 1.8 V TCXO. MeshCore runs the SX1262 on its DC-DC regulator
with boosted receive gain, a 140 mA overcurrent limit, and 22 dBm. UMSH sets
the TCXO, the DC-DC regulator, and boosted gain (`Ctrl1V8`, `use_dcdc`,
`rx_boost`); transmit power is configuration.

## 5. Buttons and LEDs

| Part | Where | GPIO | Polarity | Notes |
|---|---|---:|---|---|
| USR button (K1) | Carrier | 21 | Low when pressed, 10 kΩ pull-up | RTC GPIO: wakes from deep sleep |
| Green LED (D1) | Carrier | 48 | High = on, 330 Ω series | |
| Yellow user LED | XIAO | 21 | Low = on | Same net as USR |
| Red charge LED | XIAO | — | Charger-driven | Not under firmware control |
| BOOT | XIAO | 0 | Low when pressed | Strapping pin; covered by the carrier |
| RESET | XIAO | EN | | Covered by the carrier |

**GPIO21 is shared.** The XIAO's yellow user LED and the carrier's USR button
are the same net, so the yellow LED lights while USR is held, and firmware
must leave GPIO21 an input: driving it would fight the button.

GPIO0 is the ROM download strap. UMSH never claims it.

**BOOT and RESET are under the carrier.** With the kit assembled, USR is the
only button that can be pressed: there is no manual way into the ROM
bootloader and no reset short of removing power.

## 6. USB and serial

USB goes straight to the ESP32-S3's USB-Serial-JTAG controller
(`303a:1001`) on GPIO19/20. There is no USB-UART bridge.

### 6.1 Application UART

UART0 on D6 (GPIO43, TX) and D7 (GPIO44, RX) carries ULCP to a
microcontroller wired to the header: the device's own interface, served
beside a host on USB or BLE (`ulcp-uart`, on by default). It runs at
115200 8N1 unless the build sets `UMSH_ULCP_UART_BAUD`, with HDLC-Lite
framing and XON/XOFF pacing under `PROP_UART_WINDOW`. RX is pulled up, so
the pads may be left unwired.

The board light-sleeps while the link listens (§7.2). An application
that has sent nothing for 100 ms sends a wake preamble before it writes
again.

The boot ROM prints on D6 at every reset. The application reads that as a
lost frame and starts a new session, which a restart requires anyway.

### 6.2 No VBUS sense

Nothing routes VBUS, the battery, or the charger's status to a GPIO, so the
firmware cannot tell USB power from a battery. Host presence comes from the
bus instead (`usb-presence-sof`): a full-speed host sends a start-of-frame
packet every millisecond to an enabled port, and the controller latches each
one in its `SOF` interrupt-raw bit with or without a driver.

The controller is clocked only while the chip is awake, so the policy has two
halves:

- **Host present:** the transport's wake locks keep the chip awake; the flag
  is checked every 250 ms, and four silent checks in a row (cable pulled, or
  bus suspended) declare the host gone. The transport closes and the chip may
  light-sleep.
- **No host:** once a second the chip holds itself awake for 20 ms and looks
  for a start-of-frame. A host that attaches meanwhile has reset the bus and
  keeps sending frames while it retries the requests the sleeping controller
  missed, so the next probe finds it.

`esp-println` reads the same flag to pick its output port.

### 6.3 D+ activity as a wake source

esp-hal's S3 sleep support offers no USB wake source. Every packet, bus
reset, and resume drives D+ low, so a GPIO wake on GPIO20 could replace the
probe while no host is present. esp-hal's `Input` cannot be used for it: building
one calls `disable_usb_pads()`, which drops the D+ pull-up and detaches the
board. Whether the pad's digital input reads D+ while the USB PHY owns it is
unconfirmed.

### 6.4 Flashing

espflash resets the chip into the ROM bootloader over USB-Serial-JTAG, and a
hard reset afterward starts the new image.

The factory Meshtastic image is different. It runs Arduino's TinyUSB CDC
(`2886:0059`, "seeed_xiao_s3"), not USB-Serial-JTAG, and answers the reset
request by setting `RTC_CNTL_OPTION1.FORCE_DOWNLOAD_BOOT` and restarting into
the ROM. The ROM enumerates as `303a:1001` on a different port, so the first
flash fails to connect and has to be rerun on the new port. The latch then
survives every reset short of power loss, so the freshly written image boots
back into the ROM (`boot:0x23 (DOWNLOAD(USB/UART0))`). esptool clears the
latch before its hard reset; espflash does not. Removing power (USB and any
battery) clears it. The web flasher clears the latch as esptool does, and
follows the board to the ROM's new port.

## 7. Power

### 7.1 Battery

The XIAO charges a single Li-ion/LiPo cell from its battery pads. Nothing
measures the cell, so UMSH advertises `CAP_BATTERY` with an empty
`PROP_BATTERY`.

### 7.2 Light sleep

The S3 light-sleeps whenever nothing holds a wake lock. The USB pads and
their pull-up stay powered, so a host still sees the device attached; RXEN
holds its level.

Light sleep stops the UART, so the application UART wakes the chip: three
rising edges on RX, which the application's wake preamble supplies. The
link then holds a wake lock for 250 ms after the last octet it received,
and while it writes. RX interrupts at every octet, so the first octet
after a wake reaches the link before the chip can sleep again. A UART wake
source keeps the digital peripherals powered through the sleep. Not yet
measured: how long the wake takes, how many octets it loses, and the
sleep current it adds.

### 7.3 Deep sleep

UMSH powers off into deep sleep with USR (GPIO21, an RTC GPIO) armed as the
wake source. Plugging in USB does not wake it. GPIO38 (RXEN) and GPIO41 (NSS)
are not RTC pads and float in deep sleep; if sleeping current is high, hold
NSS high and RXEN low with `set_pad_hold` before sleeping.

## 8. I²C and expansion

| Function | GPIO | XIAO label |
|---|---:|---|
| SDA | 5 | D4 |
| SCL | 6 | D5 |

Nothing is fitted. UMSH opens the bus to hosts at 100 kHz (`ulcp-i2c`) as
"I2C0 SDA D4/GPIO5 SCL D5/GPIO6".

## 9. UMSH board definition

| | |
|---|---|
| Image | `xiao-esp32s3` |
| Board feature | `board-xiao-esp32s3` |
| BSP crate | `umsh-bsp-xiao-esp32s3` |
| `PROP_DEV_MODEL` | `Seeed XIAO ESP32S3 + Wio-SX1262 Kit` |
| BLE pairing `model_id` | 10 |
| Default features | `ulcp-uart`, `ble`, `psram`, `coex`, `bridge-client`, `meshcore-forwarder`, `lan-bearer`, `entropy-sar-adc` |
| Capabilities | `radio-sx126x`, `radio-rxen`, `status-led`, `power-off-deep-sleep`, `usb-presence-sof`, `ulcp-i2c` |

No `display` (the button and LED are the interface), no `battery-telemetry`,
and no GNSS. ADC1 is free, so the boot entropy read from the SAR ADC is on.

## 10. Bring-up checklist

- **Identification:** USR reads low when pressed and lights the yellow LED;
  GPIO48 lights the green LED; the boot log reports 8 MiB of octal PSRAM.
- **First boot over Meshtastic:** the journals format and the identity persists
  across a reset.
- **Radio:** receive and transmit against another board, on USB and on battery
  (light-sleeping); RXEN holds while asleep; MeshCore forwarding.
- **BLE:** first pairing, bonded reconnect, and the hold-through-boot ceremony.
- **Wi-Fi:** the bridge and the LAN bearer under coexistence, with heap minima
  from a `debug-log` build.
- **USB presence:** plug and unplug on macOS, Linux (with autosuspend),
  Windows, and through a hub; host suspend and resume; time from plug-in to
  port. A charger is allowed to keep the board awake.
- **Controls:** beacon press, alert cancel, 4 s power-off, USR wake.
- **Power:** light- and deep-sleep current, and a multi-hour battery soak.
- **Flashing:** `make flash-xiao-esp32s3` and the web flasher on a
  factory-fresh kit; a reflash keeps the device name.

### 10.1 Confirmed on hardware (2026-10-16, one kit, USB power, no battery)

- Flashed over the factory Meshtastic image (§6.4). The image boots, the
  journals format, and the identity, device name, PHY setting, and BLE bond
  all survive reflashing. PSRAM is inferred working: the session lives there.
- ULCP over USB-Serial-JTAG; the transport stays up while a host sends
  start-of-frames.
- SX1262 transmit and receive at 917.5 MHz: a discover from the XIAO drew
  answers from five nodes (-24 to -88 dBm), and the XIAO's own node answered
  a ping relayed by a LAN bridge.
- Locate alert (triple blink) and its cancellation by USR; the two-blink
  pairing indicator; a USR beacon; the 4 s power-off with three flashes, deep
  sleep, and USR wake; the hold-through-boot ceremony (two flashes, window
  reopened over an existing bond).
- BLE advertising, first pairing from the iOS app, and attach. Advertising
  stops while a USB host holds the session and resumes after a reboot.

Not yet run: Wi-Fi, the bridge, and the LAN bearer; USB unplug and light
sleep (needs a battery); current measurements.

## 11. Sources

- Kit product page:
  https://www.seeedstudio.com/Wio-SX1262-with-XIAO-ESP32S3-p-5982.html
- **Wio-SX1262 for XIAO schematic** (B2B carrier: J3, RF_SW1, K1, D1):
  https://files.seeedstudio.com/products/SenseCAP/Wio_SX1262/Schematic_Diagram_Wio-SX1262_for_XIAO.pdf
- XIAO ESP32S3 wiki (pin tables, user LED, battery):
  https://wiki.seeedstudio.com/xiao_esp32s3_getting_started/
- MeshCore variant:
  https://github.com/meshcore-dev/MeshCore/tree/main/variants/xiao_s3_wio
- Meshtastic variant:
  https://github.com/meshtastic/firmware/tree/develop/variants/esp32s3/seeed_xiao_s3
- ESP32-S3 Technical Reference Manual (USB Serial/JTAG controller, RTC GPIO):
  https://www.espressif.com/sites/default/files/documentation/esp32-s3_technical_reference_manual_en.pdf
