# xiao-nrf52

UMSH firmware for the **Seeed Studio XIAO nRF52840 & Wio-SX1262 Kit** (SKU
102010710): a XIAO nRF52840 on Seeed's Wio-SX1262 radio carrier, mated
through the 2×7 header. It is a thin manifest over the shared nRF52840
sources in [`../nrf52-tracker/`](../nrf52-tracker/); what is particular to
the board is selected by the `board-xiao-nrf52` feature and lives in
[`umsh-bsp-xiao-nrf52`](../../crates/umsh-bsp-xiao-nrf52/). Pin maps, power,
and the reasoning behind each choice are in the
[hardware reference](../../docs/hardware/seeed-xiao-nrf52840-wio-sx1262-kit-hardware.md).

This is not the XIAO ESP32S3 kit
([`firmware-esp32/firmware/xiao-esp32s3`](../../firmware-esp32/firmware/xiao-esp32s3/)).
The two carriers share a name and a radio module, not a pinout.

## Building and flashing

From the repository root:

```sh
make flash-xiao-nrf52
```

Double-tap RESET to enter the bootloader first. `make flash-ble-xiao-nrf52`
updates the firmware over BLE instead.

- **The UF2 is packed with the generic family `0xADA52840`.** Retail kits
  ship the *Sense* bootloader configuration on plain hardware (the volume
  is `XIAO-SENSE`). A UF2 of the wrong family is copied without error and
  silently not written: if a flash succeeds and the old image still runs,
  check the family first.
- The application starts at `0x27000`, and the writable window ends at
  `0xEA000`, not `0xED000`.

## Features

`default` is `board-xiao-nrf52` and `ulcp-i2c`. The board feature carries the
battery monitor, the active-low RGB LED, the MeshCore forwarder, and the
REG1 DC/DC converter, whose inductor this XIAO has.

| Feature | Default | What it adds |
|---|---|---|
| `ulcp-i2c` | on | The header I2C bus on D6 (SDA) and D7 (SCL), open to hosts at 100 kHz with the internal pull-ups |
| `node-msg` | off | Node messaging for a host on USB or BLE |
| `ulcp-uart` | off | An application UART on D6 and D7, with node messaging; see below |

### The application UART

`ulcp-uart` serves a microcontroller wired to D6 (`P1.11`, TX) and D7
(`P1.12`, RX) as the device's own interface, beside a host on USB or BLE.
Those pads are the I2C bus in the default build, so it is one or the other,
and the UART is **off by default**. Build it with:

```sh
cd firmware/xiao-nrf52
cargo build --release --no-default-features --features board-xiao-nrf52,ulcp-uart
```

Pack and flash the result with `scripts/mkimage.py` and `scripts/flash.py`,
as the `build-xiao-nrf52` and `flash-xiao-nrf52` targets do. The link runs at
115200 8N1 unless `UMSH_ULCP_UART_BAUD` names another rate the UARTE has, and
is paced with XON and XOFF. RX is pulled up, so the pads may be left unwired.
The UARTE keeps listening, and its clock running, while the CPU sleeps; that
cost has not been measured. The board needs no wake preamble, and discards
one as fill.

## Quirks

- **No buttons.** The XIAO's RESET is the only one, and it cannot be read.
  The carrier has a footprint for a user button (K1), but it ships empty,
  and so does its pull-up. There is no hold-to-power-off, no press-to-wake,
  and no force-pairing gesture; everything is done over USB or BLE.
- **Pairing.** A pairing window opens at boot only while the radio has no
  bonds. After that, another host is let in by setting `PROP_BLE_PAIRING`
  from a bonded host or over USB, which is also how a radio whose last
  bonded host is gone is recovered.
- **Power-off is only protective.** System OFF is reached by the low-battery
  cutoff alone. It is left by RESET, by plugging in USB, or, with nobody
  present, by the comparator wake once the cell has recharged.
- **`P0.14` stays low.** It is the low side of the battery divider, not a
  switch for it: driving it high, or letting it float, puts the ADC pin at
  or over its absolute maximum. The divider draws about 2.8 µA as a result.
- **Charge state.** The charger's status line, read with the battery
  voltage, tells charging from charged.
- **LED.** The RGB LED is common-anode, so it is driven low to light. Green
  is on a larger resistor and looks dimmer than red and blue.
- **QSPI flash.** The 2 MB part is fitted, whatever the schematic says.
  Nothing uses it, and its pins are not free.
- **GNSS.** The kit has none. An L76K can be added on D6 and D7, which this
  firmware does not support.
