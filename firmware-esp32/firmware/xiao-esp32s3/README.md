# xiao-esp32s3

UMSH firmware for the **Seeed XIAO ESP32S3 + Wio-SX1262 kit**: a XIAO
ESP32S3 on Seeed's Wio-SX1262 radio carrier, mated through the XIAO's 30-pin
board-to-board connector. It is a thin manifest over the shared ESP32 sources
in [`../esp32-tracker/`](../esp32-tracker/); what is particular to the board
is selected by the `board-xiao-esp32s3` feature and lives in
[`umsh-bsp-xiao-esp32s3`](../../crates/umsh-bsp-xiao-esp32s3/). Pin maps,
power, and the reasoning behind each choice are in the
[hardware reference](../../../docs/hardware/seeed-xiao-esp32s3-wio-sx1262-kit-hardware.md).

This is not the XIAO nRF52840 kit
([`firmware/xiao-nrf52`](../../../firmware/xiao-nrf52/)). The two carriers
share a name and a radio module, not a pinout.

## Building and flashing

From the repository root, with the Xtensa toolchain installed (see the
[workspace README](../../README.md)):

```sh
make flash-xiao-esp32s3
```

espflash resets the board into the ROM bootloader by itself. The first flash
over the factory Meshtastic image is the exception:

- It fails to connect, because the reset makes the board re-enumerate as the
  ROM on a new port. Run it again on that port.
- The new image then boots back into the ROM until the board loses power,
  because the reset latched the S3's force-download flag and espflash does
  not clear it. Unplug the board, and any battery, once.

The [web flasher](https://umsh.dev/flasher/) handles both.

## Features

`default` is `board-xiao-esp32s3`, `ulcp-uart`, `ble`, `psram`, `coex`,
`bridge-client`, `meshcore-forwarder`, `lan-bearer`, and `entropy-sar-adc`.
The board feature adds the header I2C bus on D4 (SDA) and D5 (SCL), open to
hosts at 100 kHz (`ulcp-i2c`). The workspace README describes the features
every image shares.

### The application UART

`ulcp-uart` serves a microcontroller wired to D6 (GPIO43, TX) and D7
(GPIO44, RX) as the device's own interface, with node messaging, beside a
host on USB or BLE. It is **on by default**: this kit's host link is the
native USB port, so UART0 is otherwise unused, and nothing else is on those
pads. The link runs at 115200 8N1 unless the build sets
`UMSH_ULCP_UART_BAUD`, and is paced with XON and XOFF. RX is pulled up, so
the pads may be left unwired.

- **The board light-sleeps while the link listens.** Activity on D7 wakes
  it, and it stays awake for 250 ms after the last octet it received.
  The application must send a wake preamble before writing after 100 ms
  of quiet (spec §Waking a Device on a UART); `umshctl --uart-window`
  does. Keeping the UART able to wake the chip keeps the digital
  peripherals powered through the sleep, which costs sleep current that
  has not been measured.
- **The boot ROM prints on D6 at every reset**, and so does any boot text
  written before the firmware claims the port while no USB host is attached.
  The application reads it as a lost frame and starts a new session, which a
  restart requires anyway.

## Quirks

- **USR is the only button you can press.** BOOT and RESET are on the XIAO,
  under the carrier. A press of USR sends a check-in, holding it through boot
  opens the pairing window over existing bonds (two flashes), and holding it
  for 4 seconds powers off into deep sleep, from which USR wakes the board.
  Plugging in USB does not.
- **USR and the XIAO's yellow LED share GPIO21**, so the yellow LED lights
  while USR is held, and the firmware never drives the pin.
- **No VBUS or battery sense.** Nothing tells the firmware whether USB or a
  battery powers it, or how full the battery is: `PROP_BATTERY` is empty.
  Whether a USB host is present is read from the bus's start-of-frame
  packets. With no host, the board wakes for 20 ms each second to look for
  one.
- **The RF switch has a receive-enable line** (`radio-rxen`, GPIO38) that the
  firmware drives, alongside DIO2 on the transmit side.
- **PSRAM is octal** and takes GPIO33–37.
