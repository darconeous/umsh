# XIAO and SenseCAP Solar BLE flashing

`make flash-ble-xiao-nrf52` and `make flash-ble-sensecap-solar` build the
selected board's shipping image, create its application-only DFU ZIP,
and upload it through the computer's Bluetooth adapter. The board must
already be in **BLE DFU**. These targets do not enter the bootloader.

## Setup

From the repository root, with Git and Python 3.10 or newer installed:

```sh
make install-ble-dfu-setup
```

The target creates an isolated environment under `target/ble-dfu`, installs
Bleak 3.0.2, checks out unmodified `nrf_dfu_py` revision
`409e4b75d55c8d75859022217dfba0db33730f16`, and checks the uploader imports.
It can be run again; an existing modified checkout or a different revision
is left untouched and reported as an error. To use a different Python
installation, pass `DFU_BLE_SETUP_PYTHON=/path/to/python3`.

These are the uploader revision and Bleak version used for the Wio and
XIAO hardware tests. No Nordic DK or dongle is needed. macOS must
allow Bluetooth access for the terminal running the command. Other Bleak
platforms have not been hardware-qualified here.

DFU packaging also requires `adafruit-nrfutil`, as with
the `dfu-zip-*` targets. Set `NRFUTIL=/path/to/adafruit-nrfutil` if needed.
Existing uploader environments can be selected with `DFU_BLE_PYTHON` and
`DFU_BLE_UPLOADER` (the directory containing `dfu_lib.py`).

## Upload

With the board already in BLE DFU, find its bootloader UUID/address:

```sh
make scan-ble-dfu
```

For an XIAO, upload with:

```sh
make flash-ble-xiao-nrf52 DFU_BLE_ADDRESS=<bootloader-UUID-or-MAC>
```

For a SenseCAP Solar P1, upload with:

```sh
make flash-ble-sensecap-solar DFU_BLE_ADDRESS=<bootloader-UUID-or-MAC>
```

Use the bootloader's identifier, which can differ from the application's.
The shared `AdaDFU` name does not identify a board; confirm which nearby
bootloader belongs to the intended board. The uploader requires an exact identifier
advertising the legacy DFU service and never falls back to another device.

The transfer uses 20-byte packets, packet receipts every eight packets,
and one upload attempt, matching the hardware-tested settings. It rejects
packages containing bootloader/SoftDevice images or requiring a SoftDevice
other than S140 7.3.0. Upload or validation errors exit unsuccessfully
without automatically starting another update.

After bootloader validation, activation is requested. Read the application
version afterward to confirm the running image. During XIAO qualification,
the new application booted automatically but USB returned only after a
physical RESET; see [qualification results](../../docs/dfu-entry.md).

Adapter tests run without Bluetooth hardware or third-party packages:

```sh
python3 -m unittest discover -s tools/ble-dfu -p 'test_*.py'
```
