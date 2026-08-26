---
name: flashing
description: Flash UMSH firmware to a board. Per-board `make flash-*` targets, DFU entry, UF2 drive names and family IDs, app base addresses, and the flash-layout gotchas for T-Echo, T1000-E, Wio Tracker L1, SenseCAP Solar P1, XIAO nRF52840, Heltec V3, and Heltec V2.
---

# Flashing UMSH firmware

Use the Makefile — don't invoke objcopy/uf2conv/espflash by hand.

## nRF52840

UF2/DFU via `scripts/flash.py`; device must be in DFU mode: 1200-baud touch, double-tap
reset, or the per-board button gesture.

**The entry path does not decide the flashing method.** However the board reached the
Adafruit bootloader, it presents both the UF2 mass-storage volume *and* a CDC serial-DFU
port, so `flash-<board>` (copy) and `flash-<board>-serial` (adafruit-nrfutil) both work.
The one exception is a board sent there by `enter_dfu_serial()` (GPREGRET `0x4e`), which
is serial-only by design and mounts no drive; the 1200-baud touch in shipped UMSH firmware
uses `0x57`, which offers both. The bootloader's serial port is not the one the
application enumerates — pass `DFU_SERIAL_PORT=/dev/cu.usbmodem<N>` explicitly.

- `make flash-techo-console`, `make flash-techo`
- `make flash-wio-tracker-l1-console`, `make flash-wio-tracker-l1` (UF2 drive `/Volumes/TRACKER L1`; app base `0x27000` — S140 v7.3.0, **not** the T-Echo's `0x26000`)
- `make flash-t1000e-console` (UF2 drive `/Volumes/T1000-E`). **T1000-E has exactly two DFU entry paths: hold the user button while cycling USB power twice, or enter from software. There is no hold-the-button-while-plugging-in gesture** — do not describe one, and note there is no double-tap reset on this board either. Both paths land in the same bootloader, so `make flash-t1000e-console` and `make flash-t1000e-console-serial` (override `DFU_SERIAL_PORT=/dev/cu.usbmodemN`) are equally usable from either one. The board is factory-sealed with no debug header — a damaged bootloader is unrecoverable
- `make flash-sensecap-solar` (shipping image) or `make flash-sensecap-solar-console`
- `make flash-xiao-nrf52` (Seeed XIAO nRF52840 + Wio-SX1262 kit; app base `0x27000`, **app window ends `0xEA000`**). Packed with the generic `0xADA52840` family, not a Seeed one: retail kits ship the *Sense* bootloader config on plain hardware (`/Volumes/XIAO-SENSE`), and **a wrong-family UF2 is copied with no error and silently not written** — if a flash "succeeds" but the old image still runs, check the family first

To perform a 1200 baud DFU touch (resetting the board into bootloader mode by opening and
closing the serial port at 1200 baud) using the `stty` command on Linux, run
`stty -F /dev/ttyACM0 1200` (or `stty -f /dev/cu.usbmodemXXXX 1200` on macOS) immediately
before launching your flashing tool.

## ESP32

Build from `firmware-esp32/`; needs the espup toolchain
(`cargo install espup espflash && espup install`). Flash via ROM serial bootloader —
cannot be bricked, stays attached as monitor.

- `make flash-heltec-v3`, `make flash-heltec-v3-console` (override `ESPFLASH_PORT=...`)
- `make flash-heltec-v2` (classic ESP32; same CP2102 flow, `--chip esp32`)
- ESP32 flashes rewrite the partition table (`partitions-umsh.csv`, carries the 64 KB `umsh` data partition) — reflashing loses data past the old factory partition.
