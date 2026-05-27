#!/usr/bin/env python3
"""
Convert an embedded ELF to the Microsoft UF2 file format and
optionally drop it onto a mounted UF2-bootloader mass-storage volume.

This is intentionally a single self-contained script with no
third-party Python dependencies: it shells out to a host
`*-objcopy` (defaults to `arm-none-eabi-objcopy`) for the ELF→bin
step and then packs the bin into UF2 blocks in pure Python.

The UF2 layout is documented at https://github.com/microsoft/uf2.

Each supported board has different SoftDevice / bootloader layout
and family-ID conventions; pick one via `--board`. The board preset
sets the flash base address, family ID, and a sensible default
`--copy-to` mount path. Individual flags still override the preset.

Boards
------

  techo            LilyGO T-Echo (Adafruit family 0xADA52840,
                   S140 v6.1.1, app @ 0x26000, /Volumes/TECHOBOOT).
  wio-tracker-l1   Seeed Wio Tracker L1 / L1 Pro
                   (Seeed family 0x28861667, S140 v7.3.0,
                   app @ 0x27000, /Volumes/TRACKER L1).
  t1000e           Seeed SenseCAP T1000-E (Seeed family 0x28860057,
                   S140 v7.3.0, app @ 0x27000, /Volumes/T1000-E).

Examples
--------

  # Convert only:
  scripts/flash.py --board techo \\
      target/thumbv7em-none-eabihf/release/firmware-hello-techo

  # Convert and copy to a mounted bootloader drive:
  scripts/flash.py --board wio-tracker-l1 \\
      target/thumbv7em-none-eabihf/release/firmware-hello-wio-tracker-l1 \\
      --copy-to "/Volumes/TRACKER L1"

  # Same as above with the board's default mount path picked up:
  scripts/flash.py --board wio-tracker-l1 --copy-default \\
      target/thumbv7em-none-eabihf/release/firmware-hello-wio-tracker-l1

  # Flash via serial DFU (useful on T1000-E where the user-button bootloader
  # path only exposes /dev/tty.usbmodem* and not the UF2 mass-storage drive):
  scripts/flash.py --board t1000e --serial-dfu /dev/tty.usbmodem1101 \\
      target/thumbv7em-none-eabihf/release/firmware-companion-cli-t1000e
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

# UF2 block layout (https://github.com/microsoft/uf2).
UF2_MAGIC_START0 = 0x0A324655   # "UF2\n"
UF2_MAGIC_START1 = 0x9E5D5157   # randomly selected
UF2_MAGIC_END = 0x0AB16F30      # randomly selected
UF2_FLAG_FAMILY_ID = 0x00002000
UF2_PAYLOAD_BYTES = 256
UF2_BLOCK_BYTES = 512

DEFAULT_OBJCOPY = "arm-none-eabi-objcopy"

# Common locations to look for adafruit-nrfutil (used by --serial-dfu).
# `shutil.which` checks PATH first; these are pip-install fallbacks for
# users (e.g. macOS Homebrew Python) where pip's bin dir isn't on PATH.
ADAFRUIT_NRFUTIL_FALLBACKS = [
    os.path.expanduser("~/Library/Python/3.13/bin/adafruit-nrfutil"),
    os.path.expanduser("~/Library/Python/3.12/bin/adafruit-nrfutil"),
    os.path.expanduser("~/Library/Python/3.11/bin/adafruit-nrfutil"),
    os.path.expanduser("~/.local/bin/adafruit-nrfutil"),
]

# Board presets. Each entry has the flash base address (where the app
# starts, after MBR + SoftDevice), the UF2 family ID the bootloader
# accepts, and the typical macOS mount path for the bootloader volume.
#
# When changing these, also update:
#   * docs/firmware-plan-<board>.md (Phase 0 section)
#   * docs/<vendor>-<board>-hardware.md (bootloader / flash layout section)
BOARDS = {
    "techo": {
        "base":   0x00026000,        # S140 v6.1.1 reserves 152 KiB
        "family": 0xADA52840,        # Adafruit nRF52840 family
        "mount":  "/Volumes/TECHOBOOT",
        "description": "LilyGO T-Echo",
    },
    "wio-tracker-l1": {
        "base":   0x00027000,        # S140 v7.3.0 reserves 156 KiB
        "family": 0x28861667,        # Seeed family (VID 0x2886 | PID 0x1667)
        "mount":  "/Volumes/TRACKER L1",
        "description": "Seeed Wio Tracker L1 / L1 Pro",
    },
    "t1000e": {
        "base":   0x00027000,        # S140 v7.3.0 reserves 156 KiB (confirmed Phase 0)
        "family": 0x28860057,        # Seeed family (VID 0x2886 | PID 0x0057)
        "mount":  "/Volumes/T1000-E",
        "description": "Seeed SenseCAP T1000-E",
    },
}


def pack_uf2(data: bytes, base_addr: int, family_id: int) -> bytes:
    """Pack a flat flash image into a UF2 byte stream."""
    if not data:
        raise ValueError("empty flash image")

    blocks = []
    n_blocks = (len(data) + UF2_PAYLOAD_BYTES - 1) // UF2_PAYLOAD_BYTES
    for i in range(n_blocks):
        chunk = data[i * UF2_PAYLOAD_BYTES : (i + 1) * UF2_PAYLOAD_BYTES]
        if len(chunk) < UF2_PAYLOAD_BYTES:
            chunk = chunk + b"\x00" * (UF2_PAYLOAD_BYTES - len(chunk))

        header = (
            UF2_MAGIC_START0.to_bytes(4, "little")
            + UF2_MAGIC_START1.to_bytes(4, "little")
            + UF2_FLAG_FAMILY_ID.to_bytes(4, "little")
            + (base_addr + i * UF2_PAYLOAD_BYTES).to_bytes(4, "little")
            + UF2_PAYLOAD_BYTES.to_bytes(4, "little")
            + i.to_bytes(4, "little")
            + n_blocks.to_bytes(4, "little")
            + family_id.to_bytes(4, "little")
        )
        # The data area is 476 bytes; the last 4 are the end magic.
        # We use 256 bytes of payload, so pad to 476.
        padding = b"\x00" * (476 - UF2_PAYLOAD_BYTES)
        end = UF2_MAGIC_END.to_bytes(4, "little")

        block = header + chunk + padding + end
        assert len(block) == UF2_BLOCK_BYTES, f"block {i} is {len(block)} bytes"
        blocks.append(block)

    return b"".join(blocks)


def elf_to_bin(elf_path: str, objcopy: str) -> bytes:
    """Run objcopy -O binary and return the resulting bytes."""
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as tmp:
        bin_path = tmp.name
    try:
        subprocess.run(
            [objcopy, "-O", "binary", elf_path, bin_path],
            check=True,
        )
        with open(bin_path, "rb") as fh:
            return fh.read()
    finally:
        try:
            os.unlink(bin_path)
        except OSError:
            pass


def parse_int(value: str) -> int:
    """Accept decimal, hex (0x...) or binary (0b...) literals."""
    return int(value, 0)


def find_adafruit_nrfutil() -> str | None:
    """Locate adafruit-nrfutil on PATH or in known pip-install fallbacks."""
    found = shutil.which("adafruit-nrfutil")
    if found:
        return found
    for path in ADAFRUIT_NRFUTIL_FALLBACKS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def flash_serial_dfu(elf_path: str, port: str, objcopy: str) -> int:
    """ELF → ihex → DFU zip → adafruit-nrfutil dfu serial."""
    nrfutil = find_adafruit_nrfutil()
    if nrfutil is None:
        print("flash.py: adafruit-nrfutil not found in PATH or common pip "
              "install locations.", file=sys.stderr)
        print("flash.py: install with: pip install --user adafruit-nrfutil",
              file=sys.stderr)
        return 1

    hex_path = elf_path + ".hex"
    zip_path = elf_path + ".zip"

    print(f"flash.py: extracting ihex via {objcopy} ...")
    subprocess.run([objcopy, "-O", "ihex", elf_path, hex_path], check=True)

    print(f"flash.py: packaging DFU zip via {nrfutil} ...")
    subprocess.run(
        [nrfutil, "dfu", "genpkg",
         "--dev-type", "0x0052",   # arbitrary non-zero; bootloader ignores it
         "--application", hex_path,
         zip_path],
        check=True,
    )

    print(f"flash.py: flashing via serial DFU on {port} ...")
    result = subprocess.run(
        [nrfutil, "--verbose", "dfu", "serial",
         "-pkg", zip_path,
         "-p", port,
         "-b", "115200"],
    )
    return result.returncode


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Convert an ELF to UF2 and optionally drop on a bootloader volume.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("elf", help="path to the input ELF binary")
    parser.add_argument(
        "--board",
        choices=sorted(BOARDS.keys()),
        metavar="NAME",
        help="board preset name. Sets --base, --family, and the default "
        "--copy-to path. Supported: " + ", ".join(sorted(BOARDS.keys())),
    )
    parser.add_argument(
        "--base",
        type=parse_int,
        metavar="ADDR",
        help="flash base address (overrides --board, required if no --board)",
    )
    parser.add_argument(
        "--family",
        type=parse_int,
        metavar="ID",
        help="UF2 family ID (overrides --board, required if no --board)",
    )
    parser.add_argument(
        "--out",
        metavar="PATH",
        help="output UF2 path (default: <elf>.uf2)",
    )
    parser.add_argument(
        "--copy-to",
        metavar="PATH",
        help="after writing --out, also copy it to this path (typically a "
        "mounted bootloader drive, e.g. /Volumes/TECHOBOOT)",
    )
    parser.add_argument(
        "--copy-default",
        action="store_true",
        help="copy to the board preset's default mount path; ignored if "
        "--copy-to is also given",
    )
    parser.add_argument(
        "--serial-dfu",
        metavar="PORT",
        help="instead of producing a UF2, flash the ELF over serial DFU at "
        "PORT (e.g. /dev/tty.usbmodem1101). Uses arm-none-eabi-objcopy + "
        "adafruit-nrfutil; both must be installed. Useful when the "
        "bootloader exposes only serial DFU (e.g. T1000-E button-held entry).",
    )
    parser.add_argument(
        "--objcopy",
        default=DEFAULT_OBJCOPY,
        metavar="CMD",
        help=f"objcopy binary to invoke (default: {DEFAULT_OBJCOPY})",
    )
    args = parser.parse_args(argv)

    # Resolve board preset → base, family, default mount.
    preset = BOARDS.get(args.board) if args.board else None
    base = args.base if args.base is not None else (preset["base"] if preset else None)
    family = args.family if args.family is not None else (preset["family"] if preset else None)
    if base is None or family is None:
        parser.error("must specify --board, or both --base and --family")

    copy_to = args.copy_to
    if copy_to is None and args.copy_default:
        if preset is None:
            parser.error("--copy-default requires --board")
        copy_to = preset["mount"]

    if not os.path.isfile(args.elf):
        print(f"flash.py: not a file: {args.elf}", file=sys.stderr)
        return 1

    if args.serial_dfu:
        return flash_serial_dfu(args.elf, args.serial_dfu, args.objcopy)

    out_path = args.out or args.elf + ".uf2"

    print(f"flash.py: extracting flash image via {args.objcopy} ...")
    bin_bytes = elf_to_bin(args.elf, args.objcopy)
    print(f"flash.py: flash image = {len(bin_bytes)} bytes "
          f"({len(bin_bytes) / 1024:.1f} KiB)")

    uf2 = pack_uf2(bin_bytes, base, family)
    n_blocks = len(uf2) // UF2_BLOCK_BYTES
    label = f" ({preset['description']})" if preset else ""
    print(f"flash.py: packed {n_blocks} UF2 blocks "
          f"(base = 0x{base:08X}, family = 0x{family:08X}){label}")

    with open(out_path, "wb") as fh:
        fh.write(uf2)
    print(f"flash.py: wrote {out_path}")

    if copy_to:
        dest = copy_to
        if not os.path.exists(dest):
            print(f"flash.py: bootloader volume not mounted: {dest}", file=sys.stderr)
            print(f"flash.py: put the device in DFU mode (1200-baud reset, "
                  f"double-tap reset, or hold boot button while plugging in) "
                  f"and rerun.", file=sys.stderr)
            return 1
        if os.path.isdir(dest):
            dest = os.path.join(dest, os.path.basename(out_path))
        # The bootloader unmounts the volume as soon as the last block lands,
        # so copyfile() may finish (or appear to fail) before final metadata
        # syncs. Treat "device disappeared mid-copy" as success.
        try:
            shutil.copyfile(out_path, dest)
            print(f"flash.py: copied to {dest}")
        except OSError as exc:
            # macOS reports "Device not configured" when the UF2 bootloader
            # disconnects USB mid-copy after the final block. The flash
            # itself has already succeeded by that point.
            msg = str(exc).lower()
            if "device not configured" in msg or "no such file" in msg:
                print(f"flash.py: copied to {dest} (bootloader unmounted "
                      f"mid-copy; this is normal — flash succeeded)")
            else:
                raise

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
