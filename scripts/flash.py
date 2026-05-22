#!/usr/bin/env python3
"""
Convert an embedded ELF to the Microsoft UF2 file format and
optionally drop it onto a mounted UF2-bootloader mass-storage volume
(e.g. /Volumes/TECHOBOOT for the LilyGO T-Echo).

This is intentionally a single self-contained script with no
third-party Python dependencies: it shells out to a host
`*-objcopy` (defaults to `arm-none-eabi-objcopy`) for the ELF→bin
step and then packs the bin into UF2 blocks in pure Python.

The UF2 layout is documented at https://github.com/microsoft/uf2.
For nRF52840 with the Adafruit UF2 bootloader, the family ID is
0xADA52840 and the application flash region begins at 0x00026000
(after the reserved S140 SoftDevice slot).

Examples
--------

  # Convert only:
  scripts/flash.py target/thumbv7em-none-eabihf/release/firmware-hello-techo

  # Convert and copy to a mounted bootloader drive:
  scripts/flash.py target/thumbv7em-none-eabihf/release/firmware-hello-techo \\
      --copy-to /Volumes/TECHOBOOT
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
DEFAULT_BASE_ADDR = 0x00026000        # nRF52840 with S140 reserved
DEFAULT_FAMILY_ID = 0xADA52840        # Adafruit nRF52840


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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Convert an ELF to UF2 and optionally drop on a bootloader volume.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("elf", help="path to the input ELF binary")
    parser.add_argument(
        "--base",
        type=parse_int,
        default=DEFAULT_BASE_ADDR,
        metavar="ADDR",
        help=f"flash base address (default: 0x{DEFAULT_BASE_ADDR:08X})",
    )
    parser.add_argument(
        "--family",
        type=parse_int,
        default=DEFAULT_FAMILY_ID,
        metavar="ID",
        help=f"UF2 family ID (default: 0x{DEFAULT_FAMILY_ID:08X})",
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
        "--objcopy",
        default=DEFAULT_OBJCOPY,
        metavar="CMD",
        help=f"objcopy binary to invoke (default: {DEFAULT_OBJCOPY})",
    )
    args = parser.parse_args(argv)

    if not os.path.isfile(args.elf):
        print(f"flash.py: not a file: {args.elf}", file=sys.stderr)
        return 1

    out_path = args.out or args.elf + ".uf2"

    print(f"flash.py: extracting flash image via {args.objcopy} ...")
    bin_bytes = elf_to_bin(args.elf, args.objcopy)
    print(f"flash.py: flash image = {len(bin_bytes)} bytes "
          f"({len(bin_bytes) / 1024:.1f} KiB)")

    uf2 = pack_uf2(bin_bytes, args.base, args.family)
    n_blocks = len(uf2) // UF2_BLOCK_BYTES
    print(f"flash.py: packed {n_blocks} UF2 blocks "
          f"(base = 0x{args.base:08X}, family = 0x{args.family:08X})")

    with open(out_path, "wb") as fh:
        fh.write(uf2)
    print(f"flash.py: wrote {out_path}")

    if args.copy_to:
        dest = args.copy_to
        if os.path.isdir(dest):
            dest = os.path.join(dest, os.path.basename(out_path))
        shutil.copyfile(out_path, dest)
        print(f"flash.py: copied to {dest}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
