#!/usr/bin/env python3
"""
Convert a firmware ELF into the images a board can actually be flashed with.

This is a build step, not a flashing step: `make build-<board>` runs it
after `cargo build`, so the flashable artifacts sit next to the ELF ready
to be copied to a bootloader volume, attached to a release, or served to
the web flasher. scripts/flash.py only ever moves an image this produced
— it does no conversion of its own.

Needs nothing but Python: no objcopy, no cross-toolchain. Rust already
cross-compiles and links for the target on its own.

  # UF2, for the mass-storage bootloader (what every `make flash-*` uses):
  scripts/mkimage.py --board t1000e \\
      target/thumbv7em-none-eabihf/release/firmware-t1000e

  # ...and Intel HEX alongside it, for the serial-DFU path:
  scripts/mkimage.py --board t1000e --hex \\
      target/thumbv7em-none-eabihf/release/firmware-t1000e

Writes <elf>.uf2 and, with --hex, <elf>.hex. Board presets set the flash
base address and UF2 family ID; --base and --family override them for a
board without a preset.
"""

from __future__ import annotations

import argparse
import os
import sys

from firmware_image import (
    BOARDS,
    UF2_BLOCK_BYTES,
    add_board_args,
    elf_to_bin,
    elf_to_ihex,
    pack_uf2,
)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Convert a firmware ELF to its flashable images.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("elf", help="path to the input ELF binary")
    add_board_args(parser)
    parser.add_argument(
        "--out",
        metavar="PATH",
        help="output UF2 path (default: <elf>.uf2)",
    )
    parser.add_argument(
        "--hex",
        action="store_true",
        help="also write Intel HEX (<elf>.hex), which the serial-DFU path "
        "hands to adafruit-nrfutil",
    )
    args = parser.parse_args(argv)

    preset = BOARDS.get(args.board) if args.board else None
    base = args.base if args.base is not None else (preset["base"] if preset else None)
    family = args.family if args.family is not None else (preset["family"] if preset else None)
    if base is None or family is None:
        parser.error("must specify --board, or both --base and --family")

    if not os.path.isfile(args.elf):
        print(f"mkimage.py: not a file: {args.elf}", file=sys.stderr)
        return 1

    low, image = elf_to_bin(args.elf)
    if low != base:
        # The linker script and the board preset disagree about where the
        # application starts. Flashing this would put the image at the
        # wrong offset, so stop rather than produce a UF2 that lands in
        # the wrong place.
        print(f"mkimage.py: ELF loads at 0x{low:08X} but the --base for this "
              f"board is 0x{base:08X}. Check memory.x against the preset.",
              file=sys.stderr)
        return 1

    uf2 = pack_uf2(image, base, family)
    out_path = args.out or args.elf + ".uf2"
    with open(out_path, "wb") as fh:
        fh.write(uf2)

    label = f" ({preset['description']})" if preset else ""
    print(f"mkimage.py: {len(image)} bytes ({len(image) / 1024:.1f} KiB) → "
          f"{len(uf2) // UF2_BLOCK_BYTES} UF2 blocks at 0x{base:08X}, "
          f"family 0x{family:08X}{label}")
    print(f"mkimage.py: wrote {out_path}")

    if args.hex:
        hex_path = os.path.splitext(out_path)[0] + ".hex"
        with open(hex_path, "w") as fh:
            fh.write(elf_to_ihex(args.elf))
        print(f"mkimage.py: wrote {hex_path}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
