#!/usr/bin/env python3
"""
Copy a built UF2 onto a mounted bootloader volume.

That is the whole job. Building the image is scripts/mkimage.py, run by
`make build-<board>`; serial DFU is adafruit-nrfutil, called directly
from the Makefile. This exists because neither of those can put a UF2 on
a mass-storage bootloader, and because `cp` gets it wrong:

  * The board preset knows where each bootloader mounts, so callers name
    a board rather than remembering "/Volumes/TRACKER L1".
  * The bootloader drops off the USB bus the instant the final block
    lands, before the copy returns. macOS surfaces that as "Device not
    configured" or EIO, so a plain `cp` reports a flash that in fact
    succeeded as a failure. Distinguishing the two is the reason this is
    a script and not a one-line shell command.

  scripts/flash.py --board t1000e --copy-default \\
      target/thumbv7em-none-eabihf/release/firmware-t1000e.uf2

  scripts/flash.py --copy-to "/Volumes/XIAO-BOOT" \\
      target/thumbv7em-none-eabihf/release/firmware-xiao-nrf52.uf2

Board presets live in scripts/firmware_image.py.
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time

from firmware_image import BOARDS, add_board_args


def copy_to_volume(uf2_path: str, copy_to: str) -> int:
    """Copy a UF2 onto a mounted bootloader volume."""
    dest = copy_to
    if not os.path.exists(dest):
        print(f"flash.py: bootloader volume not mounted: {dest}", file=sys.stderr)
        print(f"flash.py: put the device in DFU mode (1200-baud reset, "
              f"double-tap reset, or the board's button gesture) "
              f"and rerun.", file=sys.stderr)
        return 1
    if os.path.isdir(dest):
        dest = os.path.join(dest, os.path.basename(uf2_path))
    # The bootloader unmounts the volume as soon as the last block lands,
    # so copyfile() may finish (or appear to fail) before final metadata
    # syncs. Treat "device disappeared mid-copy" as success.
    try:
        shutil.copyfile(uf2_path, dest)
        print(f"flash.py: copied to {dest}")
    except OSError as exc:
        # macOS reports "Device not configured" when the UF2 bootloader
        # disconnects USB mid-copy after the final block. The flash
        # itself has already succeeded by that point.
        msg = str(exc).lower()
        if "device not configured" in msg or "no such file" in msg:
            print(f"flash.py: copied to {dest} (bootloader unmounted "
                  f"mid-copy; this is normal — flash succeeded)")
        elif "input/output error" in msg:
            # EIO is ambiguous: it is what in-flight writes get when
            # the bootloader detaches after the final block, but it is
            # also what a genuinely failed partial copy produces. The
            # volume disappearing shortly afterwards is the success
            # signal — the bootloader only exits DFU on a complete UF2.
            mount_root = copy_to if os.path.isdir(copy_to) else os.path.dirname(dest)
            for _ in range(10):
                if not os.path.exists(mount_root):
                    break
                time.sleep(0.5)
            if os.path.exists(mount_root):
                print(f"flash.py: copy failed: {exc}", file=sys.stderr)
                return 1
            print(f"flash.py: copied to {dest} (bootloader unmounted "
                  f"mid-copy; this is normal — flash succeeded)")
        else:
            print(f"flash.py: copy failed: {exc}", file=sys.stderr)
            return 1
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Copy a built UF2 onto a mounted bootloader volume.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("uf2", help="the .uf2 to copy, from `make build-<board>`")
    add_board_args(parser)
    parser.add_argument(
        "--copy-to",
        metavar="PATH",
        help="copy the UF2 here (a mounted bootloader drive, e.g. "
        "/Volumes/TECHOBOOT)",
    )
    parser.add_argument(
        "--copy-default",
        action="store_true",
        help="copy to the board preset's default mount path; ignored if "
        "--copy-to is also given",
    )
    args = parser.parse_args(argv)

    preset = BOARDS.get(args.board) if args.board else None

    copy_to = args.copy_to
    if copy_to is None and args.copy_default:
        if preset is None:
            parser.error("--copy-default requires --board")
        copy_to = preset["mount"]
    if copy_to is None:
        parser.error("nothing to do: pass --copy-to or --copy-default")

    if not args.uf2.endswith(".uf2"):
        parser.error(
            "expected a .uf2 — this script does not convert anything. "
            "Run `make build-<board>`, or scripts/mkimage.py directly."
        )
    if not os.path.isfile(args.uf2):
        print(f"flash.py: not a file: {args.uf2}", file=sys.stderr)
        print("flash.py: build it first with `make build-<board>`.",
              file=sys.stderr)
        return 1

    return copy_to_volume(args.uf2, copy_to)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
