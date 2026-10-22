#!/usr/bin/env python3
"""Generate the splash logos beside this script.

Host-only; needs Pillow. Firmware builds include the finished bytes and
need no image tools. Run from anywhere:

    python3 crates/umsh-splash/assets/generate.py

The format is described in README.md next to this file.
"""

from pathlib import Path

from PIL import Image

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
LOGO = ROOT / "docs/logo/umsh-logo-orange-noshadow.png"
# The logo's widths. Each leaves about 2.7 mm clear at either side of its
# panel: 24 px of the Pager's 480, 16 px of the T-Deck's 320.
LOGO_WIDTHS = (432, 288)
LEVELS = 16
# The source is a paletted PNG whose fill wobbles between about 228 and 254
# alpha; its edges ramp up from far below. Alpha from here up is the fill.
SOLID = 220


def level(alpha):
    """Eight-bit coverage rounded to one of LEVELS."""
    return (alpha * (LEVELS - 1) + 127) // 255


def logo(width):
    """The logo's alpha at `width`, run-length coded a level at a time."""
    source = Image.open(LOGO).convert("RGBA").getchannel("A")
    source = source.point(lambda alpha: 255 if alpha >= SOLID else alpha)
    height = round(source.height * width / source.width)
    coverage = source.resize((width, height), Image.Resampling.LANCZOS)
    levels = [level(alpha) for alpha in coverage.getdata()]
    out = bytearray(width.to_bytes(2, "big") + height.to_bytes(2, "big"))
    i = 0
    while i < len(levels):
        value = levels[i]
        run = 1
        while i + run < len(levels) and levels[i + run] == value and run < 271:
            run += 1
        if run < 16:
            out.append(value << 4 | run)
        else:
            out.append(value << 4)
            out.append(run - 16)
        i += run
    path = HERE / f"umsh-{width}x{height}.rle"
    path.write_bytes(out)
    print(f"{path.name}: {width}x{height}, {len(out)} bytes")


def main():
    for width in LOGO_WIDTHS:
        logo(width)


if __name__ == "__main__":
    main()
