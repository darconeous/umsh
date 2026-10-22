#!/usr/bin/env python3
"""Write the open-source crates in the communicator images, by license.

Device › About › Credits shows the list the firmware build reads, which is
committed: `crates/umsh-ux-communicator/crates.txt`. Each line is a license
expression, a colon, and the crates under it:

    MIT OR Apache-2.0: aead, aes, ...

The crates are what `cargo tree` says each image links (no build scripts,
no proc macros), in every communicator image, by name. UMSH's own crates
are left out: the UMSH entry covers them.

usage: crate_notices.py [--check]

--check exits 1 when the committed list is not what this would write.
Needs the `esp` toolchain, as building the images does.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGES = ("tlora-pager", "tdeck")
TARGET = "xtensa-esp32s3-none-elf"
OUT = ROOT / "crates" / "umsh-ux-communicator" / "crates.txt"

# Crates whose manifest names a license file rather than an expression:
# what the file says.
LICENSE_FILES = {
    # The crate is MIT OR Apache-2.0; its fonts come from U8g2.
    "u8g2-fonts": "(MIT OR Apache-2.0) AND LicenseRef-U8g2",
}

# Licenses first in a choice, as most crates give them.
FIRST = ("MIT", "Apache-2.0")

LINE = re.compile(r"^(?P<name>\S+) v\S+(?P<source> \(.*\))?\|(?P<license>.*?)(?: \(\*\))?$")


def linked(image):
    """The (name, source, license) of every crate `image` links."""
    out = subprocess.run(
        [
            "cargo",
            "tree",
            "--target",
            TARGET,
            "--edges",
            "normal,no-proc-macro",
            "--prefix",
            "none",
            "--format",
            "{p}|{l}",
        ],
        cwd=ROOT / "firmware-esp32" / "firmware" / image,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for line in out.splitlines():
        m = LINE.match(line)
        if not m:
            raise SystemExit(f"crate_notices: unexpected `cargo tree` line: {line!r}")
        yield m["name"], (m["source"] or "").strip(" ()"), m["license"].strip()


def canonical(expression):
    """`expression` with `/` read as OR and a choice's terms in one order."""
    terms = [t.strip() for t in re.split(r"\s+OR\s+|/", expression)]
    if any(" " in t or "(" in t for t in terms):
        return expression
    rank = {t: i for i, t in enumerate(FIRST)}
    terms.sort(key=lambda t: (rank.get(t, len(FIRST)), t))
    return " OR ".join(terms)


def notices():
    licenses = {}
    for image in IMAGES:
        for name, source, license in linked(image):
            # A path source is this repository's own.
            if source.startswith("/"):
                continue
            license = license or LICENSE_FILES.get(name)
            if not license:
                raise SystemExit(f"crate_notices: {name} names no license; add it to LICENSE_FILES")
            licenses.setdefault(canonical(license), set()).add(name)
    # Most crates first, then by license.
    groups = sorted(licenses.items(), key=lambda g: (-len(g[1]), g[0]))
    return "".join(f"{license}: {', '.join(sorted(names))}\n" for license, names in groups)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", action="store_true", help="fail if the committed list is stale")
    args = parser.parse_args()
    text = notices()
    if args.check:
        if not OUT.exists() or OUT.read_text() != text:
            print(f"{OUT.relative_to(ROOT)} is stale: run `make crate-notices`", file=sys.stderr)
            return 1
        return 0
    OUT.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
