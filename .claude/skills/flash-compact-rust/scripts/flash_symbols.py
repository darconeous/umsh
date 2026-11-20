#!/usr/bin/env python3
"""Attribute flash in a firmware ELF by symbol.

  flash_symbols.py top  ELF [N]       the N largest code and read-only symbols
  flash_symbols.py dups ELF [N]       functions instantiated more than once
  flash_symbols.py diff OLD NEW [N]   per-symbol growth and shrinkage, and the net

ELF may also be a saved `arm-none-eabi-nm -S -C` listing, so a baseline
can be kept after the target directory moves on. Stdlib only.
"""

import collections
import re
import subprocess
import sys

NM = "arm-none-eabi-nm"
HASH = re.compile(r"::h[0-9a-f]{16}$")


def symbols(path):
    """Size per demangled name, for text and read-only data."""
    try:
        with open(path, "rb") as f:
            is_elf = f.read(4) == b"\x7fELF"
    except OSError as e:
        sys.exit(f"{path}: {e}")
    if is_elf:
        lines = subprocess.run(
            [NM, "-S", "--size-sort", "-C", path],
            check=True, capture_output=True, text=True,
        ).stdout.splitlines()
    else:
        with open(path) as f:
            lines = f.read().splitlines()
    sizes = collections.Counter()
    for line in lines:
        fields = line.split(None, 3)
        if len(fields) == 4 and fields[2] in "tTrR":
            sizes[HASH.sub("", fields[3].strip())] += int(fields[1], 16)
    return sizes


def short(name, width=160):
    return name if len(name) <= width else name[: width - 1] + "…"


def strip_arguments(text):
    """`text` with every `<…>` argument list removed."""
    out, depth = [], 0
    for ch in text:
        if ch == "<":
            depth += 1
        elif ch == ">" and depth:
            depth -= 1
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def generic_free(name):
    """The function `name` instantiates, without its generic arguments.

    A leading `<Type as Trait>` or `<Type>` keeps its paths, so methods of
    different types stay apart and only their arguments are dropped.
    """
    if not name.startswith("<"):
        return strip_arguments(name)
    depth = 0
    for i, ch in enumerate(name):
        depth += {"<": 1, ">": -1}.get(ch, 0)
        if depth == 0:
            return "<" + strip_arguments(name[1:i]) + ">" + strip_arguments(name[i + 1 :])
    return strip_arguments(name)


def top(path, n):
    sizes = symbols(path)
    for name, size in sizes.most_common(n):
        print(f"{size:8d}  {short(name)}")
    print(f"{sum(sizes.values()):8d}  total")


def dups(path, n):
    groups = collections.defaultdict(list)
    for name, size in symbols(path).items():
        if name.startswith("OUTLINED_FUNCTION") or "drop_glue" in name:
            continue
        groups[generic_free(name)].append(size)
    rows = [(sum(s), len(s), k) for k, s in groups.items() if len(s) > 1]
    rows.sort(reverse=True)
    print("   total  copies  function (generic arguments removed)")
    for total, count, name in rows[:n]:
        print(f"{total:8d}  {count:6d}  {short(name, 140)}")


def diff(old, new, n):
    a, b = symbols(old), symbols(new)
    rows = sorted((b[k] - a[k], k) for k in a.keys() | b.keys() if a[k] != b[k])
    for delta, name in rows[:n]:
        print(f"{delta:+8d}  {short(name)}")
    if len(rows) > 2 * n:
        print("     ...")
    for delta, name in rows[max(n, len(rows) - n):]:
        print(f"{delta:+8d}  {short(name)}")
    print(f"{sum(d for d, _ in rows):+8d}  net (symbols only; check `arm-none-eabi-size` too)")


def main(argv):
    if len(argv) < 3 or argv[1] not in ("top", "dups", "diff"):
        sys.exit(__doc__)
    if argv[1] == "diff":
        if len(argv) < 4:
            sys.exit(__doc__)
        diff(argv[2], argv[3], int(argv[4]) if len(argv) > 4 else 15)
    else:
        n = int(argv[3]) if len(argv) > 3 else 30
        (top if argv[1] == "top" else dups)(argv[2], n)


if __name__ == "__main__":
    main(sys.argv)
