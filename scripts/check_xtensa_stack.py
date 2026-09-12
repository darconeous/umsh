#!/usr/bin/env python3
"""Reject Xtensa function frames that alone exceed the linked main stack.

This is a necessary budget check, not a call-graph or RTOS-task stack proof.
Nested calls, interrupts, and radio task stacks still need hardware measurement.
Uses the objdump shipped with the ESP toolchain; no Python dependencies.
"""

import argparse
import re
import subprocess


def stack_size(symbols):
    bounds = {}
    for line in symbols.splitlines():
        fields = line.split()
        if fields and fields[-1] in ("_stack_start", "_stack_end"):
            bounds[fields[-1]] = int(fields[0], 16)
    return bounds["_stack_start"] - bounds["_stack_end"]


def function_frames(disassembly):
    """Read both ENTRY-immediate and the large-frame MOVSP prologue."""
    for block in re.split(r"\n(?=[0-9a-f]+ <)", disassembly):
        lines = block.splitlines()
        if not lines or not re.fullmatch(r"[0-9a-f]+ <.+>:", lines[0]):
            continue
        size = None
        # Large frames exceed ENTRY's immediate range. LLVM emits ENTRY
        # for the register window, then L32R/SUB/MOVSP for the remainder.
        literal = None
        decrement = None
        for line in lines[1:9]:
            entry = re.search(r"\bentry\s+a1,\s*(0x[0-9a-f]+|[0-9]+)", line)
            if entry:
                size = int(entry[1], 0)
            load = re.search(r"\bl32r\s+(a\d+),.*\(([0-9a-f]+) <", line)
            if load:
                literal = (load[1], int(load[2], 16))
            sub = re.search(r"\bsub\s+(a\d+),\s*a1,\s*(a\d+)", line)
            if sub and literal and sub[2] == literal[0]:
                decrement = (sub[1], literal[1])
            move = re.search(r"\bmovsp\s+a1,\s*(a\d+)", line)
            if move:
                if size is None or decrement is None or move[1] != decrement[0]:
                    raise ValueError(f"unrecognized stack prologue: {lines[0]}")
                size += decrement[1]
                break
        if size is not None:
            yield lines[0], size


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf")
    parser.add_argument("--objdump", default="xtensa-esp32s3-elf-objdump")
    parser.add_argument("--reserve", type=int, default=8192,
                        help="minimum space left beyond any single frame (default: 8192)")
    args = parser.parse_args()
    symbols = subprocess.check_output([args.objdump, "-t", args.elf], text=True)
    disassembly = subprocess.check_output([args.objdump, "-d", "-C", args.elf], text=True)
    available = stack_size(symbols)
    frames = list(function_frames(disassembly))
    if not frames:
        raise SystemExit("stack check: no Xtensa function prologues found")
    failures = [(name, size) for name, size in frames if size + args.reserve > available]
    if failures:
        for name, size in failures:
            print(f"stack check FAILED: {size} byte frame + {args.reserve} reserve > "
                  f"{available} byte main stack: {name}")
        raise SystemExit(1)
    print(f"stack check: main stack {available} bytes; "
          f"largest individual frame {max(size for _, size in frames)} bytes; "
          f"reserve {args.reserve} bytes")


if __name__ == "__main__":
    main()
