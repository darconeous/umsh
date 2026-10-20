#!/usr/bin/env python3
"""Reject oversized Xtensa frames and the known device-task construction chain.

This is a necessary budget check, not a call-graph or RTOS-task stack proof.
Nested calls, interrupts, and radio task stacks still need hardware measurement.
Uses the objdump shipped with the ESP toolchain; no Python dependencies.
"""

import argparse
import re
import subprocess

HEADER = re.compile(r"[0-9a-f]+ <(.+)>:")
ENTRY = re.compile(r"\bentry\s+a1,\s*(0x[0-9a-f]+|[0-9]+)")
LOAD = re.compile(r"\bl32r\s+(a\d+),.*\(([0-9a-f]+) <")
SUB = re.compile(r"\bsub\s+(a\d+),\s*a1,\s*(a\d+)")
MOVSP = re.compile(r"\bmovsp\s+a1,\s*(a\d+)")
# How far into a function its prologue reaches.
PROLOGUE_LINES = 8


def stack_size(symbols):
    bounds = {}
    for line in symbols.splitlines():
        fields = line.split()
        if fields and fields[-1] in ("_stack_start", "_stack_end"):
            bounds[fields[-1]] = int(fields[0], 16)
    return bounds["_stack_start"] - bounds["_stack_end"]


def prologue_frame(name, lines):
    """Read both ENTRY-immediate and the large-frame MOVSP prologue."""
    size = None
    # Large frames exceed ENTRY's immediate range. LLVM emits ENTRY
    # for the register window, then L32R/SUB/MOVSP for the remainder.
    literal = None
    decrement = None
    for line in lines:
        entry = ENTRY.search(line)
        if entry:
            size = int(entry[1], 0)
        load = LOAD.search(line)
        if load:
            literal = (load[1], int(load[2], 16))
        sub = SUB.search(line)
        if sub and literal and sub[2] == literal[0]:
            decrement = (sub[1], literal[1])
        move = MOVSP.search(line)
        if move:
            if size is None or decrement is None or move[1] != decrement[0]:
                raise ValueError(f"unrecognized stack prologue: <{name}>")
            size += decrement[1]
            break
    return size


def function_frames(lines):
    """Each function's frame, as `(mangled name, size)`, from objdump's
    disassembly read a line at a time: only a prologue is kept, so memory
    stays flat however large the program."""
    name = None
    prologue = []
    for line in lines:
        header = HEADER.fullmatch(line.rstrip("\n"))
        if header:
            if name is not None:
                size = prologue_frame(name, prologue)
                if size is not None:
                    yield name, size
            name = header[1]
            prologue = []
        elif name is not None and len(prologue) < PROLOGUE_LINES:
            prologue.append(line)
    if name is not None:
        size = prologue_frame(name, prologue)
        if size is not None:
            yield name, size


def demangle(cxxfilt, names):
    """`names` demangled, without crate disambiguators. Mangled names stay
    short however deep the generics run; demangled, they spell every type
    out, so only names that are matched or reported are demangled."""
    if not names:
        return {}
    out = subprocess.run([cxxfilt, "-i"], input="\n".join(names) + "\n",
                         capture_output=True, text=True, check=True).stdout
    return dict(zip(names, out.splitlines()))


def device_task_construction(frames):
    """Conservative lower bound for main -> device_task -> future initializer.

    Embassy's generated constructor can copy the large boot snapshot while its
    initializer materializes the entire future. If LLVM keeps the constructor
    out of line, all three frames coexist. Single-frame-plus-reserve checking
    missed this on T-Beam. An inlined stage has no separate frame to add.
    This intentionally checks our known startup path, not a general call graph.
    """
    main = []
    constructor = []
    initializer = []
    for name, size in frames:
        if re.fullmatch(r"firmware_\w+::__main::____embassy_main_task::"
                        r"____embassy_main_task_inner_function::\{closure#0\}", name):
            main.append((name, size))
        elif re.fullmatch(r"firmware_\w+::device_task", name):
            constructor.append((name, size))
        elif ("UninitCell<" in name and "::__device_task_task::" in name
              and "::write_in_place::<" in name):
            initializer.append((name, size))
    if not main:
        return []
    return [max(stage, key=lambda frame: frame[1])
            for stage in (main, constructor, initializer) if stage]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf")
    parser.add_argument("--objdump", default="xtensa-esp32s3-elf-objdump")
    parser.add_argument("--cxxfilt", default=None,
                        help="demangler (default: objdump's sibling c++filt)")
    parser.add_argument("--reserve", type=int, default=8192,
                        help="minimum space left beyond any single frame (default: 8192)")
    args = parser.parse_args()
    cxxfilt = args.cxxfilt or re.sub(r"objdump$", "c++filt", args.objdump)
    symbols = subprocess.check_output([args.objdump, "-t", args.elf], text=True)
    available = stack_size(symbols)
    with subprocess.Popen([args.objdump, "-d", "--no-show-raw-insn", args.elf],
                          stdout=subprocess.PIPE, text=True) as objdump:
        frames = list(function_frames(objdump.stdout))
    if objdump.returncode:
        raise SystemExit(f"stack check: {args.objdump} failed")
    if not frames:
        raise SystemExit("stack check: no Xtensa function prologues found")
    # Only the startup path's stages and what fails are named; identifiers
    # appear whole in mangled names, so the candidates are found unmangled.
    failing = [(name, size) for name, size in frames if size + args.reserve > available]
    candidates = [(name, size) for name, size in frames
                  if "device_task" in name or "embassy_main_task" in name]
    names = demangle(cxxfilt, sorted({name for name, _ in failing + candidates}))
    failures = [(names[name], size) for name, size in failing]
    construction = device_task_construction(
        [(names[name], size) for name, size in candidates])
    construction_size = sum(size for _, size in construction)
    if construction_size > available:
        print(f"stack check FAILED: device task construction needs at least "
              f"{construction_size} bytes > {available} byte main stack")
        for name, size in construction:
            print(f"  {size} bytes: {name}")
        raise SystemExit(1)
    if failures:
        for name, size in failures:
            print(f"stack check FAILED: {size} byte frame + {args.reserve} reserve > "
                  f"{available} byte main stack: {name}")
        raise SystemExit(1)
    print(f"stack check: main stack {available} bytes; "
          f"largest individual frame {max(size for _, size in frames)} bytes; "
          f"reserve {args.reserve} bytes")
    if construction:
        print(f"stack check: device task construction lower bound "
              f"{construction_size} bytes; {available - construction_size} bytes "
              "remain for callers, interrupts, and other nested work")


if __name__ == "__main__":
    main()
