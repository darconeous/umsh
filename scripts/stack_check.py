#!/usr/bin/env python3
"""
Check that an embassy firmware's startup fits in its stack.

Spawning an embassy task writes the task's future into its pool with
`UninitCell::write_in_place`, and the compiler builds that whole future
on the stack first, then copies it. Every spawn happens inside the main
task, so the deepest point of startup is the main task's frame plus the
largest of those `write_in_place` frames. A stack that cannot hold that
grows down into the statics below it and corrupts them silently: the
image boots into whatever the overwritten memory breaks.

The frames are read from the `sub sp, #imm` instructions in each
function, which is how the compiler reserves them on thumbv7em. Like
mkimage.py, this reads the ELF itself and needs nothing but Python.

  scripts/stack_check.py target/thumbv7em-none-eabihf/release/firmware-techo
"""

from __future__ import annotations

import argparse
import struct
import sys

SHT_SYMTAB = 2
STT_FUNC = 2

# Kept free beyond the measured frames, for the functions those frames
# call and for interrupts taken on the same stack.
DEFAULT_RESERVE = 4 * 1024

MAIN_TASK = b"____embassy_main_task_inner_function"
SPAWN = (b"10UninitCell", b"14write_in_place")


def elf_symbols(data: bytes):
    """Yield (name, value, size, type) for every symbol in the ELF."""
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise ValueError("not a 32-bit little-endian ELF")
    shoff = struct.unpack_from("<I", data, 0x20)[0]
    shentsize, shnum = struct.unpack_from("<HH", data, 0x2E)
    sections = [
        struct.unpack_from("<10I", data, shoff + i * shentsize) for i in range(shnum)
    ]
    for (_name, sh_type, _flags, _addr, sh_off, sh_size,
         sh_link, _info, _align, sh_entsize) in sections:
        if sh_type != SHT_SYMTAB:
            continue
        strtab_off = sections[sh_link][4]
        for off in range(sh_off, sh_off + sh_size, sh_entsize):
            st_name, st_value, st_size, st_info = struct.unpack_from("<IIIB", data, off)
            end = data.index(b"\0", strtab_off + st_name)
            yield data[strtab_off + st_name:end], st_value, st_size, st_info & 0xF


def code_at(data: bytes, addr: int, size: int) -> bytes:
    """The bytes of `size` at link address `addr`, from its section."""
    shoff = struct.unpack_from("<I", data, 0x20)[0]
    shentsize, shnum = struct.unpack_from("<HH", data, 0x2E)
    for i in range(shnum):
        (_name, _type, _flags, sh_addr, sh_off, sh_size,
         *_rest) = struct.unpack_from("<10I", data, shoff + i * shentsize)
        if sh_addr <= addr and addr + size <= sh_addr + sh_size and sh_addr:
            return data[sh_off + addr - sh_addr:sh_off + addr - sh_addr + size]
    return b""


def thumb_expand_imm(imm12: int) -> int:
    """ThumbExpandImm from the ARMv7-M architecture manual."""
    if imm12 >> 10 == 0:
        byte = imm12 & 0xFF
        return [byte, byte * 0x00010001, byte * 0x01000100, byte * 0x01010101][(imm12 >> 8) & 3]
    value = 0x80 | (imm12 & 0x7F)
    rotate = imm12 >> 7
    return ((value >> rotate) | (value << (32 - rotate))) & 0xFFFFFFFF


def frame_bytes(code: bytes) -> int:
    """Total of the `sub sp, #imm` reservations in a function's code."""
    total = 0
    i = 0
    while i + 2 <= len(code):
        hw1 = struct.unpack_from("<H", code, i)[0]
        if hw1 >> 11 in (0b11101, 0b11110, 0b11111) and i + 4 <= len(code):
            hw2 = struct.unpack_from("<H", code, i + 2)[0]
            i_bit, imm3, imm8 = (hw1 >> 10) & 1, (hw2 >> 12) & 7, hw2 & 0xFF
            rd = (hw2 >> 8) & 0xF
            # SUB.W SP, SP, #<modified immediate> (T2), S clear.
            if hw1 & 0xFBFF == 0xF1AD and hw2 & 0x8000 == 0 and rd == 13:
                total += thumb_expand_imm(i_bit << 11 | imm3 << 8 | imm8)
            # SUBW SP, SP, #<imm12> (T3).
            elif hw1 & 0xFBFF == 0xF2AD and hw2 & 0x8000 == 0 and rd == 13:
                total += i_bit << 11 | imm3 << 8 | imm8
            i += 4
            continue
        # SUB SP, SP, #<imm7 * 4> (T1).
        if hw1 & 0xFF80 == 0xB080:
            total += (hw1 & 0x7F) * 4
        i += 2
    return total


def check(elf_path: str, reserve: int = DEFAULT_RESERVE) -> tuple[bool, str]:
    """Return (fits, report) for the image at `elf_path`."""
    with open(elf_path, "rb") as fh:
        data = fh.read()
    stack_start = stack_end = None
    main_frame, spawn_frame, spawn_name = 0, 0, b""
    for name, value, size, kind in elf_symbols(data):
        if name == b"_stack_start":
            stack_start = value
        elif name == b"_stack_end":
            stack_end = value
        elif kind == STT_FUNC and size:
            is_spawn = all(part in name for part in SPAWN)
            if not is_spawn and MAIN_TASK not in name:
                continue
            frame = frame_bytes(code_at(data, value & ~1, size))
            if is_spawn and frame > spawn_frame:
                spawn_frame, spawn_name = frame, name
            elif not is_spawn:
                main_frame = max(main_frame, frame)
    if stack_start is None or stack_end is None or not main_frame:
        return True, f"{elf_path}: no embassy main task or stack bounds; not checked"
    stack = stack_start - stack_end
    peak = main_frame + spawn_frame
    # `…___device_task_task_inner_function…` names the `device_task` spawn.
    task = spawn_name.split(b"_task_inner_function")[0].rsplit(b"___", 1)[-1]
    task = task.decode(errors="replace") or "?"
    report = (
        f"stack {stack} B; startup peak {peak} B (main task {main_frame} B + "
        f"spawning {task} {spawn_frame} B); margin {stack - peak} B, "
        f"{reserve} B required"
    )
    return stack - peak >= reserve, report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("elf", nargs="+", help="firmware ELF")
    parser.add_argument("--reserve", type=int, default=DEFAULT_RESERVE,
                        help=f"bytes to keep free (default {DEFAULT_RESERVE})")
    args = parser.parse_args(argv)
    failed = False
    for elf in args.elf:
        fits, report = check(elf, args.reserve)
        print(f"stack_check.py: {report}", file=sys.stderr if not fits else sys.stdout)
        failed |= not fits
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
