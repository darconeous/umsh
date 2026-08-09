#!/usr/bin/env python3
"""
Board presets and firmware image conversion, shared by mkuf2.py (build)
and flash.py (flash).

No third-party Python packages, and no external toolchain: the ELF is
read here rather than shelling out to `arm-none-eabi-objcopy`. Building
UMSH firmware needs a Rust toolchain and nothing else.

The UF2 layout is documented at https://github.com/microsoft/uf2.
"""

from __future__ import annotations

import struct

# ELF constants (32-bit little-endian; every board here is thumbv7em).
SHF_ALLOC = 0x2
SHT_NOBITS = 8
PT_LOAD = 1

# UF2 block layout.
UF2_MAGIC_START0 = 0x0A324655   # "UF2\n"
UF2_MAGIC_START1 = 0x9E5D5157   # randomly selected
UF2_MAGIC_END = 0x0AB16F30      # randomly selected
UF2_FLAG_FAMILY_ID = 0x00002000
UF2_PAYLOAD_BYTES = 256
UF2_BLOCK_BYTES = 512

# Board presets. Each entry has the flash base address (where the app
# starts, after MBR + SoftDevice), the UF2 family ID the bootloader
# accepts, and the typical macOS mount path for the bootloader volume.
#
# When changing these, also update:
#   * docs/firmware-plan-<board>.md (Phase 0 section)
#   * docs/<vendor>-<board>-hardware.md (bootloader / flash layout section)
#   * site/data/hardware.toml (the [boards.flash] table)
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
    "sensecap-solar": {
        # Confirmed Phase 0 against an in-hand P1-Pro's INFO_UF2.TXT +
        # CURRENT.UF2 (2026-07-23):
        #   Bootloader: UF2 Bootloader 0.9.2-OTAFIX2.2-BP1.3
        #   Model: Seeed Solar Node P1
        #   Board-ID: nRF52840-SeeedSenseCAPSolarP1-v1
        #   SoftDevice: S140 7.3.0  → app starts at 0x27000
        #   Family ID (from CURRENT.UF2): 0x28860044  ← NOT VID<<16|PID
        #   Bootloader volume name: SENSECAP
        "base":   0x00027000,        # S140 v7.3.0 reserves 156 KiB (confirmed)
        "family": 0x28860044,        # Seeed Solar Node P1 family (confirmed from CURRENT.UF2)
        "mount":  "/Volumes/SENSECAP",
        "description": "SenseCAP Solar Node P1 / P1-Pro",
    },
    "xiao-nrf52": {
        # Confirmed against an in-hand retail kit (2026-08-03) from
        # INFO_UF2.TXT + CURRENT.UF2, and by direct write probes:
        #   Bootloader: UF2 Bootloader 0.6.1 (Nov 12 2021)
        #   Board-ID: Seeed_XIAO_nRF52840_Sense   ← the *Sense* config,
        #             on plain XIAO nRF52840 hardware
        #   SoftDevice: S140 7.3.0  → app starts at 0x27000
        #   Board-specific family (from CURRENT.UF2): 0x28860045
        #   Bootloader volume name: XIAO-SENSE
        #
        # We pack with the GENERIC 0xADA52840 family, not the
        # board-specific 0x28860045. The 0.6.1 `write_block` accepts
        # either, and the generic one works whichever bootloader config a
        # given unit shipped with — which matters precisely because Seeed
        # ships the Sense config here, so a unit with the plain
        # `XIAO-BOOT` config (family 0x28860044, volume XIAO-BOOT) is also
        # plausible in the wild. Verified accepted by probe.
        #
        # A UF2 with the wrong family is SILENTLY IGNORED: the copy exits
        # 0 with no error and the volume stays mounted, indistinguishable
        # from a real flash. Our own `sensecap-solar` preset above was
        # tested against this kit and did exactly that. If a flash appears
        # to succeed but the board comes back running the old image, check
        # the family before anything else.
        "base":   0x00027000,        # S140 v7.3.0 reserves 156 KiB (confirmed)
        "family": 0xADA52840,        # generic nRF52840 — tolerates XIAO-BOOT and XIAO-SENSE
        # Retail units mount as XIAO-SENSE; a re-bootloadered unit may
        # mount as XIAO-BOOT instead, so --copy-default is less reliable
        # here than on the other boards. Use --copy-to with the volume you
        # actually see, or drag and drop.
        "mount":  "/Volumes/XIAO-SENSE",
        "description": "Seeed XIAO nRF52840 + Wio-SX1262 Kit",
    },
}


def parse_int(value: str) -> int:
    """Accept decimal, hex (0x...) or binary (0b...) literals."""
    return int(value, 0)


def add_board_args(parser) -> None:
    """Add the --board/--base/--family trio shared by both front ends."""
    parser.add_argument(
        "--board",
        choices=sorted(BOARDS.keys()),
        metavar="NAME",
        help="board preset name. Supported: " + ", ".join(sorted(BOARDS.keys())),
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


def elf_sections(data: bytes):
    """Yield (load_address, bytes) for every loadable section with content.

    This is what `objcopy -O binary` operates on: allocatable sections
    that occupy space in the file. Program headers are deliberately not
    used to select content — the first PT_LOAD on these images covers the
    ELF header itself, well below the application base, and emitting it
    would place junk over the SoftDevice. Segments are consulted only to
    translate a section's virtual address into its load address, which is
    what `.data` (running in RAM, stored in flash) depends on.
    """
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise ValueError("not a 32-bit little-endian ELF")

    phoff, shoff = struct.unpack_from("<II", data, 0x1C)
    phentsize, phnum, shentsize, shnum, _shstrndx = struct.unpack_from(
        "<HHHHH", data, 0x2A
    )

    segments = []
    for i in range(phnum):
        p_type, _off, p_vaddr, p_paddr, _filesz, p_memsz, _flags, _align = (
            struct.unpack_from("<8I", data, phoff + i * phentsize)
        )
        if p_type == PT_LOAD and p_memsz:
            segments.append((p_vaddr, p_paddr, p_memsz))

    def load_address(addr: int, size: int) -> int:
        for p_vaddr, p_paddr, p_memsz in segments:
            if addr >= p_vaddr and addr + size <= p_vaddr + p_memsz:
                return addr - p_vaddr + p_paddr
        return addr

    for i in range(shnum):
        (_name, sh_type, sh_flags, sh_addr, sh_off, sh_size,
         _link, _info, _align, _entsize) = struct.unpack_from(
            "<10I", data, shoff + i * shentsize
        )
        if not (sh_flags & SHF_ALLOC) or sh_type == SHT_NOBITS or sh_size == 0:
            continue
        yield load_address(sh_addr, sh_size), data[sh_off:sh_off + sh_size]


def elf_to_bin(elf_path: str) -> tuple[int, bytes]:
    """Flatten an ELF to (lowest load address, contiguous image bytes)."""
    with open(elf_path, "rb") as fh:
        data = fh.read()

    chunks = sorted(elf_sections(data))
    if not chunks:
        raise ValueError(f"no loadable content in {elf_path}")

    low = chunks[0][0]
    high = max(addr + len(payload) for addr, payload in chunks)
    image = bytearray(high - low)
    for addr, payload in chunks:
        image[addr - low:addr - low + len(payload)] = payload
    return low, bytes(image)


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


def _ihex_record(rectype: int, offset: int, payload: bytes) -> str:
    body = bytes([len(payload), (offset >> 8) & 0xFF, offset & 0xFF, rectype]) + payload
    checksum = (-sum(body)) & 0xFF
    return ":" + body.hex().upper() + f"{checksum:02X}"


def elf_to_ihex(elf_path: str, row: int = 16) -> str:
    """Flatten an ELF to Intel HEX, as `objcopy -O ihex` would.

    Records come from the sections themselves, not from the contiguous
    image `elf_to_bin` builds: `-O binary` fills the gaps between
    sections with zeros because a flat image has nowhere to put a hole,
    but `-O ihex` can simply skip them, and does. Emitting the padding
    here would write bytes objcopy would not.

    Where GNU objcopy uses extended *segment* records (type 2), this uses
    extended *linear* records (type 4). Both are standard Intel HEX and
    describe the same bytes at the same addresses.
    """
    with open(elf_path, "rb") as fh:
        data = fh.read()

    lines = []
    upper = None
    for addr, payload in sorted(elf_sections(data)):
        offset = 0
        while offset < len(payload):
            here = addr + offset
            # A record's address field is only 16 bits, so it may not
            # straddle a 64 KiB boundary.
            span = min(row, 0x10000 - (here & 0xFFFF), len(payload) - offset)
            high = here >> 16
            if high != upper:
                lines.append(_ihex_record(0x04, 0, high.to_bytes(2, "big")))
                upper = high
            lines.append(
                _ihex_record(0x00, here & 0xFFFF, payload[offset:offset + span])
            )
            offset += span
    lines.append(_ihex_record(0x01, 0, b""))
    return "\n".join(lines) + "\n"
