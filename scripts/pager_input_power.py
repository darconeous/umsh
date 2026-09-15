#!/usr/bin/env python3
"""Retrieve the RAM summary from a Pager input-qualification image over USB.

Uses only the standard library. Sends ULCP NOPs; never resets the board or
changes settings. Run after reconnecting USB, with other serial clients closed.
"""

import argparse
import os
import re
import select
import termios
import time
import tty


def nop_frame():
    payload = b"\x81\x00"  # TID 1, CMD_NOP
    crc = 0xFFFF
    for byte in payload:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8408 if crc & 1 else 0)
    data = payload + (crc ^ 0xFFFF).to_bytes(2, "little")
    escaped = bytearray(b"\x7e")
    for byte in data:
        if byte in (0x7E, 0x7D, 0x11, 0x13):
            escaped.extend((0x7D, byte ^ 0x20))
        else:
            escaped.append(byte)
    return bytes(escaped) + b"\x7e"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", help="Pager USB serial port")
    args = parser.parse_args()
    fd = os.open(args.port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    saved = termios.tcgetattr(fd)
    try:
        tty.setraw(fd, termios.TCSANOW)
        settings = termios.tcgetattr(fd)
        settings[4] = settings[5] = termios.B115200
        termios.tcsetattr(fd, termios.TCSANOW, settings)
        deadline = time.monotonic() + 10
        next_request = 0
        received = bytearray()
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_request:
                os.write(fd, nop_frame())
                next_request = now + 1
            if not select.select([fd], [], [], 0.2)[0]:
                continue
            received.extend(os.read(fd, 4096))
            match = re.search(rb"pager input-power: [^\r\n]+\r\n", received)
            if match:
                print(match[0].decode("ascii").strip())
                return
            del received[:-8192]
        raise SystemExit(
            "No retained summary received. Check the qualification image and "
            "battery measurement interval; ordinary ULCP clients discard this ASCII report."
        )
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, saved)
        os.close(fd)


if __name__ == "__main__":
    main()
