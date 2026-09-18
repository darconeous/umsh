#!/usr/bin/env python3
"""Read-only ULCP USB boundary regression probe (POSIX, standard library only).

Stop any bridge using the port before running. Sends only NOP commands with
padding so HDLC wire lengths straddle 64-byte USB packet boundaries. It neither
changes saved settings nor requests RF transmissions. Opening the port starts a
new host session. Firmware that confuses USB ZLPs with serial EOF can discard a
reply or announce an unexpected new session at exact packet boundaries.
"""

import argparse
import collections
import os
import select
import termios
import time
import tty


def crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x8408 if crc & 1 else 0)
    return (~crc) & 0xFFFF


def encode(data):
    wire = bytearray([0x7E])
    for byte in data + crc16(data).to_bytes(2, "little"):
        wire.extend([0x7D, byte ^ 0x20] if byte in (0x7E, 0x7D, 0x11, 0x13) else [byte])
    wire.append(0x7E)
    return wire


class Reader:
    def __init__(self, fd):
        self.fd = fd
        self.buffer = bytearray()
        self.escaped = False
        self.frames = collections.deque()

    def next_frame(self, deadline):
        while not self.frames:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.fd], [], [], remaining)[0]:
                raise TimeoutError("no matching ULCP response before deadline")
            chunk = os.read(self.fd, 4096)
            if not chunk:
                raise EOFError("serial port closed")
            for byte in chunk:
                if byte == 0x7E:
                    if len(self.buffer) >= 4:
                        frame, fcs = self.buffer[:-2], self.buffer[-2:]
                        if crc16(frame) == int.from_bytes(fcs, "little"):
                            self.frames.append(bytes(frame))
                    self.buffer.clear()
                    self.escaped = False
                elif byte == 0x7D:
                    self.escaped = True
                else:
                    self.buffer.append(byte ^ 0x20 if self.escaped else byte)
                    self.escaped = False
        return self.frames.popleft()


def exchange(fd, reader, tid, wire, allow_attach=False):
    started = time.monotonic()
    deadline = started + 3
    remaining = wire
    while remaining:
        if not select.select([], [fd], [], max(0, deadline - time.monotonic()))[1]:
            raise TimeoutError("serial write stalled")
        remaining = remaining[os.write(fd, remaining):]
    while True:
        frame = reader.next_frame(deadline)
        # CMD_SESSION_RESET = 24, reason Attached = 0.
        if frame == bytes([0x80, 24, 0]) and not allow_attach:
            raise RuntimeError("unexpected session attach during a NOP exchange")
        if frame[0] & 7 == tid and frame[1] == 6:
            if frame != bytes([0x80 | tid, 6, 0, 0]):
                raise RuntimeError("NOP did not return STATUS_OK")
            return (time.monotonic() - started) * 1000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", help="explicit ULCP serial port")
    parser.add_argument("--count", type=int, default=400)
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be positive")
    fd = os.open(args.port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    try:
        tty.setraw(fd)
        config = termios.tcgetattr(fd)
        config[4] = config[5] = termios.B115200
        config[2] |= termios.CLOCAL | termios.CREAD
        termios.tcsetattr(fd, termios.TCSANOW, config)
        reader = Reader(fd)
        # Consume the attachment notice and establish a correlated round trip
        # before testing boundaries. ULCP transaction IDs are only 1 through 7.
        exchange(fd, reader, 7, encode(bytes([0x87, 0])), allow_attach=True)
        sizes = (63, 64, 65, 127, 128, 129, 255, 256)
        worst_ms = 0
        for sample in range(args.count):
            tid, size = sample % 7 + 1, sizes[sample % len(sizes)]
            wire = next(
                wire
                for pad in (85, 86, 87, 88)
                for length in range(size)
                if len(wire := encode(bytes([0x80 | tid, 0]) + bytes([pad]) * length)) == size
            )
            try:
                worst_ms = max(worst_ms, exchange(fd, reader, tid, wire))
            except (TimeoutError, RuntimeError) as error:
                raise RuntimeError(f"sample={sample}, wire_bytes={size}: {error}") from error
        print(f"PASS {args.count} NOP exchanges; wire_sizes={sizes}; max_rtt_ms={worst_ms:.3f}")
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()
