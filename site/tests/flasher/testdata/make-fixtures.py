#!/usr/bin/env python3
"""Regenerate the flasher's DFU test fixtures.

    python3 site/tests/flasher/testdata/make-fixtures.py

`dfu-frames.json` holds the exact bytes the legacy Nordic serial DFU protocol
puts on the wire for a known image, so `nrf-dfu.test.mjs` can compare the
browser implementation against something that did not come from it. The framing
below is transcribed from `dfu/dfu_transport_serial.py` in adafruit-nrfutil
(BSD-3-Clause, Copyright (c) 2015 Nordic Semiconductor) — the tool `make
flash-<board>-serial` shells out to — deliberately kept in a different language
from the code under test.

`sample-dfu.zip` is a miniature of what `make dfu-zip-<board>` writes: the same
entry names, the same manifest schema, a 14-byte init packet, and the S140
7.3.0 requirement. It is synthetic so the repository does not have to carry a
half-megabyte release artifact.
"""

import json
import struct
import zipfile
from pathlib import Path

DATA_INTEGRITY_CHECK_PRESENT = 1
RELIABLE_PACKET = 1
HCI_PACKET_TYPE = 14

DFU_INIT_PACKET = 1
DFU_START_PACKET = 3
DFU_DATA_PACKET = 4
DFU_STOP_DATA_PACKET = 5
DFU_UPDATE_MODE_APP = 4

DFU_PACKET_MAX_SIZE = 512


def slip_parts_to_four_bytes(seq, dip, rp, pkt_type, pkt_len):
    ints = [0, 0, 0, 0]
    ints[0] = seq | (((seq + 1) % 8) << 3) | (dip << 6) | (rp << 7)
    ints[1] = pkt_type | ((pkt_len & 0x000F) << 4)
    ints[2] = (pkt_len & 0x0FF0) >> 4
    ints[3] = (~(ints[0] + ints[1] + ints[2]) + 1) & 0xFF
    return bytes(ints)


def calc_crc16(data, crc=0xFFFF):
    for byte in data:
        crc = (crc >> 8 & 0x00FF) | (crc << 8 & 0xFF00)
        crc ^= byte
        crc ^= (crc & 0x00FF) >> 4
        crc ^= (crc << 8) << 4
        crc ^= ((crc & 0x00FF) << 4) << 1
        crc &= 0xFFFF
    return crc & 0xFFFF


def slip_encode_esc_chars(data):
    out = bytearray()
    for byte in data:
        if byte == 0xC0:
            out += b"\xdb\xdc"
        elif byte == 0xDB:
            out += b"\xdb\xdd"
        else:
            out.append(byte)
    return bytes(out)


def hci_packet(payload, seq):
    header = slip_parts_to_four_bytes(
        seq, DATA_INTEGRITY_CHECK_PRESENT, RELIABLE_PACKET, HCI_PACKET_TYPE, len(payload)
    )
    body = header + payload
    body += struct.pack("<H", calc_crc16(body))
    return b"\xc0" + slip_encode_esc_chars(body) + b"\xc0"


def firmware_pattern():
    """1 KiB — two data packets — containing both SLIP escape bytes."""
    data = bytearray((i * 7 + (0xC0 if i % 97 == 0 else 0)) & 0xFF for i in range(1024))
    data[10] = 0xC0
    data[11] = 0xDB
    data[600] = 0xC0
    return bytes(data)


def init_packet():
    return bytes(range(0x10, 0x1E))


def golden_frames():
    firmware = firmware_pattern()
    frames = []
    seq = 0

    seq = (seq + 1) % 8
    frames.append(
        hci_packet(
            struct.pack("<IIIII", DFU_START_PACKET, DFU_UPDATE_MODE_APP, 0, 0, len(firmware)),
            seq,
        )
    )

    seq = (seq + 1) % 8
    frames.append(hci_packet(struct.pack("<I", DFU_INIT_PACKET) + init_packet() + b"\x00\x00", seq))

    for offset in range(0, len(firmware), DFU_PACKET_MAX_SIZE):
        seq = (seq + 1) % 8
        chunk = firmware[offset : offset + DFU_PACKET_MAX_SIZE]
        frames.append(hci_packet(struct.pack("<I", DFU_DATA_PACKET) + chunk, seq))

    seq = (seq + 1) % 8
    frames.append(hci_packet(struct.pack("<I", DFU_STOP_DATA_PACKET), seq))
    return [frame.hex() for frame in frames]


def sample_package(path):
    manifest = {
        "manifest": {
            "application": {
                "bin_file": "firmware-t1000e.bin",
                "dat_file": "firmware-t1000e.dat",
                "init_packet_data": {
                    "application_version": 4294967295,
                    "device_revision": 65535,
                    "device_type": 82,
                    "firmware_crc16": 40620,
                    "softdevice_req": [0x123],
                },
            },
            "dfu_version": 0.5,
        }
    }
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("firmware-t1000e.bin", firmware_pattern() * 4)
        archive.writestr("firmware-t1000e.dat", init_packet())
        archive.writestr("manifest.json", json.dumps(manifest))


def main():
    here = Path(__file__).parent
    (here / "dfu-frames.json").write_text(json.dumps({"frames": golden_frames()}, indent=1) + "\n")
    sample_package(here / "sample-dfu.zip")
    print(f"wrote {here}/dfu-frames.json and {here}/sample-dfu.zip")


if __name__ == "__main__":
    main()
