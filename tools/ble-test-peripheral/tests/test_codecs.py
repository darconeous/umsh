"""The peripheral's codecs against the vectors the Rust codecs produced
(`make ble-test-vectors`; checked by `umsh-mobile-core`'s
`ble_test_vectors_match`)."""

import json
from pathlib import Path

import pytest

from ble_test_peripheral import (
    HdlcDecoder,
    Reassembler,
    advertising_payloads,
    gatt_segments,
    hdlc_encode,
)

VECTORS = json.loads((Path(__file__).parent / "vectors.json").read_text())


@pytest.mark.parametrize("case", VECTORS["sar"])
def test_segmentation(case):
    frame = bytes.fromhex(case["frame"])
    values = gatt_segments(frame, case["max_value_length"])
    assert [value.hex() for value in values] == case["values"]


@pytest.mark.parametrize("case", VECTORS["reassembly"])
def test_reassembly(case):
    reassembler = Reassembler()
    results = []
    for value in case["values"]:
        result = reassembler.push(bytes.fromhex(value))
        results.append(
            "error" if isinstance(result, str) else result.hex() if result is not None else None
        )
    assert results == case["results"]


@pytest.mark.parametrize("case", VECTORS["hdlc_encode"])
def test_hdlc_encode(case):
    assert hdlc_encode(bytes.fromhex(case["frame"])).hex() == case["wire"]


@pytest.mark.parametrize("case", VECTORS["hdlc_decode"])
def test_hdlc_decode(case):
    stream = bytes.fromhex(case["stream"])
    whole = [frame.hex() for frame in HdlcDecoder().push(stream)]
    assert whole == case["frames"]
    # A stream arrives in arbitrary chunks; one octet at a time is the worst.
    decoder = HdlcDecoder()
    single = [frame.hex() for byte in stream for frame in decoder.push([byte])]
    assert single == case["frames"]


@pytest.mark.parametrize("case", VECTORS["advertising"])
def test_advertising_matches_the_firmware(case):
    name = bytes.fromhex(case["name"]).decode()
    adv, scan = advertising_payloads(case["pairing"], name, case["model_id"])
    assert adv.hex() == case["advertising"]
    assert scan.hex() == case["scan_response"]


def test_advertising_outside_pairing_mode_names_nothing():
    adv, scan = advertising_payloads(False, "T1000-E 4F2A", 2)
    assert adv[:3] == bytes([2, 0x01, 0x04])
    assert len(adv) == 21
    assert scan == b""


def test_advertising_in_pairing_mode_carries_model_and_name():
    adv, scan = advertising_payloads(True, "T1000-E 4F2A", 2)
    assert adv[:3] == bytes([2, 0x01, 0x06])
    assert adv[21:] == bytes([5, 0xFF, 0xFF, 0xFF, 0x00, 0x02])
    assert scan == bytes([13, 0x09]) + b"T1000-E 4F2A"


def test_a_long_name_is_cut_on_a_character_boundary():
    _, scan = advertising_payloads(True, "é" * 20, 2)
    assert scan[1] == 0x08
    assert scan[2:].decode() == "é" * 14
