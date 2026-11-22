"""Conformance of the Python region-code port against the Rust canon."""

from __future__ import annotations

import hashlib
import json

import pytest

from paths import REGIONS
from regiondb_build import regioncode

VECTORS = json.loads((REGIONS / "tests" / "regioncode-vectors.json").read_text())


def test_short_code_table_matches_rust_digest():
    alphabet = VECTORS["short_code_alphabet"]
    lines = []
    for a in alphabet:
        lines.append(f"{a}={regioncode.from_short_code(a):04X}")
        for b in alphabet:
            lines.append(f"{a}{b}={regioncode.from_short_code(a + b):04X}")
            for c in alphabet:
                lines.append(f"{a}{b}{c}={regioncode.from_short_code(a + b + c):04X}")
    table = "".join(line + "\n" for line in lines)
    assert len(lines) == VECTORS["short_code_count"]
    assert hashlib.sha256(table.encode()).hexdigest() == VECTORS["short_code_digest"]


@pytest.mark.parametrize(("code", "expected"), sorted(VECTORS["short_codes"].items()))
def test_short_code_samples(code, expected):
    assert regioncode.from_short_code(code) == expected


@pytest.mark.parametrize(("name", "expected"), sorted(VECTORS["names"].items()))
def test_named_regions(name, expected):
    assert regioncode.from_name(name) == expected


def test_case_folding_is_identity_for_derivation():
    assert regioncode.from_name("Rogue Valley") == regioncode.from_name("rOGUE vALLEY")
    assert regioncode.from_short_code("sfo") == regioncode.from_short_code("SFO")


def test_named_regions_never_collide_with_all_letter_short_codes():
    letter_codes = set()
    for a in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        letter_codes.add(regioncode.from_short_code(a))
        for b in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            letter_codes.add(regioncode.from_short_code(a + b))
            for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                letter_codes.add(regioncode.from_short_code(a + b + c))
    for value in range(0x10000):
        assert regioncode.transform_letter_chunk(value) not in letter_codes


def test_letters_round_trip_and_rejects_digit_codes():
    assert regioncode.letters(regioncode.from_short_code("MFR")) == "MFR"
    assert regioncode.letters(regioncode.from_short_code("US")) == "US"
    assert regioncode.letters(regioncode.from_short_code("W7")) is None


def test_short_code_form_detection():
    assert regioncode.is_short_code_form("SFO")
    assert regioncode.is_short_code_form("W7")
    assert not regioncode.is_short_code_form("SFOO")
    assert not regioncode.is_short_code_form("SF Bay Area")
    assert not regioncode.is_short_code_form("")


def test_rejects_out_of_form_short_codes():
    with pytest.raises(regioncode.RegionCodeError):
        regioncode.from_short_code("SF-")
    with pytest.raises(regioncode.RegionCodeError):
        regioncode.from_short_code("")


def test_from_string_trims_only_ascii_white_space():
    assert regioncode.from_string(" \t\r\n\x0cRogue Valley \t") == regioncode.from_name(
        "Rogue Valley"
    )
    nbsp = "Rogue Valley\u00a0"
    assert regioncode.from_string(nbsp) == regioncode.from_name(nbsp)
    assert regioncode.from_string(nbsp) != regioncode.from_name("Rogue Valley")


def test_from_string_reads_literal_codes():
    assert regioncode.from_string("0x7853") == 0x7853
    assert regioncode.from_string("0XdF6f") == 0xDF6F
    for name in ["0x12345", "0xzz", "0x 12", "0x+1"]:
        assert regioncode.from_string(name) == regioncode.from_name(name)


def test_from_string_collapses_white_space_inside_a_name():
    expected = regioncode.from_name("Rogue Valley")
    for spelling in ["Rogue  Valley", "Rogue\tValley", "Rogue \r\n Valley"]:
        assert regioncode.from_string(spelling) == expected
    assert regioncode.from_string("R" * 11 + "   " + "R" * 12)


def test_from_string_rejects_control_characters():
    for name in ["Rogue\x00Valley", "Rogue\x0bValley", "Rogue\x7f", "\x85Valley"]:
        with pytest.raises(regioncode.RegionCodeError):
            regioncode.from_string(name)
