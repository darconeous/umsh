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
