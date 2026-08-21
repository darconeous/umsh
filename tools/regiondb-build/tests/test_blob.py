"""The geometry blob codec, against the committed golden vectors."""

from __future__ import annotations

import json

import pytest

from paths import REGIONS
from regiondb_build import blob

GOLDEN = json.loads((REGIONS / "tests" / "geometry-golden.json").read_text())


def _rings(case) -> list[blob.Ring]:
    return [
        blob.Ring(role=ring["role"], points=tuple(tuple(point) for point in ring["points"]))
        for ring in case["rings"]
    ]


@pytest.mark.parametrize("case", GOLDEN["cases"], ids=lambda case: case["name"])
def test_encodes_to_golden_bytes(case):
    assert blob.encode(_rings(case)).hex() == case["blob_hex"]


@pytest.mark.parametrize("case", GOLDEN["cases"], ids=lambda case: case["name"])
def test_round_trips(case):
    assert blob.decode(bytes.fromhex(case["blob_hex"])) == _rings(case)


@pytest.mark.parametrize("case", GOLDEN["cases"], ids=lambda case: case["name"])
def test_point_in_polygon_probes(case):
    rings = _rings(case)
    for probe in case["probes"]:
        assert blob.point_in_rings(rings, probe["lon_e6"], probe["lat_e6"]) is probe["inside"], (
            probe
        )


def test_boundary_counts_as_inside():
    square = blob.Ring(blob.RING_EXTERIOR, ((0, 0), (100, 0), (100, 100), (0, 100)))
    for point in ((0, 0), (100, 100), (50, 0), (0, 50), (100, 50)):
        assert blob.point_in_rings([square], *point)
    for point in ((-1, 50), (101, 50), (50, -1), (50, 101)):
        assert not blob.point_in_rings([square], *point)


def test_hole_boundary_counts_as_inside():
    square = blob.Ring(blob.RING_EXTERIOR, ((0, 0), (100, 0), (100, 100), (0, 100)))
    hole = blob.Ring(blob.RING_HOLE, ((25, 25), (75, 25), (75, 75), (25, 75)))
    assert blob.point_in_rings([square, hole], 25, 50)
    assert not blob.point_in_rings([square, hole], 50, 50)


def test_rejects_unknown_version():
    payload = bytearray(blob.encode([blob.Ring(blob.RING_EXTERIOR, ((0, 0), (1, 0), (1, 1)))]))
    payload[0] = 99
    with pytest.raises(blob.GeometryBlobError):
        blob.decode(bytes(payload))


def test_rejects_trailing_bytes():
    payload = blob.encode([blob.Ring(blob.RING_EXTERIOR, ((0, 0), (1, 0), (1, 1)))]) + b"\x00"
    with pytest.raises(blob.GeometryBlobError):
        blob.decode(payload)


@pytest.mark.parametrize("value", [0, 1, -1, 127, -128, 2**20, -(2**20), 180_000_000])
def test_zigzag_varint_round_trip(value):
    ring = blob.Ring(blob.RING_EXTERIOR, ((value, -value), (value + 5, -value), (value, 3)))
    assert blob.decode(blob.encode([ring])) == [ring]


def test_quantization_rounds_half_away_from_zero():
    assert blob.to_e6(0.0000005) == 1
    assert blob.to_e6(-0.0000005) == -1
    assert blob.to_e6(1.2345678) == 1234568
