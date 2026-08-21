"""The lookup grid."""

from __future__ import annotations

import pytest

from regiondb_build import morton


def test_longitude_180_wraps_to_the_same_meridian_as_minus_180():
    assert morton.normalize_longitude(180.0) == -180.0
    assert morton.key(0.0, 180.0) == morton.key(0.0, -180.0)


def test_longitudes_wrap_rather_than_clamp():
    assert morton.normalize_longitude(181.0) == pytest.approx(-179.0)
    assert morton.normalize_longitude(-181.0) == pytest.approx(179.0)
    assert morton.normalize_longitude(540.0) == pytest.approx(-180.0)


def test_latitude_90_lands_in_the_last_row():
    _, y = morton.cell_xy(90.0, 0.0)
    assert y == morton.GRID - 1


def test_rejects_out_of_range_latitude_and_non_finite_values():
    for latitude in (90.5, -90.5, float("nan"), float("inf")):
        with pytest.raises(morton.MortonError):
            morton.check_latitude(latitude)
    for longitude in (float("nan"), float("inf")):
        with pytest.raises(morton.MortonError):
            morton.normalize_longitude(longitude)


def test_interleave_places_longitude_in_even_bits():
    assert morton.interleave(0b1, 0b0) == 0b01
    assert morton.interleave(0b0, 0b1) == 0b10
    assert morton.interleave(0xFFFF, 0x0000) == 0x55555555
    assert morton.interleave(0x0000, 0xFFFF) == 0xAAAAAAAA


def test_cell_range_covers_every_key_inside_the_cell():
    start, end = morton.cell_range(14, 3, 7)
    assert end - start + 1 == 4 ** (morton.MAX_DEPTH - 14)
    for corner_lat, corner_lon in _corners(morton.cell_bounds(14, 3, 7)):
        assert start <= morton.key(corner_lat, corner_lon) <= end


def test_whole_world_cell_covers_the_key_space():
    start, end = morton.cell_range(0, 0, 0)
    assert start == 0
    assert end == 2**32 - 1


def _corners(bounds):
    min_lon, min_lat, max_lon, max_lat = bounds
    nudge = 1e-9
    return [
        (min_lat + nudge, min_lon + nudge),
        (max_lat - nudge, max_lon - nudge),
        (min_lat + nudge, max_lon - nudge),
        (max_lat - nudge, min_lon + nudge),
    ]
