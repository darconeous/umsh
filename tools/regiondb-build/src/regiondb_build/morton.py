"""The fixed lookup grid.

Longitude and latitude are each mapped onto 16 bits and interleaved into a
32-bit Z-order key, so a quadtree cell at any depth is one contiguous range of
keys and a lookup is a single indexed query. Depth 16 gives cells of roughly
600 m by 300 m at the equator; that bounds the size of the cache, not the
accuracy of a result, because any cell a boundary crosses carries the exact
polygons to test.
"""

from __future__ import annotations

import math

MAX_DEPTH = 16
GRID = 1 << MAX_DEPTH


class MortonError(ValueError):
    """A coordinate cannot be placed on the lookup grid."""


def normalize_longitude(longitude: float) -> float:
    """Wrap longitude into [-180, 180).

    Exactly +180 wraps to -180: the two name the same meridian, and picking one
    keeps the grid a partition rather than an overlap.
    """
    if not math.isfinite(longitude):
        raise MortonError(f"longitude {longitude!r} is not finite")
    # Written as a floor rather than an IEEE remainder so that the Rust and
    # JavaScript readers can reproduce it with the same two operations. An
    # IEEE remainder rounds half to even, which is one more thing for three
    # implementations to agree about than this needs to be.
    return longitude - 360.0 * math.floor((longitude + 180.0) / 360.0)


def check_latitude(latitude: float) -> float:
    """Validate latitude, which is clamped rather than wrapped.

    Latitude 90 is the pole, a real position rather than a wrap-around, so it
    is clamped into the last row instead of being rejected.
    """
    if not math.isfinite(latitude):
        raise MortonError(f"latitude {latitude!r} is not finite")
    if not -90.0 <= latitude <= 90.0:
        raise MortonError(f"latitude {latitude!r} is outside [-90, 90]")
    return latitude


def cell_xy(latitude: float, longitude: float) -> tuple[int, int]:
    longitude = normalize_longitude(longitude)
    latitude = check_latitude(latitude)
    x = int(math.floor((longitude + 180.0) / 360.0 * GRID))
    y = int(math.floor((latitude + 90.0) / 180.0 * GRID))
    return min(max(x, 0), GRID - 1), min(max(y, 0), GRID - 1)


def interleave(x: int, y: int) -> int:
    """Interleave two 16-bit values, x in the even bits."""
    return _spread(x) | (_spread(y) << 1)


def _spread(value: int) -> int:
    value &= 0xFFFF
    value = (value | (value << 8)) & 0x00FF00FF
    value = (value | (value << 4)) & 0x0F0F0F0F
    value = (value | (value << 2)) & 0x33333333
    value = (value | (value << 1)) & 0x55555555
    return value


def key(latitude: float, longitude: float) -> int:
    x, y = cell_xy(latitude, longitude)
    return interleave(x, y)


def cell_range(depth: int, x: int, y: int) -> tuple[int, int]:
    """Inclusive max-depth key range covered by a cell at `depth`."""
    if not 0 <= depth <= MAX_DEPTH:
        raise MortonError(f"depth {depth} outside 0..{MAX_DEPTH}")
    shift = MAX_DEPTH - depth
    start = interleave(x << shift, y << shift)
    span = 1 << (2 * shift)
    return start, start + span - 1


def cell_bounds(depth: int, x: int, y: int) -> tuple[float, float, float, float]:
    """Geographic bounds (min_lon, min_lat, max_lon, max_lat) of a cell."""
    size = 1 << (MAX_DEPTH - depth)
    min_lon = (x * size) / GRID * 360.0 - 180.0
    max_lon = ((x + 1) * size) / GRID * 360.0 - 180.0
    min_lat = (y * size) / GRID * 180.0 - 90.0
    max_lat = ((y + 1) * size) / GRID * 180.0 - 90.0
    return min_lon, min_lat, max_lon, max_lat
