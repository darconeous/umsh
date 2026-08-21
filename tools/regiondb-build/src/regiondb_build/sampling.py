"""The sampled-dilation membership rule.

Expanded coverage is not stored as geometry. A region's effective membership is
*defined* as: a position belongs to a region if any point of a fixed sample
pattern — the position itself, six points at half the region's expansion
distance, and twelve at the full distance — lands inside the region's core.
The pattern is the semantics, not an approximation of something else, which is
what lets three implementations agree exactly: each computes the same nineteen
spherical destinations and runs the same integer point-in-polygon test.

Against true geodesic dilation this scallops the outer edge by at most a few
hundred meters between samples. An expansion margin exists so a repeater near
a border can be configured for both sides; its outer edge is fuzzy by nature,
and no routing decision changes inside the scallops.

Destinations are computed on the mean-radius sphere with the standard direct
formulas — the same model as the suggested-default tie-break, and for the same
reason: it is arithmetic every platform reproduces without a geodesic library.
A membership test never measures anything; it only has to be the same test
everywhere.
"""

from __future__ import annotations

import math

# Mean Earth radius, matching the tie-break in lookup.py.
EARTH_RADIUS_M = 6_371_008.8

# Bearings of the two sample rings, in degrees clockwise from north.
FULL_RING_BEARINGS = tuple(range(0, 360, 30))  # 12 points at expansion_m
HALF_RING_BEARINGS = tuple(range(0, 360, 60))  # 6 points at expansion_m / 2


def destination(latitude: float, longitude: float, bearing_deg: float, distance_m: float):
    """Spherical direct problem: where `distance_m` at `bearing_deg` lands."""
    angular = distance_m / EARTH_RADIUS_M
    bearing = math.radians(bearing_deg)
    lat1 = math.radians(latitude)
    sin_lat2 = math.sin(lat1) * math.cos(angular) + math.cos(lat1) * math.sin(angular) * math.cos(
        bearing
    )
    lat2 = math.asin(max(-1.0, min(1.0, sin_lat2)))
    lon2 = math.radians(longitude) + math.atan2(
        math.sin(bearing) * math.sin(angular) * math.cos(lat1),
        math.cos(angular) - math.sin(lat1) * sin_lat2,
    )
    return math.degrees(lat2), math.degrees(lon2)


def sample_positions(latitude: float, longitude: float, expansion_m: int):
    """Every position to test against core geometry, the position itself first.

    Yielding the position first lets a caller stop early on a core hit, and
    makes the core-versus-expanded distinction fall out of the same loop.
    """
    yield latitude, longitude
    if expansion_m <= 0:
        return
    for bearing in HALF_RING_BEARINGS:
        yield destination(latitude, longitude, bearing, expansion_m / 2.0)
    for bearing in FULL_RING_BEARINGS:
        yield destination(latitude, longitude, bearing, float(expansion_m))
