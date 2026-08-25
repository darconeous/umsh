"""Defects the committed administrative boundaries must not have.

Every check here is a bug that actually shipped. The boundary pipeline
buffers, clips, splits, snaps, smooths and reassembles; each of those
stages has at some point produced geometry that looked right in the one
place it was inspected and was wrong two states over. These assertions
are the systematic version of that inspection.

They read the committed extracts rather than building anything, so they
cost about a second and fail on the diff that introduces the defect.

Writing them was itself instructive: first drafts of three of these
flagged Monaco, Angola's borders and the forty-ninth parallel, because
the obvious measurement of a defect also describes something real. Each
check below says what separates the two.
"""

from __future__ import annotations

import json
import math

import numpy as np
import pytest
from shapely.geometry import Point, Polygon, shape

from paths import REGIONS

BOUNDARIES = REGIONS / "extracts" / "boundaries"

DEGREE_KM = 111.32

# Below this a detached component is a sliver rather than a place. Size
# alone does not say so — see `test_no_region_carries_a_detached_speck`.
ARTIFACT_KM2 = 1000.0

# A region whose own largest piece is smaller than this is simply a small
# place, and its lesser components are islands rather than slivers.
CONTINENT_KM2 = 10_000.0

# A hole smaller than this is a puncture rather than an enclave.
HOLE_KM2 = 50.0

# How far a state may reach into its neighbor before their shared border
# counts as having come apart.
SEAM_WIDTH_M = 250.0


def _load(layer: str) -> dict:
    return {
        path.stem: shape(json.loads(path.read_text())["geometry"])
        for path in sorted((BOUNDARIES / layer).glob("*.geojson"))
    }


@pytest.fixture(scope="module")
def countries() -> dict:
    return _load("country")


@pytest.fixture(scope="module")
def states() -> dict:
    return _load("us-state")


def _area_km2(polygon) -> float:
    latitude = polygon.representative_point().y
    return abs(polygon.area) * DEGREE_KM**2 * math.cos(math.radians(latitude))


def _components(geometry) -> list:
    return list(getattr(geometry, "geoms", [geometry]))


def test_every_boundary_is_valid(countries, states):
    invalid = [key for key, value in {**countries, **states}.items() if not value.is_valid]
    assert invalid == []


def test_no_region_carries_a_detached_speck(countries, states):
    """A speck the size of a snapping cell is not a place.

    Size alone cannot say so. Monaco, San Marino, Andorra, Liechtenstein
    and the District of Columbia are all smaller than the slivers this is
    hunting, because a landlocked region never receives a maritime reach.
    What marks an artifact is being minute *and* detached from a region
    that is otherwise enormous — the little rectangles that hung off the
    Mississippi, next to a Mississippi.
    """
    specks = []
    for key, value in {**countries, **states}.items():
        components = _components(value)
        if len(components) < 2:
            continue
        largest = max(_area_km2(component) for component in components)
        # "A speck beside a continent" needs an actual continent. Bouvet
        # Island's whole region is fifty square kilometers, and the tenth
        # of one beside it is Larsøya — a real rock, not a sliver.
        if largest < CONTINENT_KM2:
            continue
        for component in components:
            area = _area_km2(component)
            if area < ARTIFACT_KM2 and largest > area * 100:
                # A component pinned to the antimeridian is one half of a
                # region the storage format splits there; its size is a
                # property of the seam, not of the place. Tuvalu's four
                # pieces all touch it.
                west, _, east, _ = component.bounds
                if min(abs(abs(west) - 180.0), abs(abs(east) - 180.0)) < 1e-6:
                    continue
                specks.append((key, round(area, 1)))
    assert specks == []


def test_no_hole_is_a_puncture(countries, states):
    """An enclave is a hole somebody lives in; this looks for the others.

    Size cannot tell them apart either: Italy's hole for Vatican City is
    six tenths of a square kilometer and entirely correct. What makes a
    hole legitimate is that another region of the same layer occupies it.
    """
    punctures = []
    for layer in (countries, states):
        for key, value in layer.items():
            neighbors = [other for name, other in layer.items() if name != key]
            for component in _components(value):
                for ring in component.interiors:
                    hole = Polygon(ring.coords)
                    if _area_km2(hole) >= HOLE_KM2:
                        continue
                    if any(other.intersects(hole) for other in neighbors):
                        continue
                    punctures.append((key, round(_area_km2(hole), 2)))
    assert punctures == []


# Open sea the wrapped-longitude chords used to claim, and the land
# either side of the dateline that must still answer.
DATELINE_POINTS = [
    (51.5, -170.0, None, "middle of the Bering Sea"),
    (51.0, 165.0, None, "west of the Aleutians"),
    (-38.0, 172.0, None, "the Tasman Sea"),
    (52.9, 173.2, "AK", "Attu, the far west Aleutians"),
    (51.88, -176.65, "AK", "Adak"),
]


@pytest.mark.parametrize(("latitude", "longitude", "expected", "name"), DATELINE_POINTS)
def test_nothing_is_claimed_across_the_dateline(states, latitude, longitude, expected, name):
    """Longitudes wrap; a polygon that does not know it draws a chord.

    Projecting a buffer back through pyproj wraps into [-180, 180], which
    puts a 360-degree jump inside a ring for anything within reach of the
    dateline, and `make_valid` reads that as a segment across the world —
    the slab that ran through the Aleutians, claiming open sea.

    This asks what the geometry answers rather than what it looks like.
    The artifact's shape is a long segment at constant latitude, and so
    is the forty-ninth parallel; measuring the outline alone cannot tell
    them apart, and a first attempt at that flagged thirty-six real
    borders, most of them Angola's.
    """
    point = Point(longitude, latitude)
    covering = sorted(code for code, value in states.items() if value.contains(point))
    assert covering == ([expected] if expected else []), f"{name} is covered by {covering}"


def test_neighboring_states_meet_rather_than_overlap(states):
    """Shared borders are simplified once, so both sides must still meet.

    Measured as a width rather than an area: a long border carries a
    longer seam for the same sloppiness, and what matters is how far into
    its neighbor a state reaches. Reassembling faces leaves single-digit
    meters against a fifteen-kilometer tolerance. Simplifying each state
    on its own left more than a kilometer.
    """
    codes = sorted(states)
    overlaps = []
    for index, first in enumerate(codes):
        for second in codes[index + 1 :]:
            if not states[first].intersects(states[second]):
                continue
            shared = states[first].intersection(states[second])
            if shared.area <= 0.0:
                continue
            # Half the perimeter approximates the length of the seam.
            seam_km = max(shared.length * DEGREE_KM / 2, 1e-9)
            width_m = (shared.area * DEGREE_KM**2) / seam_km * 1000
            if width_m > SEAM_WIDTH_M:
                overlaps.append((first, second, round(width_m)))
    assert overlaps == []


# Corners that are defined rather than surveyed from a river: meridians
# and parallels, which the boundary is *supposed* to turn at squarely.
SURVEY_CORNERS = [
    ("OK", -103.002, 37.000, "Oklahoma panhandle, north-west"),
    ("OK", -103.002, 36.500, "Oklahoma panhandle, south-west"),
    ("UT", -109.045, 37.000, "Four Corners"),
    ("CO", -109.045, 41.000, "Colorado, north-west"),
    ("WY", -111.055, 45.000, "Wyoming, north-west"),
]


@pytest.mark.parametrize(("code", "longitude", "latitude", "name"), SURVEY_CORNERS)
def test_survey_corners_stay_square(states, code, longitude, latitude, name):
    """A moving average cannot tell a right angle from a meander.

    Smoothing rounded these off, which is as wrong as leaving a river
    border jagged: these corners are where a boundary is defined to turn,
    not an accident of where water ran.
    """
    best = None
    for component in _components(states[code]):
        points = np.asarray(component.exterior.coords, dtype=float)
        distances = np.hypot(points[:, 0] - longitude, points[:, 1] - latitude)
        index = int(distances.argmin())
        if best is None or distances[index] < best[0]:
            previous = points[index] - points[index - 1]
            following = points[(index + 1) % (len(points) - 1)] - points[index]
            heading = math.degrees(
                math.atan2(following[1], following[0]) - math.atan2(previous[1], previous[0])
            )
            best = (distances[index], abs((heading + 180) % 360 - 180))

    distance_km, turn = best
    assert distance_km * DEGREE_KM < 8.0, (
        f"{name}: nearest vertex is {distance_km * DEGREE_KM:.1f} km away"
    )
    assert turn > 60.0, f"{name}: turns {turn:.1f} degrees, so the corner was rounded off"
