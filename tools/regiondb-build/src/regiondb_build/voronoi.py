"""Generated nearest-site core regions.

The commercial-airport and positioned-IATA layers are spherical Voronoi
partitions capped by a maximum radius: a position belongs to the region of the
nearest qualifying site, unless every site is further away than the cap, in
which case the layer contributes nothing.

The construction is local rather than global, and deliberately so. A cell is
only ever needed inside its own radius cap, and a point within R of site i can
only be taken from i by a site within 2R of i — by the triangle inequality, a
site further away than that loses everywhere in the disk. So each cell is
computed as its capping disk clipped by the geodesic bisector half-space of
every site within 2R, which is exactly the spherical Voronoi cell restricted
to the cap, with none of the fragility a global tessellation brings near
coincident sites or over cells that span a hemisphere.

The clipping happens in a gnomonic projection centered on the site, where
great circles — and therefore geodesic bisectors — are exactly straight lines,
so the clip is a plain convex polygon operation with no approximation. The
capping disk is centered on the projection center, so it too maps exactly to a
circle. Only when the result is converted back to longitude and latitude does
an approximation enter, and there the straight gnomonic edges are re-densified
as great circles to within the configured curve tolerance.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from scipy.spatial import cKDTree
from shapely.geometry import MultiPolygon, Polygon

from . import geom
from .blob import point_in_rings
from .model import Site

# Mean Earth radius. Used only to give the gnomonic plane a metric scale; the
# clip itself is scale-free, and real distances go through pyproj.
EARTH_RADIUS_M = 6_371_008.8

# Bounds on the capping disk's vertex count, whatever the cap tolerance works
# out to. The cap is where a generated region fades out at maximum radius, not
# a border anyone contests, so it carries its own, much looser tolerance than
# the bisector edges that actually decide between neighboring regions.
DISK_SEGMENTS_MIN = 24
DISK_SEGMENTS_MAX = 360


def _disk_segments(radius_m: float, cap_error_m: float) -> int:
    """Vertices needed so the disk polygon stays within the cap tolerance.

    Chord sagitta on a circle of radius r with n segments is roughly
    r * (pi/n)^2 / 2; inverting gives the n that keeps it under the error.
    """
    if cap_error_m <= 0:
        return DISK_SEGMENTS_MAX
    needed = math.pi / math.sqrt(2.0 * cap_error_m / radius_m)
    return max(DISK_SEGMENTS_MIN, min(DISK_SEGMENTS_MAX, math.ceil(needed)))


class VoronoiError(ValueError):
    """A generated layer could not be constructed."""


@dataclass
class Cell:
    site: Site
    geometry: MultiPolygon


def unit_vectors(sites: list[Site]) -> np.ndarray:
    latitudes = np.radians([site.latitude for site in sites])
    longitudes = np.radians([site.longitude for site in sites])
    cos_lat = np.cos(latitudes)
    return np.column_stack(
        [cos_lat * np.cos(longitudes), cos_lat * np.sin(longitudes), np.sin(latitudes)]
    )


def _local_basis(vector: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """East and north unit vectors at a point on the sphere."""
    pole = np.array([0.0, 0.0, 1.0])
    east = np.cross(pole, vector)
    norm = np.linalg.norm(east)
    if norm < 1e-12:
        # At a pole, "east" is a matter of convention; any consistent choice
        # gives the same set of points once projected back.
        east = np.array([1.0, 0.0, 0.0])
        east = east - vector * float(np.dot(east, vector))
        norm = np.linalg.norm(east)
    east = east / norm
    north = np.cross(vector, east)
    return east, north / np.linalg.norm(north)


def _clip_half_plane(points: np.ndarray, a: float, b: float, c: float) -> np.ndarray:
    """Sutherland-Hodgman clip of a convex polygon by `a + b*x + c*y >= 0`."""
    if len(points) == 0:
        return points
    values = a + b * points[:, 0] + c * points[:, 1]
    inside = values >= 0.0
    if inside.all():
        return points
    if not inside.any():
        return np.empty((0, 2))

    output: list[np.ndarray] = []
    count = len(points)
    for index in range(count):
        following = (index + 1) % count
        current_in = inside[index]
        next_in = inside[following]
        if current_in:
            output.append(points[index])
        if current_in != next_in:
            span = values[index] - values[following]
            if span != 0.0:
                ratio = values[index] / span
                output.append(points[index] + ratio * (points[following] - points[index]))
    return np.array(output) if output else np.empty((0, 2))


def _project(
    longitudes, latitudes, center: np.ndarray, east: np.ndarray, north: np.ndarray
) -> np.ndarray:
    """Gnomonic projection about `center`, in meters on the tangent plane."""
    latitudes = np.radians(np.asarray(latitudes, dtype=float))
    longitudes = np.radians(np.asarray(longitudes, dtype=float))
    cos_lat = np.cos(latitudes)
    vectors = np.column_stack(
        [cos_lat * np.cos(longitudes), cos_lat * np.sin(longitudes), np.sin(latitudes)]
    )
    along = vectors @ center
    if np.any(along <= 1e-9):
        raise VoronoiError("a point at or beyond the horizon cannot be projected gnomonically")
    return EARTH_RADIUS_M * np.column_stack([vectors @ east / along, vectors @ north / along])


def _disk_polygon(
    site: Site,
    radius_m: float,
    center: np.ndarray,
    east: np.ndarray,
    north: np.ndarray,
    cap_error_m: float,
) -> np.ndarray:
    """The capping disk, as a true geodesic disk projected into the plane.

    Building the cap from `pyproj.Geod` rather than as a circle of spherical
    radius keeps the cap on the WGS84 ellipsoid, where the policy's 100 km is
    measured. A spherical cap would be off by a few hundred meters at that
    distance — harmless for routing, but it would make the radius check
    disagree with the radius policy asked for.
    """
    segments = _disk_segments(radius_m, cap_error_m)
    angles = [index * 360.0 / segments for index in range(segments)]
    longitudes, latitudes, _ = geom.GEOD.fwd(
        [site.longitude] * segments,
        [site.latitude] * segments,
        angles,
        [radius_m] * segments,
    )
    return _project(longitudes, latitudes, center, east, north)


def _unproject(
    points: np.ndarray,
    center: np.ndarray,
    east: np.ndarray,
    north: np.ndarray,
    center_longitude: float,
) -> list[tuple[float, float]]:
    directions = (
        center[None, :]
        + (points[:, 0:1] / EARTH_RADIUS_M) * east[None, :]
        + (points[:, 1:2] / EARTH_RADIUS_M) * north[None, :]
    )
    directions /= np.linalg.norm(directions, axis=1, keepdims=True)
    latitudes = np.degrees(np.arcsin(np.clip(directions[:, 2], -1.0, 1.0)))
    longitudes = np.degrees(np.arctan2(directions[:, 1], directions[:, 0]))
    # Keep the ring continuous with the site rather than wrapped into
    # [-180, 180): a cell straddling the antimeridian would otherwise fold into
    # a polygon spanning the whole world. `geom.normalize` splits it properly.
    longitudes = (
        center_longitude + np.remainder(longitudes - center_longitude + 180.0, 360.0) - 180.0
    )
    return list(zip(longitudes.tolist(), latitudes.tolist(), strict=True))


def build_cells(
    sites: list[Site], max_radius_m: float, curve_error_m: float, cap_error_m: float = 1000.0
) -> list[Cell]:
    """Build the capped nearest-site core geometry for every site."""
    if not sites:
        return []
    if max_radius_m <= 0:
        raise VoronoiError("a generated layer needs a positive maximum radius")

    vectors = unit_vectors(sites)
    tree = cKDTree(vectors)

    # Chord length subtending the 2R central angle: the search radius that
    # captures every site able to take territory inside the cap.
    influence_angle = min(2.0 * max_radius_m / EARTH_RADIUS_M, math.pi)
    influence_chord = 2.0 * math.sin(influence_angle / 2.0)

    cells: list[Cell] = []

    for index, site in enumerate(sites):
        # A cap reaching over a pole cannot be drawn as one longitude/latitude
        # ring: the pole is a singularity where every longitude meets, and a
        # ring crossing it would need a synthetic segment along the top edge.
        # No IATA location is anywhere near either pole, so this is a loud
        # error rather than a special case nothing would ever exercise.
        if abs(site.latitude) > 90.0 - math.degrees(max_radius_m / EARTH_RADIUS_M):
            raise VoronoiError(
                f"site {site.iata} at latitude {site.latitude} is within the radius cap "
                "of a pole; polar caps are not representable as a single ring"
            )

        center = vectors[index]
        east, north = _local_basis(center)
        polygon = _disk_polygon(site, max_radius_m, center, east, north, cap_error_m)

        for neighbor in tree.query_ball_point(center, influence_chord):
            if neighbor == index:
                continue
            difference = center - vectors[neighbor]
            if not np.any(difference):
                raise VoronoiError(
                    f"sites {site.iata} and {sites[neighbor].iata} share a position; "
                    "the update pass must resolve coincident sites"
                )
            polygon = _clip_half_plane(
                polygon,
                float(np.dot(center, difference)),
                float(np.dot(east, difference)) / EARTH_RADIUS_M,
                float(np.dot(north, difference)) / EARTH_RADIUS_M,
            )
            if len(polygon) < 3:
                break

        if len(polygon) < 3:
            raise VoronoiError(
                f"site {site.iata} was clipped away entirely; two sites are likely "
                "closer together than the geometry grid can distinguish"
            )

        ring = _unproject(polygon, center, east, north, site.longitude)
        densified: list[tuple[float, float]] = []
        for position, start in enumerate(ring):
            end = ring[(position + 1) % len(ring)]
            densified.extend(geom.densify_great_circle(start, end, curve_error_m))

        # Densification returns longitudes wrapped into [-180, 180]. A cell
        # near the antimeridian needs its ring continuous around the site
        # instead — a jump from +179.9 to -179.9 mid-ring reads as a trip
        # around the world, and repair slices the result into garbage slabs.
        densified = [
            (
                site.longitude + ((lon - site.longitude + 180.0) % 360.0) - 180.0,
                lat,
            )
            for lon, lat in densified
        ]

        cell = geom.normalize(Polygon(densified), name=f"{site.iata} core cell")
        cells.append(Cell(site=site, geometry=cell))

    return cells


def validate_cells(cells: list[Cell], max_radius_m: float) -> list[str]:
    """Check the invariants a generated layer is supposed to hold."""
    warnings: list[str] = []
    for cell in cells:
        lon_e6 = geom.to_e6(cell.site.longitude)
        lat_e6 = geom.to_e6(cell.site.latitude)
        contained = False
        for rings in geom.to_parts(cell.geometry):
            if point_in_rings(rings, lon_e6, lat_e6):
                contained = True
                break
        if not contained:
            warnings.append(f"{cell.site.iata}: generator point lies outside its own core")

        vertices = [point for polygon in cell.geometry.geoms for point in polygon.exterior.coords]
        if not vertices:
            continue
        longitudes = [point[0] for point in vertices]
        latitudes = [point[1] for point in vertices]
        _, _, distances = geom.GEOD.inv(
            [cell.site.longitude] * len(vertices),
            [cell.site.latitude] * len(vertices),
            longitudes,
            latitudes,
        )
        furthest = max(distances)
        # A vertex may sit a hair outside the cap: the disk is stored as a
        # polygon through points on the circle, and snapping to the coordinate
        # grid moves each one by up to half a grid step.
        if furthest > max_radius_m + 10.0:
            warnings.append(
                f"{cell.site.iata}: core extends {furthest / 1000:.1f} km from its site, "
                f"past the {max_radius_m / 1000:.0f} km cap"
            )
    return warnings
