"""Shapely-side geometry: normalization, geodesic operations, blob conversion.

Everything here works in WGS84 lon/lat degrees, and every operation that means
a distance goes through `pyproj` rather than pretending degrees are meters.
Buffers and radius caps project into a local azimuthal-equidistant frame
centered on the feature being worked on, which is accurate at the hundred-
kilometer scales this database uses and avoids the distortion a single global
projection would introduce.
"""

from __future__ import annotations

import math

from pyproj import Geod, Transformer
from shapely import make_valid, set_precision
from shapely.errors import GEOSException
from shapely.geometry import MultiPolygon, Polygon, box
from shapely.geometry.base import BaseGeometry
from shapely.ops import transform as shapely_transform
from shapely.ops import unary_union

from .blob import RING_EXTERIOR, RING_HOLE, Ring, to_e6

GEOD = Geod(ellps="WGS84")

# Degrees of latitude per meter, used only to turn a simplification tolerance
# in meters into the uniform coordinate tolerance shapely wants. Longitude
# degrees are shorter than this away from the equator, so a tolerance derived
# this way removes less than the requested distance there, never more.
_METERS_PER_DEGREE = 111_320.0

# The storage grid. Snapping before encoding keeps shapely's idea of a polygon
# and the compiled integer polygon identical, so a point the reference
# evaluator calls inside cannot fall outside at runtime.
GRID_SIZE = 1e-6


class GeometryError(ValueError):
    """A geometry could not be normalized into something usable."""


def polygonal(geometry: BaseGeometry) -> MultiPolygon:
    """Reduce any geometry to its polygonal parts.

    `make_valid` on a self-intersecting polygon can hand back lines and points
    alongside the repaired area; those carry no coverage and are dropped.
    """
    if geometry.is_empty:
        return MultiPolygon()
    parts: list[Polygon] = []
    geometries = getattr(geometry, "geoms", [geometry])
    for part in geometries:
        if isinstance(part, Polygon):
            if not part.is_empty and part.area > 0:
                parts.append(part)
        elif isinstance(part, MultiPolygon):
            parts.extend(sub for sub in part.geoms if not sub.is_empty and sub.area > 0)
    return MultiPolygon(parts)


def normalize(geometry: BaseGeometry, *, name: str = "geometry") -> MultiPolygon:
    """Repair, split at the antimeridian, and snap onto the storage grid."""
    if geometry.is_empty:
        raise GeometryError(f"{name} is empty")
    repaired = polygonal(make_valid(geometry))
    if repaired.is_empty:
        raise GeometryError(f"{name} has no polygonal area after repair")

    original_area = abs(geometry.area)
    if original_area > 0 and abs(repaired.area) < original_area * 0.5:
        raise GeometryError(
            f"{name} lost more than half its area during validity repair; "
            "the source geometry needs a look rather than an automatic fix"
        )

    split = split_antimeridian(repaired)
    snapped = polygonal(set_precision(split, GRID_SIZE))
    if snapped.is_empty:
        raise GeometryError(f"{name} vanished when snapped to the {GRID_SIZE} degree grid")
    return snapped


def split_antimeridian(geometry: BaseGeometry) -> MultiPolygon:
    """Split geometry that runs past ±180 into pieces inside the valid range.

    Buffering or Voronoi construction near the dateline naturally produces
    coordinates such as 181°, which are meaningful but unrepresentable. Source
    polygons already inside the range are returned untouched; datasets store a
    dateline-crossing country as separate polygons on each side already.
    """
    min_lon, _, max_lon, _ = geometry.bounds
    if min_lon >= -180.0 and max_lon <= 180.0:
        return polygonal(geometry)

    pieces: list[BaseGeometry] = []
    for offset in (-360.0, 0.0, 360.0):
        window = box(-180.0 + offset, -90.0, 180.0 + offset, 90.0)
        clipped = geometry.intersection(window)
        if clipped.is_empty:
            continue
        shifted = shapely_transform(lambda x, y, off=offset: (x - off, y), clipped)
        pieces.append(polygonal(shifted))
    if not pieces:
        raise GeometryError("geometry lies entirely outside the representable longitude range")
    return polygonal(unary_union(pieces))


def simplify_m(geometry: BaseGeometry, tolerance_m: float) -> BaseGeometry:
    """Topology-preserving simplification with a tolerance given in meters."""
    if tolerance_m <= 0:
        return geometry
    simplified = geometry.simplify(tolerance_m / _METERS_PER_DEGREE, preserve_topology=True)
    return polygonal(make_valid(simplified))


def _local_projection(longitude: float, latitude: float) -> tuple[Transformer, Transformer]:
    """Azimuthal-equidistant frame centered on a point, and its inverse."""
    crs = (
        f"+proj=aeqd +lat_0={latitude} +lon_0={longitude} "
        "+x_0=0 +y_0=0 +ellps=WGS84 +datum=WGS84 +units=m +no_defs"
    )
    return (
        Transformer.from_crs("EPSG:4326", crs, always_xy=True),
        Transformer.from_crs(crs, "EPSG:4326", always_xy=True),
    )


def buffer_m(geometry: BaseGeometry, distance_m: float) -> MultiPolygon:
    """Outward geodesic buffer, applied per connected component.

    Each component is buffered in a projection centered on itself, so the
    distance means the same thing at every latitude. A component large enough
    that one local frame would distort it — a country — is why policy keeps
    expansion at zero for the administrative layers.
    """
    if distance_m <= 0:
        return polygonal(geometry)

    buffered: list[BaseGeometry] = []
    for component in polygonal(geometry).geoms:
        center = component.representative_point()
        forward, inverse = _local_projection(center.x, center.y)
        projected = shapely_transform(lambda x, y, t=forward: t.transform(x, y), component)
        grown = projected.buffer(distance_m, quad_segs=16)
        restored = shapely_transform(lambda x, y, t=inverse: t.transform(x, y), grown)
        # Snap each piece onto the storage grid before combining them. A region
        # already split at the antimeridian arrives here as two components whose
        # buffers meet along the seam, and overlaying two independently
        # projected boundaries at full floating-point precision is exactly the
        # case GEOS reports as a side location conflict.
        buffered.append(polygonal(set_precision(make_valid(restored), GRID_SIZE)))

    return polygonal(split_antimeridian(_union(buffered)))


def drop_dust(geometry: BaseGeometry, min_area_km2: float) -> MultiPolygon:
    """Sweep sub-threshold components and holes out of a water-reach shape.

    After a region is unioned with its maritime reach, every genuine land
    component sits inside a water component at least two reaches across, so
    a free-standing polygon or a hole smaller than the threshold can only be
    an artifact: a sliver seam between a full-resolution edge and its
    simplified mask, or precision noise where a buffer met a ceiling. Each
    one renders as a dash of confetti on the map, and none of them changes
    any lookup answer that the seam itself did not already get wrong.
    """

    def area_km2(ring_coords) -> float:
        shell = Polygon(ring_coords)
        latitude = shell.representative_point().y
        return abs(shell.area) * (111.32**2) * abs(math.cos(math.radians(latitude)))

    kept = []
    for component in polygonal(geometry).geoms:
        if area_km2(component.exterior.coords) < min_area_km2:
            continue
        holes = [hole for hole in component.interiors if area_km2(hole.coords) >= min_area_km2]
        kept.append(Polygon(component.exterior, holes))
    return MultiPolygon(kept)


def _union(pieces: list[BaseGeometry]) -> BaseGeometry:
    """Combine buffered components, tolerating an overlay GEOS cannot resolve.

    Falling back to the un-unioned collection is safe for what this geometry is
    used for: overlapping parts of one region still answer the same question,
    since a position inside two parts of a region is simply inside that region.
    The union is worth attempting because it keeps the stored geometry smaller
    and the bounding boxes tighter, not because membership depends on it.
    """
    if len(pieces) == 1:
        return pieces[0]
    try:
        return unary_union(pieces)
    except GEOSException:
        return MultiPolygon([part for piece in pieces for part in polygonal(piece).geoms])


def geodesic_disk(longitude: float, latitude: float, radius_m: float, *, segments: int = 180):
    """A polygon approximating the geodesic disk of `radius_m` about a point."""
    if radius_m <= 0:
        raise GeometryError("disk radius must be positive")
    azimuths = [index * 360.0 / segments for index in range(segments)]
    lons, lats, _ = GEOD.fwd(
        [longitude] * segments,
        [latitude] * segments,
        azimuths,
        [radius_m] * segments,
    )
    ring = list(zip(lons, lats, strict=True))
    disk = Polygon(ring)
    if not disk.is_valid:
        disk = make_valid(disk)
    return polygonal(disk)


def densify_great_circle(
    start: tuple[float, float], end: tuple[float, float], max_error_m: float
) -> list[tuple[float, float]]:
    """Points along the great circle from `start` to `end`, excluding `end`.

    A Voronoi edge is a great-circle arc, but a GeoJSON or compiled polygon
    edge is a straight line in lon/lat. Subdividing keeps the difference under
    the configured tolerance, so the compiled boundary is the boundary the
    tessellation actually meant.
    """
    lon1, lat1 = start
    lon2, lat2 = end
    _, _, distance = GEOD.inv(lon1, lat1, lon2, lat2)
    if distance <= 0:
        return [start]

    # Sagitta of a chord on a sphere: error ≈ R(1 - cos(θ/2)) ≈ R θ² / 8.
    earth_radius = 6_371_008.8
    angle = distance / earth_radius
    max_angle = 2.0 * math.sqrt(2.0 * max_error_m / earth_radius) if max_error_m > 0 else angle
    steps = max(1, math.ceil(angle / max_angle)) if max_angle > 0 else 1
    if steps == 1:
        return [start]

    points = [start]
    intermediate = GEOD.npts(lon1, lat1, lon2, lat2, steps - 1)
    points.extend(intermediate)
    return points


def to_parts(geometry: BaseGeometry) -> list[list[Ring]]:
    """Convert polygonal geometry into per-component blob ring lists."""
    parts: list[list[Ring]] = []
    for polygon in polygonal(geometry).geoms:
        exterior = _ring_points(polygon.exterior.coords)
        if len(exterior) < 3:
            continue
        rings = [Ring(role=RING_EXTERIOR, points=exterior)]
        for interior in polygon.interiors:
            hole = _ring_points(interior.coords)
            if len(hole) >= 3:
                rings.append(Ring(role=RING_HOLE, points=hole))
        parts.append(rings)
    return parts


def _ring_points(coords) -> tuple[tuple[int, int], ...]:
    """Quantize a ring, drop its repeated closing vertex and any duplicates."""
    points: list[tuple[int, int]] = []
    for lon, lat in coords:
        quantized = (to_e6(lon), to_e6(lat))
        if not points or points[-1] != quantized:
            points.append(quantized)
    while len(points) > 1 and points[0] == points[-1]:
        points.pop()
    return tuple(points)
