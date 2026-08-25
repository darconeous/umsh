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

import numpy as np
from pyproj import Geod, Transformer
from shapely import coverage_simplify, make_valid, set_precision
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
        # pyproj wraps longitudes into [-180, 180], so a component near the
        # dateline comes back with jumps of 360° that read as a chord across
        # the whole world — make_valid then bakes that chord into the shape
        # as horizontal spikes and eaten coverage. Unwrap around the
        # component's own center; split_antimeridian below expects exactly
        # this continuous past-±180 form.
        restored = shapely_transform(
            lambda x, y, c=center.x: (c + ((x - c + 180.0) % 360.0) - 180.0, y),
            restored,
        )
        # Snap each piece onto the storage grid before combining them. A region
        # already split at the antimeridian arrives here as two components whose
        # buffers meet along the seam, and overlaying two independently
        # projected boundaries at full floating-point precision is exactly the
        # case GEOS reports as a side location conflict.
        buffered.append(polygonal(set_precision(make_valid(restored), GRID_SIZE)))

    return polygonal(split_antimeridian(_union(buffered)))


def fill_holes(geometry: BaseGeometry) -> MultiPolygon:
    """Fill every hole in every component.

    For a region unioned with its maritime reach, a hole is usually water
    enclosed entirely by that one region's own water — the middle of the
    Sea of Okhotsk, the center of Hudson Bay — and filling it stops an
    enclosed sea from rendering as a bite out of its country, giving the
    only sensible answer to the rare node in the middle of one.

    Not every hole is one of those, so this takes no view on which are:
    a jurisdiction is also punched through wherever a neighbor's begins.
    Callers that fill a region bounded by other regions must clip the
    result back to that boundary, or filling annexes the neighbor.
    """
    return MultiPolygon([Polygon(component.exterior) for component in polygonal(geometry).geoms])


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


# How much a region may be distorted before the pass gives up on it and
# keeps the original outline. One tolerance cannot serve both Siberia and
# Monaco: at fifteen kilometers Visvalingam-Whyatt takes half of Monaco
# and all of Vatican City, and no choice of algorithm avoids that.
_KEEP_ORIGINAL_ABOVE = 0.25

# A speck or hole this size is the width of a snapping cell along a
# border, not a place: every region here carries a hundred-kilometer
# maritime reach, so its smallest real component is far larger.
_SEAM_ARTIFACT_KM2 = 120.0

# Detached fragments up to this size go too, but only when the region
# they hang off is a hundred times bigger — Monaco is smaller than these
# and must stay.
_DETACHED_ARTIFACT_KM2 = 1000.0


def _sweep(geometry: MultiPolygon) -> MultiPolygon:
    """Remove the seam artifacts, without ever emptying a region.

    Sweeping by size alone cannot be safe here: a threshold high enough
    to catch a sliver along a border is higher than Bouvet Island's whole
    region, and applying it deleted the country outright — which the
    write step then refused, as it should. So components go only by the
    detached rule, which needs a larger sibling to compare against, and
    punctures are filled without touching components at all.
    """
    filled = MultiPolygon(
        [
            Polygon(
                component.exterior,
                [
                    ring
                    for ring in component.interiors
                    if _area_km2(Polygon(ring)) >= _SEAM_ARTIFACT_KM2
                ],
            )
            for component in polygonal(geometry).geoms
        ]
    )
    return _drop_detached(filled, _DETACHED_ARTIFACT_KM2)


def _drop_detached(geometry: MultiPolygon, floor_km2: float) -> MultiPolygon:
    """Drop specks that are tiny beside the rest of their own region.

    A threshold on size alone cannot do this: Monaco, San Marino and the
    District of Columbia are all smaller than the fragments this removes,
    because a landlocked region never receives a maritime reach. What
    marks an artifact is being minute *and* detached from something
    enormous — a speck beside a continent, rather than a country that
    happens to be small.
    """
    components = list(geometry.geoms)
    if len(components) < 2:
        return geometry
    areas = [_area_km2(component) for component in components]
    largest = max(areas)
    kept = [
        component
        for component, area in zip(components, areas, strict=True)
        if area >= floor_km2 or largest <= area * 100
    ]
    return MultiPolygon(kept) if kept else geometry


def _area_km2(polygon) -> float:
    latitude = polygon.representative_point().y
    return abs(polygon.area) * _KM_PER_DEGREE**2 * math.cos(math.radians(latitude))


_KM_PER_DEGREE = 111.32


def simplify_shared(shapes: dict[str, BaseGeometry], tolerance_m: float) -> dict[str, MultiPolygon]:
    """Simplify one layer of neighboring regions, keeping them a coverage.

    Simplifying each region on its own moves a shared border twice, once
    per side, and the two halves stop meeting. GEOS solves this directly:
    `coverage_simplify` runs Visvalingam-Whyatt over a polygonal coverage
    and keeps shared edges identical by construction, so no border can
    come apart, no sliver can appear between neighbors, and corners — a
    triangle of large area, unlike a meander's — survive on their own
    merit rather than by being detected.

    The shapes must already be a coverage: non-overlapping, and matching
    vertex-for-vertex along shared edges. Snapping the whole layer to one
    grid first is what makes that true here, because the maritime reach
    is built per region and its seams land a meter apart on either side.

    One thing this does not fix, and nothing can: a single tolerance
    cannot serve both Siberia and Monaco. A region the pass would leave
    unrecognizable keeps the outline it came in with.
    """
    if tolerance_m <= 0:
        return {key: polygonal(shape) for key, shape in shapes.items()}

    tolerance = tolerance_m / _METERS_PER_DEGREE
    keys = list(shapes)
    # Swept before anything else, so that the fallback below restores a
    # cleaned outline rather than the raw one. A region kept at its
    # original shape would otherwise keep the seam artifacts of the
    # stages before this, having skipped the sweep applied to the rest.
    given = {key: _sweep(polygonal(shapes[key])) for key in keys}
    # Well below the tolerance, and enough to make near-coincident edges
    # actually coincident — the coverage precondition.
    grid = tolerance / 8.0
    snapped = [polygonal(set_precision(make_valid(given[key]), grid)) for key in keys]

    simplified = coverage_simplify(np.array(snapped, dtype=object), tolerance)

    # Snapping each region on its own does not quite produce a coverage:
    # the maritime reach is built per region and its seams land a meter
    # apart, so a shared edge can snap onto different cells on either
    # side. `coverage_simplify` takes its precondition on trust and
    # carries the difference through as a speck in one region and a hole
    # the same size in its neighbor. Both are swept afterwards.
    result: dict[str, MultiPolygon] = {}
    untouched: list[str] = []
    for key, value in zip(keys, simplified, strict=True):
        rebuilt = _sweep(polygonal(make_valid(value)))
        original = given[key]
        if abs(rebuilt.area - original.area) > original.area * _KEEP_ORIGINAL_ABOVE:
            rebuilt = original
            untouched.append(key)
        result[key] = rebuilt

    # A region kept at its original outline is authoritative there: its
    # simplified neighbors yield, rather than overlapping it by up to a
    # tolerance. The District of Columbia is the case that matters, being
    # small enough to keep and surrounded by a Maryland that was not.
    for key in untouched:
        for other in keys:
            if other == key or not result[other].intersects(result[key]):
                continue
            result[other] = polygonal(result[other].difference(result[key]))
    return result


def max_area_change(
    before: dict[str, BaseGeometry], after: dict[str, MultiPolygon]
) -> tuple[str, float]:
    """The region that `simplify_shared` moved most, as a fraction of its area."""
    worst_key, worst = "", 0.0
    for key, original in before.items():
        area = max(original.area, 1e-12)
        change = abs(after[key].area - original.area) / area
        if change > worst:
            worst_key, worst = key, change
    return worst_key, worst


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
    # GEOD.fwd wraps longitudes; a disk laid over the dateline needs its
    # ring continuous around its own center, then splitting.
    ring = [
        (longitude + ((lon - longitude + 180.0) % 360.0) - 180.0, lat)
        for lon, lat in zip(lons, lats, strict=True)
    ]
    disk = Polygon(ring)
    if not disk.is_valid:
        disk = make_valid(disk)
    return polygonal(split_antimeridian(disk))


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
