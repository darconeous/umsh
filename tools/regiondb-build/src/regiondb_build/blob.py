"""The compiled geometry encoding.

Polygons are stored as a project-defined blob rather than WKB or SpatiaLite
geometry, for two reasons: the runtime must not need a SQLite extension on
iOS, and coordinates quantized to a fixed integer grid make boundary tests
exact instead of epsilon-dependent. One blob holds one connected polygon
component — an exterior ring plus its holes — so a country's remote islands
each get their own bounding box and the R-tree stays useful.

Coordinates are 1e-6 degrees (about 11 cm at the equator), delta-encoded from
the previous vertex and zigzag-varint packed. Ring closure is implicit; the
repeated final vertex is never stored.
"""

from __future__ import annotations

from dataclasses import dataclass

GEOMETRY_FORMAT_VERSION = 1

RING_EXTERIOR = 0
RING_HOLE = 1

COORD_SCALE = 1_000_000


class GeometryBlobError(ValueError):
    """A blob is malformed or uses an unsupported version."""


@dataclass(frozen=True)
class Ring:
    """One closed ring as integer 1e-6-degree coordinates, without closure."""

    role: int
    points: tuple[tuple[int, int], ...]


def to_e6(degrees: float) -> int:
    """Quantize a degree value onto the storage grid.

    Round-half-away-from-zero rather than Python's banker's rounding, so the
    Rust and JavaScript readers can reproduce the grid with plain arithmetic.
    """
    scaled = degrees * COORD_SCALE
    return int(scaled + 0.5) if scaled >= 0 else -int(-scaled + 0.5)


def from_e6(value: int) -> float:
    return value / COORD_SCALE


def _write_varint(out: bytearray, value: int) -> None:
    if value < 0:
        raise GeometryBlobError("varint values are unsigned")
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return


def _write_zigzag(out: bytearray, value: int) -> None:
    _write_varint(out, ((-value) << 1) - 1 if value < 0 else value << 1)


def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise GeometryBlobError("truncated varint")
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7
        if shift > 63:
            raise GeometryBlobError("varint too long")


def _read_zigzag(data: bytes, offset: int) -> tuple[int, int]:
    raw, offset = _read_varint(data, offset)
    return (raw >> 1) ^ -(raw & 1), offset


def encode(rings: list[Ring]) -> bytes:
    """Encode one polygon component."""
    if not rings:
        raise GeometryBlobError("a geometry part needs at least one ring")
    if rings[0].role != RING_EXTERIOR:
        raise GeometryBlobError("the first ring of a part must be its exterior")

    out = bytearray()
    out.append(GEOMETRY_FORMAT_VERSION)
    _write_varint(out, len(rings))
    for ring in rings:
        if len(ring.points) < 3:
            raise GeometryBlobError("a ring needs at least three distinct vertices")
        out.append(ring.role)
        _write_varint(out, len(ring.points))
        previous_lon = 0
        previous_lat = 0
        for lon, lat in ring.points:
            _write_zigzag(out, lon - previous_lon)
            _write_zigzag(out, lat - previous_lat)
            previous_lon = lon
            previous_lat = lat
    return bytes(out)


def decode(blob: bytes) -> list[Ring]:
    """Decode one polygon component."""
    if not blob:
        raise GeometryBlobError("empty geometry blob")
    version = blob[0]
    if version != GEOMETRY_FORMAT_VERSION:
        raise GeometryBlobError(f"unsupported geometry format version {version}")

    offset = 1
    ring_count, offset = _read_varint(blob, offset)
    rings: list[Ring] = []
    for _ in range(ring_count):
        if offset >= len(blob):
            raise GeometryBlobError("truncated ring header")
        role = blob[offset]
        offset += 1
        point_count, offset = _read_varint(blob, offset)
        points: list[tuple[int, int]] = []
        lon = 0
        lat = 0
        for _ in range(point_count):
            delta_lon, offset = _read_zigzag(blob, offset)
            delta_lat, offset = _read_zigzag(blob, offset)
            lon += delta_lon
            lat += delta_lat
            points.append((lon, lat))
        rings.append(Ring(role=role, points=tuple(points)))
    if offset != len(blob):
        raise GeometryBlobError("trailing bytes after geometry blob")
    return rings


def point_in_rings(rings: list[Ring], lon_e6: int, lat_e6: int) -> bool:
    """Exact integer point-in-polygon, boundary inclusive.

    A point exactly on a boundary counts as inside — everywhere, in every
    implementation. Two abutting regions therefore both claim their shared
    edge, which is the harmless failure; a gap between them would leave a
    position with no region at all.
    """
    exterior = [ring for ring in rings if ring.role == RING_EXTERIOR]
    holes = [ring for ring in rings if ring.role == RING_HOLE]
    if not exterior:
        return False

    for ring in rings:
        if _on_ring(ring, lon_e6, lat_e6):
            return True
    if not _strictly_inside(exterior[0], lon_e6, lat_e6):
        return False
    return not any(_strictly_inside(hole, lon_e6, lat_e6) for hole in holes)


def _on_ring(ring: Ring, x: int, y: int) -> bool:
    points = ring.points
    for index in range(len(points)):
        x1, y1 = points[index]
        x2, y2 = points[(index + 1) % len(points)]
        if (x2 - x1) * (y - y1) - (y2 - y1) * (x - x1) != 0:
            continue
        if min(x1, x2) <= x <= max(x1, x2) and min(y1, y2) <= y <= max(y1, y2):
            return True
    return False


def _strictly_inside(ring: Ring, x: int, y: int) -> bool:
    """Crossing-number test with a half-open rule on the vertical span.

    Treating each edge as containing its lower endpoint and not its upper one
    makes a ray through a vertex count once rather than twice or zero times,
    with no tolerance anywhere.
    """
    points = ring.points
    inside = False
    for index in range(len(points)):
        x1, y1 = points[index]
        x2, y2 = points[(index + 1) % len(points)]
        if (y1 > y) != (y2 > y):
            # Sign-safe form of `x < x1 + (y - y1) * (x2 - x1) / (y2 - y1)`.
            side = (x2 - x1) * (y - y1) - (y2 - y1) * (x - x1)
            if side != 0 and (side > 0) == (y2 > y1):
                inside = not inside
    return inside
