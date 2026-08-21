/**
 * The compiled geometry encoding, in JavaScript.
 *
 * A port of `crates/umsh-regiondb/src/blob.rs` and its Python counterpart.
 * The three implementations must agree exactly — a map that answers a click
 * differently from the phone in your pocket is worse than no map — so this is
 * written to be transcribed rather than to be idiomatic, and
 * `regions/tests/geometry-golden.json` holds every implementation to the same
 * bytes and the same probes.
 *
 * Coordinates are 1e-6-degree integers throughout. That is what makes the
 * boundary rule exact: a point on a boundary is inside, decided by integer
 * arithmetic rather than by whichever epsilon each language would have
 * chosen.
 */

export const GEOMETRY_FORMAT_VERSION = 1;
export const COORD_SCALE = 1_000_000;

export const RING_EXTERIOR = 0;
export const RING_HOLE = 1;

export class GeometryError extends Error {}

/** Quantize a degree value onto the storage grid, half away from zero. */
export function toE6(degrees) {
  const scaled = degrees * COORD_SCALE;
  return scaled >= 0 ? Math.floor(scaled + 0.5) : -Math.floor(-scaled + 0.5);
}

/** Convert a stored coordinate back to degrees. */
export function fromE6(value) {
  return value / COORD_SCALE;
}

/** Decode one polygon component: an exterior ring and its holes. */
export function decode(bytes) {
  if (bytes.length === 0) {
    throw new GeometryError("empty geometry blob");
  }
  const version = bytes[0];
  if (version !== GEOMETRY_FORMAT_VERSION) {
    throw new GeometryError(`unsupported geometry format version ${version}`);
  }

  let offset = 1;
  const varint = () => {
    let result = 0;
    let shift = 0;
    for (;;) {
      if (offset >= bytes.length) {
        throw new GeometryError("truncated varint");
      }
      const byte = bytes[offset++];
      // Numbers stay exact: coordinates are well inside 32 bits, and the
      // shift is bounded below the point where doubles lose integers.
      result += (byte & 0x7f) * 2 ** shift;
      if ((byte & 0x80) === 0) return result;
      shift += 7;
      if (shift > 49) throw new GeometryError("varint too long");
    }
  };
  const zigzag = () => {
    const raw = varint();
    return raw % 2 === 0 ? raw / 2 : -(raw + 1) / 2;
  };

  const ringCount = varint();
  const rings = [];
  for (let index = 0; index < ringCount; index += 1) {
    if (offset >= bytes.length) {
      throw new GeometryError("truncated ring header");
    }
    const role = bytes[offset++];
    if (index === 0 && role !== RING_EXTERIOR) {
      throw new GeometryError("geometry part has no exterior ring");
    }
    const pointCount = varint();
    const points = new Int32Array(pointCount * 2);
    let longitude = 0;
    let latitude = 0;
    for (let point = 0; point < pointCount; point += 1) {
      longitude += zigzag();
      latitude += zigzag();
      points[point * 2] = longitude;
      points[point * 2 + 1] = latitude;
    }
    rings.push({ role, points });
  }
  if (offset !== bytes.length) {
    throw new GeometryError("trailing bytes after geometry blob");
  }
  return rings;
}

/**
 * Exact integer point-in-polygon, boundary inclusive.
 *
 * A point exactly on a boundary counts as inside, everywhere. Two abutting
 * regions therefore both claim their shared edge, which costs an operator one
 * extra entry in a list they are reviewing anyway; a gap between them would
 * leave a position with no region at all.
 */
export function pointInRings(rings, longitudeE6, latitudeE6) {
  let exterior = null;
  for (const ring of rings) {
    if (onRing(ring, longitudeE6, latitudeE6)) return true;
    if (ring.role === RING_EXTERIOR && exterior === null) exterior = ring;
  }
  if (exterior === null) return false;
  if (!strictlyInside(exterior, longitudeE6, latitudeE6)) return false;
  for (const ring of rings) {
    if (ring.role === RING_HOLE && strictlyInside(ring, longitudeE6, latitudeE6)) {
      return false;
    }
  }
  return true;
}

function onRing(ring, x, y) {
  const points = ring.points;
  const count = points.length / 2;
  for (let index = 0; index < count; index += 1) {
    const next = (index + 1) % count;
    const x1 = points[index * 2];
    const y1 = points[index * 2 + 1];
    const x2 = points[next * 2];
    const y2 = points[next * 2 + 1];
    if ((x2 - x1) * (y - y1) - (y2 - y1) * (x - x1) !== 0) continue;
    if (
      Math.min(x1, x2) <= x && x <= Math.max(x1, x2) &&
      Math.min(y1, y2) <= y && y <= Math.max(y1, y2)
    ) {
      return true;
    }
  }
  return false;
}

/**
 * Crossing-number test with a half-open rule on each edge's vertical span, so
 * a ray through a vertex counts once rather than twice or not at all.
 */
function strictlyInside(ring, x, y) {
  const points = ring.points;
  const count = points.length / 2;
  let inside = false;
  for (let index = 0; index < count; index += 1) {
    const next = (index + 1) % count;
    const x1 = points[index * 2];
    const y1 = points[index * 2 + 1];
    const x2 = points[next * 2];
    const y2 = points[next * 2 + 1];
    if ((y1 > y) !== (y2 > y)) {
      const side = (x2 - x1) * (y - y1) - (y2 - y1) * (x - x1);
      if (side !== 0 && side > 0 === y2 > y1) inside = !inside;
    }
  }
  return inside;
}
