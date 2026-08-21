/**
 * The sampled-dilation membership rule, in JavaScript.
 *
 * Expanded coverage is not stored as geometry. A region's effective
 * membership is *defined* as: a position belongs to a region if any point of a
 * fixed sample pattern — the position itself, six points at half the region's
 * expansion distance, and twelve at the full distance — lands inside the
 * region's core. The pattern is the semantics, not an approximation of it,
 * which is what lets this file, the Rust reader, and the Python builder agree
 * exactly rather than approximately.
 *
 * Mirrors `crates/umsh-regiondb/src/sampling.rs` operation for operation.
 */

/** Mean Earth radius, matching the suggested-default tie-break. */
export const EARTH_RADIUS_M = 6_371_008.8;

/** Bearings of the full-distance ring, degrees clockwise from north. */
export const FULL_RING_BEARINGS = [0, 30, 60, 90, 120, 150, 180, 210, 240, 270, 300, 330];

/** Bearings of the half-distance ring. */
export const HALF_RING_BEARINGS = [0, 60, 120, 180, 240, 300];

const RADIANS = Math.PI / 180;
const DEGREES = 180 / Math.PI;

/** Spherical direct problem: where `distanceM` at `bearingDeg` lands. */
export function destination(latitude, longitude, bearingDeg, distanceM) {
  const angular = distanceM / EARTH_RADIUS_M;
  const bearing = bearingDeg * RADIANS;
  const lat1 = latitude * RADIANS;
  const sinLat2 =
    Math.sin(lat1) * Math.cos(angular) +
    Math.cos(lat1) * Math.sin(angular) * Math.cos(bearing);
  const lat2 = Math.asin(Math.min(1, Math.max(-1, sinLat2)));
  const lon2 =
    longitude * RADIANS +
    Math.atan2(
      Math.sin(bearing) * Math.sin(angular) * Math.cos(lat1),
      Math.cos(angular) - Math.sin(lat1) * sinLat2,
    );
  return [lat2 * DEGREES, lon2 * DEGREES];
}

/**
 * Every position to test against core geometry, the position itself first.
 *
 * The position leads so a caller can stop on a core hit, and so the
 * core-versus-expanded distinction falls out of the same loop: a hit at index
 * zero is core, a hit anywhere later is expanded.
 */
export function samplePositions(latitude, longitude, expansionM) {
  const positions = [[latitude, longitude]];
  if (expansionM <= 0) return positions;
  for (const bearing of HALF_RING_BEARINGS) {
    positions.push(destination(latitude, longitude, bearing, expansionM / 2));
  }
  for (const bearing of FULL_RING_BEARINGS) {
    positions.push(destination(latitude, longitude, bearing, expansionM));
  }
  return positions;
}
