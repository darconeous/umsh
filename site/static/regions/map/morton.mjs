/**
 * The fixed lookup grid, in JavaScript.
 *
 * Mirrors `crates/umsh-regiondb/src/morton.rs`. The longitude wrap is written
 * as a floor rather than a remainder operator for the same reason it is
 * there: an IEEE remainder rounds half to even, and that is one more thing
 * for three implementations to agree about than this needs to be.
 */

export const MAX_DEPTH = 16;
export const GRID = 65536;

export class MortonError extends Error {}

/** Wrap longitude into [-180, 180). Exactly +180 wraps to -180. */
export function normalizeLongitude(longitude) {
  if (!Number.isFinite(longitude)) {
    throw new MortonError(`longitude ${longitude} is not finite`);
  }
  return longitude - 360 * Math.floor((longitude + 180) / 360);
}

/** Validate latitude, which is clamped into the grid rather than wrapped. */
export function checkLatitude(latitude) {
  if (!Number.isFinite(latitude)) {
    throw new MortonError(`latitude ${latitude} is not finite`);
  }
  if (latitude < -90 || latitude > 90) {
    throw new MortonError(`latitude ${latitude} is outside [-90, 90]`);
  }
  return latitude;
}

/** Grid coordinates of the cell containing a position. */
export function cellXy(latitude, longitude) {
  const lon = normalizeLongitude(longitude);
  const lat = checkLatitude(latitude);
  const x = Math.floor(((lon + 180) / 360) * GRID);
  const y = Math.floor(((lat + 90) / 180) * GRID);
  return [Math.min(Math.max(x, 0), GRID - 1), Math.min(Math.max(y, 0), GRID - 1)];
}

function spread(value) {
  let v = value & 0xffff;
  v = (v | (v << 8)) & 0x00ff00ff;
  v = (v | (v << 4)) & 0x0f0f0f0f;
  v = (v | (v << 2)) & 0x33333333;
  v = (v | (v << 1)) & 0x55555555;
  return v;
}

/** Interleave two 16-bit values, `x` into the even bits. */
export function interleave(x, y) {
  // `>>> 0` keeps the result an unsigned 32-bit value: the top bit of a
  // northern-hemisphere key would otherwise read as negative.
  return ((spread(x) | (spread(y) << 1)) >>> 0);
}

/** The maximum-depth Morton key for a position. */
export function key(latitude, longitude) {
  const [x, y] = cellXy(latitude, longitude);
  return interleave(x, y);
}
