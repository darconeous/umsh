/**
 * Reading a compiled `.regiondb` in the browser.
 *
 * The viewer opens the actual released database — the same file a phone
 * downloads — rather than a separately generated approximation of it. That is
 * the whole point: a map that could disagree with the runtime would be worse
 * than no map, because it would be believed.
 *
 * This module takes any handle exposing `exec(sql, params) -> rows`, so the
 * WASM SQLite binding stays a detail of the page rather than a dependency of
 * the lookup logic, and the node conformance tests can drive it directly.
 */

import { decode, pointInRings, toE6, fromE6 } from "./geometry.mjs";
import { key as mortonKey, normalizeLongitude, checkLatitude } from "./morton.mjs";
import { samplePositions } from "./sampling.mjs";

export const FORMAT_VERSION = 1;

export const MEMBERSHIP_CORE = 0;
export const MEMBERSHIP_EXPANDED = 1;

export class RegionDbError extends Error {}

/** Decode a set of region ids stored as varint gaps. */
export function decodeRegionIds(bytes) {
  const identifiers = [];
  let value = 0;
  let shift = 0;
  let current = 0;
  for (const byte of bytes) {
    value += (byte & 0x7f) * 2 ** shift;
    if (byte & 0x80) {
      shift += 7;
      continue;
    }
    current += value;
    identifiers.push(current);
    value = 0;
    shift = 0;
  }
  return identifiers;
}

export class RegionDb {
  constructor(handle) {
    this.handle = handle;

    const version = handle.exec("PRAGMA user_version")[0]?.[0] ?? 0;
    if (version < 1) throw new RegionDbError("file is not a region database");
    if (version > FORMAT_VERSION) {
      throw new RegionDbError(
        `region database declares format version ${version}; this build understands ` +
          `up to ${FORMAT_VERSION}`,
      );
    }
    this.formatVersion = version;

    this.metadata = new Map(handle.exec("SELECT key, value FROM metadata"));

    this.regions = new Map();
    for (const row of handle.exec(
      "SELECT id, namespace, code, radio_name, wire_code, layer, priority, " +
        "default_rank, expansion_m, site_lon, site_lat FROM regions",
    )) {
      const [id, namespace, code, radioName, wireCode, layer, priority, defaultRank,
        expansionM, siteLon, siteLat] = row;
      this.regions.set(id, {
        regionId: id,
        namespace,
        code,
        regionKey: `${namespace}:${code}`,
        // A stored radio name is the exception: it exists only where the wire
        // string differs from the code, which today means custom regions.
        radioName: radioName === null ? code : radioName,
        wireCode,
        layer,
        priority,
        defaultRank,
        expansionM,
        site: siteLon === null ? null : [siteLon, siteLat],
      });
    }

    this.hasLookupRanges =
      handle.exec("SELECT 1 FROM lookup_ranges LIMIT 1").length > 0;
  }

  get datasetVersion() {
    return this.metadata.get("dataset_version") ?? "unknown";
  }

  quantize(latitude, longitude) {
    return [toE6(normalizeLongitude(longitude)), toE6(checkLatitude(latitude))];
  }

  /** Whether one position lands in a region's core geometry. */
  coreHit(regionId, latitude, longitude) {
    const [lonE6, latE6] = this.quantize(latitude, longitude);
    const rows = this.handle.exec(
      "SELECT geometry, min_lon, min_lat, max_lon, max_lat FROM geometry_parts " +
        "WHERE region_id = ? ORDER BY id",
      [regionId],
    );
    for (const [payload, minLon, minLat, maxLon, maxLat] of rows) {
      // The stored bounds are the part's own quantized extent, so a point
      // outside them cannot lie on its boundary either.
      if (
        lonE6 < toE6(minLon) || lonE6 > toE6(maxLon) ||
        latE6 < toE6(minLat) || latE6 > toE6(maxLat)
      ) {
        continue;
      }
      if (pointInRings(decode(payload), lonE6, latE6)) return true;
    }
    return false;
  }

  /** Sampled-dilation membership: core, expanded, or not a member. */
  membership(regionId, latitude, longitude) {
    const region = this.regions.get(regionId);
    if (region === undefined) return null;
    const samples = samplePositions(latitude, longitude, region.expansionM);
    for (let index = 0; index < samples.length; index += 1) {
      if (this.coreHit(regionId, samples[index][0], samples[index][1])) {
        return index === 0 ? MEMBERSHIP_CORE : MEMBERSHIP_EXPANDED;
      }
    }
    return null;
  }

  /** The fast path: cached ranges when present, the R-tree otherwise. */
  memberships(latitude, longitude) {
    if (!this.hasLookupRanges) return this.rtreeMemberships(latitude, longitude);

    const lookup = mortonKey(latitude, longitude);
    const rows = this.handle.exec(
      "SELECT end_key, base_set_id, candidate_region_ids FROM lookup_ranges " +
        "WHERE start_key <= ? ORDER BY start_key DESC LIMIT 1",
      [lookup],
    );
    const found = new Map();
    if (rows.length === 0) return found;
    const [endKey, baseSetId, candidates] = rows[0];
    if (lookup > endKey) return found;

    const payload = this.handle.exec(
      "SELECT region_ids FROM region_sets WHERE id = ?",
      [baseSetId],
    )[0]?.[0];
    // Base-set regions are known members of the whole cell, but core versus
    // expanded is still a property of the exact position.
    for (const regionId of payload ? decodeRegionIds(payload) : []) {
      const value = this.membership(regionId, latitude, longitude);
      found.set(regionId, value === null ? MEMBERSHIP_EXPANDED : value);
    }
    if (candidates) {
      for (const regionId of decodeRegionIds(candidates)) {
        const value = this.membership(regionId, latitude, longitude);
        if (value !== null) found.set(regionId, value);
      }
    }
    return found;
  }

  /**
   * Candidates from the padded R-tree boxes, then the sampled test.
   *
   * Boxes are stored padded by each region's expansion distance and may
   * extend past ±180; querying the longitude at all three wrappings is what
   * keeps a position on one side of the antimeridian able to see a region
   * whose padded box hangs over from the other side.
   */
  rtreeMemberships(latitude, longitude) {
    const [lonE6, latE6] = this.quantize(latitude, longitude);
    const lon = fromE6(lonE6);
    const lat = fromE6(latE6);
    const candidates = new Set();
    for (const wrapped of [lon - 360, lon, lon + 360]) {
      for (const [regionId] of this.handle.exec(
        "SELECT DISTINCT p.region_id FROM effective_rtree r " +
          "JOIN geometry_parts p ON p.id = r.part_id " +
          "WHERE r.min_lon <= ? AND r.max_lon >= ? AND r.min_lat <= ? AND r.max_lat >= ?",
        [wrapped, wrapped, lat, lat],
      )) {
        candidates.add(regionId);
      }
    }
    const found = new Map();
    for (const regionId of candidates) {
      const value = this.membership(regionId, latitude, longitude);
      if (value !== null) found.set(regionId, value);
    }
    return found;
  }

  /** Look up a position. */
  lookup(latitude, longitude) {
    this.quantize(latitude, longitude);
    const found = this.memberships(latitude, longitude);

    const matches = [];
    for (const [regionId, membership] of found) {
      const region = this.regions.get(regionId);
      if (region !== undefined) matches.push({ ...region, membership });
    }
    matches.sort(
      (first, second) =>
        first.priority - second.priority ||
        first.membership - second.membership ||
        (first.regionKey < second.regionKey ? -1 : first.regionKey > second.regionKey ? 1 : 0),
    );

    return {
      latitude,
      longitude,
      matches,
      radioRegions: radioRegions(matches),
      suggestedDefaultRegion: suggestedDefault(matches, latitude, longitude),
      datasetVersion: this.datasetVersion,
    };
  }
}

/**
 * Collapse semantic matches onto the list a radio would be given.
 *
 * Two matches that encode identically are one region as far as the radio is
 * concerned — the airport and metro senses of a code, say — so the first in
 * policy order takes the slot.
 */
export function radioRegions(matches) {
  const seen = new Set();
  const out = [];
  for (const match of matches) {
    if (seen.has(match.wireCode)) continue;
    seen.add(match.wireCode);
    out.push({ name: match.radioName, code: match.wireCode });
  }
  return out;
}

/**
 * Great-circle distance to a match's generating site, for breaking ties among
 * overlapping expansion margins. Spherical on purpose: it only ever orders two
 * candidates already within a hundred kilometers, and every implementation
 * reproduces it with plain arithmetic.
 */
function siteDistance(match, latitude, longitude) {
  if (match.site === null) return Infinity;
  const [siteLongitude, siteLatitude] = match.site;
  const lat1 = (latitude * Math.PI) / 180;
  const lat2 = (siteLatitude * Math.PI) / 180;
  const deltaLat = lat2 - lat1;
  const deltaLon = ((siteLongitude - longitude) * Math.PI) / 180;
  const haversine =
    Math.sin(deltaLat / 2) ** 2 +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(deltaLon / 2) ** 2;
  return 2 * Math.asin(Math.sqrt(haversine)) * 6_371_008.8;
}

/**
 * Choose the region to suggest as the packet default. Metro regions rank
 * first where one exists, then the IATA-derived layers; country and state
 * regions are deliberately never chosen, being large enough that tagging a
 * flood with one broadens its scope past what an operator intends.
 */
export function suggestedDefault(matches, latitude, longitude) {
  let best = null;
  for (const match of matches) {
    if (match.defaultRank === null) continue;
    if (
      best === null ||
      match.defaultRank < best.defaultRank ||
      (match.defaultRank === best.defaultRank &&
        (match.membership < best.membership ||
          (match.membership === best.membership &&
            (siteDistance(match, latitude, longitude) <
              siteDistance(best, latitude, longitude) ||
              (siteDistance(match, latitude, longitude) ===
                siteDistance(best, latitude, longitude) &&
                match.regionKey < best.regionKey)))))
    ) {
      best = match;
    }
  }
  return best === null ? null : { name: best.radioName, code: best.wireCode };
}
