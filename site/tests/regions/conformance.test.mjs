/**
 * The browser lookup engine, against the shared conformance fixture.
 *
 *     node --test "site/tests/regions/*.test.mjs"
 *
 * The map viewer answers a click with the same code the phone runs, so the
 * two must agree exactly — a viewer that could disagree with the runtime
 * would be worse than no viewer, because it would be believed. These are the
 * same fixtures `cargo test -p umsh-regiondb` and the Python suite replay:
 * `regions/tests/conformance.json` for lookups and
 * `regions/tests/geometry-golden.json` for the geometry codec.
 *
 * The database is opened here through node's built-in SQLite rather than the
 * WASM binding the page uses. What is under test is the lookup logic, and
 * keeping it free of any particular SQLite binding is what lets it be tested
 * without a browser.
 *
 * These live outside `site/static/` because everything under that directory
 * is copied verbatim into the published site.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { decode, pointInRings } from "../../static/regions/map/geometry.mjs";
import { interleave, key, normalizeLongitude } from "../../static/regions/map/morton.mjs";
import { samplePositions } from "../../static/regions/map/sampling.mjs";
import { RegionDb } from "../../static/regions/map/regiondb.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const regions = join(here, "..", "..", "..", "regions");

const fixtureDatabase = join(regions, "tests", "fixture", "fixture.regiondb");
const conformance = JSON.parse(readFileSync(join(regions, "tests", "conformance.json")));
const golden = JSON.parse(readFileSync(join(regions, "tests", "geometry-golden.json")));

/** Adapt node's SQLite to the row-array shape the reader expects. */
function openDatabase(path) {
  const database = new DatabaseSync(path, { readOnly: true });
  return {
    exec(sql, params = []) {
      if (sql.startsWith("PRAGMA")) {
        return database.prepare(sql).all().map((row) => Object.values(row));
      }
      return database
        .prepare(sql)
        .all(...params)
        .map((row) => Object.values(row));
    },
  };
}

const database = new RegionDb(openDatabase(fixtureDatabase));

test("opens the fixture and reports its version", () => {
  assert.equal(database.formatVersion, 1);
  assert.equal(database.datasetVersion, "fixture-1");
  assert.ok(database.regions.size > 0);
  assert.ok(database.metadata.has("content_hash"));
});

test("refuses a newer format version", () => {
  // A future release may add tables this build cannot interpret. Reading it
  // anyway would produce a plausible-looking but wrong region list.
  const handle = openDatabase(fixtureDatabase);
  const original = handle.exec;
  handle.exec = (sql, params) =>
    sql.startsWith("PRAGMA user_version") ? [[99]] : original(sql, params);
  assert.throws(() => new RegionDb(handle), /format version 99/);
});

test("geometry blobs match the golden vectors", () => {
  assert.equal(golden.geometry_format_version, 1);
  for (const entry of golden.cases) {
    const rings = decode(Uint8Array.from(Buffer.from(entry.blob_hex, "hex")));
    assert.equal(rings.length, entry.rings.length, entry.name);
    for (const [index, want] of entry.rings.entries()) {
      assert.equal(rings[index].role, want.role, entry.name);
      assert.deepEqual(
        Array.from(rings[index].points),
        want.points.flat(),
        `${entry.name}: vertices`,
      );
    }
    for (const probe of entry.probes) {
      assert.equal(
        pointInRings(rings, probe.lon_e6, probe.lat_e6),
        probe.inside,
        `${entry.name}: probe ${probe.lon_e6},${probe.lat_e6}`,
      );
    }
  }
});

test("the lookup grid agrees with the other implementations", () => {
  assert.equal(normalizeLongitude(180), -180);
  assert.equal(key(0, 180), key(0, -180));
  assert.equal(interleave(0xffff, 0), 0x55555555);
  assert.equal(interleave(0, 0xffff), 0xaaaaaaaa);
});

test("the sample pattern is nineteen points, position first", () => {
  const samples = samplePositions(37.5, -122.2, 2000);
  assert.equal(samples.length, 19);
  assert.deepEqual(samples[0], [37.5, -122.2]);
  assert.deepEqual(samplePositions(37.5, -122.2, 0), [[37.5, -122.2]]);
});

test("conformance cases replay exactly", () => {
  assert.equal(conformance.dataset_version, database.datasetVersion);
  assert.ok(conformance.cases.length > 0);

  for (const entry of conformance.cases) {
    const result = database.lookup(entry.lat, entry.lon);
    const where = `${entry.lat},${entry.lon}`;
    assert.deepEqual(
      result.matches.map((match) => match.regionKey),
      entry.region_keys,
      `matches at ${where}`,
    );
    assert.deepEqual(
      result.matches.map((match) => (match.membership === 0 ? "core" : "expanded")),
      entry.memberships,
      `membership at ${where}`,
    );
    assert.deepEqual(
      result.radioRegions.map((region) => region.name),
      entry.radio_names,
      `radio names at ${where}`,
    );
    assert.deepEqual(
      result.radioRegions.map((region) => region.code),
      entry.wire_codes,
      `wire codes at ${where}`,
    );
    assert.equal(
      result.suggestedDefaultRegion?.code ?? null,
      entry.default_wire_code,
      `suggested default at ${where}`,
    );
  }
});

test("a position with no coverage returns nothing", () => {
  const result = database.lookup(10, -150);
  assert.equal(result.radioRegions.length, 0);
  assert.equal(result.suggestedDefaultRegion, null);
});

test("rejects positions that are not on the globe", () => {
  for (const [latitude, longitude] of [[91, 0], [-91, 0], [NaN, 0], [0, Infinity]]) {
    assert.throws(() => database.lookup(latitude, longitude), `${latitude},${longitude}`);
  }
});
