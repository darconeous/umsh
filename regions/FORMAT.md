# The `.regiondb` format

A region database is an ordinary SQLite database with a defined UMSH schema and
a project-specific extension. Any platform with SQLite can read one, and any
developer can open one with standard tools.

Geometry is stored in a small blob encoding defined here rather than as
SpatiaLite geometry, for two reasons. Requiring a native SQLite extension on
iOS is precisely the dependency this design avoids, and integer coordinates
make the boundary rule exact instead of epsilon-dependent.

## Versioning

Two versions, answering two different questions.

- `PRAGMA user_version` is the **format version**, currently `1`. A runtime
  that finds a version it does not implement must refuse the file. Reading a
  newer database on a best-effort basis would produce a plausible-looking but
  wrong region list, which is worse than an error.
- `metadata.dataset_version` is the **data release**, such as `2026.08.1`. It
  is independent of the wire protocol, the mobile API, and firmware versions. A
  newer application reads older format-compatible databases.

`metadata.content_hash` is a SHA-256 over the normalized logical tables. It is
the reproducibility guarantee: two builds of the same inputs agree here even
where SQLite's own bytes differ.

## Schema

```sql
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE sources (
    id INTEGER PRIMARY KEY,
    source_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    url TEXT, revision TEXT, sha256 TEXT, license TEXT, attribution TEXT
);

CREATE TABLE regions (
    id INTEGER PRIMARY KEY,
    region_key TEXT NOT NULL UNIQUE,   -- "iata-airport:SFO"
    namespace TEXT NOT NULL,           -- tooling only, never transmitted
    code TEXT NOT NULL,
    display_name TEXT NOT NULL,
    radio_name TEXT NOT NULL,          -- what a repeater is configured with
    wire_code INTEGER NOT NULL,        -- canonical umsh_core::RegionCode
    kind TEXT NOT NULL,
    layer TEXT NOT NULL,
    priority INTEGER NOT NULL,         -- presentation order
    default_rank INTEGER,              -- eligibility for the packet default
    expansion_m INTEGER NOT NULL DEFAULT 0,
    site_lon REAL, site_lat REAL,      -- generating site, for nearest tie-breaks
    source_id INTEGER,
    flags INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    FOREIGN KEY(source_id) REFERENCES sources(id)
);

CREATE TABLE geometry_parts (
    id INTEGER PRIMARY KEY,
    region_id INTEGER NOT NULL,
    role INTEGER NOT NULL,             -- 0 = core, 1 = effective
    min_lon REAL NOT NULL, min_lat REAL NOT NULL,
    max_lon REAL NOT NULL, max_lat REAL NOT NULL,
    geometry BLOB NOT NULL,
    FOREIGN KEY(region_id) REFERENCES regions(id)
);

CREATE VIRTUAL TABLE effective_rtree USING rtree(
    part_id, min_lon, max_lon, min_lat, max_lat
);

CREATE TABLE region_sets (id INTEGER PRIMARY KEY, region_ids BLOB NOT NULL);

CREATE TABLE lookup_ranges (
    start_key INTEGER PRIMARY KEY,
    end_key INTEGER NOT NULL,
    base_set_id INTEGER NOT NULL,
    candidate_region_ids BLOB,
    FOREIGN KEY(base_set_id) REFERENCES region_sets(id)
);

CREATE TABLE provenance (
    region_id INTEGER NOT NULL,
    source_id INTEGER,
    source_feature_id TEXT,
    detail TEXT,
    PRIMARY KEY(region_id, source_id, source_feature_id, detail)
);
```

### Core geometry is stored only where it differs

A region with `expansion_m = 0` has identical core and effective geometry, and
the build writes it once. **A region with no `role = 0` rows has its effective
geometry as its core**, and a position inside it is a core match. Readers must
implement this; treating a missing core as an empty one would report every
country and state match as merely expanded.

## Geometry blobs

One blob is one connected polygon component: an exterior ring and its holes.
Storing components separately is what keeps the R-tree bounding boxes useful
for a country with remote islands.

```
u8   geometry_format_version          # 1
varint ring_count
for each ring:
    u8   ring_role                    # 0 = exterior, 1 = hole
    varint point_count
    zigzag_varint lon_e6              # first vertex, absolute
    zigzag_varint lat_e6
    repeated point_count - 1 times:
        zigzag_varint delta_lon_e6    # from the previous vertex
        zigzag_varint delta_lat_e6
```

Coordinates are in 1e-6 degrees, about 11 cm at the equator, and fit in signed
32 bits. The first ring must be the exterior. Ring closure is implicit: the
repeated final vertex is never stored.

Golden vectors: `tests/geometry-golden.json`.

## Point-in-polygon

**A point exactly on a boundary is inside**, in every implementation.

Two abutting regions therefore both claim their shared edge. That costs an
operator one extra entry in a list they are reviewing anyway; the alternative
leaves positions with no region at all, which is a bug nobody would find until
a repeater in the wrong place stopped forwarding.

Tests are exact integer orientation tests on the quantized coordinates, never
epsilon comparisons. A ring's interior uses a crossing-number test with a
half-open rule on each edge's vertical span, so a ray through a vertex counts
once. Holes are respected, and a point on a hole's boundary is inside the
polygon.

## The lookup grid

Longitude is wrapped into `[-180, 180)` and latitude validated against
`[-90, 90]`; NaN and infinity are errors, and exactly +180 wraps to -180 so the
grid is a partition. The wrap is written as

```
longitude - 360 * floor((longitude + 180) / 360)
```

in every implementation, rather than as each language's remainder operator,
because an IEEE remainder rounds half to even and that is one more thing for
three implementations to agree about than this needs to be.

Each axis is quantized to 16 bits and interleaved, longitude into the even
bits, giving a 32-bit Z-order key.

## Lookup

```sql
SELECT start_key, end_key, base_set_id, candidate_region_ids
FROM lookup_ranges WHERE start_key <= ?1 ORDER BY start_key DESC LIMIT 1;
```

Verify `?1 <= end_key`; a key past the range's end has no coverage. The base
set is the answer for every position in the range. If `candidate_region_ids` is
empty, it is the whole answer. Otherwise those few regions — and only those —
are tested against their exact effective geometry and unioned in.

`region_ids` blobs are sorted region ids stored as varint gaps.

The cache is an optimization over the exact polygons in the same file. It is
never a second source of truth, and the build proves that by comparing the
cached path against an exhaustive scan over thousands of positions weighted
toward boundaries. A database whose cache is disabled is still correct, only
slower.

## Result policy

Matches are ordered by `priority`, then core before expanded, then region key.
The radio-facing list is that order with duplicate `wire_code` values dropped,
so the airport and metro senses of `SFO` collapse to one entry while both
survive as semantic matches.

The suggested default region is the eligible match with the lowest
`default_rank`, preferring core over expanded, breaking ties by distance to the
generating site. Only the IATA-derived layers carry a `default_rank`: a country
or state is large enough that tagging a flood with one would broaden its scope
far past what an operator setting up a repeater intends.

That tie-break distance is a great-circle distance on a sphere of radius
6 371 008.8 m — deliberately not the WGS84 model the build measures radius caps
and buffers with. It is never a measurement, only an ordering between two
candidates already within a hundred kilometers of each other, and keeping it
spherical means a browser can reproduce it with arithmetic rather than a
geodesic library. Where two expansion buffers overlap the two sites can be
equidistant to within tens of meters, and there the two models genuinely
disagree about the winner.

## Conformance

`tests/conformance.json` carries positions and their expected results, and
every implementation must reproduce it exactly. `tests/regioncode-vectors.json`
carries a digest over all 47,988 short codes plus named-region vectors, so a
port of the region-code derivation can be checked against `umsh-core` rather
than trusted.
