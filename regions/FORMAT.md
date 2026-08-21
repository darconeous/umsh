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
- `metadata.dataset_version` is the **data release**: ISO year, ISO week, and
  the build within that week, such as `2026.34.2`. Upstream boundary and
  airport data moves on no calendar of its own, so the version says when a
  build was cut rather than claiming to describe what changed; the week is a
  finer grain than a month without inviting a daily cadence. It is independent
  of the wire protocol, the mobile API, and firmware versions. A newer
  application reads older format-compatible databases.

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
    namespace TEXT NOT NULL,           -- tooling only, never transmitted
    code TEXT NOT NULL,                -- namespace-local code
    radio_name TEXT,                   -- only when it differs from code
    wire_code INTEGER NOT NULL,        -- canonical umsh_core::RegionCode
    layer TEXT NOT NULL,
    priority INTEGER NOT NULL,         -- presentation order
    default_rank INTEGER,              -- eligibility for the packet default
    expansion_m INTEGER NOT NULL DEFAULT 0,
    site_lon REAL, site_lat REAL,      -- generating site, for nearest tie-breaks
    source_id INTEGER,
    flags INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(source_id) REFERENCES sources(id),
    UNIQUE(namespace, code)
);

CREATE TABLE geometry_parts (
    id INTEGER PRIMARY KEY,
    region_id INTEGER NOT NULL,
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

The table holds what lookup needs and nothing else. A region's key is
`namespace || ':' || code`, composed by readers rather than stored. Display
names, municipalities, and other prose stay in the committed extracts;
`radio_name` is NULL wherever the wire string is simply the code, which is
every region except the custom ones.

### Only core geometry is stored

`geometry_parts` holds each region's core polygons and nothing else. The
expansion margin — the overlap that lets a repeater near a border serve both
sides — is the `expansion_m` number, resolved at lookup time by the sampled
rule below. The R-tree box of each part is the part's bounds grown by its
region's expansion distance (latitude clamped at the poles, longitude allowed
to run past ±180), so the candidate filter still finds a region from inside
its margin.

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

## The sampled expansion rule

Effective membership is *defined* by sampling, not approximated by it:

> A position is a member of a region if any of the following positions lies
> inside the region's core geometry (boundary inclusive): the position itself;
> six points at half the region's expansion distance, at bearings 0°, 60°,
> 120°, 180°, 240°, 300°; and twelve points at the full distance, at bearings
> every 30° from 0°. A hit on the position itself is a **core** match; a hit
> on any other sample is an **expanded** match. A region whose expansion is
> zero is tested at the position alone.

Destinations are computed on the mean-radius sphere (R = 6 371 008.8 m) with
the standard direct formulas — the same model as the tie-break below, chosen
because every platform reproduces it with plain arithmetic. Since the pattern
is the semantics, implementations agree exactly; against true geodesic
dilation the outer edge scallops by a few hundred meters between samples,
which is well inside what an expansion margin means.

## Lookup

```sql
SELECT start_key, end_key, base_set_id, candidate_region_ids
FROM lookup_ranges WHERE start_key <= ?1 ORDER BY start_key DESC LIMIT 1;
```

Verify `?1 <= end_key`; a key past the range's end has no coverage. The base
set lists regions that are members everywhere in the range (their core or
expanded status still depends on the exact position). If
`candidate_region_ids` is non-empty, those few regions — and only those — are
resolved with the sampled rule and unioned in.

A database built without the cache has an empty `lookup_ranges` table. There
the reader collects candidates from `effective_rtree` instead — querying the
longitude at all three wrappings (λ−360, λ, λ+360), because padded boxes may
hang past the antimeridian — and resolves each with the same sampled rule.

`region_ids` blobs are sorted region ids stored as varint gaps.

The cache and the R-tree are optimizations over the same core polygons; they
are never a second source of truth. The build proves it by comparing the fast
paths against an exhaustive scan over thousands of positions weighted toward
boundaries.

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
