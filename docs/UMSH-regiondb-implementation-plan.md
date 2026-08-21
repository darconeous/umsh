# UMSH Geographic Region Database — Comprehensive Implementation Plan

**Repository:** `https://github.com/darconeous/umsh`  
**Primary data directory:** `regions/`  
**Document date:** 2026-08-20  
**Status:** Implementation plan / agent handoff  
**Audience:** An implementation agent with no access to the preceding design conversation

---

## 1. Objective

Implement a geographic region system for UMSH that can take a latitude/longitude and return the set of UMSH region identifiers that a repeater at that location should normally be configured to accept.

The system has two related purposes:

1. **Runtime lookup:** An iPhone, desktop application, command-line tool, or web application should be able to load one small downloadable database file, supply a geographic position, and receive the appropriate ordered list of region identifiers.
2. **Human inspection:** The same compiled database should be viewable on an interactive map so that generated boundaries, overlaps, expansions, overrides, and lookup results can be inspected and debugged.

The downloaded database should ideally be only a few megabytes. Lookup should be comfortably fast on older iPhone hardware; a normal lookup should be far below one second, with a design target of tens of milliseconds after the database has been opened.

The difficult geographic work must happen at **build time**, not on the radio or phone. Runtime clients should not need to know how Voronoi cells, commercial-airport classification, metropolitan boundaries, administrative boundaries, expansion buffers, or overrides are derived.

---

## 2. Existing UMSH region-code behavior that must be preserved

Before implementing this project, read these existing files in the UMSH repository:

- `crates/umsh-core/src/region.rs`
- `docs/protocol/src/packet-options.md`, especially “Region Code” and “Region Code Encoding”
- `docs/protocol/src/repeater-operation.md`, especially “Region policy”
- `crates/umsh-mobile-core/src/ulcp.rs`
- `apps/ios/README.md`
- repository-root `CLAUDE.md`

These files are authoritative for current UMSH protocol and repository conventions.

### 2.1 RegionCode wire representation

UMSH already has a 16-bit `RegionCode`.

There are two encoding spaces:

- **Short code:** one to three ASCII letters or digits, encoded directly with ARNCE/HAM-16. Three letters are conventionally an IATA code; two are conventionally an ISO 3166-1 country or bare subdivision code. Digit-bearing short codes encode faithfully but share their space with the hashes and must never be displayed as text.
- **Named region:** a human-readable name is ASCII-case-folded, hashed with SHA-256, and transformed when necessary so that the result cannot decode as one to three letters.

This distinction is deliberate and must not be replaced by a new wire encoding as part of this project.

Examples:

- `MFR` → short code (IATA convention)
- `SFO` → short code (IATA convention)
- `US` → short code (ISO 3166-1 convention)
- `OR` → short code (subdivision convention)
- `Rogue Valley` → named region (hashed)

`RegionCode::from_short_code` and `RegionCode::from_name` in `umsh-core` are the canonical implementations. Any string of one to three ASCII alphanumerics is a short code unconditionally—there is no such thing as a two- or three-letter "named" region. The builder and runtime should use these functions rather than reimplementing the ARNCE/hash transform independently wherever possible.

### 2.2 Namespaces are database metadata, not radio namespaces

The region database needs internal namespaces so that tooling can distinguish, for example:

- `iata-airport:SFO`
- `iata-location:SQL`
- `iata-metro:SFO`
- `country:US`
- `us-state:CA`
- `custom:rogue-valley`

These namespaces are **not sent to the radio**.

The radio-facing region list consists of the normal UMSH region strings / `RegionCode` values. Therefore:

- both `iata-airport:SFO` and `iata-metro:SFO` produce the same radio region `SFO`;
- `country:IN` (India) and `us-state:IN` (Indiana) may both use the radio-facing name `IN`. They encode to the same short code by construction—not a hash collision—and the existing UMSH model deliberately tolerates geographically remote regions sharing a code;
- duplicate final `RegionCode` values are collapsed.

The detailed lookup result must preserve the semantic matches even when the final radio list deduplicates them.

### 2.3 Existing repeater settings

UMSH already exposes repeater configuration in the mobile facade. `UlcpRepeaterSettingsRecord` contains:

- `enabled: bool` — whether the repeater role is on;
- `regions: Vec<String>` — the configured region filter, expressed as region strings (empty imposes no regional restriction);
- `default_region: Option<Vec<u8>>` — the 2-octet region inserted into an otherwise untagged flood;
- `min_rssi_dbm: Option<i16>` and `min_snr_db: Option<i8>` — signal-quality forwarding thresholds, not relevant to this project.

The geographic database should return both:

- an ordered list suitable for the `regions` field; and
- a suggested `default_region`.

The database must not directly mutate a radio. Device configuration remains an application policy / UI action.

---

## 3. Geographic semantics

The compiler must produce final effective region coverage for several independent region classes. These classes may overlap.

A lookup returns **all effective regions covering the requested position**, ordered by policy and deduplicated for the radio-facing result.

### 3.1 Commercial-airport region

Purpose: provide a broad, recognizable IATA label that most people in the area would associate with normal passenger air travel.

Definition:

> A qualifying commercial airport is an airport that provides ordinary passenger transportation service to the general public, as opposed to a general-aviation airport used primarily by private, business, training, cargo-only, emergency, or similar aviation.

A qualifying airport may be large or small. The important distinction is ordinary public passenger service, not runway size.

General-aviation fields such as San Carlos Airport (`SQL`) must **not** become commercial-airport regions merely because an upstream database happens to set `scheduled_service=yes`.

The commercial-airport layer is generated as a nearest-site partition, subject to a maximum radius.

Initial default:

```text
commercial_airport_max_radius_m = 100_000
```

For a point more than 100 km from every qualifying commercial airport, the commercial-airport layer contributes no region.

### 3.2 Nearest positioned IATA location

Purpose: provide a finer local IATA geographic label.

The initial source is the positioned IATA records available from the airport dataset. Any record with:

- a valid three-letter IATA code, and
- defensible coordinates

is eligible regardless of whether it is a commercial passenger airport, general-aviation airport, heliport, seaplane base, etc.

Initial default:

```text
positioned_iata_max_radius_m = 100_000
```

The positioned-IATA layer is also a nearest-site partition capped by radius.

The commercial-airport and positioned-IATA regions may resolve to the same IATA code. The detailed result preserves both semantic matches, but the radio-facing list contains that code only once.

### 3.3 Important source-coverage limitation

The OurAirports/datasets source is primarily an **airport** database. IATA location codes can also identify rail stations and other intermodal locations.

The V1 architecture must therefore call this source “positioned IATA locations” in a source-neutral way and support adding additional point datasets later. Do not hard-code the assumption that every physical IATA location is an airport into the compiled format.

V1 may ship with airport-derived positioned IATA locations only if no suitable open global rail/intermodal source is yet available. Document this limitation in the generated metadata.

### 3.4 Metropolitan IATA regions

Metropolitan IATA codes such as `NYC`, `LON`, or `WAS` are **containment regions**, not nearest-neighbor regions.

A metropolitan code is returned only when the lookup position lies inside the explicitly defined polygon for that metro area.

Do not assign the “nearest” metro area to a point outside its polygon.

IATA does not provide a useful official land boundary for these codes. UMSH therefore defines its own geographic interpretation. Every metro polygon must carry provenance and notes explaining the boundary source and interpretation.

### 3.5 Country regions

A point on land should receive the two-letter ISO 3166-1 alpha-2 code for the containing country.

Examples:

```text
US
CA
GB
FR
IN
```

These are two-letter UMSH short codes, encoded directly rather than hashed.

V1 should treat country regions as land containment. Territorial waters should not be silently inferred. Maritime regions can be added later as a separate policy if desired.

### 3.6 US-state regions

A point within the United States should additionally receive its US state postal abbreviation.

Examples:

```text
OR
CA
IN
NY
```

Include the 50 states and District of Columbia in V1. Decide explicitly whether US territories are represented as state-like regions; do not accidentally include or exclude them based solely on source schema.

These are two-letter UMSH short codes, encoded directly rather than hashed.

### 3.7 Human-defined regions

The source tree must allow arbitrary explicitly authored regions, for example:

```text
Rogue Valley
SF Bay Area
Southern Oregon
Ashland
```

These should normally use the human-readable region name as the radio-facing name, subject to the existing UMSH 24-byte UTF-8 region-name limit.

Custom regions may overlap any other region.

### 3.8 Region expansion / overlap

Every region may have an outward expansion distance.

This exists specifically so repeaters near a border can be configured for both adjacent regions.

Example:

```yaml
expansion_m: 10000
```

A region's effective routing coverage is:

```text
effective geometry = outward_buffer(core geometry, expansion_m)
```

Expansion occurs **after** core geometry generation and after any core-boundary overrides.

Default expansion may be configured per layer, for example:

```yaml
defaults:
  commercial_airport:
    expansion_m: 10000
  positioned_iata:
    expansion_m: 5000
  metro:
    expansion_m: 0
  country:
    expansion_m: 0
  us_state:
    expansion_m: 0
```

These values are policy inputs, not hard-coded format rules. Start conservatively and make them easy to tune using the map.

Country and state expansion should default to zero.

### 3.9 Manual overrides

The source format must support manual changes to generated boundaries.

At minimum support:

- **force assignment** — inside a polygon, a particular region wins the core assignment for an exclusive generated layer;
- **include** — union a polygon into a region without removing other regions;
- **exclude** — subtract a polygon from a region;
- **replace** — replace an explicitly authored/non-generated core geometry.

For generated nearest-site layers, `force` is generally safer than a naïve “replace one Voronoi polygon” operation because changing one member of a partition affects its neighbors.

Example:

```yaml
id: override:mfd-east
layer: commercial_airport
operation: force
target: iata-airport:MFD
geometry: overrides/mfd-east.geojson
reason: "Use the locally agreed Mansfield routing boundary."
```

A `force` operation on an exclusive core layer means:

1. the target region is included inside the override polygon;
2. other core regions in the same exclusive layer are removed inside that polygon;
3. expansion is applied only after the forced core assignment is complete.

Overrides must be deterministic and have explicit priority when two force polygons overlap.

---

## 4. Radio-facing result policy

A detailed lookup may produce many semantic matches:

```json
{
  "matches": [
    {"id":"iata-airport:SFO","membership":"core"},
    {"id":"iata-location:SQL","membership":"core"},
    {"id":"iata-location:PAO","membership":"expanded"},
    {"id":"iata-metro:SFO","membership":"core"},
    {"id":"country:US","membership":"core"},
    {"id":"us-state:CA","membership":"core"},
    {"id":"custom:sf-bay-area","membership":"core"}
  ]
}
```

The corresponding radio-facing list is derived from each matched region's canonical UMSH `RegionCode`.

For example:

```json
{
  "region_strings": ["SFO", "SQL", "PAO", "US", "CA", "SF Bay Area"],
  "region_codes": ["0x....", "..."]
}
```

If the metro match and airport match both encode as `SFO`, only one `SFO` is emitted to the radio-facing list.

### 4.1 Ordering

The database must store a stable sort priority rather than making clients guess.

Suggested default order:

1. commercial-airport core
2. commercial-airport expanded
3. positioned-IATA core
4. positioned-IATA expanded
5. metro
6. country
7. US state
8. custom regions, ordered by explicit custom priority / specificity

This order is a presentation/configuration policy only. Repeater matching is set membership.

### 4.2 Suggested default packet region

Return a separate `suggested_default_region`.

Recommended initial policy:

1. nearest commercial-airport core match;
2. otherwise nearest commercial-airport expanded match;
3. otherwise positioned-IATA core match;
4. otherwise positioned-IATA expanded match;
5. otherwise no automatic default.

Do **not** automatically choose a country or state as the packet's default region without a deliberate protocol/product decision; those regions may be extremely large and would broaden flood scope substantially.

Custom regions may opt into default eligibility later with an explicit policy field.

---

## 5. Repository layout

Keep human-managed and source data under `regions/`, while following the existing UMSH convention that reusable Rust libraries live in `crates/` and host development tools live in `tools/`.

Recommended layout:

```text
regions/
├── README.md
├── FORMAT.md
├── SOURCES.md
├── LICENSES.md
├── policy.yaml
│
├── upstream/
│   ├── sources.yaml
│   └── lock.json
│
├── extracts/                # machine-written distilled source data; committed
│   ├── iata-locations.csv
│   ├── commercial-airport-candidates.csv
│   ├── metro-codes.csv
│   └── boundaries/          # only layers measured small enough to commit
│
├── classifications/
│   ├── commercial-airports.yaml
│   └── iata-location-overrides.yaml
│
├── metros/
│   ├── metros.yaml
│   └── geometry/
│       ├── NYC.geojson
│       ├── LON.geojson
│       └── ...
│
├── custom/
│   ├── regions.yaml
│   └── geometry/
│
├── overrides/
│   ├── overrides.yaml
│   └── geometry/
│
├── tests/
│   ├── known-points.yaml
│   ├── boundary-points.yaml
│   └── expected-collisions.yaml
│
├── vendor/                  # downloaded/pinned upstream data; normally gitignored
│   └── ...
│
├── build/                   # generated intermediate data; gitignored
│   └── ...
│
└── dist/                    # generated release artifacts; gitignored or release-only
    ├── world.regiondb
    ├── manifest.json
    ├── build-report.json
    └── changes.json

tools/
└── regiondb-build/          # Python geospatial compiler

crates/
└── umsh-regiondb/           # Rust runtime reader/lookup library

crates/umsh-mobile-core/
└── ...                      # UniFFI facade additions

apps/ios/UMSH/
└── ...                      # Swift RegionService + UI integration

site/
├── content/regions/...
├── static/regions/...
└── ...                      # map/debugger UI
```

Do not commit multi-hundred-megabyte raw GIS snapshots. The pipeline has three stages with distinct commit policies:

1. **Fetch** (`make regions-fetch`) — downloads raw upstream data into `regions/vendor/`, gitignored, pinned by `regions/upstream/lock.json`.
2. **Update** (`make regions-update`) — distills the vendor data into small, deterministic, diff-friendly extracts under `regions/extracts/`, which **are committed**. These contain only the data the compilation actually consumes: point/attribute datasets (IATA codes, coordinates, classifications) as sorted stable-keyed CSV, and boundary layers only where the simplified geometry is measured small enough to be worth committing—large polygon layers may stay on the fetch path.
3. **Build** (`make regions-build`) — consumes only committed files (`regions/extracts/` plus the human-authored manifests). It needs neither network access nor `regions/vendor/`, so a clean checkout builds offline and reproducibly.

Extract files are machine-written and never hand-edited: each carries a provenance header (source id, upstream revision, SHA-256, retrieval date), and the update pass is idempotent—the same vendor data yields byte-identical extracts. Manual corrections belong in `classifications/` and `overrides/`, which the build applies on top; edits to extracts would be clobbered by the next update. Because refreshes land as ordinary commits, the PR diff of `regions/extracts/` is the geographic-policy review.

The lock file records the provenance of the committed extracts rather than serving as a build input.

Human-authored metro/custom/override data **must** be committed.

---

## 6. Source data

### 6.1 Airport / positioned-IATA source

Use the upstream OurAirports `airports.csv` as the primary source rather than relying only on the processed `datasets/airport-codes` CSV.

Why:

- OurAirports is public-domain data.
- It contains the IATA code and coordinates needed for physical IATA sites.
- It contains `scheduled_service`, which the processed `datasets/airport-codes` file intentionally removes.
- The `datasets/airport-codes` project itself states that its original source is OurAirports.

Sources:

- `https://ourairports.com/data/`
- `https://ourairports.com/help/data-dictionary.html`
- `https://github.com/datasets/airport-codes`

The builder should pin the downloaded source revision / hash.

Keep at least these fields during normalization:

```text
id
ident
type
name
latitude_deg
longitude_deg
iso_country
iso_region
municipality
scheduled_service
gps_code
icao_code
iata_code
local_code
home_link
wikipedia_link
```

Only records with a non-empty, valid three-letter IATA code and valid coordinates participate in the positioned-IATA layer.

Closed facilities should not be accepted unless explicitly overridden.

### 6.2 Commercial-airport classification

Do not treat `scheduled_service=yes` as sufficient evidence by itself.

The San Carlos Airport (`SQL`) case has already demonstrated that the field can conflict with the intended UMSH meaning of a normal regional/commercial passenger airport.

The compiled commercial classification should therefore be a **separate normalized input**.

Recommended workflow:

1. Bootstrap candidate airports from:
   - valid IATA code;
   - operational airport;
   - `scheduled_service=yes`.
2. Apply committed manual classification overrides:
   - explicit include;
   - explicit exclude;
   - optional classification notes/evidence.
3. Produce a build warning/report for candidates whose classification is uncertain.
4. Keep the source interface pluggable so a better current route/passenger-service data source can be added later.

Do not make the old OpenFlights route dataset normative. It is useful for experiments but is not current enough to be the long-term source of truth.

Example `regions/classifications/commercial-airports.yaml`:

```yaml
version: 1

overrides:
  SQL:
    commercial: false
    reason: "General-aviation reliever airport; not a normal scheduled passenger gateway."
    evidence:
      - "https://www.smcgov.org/publicworks/san-carlos-airport"

  MFR:
    commercial: true
    reason: "Regional scheduled passenger airport."
```

The builder should generate a review report listing:

- newly added upstream `scheduled_service=yes` airports;
- airports that disappeared;
- airports whose coordinates moved significantly;
- airports whose upstream scheduled-service flag changed;
- manually overridden records whose upstream state now conflicts.

### 6.3 Metro-code seed list

The previously identified seed source is:

- `https://github.com/lxndrblz/Airports/blob/main/citycodes.csv`

The repository is licensed CC BY-SA 4.0. Treat licensing explicitly; do not mix that file into MIT/Apache source code without attribution.

Use it only as a seed/list of metro IATA codes. Its point coordinates are **not metro boundaries**.

Each supported metro must have a human-reviewed polygon and provenance.

Example `regions/metros/metros.yaml`:

```yaml
version: 1

metros:
  - id: iata-metro:NYC
    iata: NYC
    name: New York metropolitan area
    geometry: geometry/NYC.geojson
    expansion_m: 0
    source:
      name: US Census metropolitan statistical area
      url: "..."
      vintage: "2025"
    interpretation: >
      UMSH traveler-oriented NYC metro boundary. This is a UMSH routing
      definition, not an official geographic boundary published by IATA.
    confidence: high
```

### 6.4 Country boundaries

Recommended V1 source:

- `geoBoundaries` `gbOpen` ADM0, CC BY 4.0:
  `https://www.geoboundaries.org/`

Reasons:

- global administrative boundary coverage;
- machine-readable source metadata;
- more suitable for point containment than a purely cartographic low-detail world map.

The builder should simplify the source geometry for the compiled database, but retain enough accuracy for routing. Record the source release, boundary year, and attribution.

Natural Earth is a public-domain alternative and useful for map/background data:

- `https://www.naturalearthdata.com/`
- `https://www.naturalearthdata.com/about/terms-of-use/`

If the implementation chooses Natural Earth instead, document that its geometry is cartographic and may be coarser near borders.

Country output names should be ISO 3166-1 alpha-2 codes.

### 6.5 US state boundaries

Use a pinned US Census TIGER/Line states release.

Current source family:

- `https://www.census.gov/geographies/mapping-files/time-series/geo/tiger-line-file.html`

Normalize to the 50 states plus District of Columbia and output USPS two-letter abbreviations.

Use state FIPS/GEOID internally for source identity; do not rely on display names as primary keys.

### 6.6 Custom and override geometries

All custom/override geometry must be GeoJSON in WGS84 (`EPSG:4326`).

Constraints:

- Polygon or MultiPolygon only.
- Valid geometry required.
- No self-intersections after normalization.
- Ring orientation normalized by the builder.
- Antimeridian-crossing input accepted but normalized/split by the compiler.
- Geometry file path must be relative to the owning manifest.
- Human-authored records require a stable internal `id`.

---

## 7. Source manifest schema

Use YAML for human-edited policy/manifests and GeoJSON for human-edited geometry.

Example custom region:

```yaml
- id: custom:rogue-valley
  kind: custom
  name: Rogue Valley
  radio_name: Rogue Valley
  geometry: geometry/rogue-valley.geojson
  expansion_m: 5000
  priority: 100
  source:
    type: manual
    notes: "Locally agreed routing region."
```

Example generated-layer policy:

```yaml
layers:
  commercial_airport:
    enabled: true
    max_radius_m: 100000
    default_expansion_m: 10000
    exclusive_core: true
    radio_kind: iata

  positioned_iata:
    enabled: true
    max_radius_m: 100000
    default_expansion_m: 5000
    exclusive_core: true
    radio_kind: iata

  metro:
    enabled: true
    default_expansion_m: 0
    exclusive_core: false

  country:
    enabled: true
    default_expansion_m: 0
    exclusive_core: true

  us_state:
    enabled: true
    default_expansion_m: 0
    exclusive_core: true
```

Every policy value that materially changes a lookup result must be included in the build metadata/hash.

---

## 8. Builder technology

Implement the geospatial compiler as a Python 3.12+ tool under `tools/regiondb-build/`.

Python is recommended for the builder because this stage benefits from mature geospatial/scientific libraries and is not part of any resource-constrained runtime.

Suggested dependencies:

- `numpy`
- `scipy`
- `shapely >= 2`
- `pyproj`
- `geopandas` and/or `pyogrio`
- `PyYAML`
- `httpx` or `requests`

Use a checked-in `pyproject.toml` and a deterministic lockfile (`uv.lock` is reasonable). Note that this is new precedent: the repository's existing Python is bare Makefile-driven scripts under `scripts/` with no packaging, so this would be its first packaged Python project.

The builder must have no hidden network dependency during `build`: fetching is a separate explicit step, and `build` reads only committed files.

Commands:

```text
regiondb-build fetch
regiondb-build update
regiondb-build build
regiondb-build validate
regiondb-build diff OLD.regiondb NEW.regiondb
regiondb-build export-geojson
regiondb-build inspect CODE
```

`fetch` is the only command that touches the network, and `update` the only one that reads `regions/vendor/`; `build` and everything after it operate on the committed tree alone.

---

## 9. Build pipeline

### 9.1 Fetch / pin upstream data

`regiondb-build fetch`:

1. Read `regions/upstream/sources.yaml`.
2. Download each configured source.
3. Verify expected source identity where pinned.
4. Compute SHA-256.
5. Write/update `regions/upstream/lock.json`.
6. Save source files under `regions/vendor/`.
7. Never silently use a different upstream file when hash verification fails.

The lock entry should include:

```json
{
  "id": "ourairports-airports",
  "url": "...",
  "retrieved_at": "...",
  "sha256": "...",
  "upstream_revision": "...",
  "license": "Public Domain"
}
```

The vendor files exist only to feed the update pass; `build` never reads them. The lock records the provenance of whatever extracts were last committed.

### 9.2 Update / distill committed extracts

`regiondb-build update` consumes `regions/vendor/` plus the lock and writes deterministic, diff-friendly extracts under `regions/extracts/`, which are committed (§5). Sorted stable-keyed CSV with canonical column order and fixed number formatting for point/attribute data; for any boundary layer small enough to commit, one GeoJSON file per region with fixed 1e-6-degree precision and canonical key ordering.

The pass must be idempotent: identical vendor data yields byte-identical extracts. Each file carries a provenance header naming the source, upstream revision, SHA-256, and retrieval date.

During distillation, normalize:

- Unicode to a documented form where applicable;
- IATA letters to uppercase ASCII;
- longitudes to `[-180, 180)`;
- latitude validation to `[-90, 90]`;
- source IDs;
- stable sorting;
- duplicate records;
- invalid or missing coordinates;
- closed/obsolete facilities.

Never “pick the first duplicate.” Ambiguous duplicate IATA point records should fail or require an explicit override.

Extracts are never hand-edited; manual corrections live in `classifications/` and `overrides/`. A drift check (`regiondb-build validate` given vendor data, or scheduled CI) re-runs the distillation against the pinned vendor files and verifies the committed extracts match byte for byte, so they cannot silently diverge from what the pass would produce.

### 9.3 Derive canonical radio identity

Every compiled region gets:

- an internal namespaced ID;
- a human display name;
- a radio-facing string;
- its canonical 16-bit UMSH `RegionCode`.

Rules:

- IATA-derived regions use exactly the three-letter IATA code and `RegionCode::from_short_code`.
- Country and US-state regions use their two-letter code and `RegionCode::from_short_code`.
- Custom regions use `RegionCode::from_name(radio_name)`. A `radio_name` of one to three ASCII alphanumerics always occupies the short-code space—the runtime parses it as a short code unconditionally—so reject such a custom name unless the source explicitly declares that the short-code identity is intentional.
- All radio-facing names must satisfy the existing 24-byte UTF-8 limit.
- Detect local collisions among named-region hashes and report them. Hashed names can never collide with all-letter short codes (the transform vacates that space), but they can collide with each other and with digit-bearing short codes. A collision between geographically remote regions is permitted by current UMSH semantics, but a collision among regions that can simultaneously cover a point is an error unless explicitly waived.

The Python builder should not invent its own subtly different hash transform. Either:
- call a small Rust helper from `umsh-core` during build; or
- maintain conformance vectors generated from `umsh-core` and test the Python implementation exhaustively.

Prefer reusing Rust when practical.

---

## 10. Generating nearest-site core regions

Commercial-airport and positioned-IATA core regions are generated from point sets.

### 10.1 Distance model

Use a spherical or WGS84-geodesic model consistently.

Recommended:

- use unit-sphere coordinates for spherical Voronoi topology;
- use WGS84 geodesic operations (`pyproj.Geod`) for distances, densification, and radius checks.

Record the model and constants in metadata.

The difference between a sphere and WGS84 is not operationally important for 100 km routing scopes, but reproducibility is.

### 10.2 Spherical Voronoi

Use `scipy.spatial.SphericalVoronoi` on 3D unit vectors.

For each site set independently:

1. Convert site coordinates to unit vectors.
2. Construct a spherical Voronoi tessellation.
3. Sort region vertices.
4. Convert each spherical edge to a densified great-circle polyline.
5. Convert to WGS84 lon/lat geometry.
6. Split at the antimeridian as necessary.
7. Intersect each cell with its configured geodesic maximum-radius disk.
8. Validate that the generator point lies in the resulting core unless intentionally overridden.

Do not generate a planar lon/lat Voronoi diagram.

### 10.3 Great-circle densification

A spherical Voronoi edge is a great-circle arc. A GeoJSON polygon edge is treated as a straight segment in projected lon/lat rendering.

Densify arcs so the maximum deviation from the intended great-circle boundary stays below the chosen geometric tolerance.

Make tolerance configurable, for example:

```yaml
geometry:
  max_curve_error_m: 50
```

The builder report should record actual maximum segment length/error assumptions.

### 10.4 Radius cap

The 100 km maximum is part of the core geometry:

```text
core = spherical_voronoi_cell ∩ geodesic_disk(site, max_radius)
```

Beyond every site's maximum radius, that generated layer has no core assignment.

This intentionally allows zero-region areas in oceans and remote regions.

---

## 11. Administrative and explicit core geometry

Country, state, metro, and custom core regions start from source polygons.

Normalize each geometry:

1. transform to WGS84 if needed;
2. make valid using a deterministic repair policy;
3. reject unexpectedly destructive repairs;
4. split antimeridian crossings;
5. simplify using topology-preserving simplification;
6. retain holes;
7. preserve source provenance.

Use separate simplification tolerances by layer. Administrative coastlines may need more simplification than small manually authored local regions.

Suggested starting tolerances:

```text
countries:   100 m
US states:    50 m
metros:       25 m
custom:       10 m or none unless explicitly configured
```

These are starting points; measure compiled size and visual quality.

---

## 12. Overrides and precedence

Apply overrides to **core** geometry before expansion.

Recommended precedence:

```text
generated/source core
→ layer force overrides
→ explicit include/exclude adjustments
→ validate core topology
→ expansion
→ final effective geometry
```

For an exclusive core layer such as commercial-airport or positioned-IATA:

- `force(target, polygon)` removes that polygon from every other region in the same layer and unions it into `target`.
- equal-priority overlapping `force` operations are an error;
- different priorities resolve highest priority first and must be reported.

For non-exclusive layers, `include` and `exclude` operate on the target region without altering others.

Every applied override should be preserved in database metadata sufficiently to explain a lookup.

---

## 13. Expansion

Expansion is applied after the final core is known.

For small/local regions, perform an outward geodesic buffer by projecting each connected component into a suitable local metric projection, buffering, and transforming back.

For generated IATA cells, their capped extents are small enough that a local azimuthal-equidistant projection centered near the source point is appropriate.

For large regions (country-scale), expansion should normally be zero. If a future large region requests expansion, use a robust geodesic/partitioned buffering method rather than buffering thousands of kilometers in one local projection.

The compiled database stores both:

- **core geometry**
- **effective geometry** (core plus expansion)

Runtime routing membership uses effective geometry.

The web viewer can distinguish core from expanded-only coverage.

---

## 14. Recommended `.regiondb` design

Use SQLite as the single-file container.

Reasons:

- one portable file;
- available on Apple platforms;
- mature Rust support;
- easy metadata/versioning;
- durable indexes;
- straightforward debugging with standard tools;
- browser access is possible through WASM SQLite;
- adding metadata tables later does not require changing a bespoke container header.

Use a project-specific extension:

```text
world.regiondb
```

This is an ordinary SQLite database with a defined UMSH schema.

### 14.1 Versioning

Use both:

- SQLite `PRAGMA user_version` for the binary/schema format version;
- semantic metadata for the geographic data release.

Example:

```text
format_version = 1
dataset_version = "2026.08.1"
```

A runtime must reject a newer unsupported `format_version`.

### 14.2 Core schema

Suggested V1 schema:

```sql
CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE sources (
    id INTEGER PRIMARY KEY,
    source_key TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    url TEXT,
    revision TEXT,
    sha256 TEXT,
    license TEXT,
    attribution TEXT
);

CREATE TABLE regions (
    id INTEGER PRIMARY KEY,
    region_key TEXT NOT NULL UNIQUE,        -- e.g. "iata-airport:SFO"
    namespace TEXT NOT NULL,                -- tooling only
    code TEXT NOT NULL,                     -- namespace-local code/name
    display_name TEXT NOT NULL,
    radio_name TEXT NOT NULL,
    wire_code INTEGER NOT NULL,             -- canonical UMSH RegionCode u16
    kind TEXT NOT NULL,
    layer TEXT NOT NULL,
    priority INTEGER NOT NULL,
    default_rank INTEGER,
    expansion_m INTEGER NOT NULL DEFAULT 0,
    source_id INTEGER,
    flags INTEGER NOT NULL DEFAULT 0,
    notes TEXT,
    FOREIGN KEY(source_id) REFERENCES sources(id)
);

CREATE TABLE geometry_parts (
    id INTEGER PRIMARY KEY,
    region_id INTEGER NOT NULL,
    role INTEGER NOT NULL,                  -- 0=core, 1=effective
    min_lon REAL NOT NULL,
    min_lat REAL NOT NULL,
    max_lon REAL NOT NULL,
    max_lat REAL NOT NULL,
    geometry BLOB NOT NULL,
    FOREIGN KEY(region_id) REFERENCES regions(id)
);

CREATE VIRTUAL TABLE effective_rtree USING rtree(
    part_id,
    min_lon, max_lon,
    min_lat, max_lat
);

CREATE TABLE region_sets (
    id INTEGER PRIMARY KEY,
    region_ids BLOB NOT NULL
);

CREATE TABLE lookup_ranges (
    start_key INTEGER PRIMARY KEY,
    end_key INTEGER NOT NULL,
    base_set_id INTEGER NOT NULL,
    candidate_region_ids BLOB,
    FOREIGN KEY(base_set_id) REFERENCES region_sets(id)
);

CREATE TABLE provenance (
    region_id INTEGER NOT NULL,
    source_id INTEGER NOT NULL,
    source_feature_id TEXT,
    detail TEXT,
    PRIMARY KEY(region_id, source_id, source_feature_id)
);
```

The exact schema may be adjusted during implementation, but preserve the concepts.

### 14.3 Geometry encoding

Do not require SpatiaLite or another native extension at runtime.

Use a small project-defined geometry BLOB format containing only what UMSH needs:

- Polygon parts;
- exterior ring plus zero or more holes;
- WGS84 longitude/latitude fixed-point integer coordinates;
- delta + zigzag-varint encoding.

Recommended coordinate unit:

```text
1e-6 degree
```

This is far more precise than the source/route-boundary requirement while remaining within signed 32-bit longitude/latitude values.

Suggested BLOB conceptual layout:

```text
u8 geometry_format_version
varint ring_count

for each ring:
    u8 ring_role             # exterior / hole
    varint point_count
    zigzag_varint lon_e6_0
    zigzag_varint lat_e6_0
    repeated:
        zigzag_varint delta_lon_e6
        zigzag_varint delta_lat_e6
```

Do not repeat the closing point; closure is implicit.

Store each disconnected polygon component as its own `geometry_parts` row. This keeps RTree bounding boxes useful even for countries with remote islands.

Provide encoder/decoder golden vectors in `regions/tests/`.

---

## 15. Runtime spatial index: hybrid cache + exact fallback

The compiled database should contain final effective polygons, so an exact lookup can always be performed with:

1. bounding-box candidate lookup;
2. point-in-polygon test;
3. region collection/deduplication.

This alone is likely fast enough.

Add an adaptive lookup cache to make the common path even cheaper without sacrificing exact boundary behavior.

### 15.1 Fixed lookup grid key

Use a lon/lat quadtree with a maximum depth of 16 for V1.

At depth 16:

- X and Y are each unsigned 16-bit coordinates;
- interleaving X/Y produces a 32-bit Morton/Z-order key;
- equatorial cell width is roughly 600 m and north/south height roughly 300 m.

The maximum depth does **not** limit boundary accuracy because cells crossed by a boundary fall back to exact polygon testing.

Coordinate mapping:

```text
normalized_lon in [-180, 180)
lat in [-90, 90]

x = floor((normalized_lon + 180) / 360 * 65536)
y = floor((lat + 90) / 180 * 65536)

clamp x/y to 0...65535
morton = interleave_bits(x, y)
```

Document exact handling of `lon=180`, `lat=90`, NaN, and infinities.

### 15.2 Building adaptive cells

Start with the whole world.

For each cell and every effective region that could intersect it, classify the region relation:

- region contains the whole cell → guaranteed member;
- region disjoint from the cell → guaranteed non-member;
- otherwise → boundary/mixed.

If there are no mixed regions, the cell can be emitted immediately with a complete `region_set`.

If mixed regions exist and depth < maximum depth, subdivide into four children.

At maximum depth, emit:

- a `base_set_id` of regions known to contain the whole cell;
- a small list of mixed candidate region IDs that must be tested at runtime.

This avoids the classic bug where a small polygon wholly inside a large cell is missed by center-point sampling. The compiler must use geometry relations, not only sample points.

### 15.3 Converting cells to ranges

Each adaptive quadtree leaf corresponds to a contiguous range of max-depth Morton keys.

Store leaves as:

```text
start_key
end_key
base_set_id
candidate_region_ids
```

Merge adjacent ranges that have identical base/candidate sets.

A normal runtime lookup becomes one indexed query:

```sql
SELECT start_key, end_key, base_set_id, candidate_region_ids
FROM lookup_ranges
WHERE start_key <= ?1
ORDER BY start_key DESC
LIMIT 1;
```

Verify `?1 <= end_key`.

If `candidate_region_ids` is empty, return the base set immediately.

If candidates exist, test only those few effective region geometries and union positive matches with the base set.

### 15.4 Why this hybrid is preferred

It gives all of these properties simultaneously:

- deterministic compiled geographic policy;
- very fast common-case lookup;
- no raster approximation at boundaries;
- map-quality geometry in the same file;
- small runtime implementation;
- no dependency on SpatiaLite;
- ability to tune cache depth/size independently from geometric accuracy.

If benchmarks show direct RTree lookup is already fast enough, the cache can initially be optional, but the schema and conformance tests should support it from the beginning.

---

## 16. Point-in-polygon semantics

Define boundary behavior once and use it everywhere.

Recommended:

> A point exactly on a polygon boundary counts as inside.

This avoids tiny gaps.

Implementation requirements:

- longitude already normalized;
- antimeridian-crossing polygons split during build;
- holes respected;
- integer/fixed-point geometry preferred for deterministic boundary tests;
- use the same rule in Rust, Python reference code, and JavaScript.

For points extremely close to an edge, exact integer orientation tests are preferable to epsilon-based floating-point heuristics.

---

## 17. Detailed lookup result

The shared runtime should expose semantic information, not just strings.

Conceptual Rust types:

```rust
pub struct RegionMatch {
    pub region_id: u32,
    pub region_key: String,
    pub namespace: String,
    pub code: String,
    pub display_name: String,
    pub radio_name: String,
    pub wire_code: RegionCode,
    pub kind: RegionKind,
    pub membership: Membership,
    pub priority: i32,
}

pub enum Membership {
    Core,
    Expanded,
}

pub struct RegionLookup {
    pub latitude: f64,
    pub longitude: f64,
    pub matches: Vec<RegionMatch>,
    pub radio_regions: Vec<RadioRegion>,
    pub suggested_default_region: Option<RadioRegion>,
    pub dataset_version: String,
}

pub struct RadioRegion {
    pub name: String,
    pub code: RegionCode,
}
```

To determine `Core` vs `Expanded`, the runtime can test core geometry only when diagnostic detail is requested. Normal fast routing lookup can use effective geometry only.

Provide two APIs:

```rust
lookup_codes(lat, lon)       // fast path for normal app/device setup
lookup_detailed(lat, lon)    // diagnostics/map UI
```

---

## 18. Rust runtime crate

Add:

```text
crates/umsh-regiondb/
```

This is the reference reader/lookup implementation. Add it to both `members` and `default-members` in the root `Cargo.toml`—the workspace lists every crate explicitly, and only `default-members` entries build from a plain root `cargo build`.

Responsibilities:

- open/read `.regiondb`;
- validate `format_version`;
- calculate Morton key;
- resolve `lookup_ranges`;
- decode region sets;
- decode geometry blobs;
- exact point-in-polygon fallback;
- load region metadata;
- deduplicate by canonical `RegionCode`;
- select suggested default region;
- provide lookup/version/metadata APIs.

It should depend on `umsh-core` for `RegionCode`.

Suggested public API:

```rust
let db = RegionDb::open(path)?;

let result = db.lookup_codes(42.1946, -122.7095)?;
for region in result.radio_regions {
    println!("{} {}", region.name, region.code);
}
```

Also support lookup from an in-memory byte buffer if practical, useful for testing and WASM/native packaging.

### 18.1 SQLite dependency

Use `rusqlite` or another small, mature SQLite wrapper.

Avoid requiring SpatiaLite.

On platforms where system SQLite is available, prefer it unless reproducibility/build constraints make a bundled SQLite more practical.

Measure binary-size impact before enabling bundled SQLite in mobile artifacts.

---

## 19. Mobile / Swift integration

The repository already has:

- `crates/umsh-mobile-core`
- UniFFI bindings
- `packages/UMSHMobileCore`
- SwiftUI under `apps/ios/`

Prefer reusing the Rust runtime through the existing UniFFI facade rather than writing a second independent Swift geometry engine for V1.

### 19.1 Mobile-core facade

Expose a stable value-oriented API from `umsh-mobile-core`, consistent with its existing design.

Possible records:

```rust
#[derive(uniffi::Record)]
pub struct MobileRegionMatchRecord {
    pub key: String,
    pub display_name: String,
    pub radio_name: String,
    pub wire_code: Vec<u8>,
    pub kind: MobileRegionKind,
    pub membership: MobileRegionMembership,
}

#[derive(uniffi::Record)]
pub struct MobileRegionLookupRecord {
    pub matches: Vec<MobileRegionMatchRecord>,
    pub radio_regions: Vec<String>,
    pub radio_region_codes: Vec<Vec<u8>>,
    pub suggested_default_region: Option<Vec<u8>>,
    pub dataset_version: String,
}
```

A high-level object could own the database:

```text
MobileRegionDatabase.open(path)
MobileRegionDatabase.lookup(latitude, longitude)
MobileRegionDatabase.version()
```

Increment `MOBILE_API_VERSION` if the binding-visible contract requires it.

### 19.2 Swift service

Add a small native wrapper/service, for example:

```text
apps/ios/UMSH/Services/Regions/RegionService.swift
```

Responsibilities:

- resolve which database to open: the downloaded copy or the bundled one, whichever has the newer `dataset_version` (an app update can ship a bundle newer than an earlier download, so "downloaded wins" is wrong);
- call the UniFFI API;
- expose async-safe Swift application methods;
- perform the user-initiated update check and download (§20);
- report the active database's version and origin (bundled vs downloaded) for the Settings UI;
- map failures to localized UI errors.

Do not duplicate geographic policy in Swift.

### 19.3 Applying suggestions to a radio

When a user configures a repeater and a usable location is available:

1. perform lookup;
2. show suggested region list;
3. allow the user to inspect/edit it;
4. convert the selected `radio_regions` directly into the existing repeater `regions` strings;
5. use `suggested_default_region` for `default_region` only when the user accepts the suggestion.

Do not silently overwrite an operator's manually configured regions when the database updates.

---

## 20. Database download/update behavior

The app bundle always includes a copy of the regiondb that is current at app-release time—an app build step copies the latest release into the bundle—so region lookup always works, on first run and offline, with no download ever required. The bundled copy is not a degraded fallback; it is the same released database.

Updates between app releases are user-initiated: a Settings entry shows the active database's dataset version and origin (bundled vs downloaded) and offers a "check for updates" action that fetches the manifest, compares versions, and downloads on confirmation. No automatic background updates in V1—not because an update is dangerous (applying regions to a repeater is a manual act, so a new database changes nothing by itself), but because there is simply no need for the machinery yet; the Settings check is enough.

The runtime picks whichever of the bundled and downloaded copies has the newer `dataset_version`. A downloaded database whose `format_version` the app cannot read is rejected and the bundled copy is used—the bundled one is always readable by the app that shipped it. A downloaded copy that no longer beats the bundle (after an app update) may be deleted as housekeeping.

The site hosts exactly one database—the current release:

```text
https://umsh.dev/regions/manifest.json
https://umsh.dev/regions/world-<version>.regiondb
```

The version lives in the filename for cache-busting, not archival: GitHub Pages and intermediate caches can serve a stale body under a reused URL, and a unique filename per release makes the manifest→database handoff unambiguous. Each publish deletes the previous file from the site. Older releases are archived on GitHub Releases (the same division of labor as firmware: Releases are the archive, `umsh.dev` mirrors only what browsers need to `fetch()`), and non-browser clients can retrieve them from there if ever needed.

Possible manifest:

```json
{
  "format_version": 1,
  "dataset_version": "2026.08.1",
  "created_at": "2026-08-20T00:00:00Z",
  "url": "/regions/world-2026.08.1.regiondb",
  "size": 4871936,
  "sha256": "...",
  "min_mobile_api_version": 40
}
```

(`MOBILE_API_VERSION` is currently 39; the example presumes the bump this feature would introduce.)

Update procedure:

1. fetch manifest;
2. compare dataset version;
3. verify supported format version;
4. download to temporary file;
5. verify length and SHA-256 against the manifest;
6. open database and run integrity/version checks;
7. atomically rename into place;
8. retain previous known-good copy until new file has opened successfully.

Integrity rests on HTTPS plus the manifest's SHA-256; release signing is deliberately out of scope for now and can be added later without changing this flow.

---

## 21. Web map / debugger

Implement the map as a static application integrated with `umsh.dev`, not as a separate server dependency.

The repository's website is Zola and is deployed to GitHub Pages. Put the region viewer under something like:

```text
https://umsh.dev/regions/map/
```

### 21.1 Browser database access

The browser must open the actual `.regiondb`, not a separately generated approximation.

Use a pinned, locally hosted WASM SQLite implementation such as `sql.js` or `wa-sqlite`.

Do not rely on CDN-only CSS/JS for critical map layout. The earlier prototype exposed how fragile that can be when external Leaflet assets fail to load. Vendor or bundle critical dependencies.

### 21.2 Map library

MapLibre GL JS is a good fit for the viewer.

The app should:

- lazy-load region geometry for the viewport;
- decode the project's geometry BLOB format;
- render core/effective boundaries;
- avoid inserting the entire global geometry into the DOM at once.

### 21.3 Required viewer features

At minimum:

- pan/zoom global map;
- click map to run a real database lookup;
- coordinate entry;
- code search;
- layer toggles:
  - commercial airport;
  - positioned IATA;
  - metro;
  - country;
  - US state;
  - custom;
- core vs expanded-area visualization;
- override visualization;
- generator-point markers;
- optional adaptive-cell visualization for debugging;
- lookup result panel showing:
  - detailed semantic matches;
  - core vs expanded membership;
  - final deduplicated radio strings;
  - final 16-bit `RegionCode`s;
  - suggested default region;
  - database version;
- “show this region” mode;
- provenance/source panel.

### 21.4 Map lookup conformance

The browser lookup implementation must run the same golden tests as the Rust runtime.

A map click must not use a different ad-hoc geographic calculation from the downloadable database.

---

## 22. Optional HTTP lookup service

The static downloadable database is the primary architecture, but a lightweight HTTP service is useful for clients that do not want to download it.

Implement only after the local runtime is stable.

Possible endpoint:

```http
GET /api/v1/regions/lookup?lat=42.1946&lon=-122.7095
```

Response:

```json
{
  "position": {
    "latitude": 42.1946,
    "longitude": -122.7095
  },
  "dataset_version": "2026.08.1",
  "matches": [
    {
      "key": "iata-airport:MFR",
      "display_name": "Rogue Valley International-Medford Airport",
      "radio_name": "MFR",
      "wire_code": "0x5242",
      "kind": "commercial_airport",
      "membership": "core"
    },
    {
      "key": "iata-location:ASH",
      "display_name": "Ashland Municipal Airport",
      "radio_name": "ASH",
      "wire_code": "0x....",
      "kind": "positioned_iata",
      "membership": "core"
    },
    {
      "key": "country:US",
      "display_name": "United States",
      "radio_name": "US",
      "wire_code": "0x....",
      "kind": "country",
      "membership": "core"
    },
    {
      "key": "us-state:OR",
      "display_name": "Oregon",
      "radio_name": "OR",
      "wire_code": "0x....",
      "kind": "us_state",
      "membership": "core"
    }
  ],
  "radio_regions": ["MFR", "ASH", "US", "OR"],
  "suggested_default_region": "MFR"
}
```

Additional endpoints:

```text
GET /api/v1/regions/version
GET /api/v1/regions/{namespace}/{code}
GET /api/v1/regions/database
```

The service should use `umsh-regiondb` directly so its result is exactly the same as offline lookup.

Cache the database in-process; do not hit a network database for each lookup.

---

## 23. Build reports and diagnostics

Every build must emit `build-report.json` plus a readable console summary.

Include:

```text
source revisions/hashes
number of positioned IATA sites
number of commercial airports
number of metros
number of countries
number of US states
number of custom regions
number of overrides
number of geometry parts
core/effective total vertices
number of lookup ranges
number of unique region sets
number of boundary fallback cells
maximum mixed candidate count
maximum radio-region count observed
database size
build duration
validation results
warnings
```

Also emit `changes.json` when comparing to a previous release:

```text
added/removed sites
commercial-classification changes
moved coordinates
added/removed regions
changed metro/custom/override geometry
area changed per region
large boundary shifts
radio-code collision changes
database-size delta
```

Data refreshes should be reviewed as geographic policy changes, not blindly published; the committed-extract diff (§5) makes that review an ordinary PR, with these reports as supporting material.

---

## 24. Validation and conformance

This project needs a strong validation suite: the database drives the region suggestions operators apply to repeaters, and a wrong answer is a misconfigured repeater someone has to notice and fix by hand. (It does not change forwarding behavior by itself—applying regions is always a manual act.)

### 24.1 Source validation

Fail or warn on:

- invalid IATA codes;
- missing coordinates;
- out-of-range coordinates;
- duplicate source IDs;
- duplicate IATA codes with conflicting coordinates;
- closed facilities included without override;
- invalid GeoJSON;
- missing source/license metadata;
- radio names over 24 bytes;
- custom names that accidentally occupy the 1–3-alphanumeric short-code input form.

### 24.2 Geometry validation

Check:

- all geometries valid after normalization;
- no unintentional self-intersections;
- antimeridian handling;
- correct holes;
- generated site lies in its own core;
- generated core does not extend beyond max radius;
- exclusive generated cores do not overlap before expansion except at mathematical boundaries;
- forced overrides obey priority;
- expansion only increases effective coverage;
- effective geometry contains core;
- country/state layers meet expected topology checks.

### 24.3 Known-point tests

Maintain human-readable test fixtures.

Required examples include at least:

```yaml
- name: San Carlos Airport
  lat: 37.5119
  lon: -122.2495
  expect:
    include_semantic:
      - iata-location:SQL
      - country:US
      - us-state:CA
    exclude_semantic:
      - iata-airport:SQL
```

The commercial result at/near SQL should resolve to the intended real commercial airport according to the compiled classification/boundary policy, not SQL itself.

Add known points for:

- Ashland / Medford area;
- San Francisco Bay Area;
- central New York;
- central London;
- a point just outside a metro polygon;
- US state borders;
- country borders;
- antimeridian;
- high latitude;
- remote ocean with no IATA result;
- a manual override;
- an expanded overlap strip.

### 24.4 Boundary tests

For every important boundary, generate points:

```text
inside by 100 m
inside by 10 m
on edge
outside by 10 m
outside by 100 m
```

Verify boundary-is-inside semantics.

### 24.5 Reference-vs-compiled property testing

The Python builder should retain a slow direct/reference evaluator.

For a large random sample of global points:

1. calculate result directly from final effective geometry;
2. query the compiled `.regiondb` cache/fallback algorithm;
3. require identical semantic region sets.

Test particularly densely around all geometry boundaries.

### 24.6 Cross-implementation conformance

Generate a portable fixture:

```text
regions/tests/conformance.json
```

containing thousands of:

```json
{
  "lat": 37.5,
  "lon": -122.25,
  "region_keys": ["..."],
  "radio_names": ["..."],
  "wire_codes": [1234, 5678],
  "default_wire_code": 1234
}
```

Run it through:

- Python reference lookup;
- Rust `umsh-regiondb`;
- UniFFI/mobile facade;
- browser JavaScript lookup.

Every implementation must agree.

---

## 25. Performance targets

Use explicit budgets.

Suggested V1 targets:

### Database

- preferred: `< 5 MB`
- acceptable initial: `< 10 MB`
- build warning: `> 10 MB`
- build failure only if a deliberately configured hard limit is exceeded

### Native lookup after open

On a representative older supported iPhone:

- median: `< 20 ms`
- p95: `< 100 ms`
- worst normal boundary fallback: `< 250 ms`

The user's requirement is only “within a few seconds,” but there is no reason for this design to be that slow.

### Cold open

- `< 500 ms` preferred for a several-megabyte SQLite database

### Browser

- click lookup `< 100 ms` after database load
- map geometry must be loaded by viewport rather than decoding every global polygon on startup

Benchmark and report:

- direct RTree/PIP lookup;
- cached uniform-cell lookup;
- boundary fallback;
- core-vs-effective diagnostic lookup.

If the adaptive cache does not materially improve real performance or costs too much file size, it may be reduced in depth or omitted from the first release. Exact polygon lookup remains the correctness path.

---

## 26. Licensing and provenance

Create `regions/LICENSES.md` and treat data licensing separately from UMSH source-code licensing.

Expected examples:

- OurAirports — Public Domain
- `datasets/airport-codes` — PDDL packaging, derived from OurAirports
- `lxndrblz/Airports` city-code seed — CC BY-SA 4.0
- geoBoundaries gbOpen — CC BY 4.0
- US Census TIGER/Line — US government/public data; record source/vintage
- Natural Earth, if used — Public Domain

The compiled `.regiondb` must include source attribution metadata.

Because CC BY-SA source may affect redistribution terms for derivative data, document the data artifact's license separately rather than assuming the repository's MIT/Apache code license automatically applies.

The implementation agent should not make an unsupported legal claim; if the final redistribution license is uncertain, flag it for human review before release.

---

## 27. Build reproducibility

The compiler should be deterministic.

Given:

- identical committed extracts;
- identical human-authored manifests;
- identical policy files;
- identical builder version/dependency lock;

the logical database content must be identical. Because `build` reads only the committed tree, this holds for any clean checkout without network access.

For byte-for-byte SQLite reproducibility:

- use deterministic insertion order;
- fixed page size;
- avoid timestamps inside the DB unless supplied as explicit build input;
- run `VACUUM` deterministically after population;
- do not rely on random IDs.

If exact SQLite byte identity proves unnecessarily fragile, publish a canonical `content_hash` calculated over normalized logical tables/geometry and use that as the reproducibility guarantee.

---

## 28. CI / Makefile integration

Add repository-level targets consistent with existing UMSH workflows:

```text
make regions-fetch
make regions-update
make regions-build
make regions-check
make regions-test
make regions-diff OLD=...
make regions-map
make regions-release
```

Only `regions-fetch` may touch the network. Because `regions-build` consumes committed extracts, the full build—not just the checks—runs offline in CI and on a clean checkout.

CI should run:

- Python formatting/lint/tests for the builder;
- Rust tests for `umsh-regiondb`;
- region-format conformance tests;
- small fixture-database build;
- browser lookup tests;
- source-manifest validation;
- extract-format validation (provenance headers, sorted keys, no hand edits detectable as non-canonical formatting).

Do not make every normal `cargo test` rebuild the global geographic database.

### Scheduled source review

A scheduled GitHub Action may periodically:

1. fetch new upstream datasets;
2. run the update pass against them;
3. if the committed extracts change, open a review PR whose diff of `regions/extracts/` is the review surface, accompanied by a candidate build report;
4. otherwise verify the committed extracts still match the pinned sources (the drift check of §9.2).

Do **not** automatically merge or publish new routing boundaries simply because an upstream airport or administrative dataset changed—the PR is where a human reviews the geographic change.

---

## 29. Release artifacts

A region-data release should include:

```text
world.regiondb
manifest.json
world.regiondb.sha256
build-report.json
changes.json
SOURCES.txt / attribution
```

Every release's full artifact set goes to GitHub Releases, which serves as the permanent archive; the website carries only the current release (§20).

Potential versioning:

```text
regiondb format: 1
dataset release: 2026.08.1
```

The data release version is independent of:

- UMSH wire protocol version;
- mobile API version;
- firmware release version.

A newer app should be able to read older format-compatible region databases.

---

## 30. Web publishing integration

The UMSH site is built with Zola and published through GitHub Pages.

The site build currently preserves selected generated top-level trees: the `gh-pages` Makefile target wipes everything at the published root except `.git`, `docs`, `firmware`, and `tools` (the `! -name` list in its `find` invocation). A new top-level `/regions` tree published outside the normal Zola tree must be added to that preserve list or the next deploy deletes it. Region artifacts emitted through `site/static/` need no Makefile change.

Simplest arrangement:

```text
site/static/regions/map/...
site/static/regions/manifest.json
site/static/regions/world-<version>.regiondb
```

If the regiondb is too large to commit into normal site source, have the release pipeline copy the artifact into the `gh-pages` worktree, similar in spirit to the existing firmware mirroring process.

The site carries the small mutable `manifest.json` plus the single current database under its version-stamped filename; each publish removes the previous database file. Note that gh-pages history still grows by one database blob per release regardless of deletion—tolerable at a few MB per release, and gh-pages is a pure deploy artifact that can be squashed to an orphan commit if it ever matters, since GitHub Releases holds the archive.

---

## 31. Development tools

The implementation should provide useful CLI inspection from the beginning.

Examples:

```text
regiondb-build inspect MFR
regiondb-build lookup --lat 42.1946 --lon -122.7095
regiondb-build lookup --db regions/dist/world.regiondb --lat ... --lon ...
regiondb-build export-geojson --region iata-airport:MFR
regiondb-build export-geojson --layer positioned_iata
regiondb-build diff old.regiondb new.regiondb
```

The `lookup` command should support:

```text
--detailed
--json
--show-core
--show-provenance
```

A developer must be able to answer “why did this position get this region?” without opening a debugger.

---

## 32. Suggested implementation phases

### Phase 0 — format/spec skeleton and benchmark

Deliver:

- `regions/README.md`
- `regions/FORMAT.md`
- source/policy schemas
- minimal `umsh-regiondb` crate
- tiny hand-authored test `.regiondb`
- benchmark direct RTree/PIP versus optional cache

Goal: validate the SQLite/custom-geometry/runtime approach before building global data.

Acceptance:

- Rust can open a fixture DB and return correct region sets;
- iOS UniFFI smoke test can call the reader;
- browser can open the fixture DB.

### Phase 1 — IATA sources and generated cores

Deliver:

- OurAirports fetch/lock/update, with the distilled extracts committed;
- positioned-IATA site list;
- commercial-airport classification layer and overrides;
- spherical Voronoi generation;
- 100 km caps;
- core GeoJSON debug exports;
- San Carlos regression test.

Acceptance:

- `SQL` appears as a positioned IATA region but not a commercial-airport region;
- known western-US points behave sensibly;
- global generated core topology validates.

### Phase 2 — `.regiondb` V1 compiler

Deliver:

- final SQLite schema;
- geometry encoding;
- core/effective geometry tables;
- RTree;
- region metadata/provenance;
- region-set interning;
- optional adaptive lookup cache;
- build report.

Acceptance:

- random reference-vs-compiled tests pass;
- DB is within initial size budget;
- Rust lookup meets performance target.

### Phase 3 — country/state/metro/custom/override/expansion

Deliver:

- country ingestion;
- US-state ingestion;
- metro manifest and initial reviewed metro polygons;
- custom-region source schema;
- overrides;
- expansion buffers;
- collision validation.

Acceptance:

- detailed lookup returns all semantic layers;
- overlap strips return both adjacent regions;
- metro is containment-only;
- forced override is visible in map/debug export.

### Phase 4 — mobile integration

The Rust half is delivered: `umsh-regiondb` is a dependency of
`umsh-mobile-core`, the `MobileRegionDatabase` object and its records are
across the UniFFI boundary, `MOBILE_API_VERSION` is 40, and
`scripts/ios/stage-regiondb.sh` bundles the database. The SwiftUI half is
specified in `docs/regiondb-mobile-ui.md` and not yet built. The download and
update path is deliberately deferred until Phase 6 publishes a manifest to
compare against; the bundled database is the released database, not a
degraded fallback, so nothing is missing without it.

Deliver:

- `umsh-regiondb` integration into `umsh-mobile-core`;
- UniFFI records/functions;
- Swift `RegionService`;
- current regiondb bundled by an app build step;
- Settings entry showing database version/origin with a user-initiated check-and-update path;
- download/verification path;
- repeater-configuration suggestions.

Acceptance:

- iOS lookup matches Rust/Python fixtures;
- region lookup works on first run with no network, using the bundled database;
- the Settings check finds, downloads, and activates a newer release, and the newer of bundled/downloaded always wins;
- applying suggested regions writes the existing repeater settings correctly;
- existing manually configured regions are never silently replaced.

### Phase 5 — web viewer/debugger

Deliver:

- static region map under `umsh.dev`;
- browser SQLite loader;
- MapLibre viewer;
- manual point lookup;
- layer/core/expanded/override toggles;
- provenance;
- code search;
- conformance tests.

Acceptance:

- clicking a point matches native runtime result exactly;
- no mixed/scrambled map tiles from missing external CSS;
- the viewer consumes the actual released `.regiondb`.

### Phase 6 — release pipeline and optional HTTP API

Deliver:

- versioned region-data releases;
- manifest/checksum;
- website publication (current release only) and GitHub Releases archive;
- update diff reports;
- optional HTTP lookup service using the same Rust crate.

Acceptance:

- a clean client can discover, download, validate, and use the current database;
- previous releases remain available from GitHub Releases;
- HTTP and offline results are identical.

---

## 33. Things that must not be done

- Do not compute nearest airports on the radio.
- Do not require phones to regenerate Voronoi geometry.
- Do not use planar longitude/latitude Voronoi construction for the global source geometry.
- Do not treat every `scheduled_service=yes` OurAirports row as automatically qualifying for the commercial layer.
- Do not assign metro codes by nearest-center distance.
- Do not silently extend airport regions hundreds of kilometers across oceans; retain the configured maximum radius.
- Do not apply expansion to country/state layers unless policy explicitly asks for it.
- Do not discard namespaces from the compiled metadata merely because the final radio code does not need them.
- Do not introduce a new radio region-code encoding; use `umsh_core::RegionCode`.
- Do not let a custom 1–3-alphanumeric name accidentally claim short-code encoding.
- Do not implement the web map from a separately generated dataset that can disagree with `.regiondb`.
- Do not auto-publish upstream boundary changes without a diff/review step.
- Do not make build-time network access implicit.
- Do not depend on SpatiaLite on iOS.
- Do not use CDN-only critical CSS/JS in the map viewer.

---

## 34. Open policy decisions that should remain configurable

Do not block implementation on these; expose them as policy inputs and choose conservative initial defaults.

1. Exact commercial-airport maximum radius (start at 100 km).
2. Positioned-IATA maximum radius (start at 100 km).
3. Default expansion distance per layer.
4. Which commercial-airport evidence source eventually supplements/replaces manual classification.
5. Initial list of supported metro codes.
6. Boundary source for each metro.
7. Country boundary dataset if geoBoundaries licensing/size is undesirable.
8. Whether US territories receive state-like codes.
9. Whether country regions should eventually include territorial waters.
10. Maximum acceptable regiondb size.
11. Adaptive-cache maximum depth.
12. Whether and when to introduce release signing (deliberately absent from V1; the update flow is designed so it can be added without changes).
13. Whether any custom region is eligible to become `suggested_default_region`.

All of these must be visible in `policy.yaml` or source metadata rather than buried as magic constants.

---

## 35. Initial concrete policy recommendation

Use this to get the first complete system running:

```yaml
format_version: 1

distance:
  model: WGS84

geometry:
  curve_error_m: 50
  country_simplify_m: 100
  state_simplify_m: 50
  metro_simplify_m: 25
  custom_simplify_m: 0

lookup_cache:
  enabled: true
  max_depth: 16

layers:
  commercial_airport:
    max_radius_m: 100000
    expansion_m: 10000
    exclusive_core: true
    order: 100

  positioned_iata:
    max_radius_m: 100000
    expansion_m: 5000
    exclusive_core: true
    order: 200

  metro:
    expansion_m: 0
    order: 300

  country:
    expansion_m: 0
    order: 400

  us_state:
    expansion_m: 0
    order: 500

  custom:
    default_expansion_m: 0
    order: 600

default_region:
  preference:
    - commercial_airport_core
    - commercial_airport_expanded
    - positioned_iata_core
    - positioned_iata_expanded
```

The actual 10 km / 5 km expansion values are intentionally easy to change after inspecting the map. Do not treat them as protocol constants.

---

## 36. Definition of done

The system is complete when all of the following are true:

1. A clean checkout builds the database offline from committed extracts, and one documented command refreshes those extracts from pinned upstream sources.
2. Human-maintained metros, custom regions, commercial classification overrides, and boundary overrides live under `regions/`.
3. A deterministic build produces one versioned `.regiondb`.
4. The DB contains source/provenance metadata, semantic namespaces, radio names/codes, core geometry, effective geometry, and a lookup index.
5. A Rust API can open the DB and return a lookup result.
6. The existing iOS app can call that API through `umsh-mobile-core`/UniFFI.
7. The result includes:
   - commercial-airport region when in range;
   - nearest positioned-IATA region when in range;
   - containing metro when applicable;
   - country;
   - US state when applicable;
   - custom regions;
   - expanded neighboring regions;
   - manual overrides.
8. The detailed semantic matches are correctly deduplicated into final UMSH radio regions.
9. The suggested packet default remains a deliberately narrow IATA-derived region.
10. A static web map opens the same `.regiondb`, visualizes its boundaries, and performs identical manual lookups.
11. Python reference, Rust, mobile, and browser conformance tests agree.
12. San Carlos (`SQL`) is a regression test proving that positioned-IATA classification and commercial-airport classification are distinct.
13. Build output includes a change report so new geographic releases can be reviewed.
14. File size and lookup latency meet the documented budgets.
15. A versioned database can be downloaded, checksum-verified, and atomically installed by the app.

---

## 37. Recommended first implementation task

The first agent should **not** begin by downloading every global boundary source.

Start by proving the format and runtime with a deliberately tiny fixture:

- SFO, SQL, SJC, OAK, PAO as positioned IATA sites;
- SFO, SJC, OAK as qualifying commercial airports;
- one hand-authored `SFO` metro polygon;
- `US`;
- `CA`;
- one custom region;
- one forced override;
- nonzero expansion around at least one generated region.

Build that into a small `.regiondb`.

Then implement:

1. Rust lookup;
2. Python reference lookup;
3. browser lookup;
4. cross-implementation golden tests.

Only after the full vertical slice works should the implementation scale to global source ingestion.

This order will catch format/API mistakes while the dataset is small enough to inspect manually.

---

## Appendix A — Expected source references

These are starting references, not substitutes for pinned source manifests.

### OurAirports

- Data: https://ourairports.com/data/
- Data dictionary: https://ourairports.com/help/data-dictionary.html
- Upstream mirror: https://github.com/davidmegginson/ourairports-data

### datasets/airport-codes

- Repository: https://github.com/datasets/airport-codes
- Useful mainly as the originally requested dataset/reference; its processed CSV removes `scheduled_service`, so prefer raw OurAirports for the builder.

### Metro code seed

- https://github.com/lxndrblz/Airports
- `citycodes.csv`
- License: CC BY-SA 4.0

### IATA location-code background

- https://www.iata.org/en/iata-repository/pressroom/fact-sheets/fact-sheet-iata-location-codes/

IATA notes that location codes can apply to airports and intermodal locations and that metropolitan coding is a coding designation; it does not provide the land-containment polygons UMSH requires.

### Country boundaries

- https://www.geoboundaries.org/
- Recommended `gbOpen` ADM0 source
- License: CC BY 4.0

Alternative/background map source:

- https://www.naturalearthdata.com/
- Public domain

### US state boundaries

- https://www.census.gov/geographies/mapping-files/time-series/geo/tiger-line-file.html

---

## Appendix B — Key design rationale

The database is deliberately a **compiled routing dataset**, not merely a copy of airport points.

However, the final effective polygons remain in the file because they provide:

- exact fallback lookup near adaptive-cell boundaries;
- visual inspection;
- provenance/debugging;
- future ability to rebuild cache indexes without reacquiring source data.

The adaptive Morton-range cache is an optimization over those final effective polygons. It is not a second source of geographic truth.

This hybrid approach avoids both extremes:

- **point-only database:** every client would need to reproduce geographic policy;
- **raster-only database:** exact boundaries and human visualization become awkward;
- **polygon-only database:** already viable, but every lookup pays the geometry cost;
- **compiled cells + polygons:** common lookups are trivial, boundary lookups remain exact, and the map has real geometry.

Most importantly, the radio never needs any of this machinery. The phone/tool resolves position to normal UMSH `RegionCode`s and loads the resulting list onto the repeater using the existing repeater configuration path.
