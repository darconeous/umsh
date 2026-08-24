# UMSH region database

Source data and manifests for the geographic region database. Given a latitude
and longitude, a compiled `.regiondb` answers which UMSH regions a repeater at
that position should normally be configured to accept.

The radio never runs any of this. A phone or a command-line tool resolves a
position into ordinary UMSH region strings and loads them onto the repeater
through the existing configuration path, exactly as an operator typing them by
hand would.

## What lives here

| Path | Contents | Committed |
|---|---|---|
| `policy.yaml` | Compilation policy: layers, radius caps, expansion, tolerances | yes |
| `upstream/sources.yaml` | Pinned upstream downloads | yes |
| `upstream/lock.json` | What was actually retrieved, and its hash | yes |
| `extracts/` | Distilled source data the build consumes | yes |
| `classifications/` | Manual commercial-airport classification | yes |
| `metros/` | Metropolitan region definitions and polygons | yes |
| `custom/` | Hand-authored regions | yes |
| `overrides/` | Manual corrections to generated boundaries | yes |
| `tests/` | Known points, golden vectors, conformance fixture, test fixture tree | yes |
| `vendor/` | Raw upstream downloads | no |
| `build/` | Intermediate data, including the country boundary layer | no |
| `dist/` | Release artifacts | no |

## The three stages

```
make regions-fetch     # network → regions/vendor/, pinned in upstream/lock.json
make regions-update    # regions/vendor/ → regions/extracts/ (committed) and regions/build/
make regions-build     # committed tree → regions/dist/world.regiondb
```

Only `regions-fetch` touches the network, and only `regions-update` reads
`regions/vendor/`. Everything after that runs on files in the repository.

Because a data refresh lands as an ordinary commit, the diff of
`regions/extracts/` is where a geographic change gets reviewed. Extracts are
machine-written and carry a provenance header; hand-editing one is pointless,
because the next update pass overwrites it. Corrections go in
`classifications/` and `overrides/`, which the build applies on top.

`regions-update --check` re-derives the extracts from the pinned vendor files
and fails if the committed ones differ, so they cannot drift.

Every layer's extract is committed, including the country layer, so a clean
checkout builds the whole world offline. The country layer stays small enough
to commit because it is not a coastline dataset: a country region is the area
of asserted jurisdiction — land plus exclusive economic zone — so the fractal
coastline is interior to the region and never stored.

## Layers

A position can be in several regions at once. They are independent, they may
overlap, and a lookup returns all of them.

- **Commercial airport** (`iata-airport:`) — the nearest airport that provides
  ordinary passenger service to the public, within 100 km. Not every airport
  with a scheduled flight: see `classifications/commercial-airports.yaml`.
- **Positioned IATA** (`iata-location:`) — the nearest IATA-coded location of
  any kind within 100 km, including general aviation fields and heliports.
- **Metro** (`iata-metro:`) — containment only. A metropolitan code applies
  inside its polygon and nowhere else; the nearest metro area to a position
  outside every polygon is not that position's metro area. The current
  polygons are generated circular placeholders (see `metros/metros.yaml`),
  individually replaceable with reviewed boundaries. Metro regions rank first
  for the suggested packet default: inside the Tokyo area the tag people mean
  is `TYO`, and the broader flood that follows is a deliberate trade.
- **Country** (`country:`) — ISO 3166-1 alpha-2, over the country's land and
  the water within `maritime_reach_m` of it (100 km by default, matching how
  far the IATA layers project offshore), clipped to its EEZ + land union so
  the reach never crosses a maritime boundary. A boat in coastal waters is in
  its country's region; a boat mid-ocean is in nobody's. Contested areas —
  overlapping claims and joint regimes — are omitted entirely; the database
  takes no position on any dispute.
- **US state** (`us-state:`) — the 50 states plus the District of Columbia,
  each with the same water reach clipped to the nation's own water: the
  channels between a state's islands and its mainland belong to the state.
  Open water within reach of two states carries both, the same both-sides
  answer the expansion margins give on land. Territories are excluded in V1;
  see `policy.yaml`.
- **Custom** (`custom:`) — anything a person wants to define, either in
  `custom/regions.yaml` or through a community pack under `communities/`: a
  directory a local mesh group maintains, fenced to its declared area of
  influence. See `docs/community-region-packs.md`.

Namespaces are for tooling. Both `iata-airport:SFO` and `iata-metro:SFO`
produce the radio-facing region `SFO`, and the final list carries it once.

## Expansion

Every region may carry an outward expansion distance. This exists so a
repeater near a border can be configured for both sides: without it, an
operator a kilometer from a boundary would be told about exactly one of the
two regions their radio can plainly hear. Expansion is applied after
overrides, so a hand-corrected boundary widens the same way a generated one
does.

Expansion is a number, not stored geometry. The compiled database keeps core
polygons only, and a lookup resolves the margin with a fixed sample pattern
around the queried position — see `FORMAT.md`. A match is therefore either
core (the position itself is inside) or expanded (only the margin reaches
it).

## Editing

- Geometry is GeoJSON in WGS84, Polygon or MultiPolygon, one feature per file,
  path relative to the manifest that names it.
- A custom region's radio name must fit in 24 bytes of UTF-8.
- A custom radio name of one to three ASCII alphanumerics is read by the
  runtime as a short code, not as a name — it would claim an IATA or ISO
  identity. The build refuses one unless the manifest says the short-code
  identity is deliberate.
- Every metro polygon needs provenance and an interpretation note. IATA
  publishes no land boundary for these codes, so each one is a UMSH routing
  definition rather than an official boundary, and should say so.

## Looking at it

The map at `/regions/` loads a database and answers clicks with the same
lookup the radio-facing tooling uses.

```
make regions-map-serve      # http://127.0.0.1:1111/regions/
```

That stages `regions/dist/world.regiondb` where Zola serves it, or falls back
to the committed Bay Area fixture when no world build exists. The page also
has a file picker, so any `.regiondb` can be opened without staging anything.

For the same answers without a browser:

```
uv run --project tools/regiondb-build regiondb-build lookup \
    --db regions/dist/world.regiondb --lat 42.1946 --lon -122.7095 --detailed
```

## Publishing it

The published site can carry the database so a browser opens the map with
nothing to upload:

```
make regions-build            # if there is no dist/world.regiondb yet
make gh-pages-with-regions
git push origin gh-pages
```

`gh-pages-with-regions` stages the database into `site/static/regions/` and
then builds the pages tree, in that order — Zola has to see the file before
it copies `static/`. Each publish adds a fresh ~5 MB blob to the `gh-pages`
branch, which is affordable occasionally and not as a habit.

This is a way to show people the map, not a release: there is no manifest, no
checksum, and no archived history. Those arrive with the release pipeline.

See `FORMAT.md` for the compiled format and `SOURCES.md` for where the data
comes from.
