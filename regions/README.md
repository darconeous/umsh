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

### One layer is not committed

The global country boundary layer is written to `regions/build/`, not to
`regions/extracts/`. Even simplified to the tolerance the build actually uses,
it is tens of megabytes of GeoJSON per release — a diff nobody reads and a
history nobody wants. A world build therefore needs `regions-fetch` and
`regions-update` first. Every other layer, including US states, is committed,
so the test fixture and every check around it build offline from a clean
checkout.

## Layers

A position can be in several regions at once. They are independent, they may
overlap, and a lookup returns all of them.

- **Commercial airport** (`iata-airport:`) — the nearest airport that provides
  ordinary passenger service to the public, within 100 km. Not every airport
  with a scheduled flight: see `classifications/commercial-airports.yaml`.
- **Positioned IATA** (`iata-location:`) — the nearest IATA-coded location of
  any kind within 100 km, including general aviation fields and heliports.
- **Metro** (`iata-metro:`) — containment only. A metropolitan code applies
  inside its reviewed polygon and nowhere else; the nearest metro area to a
  position outside every polygon is not that position's metro area.
- **Country** (`country:`) — ISO 3166-1 alpha-2, land containment.
- **US state** (`us-state:`) — the 50 states plus the District of Columbia.
  Territories are excluded in V1; see `policy.yaml`.
- **Custom** (`custom:`) — anything a person wants to define.

Namespaces are for tooling. Both `iata-airport:SFO` and `iata-metro:SFO`
produce the radio-facing region `SFO`, and the final list carries it once.

## Expansion

Every region may be buffered outward. This exists so a repeater near a border
can be configured for both sides: without it, an operator a kilometer from a
boundary would be told about exactly one of the two regions their radio can
plainly hear. Expansion is applied after overrides, so a hand-corrected
boundary is expanded the same way a generated one is.

The compiled database keeps both the core and the effective geometry. Routing
membership uses the effective geometry; the distinction is what lets a lookup
say whether a position is really in a region or only in its margin.

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

See `FORMAT.md` for the compiled format and `SOURCES.md` for where the data
comes from.
