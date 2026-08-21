# Sources

Pinned in `upstream/sources.yaml`, recorded in `upstream/lock.json`, and
attributed inside every compiled database's `sources` table.

## OurAirports — positioned IATA locations and commercial candidates

`https://ourairports.com/data/`, retrieved from the
`davidmegginson/ourairports-data` mirror.

Chosen over the processed `datasets/airport-codes` CSV because that project
strips `scheduled_service`, which is the field the commercial-airport candidate
list is bootstrapped from. Public domain.

Records need a three-letter IATA code and usable coordinates to take part.
Closed facilities are dropped. Two records claiming the same IATA code at
different positions stop the update pass rather than being resolved by
whichever sorted first — the choice moves a routing boundary and has to be
somebody's decision.

### The name of this layer

The layer is called *positioned IATA locations*, not *airports*, because IATA
location codes also identify rail stations and other intermodal points. This
source is an airport database and V1 therefore ships airport-derived locations
only. Nothing in the compiled format assumes every physical IATA location is an
airport, so another point dataset can be added without a format change.

## Commercial-airport classification

`scheduled_service = yes` is where the candidate list comes from and nothing
more. The field means "some scheduled flight exists", which is not the question
the commercial layer is trying to answer — whether a person here would call
this their airport. San Carlos (`SQL`) is the standing example: general
aviation, marked as having scheduled service, and not what anyone in San Carlos
means by their airport.

`classifications/commercial-airports.yaml` has the final say in both
directions, and every entry carries a reason. The build reports candidates
whose classification looks uncertain rather than guessing.

The OpenFlights route dataset is not used. It is interesting for experiments
and too stale to be a source of truth.

## Metropolitan codes — `lxndrblz/Airports`

`citycodes.csv`, **CC BY-SA 4.0**. Used only as a seed list of metropolitan
IATA codes. Its coordinates are city center points and are never used as
geometry: a metro region is a containment polygon, and assigning one by nearest
center would give a metro code to positions well outside the metro area.

Every supported metro needs a reviewed polygon with provenance in
`metros/metros.yaml`. IATA publishes no land boundary for these codes, so each
polygon is a UMSH routing definition rather than an official boundary and says
so in its own record.

See `LICENSES.md` — this source is share-alike.

## Country boundaries — geoBoundaries CGAZ ADM0

`https://www.geoboundaries.org/`, **CC BY 4.0**, the globally dissolved ADM0
layer pinned to a commit.

The dissolved global layer is used rather than per-country downloads so that
coverage comes from one internally consistent release with no seams between
neighbors. geoBoundaries stores release data in Git LFS, so the pinned URL is
on `media.githubusercontent.com`, which serves the content rather than a
pointer file.

Features are keyed by ISO 3166-1 alpha-3 and UMSH region codes are the
two-letter form, so a crosswalk source is pinned alongside. Features with no
alpha-2 code — disputed areas and a handful of unassigned territories — are
skipped, and the update pass names each one.

Country regions are land containment. Territorial waters are not inferred; a
maritime policy can be added later as its own layer.

## US state boundaries — Census TIGER/Line 2024

`https://www.census.gov/geographies/mapping-files/time-series/geo/tiger-line-file.html`

The 50 states plus the District of Columbia. State FIPS (`GEOID`) is the source
key and `STUSPS` supplies the two-letter radio-facing code; display names are
never keys. Territories are excluded in V1 — an explicit policy choice recorded
in `policy.yaml`, not an accident of the source schema.

## ISO 3166-1 crosswalk — `datasets/country-codes`

`country-codes.csv`, PDDL 1.0. Alpha-3 to alpha-2 only. No two-letter code is
derivable from a three-letter one by rule, so a table is required.
