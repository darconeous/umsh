# Community region packs

How a local mesh group maintains its own region definitions inside the UMSH
region database, without anyone else having to review geography they don't
know and without the group being able to affect anywhere outside its area.

The concrete motivating case is Cascadia Mesh, which has published a
recommended region layout for repeaters in its area: a hierarchy from `west`
(the whole Western US / SW Canada mesh) down through `pnw`, `wa`, `w-wa` to
metro tags like `sea`, most of them grounded in county lines, several
deliberately cross-border, and several deliberately reusing IATA short codes.
That layout is local knowledge. The people who can review whether the Palouse
includes Lewiston are in the Palouse — the database's job is to give them a
fenced place to encode it, not to encode it for them.

## What exists today

The first slice is implemented and additive-only:

- **A pack is a directory**: `regions/communities/<pack>/` with a `pack.yaml`
  manifest and a `regions.yaml` of definitions, geometry alongside as
  GeoJSON. `regions/communities/cascadia/` is a worked skeleton.
- **The fence is the whole contract.** `pack.yaml` declares an area of
  influence; the build refuses the tree if any pack region escapes it (with a
  250 m tolerance for edge wobble). Inside the fence the pack's files are
  authoritative; outside it they cannot say anything. The fence bounds what a
  pack *may* define, not what it *has* defined, so it is drawn generously.
- **Region ids are namespaced by the pack**: every id must begin with
  `custom:<pack>/`, which is what keeps packs from colliding with each other
  or with the root custom regions.
- **Packs compile as ordinary custom regions.** No format change, no reader
  change, no new layer: the phone, the Rust crate, the CLI, and the web map
  all already understand the result. A pack adds regions; it never reshapes
  the global IATA, country, or state layers.
- **Hierarchy is containment.** A region may name a `parent` defined earlier
  in the same file, and the build verifies the child lies inside it. Nothing
  more is needed at lookup time: a lookup returns every region covering the
  position, so a repeater in Seattle receives `west, pnw, wa, w-wa, sea`
  purely because the shapes nest — five entries, comfortably inside the
  identity option's ten-slot Supported Regions budget.
- **Short-code reuse is deliberate and declared.** A radio name of one to
  three ASCII alphanumerics is a short code — Cascadia's `sea` *is* `SEA`,
  the same wire code as the airport, which for a Seattle metro region is
  exactly right. The existing `allow_short_code: true` gate makes the
  identity grab a reviewed statement rather than an accident; longer names
  hash into the non-code space as usual.
- **A pack can exist without shipping.** `enabled: false` keeps a pack fully
  validated on every build while compiling nothing — the state the cascadia
  skeleton is in, because its shapes are illustrative sketches, not
  community-reviewed boundaries. Flipping the flag is the act of adoption
  and belongs in a pull request from the community itself.

## Governance is git

No new infrastructure. A pack directory gets a CODEOWNERS entry naming the
community's maintainers, which gives them review authority over their folder
and nothing else. CI validates what the build validates: containment, id
prefixes, geometry validity, name rules. A pack pull request that touches
files outside its own directory is reviewed like any other change to the
tree. The world build remains one reproducible artifact with one content
hash — delegation of authorship, not of publication.

One consequence to state plainly: the compiled database is global, so a
pack's regions appear for anyone who looks up a position inside its area,
whether or not they have heard of the community. That is the point — a
repeater operator in Spokane should be offered `geg` — and it is why the
fence and additive-only rules are invariants rather than conventions.

## Deliberately not yet

Each of these is compatible with the format as it stands; none blocks a
community from starting with drawn polygons today.

- **Geometry by reference.** The real maintainability win for a layout like
  Cascadia's: `sea` is "King, Pierce, Snohomish", so let the definition *be*
  a county list composed by the build from a counties dataset (TIGER
  counties are in the same source family as the state extracts), with
  `states:` and `regions:` composition and an optional buffer, reserving
  drawn GeoJSON for the genuinely irregular (`salishmesh`). A county list is
  reviewable in a diff by someone who knows the area; a four-thousand-vertex
  polygon is not. Needs a counties extract stage that commits only the
  counties packs actually reference.
- **Parents as unions of children.** `w-wa = sea ∪ oly ∪ kit ∪ …` plus a
  remainder, making the hierarchy self-maintaining instead of separately
  drawn. Falls out naturally once composition-by-reference exists.
- **Depth-aware ordering.** Today each pack region carries an explicit
  priority within the custom layer. A hierarchy wants deepest-first ordering
  and a say in default-region eligibility (a Seattle repeater's suggested
  packet default should arguably be `sea`, ahead of the airport layer).
  Policy hooks, not format changes.
- **Area-scoped policy overrides.** The ability for a pack to adjust IATA
  layer behavior inside its own fence — suppress a positioned location,
  reclassify an airport locally. Expressible under the same containment
  rule, but held back on purpose: it changes answers for everyone standing
  in the area, not just pack adherents, so it needs a governance story
  stronger than "the folder's owners agreed". Additive-only keeps the first
  version's blast radius at zero.
- **A dedicated `community` layer.** Packs currently ride the `custom`
  layer. If they grow their own layer name, it is a policy and viewer
  change; the compiled schema already carries layer as data.

## Manifest reference

`pack.yaml`:

```yaml
version: 1
id: cascadia            # must equal the directory name
name: Cascadia Mesh
maintainers:
  - someone@example.net
influence: geometry/influence.geojson
enabled: false          # omit (or true) once the community adopts the pack
```

`regions.yaml` entries take the same schema as `regions/custom/regions.yaml`
— `id`, `name`, `radio_name`, `geometry`, optional `expansion_m`,
`priority`, `allow_short_code`, `source.notes` — plus the pack rules: the
`custom:<pack>/` id prefix, and optional `parent` naming an earlier region
in the same file that must contain the child.

The loader and its invariants live in
`tools/regiondb-build/src/regiondb_build/sourcetree.py`
(`_load_communities`), with tests in
`tools/regiondb-build/tests/test_communities.py`.
