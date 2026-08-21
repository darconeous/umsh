# Region suggestions in the iOS app

The specification for the "Update based on location" flow. The Rust facade,
bindings, packaging, and staging described here are already in the tree; this
document describes the SwiftUI work that consumes them, precisely enough to
build from. The geographic policy — what a position's uncertainty means, which
regions count as already configured, what each accept mode produces — lives
entirely in Rust; the app renders answers and never re-derives them.

## What already exists

- `MobileRegionDatabase` in `UMSHMobileCore`: `open(path:)`,
  `datasetVersion()`, `formatVersion()`, `regionCount()`,
  `lookup(latitude:longitude:)`, and
  `propose(position:currentRegions:currentDefaultRegion:)`. All errors are
  `MobileRegionError` cases with `summary_key`/`diagnostic_code` on the Rust
  side; the interesting ones for the UI are `PositionTooCoarse` and
  `MissingSpatialIndex`.
- `scripts/ios/stage-regiondb.sh`: copies `regions/dist/world.regiondb` into
  the built product's resources as `world.regiondb`, falls back to the
  committed Bay Area fixture with a warning on development builds, and
  refuses an archive (`ACTION=install`) without the real database.
  `make ios-archive` checks the same thing before invoking xcodebuild.
- `packages/UMSHMobileCore`: links `sqlite3` explicitly, and its test target
  carries a copy of the fixture (kept in sync by `make regions-build-fixture`)
  with lookup/proposal tests that mirror `regions/tests/known-points.yaml`.

## Before anything else: two facts to establish on a Mac

1. **Apple's SQLite has the R-tree module?**
   `sqlite3 :memory: "create virtual table t using rtree(id,x0,x1);"`
   The shipped world database has no lookup cache, so every lookup uses the
   R-tree. `RegionDb::open` probes for it and returns `MissingSpatialIndex`
   when absent. If the probe fails on iOS, enable the `bundled-sqlite`
   feature of `umsh-regiondb` for the iOS build — and then audit symbol
   collision with the app's own `import SQLite3` deliberately, because
   `rusqlite/bundled` does not prefix its symbols.
2. **The regenerated `UMSHMobileCore.swift` compiles and its tests pass:**
   `make ios-mobile-core`, `scripts/ios/verify-mobile-core-swift.sh`,
   `xcodebuild test -scheme UMSHMobileCore`. The bindings were regenerated on
   a machine without `swift-format`; if the macOS toolchain reformats the
   file, commit the reformatted version and note it.

## Xcode wiring

- Add a `PBXShellScriptBuildPhase` to the UMSH app target, **after** the
  resources phase, running `"$SRCROOT"/../../scripts/ios/stage-regiondb.sh`.
  Declare `$(SRCROOT)/../../regions/dist/world.regiondb` as an input and
  `$(BUILT_PRODUCTS_DIR)/$(UNLOCALIZED_RESOURCES_FOLDER_PATH)/world.regiondb`
  as an output so Xcode reruns it when the database changes. The project has
  no script phases today.
- `PrivacyInfo.xcprivacy` and
  `INFOPLIST_KEY_NSLocationWhenInUseUsageDescription`
  (`project.pbxproj`, two configurations) currently describe location as used
  only for the identity announcement. Reword to also cover an on-device
  region lookup whose result is shown to the user and never transmitted —
  for example: "UMSH reads your location only when you choose to include it
  in the identity your phone announces to the mesh, or to look up the mesh
  regions around you on this device; lookups never leave your phone."

## RegionService

`apps/ios/UMSH/Services/Regions/RegionService.swift`, registered once in
`AppRootView` beside `PhoneLocationService` (the one-seam convention).

- `@MainActor @Observable final class RegionService`. Opening is a blocking
  file read plus an in-memory region table, so do it off the main actor once
  at startup (`Task.detached` or an async `load()` awaited lazily) and
  publish `state: unavailable(message) | ready(MobileRegionDatabase)`.
- Resolve the database from `Bundle.main.url(forResource: "world",
  withExtension: "regiondb")`. There is no downloaded copy yet — the update
  path is deliberately deferred until the site publishes a manifest — but
  keep resolution in one method so it grows a comparison later.
- Expose `datasetVersion: String?`, `regionCount: UInt32?`,
  `lookup(latitude:longitude:)` and
  `propose(position:currentRegions:currentDefaultRegion:)` as `async` methods
  that hop off the main actor; the underlying object is `Sendable` and locks
  internally, and a worst-case lookup is about a millisecond, so a `propose`
  (five lookups) is well under any interaction budget.
- Map `MobileRegionError` to user strings here, keyed by case — the Rust
  `summary_key` values name the catalog entries.

Settings gains a "Region database" row (near the app-version footer in
`SettingsView`): dataset version and region count, or the unavailable
message. No actions yet.

## The suggestion sheet

`apps/ios/UMSH/Features/Regions/RegionSuggestionSheet.swift` — one sheet
serving both editors. It receives the current `regions: [String]` and
`defaultRegion: Data?`, a list of position sources (below), and returns a
`MobileRegionOutcomeRecord` through a completion; **it never touches a
device**. The caller assigns the outcome's two fields and the editor's
existing Apply/dirty machinery remains the only path to the air.

### Position sources

Offered in this order, first available preselected:

1. **Node's advertised position** — the default whenever known.
   - Remote: `identLocation` bytes from the identity category's cached
     reading (`UlcpDevicePropertiesRecord.identLocation` plus the decoded
     `identLatitudeDeg`/`identLongitudeDeg`), or
     `PeerSummary.advertisedIdentity` when the management cache has nothing.
   - BLE: the setup draft's identity location.
   - Pass the raw cell bytes as `locationBytes` so Rust owns the
     uncertainty.
2. **Node's GNSS fix** — only when it lies **outside** the advertised cell
   (test with the cell bounds; the mobile core exposes both). A coarsened
   advert still contains the fix it was derived from, so this row appears
   exactly when the two genuinely disagree — a stale saved position, or a
   node moved since it advertised. Pass `accuracyM` from
   `UlcpGnssRecord.accuracyDm` (decimeters → meters).
3. **This phone** — BLE path only, via `PhoneLocationService`; it is a proxy
   for where the radio is, honest only when they are in the same place. Pass
   the reading's `horizontalAccuracy` as `accuracyM`.
4. **Enter coordinates** — always available; two decimal fields. The only
   correct source when configuring a repeater for a site you are not
   standing at. No uncertainty (`locationBytes` and `accuracyM` nil).

Render the chosen position with the existing `LocationPresentation` helpers,
including its stated uncertainty (`cellMeters` from the proposal).

### Content

Once a source resolves, call `propose` and show:

- The matched regions like the CLI's `--detailed` view: one row per
  `lookup.matches` entry — region key, radio name, layer, core/expanded.
  `RegionCodeText.label` renders the code half.
- The diff: `alreadyPresent` (kept), the additions (rows in
  `replace.regions` not in `alreadyPresent`), and `notSuggested` (current
  regions the position does not account for, labeled as kept-by-add /
  dropped-by-replace).
- An uncertainty note when `uncertainRegions` is non-empty: the position's
  cell straddles these regions' boundaries, so both sides are included —
  name them.
- `PositionTooCoarse` renders as guidance to pick a better source (the
  advertised position is coarser than 25 km), not as a failure.

### Actions

- **Replace all** — return `proposal.replace`.
- **Add N missing** (N from the appended count) — return
  `proposal.addMissing`.
- **Cancel** — dismiss.

Disable an action whose outcome has `changesAnything == false` and label it
"already matches". Both disabled means the sheet is purely informative.

## Entry points

A button — "Update based on location" — in each region editor's Flood
regions section:

- **BLE** (`RepeaterSettingsSection`): writes the outcome into
  `$draft.regions` / `$draft.defaultRegion`. Sources 1 (draft identity), 2,
  3, 4.
- **Remote** (`RemoteRepeaterEditor`): enabled only once the regions
  property has been read — the current list is the diff base, and the editor
  already refuses edits in the "Not read" state. Writes
  `edits.regions.edited` / `edits.defaultRegion.edited` and marks both
  properties dirty only when the value actually changed, so only changed
  properties go on the air. Sources 1 (identity category cache, offering
  `refreshCategory(.identity)` when unread), 2 (remote GNSS reading), 4.

## Verification

- `xcodebuild test -scheme UMSHMobileCore` — the fixture lookup and proposal
  tests prove the iOS path agrees with the Rust/Python references.
- In the simulator, against a fake radio: both editors; each applicable
  source; both accept modes landing in the editor fields without
  transmitting; a coarse advertised cell showing the too-coarse guidance;
  and a node whose GNSS fix disagrees with its advert showing source 2.
- `make ios-archive` in a tree without `regions/dist/world.regiondb` must
  fail with the staging message; with it, the archive's bundle must contain
  the ~4.8 MB `world.regiondb`, not the 127 KB fixture.
