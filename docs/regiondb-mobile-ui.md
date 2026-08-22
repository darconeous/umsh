# Region suggestions in the iOS app

The "Update based on location" flow: how the app turns a place into a
repeater's routing regions. The geographic policy — what a position's
uncertainty means, which regions count as already configured, what each
accept mode produces — lives entirely in Rust. The app renders answers and
never re-derives them.

## The pieces

- `MobileRegionDatabase` in `UMSHMobileCore`: `open(path:)`,
  `datasetVersion()`, `formatVersion()`, `regionCount()`,
  `lookup(latitude:longitude:)`, and
  `propose(position:currentRegions:currentDefaultRegion:)`. Every failure is
  a `MobileRegionError` case carrying `summary_key`/`diagnostic_code` on the
  Rust side; the ones the UI treats specially are `PositionTooCoarse` and
  `MissingSpatialIndex`.
- `UlcpSyncRecord.ident_position` (`UlcpIdentPositionRecord`): where a
  device says it is, read at Bluetooth attach under `CAP_IDENT`. The
  encoded cell verbatim plus what it decodes to — the bytes are what a
  proposal needs, because the cell's bounds *are* the uncertainty, and the
  degrees are what a readout shows. A device advertising no position
  reports an empty cell, which is a value rather than an absence.
- `scripts/ios/stage-regiondb.sh`: copies `regions/dist/world.regiondb`
  into the built product's resources as `world.regiondb`, falls back to the
  committed Bay Area fixture with a warning on development builds, and
  refuses an archive (`ACTION=install`) without the real database.
  `make ios-archive` checks the same thing before invoking xcodebuild.
- `packages/UMSHMobileCore`: links `sqlite3` explicitly, and its test target
  carries a copy of the fixture (kept in sync by `make regions-build-fixture`)
  with lookup and proposal tests mirroring `regions/tests/known-points.yaml`.

## Two platform facts, established

**Apple's SQLite carries the R-tree module.** The shipped world database
has no lookup cache, so every lookup goes through the R-tree, and
`RegionDb::open` probes for it — but only when there is no cache, which
means a test against the fixture as built proves nothing:
`regions/tests/fixture/fixture.regiondb` has 3,003 cache rows and the
world database has none. `testLookupsWorkWithoutTheCache` empties a copy of
the fixture's cache to take the path deliberately, and the app itself
answers San Carlos out of the real 4.8 MB database on the simulator. The
`bundled-sqlite` feature of `umsh-regiondb` stays unused, and with it the
symbol-collision question against the app's own `import SQLite3`.

**The regenerated bindings are stable.** `make ios-mobile-core` reproduces
`packages/UMSHMobileCore/Sources/UMSHMobileCore/UMSHMobileCore.swift` byte
for byte on macOS; the machine without `swift-format` that first generated
them left nothing for the Mac toolchain to reformat.

## Xcode wiring

- A `PBXShellScriptBuildPhase` on the UMSH app target, after the resources
  phase, runs `"$SRCROOT"/../../scripts/ios/stage-regiondb.sh` with
  `$(SRCROOT)/../../regions/dist/world.regiondb` as its input and
  `$(BUILT_PRODUCTS_DIR)/$(UNLOCALIZED_RESOURCES_FOLDER_PATH)/world.regiondb`
  as its output, so Xcode reruns it when the database changes. It is the
  project's only script phase.
- `INFOPLIST_KEY_NSLocationWhenInUseUsageDescription` (`project.pbxproj`,
  two configurations) covers both uses: the identity announcement, and an
  on-device region lookup whose result is shown to the user and never
  transmitted. `PrivacyInfo.xcprivacy` needs nothing — it never described
  location, and a lookup that never leaves the phone collects nothing.

## RegionService

`apps/ios/UMSH/Services/Regions/RegionService.swift`, registered once in
`AppRootView` beside `PhoneLocationService` and published as two
environment entries: `\.regionService`, and `\.readPhonePosition` for one
reading of where the phone is. Both are nil in any tree that did not
register them, where the suggestion controls are simply not offered.

- `@MainActor @Observable`, with `state: loading | ready | unavailable`.
  Opening is a blocking file read plus an in-memory region table, so it
  happens off the main actor once at startup and publishes its result
  rather than being awaited into a screen.
- The database is resolved from `Bundle.main.url(forResource: "world",
  withExtension: "regiondb")` in one method. There is no downloaded copy —
  the update path waits on the site publishing a manifest — but resolution
  stays in one place so it can grow a comparison later.
- `lookup` and `propose` are `async` and hop off the main actor; the
  underlying object is `Sendable` and locks internally, and a worst-case
  lookup is about a millisecond, so a `propose` (five lookups) is well
  inside any interaction budget.
- `RegionService.text(for:)` is the catalog the Rust `summary_key` values
  name: one entry per error case, and nothing from Rust is shown directly.

`PhoneLocationService.readOnce()` answers with a single fix on its own
manager, so a lookup cannot displace the sharing schedule's callbacks. It
answers exactly once however the attempt ends, including the case nothing
else covers: a permission sheet left standing, which times out at 20 s.

Settings carries a read-only "Region database" section — dataset version
and region count, or the unavailable message. There is no app-version
footer to sit beside, so it stands on its own after Devices.

## The suggestion sheet

`apps/ios/UMSH/Features/Regions/RegionSuggestionSheet.swift` — one sheet
serving both editors. It takes the current `regions: [String]` and
`defaultRegion: Data?`, a list of position sources, and returns a
`MobileRegionOutcomeRecord` through a completion; **it never touches a
device**. The caller assigns the outcome's two fields and the editor's
existing Apply/dirty machinery remains the only path to the air.

### Position sources

Offered in this order, first available preselected:

1. **Where the node says it is** — the default whenever known. Remote:
   `identLocation` plus the decoded degrees from the identity category's
   cached reading. Bluetooth: `UlcpSyncRecord.ident_position`. The raw cell
   bytes go across as `locationBytes` so Rust owns the uncertainty.
2. **The node's own fix** — only when it lies **outside** the advertised
   cell. A coarsened advert still contains the fix it was derived from, so
   this row appears exactly when the two genuinely disagree: a stale saved
   position, or a node moved since it advertised. `accuracyM` comes from
   `accuracyDm` (decimeters → meters).
3. **This phone** — Bluetooth only, and only because at a bench the phone
   is within a few meters of the device. A node managed across the mesh is
   by definition somewhere the phone is not, so the sheet takes this as an
   explicit `offersPhone` rather than offering it wherever a location seam
   exists. `accuracyM` is the reading's `horizontalAccuracy`.
4. **Enter coordinates** — always available; two decimal fields. The only
   correct source when configuring a repeater for a site you are not
   standing at. No uncertainty (`locationBytes` and `accuracyM` nil).

Where the caller can go and read a node's position, the sheet offers that
too, rather than showing a source list with a hole in it.

`AdvertisedCell.contains` decides rule 2 from the cell's byte count: an
n-byte cell spans 180°/16ⁿ of latitude and 360°/16ⁿ of longitude around the
reported center, which is the encoding's own definition. Comparing in
meters would need a projection and would answer differently near the poles.

### Content

Once a source resolves, `propose` runs and the sheet shows:

- The matched regions like the CLI's `--detailed` view: one row per
  `lookup.matches` entry — region code, layer, and whether the position is
  in the region's own area or only its expansion margin.
  `RegionCodeText.label` renders the code half.
- The diff: the additions, `alreadyPresent`, and `notSuggested` labeled as
  kept-by-add / dropped-by-replace, plus the suggested default tag.
- An uncertainty note when `uncertainRegions` is non-empty: the position's
  cell straddles these regions' boundaries, so both sides are included.
- `PositionTooCoarse` renders as guidance to pick a better source (the
  advertised position is coarser than 25 km), not as a failure.

### Actions

- **Replace All** — returns `proposal.replace`.
- **Add N Missing** — returns `proposal.addMissing`.
- **Cancel** — dismisses.

An action whose outcome has `changesAnything == false` is disabled. Both
disabled means the sheet is purely informative and says so.

## Entry points

A button — "Update based on location" — in each region editor's flood
regions section:

- **Bluetooth** (`RepeaterSettingsSection`): writes the outcome into
  `$draft.regions` / `$draft.defaultRegion`. All four sources.
- **Remote** (`RemoteRepeaterEditor`): offered only once the regions
  property has been read — the current list is the diff base, and the
  editor already refuses edits in the "Not read" state. Writes
  `edits.regions.edited` / `edits.defaultRegion.edited`, leaving the
  existing dirty comparison to put only changed properties on the air.
  Sources 1, 2 and 4; the identity and GNSS categories are loaded from
  cache on appear, costing nothing on the air, and the sheet offers
  `refreshCategory(.identity)` when the cache has nothing.

## Commissioning a repeater

"Set up a repeater" fills the region list in from where the phone is,
without being asked (`suggestsFromPhone`). A repeater is being commissioned
at the place it will serve, so the regions covering that place are the
answer far more often than an empty list is. It takes `proposal.replace` —
the whole suggested list and tag — and everything it did is on screen: the
footer names the data release it used, and an Undo row puts back exactly
what the device reported. Nothing is written until the sheet's own Apply.

The other goals do not, and the manual button remains everywhere.

## Verification

- `cargo test -p umsh-mobile-core` — the sync record carries an advertised
  position, and an unplaced device reports an empty cell rather than
  nothing.
- `scripts/ios/verify-mobile-core-swift.sh` and
  `xcodebuild test -scheme UMSHMobileCore` — the fixture lookup and
  proposal tests prove the iOS path agrees with the Rust and Python
  references, and the uncached lookup proves the R-tree path.
- In the simulator, against the canned managed device: the remote editor's
  button appears only after a read; the advertised position, typed
  coordinates, and the read-the-node's-position offer all resolve; the
  world database answers San Carlos with SFO, SQL, US and CA; and both
  accept modes land in the editor fields, dirty and untransmitted.
- Still open, needing hardware: the Bluetooth editor, the repeater
  commissioning prefill, a node whose fix disagrees with its advert, and a
  coarse advertised cell showing the too-coarse guidance.
- `make ios-archive` in a tree without `regions/dist/world.regiondb` must
  fail with the staging message; with it, the archive's bundle must contain
  the ~4.8 MB `world.regiondb`, not the 127 KB fixture.
