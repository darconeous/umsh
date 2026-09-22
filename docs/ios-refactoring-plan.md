# iOS refactoring plan

The goal is an interface that can be changed consistently and services whose
ownership and failure behavior are straightforward to understand. Work is split
into two stages so presentation cleanup can be reviewed independently of changes
to application behavior.

## Stage 1: shared presentation

Authorized scope: presentation components and their callers. Keep navigation,
selection, menus, operation lifetimes, focus, validation, persistence, and radio
ownership with their existing owners. Do not add a dependency or redesign the
application architecture in this stage.

### 1. Establish shared styles and a component gallery

- [x] Give identity rows shared spacing and typography: 12-point row spacing,
  2-point title/subtitle spacing, body titles, caption subtitles, and named
  standard (44-point) and compact (32-point) peer-avatar sizes.
- [x] Replace `AnyView` accessories with typed view builders for inline symbols
  and trailing metadata. Permit multiline contextual details.
- [x] Allow accessibility-size titles to wrap and move trailing metadata below
  the title/subtitle rather than squeezing the text column.
- [x] Give identity headers information (52-point), editable profile (64-point),
  and hero (72-point) styles. Reflow horizontal headers vertically at
  accessibility text sizes.
- [x] Add a debug-only Component Gallery in Settings and SwiftUI previews.
  Fixtures exercise favorite, unknown, stale, reported-location, unverified,
  compact, long-name, radio-setup, busy, channel, header, and field states.
  Fixtures construct no runtime, transport, database, or device operations.

### 2. Migrate identity lists

- [x] Use `PeerRow` in the peer list, discovery, conversation search, map list,
  management peer lists, repeater list, import preview, and the Settings identity row.
- [x] Preserve each caller's metadata and favorite policy. Keep actions, menu
  commands, navigation destinations, and the full-row hit area at the caller.
- [x] Share channel identity content between channel rows and search results;
  keep scope and muted-state display as explicit presentation options.

### 3. Reuse other repeated presentation

- [x] Use `RadioDiscoveryRow` in both companion selection and device setup,
  preserving their different fallback names, badges, selection rules, and
  migration actions.
- [x] Reuse identity headers in peer and local-identity profiles, onboarding,
  recovery, and conversation information links. Leave editable name bindings,
  focus, save callbacks, and explanatory text in their screens.
- [x] Extract shared status badges and number-entry presentation. Stack field
  labels above values at accessibility sizes and keep units together. Keep
  unknown readings read-only and retain field-level rejection messages.
- [x] Move shared remote fields, reading footers, problem sections, and radio
  presets out of large screen files. Share bandwidth formatting between setup
  and remote management without changing parsing, validation, or applied values.

### 4. Establish section boundaries

- [x] Extract actual child `View` types for management identity, categories,
  and lifecycle sections, Settings region-database information, radio provisioning
  information, conversation metadata, and advertised peer identity information.
- [x] Put advertised-identity rows and warnings with their reusable section,
  instead of making import screens depend on declarations in the peer screen.
- [x] Preserve screen state and operation ownership. These are presentation
  boundaries, not additional view models or a new navigation architecture.

### Validation and intentional presentation changes

Build both simulator and device targets. Inspect normal and accessibility text,
light and dark appearance, and narrow and standard widths. Compare representative
staging screens where simulator interaction is available. Check that button and
navigation wrappers, context menus, callbacks, and accessibility descriptions
remain attached after extraction. Do not add tests that simply mirror view syntax.

Intentional normalization: standard map peers use the same 44-point avatar and
caption metadata as other standard peer rows; accessibility text can increase row
height; header orientation follows Dynamic Type; bandwidth labels consistently
retain up to two fractional kilohertz digits. Existing copy and operation semantics
otherwise remain with their features.

Validation completed on September 21, 2026:

- Simulator and device Debug builds passed with Xcode 27.0 and code signing
  disabled. Existing concurrency and observation warnings remain outside this
  presentation change.
- A temporary gallery-only app rendered all four fixture groups at 320- and
  393-point widths, in light/dark appearance and `.large`/`.accessibility3`
  Dynamic Type (32 images). Representative images from every group were visually
  inspected. The narrow accessibility pass exposed clipped field values and
  wrapped units; the shared field style was corrected and the images regenerated.
  Local output is under `target/ios-ui-gallery/screenshots/`.
- The completed app launched in the simulator with staging enabled. Both the
  baseline and final launch displayed the empty Conversations screen; this is
  startup evidence, not a populated staging-data comparison.
- The renderer hosted the actual components without an application runtime.
  These checks verify component geometry, not native List interaction or complete
  screen behavior. Simulator app control was unavailable, so end-to-end navigation,
  context menus, swipe actions, keyboard/focus behavior, VoiceOver traversal, and
  populated staging-screen comparisons remain manual checks.
- `git diff --check` passed. Existing radio recovery changes were preserved;
  no service lifecycle, protocol, persistence, or device-operation changes were
  made as part of Stage 1.
- The reported map metadata regression was reproduced in the actual native
  map List over material. SwiftUI's secondary foreground styles rendered
  invisibly there, including `Color.secondary`. The shared row's subtitle and
  trailing details now use UIKit's adaptive secondary label color, as do the
  map's reporting icon and grabber. The gallery includes a native map-card
  example with last-heard ages, an older location claim, a reported neighbor,
  and distances, so this context is part of future visual checks.
  The device build passed. Simulator screenshots confirmed restored details in
  light appearance and at a 320-point width with accessibility text in dark
  appearance; results are `target/ios-ui-gallery/map-restored.png` and
  `target/ios-ui-gallery/map-restored-dark-accessibility.png`.

Stage 1 implementation is complete, including the map metadata correction.

## Stage 2: behavior and service boundaries

Authorized after the Stage 1 and Bluetooth recovery commits. The implementation
keeps the existing process-owned transport and changes the application boundaries
listed below. It does not attempt to replace every best-effort background action
or every feature-specific result type.

### 1. Repair the test foundation

- [x] Repair the persistence smoke test's historical version-12 fixture. Its
  downgrade helper currently leaves `is_reaction` present, so migration attempts
  to add an existing column. Use an actual historical schema fixture rather than
  reverse-engineering one by dropping columns from today's schema.
- [x] Add an app Swift Testing target and a small UI test target. Cover observable
  behavior and meaningful transitions, not private implementation details.
- [x] Integrate the focused checks with CI and retain the existing host smoke
  tests. Keep device-only qualification separate from simulator/build evidence.
- [x] Add narrow dependency seams where needed for deterministic identity,
  messaging, persistence, clock, and transport behavior. Avoid a blanket mock
  layer or a parallel application framework.

### 2. Make errors and operation outcomes explicit

- [x] Replace silent catches and ambiguous optional/Boolean outcomes at the
  relevant boundaries with typed results that distinguish cancellation,
  unavailable services, validation failures, and operational failures.
- [x] Keep user-facing recovery near the failed action. Reuse error presentation
  while preserving feature-specific recovery actions and retry policy.
- [x] Test that failed persistence or device operations do not report success,
  erase pending input, or leave controls permanently busy.

### 3. Split application responsibilities at ownership boundaries

- [x] Keep `AppRuntime` as the composition root; separate identity operations,
  messaging coordination, conversation drafts, and persistence-facing work into
  focused collaborators as their contracts become clear.
- [x] Preserve the single process-owned companion transport and the distinction
  between companion use and temporary administrative device sessions.
- [x] Keep AccessorySetupKit authorization in its current owner and CoreBluetooth
  in the transport layer. Do not rebuild these lifetimes to simplify a view.
- [x] Give asynchronous operations explicit cancellation and ownership semantics;
  avoid unstructured tasks that outlive the state they update.
- [x] Prefer ordinary SwiftUI composition and observable state. Introduce a
  screen model only when it owns meaningful behavior, not for every view.

### 4. Strengthen Swift/Rust contracts

- [x] Review result and error types at the UniFFI boundary and make outcomes
  exhaustive where Swift currently reconstructs meaning from strings or nil.
- [x] Keep protocol interpretation and validation with the core that owns them;
  expose the data the interface actually needs rather than duplicating decoding.
- [x] Validate boundary changes with targeted Rust and Swift tests and rebuild
  the generated bindings together with their consumers.

### 5. Narrow updates and audit concurrency

- [x] Replace broad reloads with targeted updates where measurements and call
  paths show they cause unnecessary work or stale UI. Retain clear fallback
  reconciliation rather than assuming local optimistic state is authoritative.
- [x] Audit queue and actor isolation at transport callbacks. Add assertions and
  focused tests around the real callback and connection state machines.
- [x] Check request cancellation, disconnect/reconnect, stale session responses,
  and pending-operation completion without disturbing restoration ownership.
- [x] Measure before introducing caching, extra observation layers, or new
  performance abstractions.

### Implementation and evidence

- `IdentityOperations` owns vault/store decisions and name persistence. A failed
  identity lookup cannot be mistaken for an empty install. Name-save results
  reach Settings and onboarding; onboarding keeps the entered name and stays on
  the same step after failure.
- `ConversationDraftStore` serializes each conversation's writes, retains failed
  input in memory, rejects writes after runtime shutdown, and prevents send
  cleanup from replacing newer input. A canceled caller cannot start a new
  save, but it cannot stop the clear that follows a released message either;
  only runtime shutdown refuses that write. Views report save failures and can
  retry; leaving a transcript hands off its final text without waiting for the
  debounce.
- `ChatSubmissionCoordinator` owns persist/reject/release ordering. A persistence
  failure cannot release frames. A release failure marks the stored message as
  failed without clearing its draft. Failure after release is explicitly a
  submitted message with a warning, including in the alert title. The only send
  warning is the submission's own draft-clear failure, since that is the one
  case where the composer must keep its text; a failed reload after a send is
  reported by the root view's banner instead of being repeated in the alert.
- `ApplicationStateLoader` maps a complete storage snapshot before publishing.
  Read failures retain the last usable interface and provide a retry. The store
  reads each snapshot in a read transaction. Chat submission and read cursors
  skip peer decoding and neighbor-report queries; structural changes fall back
  to full reconciliation. A test makes the report table unavailable to prove
  these conversation-only refreshes do not query it. No latency claim or new
  caching layer is based on this check.
- `UlcpOperationFailureKind` moves device-operation classification into Rust.
  Swift exhaustively switches on the kind instead of parsing English operation
  and status labels. Live changes whose chained save failed retain the existing
  unsaved-warning behavior. Input errors and compose errors also use exhaustive
  mappings of UniFFI error cases. Generated Swift bindings and both library
  slices were rebuilt together.
- Local management and device-key operations use cancelable waiters. Cancellation
  releases the caller but keeps the protocol slot occupied until completion or
  disconnect. Tests cover cancellation before registration and cancellation of
  an actual session request, including teardown. Session and GATT entry points
  assert their queue, and cross-queue operation closures are `@Sendable`.
- The version-12 fixture is frozen from commit `94502d422`, with populated
  identity, peer, draft, message, checkpoint, and archive records. It migrates to
  the current schema and opens again without depending on today's CREATE TABLE
  definitions. No application schema migration was added.
- `UMSHTests` uses Swift Testing; `UMSHUITests` verifies a failed onboarding save
  preserves input and a retry advances. Test launches use an isolated store and
  bypass Keychain/bootstrap/Bluetooth. CI runs both targets, the existing host
  checks, package tests, and simulator/device build gates.

Validation on September 21, 2026: 147 targeted Rust ULCP tests, 21 application
tests, the onboarding UI test, and simulator/device Debug builds passed, the
last two rerun after the final review fixes. All seven host smoke checks passed
against regenerated bindings: mobile-core Swift, persistence migration (including
the historical draft, message, checkpoint, and archive records), device
management, accessory lifecycle, radio host state, radio lifecycle/deadlines,
and actual-session timeout recovery. The host-state check had never linked the
mobile-core module and failed on import until this stage; it now builds the
module the way the other checks do. `git diff --check` is clean. Existing
observation, fake-radio, and transcript animation warnings remain; the three
session closure-sendability warnings are resolved. Physical iPhone/radio
qualification for cancellation and reconnection remains a separate check.

### Constraints and completion criteria

Do not add third-party dependencies, split the app into packages, change the
database schema, or introduce a new persistent outbox as incidental refactoring.
Any such proposal needs its own justification and scope. Keep unrelated working
tree changes intact and commit only when requested.

Stage 2 is complete when the focused tests exercise the affected failure paths,
ownership is explicit, the interface still offers the same actions, and both
simulator and device builds pass. Physical-radio qualification remains a separate
check for any changed connection behavior.

## Protocol changes

No ULCP or UMSH wire-protocol changes were made. The new operation-failure kind
is an app/core UniFFI record field, so the bindings and native library must be
rebuilt together; it adds no device or over-the-air field. If the boundary review reveals
a protocol change is necessary, document it separately here before implementing
it, including compatibility, firmware/host scope, and validation.
