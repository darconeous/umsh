# ADR 0003: The shared core store, opened once per kind

- Status: Accepted
- Phase: 1

## Decision

Application state lives in the shared core's `MobileAppStore`
(`crates/umsh-mobile-core/src/store`), the same store iOS uses. Android has no
SQL of its own and ports none of the Swift migrations: the schema starts at
version 31, where those ended. A file older than that, or newer than this
build reads, is refused rather than migrated.

- **Files.** `filesDir/umsh/app.sqlite` for the live core and, in debug
  builds, `filesDir/umsh/staging.sqlite` for the staged mesh. Each is opened
  once per process and kept: the core shares the store's one connection, and
  SQLite treats a file unlinked under an open connection as corrupt.
- **One core at a time.** The process-level `AppCoreHost` makes one
  `MobileAppCore` over the current kind's store. A switch withdraws the radio,
  stops the core, ends the staged air, and closes the core before opening the
  next, so two cores never hold a radio.
- **Frame counters.** `MobileCounterStore` keeps its reservations under
  `noBackupFilesDir/counters/live` (and `…/staging`). The live directory never
  moves: any other restarts the identity's counters, and peers drop its frames
  as replays.
- **Preferences.** One Preferences DataStore,
  `filesDir/datastore/app.preferences_pb`, holds what iOS keeps in
  `UserDefaults`: the policy the core acts on (pushed with `setPolicy` on
  every change), the first-run step, and debug switches. Start over clears it
  with `edit { clear() }`; the file is never deleted under the open store.
- **Storage unavailable.** A store that will not open replaces the whole app
  with the Storage unavailable screen, which outranks onboarding. Its detail
  line is built natively per failure: SQLite's symbolic code and standard
  phrase, or the schema versions, and the file name. A corrupt file arrives as
  `SQLITE_NOTADB (26)`. Manage space works without the store, by deleting its
  files.
- **No backup.** `allowBackup="false"`, and the data extraction rules exclude
  everything, device-to-device transfer included. Restoring the counters or
  the database onto another phone would reuse counters and break peers'
  replay windows.

## Consequences

The schema, its migrations, and its tests are the core's; a change to them
lands once for both apps. The read-mapping parity goldens
(`crates/umsh-mobile-core/src/app_core/parity/`) hold Android's
`RecordMapping` and iOS's `CoreRecordMapping` to the same output.

A phone that wants its data on another phone has no path yet; that waits on
identity export.
