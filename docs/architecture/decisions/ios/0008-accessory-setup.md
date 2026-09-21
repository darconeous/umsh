# ADR 0008: Use AccessorySetupKit for radio authorization and inventory

- Status: Implemented; physical iPhone qualification pending

## Decision

On iPhone, one main-actor `RadioAccessories` service owns an
`ASAccessorySession`. The companion and administrative transports consume its
immutable inventory on their own Bluetooth queues. They retain CoreBluetooth
for connection, service discovery and ULCP data exchange. This updates the
discovery and permission portions of [ADR 0007](0007-companion-ble-boundary.md).

The pickers list only system-authorized radios with a recent connectable
advertisement and no known active connection. Missing advertisements remove
the row without revoking authorization. Adding a new radio is an explicit system-picker action,
matching the ULCP service UUID advertised during pairing. The descriptor asks
the system to perform Bluetooth LE pairing. Outside pairing, the radio can
continue advertising generic flags with a rotating address. Selecting an
authorized radio retrieves its peripheral by identifier and connects directly.
While a picker is open and the app is active, its transport scans with no
service UUID filter and duplicate reports enabled. A second authorization
check filters the sightings. Each sighting lasts six seconds; a two-second
prune timer removes expired entries. No extra advertisement data is required.
Known connected peripherals and administrative sessions are excluded; the
administrative picker also excludes the companion it cannot administer.

App inactivity, setup operations and Bluetooth unavailability suspend scanning
and clear sightings. A pending discovery request resumes when those conditions
clear. Closing the picker cancels the request entirely. Foreground scanning
does not replace or consume the companion's standing reconnect request.

`radio.accessories.configuredNames` caches names received over authenticated
companion and administrative sessions, keyed by the Bluetooth identifier.
Reconciliation removes names for revoked accessories. The configured name
wins over advertising, peripheral-cache and ASK display names; a system label
is the final fallback before a configured name is learned. This cache does not
change iOS Settings names.

The two connection purposes share authorization, not transport ownership. A
companion selection persists the reconnect target; an administrative selection
is a foreground visit. The existing pending companion request, Bluetooth
background mode, restoration identifier and administrative ownership registry
remain in use. Only the companion is automatically reconnected.

## Migration and lifecycle

Apple requires migration before creating a CoreBluetooth central manager.
Both transports therefore wait for ASK activation and reconciliation before
creating their managers. If a legacy companion needs migration, the gate stays
closed until the user finishes the migration or explicitly removes that saved
entry. Opening an available-radio list may create a central once the gate
permits it; presenting the system setup picker remains an explicit action.

The legacy identifier comes from `radio.connectedUUID`, with
`radio.lastAttachedPeripheral` as a fallback. It becomes an
`ASMigrationDisplayItem.peripheralIdentifier`; firmware age is irrelevant.
Authorization of that identifier in ASK ends its migration requirement. A
cancelled or failed picker leaves an unauthorized legacy entry pending. A
successful `showPicker` callback alone does not complete setup. An add-radio
flow waits for `pickerDidDismiss`; a migration-only request also completes on
`migrationComplete`. Both paths release the operation lock and refresh the
authorized inventory. Duplicate terminal events do not complete a request
twice, and a migration event cannot complete an unrelated add-radio flow.

The conversation banner and radio details offer **Finish Radio Setup** when
the legacy entry needs migration. This starts the migration directly, then
re-arms the saved companion's reconnect request. Activation, an open setup
dialog and a missing authorization have separate messages; they do not all
instruct the user to finish a nonexistent setup step.

`radio.accessories.managedIDs` records identifiers previously authorized by
ASK, or explicitly abandoned during legacy setup. On activation, an absent
previously managed identifier is treated as removed, not as a new legacy
migration. This prevents Settings removal while the app was closed from
resurrecting a stale companion preference. There is no global migration-done
flag: an older app version can later save a different companion that still
needs migration. Explicitly adding a removed radio authorizes it again.

The system accessory list is the authority. Add/change/remove events refresh
the list; removal stops a matching live or pending app connection and clears
the companion selection when applicable. A saved identifier or an authorized
accessory is not proof of proximity, a retained firmware bond, or an intact
phone bond. Offline entries are retained in authorization storage, but hidden
from the chooser. Bluetooth queue snapshots carry a
monotonic revision so a selection resuming with an old snapshot cannot undo a
newer removal. An administrative selection abandoned during setup cannot
start a connection after its caller has disconnected.

The migration gate covers both transports, so declining a pending legacy
migration also postpones use of other saved radios. The user can remove the
legacy entry to proceed. Radios whose identifiers an old app did not retain
must be added normally. Migration does not clear firmware bonds or replace
the firmware's separate one-time security migration.

Simulator and iOS-on-Mac use their existing transport/discovery paths, without
ASK activation. No ULCP property, service UUID or firmware setting is added.

## Evidence and pending qualification

The host inventory checks exercise fresh installation, legacy discovery,
cancelled migration, authorization before picker dismissal, multiple saved
radios, offline retention, removal across relaunch, re-addition, a later legacy
identifier from an older app, name updates, stale snapshot rejection, and
migration completion without an ordinary picker dismissal. Selection and
removal must both become available after that completion event.
They do not simulate Apple's picker, bond store or radio timing.

Before deployment, qualify on physical iPhones, including the minimum
supported iOS release and a current release:

- Fresh installation: cancel and retry Add; pair each tested firmware family;
  select the result for companion and administrative use.
- Upgrade an older app with a saved bond to old firmware and to new flags-only
  privacy firmware. Try migration without opening pairing, then with pairing
  open if needed. Confirm cancellation/relaunch/retry and no premature central
  creation. Distinguish erased firmware bonds from failed app authorization.
- Upgrade with no saved companion but legacy administrative bonds. Add these
  through the picker; verify their existing radio configuration is preserved.
- Migrate while the companion has a pending background request. Confirm there
  is no central-before-migration error or competing restored session.
- Remove a connected companion and an administrative radio through the app
  and Settings, both while running and while terminated. Verify disconnection,
  pruning, relaunch behavior and deliberate re-addition. Removing one accessory
  must not disturb another radio's administrative session.
- Cancel during migration, Bluetooth startup and administrative attachment;
  no dismissed flow may acquire a radio afterward. Exercise Bluetooth off/on,
  authorization refusal, picker failure and session invalidation.
- Verify that only authorized, recently advertising, connectable radios appear;
  stale, connected and revoked radios must disappear. Test foreground return,
  Bluetooth off/on, renames of two radios, relaunch and removal of cached names.
  Confirm flags-only RPA advertisements reach the unfiltered foreground scan.
  Keep the companion's pending connection and verify locked-phone reconnection
  through absence and RPA rotation against the existing 30-second target.
- Add another radio while the companion is connected or reconnecting; inspect
  background activity for app scanning loops or extra periodic wakeups.

## Sources

- [Meet AccessorySetupKit](https://developer.apple.com/videos/play/wwdc2024/10203/)
  describes authorization, restricted CoreBluetooth discovery, and accessory
  lifecycle events.
- [Discovering and configuring accessories](https://developer.apple.com/documentation/AccessorySetupKit/discovering-and-configuring-accessories)
  documents migration display items and the restriction on initializing
  CoreBluetooth before migration completes.
