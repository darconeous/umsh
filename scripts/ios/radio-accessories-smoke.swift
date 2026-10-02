import Foundation

private final class EqualAccessory: NSObject {
    let identity: Int
    init(_ identity: Int) { self.identity = identity }
    override func isEqual(_ object: Any?) -> Bool {
        (object as? EqualAccessory)?.identity == identity
    }
    override var hash: Int { identity }
}

@main
struct RadioAccessoriesSmokeTest {
    static func main() {
        precondition(RadioPairingPresentation.name(advertisedName: "Backpack", modelName: "T1000-E") == "Backpack")
        precondition(RadioPairingPresentation.name(advertisedName: "  ", modelName: "T1000-E") == "T1000-E")
        precondition(RadioPairingPresentation.name(advertisedName: "山のラジオ") == "山のラジオ")
        precondition(RadioPairingPresentation.name(advertisedName: nil) == nil)
        precondition(RadioPairingPresentation.modelID(manufacturerData: Data([0xFF, 0xFF, 0x00, 0x04])) == 4)
        precondition(RadioPairingPresentation.modelID(manufacturerData: Data([0xFF, 0xFF, 0x01, 0x02])) == 0x0102)
        precondition(RadioPairingPresentation.modelID(manufacturerData: Data([0x4C, 0x00, 0x00, 0x04])) == nil,
                     "Another company's data must not name a model")
        precondition(RadioPairingPresentation.modelID(manufacturerData: Data([0xFF, 0xFF, 0x00])) == nil)
        precondition(RadioPairingPresentation.modelID(manufacturerData: nil) == nil)
        precondition(RadioPairingPresentation.name(advertisedName: " \n ") == nil)

        // The app bundles the repository's board list; check the real file.
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let catalog = try! RadioBoardCatalog(
            json: Data(contentsOf: repoRoot.appendingPathComponent("docs/hardware/boards.json"))
        )
        precondition(catalog.board(modelID: 4)?.name == "Wio Tracker L1")
        precondition(catalog.board(modelID: 4)?.photo == "board-wio-tracker-l1")
        precondition(catalog.board(modelID: 0) == nil && catalog.board(modelID: nil) == nil)
        precondition(catalog.board(modelID: 0xFF00) == nil)
        precondition(catalog.board(modelID: 6)?.photo == "board-heltec-v2")
        precondition(catalog.board(modelID: 9)?.photo == "board-tlora-pager")
        let assets = repoRoot.appendingPathComponent("apps/ios/UMSH/Assets.xcassets")
        for modelID in UInt16.min...UInt16.max {
            guard let board = catalog.board(modelID: modelID) else { continue }
            guard let photo = board.photo else {
                preconditionFailure("Every cataloged board needs a photo: \(board.name)")
            }
            precondition(FileManager.default.fileExists(
                atPath: assets.appendingPathComponent("\(photo).imageset/Contents.json").path
            ), "boards.json names a photo the asset catalog lacks: \(photo)")
        }
        precondition(RadioPairingPresentation.preferredName(current: "UMSH TRACKER 2", incoming: "UMSH TRA") == "UMSH TRACKER 2")
        precondition(RadioPairingPresentation.preferredName(current: "UMSH TRA", incoming: "UMSH TRACKER 2") == "UMSH TRACKER 2")
        precondition(RadioPairingPresentation.preferredName(current: "Old radio", incoming: "Renamed radio") == "Renamed radio")
        let first = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        let second = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!
        let third = UUID(uuidString: "00000000-0000-0000-0000-000000000003")!

        // ASK can discover a radio before it has a CoreBluetooth identifier.
        // Use the discovered object for picker selection, not a required UUID.
        var discoveries = RadioPairingDiscoveries<NSObject>(catalog: catalog)
        let pendingFirst = NSObject()
        let pendingSecond = NSObject()
        precondition(discoveries.update(pendingFirst, bluetoothID: nil, advertisedName: "UMSH TRA"))
        precondition(discoveries.entries.count == 1 && discoveries.entries[0].bluetoothID == nil)
        precondition(discoveries.update(pendingFirst, bluetoothID: nil, advertisedName: "UMSH TRACKER 2"))
        precondition(!discoveries.update(pendingFirst, bluetoothID: nil, advertisedName: "UMSH TRA"))
        precondition(discoveries.entries[0].name == "UMSH TRACKER 2")
        precondition(discoveries.update(pendingSecond, bluetoothID: nil, advertisedName: "UMSH TRACKER 2"))
        precondition(discoveries.entries.count == 2, "Equal names must not merge separate radios")
        discoveries.update(pendingFirst, bluetoothID: first, advertisedName: "UMSH TRACKER 2")
        let identifiedFirst = NSObject()
        discoveries.update(identifiedFirst, bluetoothID: first, advertisedName: "UMSH TRACKER 2")
        precondition(discoveries.entries.count == 2)
        precondition(discoveries.entries[0].accessory === identifiedFirst)
        precondition(!discoveries.update(identifiedFirst, bluetoothID: first, advertisedName: nil))
        precondition(discoveries.entries.count == 2 && discoveries.entries[0].name == "UMSH TRACKER 2",
                     "A partial report must not remove a previously named pairing discovery")
        // Pairing is a name or a model. The service UUID alone isn't.
        precondition(!discoveries.update(NSObject(), bluetoothID: nil, advertisedName: nil),
                     "A service-only advertisement must not create a setup entry")
        let modelOnly = NSObject()
        precondition(discoveries.update(modelOnly, bluetoothID: nil, advertisedName: nil, modelID: 4))
        precondition(discoveries.entries.count == 3 && discoveries.entries[2].name == "Wio Tracker L1")
        precondition(discoveries.entries[2].modelID == 4)
        precondition(!discoveries.update(modelOnly, bluetoothID: nil, advertisedName: nil))
        precondition(discoveries.entries[2].name == "Wio Tracker L1")
        precondition(discoveries.update(modelOnly, bluetoothID: nil, advertisedName: "Backpack", modelID: 4))
        precondition(discoveries.entries[2].name == "Backpack", "An advertised name outranks the model")
        let unknownModel = NSObject()
        precondition(discoveries.update(unknownModel, bluetoothID: nil, advertisedName: nil, modelID: 0xFFFE))
        precondition(discoveries.entries.count == 4 && discoveries.entries[3].name == nil)
        discoveries.removeAll()
        precondition(discoveries.entries.isEmpty, "A new picker must not reuse old discoveries")
        precondition(!discoveries.update(identifiedFirst, bluetoothID: first, advertisedName: nil),
                     "A name from an earlier picker must not admit a nameless radio")

        // The system may deliver a new selection object that compares equal.
        // Its new token still needs to reach updatePicker, even for old firmware
        // whose only reported name is shortened.
        var equalDiscoveries = RadioPairingDiscoveries<EqualAccessory>(catalog: catalog)
        let olderObject = EqualAccessory(1)
        let newerObject = EqualAccessory(1)
        precondition(equalDiscoveries.update(olderObject, bluetoothID: nil, advertisedName: "TrackerB"))
        precondition(equalDiscoveries.update(newerObject, bluetoothID: nil, advertisedName: "TrackerB"))
        precondition(equalDiscoveries.entries.count == 1 && equalDiscoveries.entries[0].accessory === newerObject)

        var updates = RadioPickerUpdates()
        updates.changed()
        precondition(updates.begin() == nil, "Discovery before presentation must wait for the picker")
        updates.isPresented = true
        let initialUpdate = updates.begin()!
        precondition(updates.begin() == nil, "An unchanged snapshot is submitted only once")
        updates.changed() // ASK may never complete the first update.
        let fullerNameUpdate = updates.begin()!
        precondition(fullerNameUpdate.revision > initialUpdate.revision)
        precondition(updates.complete(initialUpdate, succeeded: false) == .ignored,
                     "An older callback cannot block or roll back a newer submission")
        precondition(updates.complete(fullerNameUpdate, succeeded: true) == .updated)
        precondition(updates.begin() == nil)

        // Explicit failures retry without another discovery callback. Missing
        // callbacks do not imply failure or block fresh discoveries.
        updates.changed()
        let failedUpdate = updates.begin()!
        precondition(updates.complete(failedUpdate, succeeded: false) == .retry(after: 0.25))
        precondition(updates.begin() == nil)
        updates.retryReady()
        let retry = updates.begin()!
        precondition(retry.revision == failedUpdate.revision && retry.number != failedUpdate.number)
        precondition(updates.complete(failedUpdate, succeeded: true) == .ignored)
        precondition(updates.begin() == nil)
        precondition(updates.complete(retry, succeeded: false) == .retry(after: 1))
        updates.retryReady()
        let lastTry = updates.begin()!
        precondition(updates.complete(lastTry, succeeded: false) == .exhausted)
        updates.changed()
        precondition(updates.begin() == nil, "A broken picker must not retry indefinitely")
        updates = RadioPickerUpdates()
        updates.isPresented = true
        updates.changed()
        let freshTry = updates.begin()!
        precondition(updates.complete(freshTry, succeeded: true) == .updated)
        precondition(updates.begin() == nil, "A new picker starts with a fresh update budget")

        func radio(_ id: UUID, _ name: String = "Saved radio") -> DiscoveredRadio {
            DiscoveredRadio(id: id, name: name, rssiDBm: 127, isRemembered: true)
        }
        func reconcile(_ authorized: [DiscoveredRadio], _ managed: Set<UUID> = [],
                       legacy: UUID? = nil) -> RadioAccessoryInventory {
            .reconcile(authorized: authorized, previouslyManaged: managed,
                       legacyID: legacy, legacyName: "Legacy companion")
        }

        // No CoreBluetooth manager may be created before the system inventory
        // has arrived. A fresh install needs no migration, but has no access.
        precondition(!RadioAccessoryInventory().canCreateCentral)
        precondition(RadioAccessoryInventory().connectionBlockDescription == "Loading saved radios…")
        var fresh = reconcile([])
        fresh.appIsActive = true
        precondition(!fresh.canCreateCentral && !fresh.canScan && fresh.radios.isEmpty)
        precondition(fresh.needsRadioSetup)
        precondition(!fresh.permitsConnection(to: first))
        precondition(fresh.connectionBlockDescription == "Add a radio to enable access.")
        fresh.pickerActive = true
        precondition(!fresh.canCreateCentral && !fresh.canScan)
        precondition(fresh.connectionBlockDescription == "Complete or cancel the open radio setup dialog.")
        fresh.pickerActive = false // Cancelling addition must still offer setup.
        precondition(fresh.needsRadioSetup && !fresh.canCreateCentral)

        // Old apps save one UUID. Firmware generation does not decide whether
        // this needs migration: absence from ASK and from managed history does.
        var legacy = reconcile([], legacy: first)
        precondition(legacy.migrationID == first && !legacy.canCreateCentral)
        precondition(!legacy.needsRadioSetup, "A legacy radio must offer migration, not addition")
        precondition(legacy.radios.map(\.id) == [first])
        precondition(legacy.radios[0].requiresMigration)
        precondition(legacy.radios[0].name == "Legacy companion")
        precondition(!legacy.permitsConnection(to: first))
        precondition(legacy.connectionBlockDescription?.contains("Finish Radio Setup") == true)

        // Cancelling or failing a picker must not consume the migration. The
        // next launch offers the same entry, even without advertisements.
        legacy.pickerActive = true
        precondition(!legacy.canCreateCentral)
        precondition(legacy.connectionBlockDescription == "Complete or cancel the open radio setup dialog.")
        legacy = reconcile([], legacy: first)
        precondition(legacy.migrationID == first && !legacy.canCreateCentral)

        // An added accessory may be reported before picker dismissal. The
        // gate remains closed until the presentation has finished.
        var migrated = reconcile([radio(first)], legacy: first)
        migrated.pickerActive = true
        precondition(!migrated.canCreateCentral && !migrated.permitsConnection(to: first))
        migrated.pickerActive = false
        precondition(migrated.canCreateCentral && migrated.permitsConnection(to: first))
        precondition(!migrated.needsRadioSetup && migrated.connectionBlockDescription == nil)
        precondition(migrated.migrationID == nil && migrated.radios.count == 1)
        precondition(!migrated.radios[0].requiresMigration)

        // No scans or RSSI are required for saved entries, including an
        // administrative radio which was never the selected companion.
        let saved = reconcile([radio(second), radio(first)], [first, second], legacy: first)
        precondition(saved.radios.map(\.id) == [first, second])
        precondition(saved.radios.allSatisfy { $0.isRemembered && !$0.hasSignal })
        precondition(saved.permitsConnection(to: second) && !saved.permitsConnection(to: third))

        // Removal while the app was closed is reconciled against managed
        // history. A lingering companion preference must not resurrect it as
        // a legacy migration candidate or remove the other saved radio.
        let removed = reconcile([radio(second)], [first, second], legacy: first)
        precondition(removed.removedIDs == [first])
        precondition(removed.migrationID == nil && removed.radios.map(\.id) == [second])
        precondition(!removed.permitsConnection(to: first) && removed.permitsConnection(to: second))
        let removalRelaunch = reconcile([radio(second)], [first, second], legacy: first)
        precondition(removalRelaunch.migrationID == nil)

        // There is no global "already migrated" flag: an older app version
        // can later select a different radio that still needs migration.
        let laterLegacy = reconcile([radio(second)], [first, second], legacy: third)
        precondition(laterLegacy.migrationID == third && !laterLegacy.canCreateCentral)
        precondition(laterLegacy.radios.map(\.id) == [second, third])

        // Explicitly abandoning an unmigrated entry allows adding another;
        // explicitly adding a formerly removed accessory restores access.
        let abandoned = reconcile([], [first], legacy: first)
        precondition(!abandoned.canCreateCentral && abandoned.migrationID == nil)
        precondition(abandoned.needsRadioSetup)
        let lastRemoved = reconcile([], [first], legacy: first)
        precondition(lastRemoved.removedIDs == [first] && lastRemoved.needsRadioSetup)
        precondition(!lastRemoved.canCreateCentral && !lastRemoved.canScan)
        precondition(lastRemoved.connectionBlockDescription == "Add a radio to enable access.")
        let readded = reconcile([radio(first)], [first], legacy: first)
        precondition(readded.permitsConnection(to: first) && readded.removedIDs.isEmpty)

        let renamed = reconcile([radio(first, "New system name")], [first], legacy: first)
        precondition(renamed.radios[0].name == "New system name" && renamed.radios.count == 1)

        // The event stream and a suspended selection can reach a Bluetooth
        // queue in either order. A stale selection must not undo revocation.
        var queueInventory = saved
        queueInventory.revision = 10
        var revoked = removed
        revoked.revision = 11
        precondition(queueInventory.accept(revoked))
        precondition(!queueInventory.accept(migrated))
        precondition(!queueInventory.permitsConnection(to: first))
        var invalidated = revoked
        invalidated.revision = 12
        invalidated.ready = false
        precondition(queueInventory.accept(invalidated))
        precondition(!queueInventory.canCreateCentral && !queueInventory.permitsConnection(to: second))
        precondition(!queueInventory.needsRadioSetup, "An unloaded inventory is not an empty authorization list")

        // Regression: ASK can publish the saved accessory and migrationComplete
        // without an ordinary picker dismissal. Previously the row appeared
        // saved but selection AND removal remained blocked by pickerActive.
        var setup = RadioAccessorySetupState()
        precondition(setup.begin(.migration))
        precondition(!setup.begin(.addition))
        var completedMigration = reconcile([radio(first)], legacy: first)
        completedMigration.pickerActive = setup.isActive
        precondition(completedMigration.migrationID == nil)
        precondition(!completedMigration.permitsConnection(to: first))
        precondition(setup.finish(.migrationComplete))
        completedMigration.pickerActive = setup.isActive
        precondition(completedMigration.permitsConnection(to: first))
        precondition(!completedMigration.pickerActive, "Removal must be unblocked too")
        precondition(!setup.finish(.pickerDismissed), "Late dismissal must not finish twice")

        // Ordinary addition still waits for dismissal; a migration event is
        // not a reason to release its connection gate.
        precondition(setup.begin(.addition))
        precondition(!setup.finish(.migrationComplete) && setup.isActive)
        precondition(setup.finish(.pickerDismissed) && !setup.isActive)

        // Cancellation, failure and invalidation release the operation lock.
        // They do not authorize a legacy radio or erase its saved entry.
        for completion: RadioAccessorySetupState.Completion in [.pickerDismissed, .failed, .invalidated] {
            precondition(setup.begin(.migration))
            precondition(setup.finish(completion) && !setup.isActive)
            let cancelled = reconcile([], legacy: first)
            precondition(cancelled.migrationID == first && !cancelled.canCreateCentral)
            precondition(!setup.finish(completion))
        }

        // The chooser lists live connection targets, not the saved inventory.
        let now: UInt64 = 20_000_000_000
        func sighting(_ id: UUID, age: UInt64 = 0, canConnect: Bool = true,
                      name: String? = nil, rssi: Int = -62) -> RadioAccessorySighting {
            RadioAccessorySighting(
                radio: DiscoveredRadio(id: id, name: name, rssiDBm: rssi, isRemembered: false),
                lastSeen: now - age, canConnect: canConnect
            )
        }
        var available = RadioAccessoryInventory.reconcile(
            authorized: [radio(first, "UMSH radio"), radio(second, "UMSH radio")],
            previouslyManaged: [first, second], legacyID: nil, legacyName: nil,
            configuredNames: [first: "Hilltop", second: "Backpack"]
        )
        // Background connection requests remain allowed; scanning does not.
        precondition(available.canCreateCentral && !available.canScan)
        precondition(available.availableRadios(sightings: [sighting(first)], now: now).isEmpty)
        available.appIsActive = true
        precondition(available.canScan)
        precondition(available.availableRadios(sightings: [], now: now).isEmpty)
        let nearby = available.availableRadios(
            sightings: [sighting(second), sighting(first, name: "Old cached name"), sighting(third)], now: now
        )
        precondition(nearby.map(\.id) == [second, first], "Keep arrival order and exclude unauthorized radios")
        precondition(nearby.map(\.name) == ["Backpack", "Hilltop"])
        precondition(nearby.allSatisfy { $0.rssiDBm == -62 && $0.isRemembered })
        precondition(available.availableRadios(
            sightings: [sighting(first, age: 6_000_000_001), sighting(second, canConnect: false)], now: now
        ).isEmpty, "Hide expired advertisements and connected or nonconnectable devices")
        precondition(available.availableRadios(
            sightings: [sighting(first)], now: now, excluding: [first]
        ).isEmpty, "An administrative picker must not offer the companion it cannot use")
        available.pickerActive = true
        precondition(available.availableRadios(sightings: [sighting(first)], now: now).isEmpty)
        available.pickerActive = false
        available.configuredNames[first] = "Renamed radio"
        precondition(available.availableRadios(sightings: [sighting(first)], now: now).first?.name == "Renamed radio")
        available.configuredNames[first] = nil
        precondition(available.availableRadios(sightings: [sighting(first, name: "Pairing name")], now: now).first?.name == "Pairing name")
        precondition(available.availableRadios(sightings: [sighting(first)], now: now).first?.name == "UMSH radio")
        let revokedNames = RadioAccessoryInventory.reconcile(
            authorized: [radio(second)], previouslyManaged: [first, second], legacyID: nil, legacyName: nil,
            configuredNames: [first: "Removed radio", second: "Retained radio"]
        )
        precondition(revokedNames.configuredNames == [second: "Retained radio"])

        print("Accessory inventory, setup lifecycle, foreground availability, names, and connection gate checks passed")
    }
}
