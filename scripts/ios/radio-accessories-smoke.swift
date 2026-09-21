import Foundation

@main
struct RadioAccessoriesSmokeTest {
    static func main() {
        let first = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        let second = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!
        let third = UUID(uuidString: "00000000-0000-0000-0000-000000000003")!
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
        let fresh = reconcile([])
        precondition(fresh.canCreateCentral && fresh.radios.isEmpty)
        precondition(!fresh.permitsConnection(to: first))
        precondition(fresh.connectionBlockDescription == nil)

        // Old apps save one UUID. Firmware generation does not decide whether
        // this needs migration: absence from ASK and from managed history does.
        var legacy = reconcile([], legacy: first)
        precondition(legacy.migrationID == first && !legacy.canCreateCentral)
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
        precondition(abandoned.canCreateCentral && abandoned.migrationID == nil)
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
