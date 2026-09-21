import Foundation

/// An accessory authorization is not evidence of radio proximity or a usable bond.
struct RadioAccessoryInventory: Sendable {
    var revision: UInt64 = 0
    var ready = false
    var radios: [DiscoveredRadio] = []
    var authorizedIDs: Set<UUID> = []
    var removedIDs: Set<UUID> = []
    var migrationID: UUID?
    var pickerActive = false
    var problem: String?
    var configuredNames: [UUID: String] = [:]
    var appIsActive = false

    /// ASK grants access per accessory. Before the first authorization a
    /// central can report poweredOff even when the phone's Bluetooth is on.
    var needsRadioSetup: Bool { ready && migrationID == nil && authorizedIDs.isEmpty }
    var canCreateCentral: Bool {
        ready && migrationID == nil && !pickerActive && !authorizedIDs.isEmpty
    }
    var canScan: Bool { canCreateCentral && appIsActive }

    /// Only a known legacy entry needs user setup. Activation and an already
    /// open system picker are different waits, with different recovery actions.
    var connectionBlockDescription: String? {
        if let problem { return problem }
        if !ready { return "Loading saved radios…" }
        if pickerActive { return "Complete or cancel the open radio setup dialog." }
        if migrationID != nil { return "This saved radio needs setup. Tap Finish Radio Setup to continue." }
        if needsRadioSetup { return "Add a radio to enable access." }
        return nil
    }

    func permitsConnection(to id: UUID) -> Bool {
        canCreateCentral && authorizedIDs.contains(id)
    }

    /// Preserve scan order, but never substitute saved inventory for a live
    /// sighting. A saved bond alone is not an available connection target.
    func availableRadios(
        sightings: [RadioAccessorySighting], now: UInt64, excluding: Set<UUID> = []
    ) -> [DiscoveredRadio] {
        guard canScan else { return [] }
        return sightings.compactMap { sighting in
            let radio = sighting.radio
            guard authorizedIDs.contains(radio.id), !excluding.contains(radio.id),
                  sighting.canConnect, now >= sighting.lastSeen,
                  now - sighting.lastSeen <= RadioAccessorySighting.lifetimeNanoseconds else { return nil }
            return DiscoveredRadio(
                id: radio.id,
                name: configuredNames[radio.id] ?? radio.name ?? radios.first { $0.id == radio.id }?.name,
                rssiDBm: radio.rssiDBm, isRemembered: true
            )
        }
    }

    /// A selection result and the event stream cross different tasks on their
    /// way to a Bluetooth queue. An older result must not restore revoked access.
    @discardableResult
    mutating func accept(_ update: Self) -> Bool {
        guard update.revision >= revision else { return false }
        self = update
        return true
    }

    /// Previously managed IDs prevent a Settings removal from being mistaken
    /// for an unmigrated legacy pairing on the next launch.
    static func reconcile(
        authorized: [DiscoveredRadio], previouslyManaged: Set<UUID>,
        legacyID: UUID?, legacyName: String?, configuredNames: [UUID: String] = [:]
    ) -> Self {
        let ids = Set(authorized.map(\.id))
        let migration = legacyID.flatMap { id in
            !ids.contains(id) && !previouslyManaged.contains(id) ? id : nil
        }
        var radios = authorized
        if let migration {
            radios.append(DiscoveredRadio(
                id: migration, name: legacyName, rssiDBm: 127,
                isRemembered: true, requiresMigration: true
            ))
        }
        return Self(
            ready: true, radios: radios.sorted { $0.id.uuidString < $1.id.uuidString },
            authorizedIDs: ids, removedIDs: previouslyManaged.subtracting(ids),
            migrationID: migration, configuredNames: configuredNames.filter { ids.contains($0.key) }
        )
    }
}

struct RadioAccessorySighting: Sendable {
    static let lifetimeNanoseconds: UInt64 = 6_000_000_000
    let radio: DiscoveredRadio
    let lastSeen: UInt64
    let canConnect: Bool
}

/// Migration has its own completion event. Waiting only for the ordinary
/// picker dismissal can leave a successfully migrated radio locked out.
struct RadioAccessorySetupState: Sendable {
    enum Kind: Sendable { case addition, migration }
    enum Completion: Sendable { case pickerDismissed, migrationComplete, failed, invalidated }

    private(set) var kind: Kind?
    var isActive: Bool { kind != nil }

    mutating func begin(_ kind: Kind) -> Bool {
        guard !isActive else { return false }
        self.kind = kind
        return true
    }

    /// True exactly once for an operation's terminal event. A migration
    /// notification must not complete an unrelated add-radio picker.
    mutating func finish(_ completion: Completion) -> Bool {
        guard let kind else { return false }
        if completion == .migrationComplete && kind != .migration { return false }
        self.kind = nil
        return true
    }
}
