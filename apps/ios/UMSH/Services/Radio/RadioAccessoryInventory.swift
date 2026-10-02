import Foundation

/// Creation-time display values come from deliberate pairing advertisements.
/// They are separate from the authenticated name cache used after connection.
enum RadioPairingPresentation {
    static func preferredName(current: String?, incoming: String) -> String {
        // Scan responses can carry a longer name than the initial packet.
        // Repeated shortened packets must not replace the longer name already
        // received during this picker session.
        if let current, current.hasPrefix(incoming) { return current }
        return incoming
    }

    /// The model identifier in a pairing advertisement's manufacturer data:
    /// the unassigned company identifier, then a big-endian identifier.
    static func modelID(manufacturerData: Data?) -> UInt16? {
        guard let bytes = manufacturerData.map(Array.init), bytes.count >= 4,
              bytes[0] == 0xFF, bytes[1] == 0xFF else { return nil }
        return UInt16(bytes[2]) << 8 | UInt16(bytes[3])
    }

    static func name(advertisedName: String?, modelName: String? = nil) -> String? {
        for candidate in [advertisedName, modelName] {
            if let name = candidate?.trimmingCharacters(in: .whitespacesAndNewlines), !name.isEmpty {
                return name
            }
        }
        return nil
    }
}

/// The supported hardware, from `docs/hardware/boards.json`. A pairing
/// advertisement names its board by model identifier.
struct RadioBoardCatalog: Sendable {
    struct Board: Decodable, Sendable {
        let modelID: UInt16
        /// The picker title.
        let name: String
        /// The asset-catalog image, for a board that has one.
        let photo: String?

        enum CodingKeys: String, CodingKey {
            case modelID = "model_id", name, photo
        }
    }

    private struct File: Decodable { let boards: [Board] }
    private let boards: [UInt16: Board]

    init() { boards = [:] }

    init(json: Data) throws {
        let file = try JSONDecoder().decode(File.self, from: json)
        boards = Dictionary(file.boards.map { ($0.modelID, $0) }, uniquingKeysWith: { first, _ in first })
    }

    func board(modelID: UInt16?) -> Board? { modelID.flatMap { boards[$0] } }

    static let bundled: RadioBoardCatalog = {
        guard let url = Bundle.main.url(forResource: "boards", withExtension: "json"),
              let catalog = try? RadioBoardCatalog(json: Data(contentsOf: url)) else {
            assertionFailure("boards.json is missing from the bundle or unreadable")
            return RadioBoardCatalog()
        }
        return catalog
    }()
}

/// Discovery precedes authorization: a Bluetooth UUID isn't required yet.
/// Keep the system's accessory object, which the picker needs for selection.
struct RadioPairingDiscoveries<Accessory: NSObject> {
    let catalog: RadioBoardCatalog

    init(catalog: RadioBoardCatalog) { self.catalog = catalog }

    struct Entry {
        var accessory: Accessory
        var bluetoothID: UUID?
        /// The advertised name, else the model's; nil for an unknown model.
        var name: String?
        var modelID: UInt16?
    }

    private(set) var entries: [Entry] = []

    mutating func removeAll() { entries.removeAll() }

    @discardableResult
    mutating func update(
        _ accessory: Accessory, bluetoothID: UUID?, advertisedName: String?, modelID: UInt16? = nil
    ) -> Bool {
        let index = entries.firstIndex {
            if let bluetoothID, $0.bluetoothID == bluetoothID { return true }
            return $0.accessory.isEqual(accessory)
        }
        let advertised = RadioPairingPresentation.name(advertisedName: advertisedName)
        let incoming = advertised ?? catalog.board(modelID: modelID)?.name
        if let index {
            let old = entries[index]
            // A report without a scan response doesn't revoke a name already
            // observed in this picker.
            let name = incoming.map { RadioPairingPresentation.preferredName(current: old.name, incoming: $0) } ?? old.name
            let model = modelID ?? old.modelID
            entries[index] = Entry(
                accessory: accessory, bluetoothID: bluetoothID ?? old.bluetoothID, name: name, modelID: model
            )
            // Equal discoveries can carry a newer system selection object.
            // Publish that object even when its identity and name are equal.
            return old.name != name || old.modelID != model || old.accessory !== accessory
        }
        // A radio advertises a name or a model only while pairing. The public
        // service UUID alone must not become a setup row.
        guard advertised != nil || modelID != nil else { return false }
        // Never merge distinct accessories by name: two radios can share it.
        entries.append(Entry(accessory: accessory, bluetoothID: bluetoothID, name: incoming, modelID: modelID))
        return true
    }
}

/// Track submitted picker snapshots without waiting for a completion callback
/// before publishing a newer discovery. Only explicit failures trigger retries.
struct RadioPickerUpdates {
    struct Attempt: Equatable {
        let revision: UInt64
        let number: UInt64
    }

    enum Completion: Equatable {
        case ignored, updated, exhausted
        case retry(after: Double)
    }

    var isPresented = false
    private var revision: UInt64 = 0
    private var submittedRevision: UInt64 = 0
    private var attemptNumber: UInt64 = 0
    private var latestAttempt: Attempt?
    private var failureCount = 0
    private var retryScheduled = false

    mutating func changed() { revision += 1 }

    mutating func begin() -> Attempt? {
        guard isPresented, !retryScheduled,
              revision != submittedRevision, failureCount < 3 else { return nil }
        attemptNumber += 1
        let attempt = Attempt(revision: revision, number: attemptNumber)
        latestAttempt = attempt
        submittedRevision = revision
        return attempt
    }

    mutating func complete(_ attempt: Attempt, succeeded: Bool) -> Completion {
        guard latestAttempt == attempt else { return .ignored }
        latestAttempt = nil
        if succeeded {
            failureCount = 0
            return .updated
        }
        failureCount += 1
        guard failureCount < 3 else { return .exhausted }
        submittedRevision = 0
        retryScheduled = true
        return .retry(after: failureCount == 1 ? 0.25 : 1)
    }

    mutating func retryReady() { retryScheduled = false }
}

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
