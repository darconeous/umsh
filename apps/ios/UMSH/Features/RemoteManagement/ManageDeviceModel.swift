import Foundation
import UMSHMobileCore

/// How a device being managed is reached, which decides what managing it
/// may assume: a local link is fast enough to refresh on sight and pushes
/// unsolicited values; the mesh is neither, and every read is the
/// operator's to spend.
enum DeviceManagementLink: Equatable {
    /// Across the mesh, through the companion radio.
    case mesh
    /// The companion radio itself, over its own local link.
    case companion
    /// A bench device over a foreground administrative BLE session.
    case administrative
}

/// Everything managing a device needs from the app: the way to reach it,
/// and the store to remember what it said.
///
/// A bundle of closures for the same reason `PeerActions` is one: the peer
/// sheet is presented from several places, and threading these through each
/// of them one parameter at a time is how the same screen ends up able to do
/// different things depending on where it was opened. It is also what makes
/// the management screens transport-blind: a mesh exchange, the companion's
/// own link, and a bench BLE session all fit behind the same handful of
/// closures.
struct DeviceManagementBackend {
    var link: DeviceManagementLink = .mesh
    /// Read named properties, reporting how many the read has left to ask
    /// for, and answer with what the device said about each.
    var fetch: (String, [UInt32], Bool, @escaping @Sendable (UInt32?) -> Void) async throws
        -> [MobileMeshManagementAnswerRecord]
    /// Write properties, answering with what the device says each is now
    /// worth.
    var write: (String, [MobileMeshPropertyWriteRecord]) async throws
        -> [MobileMeshManagementAnswerRecord]
    var save: (String) async throws -> Void
    var setAdministrator: (String, Data, Bool) async throws -> Void
    var setPeer: (String, Data, Bool) async throws -> Void
    /// Make the device conspicuous, or stop it, answering with what it
    /// reports it is doing.
    var setAlert: (String, RadioAlertState) async throws -> RadioAlertState
    /// Act on the device itself rather than on its settings: restart it, or
    /// return it to a blank factory state. Both are answered by the device
    /// doing the thing and saying nothing, so success here means the
    /// command was delivered, not that the device has finished.
    var reset: (String, MobileMeshResetScope) async throws -> Void
    /// This phone's own node key, so the administrator list can say which
    /// entry is this phone — and refuse to remove it.
    ///
    /// Asked of the radio rather than read off the local identity: what the
    /// managed device sees requests arrive from is the key the mesh session
    /// sends as, and a guard against locking this phone out has to be
    /// keyed on the one the device would actually match.
    var phoneNodeKey: () async -> Data?

    /// What this phone last learned about the device, and where to put what
    /// it learns next. Without a store these read empty and write nowhere,
    /// which costs a fetch on every open rather than breaking anything.
    var loadCard: (String) async -> StoredManagementCard?
    var saveCard: (String, StoredManagementCard) async -> Void
    var forgetCache: (String) async -> Void
    var loadValues: (String, [UInt32]) async -> [UInt32: StoredCachedProperty]
    var saveValues: (String, [UInt32: Data]) async -> Void

    /// Values the device announces on its own, for backends that have a
    /// live link to hear them on. `nil` on the mesh: a device pushes only
    /// to the host it is attached to, never across the network.
    var propertyPushes: (() -> AsyncStream<UlcpPropertyPushRecord>)? = nil
}

extension DeviceManagementBackend {
    /// Whether a screen that opens without fresh values should ask for
    /// them on sight. On a local link the answer arrives in the time a
    /// screen takes to settle; on the mesh it costs everyone airtime, so
    /// asking stays the operator's decision.
    var refreshesStaleReadings: Bool { link != .mesh }

    /// Whether to offer a factory reset at all.
    ///
    /// Only where the device is in hand. A wipe takes the device's identity
    /// with it, so the node the command was addressed to stops existing
    /// mid-exchange — there is no confirmation to wait for and no way back
    /// if it was the wrong node. Restarting is offered everywhere; this is
    /// not.
    var offersFactoryReset: Bool { link != .mesh }

    /// Whether where this phone is stands for where the device is.
    ///
    /// True on a local link — a bench session or the companion radio — where
    /// the two are within a few meters of each other, and where the phone's
    /// own fix is the freshest thing either of them knows. Across the mesh
    /// the device is by definition somewhere the phone is not, so its
    /// position there would propose regions for the operator's desk.
    var phoneStandsForDevice: Bool { link != .mesh }
}

/// The property numbers the management screens name, read once.
let ulcpProperties = ulcpManagedPropertyIds()

extension UlcpDevicePropertiesRecord {
    /// A device nothing has been read from.
    ///
    /// Built by decoding nothing rather than written out field by field, so
    /// a property added to the record needs no second place to be told
    /// about it.
    static let empty = inspectUlcpProperties(responses: [])
}

/// The properties one management screen is about, and what is known of them.
///
/// Held per category rather than per device because that is the unit that
/// goes on the air: a screen asks for its own handful and nothing else.
///
/// The octets are the truth here and the decoded record is derived from
/// them, so a write's echoes fold in as a dictionary merge — no field of
/// the record needs its own rule for what a partial update means.
struct RemoteCategoryReading {
    /// What each property last came back as, verbatim.
    private(set) var values: [UInt32: Data] = [:]
    /// What those octets mean.
    private(set) var properties = UlcpDevicePropertiesRecord.empty
    /// The properties this category covers on this device, in ask order.
    var propertyIDs: [UInt32] = []
    /// Properties the device refused, which is how it says it does not
    /// implement one its capabilities implied.
    var refused: Set<UInt32> = []
    /// When the values on screen were learned. `nil` means nothing has been
    /// read, so the fields have nothing to prefill from.
    private(set) var asOf: Date?
    /// Whether any of it came off the air this session, as opposed to out of
    /// the cache. A refreshed screen stops dating what it shows.
    private(set) var isFresh = false

    /// Take in values the device reported, from a read or from a write's
    /// echoes, and redecode around them.
    mutating func absorb(_ reported: [UInt32: Data], at instant: Date, fromAir: Bool) {
        values.merge(reported) { _, reported in reported }
        properties = inspectUlcpProperties(
            responses: values.map { ulcpPropertyRecord(propertyId: $0.key, value: $0.value) }
        )
        asOf = instant
        isFresh = isFresh || fromAir
    }
}

/// One device managed across the mesh: what it is, what it holds, and the
/// one operation at a time this phone is allowed to run against it.
///
/// Deliberately not a session — there is nothing to hold open. An operation
/// is a handful of frames that either come back or do not, and a failure is
/// reported rather than recovered from. What makes this worth an object is
/// the cache: the card and the last-known values are what let opening a
/// device's settings cost nothing, and they have to outlive any one screen.
@MainActor
@Observable
final class ManageDeviceModel {
    /// What the device is. `nil` until the first card fetch lands, which is
    /// the one exchange this screen cannot avoid.
    private(set) var card: UlcpDeviceCardRecord?
    private(set) var cardAsOf: Date?
    /// What each category last read.
    private(set) var readings: [UlcpManageCategory: RemoteCategoryReading] = [:]
    /// What the device is doing to make itself findable, once asked.
    private(set) var alert: RadioAlertState = .none
    /// The device may run one operation at a time, so the whole screen is
    /// held while any of them is out.
    private(set) var isBusy = false
    /// Properties the running fetch has yet to ask for, for progress.
    private(set) var propertiesRemaining: UInt32?
    /// What went wrong, in a sentence an operator can act on.
    var problem: String?
    /// Values the device rejected on the last apply, by property — each a
    /// sentence for the row that offered the value. Cleared by the next
    /// apply or refresh of that category.
    private(set) var writeRefusals: [UlcpManageCategory: [UInt32: String]] = [:]

    let address: String
    /// What to call the device before it has said. The peer's own name.
    let fallbackName: String
    private let management: DeviceManagementBackend

    init(peer: PeerSummary, management: DeviceManagementBackend) {
        address = peer.identity.canonicalAddress
        fallbackName = peer.displayName
        self.management = management
    }

    /// What to show as the device's name: what it calls itself, then what
    /// this phone calls it.
    var displayName: String { card?.deviceName ?? fallbackName }

    /// Whether this device says it can restart on command (`CAP_REBOOT`).
    /// Read off the cached card, so offering the control costs no airtime.
    var supportsRestart: Bool { card?.supportsReboot ?? false }

    /// Whether a factory reset is offered here at all — a question about
    /// how the device is reached, not about what it can do.
    var offersFactoryReset: Bool { management.offersFactoryReset }

    /// Whether this phone's own position can stand in for the device's — a
    /// question about how the device is reached, not about what it can do.
    var phoneStandsForDevice: Bool { management.phoneStandsForDevice }

    /// This phone's own node key, once the radio has said what it is.
    private(set) var phoneNodeKey: Data?

    /// Ask the radio for this phone's key, once.
    ///
    /// Costs nothing on the air — it is the attached radio answering about
    /// itself — but it is a round trip over the link, so it is not repeated
    /// on every screen that opens.
    private func learnPhoneNodeKey() async {
        guard phoneNodeKey == nil else { return }
        phoneNodeKey = await management.phoneNodeKey()
    }

    // MARK: - The card

    /// Whether the card on screen came off the air during this model's
    /// lifetime, as opposed to out of the cache.
    private var cardIsFresh = false

    /// Fill the card in from the cache, and ask the device only if this
    /// phone has never asked — or if the device is on a local link, where
    /// asking costs nothing anyone else can hear.
    ///
    /// The whole point of the design: over the mesh, the second and every
    /// later opening of a device's settings puts nothing on the air. On a
    /// local link the cached card still renders first, and the fresh read
    /// also revalidates the firmware version, so a reflashed device sheds
    /// its stale cache the moment its settings open.
    func loadCard() async {
        await learnPhoneNodeKey()
        guard !isBusy else { return }
        if card == nil, let stored = await management.loadCard(address) {
            adopt(stored)
        }
        if card == nil || (management.refreshesStaleReadings && !cardIsFresh) {
            await refreshCard()
        }
    }

    /// Ask the device what it is, whether or not this phone already knows.
    func refreshCard() async {
        await run { [self] in
            let answers = try await fetch(ulcpCardProperties(), multiHint: true)
            let fetched = try inspectUlcpDeviceCard(
                responses: ulcpRecordsFromAnswers(answers: answers)
            )
            // Different firmware may hold different properties, so what was
            // cached about the old firmware is not about this device any
            // more. The store drops the values; this drops what is on
            // screen.
            if fetched.deviceVersion != card?.deviceVersion {
                readings.removeAll()
            }
            let now = Date()
            await management.saveCard(
                address,
                StoredManagementCard(
                    capabilities: fetched.capabilities,
                    deviceVersion: fetched.deviceVersion,
                    deviceModel: fetched.deviceModel,
                    deviceName: fetched.deviceName,
                    fetchedAt: now
                )
            )
            card = fetched
            cardAsOf = now
            cardIsFresh = true
        }
    }

    /// Rebuild the card from what the store kept.
    ///
    /// Only the capabilities need decoding; the rest of a card is text the
    /// store holds as text. A stored blob that will not decode is one this
    /// build cannot use, and asking the device again is the only repair.
    private func adopt(_ stored: StoredManagementCard) {
        guard let decoded = try? inspectUlcpDeviceCard(
            responses: [
                ulcpPropertyRecord(
                    propertyId: ulcpProperties.caps,
                    value: stored.capabilities
                )
            ]
        ) else { return }
        card = UlcpDeviceCardRecord(
            capabilities: decoded.capabilities,
            deviceVersion: stored.deviceVersion,
            deviceModel: stored.deviceModel,
            deviceName: stored.deviceName,
            supportsDeviceName: decoded.supportsDeviceName,
            supportsBattery: decoded.supportsBattery,
            supportsLora: decoded.supportsLora,
            supportsDutyCycleLimit: decoded.supportsDutyCycleLimit,
            supportsRepeater: decoded.supportsRepeater,
            supportsIdent: decoded.supportsIdent,
            supportsDeviceIdentity: decoded.supportsDeviceIdentity,
            supportsGnss: decoded.supportsGnss,
            supportsAdvert: decoded.supportsAdvert,
            supportsAdmin: decoded.supportsAdmin,
            supportsAlert: decoded.supportsAlert,
            supportsReboot: decoded.supportsReboot,
            supportsSave: decoded.supportsSave,
            supportsMulti: decoded.supportsMulti
        )
        cardAsOf = stored.fetchedAt
    }

    // MARK: - Categories

    /// What one category covers on this device, or nothing when the device
    /// has none of it.
    func properties(of category: UlcpManageCategory) -> [UInt32] {
        guard let card,
              let properties = try? ulcpCategoryProperties(
                  category: category,
                  capabilities: card.capabilities
              )
        else { return [] }
        return properties
    }

    /// Fill a category in from the cache, and — on a local link — follow
    /// with a fresh read when nothing has come off the air this session.
    ///
    /// Every screen opens from the cache first, read-only ones included.
    /// Over the mesh it stays that way: an operator who wants a current
    /// reading asks for one, and one who is walking the screens to see
    /// what is there does not spend a device's airtime doing it. A local
    /// link answers in the time the screen takes to settle, so there the
    /// stale-or-empty case refreshes itself — but only that case: a
    /// screen already refreshed this session is not re-asked on every
    /// visit, and nothing ever reads a category no screen is showing.
    func loadCategory(_ category: UlcpManageCategory) async {
        if readings[category] == nil {
            let properties = properties(of: category)
            guard !properties.isEmpty else { return }
            let cached = await management.loadValues(address, properties)
            var reading = RemoteCategoryReading()
            reading.propertyIDs = properties
            if let oldest = cached.values.map(\.fetchedAt).min() {
                reading.absorb(
                    cached.mapValues(\.value),
                    at: oldest,
                    fromAir: false
                )
            }
            readings[category] = reading
        }
        if management.refreshesStaleReadings, readings[category]?.isFresh == false {
            await refreshCategory(category)
        }
    }

    /// Ask the device for one category's properties.
    func refreshCategory(_ category: UlcpManageCategory) async {
        let properties = properties(of: category)
        guard !properties.isEmpty, let card else { return }
        writeRefusals[category] = nil
        await run { [self] in
            let answers = try await fetch(properties, multiHint: card.supportsMulti)
            let reported = Self.values(in: answers)
            await management.saveValues(address, reported)
            // Replaced rather than merged: a refusal means the device does
            // not hold that property at all, and carrying an older value for
            // it forward would show a setting that is not there.
            var reading = RemoteCategoryReading()
            reading.propertyIDs = properties
            reading.refused = Set(answers.filter { $0.value == nil }.map(\.propertyId))
            reading.absorb(reported, at: Date(), fromAir: true)
            readings[category] = reading
        }
    }

    /// Write the fields the operator changed, and save.
    ///
    /// What the device echoes is what it is now holding, which is not always
    /// what was asked for — a transmit power above what the hardware can
    /// reach comes back clamped. Those echoes are the readback: they answer
    /// the question a second full read would have asked, and they cost
    /// nothing extra.
    ///
    /// Returns whether the device answered — false when nothing reached it,
    /// which is when the operator's unapplied fields are still the only
    /// record of what they asked for and must not be thrown away.
    @discardableResult
    func apply(
        _ category: UlcpManageCategory,
        desired: UlcpDevicePropertiesRecord,
        dirty: Set<UInt32>
    ) async -> Bool {
        guard !dirty.isEmpty else { return true }
        var answered = false
        writeRefusals[category] = nil
        await run { [self] in
            let writes = try ulcpDirtyWrites(
                desired: desired,
                dirtyPropertyIds: Array(dirty).sorted()
            )
            let answers = try await management.write(address, writes)
            answered = true
            let echoed = Self.values(in: answers)
            await management.saveValues(address, echoed)
            readings[category]?.absorb(echoed, at: Date(), fromAir: true)

            // A status where a value belonged is a setting the device would
            // not take. Each rejection goes on the row that offered the
            // value; nothing is saved, and saying so is the difference
            // between a device left half-changed and one an operator knows
            // to look at.
            let refused = answers.filter { $0.value == nil }
            guard refused.isEmpty else {
                writeRefusals[category] = refused.reduce(into: [:]) { map, answer in
                    map[answer.propertyId] = Self.refusalText(answer.statusCode)
                }
                problem = "Settings the device did accept are running but not saved."
                return
            }
            try await management.save(address)
        }
        return answered
    }

    /// Why the device would not take a value, said for the row that
    /// offered it.
    private static func refusalText(_ status: UInt32?) -> String {
        guard let status else { return "The device rejected this value." }
        let reason = switch status {
        case 2, 13: // UNIMPLEMENTED, PROP_NOT_FOUND
            "the device does not implement this setting"
        case 3: // INVALID_ARGUMENT
            "the device says it is out of range"
        case 4: // INVALID_STATE
            "the device's current state does not allow it"
        case 11: // NOMEM
            "it is too large for the device to hold"
        case 10, 12: // IN_PROGRESS, BUSY
            "the device was busy — try again"
        default:
            "the device answered \(ulcpStatusName(status: status))"
        }
        return "Rejected: \(reason)."
    }

    // MARK: - Peers and administrators

    /// Bring one of the device's key tables to `desired`, and save.
    ///
    /// Removals before additions, because a full table takes a removal but
    /// not an addition.
    func setKeys(_ desired: Set<Data>, administrators: Bool) async {
        let property = administrators
            ? ulcpProperties.devAdmins
            : ulcpProperties.devPeers
        let reading = readings[.peerNodes]
        let current = Set(
            (administrators
                ? reading?.properties.devAdminKeys
                : reading?.properties.devPeerKeys) ?? []
        )
        guard current != desired else { return }
        await run { [self] in
            let edit = administrators ? management.setAdministrator : management.setPeer
            for key in current.subtracting(desired) {
                try await edit(address, key, false)
            }
            for key in desired.subtracting(current) {
                try await edit(address, key, true)
            }
            // Live the moment the device answers, and saved only when it is
            // told to — unlike the Bluetooth path, where the session chains
            // a save behind each mutation.
            try await management.save(address)
            let table = desired.sorted { $0.lexicographicallyPrecedes($1) }
                .reduce(into: Data()) { $0 += $1 }
            await management.saveValues(address, [property: table])
            var updated = readings[.peerNodes] ?? RemoteCategoryReading()
            updated.absorb([property: table], at: Date(), fromAir: true)
            readings[.peerNodes] = updated
        }
    }

    // MARK: - Following the device's own announcements

    /// Fold values the device announces on its own into whatever is on
    /// screen, for as long as the caller keeps this running.
    ///
    /// Local links only — the backend says whether there is anything to
    /// hear. A push merges like a write's echo: the affected readings
    /// redecode around it, clean fields on an editor follow it, and a
    /// field the operator is editing keeps the edit. It deliberately does
    /// not care whether an operation is in flight; the device's latest
    /// word wins whichever order the two land in.
    func observePushes() async {
        guard let pushes = management.propertyPushes else { return }
        for await push in pushes() {
            await absorb(push)
        }
    }

    private func absorb(_ push: UlcpPropertyPushRecord) async {
        if push.propertyId == ulcpProperties.alert,
           let reported = try? inspectUlcpAlert(value: push.value)
        {
            alert = RadioAlertState(reported)
        }
        var affected = false
        for (category, var reading) in readings
        where reading.propertyIDs.contains(push.propertyId) {
            reading.absorb([push.propertyId: push.value], at: Date(), fromAir: true)
            readings[category] = reading
            affected = true
        }
        // Remembered only when some screen holds it: a category never
        // opened will read itself fresh on first sight, and pushes exist
        // only on the links where that read is cheap.
        if affected {
            await management.saveValues(address, [push.propertyId: push.value])
        }
    }

    // MARK: - Finding the device

    /// Make the device conspicuous, or stop it.
    ///
    /// The one control here that acts on the device rather than on its
    /// configuration, and the one worth the round trip: a node whose last
    /// known position is a week-old fix is found by making it beep.
    func setAlert(_ state: RadioAlertState) async {
        await run { [self] in
            alert = try await management.setAlert(address, state)
        }
    }

    // MARK: - Acting on the device

    /// Restart the device, keeping everything it has configured.
    ///
    /// Nothing here changes, so nothing is invalidated: the same device
    /// comes back with the same settings, and the readings on screen are as
    /// true afterward as they were before. What is no longer true is the
    /// uptime, which the next refresh corrects.
    func restart() async {
        await run { [self] in
            try await management.reset(address, .reboot)
        }
    }

    /// Return the device to a blank factory state.
    ///
    /// It comes back as a different node — a factory reset takes the device
    /// identity with it — so everything cached under this address describes
    /// something that no longer exists. Drop it rather than let the next
    /// open present a dead device's settings as current.
    func factoryReset() async {
        await run { [self] in
            try await management.reset(address, .factory)
        }
        await forgetCache()
    }

    /// Forget everything cached about this device, so the next open asks it
    /// afresh. For an operator who suspects the cache rather than the radio.
    func forgetCache() async {
        await management.forgetCache(address)
        card = nil
        cardAsOf = nil
        readings.removeAll()
        writeRefusals.removeAll()
    }

    // MARK: - Running one operation at a time

    /// Run one operation against the device, holding the screen while it is
    /// out and turning whatever went wrong into a sentence.
    private func run(_ operation: () async throws -> Void) async {
        guard !isBusy else { return }
        isBusy = true
        problem = nil
        defer {
            isBusy = false
            propertiesRemaining = nil
        }
        do {
            try await operation()
        } catch {
            problem = Self.text(for: error)
        }
    }

    private func fetch(
        _ properties: [UInt32],
        multiHint: Bool
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        try await management.fetch(address, properties, multiHint) { [weak self] remaining in
            Task { @MainActor in self?.propertiesRemaining = remaining }
        }
    }

    /// The answers that carried a value, which are the ones worth keeping.
    private static func values(
        in answers: [MobileMeshManagementAnswerRecord]
    ) -> [UInt32: Data] {
        answers.reduce(into: [:]) { values, answer in
            if let value = answer.value { values[answer.propertyId] = value }
        }
    }

    /// What went wrong, in terms an operator can act on.
    ///
    /// Silence is the case worth explaining: a device answers nothing at all
    /// to a node it does not list, so "no reply" and "not an administrator"
    /// arrive identically and the copy has to carry both.
    static func text(for error: any Error) -> String {
        switch error as? RemoteManagementError {
        case .noAnswer:
            """
            No response — this phone may not be an administrator of that \
            device, or the device may be out of reach.
            """
        case let .refused(status):
            "The device refused the request: \(ulcpStatusName(status: status))."
        case .unreadable:
            """
            The device answered with something this app could not read. It \
            may be running firmware this version does not understand.
            """
        case .unavailable:
            """
            This phone has no radio to send through. Connect its companion \
            radio and try again.
            """
        // Anything else is this app failing to build the request rather
        // than the device failing to answer it. Saying "no radio" here
        // sent one such bug looking for a Bluetooth problem.
        case nil:
            "This app could not make that change: \(error)."
        }
    }
}
