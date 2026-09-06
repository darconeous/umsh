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
    /// Store a Wi-Fi network on the device, given an already-encoded entry
    /// with its credential folded in. An SSID the device already holds is
    /// replaced.
    ///
    /// The one table here that is edited an item at a time rather than
    /// written whole: the credential lives only on the device and never
    /// comes back, so a host holding the reported table has nothing to
    /// rewrite it with.
    var insertNetwork: (String, Data) async throws -> Void
    /// Forget a Wi-Fi network by name. The SSID octets are the selector.
    var removeNetwork: (String, Data) async throws -> Void
    /// Make the device conspicuous, or stop it, answering with what it
    /// reports it is doing.
    var setAlert: (String, RadioAlertState) async throws -> RadioAlertState
    /// Act on the device itself rather than on its settings: restart it, or
    /// return it to a blank factory state. Both are answered by the device
    /// doing the thing and saying nothing, so success here means the
    /// command was delivered, not that the device has finished.
    var reset: (String, MobileMeshResetScope) async throws -> Void
    /// Forget every host paired with the device: the bond count written to
    /// zero. Unlike the resets above this is answered, so returning means
    /// the device said it did it. It stands apart from the ordinary Apply
    /// flow only because it is destructive and confirmed on its own.
    var clearBluetoothBonds: (String) async throws -> Void
    /// This phone's own node key, so the administrator list can say which
    /// entry is this phone—and refuse to remove it.
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
    /// mid-exchange—there is no confirmation to wait for and no way back
    /// if it was the wrong node. Restarting is offered everywhere; this is
    /// not.
    var offersFactoryReset: Bool { link != .mesh }

    /// Whether where this phone is stands for where the device is.
    ///
    /// True on a local link—a bench session or the companion radio—where
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
/// them, so a write's echoes fold in as a dictionary merge—no field of
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

    /// Whether the device actually answered for this property.
    ///
    /// The three outcomes a screen has to tell apart: answered, refused,
    /// and never asked. Absence in ``properties`` covers the last two
    /// together, which is not enough—a refusal is the device saying it
    /// does not have the property, and that is the signal for leaving its
    /// controls out rather than showing them empty.
    func answered(_ property: UInt32) -> Bool {
        propertyIDs.contains(property) && !refused.contains(property)
    }

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
/// Deliberately not a session—there is nothing to hold open. An operation
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
    /// Values the device rejected on the last apply, by property—each a
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

    /// Whether this device can join a network, as opposed to only seeing
    /// which ones are there.
    ///
    /// A capability would be the wrong test: `CAP_WIFI` is on the card, but
    /// the screen has to render before the card's promise is worth
    /// anything, and a device that advertises a station it does not hold
    /// refuses the property. The device answering for whether its station
    /// is enabled is the claim, by the pattern ``supportsBluetoothPairing``
    /// set.
    var supportsWifiStation: Bool {
        readings[.wifi]?.answered(ulcpProperties.wifiEnabled) ?? false
    }

    /// Whether this device manages its own Bluetooth bonds on command.
    ///
    /// Not a capability—Bluetooth has only one, and the rest is
    /// discovered by asking. The device answering for its bond count is
    /// the claim; a refusal, or a screen that has not been read yet, is
    /// not, so the controls stay out until the device has said otherwise.
    var supportsBluetoothPairing: Bool {
        readings[.bluetooth]?.answered(ulcpProperties.bleBondCount) ?? false
    }

    /// How this device is reached. The Bluetooth screen is the one place
    /// it changes what a control *means* rather than only what it costs:
    /// switching Bluetooth off, or forgetting every bond, severs a
    /// companion or bench link and leaves a mesh one untouched.
    var link: DeviceManagementLink { management.link }

    /// Whether a factory reset is offered here at all—a question about
    /// how the device is reached, not about what it can do.
    var offersFactoryReset: Bool { management.offersFactoryReset }

    /// Whether this phone's own position can stand in for the device's—a
    /// question about how the device is reached, not about what it can do.
    var phoneStandsForDevice: Bool { management.phoneStandsForDevice }

    /// This phone's own node key, once the radio has said what it is.
    private(set) var phoneNodeKey: Data?

    /// Ask the radio for this phone's key, once.
    ///
    /// Costs nothing on the air—it is the attached radio answering about
    /// itself—but it is a round trip over the link, so it is not repeated
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
    /// phone has never asked—or if the device is on a local link, where
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
            supportsBle: decoded.supportsBle,
            supportsWifiScan: decoded.supportsWifiScan,
            supportsWifi: decoded.supportsWifi,
            supportsIpv4: decoded.supportsIpv4,
            supportsIpv6: decoded.supportsIpv6,
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

    /// Fill a category in from the cache, and—on a local link—follow
    /// with a fresh read when nothing has come off the air this session.
    ///
    /// Every screen opens from the cache first, read-only ones included.
    /// Over the mesh it stays that way: an operator who wants a current
    /// reading asks for one, and one who is walking the screens to see
    /// what is there does not spend a device's airtime doing it. A local
    /// link answers in the time the screen takes to settle, so there the
    /// stale-or-empty case refreshes itself—but only that case: a
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
            await cache(reported)
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

    /// Write the fields the operator changed, and normally save.
    ///
    /// What the device echoes is what it is now holding, which is not always
    /// what was asked for—a transmit power above what the hardware can
    /// reach comes back clamped. Those echoes are the readback: they answer
    /// the question a second full read would have asked, and they cost
    /// nothing extra.
    ///
    /// Returns whether the device answered—false when nothing reached it,
    /// which is when the operator's unapplied fields are still the only
    /// record of what they asked for and must not be thrown away.
    @discardableResult
    func apply(
        _ category: UlcpManageCategory,
        desired: UlcpDevicePropertiesRecord,
        dirty: Set<UInt32>,
        save: Bool = true
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
            await cache(echoed)
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
                problem = save
                    ? "Settings the device did accept are running but not saved."
                    : "The device rejected some counter resets."
                return
            }
            if save {
                try await management.save(address)
            }
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
            "the device was busy—try again"
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
            // told to—unlike the Bluetooth path, where the session chains
            // a save behind each mutation.
            try await management.save(address)
            let table = desired.sorted { $0.lexicographicallyPrecedes($1) }
                .reduce(into: Data()) { $0 += $1 }
            await cache([property: table])
            var updated = readings[.peerNodes] ?? RemoteCategoryReading()
            updated.absorb([property: table], at: Date(), fromAir: true)
            readings[.peerNodes] = updated
        }
    }

    // MARK: - Following the device's own announcements

    /// Fold values the device announces on its own into whatever is on
    /// screen, for as long as the caller keeps this running.
    ///
    /// Local links only—the backend says whether there is anything to
    /// hear. A push merges like a write's echo: the affected readings
    /// redecode around it, clean fields on an editor follow it, and a
    /// field the operator is editing keeps the edit. It deliberately does
    /// not care whether an operation is in flight; the device's latest
    /// word wins whichever order the two land in.
    /// Held by the model rather than by the view that starts it.
    ///
    /// A `task` modifier is cancelled when its view disappears, and in a
    /// navigation stack pushing a category screen makes the device screen
    /// disappear — so a subscription held there would be dropped by the
    /// very act of opening the screen that most wants it. This one lives
    /// as long as the device is being managed, which is what a device's
    /// running commentary is scoped to.
    /// Not isolated, so the deinitializer can cancel it: everything that
    /// touches it otherwise is on the main actor.
    private nonisolated(unsafe) var pushObserver: Task<Void, Never>?

    func observePushes() {
        guard pushObserver == nil, let pushes = management.propertyPushes else { return }
        pushObserver = Task { [weak self] in
            for await push in pushes() {
                guard let self else { return }
                await absorb(push)
            }
        }
    }

    deinit { pushObserver?.cancel() }

    private func absorb(_ push: UlcpPropertyPushRecord) async {
        // A scan arrives an access point at a time, so the whole value the
        // rest of this method merges never exists on the air. It has its
        // own accumulator, and nothing about it reaches a reading.
        if push.propertyId == ulcpProperties.wifiScanResults {
            absorbScanResult(push)
            return
        }
        // Nothing else here is streamed, so an item notification for one
        // says the device changed a table without saying what the table now
        // holds. Reading it back is the only honest answer, and every such
        // notification here follows an edit this phone asked for.
        guard push.kind == .is else { return }
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
            await cache([push.propertyId: push.value])
        }
    }

    // MARK: - Wi-Fi

    /// What a scan has heard, by access point.
    ///
    /// Kept apart from the readings because a scan is an event rather than
    /// a setting: it arrives an item at a time, it is never cached, and it
    /// describes where the device is standing. Keyed by BSSID, which is
    /// what a device re-reports an access point under when its signal
    /// moves, and the only thing that tells two nameless ones apart.
    private(set) var scanResults: [Data: UlcpWifiScanResultRecord] = [:]

    /// What a scan heard, strongest first.
    var heardNetworks: [UlcpWifiScanResultRecord] {
        scanResults.values.sorted { $0.rssiDbm > $1.rssiDbm }
    }

    /// Fold one announcement about the scan into the accumulator.
    ///
    /// The device says `Inserted` per access point while a scan runs and
    /// `Is` with an empty value to clear the table before one starts, so
    /// the two commands mean different things and the kind is what tells
    /// them apart.
    private func absorbScanResult(_ push: UlcpPropertyPushRecord) {
        switch push.kind {
        case .is:
            // The whole table, which at the start of a scan is empty.
            scanResults = Self.scanTable(inValue: push.value)
        case .inserted:
            guard let result = try? inspectUlcpWifiScanResult(item: push.value) else { return }
            scanResults[result.bssid] = result
        case .removed:
            guard let result = try? inspectUlcpWifiScanResult(item: push.value) else { return }
            scanResults[result.bssid] = nil
        }
    }

    /// The accumulator a whole-value read of the scan table amounts to.
    private static func scanTable(
        inValue value: Data
    ) -> [Data: UlcpWifiScanResultRecord] {
        let decoded = inspectUlcpProperties(
            responses: [
                ulcpPropertyRecord(
                    propertyId: ulcpProperties.wifiScanResults,
                    value: value
                )
            ]
        )
        return (decoded.wifiScanResults ?? []).reduce(into: [:]) { table, result in
            table[result.bssid] = result
        }
    }

    /// Ask the device to look for networks, and follow the scan to its end.
    ///
    /// Written on its own rather than through Apply because a scan is not
    /// an edit: nothing about the device changes, and an operator who taps
    /// Scan has not left a form half-filled.
    ///
    /// On a local link the results arrive as the device hears them. Across
    /// the mesh nothing is pushed, so the flag is watched instead and the
    /// table read once the device says it has stopped — which is the whole
    /// reason the flag is a property rather than a command.
    func scanForNetworks() async {
        scanResults.removeAll()
        await write([
            MobileMeshPropertyWriteRecord(
                propertyId: ulcpProperties.wifiScanning,
                value: Data([1])
            )
        ])
        guard problem == nil, management.propertyPushes == nil else { return }
        await followScanOverMesh()
    }

    /// Watch a scan the mesh will not announce the end of.
    ///
    /// Bounded rather than open-ended: a device that stops answering, or
    /// one that never clears the flag, must not leave a screen watching it
    /// forever. Twenty asks at two seconds is longer than any scan the
    /// chapter contemplates and short enough to give up on.
    private func followScanOverMesh() async {
        for _ in 0..<20 {
            try? await Task.sleep(for: .seconds(2))
            await refreshCategory(.wifi)
            guard problem == nil else { return }
            if readings[.wifi]?.properties.wifiScanning != true {
                if let value = readings[.wifi]?.values[ulcpProperties.wifiScanResults] {
                    scanResults = Self.scanTable(inValue: value)
                }
                return
            }
        }
    }

    /// Store a network on the device, with the credential the operator
    /// typed, and answer with what the device made of it.
    ///
    /// Returns the refusal status where there was one, so the join sheet
    /// can offer a weaker security mode against `STATUS_UNIMPLEMENTED`
    /// rather than making the operator start again.
    func joinNetwork(item: Data) async -> UInt32? {
        var refusal: UInt32?
        await run { [self] in
            do {
                try await management.insertNetwork(address, item)
            } catch let error as RemoteManagementError {
                guard case let .refused(status) = error else { throw error }
                refusal = status
                return
            }
            try await management.save(address)
        }
        if refusal == nil, problem == nil {
            await refreshCategory(.wifi)
        }
        return refusal
    }

    /// Tell the device which stored network to use, or none.
    ///
    /// Written on its own rather than through Apply because the one caller
    /// is the join sheet, where selecting the network just stored is the
    /// second half of one act the operator already confirmed.
    func selectNetwork(ssid: Data) async {
        await write([
            MobileMeshPropertyWriteRecord(
                propertyId: ulcpProperties.wifiNetwork,
                value: ssid
            )
        ])
    }

    /// Forget one network by name, and save.
    func forgetNetwork(ssid: Data) async {
        await run { [self] in
            try await management.removeNetwork(address, ssid)
            try await management.save(address)
        }
        guard problem == nil else { return }
        await refreshCategory(.wifi)
    }

    /// Write properties outside the Apply batch, reporting refusals as
    /// problems rather than per-row: the callers here are buttons, not
    /// fields, and there is no row to put a rejection on.
    private func write(_ writes: [MobileMeshPropertyWriteRecord]) async {
        await run { [self] in
            let answers = try await management.write(address, writes)
            let echoed = Self.values(in: answers)
            readings[.wifi]?.absorb(echoed, at: Date(), fromAir: true)
            if let refused = answers.first(where: { $0.value == nil }) {
                throw RemoteManagementError.refused(status: refused.statusCode ?? 0)
            }
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

    /// Forget every host paired with the device, along with its pairing PIN.
    ///
    /// The bond count on screen is stale the moment this returns, and on a
    /// local link the value the device pushes back cannot arrive—clearing
    /// bonds drops the very link it would arrive on. Refresh the reading
    /// from what the write means rather than from what the device says
    /// next, so the screen is not left reporting hosts that no longer exist.
    func clearBluetoothPairings() async {
        await run { [self] in
            try await management.clearBluetoothBonds(address)
        }
        guard problem == nil else { return }
        await absorb(
            UlcpPropertyPushRecord(
                propertyId: ulcpProperties.bleBondCount,
                value: Data([0]),
                kind: .is
            )
        )
        // Clearing opens a pairing window, and the window is a property
        // this screen shows as a toggle—reflect what the write means.
        await absorb(
            UlcpPropertyPushRecord(
                propertyId: ulcpProperties.blePairing,
                value: Data([1]),
                kind: .is
            )
        )
    }

    /// Return the device to a blank factory state.
    ///
    /// It comes back as a different node—a factory reset takes the device
    /// identity with it—so everything cached under this address describes
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

    /// Remember what the device said, minus what has no business
    /// outliving the moment it was said in.
    ///
    /// A scan is a list of the access points around the device right now,
    /// which is a fingerprint of where it is standing; a signal strength is
    /// a number about one instant. Neither is a setting, neither would be
    /// true an hour later, and a screen showing either as "last read
    /// yesterday" would be showing a place the device may have left. They
    /// are read fresh or not shown. The known-network table caches
    /// normally: its reported form carries no credential.
    private func cache(_ values: [UInt32: Data]) async {
        let ephemeral: Set<UInt32> = [
            ulcpProperties.wifiScanResults,
            ulcpProperties.wifiRssi,
        ]
        let keepable = values.filter { !ephemeral.contains($0.key) }
        guard !keepable.isEmpty else { return }
        await management.saveValues(address, keepable)
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
            No response—this phone may not be an administrator of that \
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
