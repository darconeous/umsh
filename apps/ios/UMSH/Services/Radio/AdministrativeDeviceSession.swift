@preconcurrency import CoreBluetooth
import Foundation
import OSLog
import UMSHMobileCore

/// What an administrative session knows about the device it is configuring.
///
/// Deliberately not a `RadioSnapshot`: that describes *the phone's* radio,
/// which is a long-lived binding with battery history, mesh traffic, and an
/// auto-reconnect lifecycle. An administered device is a foreground session
/// that exists to read a configuration and write one back.
///
/// `sync` is carried as the Rust record rather than remapped into an app
/// model on purpose — the commissioning sheet reads `UlcpSyncRecord` and
/// writes `UlcpDeviceConfigRecord`, so read and write speak one vocabulary
/// and no field can be lost in a translation layer.
struct AdministeredDeviceSnapshot: Equatable, Sendable {
    var linkState: RadioLinkState
    var identifier: UUID?
    var name: String?
    var deviceIdentity: MeshPublicIdentity?
    /// Whose device this is. Purely informational here: an administrative
    /// session never claims, so this drives a banner, not a decision.
    var hostState: RadioHostState
    var sync: UlcpSyncRecord?
    var batteryPercentage: Int?
    var batteryVoltageMillivolts: Int?
    var chargeState: RadioChargeState?
    /// `PROP_ALERT`, or `nil` on a device that cannot make itself
    /// conspicuous (no `CAP_ALERT`).
    var alert: RadioAlertState?
    /// The device's wall clock as of when it last reported one.
    var clock: RadioClock?
    /// What the device's receiver reports, on a device with `CAP_GNSS`.
    var position: RadioPosition?
    var problemDescription: String?

    static let idle = Self(
        linkState: .idle,
        identifier: nil,
        name: nil,
        deviceIdentity: nil,
        hostState: .unknown,
        sync: nil,
        batteryPercentage: nil,
        batteryVoltageMillivolts: nil,
        chargeState: nil,
        alert: nil,
        clock: nil,
        position: nil,
        problemDescription: nil
    )
}

/// A foreground BLE session for configuring a UMSH device this phone does
/// not tether to.
///
/// Everything about this type is deliberately *less* than
/// `CoreBluetoothRadioConnection`:
///
/// - Its central has **no restoration identifier**, so iOS never relaunches
///   the app in the background on its behalf. Commissioning is something a
///   person is doing right now, at a bench, with the app open.
/// - It persists **nothing**. No remembered identifier, no auto-connect
///   intent, no standing connect left armed for a device that wanders back
///   into range next Tuesday.
/// - It never claims. The Rust session is
///   `MobileUlcpSession.administrative()`, which refuses `claim` outright,
///   so a phone commissioning ten repeaters cannot leave its host key on
///   any of them.
///
/// A dropped link is therefore terminal, not provisional: the session
/// reports "connection lost" and the user retries. That is the whole
/// recovery model.
final class AdministrativeDeviceSession: NSObject, @unchecked Sendable {
    private static let logger = Logger(subsystem: "com.umsh.ios", category: "AdminDevice")

    /// Budget from `connect` to a fully attached ULCP session. Generous
    /// because a first connection to an unbonded device puts a system
    /// pairing prompt in front of the user, and someone reading a PIN off
    /// an e-paper display is not in a hurry.
    private static let attachTimeoutSeconds: TimeInterval = 60
    /// Budget for one post-attach exchange. No user gesture is involved, the
    /// link is already up, and the device has already proved it answers — so
    /// this is short. It exists because a wedged device holds the link open
    /// while answering nothing, and CoreBluetooth has no failure to report;
    /// without a deadline the caller waits forever.
    private static let operationTimeoutSeconds: TimeInterval = 20
    /// How long a device may go unheard before it leaves the scan list.
    private static let discoveryStaleSeconds: UInt64 = 6

    private struct DiscoveredEntry {
        var peripheral: CBPeripheral
        var name: String?
        var rssiDBm: Int
        var lastSeen: DispatchTime
        /// When this device was first heard, as a sequence number. Assigned
        /// once and never revised, which is the whole point: it is the only
        /// property of a discovered device that cannot change while the user
        /// is looking at the list.
        let discoveryOrder: UInt64
    }

    /// Source of `DiscoveredEntry.discoveryOrder`. Reset with the list, so a
    /// fresh scan numbers from zero rather than carrying on from the last.
    private var nextDiscoveryOrder: UInt64 = 0

    private let queue = DispatchQueue(
        label: "com.umsh.radio.administrative",
        qos: .userInitiated
    )
    // No CBCentralManagerOptionRestoreIdentifierKey: see the type comment.
    private var central: CBCentralManager?
    private var peripheral: CBPeripheral?
    private var frameIn: CBCharacteristic?
    private var frameOut: CBCharacteristic?

    private let reassembler = MobileGattReassembler()
    /// Recreated per connect, in the attach mode that connect asks for —
    /// see `connect(_:lazyAttach:)`.
    private var ulcpSession = MobileUlcpSession.administrative()
    private var selectedHostKey: Data?

    private var snapshot = AdministeredDeviceSnapshot.idle
    private var continuations: [UUID: AsyncStream<AdministeredDeviceSnapshot>.Continuation] = [:]

    private var discoveryActive = false
    private var discoveryRequested = false
    private var companionIdentifier: UUID?
    private var discovered: [UUID: DiscoveredEntry] = [:]
    private var discoveryContinuations: [UUID: AsyncStream<[DiscoveredRadio]>.Continuation] = [:]
    private var discoveryPruneGeneration = UUID()

    private var pendingWrites: [Data] = []
    private var writeInProgress = false

    /// The caller awaiting the attach. Like `operationWaiter` below it resumes
    /// *with* the configuration the device reported, rather than leaving the
    /// caller to look for it on `snapshots()`: that stream is drained by a
    /// separate task with no ordering against this continuation, so a caller
    /// reading the mirror could still see the state from before the attach.
    private var attachWaiter: CheckedContinuation<UlcpSyncRecord?, any Error>?
    private var attachGeneration = UUID()
    /// The caller awaiting a post-attach exchange — a configuration write or
    /// a re-read. Both complete on the same condition (the session is back
    /// at `attached` with nothing outstanding), so one waiter serves both
    /// and also enforces that only one runs at a time.
    ///
    /// It resumes *with* the device state observed at completion rather than
    /// leaving the caller to read `snapshots()`: that stream is drained by a
    /// separate task with no ordering against this continuation, so a caller
    /// comparing what it wrote against a snapshot could be comparing against
    /// the previous one.
    private var operationWaiter: CheckedContinuation<UlcpSyncRecord?, any Error>?
    private var operationGeneration = UUID()
    /// The caller awaiting a local management exchange — a property fetch,
    /// write pass, or save — resolved by the session update carrying its
    /// completion rather than by the attached-and-idle condition, because
    /// its result is the event, not the sync record.
    private var managementWaiter:
        CheckedContinuation<UlcpLocalManagementEventRecord, any Error>?
    private var managementGeneration = UUID()
    private var propertyPushContinuations:
        [UUID: AsyncStream<UlcpPropertyPushRecord>.Continuation] = [:]

    /// A flow abandoned without calling `disconnect()` — the sheet is
    /// dismissed, the controller goes away — must not leave the device
    /// connected or its registry claim standing. Both CoreBluetooth
    /// delegates are weak, so this runs even mid-session.
    deinit {
        if let identifier = peripheral?.identifier {
            AdminSessionRegistry.shared.deregister(identifier)
        }
        if let peripheral, let central, peripheral.state != .disconnected {
            central.cancelPeripheralConnection(peripheral)
        }
    }

    // MARK: - Identity

    /// Supply the phone identity used to classify the device's host key.
    /// An administrative session never writes it; it only wants to be able
    /// to say "this is your radio" or "this belongs to another phone".
    func useHostIdentity(_ identity: MeshPublicIdentity?) async throws {
        let hostKey = try identity.map {
            try UMSHMobileCore.publicIdentityBytes(address: $0.canonicalAddress)
        }
        await withCheckedContinuation { result in
            queue.async { [self] in
                selectedHostKey = hostKey
                result.resume()
            }
        }
    }

    // MARK: - Snapshots

    func snapshots() async -> AsyncStream<AdministeredDeviceSnapshot> {
        await withCheckedContinuation { result in
            queue.async { [self] in
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
                    let id = UUID()
                    continuations[id] = continuation
                    continuation.yield(snapshot)
                    continuation.onTermination = { [weak self] _ in
                        self?.queue.async { [weak self] in
                            self?.continuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    // MARK: - Discovery

    /// Stream the live list of nearby UMSH devices. Never auto-connects.
    ///
    /// `companionIdentifier` marks the phone's own radio in the list so the
    /// UI can steer the user away from administering the device it is
    /// already tethered to — the two links would contend for the same
    /// peripheral.
    func discover(companionIdentifier: UUID? = nil) async -> AsyncStream<[DiscoveredRadio]> {
        await withCheckedContinuation { result in
            queue.async { [self] in
                self.companionIdentifier = companionIdentifier
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
                    let id = UUID()
                    discoveryContinuations[id] = continuation
                    continuation.yield(currentDiscoveryList())
                    continuation.onTermination = { [weak self] _ in
                        self?.queue.async { [weak self] in
                            self?.discoveryContinuations[id] = nil
                        }
                    }
                }
                Self.logger.notice("action: opened administrative device discovery")
                startDiscoveryOnQueue()
                result.resume(returning: stream)
            }
        }
    }

    func stopDiscovery() async {
        await withCheckedContinuation { result in
            queue.async { [self] in
                stopDiscoveryOnQueue()
                result.resume()
            }
        }
    }

    private func startDiscoveryOnQueue() {
        discoveryRequested = true
        discovered.removeAll()
        nextDiscoveryOrder = 0
        yieldDiscoveryList()
        guard let central else {
            central = CBCentralManager(delegate: self, queue: queue)
            return
        }
        guard central.state == .poweredOn else { return }
        beginDiscoveryScan()
    }

    private func beginDiscoveryScan() {
        guard let central, central.state == .poweredOn else { return }
        discoveryRequested = false
        discoveryActive = true
        // Duplicates keep RSSI live and let a device that briefly drops out
        // reappear instead of going stale.
        central.scanForPeripherals(
            withServices: [RadioGatt.service],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
        )
        discoveryPruneGeneration = UUID()
        scheduleDiscoveryPrune(generation: discoveryPruneGeneration)
    }

    private func stopDiscoveryOnQueue() {
        guard discoveryActive || discoveryRequested else { return }
        let wasScanning = discoveryActive
        discoveryActive = false
        discoveryRequested = false
        discoveryPruneGeneration = UUID()
        discovered.removeAll()
        nextDiscoveryOrder = 0
        yieldDiscoveryList()
        if wasScanning { central?.stopScan() }
    }

    private func recordDiscovered(
        _ peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi: NSNumber
    ) {
        let advertisedName = advertisementData[CBAdvertisementDataLocalNameKey] as? String
        var entry = discovered[peripheral.identifier]
        if entry == nil {
            entry = DiscoveredEntry(
                peripheral: peripheral,
                name: advertisedName ?? peripheral.name,
                rssiDBm: rssi.intValue,
                lastSeen: .now(),
                discoveryOrder: nextDiscoveryOrder
            )
            nextDiscoveryOrder += 1
        }
        guard var entry else { return }
        entry.peripheral = peripheral
        if let advertisedName { entry.name = advertisedName }
        else if entry.name == nil { entry.name = peripheral.name }
        // Keep the last usable RSSI when a report carries the 127 sentinel.
        if rssi.intValue != 127 { entry.rssiDBm = rssi.intValue }
        entry.lastSeen = .now()
        discovered[peripheral.identifier] = entry
        yieldDiscoveryList()
    }

    private func currentDiscoveryList() -> [DiscoveredRadio] {
        // Arrival order, and nothing else. Every other property of a
        // discovered device changes while the list is on screen — RSSI with
        // every advertisement, and the name when one finally arrives, since a
        // device is first heard with only whatever `CBPeripheral.name` gives
        // us. Sorting on any of them moves rows under the user's finger.
        //
        // The companion radio is deliberately *not* pinned to the top here,
        // unlike companion discovery: it cannot be set up from this list, and
        // a list that opens with an untappable row is worse than one that
        // does not.
        discovered.values
            .sorted { $0.discoveryOrder < $1.discoveryOrder }
            .map { entry in
                DiscoveredRadio(
                    id: entry.peripheral.identifier,
                    name: entry.name,
                    rssiDBm: entry.rssiDBm,
                    isRemembered: entry.peripheral.identifier == companionIdentifier
                )
            }
    }

    private func yieldDiscoveryList() {
        let list = currentDiscoveryList()
        for continuation in discoveryContinuations.values {
            continuation.yield(list)
        }
    }

    private func scheduleDiscoveryPrune(generation: UUID) {
        queue.asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self, self.discoveryActive,
                  self.discoveryPruneGeneration == generation else { return }
            let now = DispatchTime.now().uptimeNanoseconds
            let stale = Self.discoveryStaleSeconds * 1_000_000_000
            let before = self.discovered.count
            self.discovered = self.discovered.filter { _, entry in
                now <= entry.lastSeen.uptimeNanoseconds &+ stale
            }
            if self.discovered.count != before { self.yieldDiscoveryList() }
            self.scheduleDiscoveryPrune(generation: generation)
        }
    }

    // MARK: - Connection

    /// Connect to `id` and synchronize with it, resolving with the device's
    /// configuration once the ULCP session is attached and that configuration
    /// has been read.
    ///
    /// `lazyAttach` cuts the post-attach inspection to what attaching
    /// itself requires, leaving the device to be read a screenful at a
    /// time through `fetchProperties` — the sync it resolves with is
    /// card-grade, not the device whole. The full attach is what
    /// commissioning's whole-configuration draft needs, and a lazy
    /// settings screen must never pay for.
    ///
    /// Throws if the device cannot be reached, refuses the protocol, or the
    /// whole exchange overruns its budget. A drop *after* this resolves is
    /// not thrown anywhere — it arrives on `snapshots()` as a failed link,
    /// because by then the caller is a UI showing an editor, not an
    /// `await`.
    @discardableResult
    func connect(_ id: UUID, lazyAttach: Bool = false) async throws -> UlcpSyncRecord? {
        try await withCheckedThrowingContinuation {
            (result: CheckedContinuation<UlcpSyncRecord?, any Error>) in
            queue.async { [self] in
                guard let central, central.state == .poweredOn else {
                    result.resume(throwing: RadioConnectionError.bluetoothUnavailable)
                    return
                }
                guard attachWaiter == nil, operationWaiter == nil else {
                    result.resume(throwing: RadioConnectionError.operationInProgress)
                    return
                }
                // A fresh Rust session in the requested attach mode; the
                // teardown below releases whatever the previous one held.
                ulcpSession = lazyAttach
                    ? MobileUlcpSession.administrativeLazy()
                    : MobileUlcpSession.administrative()
                // The advertised name is live; `CBPeripheral.name` is a cache
                // iOS does not refresh when a device is renamed.
                let advertisedName = discovered[id]?.name
                let target = discovered[id]?.peripheral
                    ?? central.retrievePeripherals(withIdentifiers: [id]).first
                guard let target else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                Self.logger.notice(
                    "action: administer device \(id, privacy: .public)"
                )
                stopDiscoveryOnQueue()
                teardownPeripheral()

                peripheral = target
                target.delegate = self
                // Claim the peripheral before connecting, so a companion
                // sweep racing this connect cannot revoke it mid-flight.
                AdminSessionRegistry.shared.register(target.identifier)
                attachWaiter = result
                attachGeneration = UUID()
                publish(state: .connecting, name: advertisedName ?? target.name, identifier: target.identifier)
                central.connect(target)
                scheduleAttachTimeout(generation: attachGeneration)
            }
        }
    }

    private func scheduleAttachTimeout(generation: UUID) {
        queue.asyncAfter(deadline: .now() + Self.attachTimeoutSeconds) { [weak self] in
            guard let self, self.attachGeneration == generation,
                  self.attachWaiter != nil else { return }
            Self.logger.error("administrative attach timed out")
            self.fail(
                "The device did not finish connecting",
                error: RadioConnectionError.radioNotFound
            )
        }
    }

    /// End the session and release the peripheral. Idempotent.
    func disconnect() async {
        await withCheckedContinuation { result in
            queue.async { [self] in
                Self.logger.notice("action: ended administrative session")
                stopDiscoveryOnQueue()
                finishPendingOperations(throwing: RadioConnectionError.radioNotFound)
                if let peripheral, let central, peripheral.state != .disconnected {
                    central.cancelPeripheralConnection(peripheral)
                }
                teardownPeripheral()
                publish(AdministeredDeviceSnapshot.idle)
                result.resume()
            }
        }
    }

    /// Release every CoreBluetooth and ULCP resource for the current
    /// device, including its registry claim. Does not itself cancel the
    /// connection — callers decide whether the link is being torn down or
    /// has already dropped.
    private func teardownPeripheral() {
        if let identifier = peripheral?.identifier {
            AdminSessionRegistry.shared.deregister(identifier)
        }
        peripheral?.delegate = nil
        peripheral = nil
        frameIn = nil
        frameOut = nil
        reassembler.reset()
        _ = ulcpSession.reset()
        pendingWrites.removeAll()
        writeInProgress = false
        attachGeneration = UUID()
    }

    // MARK: - Configuration

    /// Write a complete device configuration and wait for the radio to
    /// persist it. Rust owns the write ordering and the trailing save.
    func configureDevice(_ configuration: UlcpDeviceConfigRecord) async throws {
        _ = try await perform { session in try session.configureDevice(configuration: configuration) }
    }

    /// Let a node manage this device over the mesh, or stop it from doing
    /// so. Persisted by a save the Rust session chains behind the write.
    ///
    /// The device's own list is the authority and comes back on the
    /// snapshot, so nothing here reads it separately: a mutation that
    /// resolves has already republished `dev_admin_keys`.
    func setAdministrator(_ publicKey: Data, present: Bool) async throws {
        Self.logger.notice(
            "action: user \(present ? "added" : "removed", privacy: .public) an administrator"
        )
        _ = try await perform { session in
            present
                ? try session.insertDeviceAdmin(publicKey: publicKey)
                : try session.removeDeviceAdmin(publicKey: publicKey)
        }
    }

    /// Store a node on the device's identity, or take it off, so it can
    /// hold a secure session with that node on its own. Persisted by a
    /// save the Rust session chains behind the write, like the
    /// administrator table.
    func setPeer(_ publicKey: Data, present: Bool) async throws {
        Self.logger.notice(
            "action: user \(present ? "added" : "removed", privacy: .public) a device peer"
        )
        _ = try await perform { session in
            present
                ? try session.insertDevicePeer(publicKey: publicKey)
                : try session.removeDevicePeer(publicKey: publicKey)
        }
    }

    /// Start or stop the device's locate alert (`PROP_ALERT`).
    ///
    /// Live behavior rather than configuration: it is never part of a
    /// configuration write, never saved, and it outlives this session —
    /// an alert left running keeps running after the setup sheet closes.
    func setAlert(_ state: RadioAlertState) async throws {
        Self.logger.notice("action: user set locate alert to \(state.rawValue, privacy: .public)")
        _ = try await perform { session in try session.setAlert(state: state.wire) }
    }

    /// Set — or clear — the device's wall clock (`PROP_TIME`).
    ///
    /// Live state like the alert, and for the same kind of reason: the
    /// clock is never saved, so it is not part of a configuration write.
    /// The time *zone* is, and travels with `configureDevice`.
    func setTime(epochSeconds: UInt32?) async throws {
        Self.logger.notice(
            "action: user \(epochSeconds == nil ? "cleared" : "set", privacy: .public) the device clock"
        )
        _ = try await perform { session in try session.setTime(epochSeconds: epochSeconds) }
    }

    /// Re-read the device's authoritative configuration and return it.
    ///
    /// A write is already echo-verified property by property, so this is not
    /// how a bad write is caught — it is how the *saved* device is read back
    /// after the trailing `CMD_SAVE`, which is a different question.
    @discardableResult
    func refresh() async throws -> UlcpSyncRecord? {
        try await perform { session in try session.refresh() }
    }

    /// Sample where the device is, and how well it knows.
    ///
    /// A device announces a fix indicator and nothing else about a
    /// position — see ``RadioPositionPoll``. Commissioning is where that
    /// matters most: switching a receiver on and watching it acquire is
    /// the whole point of the positioning section, and without asking, the
    /// screen would show the reading taken at attach forever.
    @discardableResult
    func refreshPositioning() async throws -> UlcpSyncRecord? {
        try await perform { session in try session.refreshPositioning() }
    }

    // MARK: - Local management

    /// Read named properties from the attached device, answering with what
    /// it said about each — values and refusals alike. The administrative
    /// counterpart of the companion session's `fetchCompanionProperties`,
    /// with the same shape of answer.
    func fetchProperties(
        _ propertyIDs: [UInt32]
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        guard !propertyIDs.isEmpty else { return [] }
        let event = try await performManagement { session in
            try session.beginPropertyFetch(propertyIds: propertyIDs)
        }
        return event.answers
    }

    /// Write properties to the attached device, in the given order, and
    /// answer with what it says each is now worth.
    func writeProperties(
        _ writes: [MobileMeshPropertyWriteRecord]
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        guard !writes.isEmpty else { return [] }
        let event = try await performManagement { session in
            try session.beginPropertyWrites(writes: writes)
        }
        return event.answers
    }

    /// Persist the attached device's live configuration.
    func saveDevice() async throws {
        let event = try await performManagement { session in
            try session.beginSave()
        }
        if let status = event.statusCode, status != 0 {
            throw RemoteManagementError.refused(status: status)
        }
    }

    /// Manage the attached device's Bluetooth bonds.
    ///
    /// Unlike the resets below these are answered, so the exchange runs to
    /// completion: what a bench operator needs to know is whether the
    /// device did it, and clearing bonds sends its answer before it drops
    /// this session with the rest.
    func manageBluetooth(_ command: MobileMeshBleCommand) async throws {
        Self.logger.notice(
            "action: user sent Bluetooth command \(String(describing: command), privacy: .public)"
        )
        let event = try await performManagement { session in
            switch command {
            case .clearBonds: try session.beginBleClearBonds()
            case .startPairing: try session.beginBleStartPairing()
            }
        }
        if let status = event.statusCode, status != 0 {
            throw RemoteManagementError.refused(status: status)
        }
    }

    /// Restart the attached device, or return it to a blank factory state.
    ///
    /// Neither is answered: the device acts and the link drops, so there is
    /// no exchange to run to completion and `performManagement` would only
    /// wait out its deadline. The frame goes and the caller treats the
    /// disconnect that follows as the confirmation.
    func reset(scope: MobileMeshResetScope) async throws {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, any Error>) in
            queue.async { [self] in
                guard let peripheral, peripheral.state == .connected else {
                    result.resume(throwing: RemoteManagementError.unavailable)
                    return
                }
                do {
                    let update: UlcpSessionUpdateRecord = switch scope {
                    case .reboot: try ulcpSession.reboot()
                    case .factory: try ulcpSession.factoryReset()
                    case .protocol, .restore:
                        throw RemoteManagementError.unavailable
                    }
                    try applySessionUpdate(update, from: peripheral)
                    result.resume()
                } catch {
                    result.resume(throwing: RemoteManagementError.unavailable)
                }
            }
        }
    }

    /// Values the attached device announces on its own, verbatim.
    func propertyPushes() async -> AsyncStream<UlcpPropertyPushRecord> {
        await withCheckedContinuation { result in
            queue.async { [self] in
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(16)) { continuation in
                    let id = UUID()
                    propertyPushContinuations[id] = continuation
                    continuation.onTermination = { [weak self] _ in
                        self?.queue.async { [weak self] in
                            self?.propertyPushContinuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    /// Run one local management exchange to completion, under the same
    /// per-operation deadline as everything else here. Errors wear
    /// `RemoteManagementError` so the management screens read this
    /// session and the mesh with the same copy.
    private func performManagement(
        _ start: @escaping @Sendable (MobileUlcpSession) throws -> UlcpSessionUpdateRecord
    ) async throws -> UlcpLocalManagementEventRecord {
        try await withCheckedThrowingContinuation {
            (result: CheckedContinuation<UlcpLocalManagementEventRecord, any Error>) in
            queue.async { [self] in
                guard let peripheral, peripheral.state == .connected else {
                    result.resume(throwing: RemoteManagementError.unavailable)
                    return
                }
                guard managementWaiter == nil, operationWaiter == nil, attachWaiter == nil
                else {
                    result.resume(throwing: RemoteManagementError.unavailable)
                    return
                }
                managementWaiter = result
                managementGeneration = UUID()
                scheduleManagementTimeout(generation: managementGeneration)
                do {
                    // An immediate completion — a save with nothing to ask —
                    // resolves the waiter inside this call.
                    try applySessionUpdate(start(ulcpSession), from: peripheral)
                } catch {
                    finishManagement(throwing: RemoteManagementError.unavailable)
                }
            }
        }
    }

    private func scheduleManagementTimeout(generation: UUID) {
        queue.asyncAfter(deadline: .now() + Self.operationTimeoutSeconds) { [weak self] in
            guard let self, self.managementGeneration == generation,
                  self.managementWaiter != nil else { return }
            Self.logger.error("administrative management exchange timed out")
            self.finishManagement(throwing: RemoteManagementError.noAnswer)
        }
    }

    private func finishManagement(with event: UlcpLocalManagementEventRecord) {
        guard let waiter = managementWaiter else { return }
        managementWaiter = nil
        managementGeneration = UUID()
        waiter.resume(returning: event)
    }

    private func finishManagement(throwing error: any Error) {
        guard let waiter = managementWaiter else { return }
        managementWaiter = nil
        managementGeneration = UUID()
        waiter.resume(throwing: error)
    }

    /// Run one post-attach exchange to completion, answering with the device
    /// state as of that completion.
    private func perform(
        _ start: @escaping @Sendable (MobileUlcpSession) throws -> UlcpSessionUpdateRecord
    ) async throws -> UlcpSyncRecord? {
        try await withCheckedThrowingContinuation {
            (result: CheckedContinuation<UlcpSyncRecord?, any Error>) in
            queue.async { [self] in
                guard let peripheral, peripheral.state == .connected else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                guard operationWaiter == nil, attachWaiter == nil, managementWaiter == nil
                else {
                    result.resume(throwing: RadioConnectionError.operationInProgress)
                    return
                }
                operationWaiter = result
                operationGeneration = UUID()
                scheduleOperationTimeout(generation: operationGeneration)
                do {
                    try applySessionUpdate(start(ulcpSession), from: peripheral)
                } catch {
                    finishOperation(throwing: error)
                }
            }
        }
    }

    // MARK: - ULCP plumbing

    private func beginSynchronization(on peripheral: CBPeripheral) {
        guard let frameIn, frameIn.properties.contains(.write) else {
            fail(
                "The device has no writable ULCP endpoint",
                error: RadioConnectionError.incompatibleProtocol
            )
            return
        }
        reassembler.reset()
        pendingWrites.removeAll()
        writeInProgress = false
        do {
            try applySessionUpdate(
                ulcpSession.begin(selectedHostKey: selectedHostKey),
                from: peripheral
            )
        } catch {
            fail(
                "The ULCP session could not start",
                error: RadioConnectionError.incompatibleProtocol,
                detail: "cause=\(UlcpFrameDiagnostic.cause(error)) stage=begin"
            )
        }
    }

    private func receive(_ value: Data, from peripheral: CBPeripheral) {
        let frame: Data
        do {
            guard let reassembled = try reassembler.push(segment: value) else { return }
            frame = reassembled
        } catch {
            fail(
                "The device sent an invalid ULCP frame",
                error: RadioConnectionError.incompatibleProtocol,
                detail: """
                    cause=\(UlcpFrameDiagnostic.cause(error)) \
                    stage=gatt-reassembly segment=\(value.count)B
                    """,
                bytes: value
            )
            return
        }
        do {
            try applySessionUpdate(ulcpSession.consume(frame: frame), from: peripheral)
        } catch MobileError.UlcpUnexpectedCommand {
            // Unhandled but well formed: ignored here for the same reason
            // the tethered session ignores it — see `linkDidReceive`.
            Self.logger.notice(
                """
                administrative session: ignoring unhandled command \
                \(UlcpFrameDiagnostic.structure(frame), privacy: .public)
                """
            )
        } catch {
            fail(
                "The device sent an invalid ULCP frame",
                error: RadioConnectionError.incompatibleProtocol,
                detail: """
                    cause=\(UlcpFrameDiagnostic.cause(error)) \
                    frame=[\(UlcpFrameDiagnostic.structure(frame))]
                    """,
                bytes: frame
            )
        }
    }

    private func applySessionUpdate(
        _ update: UlcpSessionUpdateRecord,
        from peripheral: CBPeripheral
    ) throws {
        snapshot.linkState = switch update.snapshot.phase {
        case .idle: .attaching
        case .synchronizing: .synchronizing
        // An administrative session never parks awaiting a host decision —
        // Rust does not emit that phase for this attach mode — but the
        // switch has to be total.
        case .awaitingHost: .awaitingHost
        case .claiming: .provisioning
        case .configuring: .configuring
        case .attached: .attached
        }
        snapshot.hostState = switch update.snapshot.hostOwnership {
        case .unknown: .unknown
        case .localIdentityUnavailable: .localIdentityUnavailable
        case .unsupported: .unsupported
        case .unclaimed: .unclaimed
        case .ours: .matchesCurrentIdentity
        case .otherHost: .belongsToAnotherIdentity
        }
        snapshot.identifier = peripheral.identifier
        snapshot.name = update.snapshot.deviceName ?? snapshot.name ?? peripheral.name
        if let deviceKey = update.snapshot.deviceKey {
            let identity = try UMSHMobileCore.inspectPublicIdentityBytes(publicKey: deviceKey)
            snapshot.deviceIdentity = MeshPublicIdentity(
                canonicalAddress: identity.canonicalAddress,
                hint: MeshNodeHint(bytes: identity.hint.bytes, text: identity.hint.text)
            )
        } else {
            snapshot.deviceIdentity = nil
        }
        if let battery = update.snapshot.battery {
            snapshot.batteryPercentage = battery.percentage.map(Int.init)
            snapshot.batteryVoltageMillivolts = battery.voltageMv.map(Int.init)
            snapshot.chargeState = battery.chargeState.map(RadioChargeState.init)
        }
        // Carried on every update, unlike battery: the device ends an alert
        // on its own — a button press or its deadline — so the control has
        // to follow the device rather than what was last asked for.
        snapshot.alert = update.snapshot.alert.map(RadioAlertState.init)
        // Stamped on arrival, like battery: an epoch says nothing without
        // the instant it was read.
        if let time = update.snapshot.time {
            snapshot.clock = RadioClock(
                date: time.epochSeconds.map { Date(timeIntervalSince1970: TimeInterval($0)) },
                readAt: .now
            )
        }
        snapshot.position = update.snapshot.gnss.map(RadioPosition.init)
        if let provisioning = update.snapshot.provisioning {
            snapshot.sync = provisioning
        }
        snapshot.problemDescription = nil

        let operationErrorMessage = update.operationError.map {
            "\($0.operation) failed: \($0.statusName) (\($0.statusCode))"
        }
        if let operationErrorMessage {
            Self.logger.error(
                "ULCP operation rejected: \(operationErrorMessage, privacy: .public)"
            )
            snapshot.problemDescription = operationErrorMessage
        }

        if let event = update.managementEvent {
            finishManagement(with: event)
        }
        for push in update.pushedProperties {
            for continuation in propertyPushContinuations.values {
                continuation.yield(push)
            }
        }

        for frame in update.outboundFrames {
            try enqueue(frame: frame, on: peripheral)
        }
        writeNext(on: peripheral)
        publish(snapshot)

        guard !update.waitingForResponses, update.snapshot.phase == .attached else { return }
        let rejection = operationErrorMessage.map(RadioConnectionError.operationRejected)
        // The attach is only complete once whatever this session's inspection
        // asks for has landed: a caller needs a device, not a link.
        finishAttach(throwing: rejection)
        finishOperation(throwing: rejection)
    }

    private func enqueue(frame: Data, on peripheral: CBPeripheral) throws {
        // ULCP GATT SAR needs ordinary single-write values; the
        // without-response maximum is the negotiated ATT payload bound even
        // though each segment is deliberately written with a response.
        let maximumLength = UInt16(
            min(peripheral.maximumWriteValueLength(for: .withoutResponse), Int(UInt16.max))
        )
        let segments = try UMSHMobileCore.ulcpGattSegments(
            frame: frame,
            maximumValueLength: maximumLength
        )
        pendingWrites.append(contentsOf: segments.map(\.value))
    }

    private func writeNext(on peripheral: CBPeripheral) {
        guard !writeInProgress, !pendingWrites.isEmpty, let frameIn else { return }
        writeInProgress = true
        peripheral.writeValue(pendingWrites.removeFirst(), for: frameIn, type: .withResponse)
    }

    // MARK: - Completion and failure

    private func publish(
        state: RadioLinkState,
        name: String? = nil,
        identifier: UUID? = nil
    ) {
        var next = AdministeredDeviceSnapshot.idle
        next.linkState = state
        next.name = name
        next.identifier = identifier
        publish(next)
    }

    private func publish(_ next: AdministeredDeviceSnapshot) {
        snapshot = next
        for continuation in continuations.values {
            continuation.yield(next)
        }
    }

    private func finishAttach(throwing error: (any Error)?) {
        guard let waiter = attachWaiter else { return }
        attachWaiter = nil
        attachGeneration = UUID()
        if let error {
            waiter.resume(throwing: error)
        } else {
            waiter.resume(returning: snapshot.sync)
        }
    }

    /// Give up on an exchange the device never answered, without tearing the
    /// session down: the link is still up and the device may well answer the
    /// next thing asked of it. What it did with this request is unknown, which
    /// is what `operationTimedOut` says and a rejection would not.
    private func scheduleOperationTimeout(generation: UUID) {
        queue.asyncAfter(deadline: .now() + Self.operationTimeoutSeconds) { [weak self] in
            guard let self, self.operationGeneration == generation,
                  self.operationWaiter != nil else { return }
            Self.logger.error("administrative operation timed out")
            self.finishOperation(throwing: RadioConnectionError.operationTimedOut)
        }
    }

    private func finishOperation(throwing error: (any Error)?) {
        guard let waiter = operationWaiter else { return }
        operationWaiter = nil
        operationGeneration = UUID()
        if let error {
            waiter.resume(throwing: error)
        } else {
            waiter.resume(returning: snapshot.sync)
        }
    }

    private func finishPendingOperations(throwing error: any Error) {
        finishAttach(throwing: error)
        finishOperation(throwing: error)
        finishManagement(throwing: RemoteManagementError.unavailable)
    }

    /// Why a CoreBluetooth failure happened, in the terms callers act on.
    /// A missing pairing is a setup step, not a protocol incompatibility,
    /// and the two lead the user somewhere different.
    private static func failureReason(_ error: any Error) -> RadioConnectionError {
        BluetoothErrorText.isPairingFailure(error) ? .pairingRequired : .incompatibleProtocol
    }

    /// Terminal failure for this session. There is no reconnect ladder: the
    /// user is standing in front of the device and retrying is one tap.
    ///
    /// `detail` names a protocol-layer cause the way `underlying` names a
    /// CoreBluetooth one, and `bytes` are the octets behind it. Neither
    /// reaches the UI: `message` is the only part a user sees.
    private func fail(
        _ message: String,
        error: any Error,
        underlying: (any Error)? = nil,
        detail: String? = nil,
        bytes: Data? = nil
    ) {
        let octets = bytes.map { UlcpFrameDiagnostic.hex($0) } ?? "none"
        Self.logger.error(
            """
            administrative session failed: \(message, privacy: .public) \
            cause=\(underlying.map(BluetoothErrorText.diagnostic) ?? "none", privacy: .public) \
            \(detail ?? "detail unrecorded", privacy: .public) \
            octets=\(octets, privacy: .private)
            """
        )
        let name = snapshot.name ?? peripheral?.name
        if let peripheral, let central, peripheral.state != .disconnected {
            central.cancelPeripheralConnection(peripheral)
        }
        finishPendingOperations(throwing: error)
        teardownPeripheral()
        var failed = AdministeredDeviceSnapshot.idle
        failed.linkState = .failed
        failed.name = name
        failed.problemDescription = message
        publish(failed)
    }
}

// MARK: - CBCentralManagerDelegate

extension AdministrativeDeviceSession: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        guard central.state == .poweredOn else {
            if attachWaiter != nil || peripheral != nil {
                fail(
                    "Bluetooth is unavailable",
                    error: RadioConnectionError.bluetoothUnavailable
                )
            }
            return
        }
        if discoveryRequested { beginDiscoveryScan() }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        guard discoveryActive else { return }
        recordDiscovered(peripheral, advertisementData: advertisementData, rssi: RSSI)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard self.peripheral === peripheral else { return }
        Self.logger.notice(
            "event: administrative didConnect \(peripheral.identifier, privacy: .public)"
        )
        publish(state: .attaching, name: snapshot.name ?? peripheral.name, identifier: peripheral.identifier)
        peripheral.discoverServices([RadioGatt.service])
    }

    func centralManager(
        _ central: CBCentralManager,
        didFailToConnect peripheral: CBPeripheral,
        error: (any Error)?
    ) {
        guard self.peripheral === peripheral else { return }
        // No re-arm: an administrative connect is a foreground action that
        // either worked or did not.
        fail(
            error.map(BluetoothErrorText.describe) ?? "The device connection failed",
            error: error.map(Self.failureReason) ?? RadioConnectionError.radioNotFound,
            underlying: error
        )
    }

    func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        error: (any Error)?
    ) {
        guard self.peripheral === peripheral else { return }
        Self.logger.notice(
            """
            event: administrative didDisconnect \(peripheral.identifier, privacy: .public) \
            error=\(error?.localizedDescription ?? "none", privacy: .public)
            """
        )
        fail("Connection lost", error: RadioConnectionError.radioNotFound)
    }
}

// MARK: - CBPeripheralDelegate

extension AdministrativeDeviceSession: CBPeripheralDelegate {
    /// The device told us its attribute database changed.
    ///
    /// iOS has already invalidated the affected `CBService` and every
    /// characteristic under it, so the references held here address handles
    /// that have moved. Discovering again is the only correct response; it
    /// re-enters the attach path, which restarts the ULCP session.
    func peripheral(
        _ peripheral: CBPeripheral,
        didModifyServices invalidatedServices: [CBService]
    ) {
        guard self.peripheral === peripheral,
              invalidatedServices.contains(where: { $0.uuid == RadioGatt.service })
        else { return }
        Self.logger.notice(
            "event: administrative didModifyServices \(peripheral.identifier, privacy: .public)"
        )
        frameIn = nil
        frameOut = nil
        pendingWrites.removeAll()
        writeInProgress = false
        publish(state: .attaching, name: snapshot.name, identifier: peripheral.identifier)
        peripheral.discoverServices([RadioGatt.service])
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: (any Error)?) {
        guard self.peripheral === peripheral else { return }
        if let error {
            fail(BluetoothErrorText.describe(error), error: Self.failureReason(error), underlying: error)
            return
        }
        guard let service = peripheral.services?
            .first(where: { $0.uuid == RadioGatt.service }) else {
            fail(
                "The device does not expose the ULCP service",
                error: RadioConnectionError.incompatibleProtocol
            )
            return
        }
        peripheral.discoverCharacteristics([RadioGatt.frameIn, RadioGatt.frameOut], for: service)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didDiscoverCharacteristicsFor service: CBService,
        error: (any Error)?
    ) {
        guard self.peripheral === peripheral else { return }
        if let error {
            fail(BluetoothErrorText.describe(error), error: Self.failureReason(error), underlying: error)
            return
        }
        frameIn = service.characteristics?.first { $0.uuid == RadioGatt.frameIn }
        frameOut = service.characteristics?.first { $0.uuid == RadioGatt.frameOut }
        guard frameIn != nil, let frameOut else {
            fail(
                "The device has an incompatible ULCP service",
                error: RadioConnectionError.incompatibleProtocol
            )
            return
        }
        // Enabling notifications is what triggers the system pairing prompt
        // on an unbonded device, so the link state says so.
        publish(state: .pairing, name: snapshot.name ?? peripheral.name, identifier: peripheral.identifier)
        peripheral.setNotifyValue(true, for: frameOut)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateNotificationStateFor characteristic: CBCharacteristic,
        error: (any Error)?
    ) {
        guard self.peripheral === peripheral,
              characteristic.uuid == RadioGatt.frameOut else { return }
        if let error {
            fail(BluetoothErrorText.describe(error), error: Self.failureReason(error), underlying: error)
            return
        }
        guard characteristic.isNotifying else {
            fail(
                "The device refused the ULCP attachment",
                error: RadioConnectionError.incompatibleProtocol
            )
            return
        }
        beginSynchronization(on: peripheral)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didWriteValueFor characteristic: CBCharacteristic,
        error: (any Error)?
    ) {
        guard self.peripheral === peripheral,
              characteristic.uuid == RadioGatt.frameIn else { return }
        writeInProgress = false
        if let error {
            pendingWrites.removeAll()
            fail(
                "\(BluetoothErrorText.describe(error))",
                error: Self.failureReason(error),
                underlying: error
            )
            return
        }
        writeNext(on: peripheral)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: (any Error)?
    ) {
        guard self.peripheral === peripheral,
              characteristic.uuid == RadioGatt.frameOut else { return }
        if let error {
            fail(
                "\(BluetoothErrorText.describe(error))",
                error: Self.failureReason(error),
                underlying: error
            )
            return
        }
        guard let value = characteristic.value else {
            fail(
                "The device sent an empty GATT notification",
                error: RadioConnectionError.incompatibleProtocol
            )
            return
        }
        receive(value, from: peripheral)
    }
}
