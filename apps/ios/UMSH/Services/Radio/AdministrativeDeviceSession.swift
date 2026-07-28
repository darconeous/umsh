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
/// model on purpose — the editor reads `UlcpSyncRecord` and writes
/// `UlcpDeviceConfigRecord`, so read and write speak one vocabulary and no
/// field can be lost in a translation layer.
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
    var isExternallyPowered: Bool?
    var problemDescription: String?

    static let idle = Self(
        linkState: .idle,
        identifier: nil,
        name: nil,
        deviceIdentity: nil,
        hostState: .unknown,
        sync: nil,
        batteryPercentage: nil,
        isExternallyPowered: nil,
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
    /// How long a device may go unheard before it leaves the scan list.
    private static let discoveryStaleSeconds: UInt64 = 6

    private struct DiscoveredEntry {
        var peripheral: CBPeripheral
        var name: String?
        var rssiDBm: Int
        var lastSeen: DispatchTime
    }

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
    private let ulcpSession = MobileUlcpSession.administrative()
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

    private var attachWaiter: CheckedContinuation<Void, any Error>?
    private var attachGeneration = UUID()
    /// The caller awaiting a post-attach exchange — a configuration write or
    /// a re-read. Both complete on the same condition (the session is back
    /// at `attached` with nothing outstanding), so one waiter serves both
    /// and also enforces that only one runs at a time.
    private var operationWaiter: CheckedContinuation<Void, any Error>?

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
            ?? DiscoveredEntry(
                peripheral: peripheral,
                name: advertisedName ?? peripheral.name,
                rssiDBm: rssi.intValue,
                lastSeen: .now()
            )
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
        discovered.values
            .map { entry in
                DiscoveredRadio(
                    id: entry.peripheral.identifier,
                    name: entry.name,
                    rssiDBm: entry.rssiDBm,
                    isRemembered: entry.peripheral.identifier == companionIdentifier
                )
            }
            // Same ordering rule as companion discovery, and for the same
            // reason: RSSI is shown per row but never sorted on, so a device
            // does not migrate under the user's finger on a busy bench.
            .sorted { lhs, rhs in
                if lhs.isRemembered != rhs.isRemembered { return lhs.isRemembered }
                if (lhs.name == nil) != (rhs.name == nil) { return rhs.name == nil }
                if let lhsName = lhs.name, let rhsName = rhs.name, lhsName != rhsName {
                    return lhsName.localizedCaseInsensitiveCompare(rhsName) == .orderedAscending
                }
                return lhs.id.uuidString < rhs.id.uuidString
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

    /// Connect to `id` and synchronize with it, resolving once the ULCP
    /// session is attached and its configuration has been read.
    ///
    /// Throws if the device cannot be reached, refuses the protocol, or the
    /// whole exchange overruns its budget. A drop *after* this resolves is
    /// not thrown anywhere — it arrives on `snapshots()` as a failed link,
    /// because by then the caller is a UI showing an editor, not an
    /// `await`.
    func connect(_ id: UUID) async throws {
        try await withCheckedThrowingContinuation {
            (result: CheckedContinuation<Void, any Error>) in
            queue.async { [self] in
                guard let central, central.state == .poweredOn else {
                    result.resume(throwing: RadioConnectionError.bluetoothUnavailable)
                    return
                }
                guard attachWaiter == nil, operationWaiter == nil else {
                    result.resume(throwing: RadioConnectionError.operationInProgress)
                    return
                }
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
                publish(state: .connecting, name: target.name, identifier: target.identifier)
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
        try await perform { session in try session.configureDevice(configuration: configuration) }
    }

    /// Re-read the device's authoritative configuration.
    ///
    /// A write is already echo-verified property by property, so this is not
    /// how a bad write is caught — it is how the *saved* device is read back
    /// after the trailing `CMD_SAVE`, which is a different question.
    func refresh() async throws {
        try await perform { session in try session.refresh() }
    }

    /// Run one post-attach exchange to completion.
    private func perform(
        _ start: @escaping @Sendable (MobileUlcpSession) throws -> UlcpSessionUpdateRecord
    ) async throws {
        try await withCheckedThrowingContinuation {
            (result: CheckedContinuation<Void, any Error>) in
            queue.async { [self] in
                guard let peripheral, peripheral.state == .connected else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                guard operationWaiter == nil, attachWaiter == nil else {
                    result.resume(throwing: RadioConnectionError.operationInProgress)
                    return
                }
                operationWaiter = result
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
                error: RadioConnectionError.incompatibleProtocol
            )
        }
    }

    private func receive(_ value: Data, from peripheral: CBPeripheral) {
        do {
            guard let frame = try reassembler.push(segment: value) else { return }
            try applySessionUpdate(ulcpSession.consume(frame: frame), from: peripheral)
        } catch {
            fail(
                "The device sent an invalid ULCP frame",
                error: RadioConnectionError.incompatibleProtocol
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
            snapshot.isExternallyPowered = battery.isExternallyPowered
        }
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

        for frame in update.outboundFrames {
            try enqueue(frame: frame, on: peripheral)
        }
        writeNext(on: peripheral)
        publish(snapshot)

        guard !update.waitingForResponses, update.snapshot.phase == .attached else { return }
        let rejection = operationErrorMessage.map(RadioConnectionError.operationRejected)
        // The attach is only complete once the whole capability-gated read
        // has landed: the editor needs a configuration, not a link.
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
        if let error { waiter.resume(throwing: error) } else { waiter.resume() }
    }

    private func finishOperation(throwing error: (any Error)?) {
        guard let waiter = operationWaiter else { return }
        operationWaiter = nil
        if let error { waiter.resume(throwing: error) } else { waiter.resume() }
    }

    private func finishPendingOperations(throwing error: any Error) {
        finishAttach(throwing: error)
        finishOperation(throwing: error)
    }

    /// Terminal failure for this session. There is no reconnect ladder: the
    /// user is standing in front of the device and retrying is one tap.
    private func fail(_ message: String, error: any Error) {
        Self.logger.error("administrative session failed: \(message, privacy: .public)")
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
        publish(state: .attaching, name: peripheral.name, identifier: peripheral.identifier)
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
            error?.localizedDescription ?? "The device connection failed",
            error: RadioConnectionError.radioNotFound
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
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: (any Error)?) {
        guard self.peripheral === peripheral else { return }
        if let error {
            fail(error.localizedDescription, error: RadioConnectionError.incompatibleProtocol)
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
            fail(error.localizedDescription, error: RadioConnectionError.incompatibleProtocol)
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
        publish(state: .pairing, name: peripheral.name, identifier: peripheral.identifier)
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
            fail(error.localizedDescription, error: RadioConnectionError.incompatibleProtocol)
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
                "The ULCP write was not accepted: \(error.localizedDescription)",
                error: RadioConnectionError.operationRejected(error.localizedDescription)
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
                "The ULCP notification could not be read: \(error.localizedDescription)",
                error: RadioConnectionError.operationRejected(error.localizedDescription)
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
