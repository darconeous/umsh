@preconcurrency import CoreBluetooth
import Foundation
import UMSHMobileCore

/// Discovers and attaches the GATT transport for a companion radio.
///
/// The adapter owns ATT/GATT lifecycle and write backpressure. Companion wire
/// encoding, validation, segmentation, and reassembly remain in Rust.
final class CoreBluetoothRadioConnection: NSObject, RadioConnection, @unchecked Sendable {
    private enum PreferenceKey {
        static let lastAttachedPeripheral = "radio.lastAttachedPeripheral"
    }

    private enum UUIDs {
        static let service = CBUUID(string: "21EB6B15-0001-4CCF-92E4-A079171BEC97")
        static let frameIn = CBUUID(string: "21EB6B15-0002-4CCF-92E4-A079171BEC97")
        static let frameOut = CBUUID(string: "21EB6B15-0003-4CCF-92E4-A079171BEC97")
    }

    private var central: CBCentralManager?
    private let bluetoothQueue = DispatchQueue(
        label: "com.umsh.radio.core-bluetooth",
        qos: .userInitiated
    )
    private let defaults: UserDefaults
    private var peripheral: CBPeripheral?
    private var frameIn: CBCharacteristic?
    private var frameOut: CBCharacteristic?
    private var snapshot = RadioSnapshot.idle
    private var continuations: [UUID: AsyncStream<RadioSnapshot>.Continuation] = [:]
    private var frameContinuations: [UUID: AsyncStream<RadioReceivedFrame>.Continuation] = [:]
    private var scanRequested = false
    private var scanAttempt = UUID()
    private var autoConnectRequested = false
    private var autoConnectAttempt = UUID()
    private var automaticConnectionInProgress = false
    private let reassembler = MobileGattReassembler()
    private let companionSession = MobileCompanionSession()
    private var pendingWrites: [Data] = []
    private var writeInProgress = false
    private var syncAttempt = UUID()
    private var selectedHostKey: Data?
    private var preservesFailureOnDisconnect = false

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        super.init()
    }

    func snapshots() async -> AsyncStream<RadioSnapshot> {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                let initial = snapshot
                let stream = AsyncStream { continuation in
                    let id = UUID()
                    continuations[id] = continuation
                    continuation.yield(initial)
                    continuation.onTermination = { [weak self] _ in
                        self?.bluetoothQueue.async { [weak self] in
                            self?.continuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    func receivedFrames() async -> AsyncStream<RadioReceivedFrame> {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                let stream = AsyncStream { continuation in
                    let id = UUID()
                    frameContinuations[id] = continuation
                    continuation.onTermination = { [weak self] _ in
                        self?.bluetoothQueue.async { [weak self] in
                            self?.frameContinuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    func connect() async throws {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                connectOnQueue()
                result.resume()
            }
        }
    }

    private func connectOnQueue() {
        autoConnectRequested = false
        autoConnectAttempt = UUID()
        automaticConnectionInProgress = false
        scanRequested = true
        if central == nil {
            publish(state: .scanning)
            central = CBCentralManager(delegate: self, queue: bluetoothQueue)
            return
        }
        guard central?.state == .poweredOn else {
            publishBluetoothState()
            return
        }
        startScanning()
    }

    func autoConnect() async {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                autoConnectOnQueue()
                result.resume()
            }
        }
    }

    private func autoConnectOnQueue() {
        guard let value = defaults.string(forKey: PreferenceKey.lastAttachedPeripheral),
              UUID(uuidString: value) != nil
        else { return }
        autoConnectRequested = true
        if central == nil {
            central = CBCentralManager(delegate: self, queue: bluetoothQueue)
            return
        }
        guard central?.state == .poweredOn else { return }
        startAutomaticConnection()
    }

    func useHostIdentity(_ identity: MeshPublicIdentity?) async throws {
        let hostKey: Data?
        if let identity {
            hostKey = try UMSHMobileCore.publicIdentityBytes(
                address: identity.canonicalAddress
            )
        } else {
            hostKey = nil
        }
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                selectedHostKey = hostKey
                result.resume()
            }
        }
    }

    func claimForCurrentIdentity() async throws {
        try await withCheckedThrowingContinuation { result in
            bluetoothQueue.async { [self] in
                do {
                    try claimForCurrentIdentityOnQueue()
                    result.resume()
                } catch {
                    result.resume(throwing: error)
                }
            }
        }
    }

    private func claimForCurrentIdentityOnQueue() throws {
        guard let peripheral, peripheral.state == .connected, let selectedHostKey else {
            throw RadioConnectionError.identityUnavailable
        }
        guard snapshot.hostState == .unclaimed || snapshot.hostState == .belongsToAnotherIdentity
        else {
            throw RadioConnectionError.takeoverNotAllowed
        }

        do {
            try applySessionUpdate(
                companionSession.claim(hostKey: selectedHostKey),
                from: peripheral
            )
        } catch {
            publishFailure("The radio could not replace its configured host", name: peripheral.name)
            throw RadioConnectionError.incompatibleProtocol
        }
    }

    func disconnect() async {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                disconnectOnQueue()
                result.resume()
            }
        }
    }

    private func disconnectOnQueue() {
        scanRequested = false
        scanAttempt = UUID()
        autoConnectRequested = false
        autoConnectAttempt = UUID()
        automaticConnectionInProgress = false
        central?.stopScan()
        guard let peripheral else {
            publish(.idle)
            return
        }
        publish(state: .disconnecting, name: peripheral.name)
        central?.cancelPeripheralConnection(peripheral)
    }

    private func startScanning() {
        guard central?.state == .poweredOn else { return }
        scanRequested = false
        scanAttempt = UUID()
        let attempt = scanAttempt
        if let peripheral, peripheral.state != .disconnected {
            central?.cancelPeripheralConnection(peripheral)
        }
        clearPeripheral()
        publish(state: .scanning)
        central?.scanForPeripherals(
            withServices: [UUIDs.service],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: false]
        )
        bluetoothQueue.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self, self.scanAttempt == attempt, self.snapshot.linkState == .scanning else {
                return
            }
            self.central?.stopScan()
            self.publish(
                RadioSnapshot(
                    linkState: .failed,
                    name: nil,
                    localIdentifier: nil,
                    batteryPercentage: nil,
                    isExternallyPowered: nil,
                    batteryReadAt: nil,
                    deviceIdentity: nil,
                    hostState: .unknown,
                    provisioning: nil,
                    problemDescription: "No companion radio was found"
                )
            )
        }
    }

    private func startAutomaticConnection() {
        guard let central, central.state == .poweredOn, autoConnectRequested else { return }
        autoConnectRequested = false
        guard let value = defaults.string(forKey: PreferenceKey.lastAttachedPeripheral),
              let identifier = UUID(uuidString: value)
        else { return }
        guard let remembered = central.retrievePeripherals(withIdentifiers: [identifier]).first else {
            defaults.removeObject(forKey: PreferenceKey.lastAttachedPeripheral)
            publish(.idle)
            return
        }

        clearPeripheral()
        peripheral = remembered
        remembered.delegate = self
        automaticConnectionInProgress = true
        autoConnectAttempt = UUID()
        let attempt = autoConnectAttempt
        publish(
            state: .connecting,
            name: remembered.name,
            localIdentifier: remembered.identifier
        )
        central.connect(remembered)

        bluetoothQueue.asyncAfter(deadline: .now() + 8) { [weak self] in
            guard let self, let remembered = self.peripheral,
                  self.autoConnectAttempt == attempt,
                  self.automaticConnectionInProgress,
                  remembered.state != .connected
            else { return }
            self.automaticConnectionInProgress = false
            self.central?.cancelPeripheralConnection(remembered)
            self.clearPeripheral()
            self.publish(.idle)
        }
    }

    private func publishBluetoothState() {
        guard let central else { return }
        let message: String
        switch central.state {
        case .poweredOn:
            if autoConnectRequested {
                startAutomaticConnection()
            } else if scanRequested {
                startScanning()
            }
            return
        case .unauthorized: message = "Bluetooth permission is denied"
        case .unsupported: message = "Bluetooth is unavailable on this device"
        case .poweredOff: message = "Bluetooth is turned off"
        case .resetting: message = "Bluetooth is restarting"
        case .unknown: message = "Bluetooth is starting"
        @unknown default: message = "Bluetooth is unavailable"
        }
        publish(
            RadioSnapshot(
                linkState: .unavailable,
                name: nil,
                localIdentifier: nil,
                batteryPercentage: nil,
                isExternallyPowered: nil,
                batteryReadAt: nil,
                deviceIdentity: nil,
                hostState: .unknown,
                provisioning: nil,
                problemDescription: message
            )
        )
    }

    private func publish(
        state: RadioLinkState,
        name: String? = nil,
        localIdentifier: UUID? = nil
    ) {
        publish(
            RadioSnapshot(
                linkState: state,
                name: name,
                localIdentifier: localIdentifier,
                batteryPercentage: nil,
                isExternallyPowered: nil,
                batteryReadAt: nil,
                deviceIdentity: nil,
                hostState: .unknown,
                provisioning: nil,
                problemDescription: nil
            )
        )
    }

    private func publishFailure(_ message: String, name: String? = nil) {
        pendingWrites.removeAll()
        writeInProgress = false
        syncAttempt = UUID()
        _ = companionSession.reset()
        snapshot.linkState = .failed
        snapshot.name = name ?? snapshot.name
        snapshot.problemDescription = message
        publish(snapshot)
        if let peripheral, peripheral.state == .connected {
            preservesFailureOnDisconnect = true
            central?.cancelPeripheralConnection(peripheral)
        }
    }

    private func beginSynchronization(on peripheral: CBPeripheral) {
        guard let frameIn else {
            publishFailure("The radio has no writable companion endpoint", name: peripheral.name)
            return
        }
        guard frameIn.properties.contains(.write) else {
            publishFailure("The radio requires an unsupported write mode", name: peripheral.name)
            return
        }

        reassembler.reset()
        pendingWrites.removeAll(keepingCapacity: true)
        writeInProgress = false
        do {
            try applySessionUpdate(
                companionSession.begin(selectedHostKey: selectedHostKey),
                from: peripheral
            )
        } catch {
            publishFailure("The companion session could not start", name: peripheral.name)
        }
    }

    private func writeNext(on peripheral: CBPeripheral) {
        guard !writeInProgress, !pendingWrites.isEmpty, let frameIn else { return }
        writeInProgress = true
        peripheral.writeValue(pendingWrites.removeFirst(), for: frameIn, type: .withResponse)
    }

    private func enqueue(frame: Data, on peripheral: CBPeripheral) throws {
        let maximumLength = UInt16(
            min(peripheral.maximumWriteValueLength(for: .withResponse), Int(UInt16.max))
        )
        let segments = try UMSHMobileCore.companionGattSegments(
            frame: frame,
            maximumValueLength: maximumLength
        )
        pendingWrites.append(contentsOf: segments.map(\.value))
    }

    private func receive(_ value: Data, from peripheral: CBPeripheral) {
        do {
            guard let frame = try reassembler.push(segment: value) else { return }
            try applySessionUpdate(companionSession.consume(frame: frame), from: peripheral)
        } catch {
            publishFailure("The radio sent an invalid companion frame", name: peripheral.name)
        }
    }

    private func applySessionUpdate(
        _ update: CompanionSessionUpdateRecord,
        from peripheral: CBPeripheral
    ) throws {
        syncAttempt = UUID()
        snapshot.linkState = switch update.snapshot.phase {
        case .idle: .attaching
        case .synchronizing: .synchronizing
        case .awaitingHost: .awaitingHost
        case .claiming: .provisioning
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
            snapshot.batteryReadAt = .now
        }
        snapshot.provisioning = update.snapshot.provisioning.map {
            RadioProvisioningSummary(
                capabilityCount: Int($0.capabilityCount),
                hasHostFiltering: $0.hasHostFiltering,
                supportsOfflineQueue: $0.supportsOfflineQueue,
                supportsDelegatedAcknowledgements: $0.supportsDelegatedAck,
                phyEnabled: $0.phyEnabled,
                frequencyKHz: $0.frequencyKhz,
                saved: $0.saved,
                queuedFrames: $0.queuedFrames.map(Int.init),
                droppedFrames: $0.droppedFrames,
                filterCount: $0.filterCount.map(Int.init),
                hostChannelCount: $0.hostChannelCount.map(Int.init),
                hostPeerCount: $0.hostPeerCount.map(Int.init),
                autoAcknowledgementEnabled: $0.autoAck
            )
        }
        snapshot.problemDescription = nil

        for received in update.receivedFrames {
            let frame = RadioReceivedFrame(
                data: received.data,
                rssiDBm: received.rssiDbm.map(Int.init),
                linkQuality: received.lqi,
                signalToNoiseCentibels: received.snrCb.map(Int.init),
                wasBuffered: received.wasBuffered,
                wasAcknowledgedByRadio: received.wasAcknowledged,
                ageSeconds: received.ageSeconds
            )
            for continuation in frameContinuations.values {
                continuation.yield(frame)
            }
        }

        for frame in update.outboundFrames {
            try enqueue(frame: frame, on: peripheral)
        }
        writeNext(on: peripheral)
        if update.snapshot.phase == .attached {
            defaults.set(
                peripheral.identifier.uuidString,
                forKey: PreferenceKey.lastAttachedPeripheral
            )
        }
        publish(snapshot)

        guard update.waitingForResponses else { return }
        let attempt = syncAttempt
        bluetoothQueue.asyncAfter(deadline: .now() + 8) { [weak self] in
            guard let self, let peripheral = self.peripheral, self.syncAttempt == attempt else {
                return
            }
            self.publishFailure(
                "The companion radio did not finish synchronizing",
                name: peripheral.name
            )
        }
    }

    private func publish(_ newSnapshot: RadioSnapshot) {
        snapshot = newSnapshot
        for continuation in continuations.values {
            continuation.yield(newSnapshot)
        }
    }

    private func clearPeripheral() {
        peripheral?.delegate = nil
        peripheral = nil
        frameIn = nil
        frameOut = nil
        reassembler.reset()
        _ = companionSession.reset()
        pendingWrites.removeAll()
        writeInProgress = false
        syncAttempt = UUID()
        preservesFailureOnDisconnect = false
        automaticConnectionInProgress = false
    }
}

extension CoreBluetoothRadioConnection: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        publishBluetoothState()
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        guard snapshot.linkState == .scanning else { return }
        scanAttempt = UUID()
        central.stopScan()
        self.peripheral = peripheral
        peripheral.delegate = self
        let advertisedName = advertisementData[CBAdvertisementDataLocalNameKey] as? String
        publish(
            state: .connecting,
            name: advertisedName ?? peripheral.name,
            localIdentifier: peripheral.identifier
        )
        central.connect(peripheral)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard self.peripheral === peripheral else { return }
        automaticConnectionInProgress = false
        autoConnectAttempt = UUID()
        publish(
            state: .attaching,
            name: peripheral.name,
            localIdentifier: peripheral.identifier
        )
        peripheral.discoverServices([UUIDs.service])
    }

    func centralManager(
        _ central: CBCentralManager,
        didFailToConnect peripheral: CBPeripheral,
        error: (any Error)?
    ) {
        guard self.peripheral === peripheral else { return }
        if automaticConnectionInProgress {
            automaticConnectionInProgress = false
            clearPeripheral()
            publish(.idle)
            return
        }
        publishFailure(error?.localizedDescription ?? "The companion radio connection failed", name: peripheral.name)
        clearPeripheral()
    }

    func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        error: (any Error)?
    ) {
        guard self.peripheral === peripheral else { return }
        if preservesFailureOnDisconnect {
            preservesFailureOnDisconnect = false
            clearPeripheral()
            return
        }
        if let error {
            publishFailure(error.localizedDescription, name: peripheral.name)
        } else {
            publish(.disconnected)
        }
        clearPeripheral()
    }
}

extension CoreBluetoothRadioConnection: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: (any Error)?) {
        if let error {
            publishFailure(error.localizedDescription, name: peripheral.name)
            return
        }
        guard let service = peripheral.services?.first(where: { $0.uuid == UUIDs.service }) else {
            publishFailure("The radio does not expose the companion service", name: peripheral.name)
            return
        }
        peripheral.discoverCharacteristics([UUIDs.frameIn, UUIDs.frameOut], for: service)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didDiscoverCharacteristicsFor service: CBService,
        error: (any Error)?
    ) {
        if let error {
            publishFailure(error.localizedDescription, name: peripheral.name)
            return
        }
        frameIn = service.characteristics?.first(where: { $0.uuid == UUIDs.frameIn })
        frameOut = service.characteristics?.first(where: { $0.uuid == UUIDs.frameOut })
        guard frameIn != nil, let frameOut else {
            publishFailure("The radio has an incompatible companion service", name: peripheral.name)
            return
        }
        publish(
            state: .pairing,
            name: peripheral.name,
            localIdentifier: peripheral.identifier
        )
        peripheral.setNotifyValue(true, for: frameOut)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateNotificationStateFor characteristic: CBCharacteristic,
        error: (any Error)?
    ) {
        guard characteristic.uuid == UUIDs.frameOut else { return }
        if let error {
            publishFailure(error.localizedDescription, name: peripheral.name)
            return
        }
        guard characteristic.isNotifying else {
            publishFailure("The radio refused the companion attachment", name: peripheral.name)
            return
        }
        beginSynchronization(on: peripheral)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didWriteValueFor characteristic: CBCharacteristic,
        error: (any Error)?
    ) {
        guard characteristic.uuid == UUIDs.frameIn else { return }
        writeInProgress = false
        if let error {
            publishFailure(error.localizedDescription, name: peripheral.name)
            return
        }
        writeNext(on: peripheral)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: (any Error)?
    ) {
        guard characteristic.uuid == UUIDs.frameOut else { return }
        if let error {
            publishFailure(error.localizedDescription, name: peripheral.name)
            return
        }
        guard let value = characteristic.value else {
            publishFailure("The radio sent an empty GATT notification", name: peripheral.name)
            return
        }
        receive(value, from: peripheral)
    }
}
