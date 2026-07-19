@preconcurrency import CoreBluetooth
import Foundation
import UMSHMobileCore

/// Discovers and attaches the GATT transport for a companion radio.
///
/// The adapter owns ATT/GATT lifecycle and write backpressure. Companion wire
/// encoding, validation, segmentation, and reassembly remain in Rust.
@MainActor
final class CoreBluetoothRadioConnection: NSObject, RadioConnection {
    private enum PreferenceKey {
        static let lastAttachedPeripheral = "radio.lastAttachedPeripheral"
    }

    private enum UUIDs {
        static let service = CBUUID(string: "21EB6B15-0001-4CCF-92E4-A079171BEC97")
        static let frameIn = CBUUID(string: "21EB6B15-0002-4CCF-92E4-A079171BEC97")
        static let frameOut = CBUUID(string: "21EB6B15-0003-4CCF-92E4-A079171BEC97")
    }

    private enum Property {
        static let lastStatus: UInt32 = 0
        static let protocolVersion: UInt32 = 1
        static let capabilities: UInt32 = 5
        static let deviceKey: UInt32 = 64
        static let deviceName: UInt32 = 68
        static let battery: UInt32 = 69
        static let saved: UInt32 = 49
        static let hostKey: UInt32 = 96
        static let hostReceiveFilters: UInt32 = 99
    }

    private enum SyncStage {
        case idle
        case initial
        case inspection
        case claiming
    }

    private var central: CBCentralManager?
    private let defaults: UserDefaults
    private var peripheral: CBPeripheral?
    private var frameIn: CBCharacteristic?
    private var frameOut: CBCharacteristic?
    private var snapshot = RadioSnapshot.idle
    private var continuations: [UUID: AsyncStream<RadioSnapshot>.Continuation] = [:]
    private var scanRequested = false
    private var scanAttempt = UUID()
    private var autoConnectRequested = false
    private var autoConnectAttempt = UUID()
    private var automaticConnectionInProgress = false
    private let reassembler = MobileGattReassembler()
    private var pendingWrites: [Data] = []
    private var writeInProgress = false
    private var expectedProperties: [UInt8: UInt32] = [:]
    private var syncAttempt = UUID()
    private var selectedHostKey: Data?
    private var radioHostKey: Data?
    private var claimInProgress = false
    private var saveInProgress = false
    private var preservesFailureOnDisconnect = false
    private var syncStage = SyncStage.idle
    private var inspectionQueue: [UInt32] = []
    private var syncPropertyResponses: [UInt32: CompanionPropertyFrameRecord] = [:]
    private var hostKeyUnsupported = false

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        super.init()
    }

    func snapshots() -> AsyncStream<RadioSnapshot> {
        let initial = snapshot
        return AsyncStream { continuation in
            let id = UUID()
            continuations[id] = continuation
            continuation.yield(initial)
            continuation.onTermination = { [weak self] _ in
                Task { @MainActor in self?.continuations[id] = nil }
            }
        }
    }

    func connect() async throws {
        autoConnectRequested = false
        autoConnectAttempt = UUID()
        automaticConnectionInProgress = false
        scanRequested = true
        if central == nil {
            publish(state: .scanning)
            central = CBCentralManager(delegate: self, queue: nil)
            return
        }
        guard central?.state == .poweredOn else {
            publishBluetoothState()
            return
        }
        startScanning()
    }

    func autoConnect() async {
        guard let value = defaults.string(forKey: PreferenceKey.lastAttachedPeripheral),
              UUID(uuidString: value) != nil
        else { return }
        autoConnectRequested = true
        if central == nil {
            central = CBCentralManager(delegate: self, queue: nil)
            return
        }
        guard central?.state == .poweredOn else { return }
        startAutomaticConnection()
    }

    func useHostIdentity(_ identity: MeshPublicIdentity?) async {
        if let identity {
            selectedHostKey = try? UMSHMobileCore.publicIdentityBytes(
                address: identity.canonicalAddress
            )
        } else {
            selectedHostKey = nil
        }
        reconcileHostOwnership()
    }

    func claimForCurrentIdentity() async throws {
        guard let peripheral, peripheral.state == .connected, let selectedHostKey else {
            throw RadioConnectionError.identityUnavailable
        }
        guard expectedProperties.isEmpty,
              snapshot.hostState == .unclaimed || snapshot.hostState == .belongsToAnotherIdentity
        else {
            throw RadioConnectionError.takeoverNotAllowed
        }

        do {
            let transactionID: UInt8 = 1
            let frame = try UMSHMobileCore.companionPropSet(
                transactionId: transactionID,
                propertyId: Property.hostKey,
                value: selectedHostKey
            )
            expectedProperties[transactionID] = Property.hostKey
            claimInProgress = true
            saveInProgress = false
            syncStage = .claiming
            syncAttempt = UUID()
            let attempt = syncAttempt
            snapshot.linkState = .provisioning
            snapshot.hostState = .claiming
            snapshot.problemDescription = nil
            publish(snapshot)
            try enqueue(frame: frame, on: peripheral)
            writeNext(on: peripheral)
            Task { @MainActor [weak self] in
                try? await Task.sleep(for: .seconds(8))
                guard let self, self.syncAttempt == attempt, self.claimInProgress else { return }
                self.claimInProgress = false
                self.saveInProgress = false
                self.expectedProperties.removeAll()
                self.publishFailure("The radio did not finish replacing its host", name: peripheral.name)
            }
        } catch {
            claimInProgress = false
            saveInProgress = false
            expectedProperties.removeAll()
            publishFailure("The host replacement request could not be encoded", name: peripheral.name)
            throw RadioConnectionError.incompatibleProtocol
        }
    }

    func disconnect() async {
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
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(10))
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

        Task { @MainActor [weak self, weak remembered] in
            try? await Task.sleep(for: .seconds(8))
            guard let self, let remembered,
                  self.autoConnectAttempt == attempt,
                  self.automaticConnectionInProgress,
                  self.peripheral === remembered,
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
        expectedProperties.removeAll()
        syncAttempt = UUID()
        claimInProgress = false
        syncStage = .idle
        inspectionQueue.removeAll()
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
        expectedProperties.removeAll(keepingCapacity: true)
        syncPropertyResponses.removeAll(keepingCapacity: true)
        inspectionQueue.removeAll(keepingCapacity: true)
        radioHostKey = nil
        hostKeyUnsupported = false
        syncStage = .initial
        syncAttempt = UUID()
        let attempt = syncAttempt
        publish(
            state: .synchronizing,
            name: peripheral.name,
            localIdentifier: peripheral.identifier
        )

        let requests: [(UInt8, UInt32)] = [
            (1, Property.lastStatus),
            (2, Property.protocolVersion),
            (3, Property.capabilities),
            (4, Property.deviceKey),
            (5, Property.deviceName),
            (6, Property.battery),
            (7, Property.hostKey),
        ]
        do {
            for (transactionID, propertyID) in requests {
                expectedProperties[transactionID] = propertyID
                let frame = try UMSHMobileCore.companionPropGet(
                    transactionId: transactionID,
                    propertyId: propertyID
                )
                try enqueue(frame: frame, on: peripheral)
            }
            writeNext(on: peripheral)
        } catch {
            publishFailure("The companion synchronization request could not be encoded", name: peripheral.name)
            return
        }

        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(8))
            guard let self, self.syncAttempt == attempt, !self.expectedProperties.isEmpty else {
                return
            }
            self.publishFailure("The companion radio did not finish synchronizing", name: peripheral.name)
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
            let response = try UMSHMobileCore.inspectCompanionPropertyFrame(bytes: frame)
            apply(response, from: peripheral)
        } catch {
            publishFailure("The radio sent an invalid companion frame", name: peripheral.name)
        }
    }

    private func apply(_ response: CompanionPropertyFrameRecord, from peripheral: CBPeripheral) {
        guard response.transactionId != 0 else {
            // Unsolicited property changes will feed the same reducer once the
            // long-lived companion session is introduced.
            return
        }
        guard let expected = expectedProperties.removeValue(forKey: response.transactionId) else {
            return
        }
        if response.propertyId == Property.lastStatus, expected != Property.lastStatus {
            if claimInProgress && expected == Property.hostKey {
                claimInProgress = false
                publishFailure("The radio refused to replace its configured host", name: peripheral.name)
            } else if expected == Property.protocolVersion {
                publishFailure("The radio does not support the required companion protocol", name: peripheral.name)
            } else if syncStage == .initial && expected == Property.hostKey {
                hostKeyUnsupported = true
                finishSynchronizationIfComplete(on: peripheral)
            } else if syncStage == .inspection {
                publishFailure("The radio refused an advertised synchronization property", name: peripheral.name)
            } else {
                finishSynchronizationIfComplete(on: peripheral)
            }
            return
        }
        guard response.propertyId == expected else {
            publishFailure("The radio returned a mismatched companion response", name: peripheral.name)
            return
        }
        guard response.command == 6 else {
            publishFailure("The radio returned an invalid transaction response", name: peripheral.name)
            return
        }
        syncPropertyResponses[response.propertyId] = response

        switch response.propertyId {
        case Property.lastStatus where saveInProgress:
            do {
                let status = try UMSHMobileCore.inspectCompanionStatus(value: response.value)
                guard status == 0 else {
                    claimInProgress = false
                    saveInProgress = false
                    publishFailure("The radio could not save this phone as its host", name: peripheral.name)
                    return
                }
                claimInProgress = false
                saveInProgress = false
            } catch {
                claimInProgress = false
                saveInProgress = false
                publishFailure("The radio returned an invalid save result", name: peripheral.name)
                return
            }
        case Property.protocolVersion:
            guard response.value.count == 2, response.value.first == 6 else {
                publishFailure("The radio uses an incompatible companion protocol", name: peripheral.name)
                return
            }
        case Property.deviceKey:
            if response.value.isEmpty {
                snapshot.deviceIdentity = nil
            } else {
                do {
                    let identity = try UMSHMobileCore.inspectPublicIdentityBytes(publicKey: response.value)
                    snapshot.deviceIdentity = MeshPublicIdentity(
                        canonicalAddress: identity.canonicalAddress,
                        hint: MeshNodeHint(bytes: identity.hint.bytes, text: identity.hint.text)
                    )
                } catch {
                    publishFailure("The radio returned an invalid device identity", name: peripheral.name)
                    return
                }
            }
        case Property.deviceName:
            if let name = String(data: response.value, encoding: .utf8), !name.isEmpty {
                snapshot.name = name
            }
        case Property.battery:
            do {
                let battery = try UMSHMobileCore.inspectCompanionBattery(value: response.value)
                snapshot.batteryPercentage = battery.percentage.map(Int.init)
                snapshot.isExternallyPowered = battery.isExternallyPowered
                snapshot.batteryReadAt = .now
            } catch {
                publishFailure("The radio returned an invalid battery status", name: peripheral.name)
                return
            }
        case Property.hostKey:
            guard response.value.isEmpty || response.value.count == 32 else {
                publishFailure("The radio returned an invalid host identity", name: peripheral.name)
                return
            }
            radioHostKey = response.value
            if claimInProgress {
                guard response.value == selectedHostKey else {
                    claimInProgress = false
                    publishFailure("The radio did not apply the requested host identity", name: peripheral.name)
                    return
                }
                if inspectionQueue.contains(Property.saved) {
                    do {
                        let transactionID: UInt8 = 2
                        expectedProperties[transactionID] = Property.lastStatus
                        saveInProgress = true
                        let frame = try UMSHMobileCore.companionSave(transactionId: transactionID)
                        try enqueue(frame: frame, on: peripheral)
                        writeNext(on: peripheral)
                    } catch {
                        claimInProgress = false
                        saveInProgress = false
                        expectedProperties.removeAll()
                        publishFailure("The radio save request could not be encoded", name: peripheral.name)
                        return
                    }
                } else {
                    claimInProgress = false
                }
            }
        default:
            break
        }
        publish(snapshot)
        finishSynchronizationIfComplete(on: peripheral)
    }

    private func finishSynchronizationIfComplete(on peripheral: CBPeripheral) {
        guard expectedProperties.isEmpty else { return }
        syncAttempt = UUID()
        switch syncStage {
        case .initial:
            syncStage = .idle
            prepareInspection(on: peripheral)
        case .claiming:
            syncStage = .idle
            reconcileHostOwnership()
        case .inspection:
            startNextInspectionBatch(on: peripheral)
        case .idle:
            break
        }
    }

    private func reconcileHostOwnership() {
        guard expectedProperties.isEmpty else { return }
        snapshot.problemDescription = nil
        if hostKeyUnsupported {
            snapshot.hostState = .unsupported
            beginInspectionIfPossible()
            return
        }
        guard let radioHostKey else { return }
        snapshot.hostState = .classify(
            radioKey: radioHostKey,
            selectedHostKey: selectedHostKey
        )
        if snapshot.hostState == .matchesCurrentIdentity {
            beginInspectionIfPossible()
        } else {
            snapshot.linkState = .awaitingHost
            publish(snapshot)
        }
    }

    private func prepareInspection(on peripheral: CBPeripheral) {
        guard let capabilities = syncPropertyResponses[Property.capabilities]?.value else {
            publishFailure("The radio did not return its capability list", name: peripheral.name)
            return
        }
        do {
            inspectionQueue = try UMSHMobileCore.companionInspectionProperties(
                capabilities: capabilities
            )
        } catch {
            publishFailure("The radio advertised an invalid capability set", name: peripheral.name)
            return
        }
        let advertisesHostFiltering = inspectionQueue.contains(Property.hostReceiveFilters)
        if advertisesHostFiltering == hostKeyUnsupported {
            publishFailure("The radio's host capability does not match its behavior", name: peripheral.name)
            return
        }
        reconcileHostOwnership()
    }

    private func beginInspectionIfPossible() {
        guard syncStage == .idle, snapshot.provisioning == nil, let peripheral else { return }
        snapshot.linkState = .synchronizing
        publish(snapshot)
        syncStage = .inspection
        startNextInspectionBatch(on: peripheral)
    }

    private func startNextInspectionBatch(on peripheral: CBPeripheral) {
        guard syncStage == .inspection, expectedProperties.isEmpty else { return }
        guard !inspectionQueue.isEmpty else {
            finishInspection(on: peripheral)
            return
        }
        let batch = Array(inspectionQueue.prefix(7))
        inspectionQueue.removeFirst(batch.count)
        syncAttempt = UUID()
        let attempt = syncAttempt
        do {
            for (offset, propertyID) in batch.enumerated() {
                let transactionID = UInt8(offset + 1)
                expectedProperties[transactionID] = propertyID
                let frame = try UMSHMobileCore.companionPropGet(
                    transactionId: transactionID,
                    propertyId: propertyID
                )
                try enqueue(frame: frame, on: peripheral)
            }
            writeNext(on: peripheral)
        } catch {
            publishFailure("The radio inspection request could not be encoded", name: peripheral.name)
            return
        }
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(8))
            guard let self, self.syncAttempt == attempt, self.syncStage == .inspection,
                  !self.expectedProperties.isEmpty
            else { return }
            self.publishFailure("The radio did not finish its state inspection", name: peripheral.name)
        }
    }

    private func finishInspection(on peripheral: CBPeripheral) {
        do {
            let state = try UMSHMobileCore.inspectCompanionSync(
                responses: Array(syncPropertyResponses.values)
            )
            snapshot.provisioning = RadioProvisioningSummary(
                capabilityCount: Int(state.capabilityCount),
                hasHostFiltering: state.hasHostFiltering,
                supportsOfflineQueue: state.supportsOfflineQueue,
                supportsDelegatedAcknowledgements: state.supportsDelegatedAck,
                phyEnabled: state.phyEnabled,
                frequencyKHz: state.frequencyKhz,
                saved: state.saved,
                queuedFrames: state.queuedFrames.map(Int.init),
                droppedFrames: state.droppedFrames,
                filterCount: state.filterCount.map(Int.init),
                hostChannelCount: state.hostChannelCount.map(Int.init),
                hostPeerCount: state.hostPeerCount.map(Int.init),
                autoAcknowledgementEnabled: state.autoAck
            )
            syncStage = .idle
            syncAttempt = UUID()
            snapshot.linkState = .attached
            snapshot.problemDescription = nil
            defaults.set(peripheral.identifier.uuidString, forKey: PreferenceKey.lastAttachedPeripheral)
            publish(snapshot)
        } catch {
            publishFailure("The radio returned malformed synchronization state", name: peripheral.name)
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
        pendingWrites.removeAll()
        writeInProgress = false
        expectedProperties.removeAll()
        syncAttempt = UUID()
        radioHostKey = nil
        claimInProgress = false
        saveInProgress = false
        preservesFailureOnDisconnect = false
        syncStage = .idle
        inspectionQueue.removeAll()
        syncPropertyResponses.removeAll()
        hostKeyUnsupported = false
        automaticConnectionInProgress = false
    }
}

extension CoreBluetoothRadioConnection: @preconcurrency CBCentralManagerDelegate {
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

extension CoreBluetoothRadioConnection: @preconcurrency CBPeripheralDelegate {
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
