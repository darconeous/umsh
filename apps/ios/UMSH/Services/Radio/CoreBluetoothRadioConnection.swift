@preconcurrency import CoreBluetooth
import Foundation
import OSLog
import UMSHMobileCore

/// Discovers and attaches the GATT transport for a companion radio.
///
/// The adapter owns ATT/GATT lifecycle and write backpressure. Companion wire
/// encoding, validation, segmentation, and reassembly remain in Rust.
final class CoreBluetoothRadioConnection: NSObject, RadioConnection, @unchecked Sendable {
    /// Long enough for a several-hop LoRa round trip, but short enough that a
    /// silent peer does not leave the peer page waiting for half a minute.
    private static let peerPingTimeoutMilliseconds: UInt64 = 8_000
    private static let logger = Logger(subsystem: "com.umsh.ios", category: "CompanionRadio")
    private static let maximumRawTransmitBusyRetries = 20
    // The current mobile MAC needs the companion's physical TX completion
    // before starting its ACK clock. A larger CRP window is unsafe until the
    // companion itself owns the inter-frame receive/ACK window.
    private static let maximumRawTransmitsInFlight = 1

    private struct PendingRawFrame {
        var data: Data
        var meshFrameID: UInt64
        var busyRetries = 0
    }

    private struct PendingGattWrite {
        var value: Data
        var rawTransactionID: UInt8?
    }

    private struct DiscoveredEntry {
        var peripheral: CBPeripheral
        var name: String?
        var rssiDBm: Int
        var lastSeen: DispatchTime
    }

    private enum PreferenceKey {
        /// The radio the app is bound to. Set when a session first attaches,
        /// changed by "find another radio", cleared by "forget". Kept across a
        /// user Disconnect so Reconnect knows what to target.
        static let connectedUUID = "radio.connectedUUID"
        /// The single source of truth for auto-reconnect intent. The invariant
        /// is: `shouldAutoConnect == true` ⟺ there is an outstanding
        /// `connect(connectedUUID)` registered with bluetoothd. It is
        /// reconciled against the daemon on every powered-on transition and
        /// state restoration, so a force-quit cannot leave a zombie connect
        /// squatting the radio's single peripheral slot.
        static let shouldAutoConnect = "radio.shouldAutoConnect"
        /// Legacy key (pre state-machine). Migrated into `connectedUUID` +
        /// `shouldAutoConnect` once, at init.
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
    private var chatContinuations: [UUID: AsyncStream<RadioChatUpdate>.Continuation] = [:]
    private var advertisementContinuations:
        [UUID: AsyncStream<RadioAdvertisementEvent>.Continuation] = [:]
    private var scanRequested = false
    private var scanExcludesRememberedRadio = false
    private var scanAttempt = UUID()
    /// Explicit user-driven discovery: accumulate every advertising radio and
    /// stream the list instead of connecting to the first match.
    private var discoveryMode = false
    private var discoveryRequested = false
    private var discovered: [UUID: DiscoveredEntry] = [:]
    private var discoveryContinuations: [UUID: AsyncStream<[DiscoveredRadio]>.Continuation] = [:]
    private var discoveryPruneGeneration = UUID()
    private var autoConnectRequested = false
    private var autoConnectAttempt = UUID()
    private var automaticConnectionInProgress = false
    private var intentionalDisconnect = false
    private let reassembler = MobileGattReassembler()
    private let companionSession = MobileCompanionSession()
    private var pendingWrites: [PendingGattWrite] = []
    private var writeInProgress = false
    private var currentWriteRawTransactionID: UInt8?
    private var syncAttempt = UUID()
    private var selectedHostKey: Data?
    private var preservesFailureOnDisconnect = false
    private var refreshInProgress = false
    private var refreshWaiters: [CheckedContinuation<RadioSnapshot, any Error>] = []
    private var configurationWaiter: CheckedContinuation<Void, any Error>?
    private var meshSession: MobileMeshSession?
    private var pingWaiters: [UInt64: CheckedContinuation<RadioPingResult, any Error>] = [:]
    private var meshPumpGeneration = UUID()
    private var meshPumpScheduled = false
    private var pendingRawFrames: [PendingRawFrame] = []
    private var rawTransmitsInFlight: [UInt8: PendingRawFrame] = [:]
    private var lastYieldedChatBatchID: UInt64?
    private var lastChatBatchYield = DispatchTime.distantFuture
    private var autoEnableAttemptedGeneration: UInt64?

    /// Stable restoration identifier: iOS relaunches the app in the
    /// background for companion events only when a central with this
    /// identifier is recreated promptly at launch.
    private static let restoreIdentifier = "com.umsh.radio.central"
    private static var centralOptions: [String: Any] {
        [CBCentralManagerOptionRestoreIdentifierKey: restoreIdentifier]
    }
    private var restorationPendingResume = false
    /// Peripherals handed back by `willRestoreState`. Retained so a Disconnect
    /// (or the powered-on reconciliation) can revoke a standing connect that
    /// survived a force-quit even before we adopt it as the active peripheral.
    private var restoredPeripherals: [CBPeripheral] = []
    private var framesAwaitingMeshSession: [MobileMeshRxRecord] = []
    private static let maximumFramesAwaitingMeshSession = 32

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        super.init()
        // One-time migration from the pre state-machine single-key scheme. A
        // radio remembered under the old key was, by definition, one the app
        // kept auto-reconnecting to, so carry that forward as autoConnect=true.
        if defaults.string(forKey: PreferenceKey.connectedUUID) == nil,
           let legacy = defaults.string(forKey: PreferenceKey.lastAttachedPeripheral) {
            defaults.set(legacy, forKey: PreferenceKey.connectedUUID)
            defaults.set(true, forKey: PreferenceKey.shouldAutoConnect)
            defaults.removeObject(forKey: PreferenceKey.lastAttachedPeripheral)
        }
        snapshot.localIdentifier = rememberedPeripheralIdentifier
        Self.logger.notice(
            """
            launch autoConnect=\(self.shouldAutoConnect) \
            bound=\(self.rememberedPeripheralIdentifier?.uuidString ?? "nil", privacy: .public)
            """
        )
        // Recreate the central immediately when a companion radio is saved:
        // a background relaunch delivers `willRestoreState` (and the event
        // that caused it) only after this object exists. Gated on a saved
        // radio so a first launch does not prompt for Bluetooth permission
        // before onboarding reaches the radio step.
        if rememberedPeripheralIdentifier != nil {
            bluetoothQueue.async { [self] in
                if central == nil {
                    central = CBCentralManager(
                        delegate: self,
                        queue: bluetoothQueue,
                        options: Self.centralOptions
                    )
                }
            }
        }
    }

    // All streams use bounded buffering. A slow consumer must never turn a
    // periodic producer into unbounded memory growth (the default AsyncStream
    // policy buffers everything ever yielded until read).

    func snapshots() async -> AsyncStream<RadioSnapshot> {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                let initial = snapshot
                // Snapshots are absolute state: only the newest matters.
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
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
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { continuation in
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

    func chatUpdates() async -> AsyncStream<RadioChatUpdate> {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                // The Rust facade replays an unacknowledged batch on every
                // poll, so a dropped element is always re-delivered; only the
                // newest pending batch needs to sit in the buffer.
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
                    let id = UUID()
                    chatContinuations[id] = continuation
                    continuation.onTermination = { [weak self] _ in
                        self?.bluetoothQueue.async { [weak self] in
                            self?.chatContinuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    func advertisementEvents() async -> AsyncStream<RadioAdvertisementEvent> {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                // Advertisements are sparse; a small bounded buffer rides out
                // a briefly busy consumer without unbounded growth.
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(16)) { continuation in
                    let id = UUID()
                    advertisementContinuations[id] = continuation
                    continuation.onTermination = { [weak self] _ in
                        self?.bluetoothQueue.async { [weak self] in
                            self?.advertisementContinuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    func advertiseIdentity(name: String?) async throws {
        let session = try await currentMeshSession()
        try await session.advertiseIdentity(
            name: name,
            timestamp: UInt32(clamping: Int(Date.now.timeIntervalSince1970))
        )
    }

    func signIdentityBundle(name: String?) async throws -> Data {
        let session = try await currentMeshSession()
        return try await session.signIdentityBundle(
            name: name,
            timestamp: UInt32(clamping: Int(Date.now.timeIntervalSince1970))
        )
    }

    func connect() async throws {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                Self.logger.notice("action: user pressed Connect (scan for first match)")
                connectOnQueue()
                result.resume()
            }
        }
    }

    private func connectOnQueue() {
        intentionalDisconnect = false
        autoConnectRequested = false
        autoConnectAttempt = UUID()
        automaticConnectionInProgress = false
        scanExcludesRememberedRadio = rememberedPeripheralIdentifier != nil
        scanRequested = true
        if central == nil {
            publish(state: .scanning)
            central = CBCentralManager(
                delegate: self,
                queue: bluetoothQueue,
                options: Self.centralOptions
            )
            return
        }
        guard central?.state == .poweredOn else {
            publishBluetoothState()
            return
        }
        startScanning()
    }

    func discoverRadios() async -> AsyncStream<[DiscoveredRadio]> {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
                    let id = UUID()
                    discoveryContinuations[id] = continuation
                    continuation.yield(currentDiscoveryList())
                    continuation.onTermination = { [weak self] _ in
                        self?.bluetoothQueue.async { [weak self] in
                            self?.discoveryContinuations[id] = nil
                        }
                    }
                }
                Self.logger.notice("action: user opened radio discovery")
                startDiscoveryOnQueue()
                result.resume(returning: stream)
            }
        }
    }

    func selectRadio(_ id: UUID) async throws {
        try await withCheckedThrowingContinuation {
            (result: CheckedContinuation<Void, any Error>) in
            bluetoothQueue.async { [self] in
                Self.logger.notice(
                    "action: user selected radio \(id, privacy: .public)"
                )
                selectRadioOnQueue(id, completion: result)
            }
        }
    }

    func stopDiscovery() async {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                stopDiscoveryOnQueue()
                result.resume()
            }
        }
    }

    private func startDiscoveryOnQueue() {
        discoveryRequested = true
        // A fresh discovery session always starts from an empty list so a
        // powered-off radio from a previous session does not linger.
        discovered.removeAll()
        yieldDiscoveryList()
        if central == nil {
            central = CBCentralManager(
                delegate: self,
                queue: bluetoothQueue,
                options: Self.centralOptions
            )
            return
        }
        guard central?.state == .poweredOn else {
            // Bluetooth availability is reported through the shared radio
            // snapshot; the discovery list simply stays empty until powered on.
            publishBluetoothState()
            return
        }
        beginDiscoveryScan()
    }

    private func beginDiscoveryScan() {
        guard central?.state == .poweredOn else { return }
        discoveryRequested = false
        discoveryMode = true
        // Cancel a normal "connect to first match" scan; discovery now owns
        // the central. A standing wait-for-radio connection request is left
        // armed — it does not interfere with scanning.
        scanRequested = false
        // Duplicates are allowed so RSSI updates keep the list live and a radio
        // that momentarily drops out reappears rather than going stale.
        central?.scanForPeripherals(
            withServices: [UUIDs.service],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: true]
        )
        discoveryPruneGeneration = UUID()
        scheduleDiscoveryPrune(generation: discoveryPruneGeneration)
    }

    private func selectRadioOnQueue(
        _ id: UUID,
        completion: CheckedContinuation<Void, any Error>
    ) {
        guard let central, central.state == .poweredOn else {
            completion.resume(throwing: RadioConnectionError.bluetoothUnavailable)
            return
        }
        let target = discovered[id]?.peripheral
            ?? central.retrievePeripherals(withIdentifiers: [id]).first
        guard let target else {
            completion.resume(throwing: RadioConnectionError.companionNotFound)
            return
        }
        // Leave discovery and drive the normal attach path for this radio.
        endDiscovery()
        central.stopScan()

        intentionalDisconnect = false
        autoConnectRequested = false
        autoConnectAttempt = UUID()
        automaticConnectionInProgress = false
        scanRequested = false
        scanExcludesRememberedRadio = false

        // "Find another radio": unregister the previously bound radio from
        // bluetoothd (its live peripheral and any standing connect) so it stops
        // competing for the slot, then bind to the newly chosen one.
        let previousID = rememberedPeripheralIdentifier
        if let existing = peripheral,
           existing.identifier != target.identifier,
           existing.state != .disconnected {
            central.cancelPeripheralConnection(existing)
        }
        if let previousID, previousID != target.identifier {
            for stale in central.retrievePeripherals(withIdentifiers: [previousID]) {
                central.cancelPeripheralConnection(stale)
            }
        }
        clearPeripheral()
        peripheral = target
        target.delegate = self
        // Bind immediately: the user chose this radio, so it is now the
        // auto-reconnect target and a standing connect is being issued for it.
        rememberConnected(target.identifier)
        publish(state: .connecting, name: target.name, localIdentifier: target.identifier)
        issueConnect(target, on: central, reason: "selectRadio")
        completion.resume()
    }

    private func stopDiscoveryOnQueue() {
        guard discoveryMode || discoveryRequested else { return }
        let wasScanning = discoveryMode
        endDiscovery()
        // Only stop the scan if discovery actually started one; a request that
        // never reached poweredOn owns no scan.
        if wasScanning {
            central?.stopScan()
        }
    }

    /// Clear discovery state and publish the now-empty list. Does not touch the
    /// central's scan; callers decide whether they still need it.
    private func endDiscovery() {
        discoveryMode = false
        discoveryRequested = false
        discoveryPruneGeneration = UUID()
        discovered.removeAll()
        yieldDiscoveryList()
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
                lastSeen: DispatchTime.now()
            )
        entry.peripheral = peripheral
        if let advertisedName { entry.name = advertisedName }
        else if entry.name == nil { entry.name = peripheral.name }
        // Keep the last usable RSSI when a report carries the 127 sentinel.
        if rssi.intValue != 127 { entry.rssiDBm = rssi.intValue }
        entry.lastSeen = DispatchTime.now()
        discovered[peripheral.identifier] = entry
        yieldDiscoveryList()
    }

    private func currentDiscoveryList() -> [DiscoveredRadio] {
        let remembered = rememberedPeripheralIdentifier
        return discovered.values
            .map { entry in
                DiscoveredRadio(
                    id: entry.peripheral.identifier,
                    name: entry.name,
                    rssiDBm: entry.rssiDBm,
                    isRemembered: entry.peripheral.identifier == remembered
                )
            }
            .sorted { lhs, rhs in
                if lhs.isRemembered != rhs.isRemembered { return lhs.isRemembered }
                if lhs.rssiDBm != rhs.rssiDBm { return lhs.rssiDBm > rhs.rssiDBm }
                return (lhs.name ?? lhs.id.uuidString) < (rhs.name ?? rhs.id.uuidString)
            }
    }

    private func yieldDiscoveryList() {
        let list = currentDiscoveryList()
        for continuation in discoveryContinuations.values {
            continuation.yield(list)
        }
    }

    /// Drop radios not seen recently so a powered-off bench unit disappears
    /// from the list within a few seconds.
    private func scheduleDiscoveryPrune(generation: UUID) {
        bluetoothQueue.asyncAfter(deadline: .now() + 2) { [weak self] in
            guard let self, self.discoveryMode,
                  self.discoveryPruneGeneration == generation else { return }
            let now = DispatchTime.now().uptimeNanoseconds
            let staleNanos: UInt64 = 6 * 1_000_000_000
            let before = self.discovered.count
            self.discovered = self.discovered.filter { _, entry in
                now <= entry.lastSeen.uptimeNanoseconds &+ staleNanos
            }
            if self.discovered.count != before { self.yieldDiscoveryList() }
            self.scheduleDiscoveryPrune(generation: generation)
        }
    }

    func autoConnect() async {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                Self.logger.notice("action: app startup auto-connect")
                // Startup reconnect: honors a prior deliberate Disconnect.
                autoConnectOnQueue(userInitiated: false)
                result.resume()
            }
        }
    }

    func reconnect() async {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                Self.logger.notice("action: user pressed Reconnect")
                // Explicit user Reconnect: re-arms auto-connect intent.
                autoConnectOnQueue(userInitiated: true)
                result.resume()
            }
        }
    }

    private func autoConnectOnQueue(userInitiated: Bool) {
        // A state-restored link may already be connected or attaching by the
        // time app bootstrap requests its usual startup reconnect; starting
        // a fresh connection here would tear that session down.
        if restorationPendingResume { return }
        if let peripheral, peripheral.state == .connected || peripheral.state == .connecting {
            return
        }
        guard rememberedPeripheralIdentifier != nil else {
            if userInitiated {
                publishDisconnected(problem: "No saved companion radio is available to reconnect")
            } else {
                publishDisconnected(problem: nil)
            }
            return
        }
        if userInitiated {
            // Reconnect re-arms the standing connect and its intent flag.
            shouldAutoConnect = true
        } else if !shouldAutoConnect {
            // The user deliberately disconnected in a prior session; a saved
            // radio does not by itself justify reconnecting. Stay off until the
            // user asks. (Forget clears the radio entirely; this is Disconnect.)
            publishDisconnected(problem: nil)
            return
        }
        intentionalDisconnect = false
        autoConnectRequested = true
        if central == nil {
            central = CBCentralManager(
                delegate: self,
                queue: bluetoothQueue,
                options: Self.centralOptions
            )
            return
        }
        guard central?.state == .poweredOn else {
            publishBluetoothState()
            return
        }
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
                let hadKey = selectedHostKey != nil
                selectedHostKey = hostKey
                // A restored or standing-pending link can attach before app
                // bootstrap supplies the phone identity. The companion
                // session then classifies the host with no key and parks at
                // awaitingHost ("Phone identity unavailable") with nothing
                // to re-judge it. Restart synchronization now that the key
                // exists; a genuinely different owner still parks for the
                // user's decision.
                if hostKey != nil, !hadKey,
                   snapshot.linkState == .awaitingHost,
                   let peripheral, peripheral.state == .connected,
                   frameIn != nil {
                    beginSynchronization(on: peripheral)
                }
                result.resume()
            }
        }
    }

    func useMeshSession(_ session: MobileMeshSession?) async {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                meshSession?.clearWakeListener()
                meshSession = session
                meshPumpGeneration = UUID()
                meshPumpScheduled = false
                // Batch IDs restart per session; the delivery gate must not
                // suppress a fresh session's first batches.
                lastYieldedChatBatchID = nil
                lastChatBatchYield = .distantFuture
                // Push, not poll: the Rust worker announces pending updates
                // (outbound frames, ping/advertisement events, chat batches)
                // through this listener, so no polling cadence exists. If
                // data is already pending, the listener fires immediately.
                session?.setWakeListener(listener: MeshSessionWakeListener(connection: self))
                if let session {
                    for record in framesAwaitingMeshSession {
                        try? session.receive(frame: record)
                    }
                }
                framesAwaitingMeshSession.removeAll()
                result.resume()
            }
        }
    }

    /// Called by the Rust worker (on its own thread) whenever `pollUpdate`
    /// has new data. Hop to the Bluetooth queue and drain.
    fileprivate func meshSessionDidAnnounceUpdate() {
        bluetoothQueue.async { [weak self] in
            self?.scheduleMeshPump()
        }
    }

    func claimForCurrentIdentity() async throws {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, any Error>) in
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
            reportOperationFailure("The radio could not replace its configured host", name: peripheral.name)
            throw RadioConnectionError.incompatibleProtocol
        }
    }

    func configure(_ settings: RadioSettings) async throws {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, any Error>) in
            bluetoothQueue.async { [self] in
                guard let peripheral, peripheral.state == .connected else {
                    result.resume(throwing: RadioConnectionError.companionNotFound)
                    return
                }
                guard configurationWaiter == nil, !refreshInProgress else {
                    result.resume(throwing: RadioConnectionError.operationInProgress)
                    return
                }
                configurationWaiter = result
                do {
                    let record = CompanionRadioSettingsRecord(
                        deviceName: settings.deviceName,
                        phyEnabled: settings.phyEnabled,
                        frequencyKhz: settings.frequencyKHz,
                        transmitPowerDbm: settings.transmitPowerDBm,
                        bandwidthHz: settings.bandwidthHz,
                        spreadingFactor: settings.spreadingFactor,
                        codingRateDenom: settings.codingRateDenominator,
                        dutyCycleLimit: settings.dutyCycleLimit
                    )
                    try applySessionUpdate(
                        companionSession.configure(settings: record),
                        from: peripheral
                    )
                } catch {
                    finishConfiguration(throwing: error)
                }
            }
        }
    }

    func factoryReset() async throws {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, any Error>) in
            bluetoothQueue.async { [self] in
                guard let peripheral, peripheral.state == .connected else {
                    result.resume(throwing: RadioConnectionError.companionNotFound)
                    return
                }
                Self.logger.notice("action: user pressed Factory Reset")
                do {
                    try applySessionUpdate(companionSession.factoryReset(), from: peripheral)
                } catch {
                    result.resume(throwing: RadioConnectionError.incompatibleProtocol)
                    return
                }
                // The radio erases all state and reboots, dropping the link
                // itself. Abandon the binding so the app does not auto-reconnect
                // to the now-blank device — but do NOT cancel the connection
                // here: leaving the live link up lets the command's GATT write
                // flush before the radio's own reboot performs the disconnect.
                // (Set after applySessionUpdate, which re-remembers an attached
                // radio; clearing afterward wins.)
                shouldAutoConnect = false
                defaults.removeObject(forKey: PreferenceKey.connectedUUID)
                result.resume()
            }
        }
    }

    func ping(peerAddress: String) async throws -> RadioPingResult {
        try await withCheckedThrowingContinuation {
            (result: CheckedContinuation<RadioPingResult, any Error>) in
            bluetoothQueue.async { [self] in
                guard let meshSession,
                      let peripheral,
                      peripheral.state == .connected,
                      snapshot.linkState == .attached,
                      snapshot.hostState == .matchesCurrentIdentity
                else {
                    result.resume(throwing: RadioConnectionError.companionNotFound)
                    return
                }
                do {
                    let operation = try meshSession.ping(
                        peerAddress: peerAddress,
                        timeoutMs: Self.peerPingTimeoutMilliseconds
                    )
                    pingWaiters[operation] = result
                } catch {
                    result.resume(throwing: error)
                }
            }
        }
    }

    func prepareChat(
        peerAddresses: [String],
        checkpoints: [MobileChatCheckpointRecord]
    ) async throws {
        let session = try await currentMeshSession()
        try await session.registerPeers(peerAddresses: peerAddresses)
        try await session.restoreChat(checkpoints: checkpoints)
    }

    func registerChatPeers(_ peerAddresses: [String]) async throws {
        let session = try await currentMeshSession()
        try await session.registerPeers(peerAddresses: peerAddresses)
    }

    func composeText(
        peerAddress: String,
        clientToken: UInt32,
        body: String
    ) async throws -> MobileChatComposeBatchRecord {
        let session = try await currentMeshSession()
        return try await session.composeText(
            peerAddress: peerAddress,
            clientToken: clientToken,
            body: body
        )
    }

    func composeEdit(
        peerAddress: String,
        clientToken: UInt32,
        original: MobileChatOriginalRef,
        body: String
    ) async throws -> MobileChatComposeBatchRecord {
        let session = try await currentMeshSession()
        return try await session.composeEdit(
            peerAddress: peerAddress,
            clientToken: clientToken,
            original: original,
            body: body
        )
    }

    func composeDelete(
        peerAddress: String,
        clientToken: UInt32,
        original: MobileChatOriginalRef
    ) async throws -> MobileChatComposeBatchRecord {
        let session = try await currentMeshSession()
        return try await session.composeDelete(
            peerAddress: peerAddress,
            clientToken: clientToken,
            original: original
        )
    }

    func commitChatBatch(_ batchID: UInt64) async throws {
        let session = try await currentMeshSession()
        try await session.commitChatBatch(batchId: batchID)
    }

    func rejectChatBatch(
        _ batchID: UInt64,
        checkpoints: [MobileChatCheckpointRecord]
    ) async throws {
        let session = try await currentMeshSession()
        try await session.rejectChatBatch(batchId: batchID, checkpoints: checkpoints)
    }

    func applyChatArchiveResult(
        requestID: UInt32,
        kind: MobileChatArchiveResultKind,
        payload: Data
    ) async throws {
        let session = try await currentMeshSession()
        try session.applyChatArchiveResult(requestId: requestID, kind: kind, payload: payload)
    }

    func acknowledgeChatBatch(_ batchID: UInt64) async throws {
        let session = try await currentMeshSession()
        try session.acknowledgeChatBatch(batchId: batchID)
    }

    func refresh() async throws -> RadioSnapshot {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<RadioSnapshot, any Error>) in
            bluetoothQueue.async { [self] in
                guard let peripheral, peripheral.state == .connected else {
                    result.resume(throwing: RadioConnectionError.companionNotFound)
                    return
                }
                guard configurationWaiter == nil else {
                    result.resume(throwing: RadioConnectionError.operationInProgress)
                    return
                }
                refreshWaiters.append(result)
                guard !refreshInProgress else { return }
                refreshInProgress = true
                do {
                    try applySessionUpdate(companionSession.refresh(), from: peripheral)
                } catch {
                    finishRefresh(throwing: error)
                }
            }
        }
    }

    func disconnect() async {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                Self.logger.notice("action: user pressed Disconnect")
                disconnectOnQueue()
                result.resume()
            }
        }
    }

    func forget() async {
        await withCheckedContinuation { result in
            bluetoothQueue.async { [self] in
                Self.logger.notice("action: user pressed Forget")
                forgetOnQueue()
                result.resume()
            }
        }
    }

    /// Unbind from the radio entirely: revoke every standing/live connection,
    /// clear the intent flag, and drop `connectedUUID`. Unlike Disconnect, the
    /// app no longer remembers a radio and will not offer Reconnect.
    private func forgetOnQueue() {
        intentionalDisconnect = true
        scanRequested = false
        scanExcludesRememberedRadio = false
        scanAttempt = UUID()
        autoConnectRequested = false
        autoConnectAttempt = UUID()
        automaticConnectionInProgress = false
        central?.stopScan()
        shouldAutoConnect = false
        cancelAllServiceConnections()
        restoredPeripherals.removeAll()
        clearPeripheral()
        defaults.removeObject(forKey: PreferenceKey.connectedUUID)
        intentionalDisconnect = false
        publishDisconnected(problem: nil)
    }

    private func disconnectOnQueue() {
        intentionalDisconnect = true
        scanRequested = false
        scanExcludesRememberedRadio = false
        scanAttempt = UUID()
        autoConnectRequested = false
        autoConnectAttempt = UUID()
        automaticConnectionInProgress = false
        central?.stopScan()
        // Durably clear auto-reconnect intent and revoke every standing/live
        // connection for the companion service — including a request for the
        // bound radio resurrected by state restoration, or one with no live
        // peripheral object. A live, connected link is spared here so its
        // `.disconnecting` UI flow runs below. connectedUUID is kept so
        // Reconnect can re-arm.
        shouldAutoConnect = false
        let live = peripheral
        cancelAllServiceConnections(except: live?.state == .connected ? live?.identifier : nil)
        restoredPeripherals.removeAll()
        guard let peripheral = live else {
            intentionalDisconnect = false
            publishDisconnected()
            return
        }
        guard peripheral.state == .connected else {
            // Only an armed (or in-flight) connection request exists.
            // Cancelling it produces no delegate callback, so settle the
            // state here; this is the user's off switch for the standing
            // wait-for-radio request.
            central?.cancelPeripheralConnection(peripheral)
            clearPeripheral()
            intentionalDisconnect = false
            publishDisconnected(problem: nil)
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
            self.scanExcludesRememberedRadio = false
            self.publish(
                RadioSnapshot(
                    linkState: .failed,
                    name: nil,
                    localIdentifier: self.rememberedPeripheralIdentifier,
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
        guard let identifier = rememberedPeripheralIdentifier else {
            clearPeripheral()
            publishDisconnected(problem: "No saved companion radio is available to reconnect")
            return
        }
        clearPeripheral()
        guard let remembered = central.retrievePeripherals(withIdentifiers: [identifier]).first else {
            publishDisconnected(problem: "The saved companion radio is not known to Bluetooth")
            return
        }

        peripheral = remembered
        remembered.delegate = self
        automaticConnectionInProgress = true
        autoConnectAttempt = UUID()
        let attempt = autoConnectAttempt
        publish(
            state: .reconnecting,
            name: remembered.name,
            localIdentifier: remembered.identifier
        )
        issueConnect(remembered, on: central, reason: "startAutomaticConnection")

        bluetoothQueue.asyncAfter(deadline: .now() + 8) { [weak self] in
            guard let self, let remembered = self.peripheral,
                  self.autoConnectAttempt == attempt,
                  self.automaticConnectionInProgress,
                  remembered.state != .connected
            else { return }
            // The bounded window is UI honesty only. Leave the system
            // connection request armed: it never expires, costs nothing
            // while the radio is away, and completes the moment the radio
            // powers on — waking or relaunching the app in the background.
            // Disconnect (or a fresh scan) is what cancels it.
            self.automaticConnectionInProgress = false
            self.publish(
                state: .waitingForRadio,
                name: remembered.name,
                localIdentifier: remembered.identifier
            )
        }
    }

    private func publishBluetoothState() {
        guard let central else { return }
        let message: String
        switch central.state {
        case .poweredOn:
            reconcileStandingConnectionOnPoweredOn()
            if restorationPendingResume {
                resumeRestoredPeripheral()
            } else if discoveryRequested {
                beginDiscoveryScan()
            } else if autoConnectRequested {
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
                localIdentifier: rememberedPeripheralIdentifier,
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

    /// Tear down a companion link only when its framing or session state is
    /// no longer trustworthy. Ordinary CRP status failures and rejected
    /// operations must never come through this path.
    private func terminateConnectionForFatalProtocolError(_ message: String, name: String? = nil) {
        Self.logger.fault("Fatal companion protocol error: \(message, privacy: .public)")
        finishPendingOperations(throwing: RadioConnectionError.incompatibleProtocol)
        pendingWrites.removeAll()
        writeInProgress = false
        currentWriteRawTransactionID = nil
        pendingRawFrames.removeAll()
        rawTransmitsInFlight.removeAll()
        syncAttempt = UUID()
        _ = companionSession.reset()
        snapshot.linkState = .failed
        snapshot.name = name ?? snapshot.name
        snapshot.localIdentifier = rememberedPeripheralIdentifier ?? snapshot.localIdentifier
        snapshot.problemDescription = message
        publish(snapshot)
        if let peripheral, peripheral.state == .connected {
            preservesFailureOnDisconnect = true
            central?.cancelPeripheralConnection(peripheral)
        }
    }

    /// Report a failed operation without disturbing the BLE transport or the
    /// companion session. A connected radio remains connected.
    private func reportOperationFailure(_ message: String, name: String? = nil) {
        Self.logger.error("Companion operation failed: \(message, privacy: .public)")
        snapshot.name = name ?? snapshot.name
        snapshot.problemDescription = message
        publish(snapshot)
    }

    /// The radio the app is bound to (the persisted `connectedUUID`). Used for
    /// display and as the auto-reconnect target. Distinct from
    /// `shouldAutoConnect`: the app can remember a radio it is deliberately
    /// disconnected from.
    private var rememberedPeripheralIdentifier: UUID? {
        defaults.string(forKey: PreferenceKey.connectedUUID)
            .flatMap(UUID.init(uuidString:))
    }

    /// Auto-reconnect intent. Reading and writing this always goes through
    /// UserDefaults so the invariant survives force-quit and background
    /// relaunch.
    private var shouldAutoConnect: Bool {
        get { defaults.bool(forKey: PreferenceKey.shouldAutoConnect) }
        set { defaults.set(newValue, forKey: PreferenceKey.shouldAutoConnect) }
    }

    /// Bind the app to `identifier` and arm auto-reconnect. This is the only
    /// place both persisted fields are set together on a successful attach.
    private func rememberConnected(_ identifier: UUID) {
        defaults.set(identifier.uuidString, forKey: PreferenceKey.connectedUUID)
        shouldAutoConnect = true
    }

    /// Best-effort revocation of every standing/live connection this central
    /// holds for the companion service. CoreBluetooth exposes no single
    /// "cancel all pending connects" call, so this sweeps the sources it does
    /// surface: the bound radio's peripheral, anything currently connected for
    /// our service, and anything handed back by state restoration. Pass `keep`
    /// to spare one peripheral (e.g. a live link being torn down separately so
    /// its `didDisconnect` UI flow still runs).
    private func cancelAllServiceConnections(except keep: UUID? = nil) {
        guard let central, central.state == .poweredOn else { return }
        var targets: [CBPeripheral] = []
        if let peripheral { targets.append(peripheral) }
        if let id = rememberedPeripheralIdentifier {
            targets += central.retrievePeripherals(withIdentifiers: [id])
        }
        targets += central.retrieveConnectedPeripherals(withServices: [UUIDs.service])
        targets += restoredPeripherals
        var seen = Set<UUID>()
        for target in targets
        where target.identifier != keep && seen.insert(target.identifier).inserted {
            // NOTE: cancelPeripheralConnection withdraws only THIS app's
            // interest. A connection owned by another app (or another install
            // of this app) on the same phone survives this call untouched.
            Self.logger.notice(
                """
                revoke standing connect \(target.identifier, privacy: .public) \
                name=\(target.name ?? "?", privacy: .public) \
                state=\(Self.describe(target.state), privacy: .public)
                """
            )
            central.cancelPeripheralConnection(target)
        }
    }

    private static func describe(_ state: CBPeripheralState) -> String {
        switch state {
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .disconnecting: return "disconnecting"
        @unknown default: return "unknown"
        }
    }

    /// Every `central.connect` in this type routes through here so the log
    /// shows exactly what armed a standing connect and why. A standing connect
    /// is what survives force-quit, so this is the ground truth for "why is my
    /// phone reconnecting".
    private func issueConnect(
        _ target: CBPeripheral,
        on central: CBCentralManager,
        reason: String
    ) {
        Self.logger.notice(
            """
            connect(\(target.identifier, privacy: .public)) \
            name=\(target.name ?? "?", privacy: .public) \
            reason=\(reason, privacy: .public) \
            autoConnect=\(self.shouldAutoConnect) bound=\(self.rememberedPeripheralIdentifier?.uuidString ?? "nil", privacy: .public)
            """
        )
        central.connect(target)
    }

    /// Enforce the ShouldAutoConnect invariant the moment the central becomes
    /// usable. This is the reconciliation that makes force-quit irrelevant: the
    /// persisted intent, not whatever bluetoothd resurrected, decides whether a
    /// standing connect exists.
    private func reconcileStandingConnectionOnPoweredOn() {
        let connected = central?.retrieveConnectedPeripherals(withServices: [UUIDs.service]) ?? []
        let connectedSummary = connected
            .map { "\($0.identifier.uuidString)(\($0.name ?? "?"))" }
            .joined(separator: ",")
        let boundName = rememberedPeripheralIdentifier
            .flatMap { central?.retrievePeripherals(withIdentifiers: [$0]).first?.name }
        Self.logger.notice(
            """
            reconcile autoConnect=\(self.shouldAutoConnect) \
            bound=\(self.rememberedPeripheralIdentifier?.uuidString ?? "nil", privacy: .public)\
            (\(boundName ?? "?", privacy: .public)) \
            restored=\(self.restoredPeripherals.count) \
            connectedForService=[\(connectedSummary, privacy: .public)]
            """
        )
        if shouldAutoConnect {
            // Keep only the bound radio's connect; revoke every other
            // standing/live connection this app holds for the service — a
            // restored request, or a stray connect to some other companion
            // radio left over from an earlier session. Note this can only
            // cancel connections THIS app owns; a connection held by another
            // app (or the system's own bonded-device reconnect) is not ours to
            // cancel here.
            cancelAllServiceConnections(except: rememberedPeripheralIdentifier)
            restoredPeripherals.removeAll()
            return
        }
        // Auto-connect is off: revoke everything, including a force-quit
        // resurrected request, so the app stops squatting the radio. Leave
        // connectedUUID intact so Reconnect can re-arm.
        cancelAllServiceConnections()
        restoredPeripherals.removeAll()
        restorationPendingResume = false
        if peripheral != nil, snapshot.linkState != .disconnecting {
            clearPeripheral()
        }
    }

    private func publishDisconnected(name: String? = nil, problem: String? = "Radio disconnected") {
        publish(
            RadioSnapshot(
                linkState: .idle,
                name: name,
                localIdentifier: rememberedPeripheralIdentifier,
                batteryPercentage: nil,
                isExternallyPowered: nil,
                batteryReadAt: nil,
                deviceIdentity: nil,
                hostState: .unknown,
                provisioning: nil,
                problemDescription: problem
            )
        )
    }

    private func beginSynchronization(on peripheral: CBPeripheral) {
        guard let frameIn else {
            terminateConnectionForFatalProtocolError("The radio has no writable companion endpoint", name: peripheral.name)
            return
        }
        guard frameIn.properties.contains(.write) else {
            terminateConnectionForFatalProtocolError("The radio requires an unsupported write mode", name: peripheral.name)
            return
        }

        reassembler.reset()
        pendingWrites.removeAll(keepingCapacity: true)
        writeInProgress = false
        currentWriteRawTransactionID = nil
        do {
            try applySessionUpdate(
                companionSession.begin(selectedHostKey: selectedHostKey),
                from: peripheral
            )
        } catch {
            terminateConnectionForFatalProtocolError("The companion session could not start", name: peripheral.name)
        }
    }

    private func writeNext(on peripheral: CBPeripheral) {
        guard !writeInProgress, !pendingWrites.isEmpty, let frameIn else { return }
        writeInProgress = true
        let write = pendingWrites.removeFirst()
        currentWriteRawTransactionID = write.rawTransactionID
        peripheral.writeValue(write.value, for: frameIn, type: .withResponse)
    }

    private func enqueue(
        frame: Data,
        rawTransactionID: UInt8? = nil,
        on peripheral: CBPeripheral
    ) throws {
        // CoreBluetooth's with-response maximum may advertise the size of an
        // ATT long write. CRP GATT SAR requires ordinary single-write values;
        // the without-response maximum is the negotiated ATT payload bound
        // even though we deliberately send each segment with a response.
        let maximumLength = UInt16(
            min(peripheral.maximumWriteValueLength(for: .withoutResponse), Int(UInt16.max))
        )
        let segments = try UMSHMobileCore.companionGattSegments(
            frame: frame,
            maximumValueLength: maximumLength
        )
        pendingWrites.append(contentsOf: segments.map {
            PendingGattWrite(value: $0.value, rawTransactionID: rawTransactionID)
        })
    }

    private func receive(_ value: Data, from peripheral: CBPeripheral) {
        do {
            guard let frame = try reassembler.push(segment: value) else { return }
            try applySessionUpdate(companionSession.consume(frame: frame), from: peripheral)
        } catch {
            terminateConnectionForFatalProtocolError("The radio sent an invalid companion frame", name: peripheral.name)
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
                supportsDeviceName: $0.supportsDeviceName,
                supportsLoRa: $0.supportsLora,
                supportsDutyCycleLimit: $0.supportsDutyCycleLimit,
                phyEnabled: $0.phyEnabled,
                frequencyKHz: $0.frequencyKhz,
                transmitPowerDBm: $0.transmitPowerDbm,
                bandwidthHz: $0.bandwidthHz,
                spreadingFactor: $0.spreadingFactor,
                codingRateDenominator: $0.codingRateDenom,
                dutyCycleNow: $0.dutyCycleNow,
                dutyCycleLimit: $0.dutyCycleLimit,
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

        let operationErrorMessage = update.operationError.map {
            "\($0.operation) failed: \($0.statusName) (\($0.statusCode))"
        }
        if let operationErrorMessage {
            Self.logger.error("Companion operation rejected: \(operationErrorMessage, privacy: .public)")
            snapshot.problemDescription = operationErrorMessage
        }

        let shouldAutoEnable = update.snapshot.phase == .attached
            && update.snapshot.provisioning?.phyEnabled == false
            && (update.snapshot.hostOwnership == .ours
                || update.snapshot.hostOwnership == .unsupported)
            && !update.waitingForResponses
            && autoEnableAttemptedGeneration != update.snapshot.generation
        if shouldAutoEnable {
            autoEnableAttemptedGeneration = update.snapshot.generation
        }

        var rawTransmitDelay: TimeInterval?
        if let result = update.rawTransmitResult {
            guard var submission = rawTransmitsInFlight.removeValue(
                forKey: result.transactionId
            ) else {
                throw RadioConnectionError.incompatibleProtocol
            }
            switch result.disposition {
            case .sent:
                completeMeshFrame(submission.meshFrameID, transmitted: true)
                rawTransmitDelay = 0
            case .retry:
                submission.busyRetries += 1
                if submission.busyRetries <= Self.maximumRawTransmitBusyRetries {
                    Self.logger.notice(
                        "Companion raw transmit temporarily busy; retry \(submission.busyRetries, privacy: .public)"
                    )
                    pendingRawFrames.insert(submission, at: 0)
                    rawTransmitDelay = 0.1
                } else {
                    completeMeshFrame(submission.meshFrameID, transmitted: false)
                    let message = "Radio remained busy; send was not transmitted"
                    Self.logger.error(
                        "Companion raw transmit rejected: \(result.statusName, privacy: .public) (\(result.statusCode, privacy: .public))"
                    )
                    snapshot.problemDescription = message
                    rawTransmitDelay = 0
                }
            case .rejected:
                completeMeshFrame(submission.meshFrameID, transmitted: false)
                Self.logger.error(
                    "Companion raw transmit rejected: \(result.statusName, privacy: .public) (\(result.statusCode, privacy: .public))"
                )
                snapshot.problemDescription = "Radio rejected the transmission: \(result.statusName)"
                rawTransmitDelay = 0
            }
        }

        for received in update.receivedFrames {
            let record = MobileMeshRxRecord(
                data: received.data,
                rssiDbm: received.rssiDbm,
                lqi: received.lqi,
                snrCb: received.snrCb
            )
            if let meshSession {
                try meshSession.receive(frame: record)
            } else {
                // A restored background link can deliver frames before app
                // bootstrap installs the Rust session. Hold a bounded,
                // newest-wins window for replay; anything dropped is
                // ordinary RF loss to the protocol's repair path.
                framesAwaitingMeshSession.append(record)
                if framesAwaitingMeshSession.count > Self.maximumFramesAwaitingMeshSession {
                    framesAwaitingMeshSession.removeFirst(
                        framesAwaitingMeshSession.count - Self.maximumFramesAwaitingMeshSession
                    )
                }
            }
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
            try enqueue(
                frame: frame,
                rawTransactionID: update.outboundFrames.count == 1
                    ? update.rawTransmitStartedTransactionId
                    : nil,
                on: peripheral
            )
        }
        writeNext(on: peripheral)
        if update.snapshot.phase == .attached {
            // A completed attach is the app's declaration of intent to stay
            // bound to this radio: remember it and arm auto-reconnect.
            rememberConnected(peripheral.identifier)
        }
        publish(snapshot)

        if shouldAutoEnable, let provisioning = update.snapshot.provisioning {
            bluetoothQueue.async { [weak self] in
                self?.enableAttachedPhy(
                    provisioning: provisioning,
                    deviceName: update.snapshot.deviceName,
                    on: peripheral
                )
            }
        }

        if let rawTransmitDelay {
            bluetoothQueue.asyncAfter(deadline: .now() + rawTransmitDelay) { [weak self] in
                guard let self, self.peripheral === peripheral else { return }
                do {
                    try self.startRawTransmits(on: peripheral)
                } catch {
                    self.dropPendingRawFrame(
                        reason: "The companion session rejected an outbound frame before transmission",
                        name: peripheral.name
                    )
                }
            }
        }

        if !update.waitingForResponses, update.snapshot.phase == .attached {
            if refreshInProgress {
                finishRefresh(
                    throwing: operationErrorMessage.map(RadioConnectionError.operationRejected)
                )
            }
            if configurationWaiter != nil {
                finishConfiguration(
                    throwing: operationErrorMessage.map(RadioConnectionError.operationRejected)
                )
            }
        }

        // Raw PHY completion can legitimately take longer than the control
        // plane's synchronization timeout at slow LoRa settings. It has its
        // own ordered queue and must never tear down a healthy BLE session.
        guard update.waitingForResponses, !update.rawTransmitPending else { return }
        let attempt = syncAttempt
        bluetoothQueue.asyncAfter(deadline: .now() + 8) { [weak self] in
            guard let self, let peripheral = self.peripheral, self.syncAttempt == attempt else {
                return
            }
            self.reportOperationFailure(
                "The companion radio did not finish synchronizing",
                name: peripheral.name
            )
        }
    }

    /// Coalesced immediate drain of the Rust session. There is no polling
    /// cadence: pumps are triggered by the session's wake listener, by
    /// inbound BLE data, and by the one-shot chat-batch redelivery timer.
    private func scheduleMeshPump() {
        guard !meshPumpScheduled else { return }
        meshPumpScheduled = true
        let generation = meshPumpGeneration
        bluetoothQueue.async { [weak self] in
            guard let self else { return }
            self.meshPumpScheduled = false
            guard self.meshPumpGeneration == generation else { return }
            self.pumpMeshSession()
        }
    }

    /// One-shot delayed pump so an unacknowledged chat batch is redelivered.
    /// Deliberately bypasses the immediate-pump coalescing flag: a pending
    /// delayed pump must never absorb (and thereby delay) a wake-triggered
    /// immediate pump.
    private func scheduleChatBatchRedelivery() {
        let generation = meshPumpGeneration
        bluetoothQueue.asyncAfter(deadline: .now() + 2.1) { [weak self] in
            guard let self, self.meshPumpGeneration == generation else { return }
            self.pumpMeshSession()
        }
    }

    private func currentMeshSession() async throws -> MobileMeshSession {
        try await withCheckedThrowingContinuation { result in
            bluetoothQueue.async { [self] in
                guard let meshSession else {
                    result.resume(throwing: RadioConnectionError.identityUnavailable)
                    return
                }
                result.resume(returning: meshSession)
            }
        }
    }

    private func pumpMeshSession() {
        guard let meshSession,
              let peripheral,
              peripheral.state == .connected,
              snapshot.linkState == .attached
        else { return }
        do {
            let update = meshSession.pollUpdate()
            pendingRawFrames.append(contentsOf: update.outboundFrames.map {
                PendingRawFrame(data: $0.data, meshFrameID: $0.id)
            })
            try startRawTransmits(on: peripheral)
            for event in update.pingEvents {
                guard let waiter = pingWaiters.removeValue(forKey: event.operationId) else {
                    continue
                }
                switch event.outcome {
                case .reply:
                    waiter.resume(
                        returning: .reply(
                            RadioPingReply(
                                roundTripMilliseconds: event.roundTripMilliseconds ?? 0,
                                hopCount: event.hopCount,
                                routeHints: event.routeHints,
                                rssiDBm: event.rssiDbm,
                                signalToNoiseCentibels: event.snrCentibels,
                                linkQuality: event.lqi
                            )
                        )
                    )
                case .timedOut:
                    waiter.resume(returning: .timedOut)
                case .failed:
                    waiter.resume(throwing: RadioConnectionError.incompatibleProtocol)
                }
            }
            for event in update.advertisementEvents {
                let advertisement = RadioAdvertisementEvent(
                    peerAddress: event.peerAddress,
                    payload: event.payload
                )
                for continuation in advertisementContinuations.values {
                    continuation.yield(advertisement)
                }
            }
            if let chatBatchID = update.chatBatchId,
               (!update.chatMutations.isEmpty
                || !update.chatDeliveries.isEmpty
                || !update.chatArchiveLookups.isEmpty
                || !update.chatDiagnostics.isEmpty)
            {
                // The facade replays a batch until it is acknowledged, and a
                // wake-triggered pump can run several times in quick
                // succession. Deliver a given batch once; if the consumer
                // fails to acknowledge it, the one-shot redelivery pump
                // re-yields it every couple of seconds until it does.
                let now = DispatchTime.now()
                let isRetryDue = lastChatBatchYield < now
                    && now.uptimeNanoseconds - lastChatBatchYield.uptimeNanoseconds
                        > 2_000_000_000
                if chatBatchID != lastYieldedChatBatchID || isRetryDue {
                    lastYieldedChatBatchID = chatBatchID
                    lastChatBatchYield = now
                    let chatUpdate = RadioChatUpdate(
                        batchID: chatBatchID,
                        mutations: update.chatMutations,
                        deliveries: update.chatDeliveries,
                        archiveLookups: update.chatArchiveLookups,
                        diagnostics: update.chatDiagnostics
                    )
                    for continuation in chatContinuations.values {
                        continuation.yield(chatUpdate)
                    }
                    scheduleChatBatchRedelivery()
                }
            }
        } catch {
            for waiter in pingWaiters.values {
                waiter.resume(throwing: RadioConnectionError.incompatibleProtocol)
            }
            pingWaiters.removeAll()
            reportOperationFailure(
                "The Rust mesh session could not use the companion radio: \(error)",
                name: peripheral.name
            )
        }
    }

    /// Fill the companion NCP's target-sized transmit window. The NCP retains
    /// complete frames and serializes the physical LoRa radio; transaction IDs
    /// correlate completions even when a later submission is rejected early.
    private func startRawTransmits(on peripheral: CBPeripheral) throws {
        while rawTransmitsInFlight.count < Self.maximumRawTransmitsInFlight,
              let submission = pendingRawFrames.first
        {
            let update = try companionSession.transmitRaw(data: submission.data)
            guard let transactionID = update.rawTransmitStartedTransactionId,
                  rawTransmitsInFlight[transactionID] == nil
            else {
                throw RadioConnectionError.incompatibleProtocol
            }
            pendingRawFrames.removeFirst()
            rawTransmitsInFlight[transactionID] = submission
            do {
                try applySessionUpdate(update, from: peripheral)
            } catch {
                rawTransmitsInFlight.removeValue(forKey: transactionID)
                pendingRawFrames.insert(submission, at: 0)
                throw error
            }
        }
    }

    /// Drop one unsendable frame and keep the BLE link/session intact. The
    /// Rust delivery ticket will time out as failed; later queued frames may
    /// still proceed.
    private func dropPendingRawFrame(reason: String, name: String?) {
        if !pendingRawFrames.isEmpty {
            let dropped = pendingRawFrames.removeFirst()
            completeMeshFrame(dropped.meshFrameID, transmitted: false)
        }
        reportOperationFailure(reason, name: name)
        guard let peripheral, peripheral.state == .connected else { return }
        do {
            try startRawTransmits(on: peripheral)
        } catch {
            // Continue draining without turning an unsendable frame into a
            // recursive transport failure.
            bluetoothQueue.async { [weak self] in
                self?.dropPendingRawFrame(
                    reason: "The companion session rejected an outbound frame before transmission",
                    name: peripheral.name
                )
            }
        }
    }

    private func completeMeshFrame(_ frameID: UInt64, transmitted: Bool) {
        do {
            try meshSession?.completeOutboundFrame(
                frameId: frameID,
                transmitted: transmitted
            )
        } catch {
            // A stale completion is diagnostic, never a reason to tear down a
            // healthy BLE attachment.
            Self.logger.error(
                "Could not complete mesh frame \(frameID, privacy: .public): \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    /// A companion attachment is intended to provide a usable radio. Preserve
    /// the radio's authoritative profile and enable only the PHY bit after the
    /// initial inspection discovers it disabled.
    private func enableAttachedPhy(
        provisioning: CompanionSyncRecord,
        deviceName: String?,
        on peripheral: CBPeripheral
    ) {
        guard self.peripheral === peripheral,
              peripheral.state == .connected,
              snapshot.linkState == .attached
        else { return }
        let settings = CompanionRadioSettingsRecord(
            deviceName: provisioning.supportsDeviceName ? deviceName : nil,
            phyEnabled: true,
            frequencyKhz: provisioning.frequencyKhz,
            transmitPowerDbm: provisioning.transmitPowerDbm,
            bandwidthHz: provisioning.bandwidthHz,
            spreadingFactor: provisioning.spreadingFactor,
            codingRateDenom: provisioning.codingRateDenom,
            dutyCycleLimit: provisioning.dutyCycleLimit
        )
        do {
            try applySessionUpdate(
                companionSession.configure(settings: settings),
                from: peripheral
            )
        } catch {
            Self.logger.error("Could not automatically enable companion PHY")
            snapshot.problemDescription = "The companion radio could not be enabled automatically"
            publish(snapshot)
        }
    }

    private func publish(_ newSnapshot: RadioSnapshot) {
        snapshot = newSnapshot
        for continuation in continuations.values {
            continuation.yield(newSnapshot)
        }
    }

    private func finishRefresh(throwing error: (any Error)?) {
        refreshInProgress = false
        let waiters = refreshWaiters
        refreshWaiters.removeAll()
        for waiter in waiters {
            if let error {
                waiter.resume(throwing: error)
            } else {
                waiter.resume(returning: snapshot)
            }
        }
    }

    private func finishConfiguration(throwing error: (any Error)?) {
        guard let waiter = configurationWaiter else { return }
        configurationWaiter = nil
        if let error {
            waiter.resume(throwing: error)
        } else {
            waiter.resume()
        }
    }

    private func finishPendingOperations(throwing error: any Error) {
        if refreshInProgress || !refreshWaiters.isEmpty {
            finishRefresh(throwing: error)
        }
        finishConfiguration(throwing: error)
        for waiter in pingWaiters.values {
            waiter.resume(throwing: error)
        }
        pingWaiters.removeAll()
        meshPumpGeneration = UUID()
    }

    private func clearPeripheral() {
        finishPendingOperations(throwing: RadioConnectionError.companionNotFound)
        peripheral?.delegate = nil
        peripheral = nil
        frameIn = nil
        frameOut = nil
        reassembler.reset()
        _ = companionSession.reset()
        pendingWrites.removeAll()
        writeInProgress = false
        currentWriteRawTransactionID = nil
        pendingRawFrames.removeAll()
        rawTransmitsInFlight.removeAll()
        autoEnableAttemptedGeneration = nil
        syncAttempt = UUID()
        preservesFailureOnDisconnect = false
        automaticConnectionInProgress = false
        intentionalDisconnect = false
    }
}

extension CoreBluetoothRadioConnection: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        publishBluetoothState()
    }

    func centralManager(_ central: CBCentralManager, willRestoreState state: [String: Any]) {
        // iOS relaunched (or re-created) us in the background because a
        // companion event arrived. Adopt the restored peripheral now, but
        // defer all CoreBluetooth calls until the central reports poweredOn.
        let restored = state[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral] ?? []
        restoredPeripherals = restored
        Self.logger.notice(
            """
            willRestoreState restored=\(restored.count) \
            ids=\(restored.map { $0.identifier.uuidString }.joined(separator: ","), privacy: .public) \
            autoConnect=\(self.shouldAutoConnect)
            """
        )
        for restoredPeripheral in restored {
            restoredPeripheral.delegate = self
        }
        // If auto-connect is off, iOS resurrected a standing connect the user
        // deliberately abandoned. Adopt nothing; the powered-on reconciliation
        // cancels every restored request so the app stops squatting the radio.
        guard shouldAutoConnect else { return }
        guard let remembered = restored.first(where: {
            $0.identifier == rememberedPeripheralIdentifier
        }) ?? restored.first else { return }
        Self.logger.info(
            "Restoring companion radio session for \(remembered.identifier, privacy: .public)"
        )
        peripheral = remembered
        remembered.delegate = self
        restorationPendingResume = true
        publish(
            state: .reconnecting,
            name: remembered.name,
            localIdentifier: remembered.identifier
        )
    }

    /// Continue a state-restored link once Bluetooth is powered on. Process
    /// memory did not survive, so an already-connected peripheral still
    /// re-runs discovery and companion synchronization from scratch.
    private func resumeRestoredPeripheral() {
        restorationPendingResume = false
        guard let central, let peripheral else { return }
        switch peripheral.state {
        case .connected:
            publish(
                state: .attaching,
                name: peripheral.name,
                localIdentifier: peripheral.identifier
            )
            peripheral.discoverServices([UUIDs.service])
        case .connecting:
            // The system kept the pending connect alive; didConnect will
            // continue the normal attach path.
            break
        default:
            automaticConnectionInProgress = true
            autoConnectAttempt = UUID()
            let attempt = autoConnectAttempt
            issueConnect(peripheral, on: central, reason: "resumeRestoredPeripheral")
            bluetoothQueue.asyncAfter(deadline: .now() + 8) { [weak self] in
                guard let self, let remembered = self.peripheral,
                      self.autoConnectAttempt == attempt,
                      self.automaticConnectionInProgress,
                      remembered.state != .connected
                else { return }
                // Same policy as startAutomaticConnection: report honestly,
                // keep the system connection request armed.
                self.automaticConnectionInProgress = false
                self.publish(
                    state: .waitingForRadio,
                    name: remembered.name,
                    localIdentifier: remembered.identifier
                )
            }
        }
    }

    func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        if discoveryMode {
            recordDiscovered(peripheral, advertisementData: advertisementData, rssi: RSSI)
            return
        }
        guard snapshot.linkState == .scanning else { return }
        if scanExcludesRememberedRadio,
           peripheral.identifier == rememberedPeripheralIdentifier {
            return
        }
        scanExcludesRememberedRadio = false
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
        issueConnect(peripheral, on: central, reason: "scanMatch")
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        Self.logger.notice(
            """
            event: didConnect \(peripheral.identifier, privacy: .public) \
            name=\(peripheral.name ?? "?", privacy: .public) \
            adopted=\(self.peripheral === peripheral)
            """
        )
        guard self.peripheral === peripheral else { return }
        automaticConnectionInProgress = false
        intentionalDisconnect = false
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
        Self.logger.notice(
            """
            event: didFailToConnect \(peripheral.identifier, privacy: .public) \
            name=\(peripheral.name ?? "?", privacy: .public) \
            error=\(error?.localizedDescription ?? "none", privacy: .public)
            """
        )
        guard self.peripheral === peripheral else { return }
        if shouldAutoConnect,
           automaticConnectionInProgress || snapshot.linkState == .waitingForRadio {
            // A transient failure of the standing connection request; iOS
            // does not retry a failed request on its own, so re-arm it and
            // keep waiting for the radio.
            automaticConnectionInProgress = false
            issueConnect(peripheral, on: central, reason: "didFailToConnect re-arm")
            publish(
                state: .waitingForRadio,
                name: peripheral.name,
                localIdentifier: peripheral.identifier
            )
            return
        }
        terminateConnectionForFatalProtocolError(
            error?.localizedDescription ?? "The companion radio connection failed",
            name: peripheral.name
        )
        clearPeripheral()
    }

    func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        error: (any Error)?
    ) {
        Self.logger.notice(
            """
            event: didDisconnect \(peripheral.identifier, privacy: .public) \
            name=\(peripheral.name ?? "?", privacy: .public) \
            error=\(error?.localizedDescription ?? "none", privacy: .public)
            """
        )
        guard self.peripheral === peripheral else { return }
        if preservesFailureOnDisconnect {
            preservesFailureOnDisconnect = false
            clearPeripheral()
            return
        }
        if intentionalDisconnect || !shouldAutoConnect {
            clearPeripheral()
            publishDisconnected(name: peripheral.name, problem: nil)
            return
        }
        // A remote or link-loss disconnect is provisional. Keep the UI in a
        // reconnecting state while CoreBluetooth targets only the remembered
        // peripheral; report disconnected only after that bounded attempt.
        autoConnectRequested = true
        startAutomaticConnection()
    }
}

extension CoreBluetoothRadioConnection: CBPeripheralDelegate {
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: (any Error)?) {
        if let error {
            terminateConnectionForFatalProtocolError(error.localizedDescription, name: peripheral.name)
            return
        }
        guard let service = peripheral.services?.first(where: { $0.uuid == UUIDs.service }) else {
            terminateConnectionForFatalProtocolError("The radio does not expose the companion service", name: peripheral.name)
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
            terminateConnectionForFatalProtocolError(error.localizedDescription, name: peripheral.name)
            return
        }
        frameIn = service.characteristics?.first(where: { $0.uuid == UUIDs.frameIn })
        frameOut = service.characteristics?.first(where: { $0.uuid == UUIDs.frameOut })
        guard frameIn != nil, let frameOut else {
            terminateConnectionForFatalProtocolError("The radio has an incompatible companion service", name: peripheral.name)
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
            terminateConnectionForFatalProtocolError(error.localizedDescription, name: peripheral.name)
            return
        }
        guard characteristic.isNotifying else {
            terminateConnectionForFatalProtocolError("The radio refused the companion attachment", name: peripheral.name)
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
        let failedCurrentRawTransactionID = currentWriteRawTransactionID
        currentWriteRawTransactionID = nil
        if let error {
            let failedRawTransactionIDs = Set(
                pendingWrites.compactMap(\.rawTransactionID)
                    + [failedCurrentRawTransactionID].compactMap { $0 }
            )
            pendingWrites.removeAll()
            pendingRawFrames.removeAll()
            for transactionID in failedRawTransactionIDs {
                rawTransmitsInFlight.removeValue(forKey: transactionID)
            }
            _ = companionSession.abandonRawTransmits(
                transactionIds: Data(failedRawTransactionIDs.sorted())
            )
            do {
                try meshSession?.failOutboundTransmissions()
            } catch {
                Self.logger.error(
                    "Could not publish companion write failure to Rust mesh session"
                )
            }
            reportOperationFailure(
                "The companion write was not accepted: \(error.localizedDescription)",
                name: peripheral.name
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
        guard characteristic.uuid == UUIDs.frameOut else { return }
        if let error {
            reportOperationFailure(
                "The companion notification could not be read: \(error.localizedDescription)",
                name: peripheral.name
            )
            return
        }
        guard let value = characteristic.value else {
            terminateConnectionForFatalProtocolError("The radio sent an empty GATT notification", name: peripheral.name)
            return
        }
        receive(value, from: peripheral)
    }
}

/// Bridges the Rust session's pending-update announcement onto the
/// connection's Bluetooth queue. Runs on the Rust worker thread; holds the
/// connection weakly so a retired session cannot keep it alive.
private final class MeshSessionWakeListener: MobileMeshWakeListener, @unchecked Sendable {
    private weak var connection: CoreBluetoothRadioConnection?

    init(connection: CoreBluetoothRadioConnection) {
        self.connection = connection
    }

    func onUpdatePending() {
        connection?.meshSessionDidAnnounceUpdate()
    }
}
