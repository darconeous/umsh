@preconcurrency import CoreBluetooth
import Foundation
import OSLog
import UMSHMobileCore

/// Discovers and attaches the GATT transport for a companion radio.
///
/// The adapter owns ATT/GATT lifecycle, discovery, the bound-radio
/// preferences, and write backpressure. The ULCP session above it lives
/// in `UlcpRadioSession`; ULCP wire encoding, validation, segmentation,
/// and reassembly remain in Rust.
final class CoreBluetoothRadioConnection: UlcpRadioSession, RadioConnection, UlcpFrameLink,
    @unchecked Sendable {

    private struct PendingGattWrite {
        var value: Data
        var rawTransactionID: UInt8?
    }

    private struct DiscoveredEntry {
        var peripheral: CBPeripheral
        var name: String?
        var rssiDBm: Int
        var lastSeen: DispatchTime
        /// When this radio was first heard, as a sequence number. Assigned
        /// once and never revised — see `currentDiscoveryList()`.
        let discoveryOrder: UInt64
    }

    /// Source of `DiscoveredEntry.discoveryOrder`, reset with the list.
    private var nextDiscoveryOrder: UInt64 = 0

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
        /// The name the bound radio last reported over ULCP.
        ///
        /// `CBPeripheral.name` is iOS's cached GAP name, and iOS does not
        /// refresh it when a device is renamed — it keeps serving the name
        /// the radio had when it was first discovered, sometimes until the
        /// pairing is removed. Without this, every screen outside an
        /// attached session shows the old name.
        static let deviceName = "radio.deviceName"
    }

    /// The ULCP service is not this type's private business — administrative
    /// sessions discover the same one. `RadioGatt` owns the identifiers; this
    /// alias keeps the call sites here reading as they always have.
    private typealias UUIDs = RadioGatt

    private var central: CBCentralManager?
    private let bluetoothQueue = DispatchQueue(
        label: "com.umsh.radio.core-bluetooth",
        qos: .userInitiated
    )
    private let defaults: UserDefaults
    private var peripheral: CBPeripheral?
    private var frameIn: CBCharacteristic?
    private var frameOut: CBCharacteristic?
    /// Deferred publish of a Bluetooth-unavailable banner. Non-poweredOn
    /// states are frequently transient at launch / after sleep (especially on
    /// macOS: unknown → resetting → poweredOff → poweredOn), so the banner is
    /// held for a short grace window and cancelled if the stack settles to
    /// poweredOn — otherwise a radio that is actually on flashes a false
    /// "Bluetooth off" to the user.
    private var bluetoothUnavailableGrace: DispatchWorkItem?
    private static let bluetoothUnavailableGraceSeconds: TimeInterval = 1.5
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
    private var pendingWrites: [PendingGattWrite] = []
    private var writeInProgress = false
    private var currentWriteRawTransactionID: UInt8?
    private var preservesFailureOnDisconnect = false

    /// Stable restoration identifier: iOS relaunches the app in the
    /// background for ULCP events only when a central with this
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

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        // The session runs on CoreBluetooth's own queue, so delegate
        // callbacks reach it without a hop and in their original order.
        super.init(sessionQueue: bluetoothQueue)
        adopt(link: self)
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
        nextDiscoveryOrder = 0
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
            completion.resume(throwing: RadioConnectionError.radioNotFound)
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
        publish(state: .connecting, name: displayName(for: target), localIdentifier: target.identifier)
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
        nextDiscoveryOrder = 0
        yieldDiscoveryList()
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
                name: advertisedName ?? displayName(for: peripheral),
                rssiDBm: rssi.intValue,
                lastSeen: DispatchTime.now(),
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
        entry.lastSeen = DispatchTime.now()
        discovered[peripheral.identifier] = entry
        yieldDiscoveryList()
    }

    private func currentDiscoveryList() -> [DiscoveredRadio] {
        let remembered = rememberedPeripheralIdentifier
        // The saved radio stays pinned to the top — it is what most people
        // opening this list are looking for — and everything else sits in the
        // order it was first heard.
        //
        // Arrival order rather than name: RSSI churns with every
        // advertisement, and a name is not stable either, because a radio is
        // first heard with only whatever `CBPeripheral.name` gives us and
        // picks up its advertised name a moment later. Sorting on either moves
        // rows under the user's finger on a busy bench.
        return discovered.values
            .sorted { lhs, rhs in
                let lhsRemembered = lhs.peripheral.identifier == remembered
                let rhsRemembered = rhs.peripheral.identifier == remembered
                if lhsRemembered != rhsRemembered { return lhsRemembered }
                return lhs.discoveryOrder < rhs.discoveryOrder
            }
            .map { entry in
                DiscoveredRadio(
                    id: entry.peripheral.identifier,
                    name: entry.name,
                    rssiDBm: entry.rssiDBm,
                    isRemembered: entry.peripheral.identifier == remembered
                )
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

    /// Whether the published state describes a link that had come up, as
    /// opposed to a scan or a connection attempt that never landed.
    private var hadLiveLink: Bool {
        switch snapshot.linkState {
        case .idle, .unavailable, .scanning, .discovered, .connecting, .reconnecting,
             .waitingForRadio, .failed:
            false
        case .pairing, .attaching, .synchronizing, .awaitingHost, .provisioning,
             .configuring, .attached, .ready, .disconnecting:
            true
        }
    }

    private func disconnectOnQueue() {
        intentionalDisconnect = true
        scanRequested = false
        scanExcludesRememberedRadio = false
        scanAttempt = UUID()
        autoConnectRequested = false
        autoConnectAttempt = UUID()
        automaticConnectionInProgress = false
        // Durably clear auto-reconnect intent and revoke every standing/live
        // connection for the ULCP service — including a request for the
        // bound radio resurrected by state restoration, or one with no live
        // peripheral object. A live, connected link is spared here so its
        // `.disconnecting` UI flow runs below. connectedUUID is kept so
        // Reconnect can re-arm.
        shouldAutoConnect = false
        let live = peripheral
        let managerIsPoweredOn = central?.state == .poweredOn

        // State restoration can hand us a peripheral before the central's
        // mandatory initial state callback. CoreBluetooth rejects every scan
        // and connection command until that callback reports poweredOn. Make
        // Disconnect responsive now, but retain the restored peripherals so
        // `reconcileStandingConnectionOnPoweredOn` can revoke the daemon's
        // standing connect as soon as commands are legal.
        guard managerIsPoweredOn else {
            restorationPendingResume = false
            clearPeripheral()
            publishDisconnected(problem: nil)
            return
        }

        central?.stopScan()
        cancelAllServiceConnections(except: live?.state == .connected ? live?.identifier : nil)
        restoredPeripherals.removeAll()
        guard let peripheral = live else {
            intentionalDisconnect = false
            // Abandoning a scan or a standing request tears nothing down, so
            // it reports no problem; only a link that had come up says it
            // dropped.
            publishDisconnected(problem: hadLiveLink ? "Radio disconnected" : nil)
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
        publish(state: .disconnecting, name: displayName(for: peripheral))
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
                    batteryVoltageMillivolts: nil,
                    chargeState: nil,
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
            name: displayName(for: remembered),
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
                name: displayName(for: remembered),
                localIdentifier: remembered.identifier
            )
        }
    }

    private func publishBluetoothState() {
        guard let central else { return }

        // A fresh state supersedes any banner we were about to show.
        bluetoothUnavailableGrace?.cancel()
        bluetoothUnavailableGrace = nil

        if central.state == .poweredOn {
            reconcileStandingConnectionOnPoweredOn()
            if restorationPendingResume {
                resumeRestoredPeripheral()
            } else if discoveryRequested {
                beginDiscoveryScan()
            } else if autoConnectRequested {
                startAutomaticConnection()
            } else if scanRequested {
                startScanning()
            } else if snapshot.linkState == .unavailable {
                // Bluetooth is on, but a transient off/starting state left an
                // unavailable banner up and nothing else is going to publish a
                // fresh snapshot. Clear it so the UI stops claiming Bluetooth
                // is disabled when it is not.
                publishDisconnected(problem: nil)
            }
            return
        }

        let message: String
        switch central.state {
        case .unauthorized: message = "Bluetooth permission is denied"
        case .unsupported: message = "Bluetooth is unavailable on this device"
        case .poweredOff: message = "Bluetooth is turned off"
        case .resetting: message = "Bluetooth is restarting"
        case .unknown: message = "Bluetooth is starting"
        case .poweredOn: return // handled above
        @unknown default: message = "Bluetooth is unavailable"
        }

        // Defer the banner: if the stack settles to poweredOn within the grace
        // window the work item is cancelled and no false alarm is shown. A
        // genuinely unavailable radio stays in this state and the banner
        // appears once the window elapses.
        let work = DispatchWorkItem { [weak self] in
            guard let self, let central = self.central,
                  central.state != .poweredOn else { return }
            self.publishBluetoothUnavailable(message)
        }
        bluetoothUnavailableGrace = work
        bluetoothQueue.asyncAfter(
            deadline: .now() + Self.bluetoothUnavailableGraceSeconds,
            execute: work
        )
    }

    private func publishBluetoothUnavailable(_ message: String) {
        publish(
            RadioSnapshot(
                linkState: .unavailable,
                name: nil,
                localIdentifier: rememberedPeripheralIdentifier,
                batteryPercentage: nil,
                batteryVoltageMillivolts: nil,
                chargeState: nil,
                batteryReadAt: nil,
                deviceIdentity: nil,
                hostState: .unknown,
                provisioning: nil,
                problemDescription: message
            )
        )
    }

    private var rememberedPeripheralIdentifier: UUID? {
        defaults.string(forKey: PreferenceKey.connectedUUID)
            .flatMap(UUID.init(uuidString:))
    }

    /// The name the bound radio reported over ULCP the last time it was
    /// attached. Persisted so a rename survives a relaunch instead of
    /// reverting to Bluetooth's cached name until the next attach.
    private var rememberedDeviceName: String? {
        get { defaults.string(forKey: PreferenceKey.deviceName) }
        set {
            if let newValue {
                defaults.set(newValue, forKey: PreferenceKey.deviceName)
            } else {
                defaults.removeObject(forKey: PreferenceKey.deviceName)
            }
        }
    }

    /// The name to show for `peripheral`.
    ///
    /// The device's own ULCP-reported name is authoritative and
    /// `CBPeripheral.name` is a cache that does not track renames, so the
    /// remembered name wins for the bound radio. Any other peripheral —
    /// one being discovered, one never attached — has only the cache.
    private func displayName(for peripheral: CBPeripheral?) -> String? {
        guard let peripheral else { return rememberedDeviceName }
        guard peripheral.identifier == rememberedPeripheralIdentifier else {
            return peripheral.name
        }
        return rememberedDeviceName ?? peripheral.name
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
        // A different radio has a different name; keeping the old one would
        // label the new radio until its first attach reports otherwise.
        if rememberedPeripheralIdentifier != identifier {
            rememberedDeviceName = nil
        }
        defaults.set(identifier.uuidString, forKey: PreferenceKey.connectedUUID)
        shouldAutoConnect = true
    }

    /// Best-effort revocation of every standing/live connection this central
    /// holds for the ULCP service. CoreBluetooth exposes no single
    /// "cancel all pending connects" call, so this sweeps the sources it does
    /// surface: the bound radio's peripheral, anything currently connected for
    /// our service, and anything handed back by state restoration. Pass `keep`
    /// to spare one peripheral (e.g. a live link being torn down separately so
    /// its `didDisconnect` UI flow still runs).
    ///
    /// Peripherals held by an administrative session are always spared.
    /// `retrieveConnectedPeripherals(withServices:)` returns every device on
    /// the phone advertising the ULCP service — including one a concurrent
    /// commissioning session is in the middle of configuring, which this
    /// sweep has no business touching.
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
        where target.identifier != keep
            && !AdminSessionRegistry.shared.contains(target.identifier)
            && seen.insert(target.identifier).inserted {
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

    private func writeNext() {
        guard !writeInProgress, !pendingWrites.isEmpty,
              let peripheral, let frameIn else { return }
        writeInProgress = true
        let write = pendingWrites.removeFirst()
        currentWriteRawTransactionID = write.rawTransactionID
        peripheral.writeValue(write.value, for: frameIn, type: .withResponse)
    }

    // ------------------------------------------------------------------
    // UlcpFrameLink
    // ------------------------------------------------------------------

    var linkIsReady: Bool {
        peripheral?.state == .connected && frameIn != nil
    }

    var linkID: UUID? { rememberedPeripheralIdentifier }

    var linkName: String? { displayName(for: peripheral) }

    var linkIsBoundRadio: Bool {
        peripheral != nil && peripheral?.identifier == rememberedPeripheralIdentifier
    }

    /// Segment the frame and queue every ATT value, then start the queue
    /// if it was idle. GATT writes are strictly one at a time: the next
    /// value goes out from `didWriteValueFor`.
    func linkSend(frame: Data, rawTransactionID: UInt8?) {
        guard let peripheral else { return }
        // CoreBluetooth's with-response maximum may advertise the size of an
        // ATT long write. ULCP GATT SAR requires ordinary single-write values;
        // the without-response maximum is the negotiated ATT payload bound
        // even though we deliberately send each segment with a response.
        let maximumLength = UInt16(
            min(peripheral.maximumWriteValueLength(for: .withoutResponse), Int(UInt16.max))
        )
        do {
            let segments = try UMSHMobileCore.ulcpGattSegments(
                frame: frame,
                maximumValueLength: maximumLength
            )
            pendingWrites.append(contentsOf: segments.map {
                PendingGattWrite(value: $0.value, rawTransactionID: rawTransactionID)
            })
        } catch {
            terminateConnectionForFatalProtocolError(
                "The ULCP session produced an unsendable frame",
                name: displayName(for: peripheral)
            )
            return
        }
        writeNext()
    }

    func linkResetFraming() {
        reassembler.reset()
        pendingWrites.removeAll(keepingCapacity: true)
        writeInProgress = false
        currentWriteRawTransactionID = nil
    }

    func linkInvalidate() {
        pendingWrites.removeAll()
        writeInProgress = false
        currentWriteRawTransactionID = nil
        // Preserve the failure the session just published: the ordinary
        // disconnect path would overwrite it with "Radio disconnected".
        if let peripheral, peripheral.state == .connected {
            preservesFailureOnDisconnect = true
            central?.cancelPeripheralConnection(peripheral)
        }
    }

    func linkDidAttach() {
        guard let peripheral else { return }
        rememberConnected(peripheral.identifier)
    }

    func linkDidReportName(_ name: String) {
        guard name != rememberedDeviceName else { return }
        rememberedDeviceName = name
    }

    func linkAbandonBinding() {
        shouldAutoConnect = false
        defaults.removeObject(forKey: PreferenceKey.connectedUUID)
    }

    private func clearPeripheral() {
        sessionDidLoseLink()
        peripheral?.delegate = nil
        peripheral = nil
        frameIn = nil
        frameOut = nil
        linkResetFraming()
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
        // ULCP event arrived. Adopt the restored peripheral now, but
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
            name: displayName(for: remembered),
            localIdentifier: remembered.identifier
        )
    }

    /// Continue a state-restored link once Bluetooth is powered on. Process
    /// memory did not survive, so an already-connected peripheral still
    /// re-runs discovery and ULCP synchronization from scratch.
    private func resumeRestoredPeripheral() {
        restorationPendingResume = false
        guard let central, let peripheral else { return }
        switch peripheral.state {
        case .connected:
            publish(
                state: .attaching,
                name: displayName(for: peripheral),
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
                    name: displayName(for: remembered),
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
            name: advertisedName ?? displayName(for: peripheral),
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
            name: displayName(for: peripheral),
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
                name: displayName(for: peripheral),
                localIdentifier: peripheral.identifier
            )
            return
        }
        terminateConnectionForFatalProtocolError(
            error.map(BluetoothErrorText.describe) ?? "The companion radio connection failed",
            name: displayName(for: peripheral)
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
            publishDisconnected(name: displayName(for: peripheral), problem: nil)
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
    /// The radio told us its attribute database changed.
    ///
    /// iOS delivers this after a Service Changed indication and has already
    /// invalidated the affected `CBService`, which takes every
    /// `CBCharacteristic` we hold with it. Continuing against those stale
    /// references addresses attributes by handles that have moved — writes
    /// land on whatever now occupies them. The only correct response is to
    /// drop everything cached about the link and discover it again, which
    /// re-enters the ordinary attach path.
    ///
    /// A radio renamed while connected, or updated to firmware with a
    /// different set of services, arrives here.
    func peripheral(
        _ peripheral: CBPeripheral,
        didModifyServices invalidatedServices: [CBService]
    ) {
        guard invalidatedServices.contains(where: { $0.uuid == UUIDs.service }) else { return }
        Self.logger.notice(
            "event: didModifyServices — rediscovering \(peripheral.identifier, privacy: .public)"
        )
        frameIn = nil
        frameOut = nil
        pendingWrites.removeAll()
        writeInProgress = false
        currentWriteRawTransactionID = nil
        // Anything queued or already handed to the radio for transmission is
        // lost with the old handles.
        abandonOutstandingMeshFrames()
        // `beginSynchronization` restarts the ULCP session once the new
        // characteristics are in hand.
        publish(
            state: .attaching,
            name: displayName(for: peripheral),
            localIdentifier: peripheral.identifier
        )
        peripheral.discoverServices([UUIDs.service])
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: (any Error)?) {
        if let error {
            terminateConnectionForFatalProtocolError(BluetoothErrorText.describe(error), name: displayName(for: peripheral))
            return
        }
        guard let service = peripheral.services?.first(where: { $0.uuid == UUIDs.service }) else {
            terminateConnectionForFatalProtocolError("The radio does not expose the ULCP service", name: displayName(for: peripheral))
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
            terminateConnectionForFatalProtocolError(BluetoothErrorText.describe(error), name: displayName(for: peripheral))
            return
        }
        frameIn = service.characteristics?.first(where: { $0.uuid == UUIDs.frameIn })
        frameOut = service.characteristics?.first(where: { $0.uuid == UUIDs.frameOut })
        guard frameIn != nil, let frameOut else {
            terminateConnectionForFatalProtocolError("The radio has an incompatible ULCP service", name: displayName(for: peripheral))
            return
        }
        publish(
            state: .pairing,
            name: displayName(for: peripheral),
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
            terminateConnectionForFatalProtocolError(BluetoothErrorText.describe(error), name: displayName(for: peripheral))
            return
        }
        guard characteristic.isNotifying else {
            terminateConnectionForFatalProtocolError("The radio refused the ULCP attachment", name: displayName(for: peripheral))
            return
        }
        // The session is about to write, so the endpoint it will write
        // to has to be usable before the handshake starts.
        guard let frameIn else {
            terminateConnectionForFatalProtocolError("The radio has no writable ULCP endpoint", name: displayName(for: peripheral))
            return
        }
        guard frameIn.properties.contains(.write) else {
            terminateConnectionForFatalProtocolError("The radio requires an unsupported write mode", name: displayName(for: peripheral))
            return
        }
        linkDidBecomeReady()
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
            linkWritesFailed(
                rawTransactionIDs: failedRawTransactionIDs,
                message: BluetoothErrorText.describe(error)
            )
            return
        }
        writeNext()
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: (any Error)?
    ) {
        guard characteristic.uuid == UUIDs.frameOut else { return }
        if let error {
            reportOperationFailure(
                "\(BluetoothErrorText.describe(error))",
                name: displayName(for: peripheral)
            )
            return
        }
        guard let value = characteristic.value else {
            terminateConnectionForFatalProtocolError("The radio sent an empty GATT notification", name: displayName(for: peripheral))
            return
        }
        do {
            guard let frame = try reassembler.push(segment: value) else { return }
            linkDidReceive(frame: frame)
        } catch {
            terminateConnectionForFatalProtocolError("The radio sent an invalid ULCP frame", name: displayName(for: peripheral))
        }
    }
}

