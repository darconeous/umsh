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
struct AdministeredDeviceSnapshot: Equatable, Sendable {
    var linkState: RadioLinkState
    var identifier: UUID?
    var name: String?
    var deviceIdentity: MeshPublicIdentity?
    /// Whose device this is. Purely informational here: an administrative
    /// session never claims, so this drives a banner, not a decision.
    var hostState: RadioHostState
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
        batteryPercentage: nil,
        batteryVoltageMillivolts: nil,
        chargeState: nil,
        alert: nil,
        clock: nil,
        position: nil,
        problemDescription: nil
    )
}

extension AdministeredDeviceSnapshot {
    /// The device as the driver publishes it.
    init(_ state: MobileRadioStateRecord) {
        let identity = state.deviceKey.flatMap {
            try? UMSHMobileCore.inspectPublicIdentityBytes(publicKey: $0)
        }
        // This snapshot carries no reading time, so it shows only a reading
        // from the session in hand.
        let liveBattery = state.batteryCached ? nil : state.battery
        self.init(
            linkState: RadioLinkState(state.phase),
            identifier: state.linkId.flatMap(UUID.init(uuidString:)),
            name: state.name,
            deviceIdentity: identity.map {
                MeshPublicIdentity(
                    canonicalAddress: $0.canonicalAddress,
                    hint: MeshNodeHint(bytes: $0.hint.bytes, text: $0.hint.text)
                )
            },
            hostState: RadioHostState(state.host),
            batteryPercentage: liveBattery?.percentage.map(Int.init),
            batteryVoltageMillivolts: liveBattery?.voltageMv.map(Int.init),
            chargeState: liveBattery?.chargeState.map(RadioChargeState.init),
            alert: state.alert.map(RadioAlertState.init),
            clock: state.clock.map {
                RadioClock(
                    date: $0.epochSeconds.map { Date(timeIntervalSince1970: TimeInterval($0)) },
                    readAt: Date(unixMilliseconds: $0.readAtMs)
                )
            },
            position: state.position.map(RadioPosition.init),
            problemDescription: state.problem?.text
        )
    }
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
/// - It never claims. Each connect runs an administrative
///   `MobileRadioDriver`, whose session refuses `claim` outright and which
///   never turns the transmitter on, so a phone commissioning ten repeaters
///   leaves each as it found it.
///
/// A dropped link is therefore terminal, not provisional: the driver of an
/// administrative session has no reconnects to offer, so a fault shows as a
/// failure and the user retries. That is the whole recovery model.
///
/// The driver runs the ULCP session and owns the device's state; this class
/// owns discovery, the GATT attach, segmenting and write pacing, and the
/// accessory permission.
final class AdministrativeDeviceSession: NSObject, @unchecked Sendable {
    private static let logger = Logger(subsystem: "com.voria.umsh.ios", category: "AdminDevice")

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
        label: "com.voria.umsh.radio.administrative",
        qos: .userInitiated
    )
    // No CBCentralManagerOptionRestoreIdentifierKey: see the type comment.
    private var central: CBCentralManager?
    private var accessoryInventory = RadioAccessoryInventory()
    private var accessoryTask: Task<Void, Never>?
    private var bluetoothWaiters: [UUID: CheckedContinuation<Void, any Error>] = [:]
    private var selectionGeneration = UUID()
    private var lastCachedConfiguredName: String?
    private var peripheral: CBPeripheral?
    /// What to call the device in transport reports: its advertised name
    /// until it reports its own.
    private var deviceName: String?
    private var frameIn: CBCharacteristic?
    private var frameOut: CBCharacteristic?

    private let reassembler = MobileGattReassembler()
    /// The driver for the device being administered, made per connect in
    /// the inspection mode that connect asks for—see
    /// `connect(_:lazyAttach:)`—and stopped when the session lets go.
    private var driver: MobileRadioDriver?
    private var linkBridge: DriverLinkBridge?
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

    /// A connect is waiting for its attach. One at a time.
    private var attachPending = false
    private var attachGeneration = UUID()
    /// This session reported a fault and the driver's invalidation has not
    /// arrived yet. The link is finished: nothing on it may progress toward
    /// ready.
    private var faultReported = false
    /// The managed device the driver's pushes go to, while the
    /// management sheet has one open.
    private weak var managedDevice: MobileManagedDevice?
    #if DEBUG
    /// The staged devices listed before those found over Bluetooth, while
    /// staging is on.
    private var staged: StagedAdministeredDevices?
    #endif

    override init() {
        super.init()
        if RadioAccessories.usesSystemPicker {
            accessoryTask = Task { [weak self] in
                for await inventory in await RadioAccessories.shared.updates() {
                    guard !Task.isCancelled else { break }
                    self?.queue.async { [weak self] in self?.applyAccessoryInventory(inventory) }
                }
            }
        }
    }

    /// Abandoning the flow must release its connection, registry claim,
    /// and driver.
    deinit {
        accessoryTask?.cancel()
        if let identifier = peripheral?.identifier {
            AdminSessionRegistry.shared.deregister(identifier)
        }
        if let peripheral, let central, peripheral.state != .disconnected {
            central.cancelPeripheralConnection(peripheral)
        }
        driver?.stop()
    }

    private func applyAccessoryInventory(_ inventory: RadioAccessoryInventory) {
        guard accessoryInventory.accept(inventory) else { return }
        if !inventory.canScan, discoveryActive {
            stopDiscoveryOnQueue()
            discoveryRequested = true
        }
        if let id = peripheral?.identifier, inventory.removedIDs.contains(id) {
            fault(RadioTransportProblem.accessRemoved.problem)
        }
        yieldDiscoveryList()
        if inventory.canScan, discoveryRequested { startDiscoveryOnQueue() }
    }

    private func waitForBluetooth(_ inventory: RadioAccessoryInventory) async throws {
        try await withCheckedThrowingContinuation { (waiter: CheckedContinuation<Void, any Error>) in
            queue.async { [self] in
                applyAccessoryInventory(inventory)
                guard accessoryInventory.canCreateCentral else {
                    waiter.resume(throwing: RadioConnectionError.bluetoothUnavailable)
                    return
                }
                if central == nil { central = CBCentralManager(delegate: self, queue: queue) }
                if central?.state == .poweredOn { waiter.resume(); return }
                let token = UUID()
                bluetoothWaiters[token] = waiter
                queue.asyncAfter(deadline: .now() + 8) { [weak self] in
                    self?.bluetoothWaiters.removeValue(forKey: token)?
                        .resume(throwing: RadioConnectionError.bluetoothUnavailable)
                }
            }
        }
    }

    private func onQueue<T: Sendable>(_ body: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { (result: CheckedContinuation<T, Never>) in
            queue.async { result.resume(returning: body()) }
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
        await onQueue { [self] in
            selectedHostKey = hostKey
            try? driver?.setHostKey(hostKey: hostKey)
        }
    }

    // MARK: - Snapshots

    func snapshots() async -> AsyncStream<AdministeredDeviceSnapshot> {
        await onQueue { [self] in
            AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
                let id = UUID()
                continuations[id] = continuation
                continuation.yield(snapshot)
                continuation.onTermination = { [weak self] _ in
                    self?.queue.async { [weak self] in
                        self?.continuations[id] = nil
                    }
                }
            }
        }
    }

    #if DEBUG
    // MARK: - Staging

    /// List `devices` before those found over Bluetooth, and attach to
    /// them through the staging air.
    func useStagedDevices(_ devices: StagedAdministeredDevices?) async {
        await onQueue { [self] in
            staged = devices
            yieldDiscoveryList()
        }
    }
    #endif

    // MARK: - Discovery

    /// Stream the live list of nearby UMSH devices. Never auto-connects.
    ///
    /// `companionIdentifier` marks the phone's own radio in the list so the
    /// UI can steer the user away from administering the device it is
    /// already tethered to—the two links would contend for the same
    /// peripheral.
    func discover(companionIdentifier: UUID? = nil) async -> AsyncStream<[DiscoveredRadio]> {
        await onQueue { [self] in
            self.companionIdentifier = companionIdentifier
            let stream = AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
                let id = UUID()
                discoveryContinuations[id] = continuation
                continuation.yield(currentDiscoveryList())
                continuation.onTermination = { [weak self] _ in
                    self?.queue.async { [weak self] in
                        self?.discoveryContinuations[id] = nil
                        if self?.discoveryContinuations.isEmpty == true { self?.stopDiscoveryOnQueue() }
                    }
                }
            }
            Self.logger.notice("action: opened administrative device discovery")
            startDiscoveryOnQueue()
            return stream
        }
    }

    func stopDiscovery() async {
        await onQueue { [self] in stopDiscoveryOnQueue() }
    }

    private func startDiscoveryOnQueue() {
        discoveryRequested = true
        discovered.removeAll()
        nextDiscoveryOrder = 0
        yieldDiscoveryList()
        guard !RadioAccessories.usesSystemPicker || accessoryInventory.canScan else { return }
        guard let central else {
            central = CBCentralManager(delegate: self, queue: queue)
            return
        }
        guard central.state == .poweredOn else { return }
        beginDiscoveryScan()
    }

    private func beginDiscoveryScan() {
        guard let central, central.state == .poweredOn else { return }
        guard !RadioAccessories.usesSystemPicker || accessoryInventory.canScan else { return }
        discoveryRequested = false
        discoveryActive = true
        // Duplicates keep RSSI live and let a device that briefly drops out
        // reappear instead of going stale.
        central.scanForPeripherals(
            withServices: RadioAccessories.usesSystemPicker ? nil : [RadioGatt.service],
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
        if RadioAccessories.usesSystemPicker {
            guard accessoryInventory.authorizedIDs.contains(peripheral.identifier),
                  (advertisementData[CBAdvertisementDataIsConnectable] as? NSNumber)?.boolValue == true else {
                discovered.removeValue(forKey: peripheral.identifier)
                yieldDiscoveryList()
                return
            }
        }
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
        #if DEBUG
        if let staged { return staged.radios + bluetoothDiscoveryList() }
        #endif
        return bluetoothDiscoveryList()
    }

    private func bluetoothDiscoveryList() -> [DiscoveredRadio] {
        if RadioAccessories.usesSystemPicker {
            return accessoryInventory.availableRadios(
                sightings: discovered.values.sorted { $0.discoveryOrder < $1.discoveryOrder }.map { entry in
                    RadioAccessorySighting(
                        radio: DiscoveredRadio(id: entry.peripheral.identifier, name: entry.name,
                                               rssiDBm: entry.rssiDBm, isRemembered: true),
                        lastSeen: entry.lastSeen.uptimeNanoseconds,
                        canConnect: entry.peripheral.state == .disconnected
                            && !AdminSessionRegistry.shared.contains(entry.peripheral.identifier)
                    )
                }, now: DispatchTime.now().uptimeNanoseconds,
                excluding: Set([companionIdentifier].compactMap { $0 })
            )
        }
        // Arrival order, and nothing else. Every other property of a
        // discovered device changes while the list is on screen—RSSI with
        // every advertisement, and the name when one finally arrives, since a
        // device is first heard with only whatever `CBPeripheral.name` gives
        // us. Sorting on any of them moves rows under the user's finger.
        //
        // The companion radio is deliberately *not* pinned to the top here,
        // unlike companion discovery: it cannot be set up from this list, and
        // a list that opens with an untappable row is worse than one that
        // does not.
        return discovered.values
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
            self.discovered = self.discovered.filter { _, entry in
                now <= entry.lastSeen.uptimeNanoseconds &+ stale
            }
            self.yieldDiscoveryList()
            self.scheduleDiscoveryPrune(generation: generation)
        }
    }

    // MARK: - Connection

    /// Connect to `id` and synchronize with it, resolving once the ULCP
    /// session is attached and the attach's inspection has landed.
    ///
    /// `lazyAttach` cuts the post-attach inspection to what attaching
    /// itself requires, leaving the device to be read a screenful at a
    /// time through the managed device. The full attach is what
    /// commissioning needs, and a lazy settings screen must never pay for.
    ///
    /// Throws if the device cannot be reached, refuses the protocol, or the
    /// whole exchange overruns its budget. A drop *after* this resolves is
    /// not thrown anywhere—it arrives on `snapshots()` as a failed link,
    /// because by then the caller is a UI showing an editor, not an
    /// `await`.
    func connect(_ id: UUID, lazyAttach: Bool = false) async throws {
        let selection = UUID()
        await onQueue { [self] in selectionGeneration = selection }
        #if DEBUG
        if await onQueue({ [self] in staged?.offers(id) == true }) {
            try await connectStaged(id, selection: selection, lazyAttach: lazyAttach)
            return
        }
        #endif
        if RadioAccessories.usesSystemPicker {
            let inventory = try await RadioAccessories.shared.prepareSelection(id)
            try await waitForBluetooth(inventory)
        }
        try Task.checkCancellation()
        let driver = try await withCheckedThrowingContinuation {
            (result: CheckedContinuation<MobileRadioDriver, any Error>) in
            queue.async { [self] in
                do {
                    result.resume(returning: try beginConnect(id, selection: selection, lazyAttach: lazyAttach))
                } catch {
                    result.resume(throwing: error)
                }
            }
        }
        try await awaitAttach(of: driver)
    }

    /// Wait for `driver`'s attach. It resolves once the attach's
    /// inspection has landed: a caller needs a device, not a link.
    private func awaitAttach(of driver: MobileRadioDriver) async throws {
        do {
            _ = try await driver.attached()
            await onQueue { [self] in finishAttach(of: driver) }
        } catch let error as MobileRadioError {
            await onQueue { [self] in finishAttach(of: driver) }
            throw Self.attachError(error)
        }
    }

    #if DEBUG
    /// Attach to a staged device in place of a Bluetooth one. The staging
    /// air runs the device's link itself and hands the driver this
    /// session's host key before the link comes up, as `startDriver` does;
    /// this session then adopts the driver, so snapshots and operations go
    /// exactly as over Bluetooth.
    private func connectStaged(
        _ id: UUID,
        selection: UUID,
        lazyAttach: Bool
    ) async throws {
        try Task.checkCancellation()
        let driver = try await withCheckedThrowingContinuation {
            (result: CheckedContinuation<MobileRadioDriver, any Error>) in
            queue.async { [self] in
                do {
                    result.resume(returning: try beginStagedConnect(
                        id,
                        selection: selection,
                        lazyAttach: lazyAttach
                    ))
                } catch {
                    result.resume(throwing: error)
                }
            }
        }
        try await awaitAttach(of: driver)
    }

    private func beginStagedConnect(
        _ id: UUID,
        selection: UUID,
        lazyAttach: Bool
    ) throws -> MobileRadioDriver {
        guard selectionGeneration == selection else { throw CancellationError() }
        guard let staged else { throw RadioConnectionError.radioNotFound }
        guard !attachPending else { throw RadioConnectionError.operationInProgress }
        Self.logger.notice("action: administer staged device \(id, privacy: .public)")
        stopDiscoveryOnQueue()
        releasePeripheral()
        retireDriver()
        let driver: MobileRadioDriver
        do {
            driver = try staged.driver(
                for: id,
                hostKey: selectedHostKey,
                lazyInspection: lazyAttach
            )
        } catch {
            throw RadioConnectionError.radioNotFound
        }
        adopt(driver)
        attachPending = true
        return driver
    }
    #endif

    /// Start connecting on the queue, and hand back the driver whose attach
    /// the caller waits on. It reports the transport connecting first, so
    /// the attach is not judged over before it began.
    private func beginConnect(
        _ id: UUID,
        selection: UUID,
        lazyAttach: Bool
    ) throws -> MobileRadioDriver {
        guard selectionGeneration == selection else { throw CancellationError() }
        if RadioAccessories.usesSystemPicker && !accessoryInventory.permitsConnection(to: id) {
            throw RadioConnectionError.pairingRequired
        }
        guard let central, central.state == .poweredOn else {
            throw RadioConnectionError.bluetoothUnavailable
        }
        guard !attachPending else { throw RadioConnectionError.operationInProgress }
        // The advertised name is live; `CBPeripheral.name` is a cache
        // iOS does not refresh when a device is renamed.
        let advertisedName = accessoryInventory.radios.first(where: { $0.id == id })?.name
            ?? discovered[id]?.name
        let target = discovered[id]?.peripheral
            ?? central.retrievePeripherals(withIdentifiers: [id]).first
        guard let target else { throw RadioConnectionError.radioNotFound }
        Self.logger.notice("action: administer device \(id, privacy: .public)")
        stopDiscoveryOnQueue()
        releasePeripheral()
        retireDriver()

        let driver = try startDriver(lazyInspection: lazyAttach)
        peripheral = target
        target.delegate = self
        // Claim the peripheral before connecting, so a companion sweep
        // racing this connect cannot revoke it mid-flight.
        AdminSessionRegistry.shared.register(target.identifier)
        attachPending = true
        attachGeneration = UUID()
        deviceName = advertisedName ?? target.name
        reportTransport(.connecting, name: deviceName)
        central.connect(target)
        scheduleAttachTimeout(generation: attachGeneration)
        return driver
    }

    private func finishAttach(of driver: MobileRadioDriver) {
        guard self.driver === driver else { return }
        attachPending = false
        attachGeneration = UUID()
    }

    private func scheduleAttachTimeout(generation: UUID) {
        queue.asyncAfter(deadline: .now() + Self.attachTimeoutSeconds) { [weak self] in
            guard let self, self.attachGeneration == generation, self.attachPending else { return }
            Self.logger.error("administrative attach timed out")
            self.fault(RadioTransportProblem.connectionIncomplete.problem)
        }
    }

    /// End the session and release the peripheral. Idempotent.
    func disconnect() async {
        await onQueue { [self] in
            Self.logger.notice("action: ended administrative session")
            selectionGeneration = UUID()
            let waiters = bluetoothWaiters.values
            bluetoothWaiters.removeAll()
            for waiter in waiters { waiter.resume(throwing: CancellationError()) }
            stopDiscoveryOnQueue()
            if let peripheral, let central, peripheral.state != .disconnected {
                central.cancelPeripheralConnection(peripheral)
            }
            releasePeripheral()
            // Stopping the driver fails whatever was waiting on it.
            retireDriver()
            publish(AdministeredDeviceSnapshot.idle)
        }
    }

    /// Release every CoreBluetooth resource for the current device,
    /// including its registry claim. Does not itself cancel the
    /// connection—callers decide whether the link is being torn down or
    /// has already dropped.
    private func releasePeripheral() {
        if let identifier = peripheral?.identifier {
            AdminSessionRegistry.shared.deregister(identifier)
        }
        peripheral?.delegate = nil
        peripheral = nil
        deviceName = nil
        lastCachedConfiguredName = nil
        frameIn = nil
        frameOut = nil
        linkResetFraming()
        faultReported = false
        attachGeneration = UUID()
    }

    /// The driver for the next connect, in the inspection mode it asks for.
    private func startDriver(lazyInspection: Bool) throws -> MobileRadioDriver {
        let bridge = DriverLinkBridge(queue: queue)
        bridge.link = self
        let driver: MobileRadioDriver
        do {
            driver = try MobileRadioDriver.administrative(link: bridge, lazyInspection: lazyInspection)
        } catch {
            // Only fails when the system will not start a thread.
            throw RadioConnectionError.radioNotFound
        }
        adopt(driver)
        linkBridge = bridge
        return driver
    }

    /// Make `driver` this session's: its updates publish snapshots, and
    /// operations run on it.
    private func adopt(_ driver: MobileRadioDriver) {
        driver.setListener(listener: AdministrativeDriverListener(session: self, driver: driver))
        try? driver.setHostKey(hostKey: selectedHostKey)
        self.driver = driver
    }

    /// Stop the current driver and cut it off from the link, so nothing
    /// it says late reaches the next device.
    private func retireDriver() {
        linkBridge?.link = nil
        linkBridge = nil
        driver?.clearListener()
        driver?.stop()
        driver = nil
        managedDevice = nil
        attachPending = false
    }

    /// Tell the driver where the transport stands while it carries no
    /// frames.
    private func reportTransport(_ phase: MobileRadioTransportPhase, name: String?) {
        driver?.transportChanged(state: MobileRadioTransportStateRecord(
            phase: phase,
            name: name,
            linkId: peripheral?.identifier.uuidString,
            problem: nil
        ))
    }

    /// The link is finished for `problem`. The driver shows the failure
    /// and says so through `linkInvalidate`, which ends the session.
    private func fault(_ problem: MobileRadioProblem) {
        guard !faultReported, let driver else { return }
        faultReported = true
        driver.linkFault(problem: problem)
    }

    /// Whether a callback about `peripheral` is still this session's to
    /// act on.
    private func owns(_ peripheral: CBPeripheral) -> Bool {
        self.peripheral === peripheral && !faultReported
    }

    // MARK: - Management

    /// The driver for the attached device, which the core manages it
    /// through. `nil` while nothing is attached.
    func currentDriver() async -> MobileRadioDriver? {
        await onQueue { [self] in driver }
    }

    /// Hand what the attached device announces on its own, and how many
    /// announcements were lost, to `device`.
    func forwardPushes(to device: MobileManagedDevice?) async {
        await onQueue { [self] in managedDevice = device }
    }

    // MARK: - What the driver publishes

    fileprivate func driverDidAnnounceUpdate(_ driver: MobileRadioDriver) {
        queue.async { [weak self] in
            guard let self, self.driver === driver else { return }
            let update = driver.pollUpdate()
            if let state = update.state {
                publish(AdministeredDeviceSnapshot(state))
            }
            if !update.pushedProperties.isEmpty || update.pushedPropertiesDropped > 0 {
                managedDevice?.receivePushes(
                    pushes: update.pushedProperties,
                    dropped: update.pushedPropertiesDropped
                )
            }
        }
    }

    private func publish(_ next: AdministeredDeviceSnapshot) {
        snapshot = next
        for continuation in continuations.values {
            continuation.yield(next)
        }
    }

    // MARK: - Errors

    /// Why the attach did not finish, in the terms callers act on.
    private static func attachError(_ error: MobileRadioError) -> any Error {
        switch error {
        case let .LinkFailed(problem):
            connectionFailure(problem)
        case .Stopped:
            RadioConnectionError.radioNotFound
        default:
            RadioDriverAdapter.connectionError(error)
        }
    }

    /// A failed link, in the terms callers act on. A missing pairing is a
    /// setup step, not a protocol incompatibility, and the two lead the
    /// user somewhere different.
    static func connectionFailure(_ problem: MobileRadioProblem?) -> RadioConnectionError {
        guard let problem else { return .radioNotFound }
        switch problem {
        case let .transport(domain, code) where domain == RadioTransportProblem.domain:
            switch RadioTransportProblem(rawValue: code) {
            case .accessRemoved:
                return .pairingRequired
            case .bluetoothUnauthorized, .bluetoothUnsupported, .bluetoothOff,
                 .bluetoothResetting, .bluetoothStarting, .bluetoothUnavailable:
                return .bluetoothUnavailable
            case .linkLost, .connectionFailed, .connectionIncomplete, .none:
                return .radioNotFound
            default:
                return .incompatibleProtocol
            }
        case let .transport(domain, code):
            let error = NSError(domain: domain, code: Int(code))
            return BluetoothErrorText.isPairingFailure(error) ? .pairingRequired : .incompatibleProtocol
        case .synchronizationStalled, .disconnected:
            return .radioNotFound
        default:
            return .incompatibleProtocol
        }
    }
}

// MARK: - UlcpFrameLink

extension AdministrativeDeviceSession: UlcpFrameLink {
    var linkID: UUID? { peripheral?.identifier }

    /// Segment the frame and queue every ATT value, then start the queue
    /// if it was idle. GATT writes go one at a time, each with a response.
    func linkSend(frame: Data, rawTransactionID: UInt8?) {
        guard !faultReported, let peripheral else { return }
        guard peripheral.state == .connected, frameIn != nil else {
            fault(RadioTransportProblem.linkLost.problem)
            return
        }
        // ULCP GATT SAR needs ordinary single-write values; the
        // without-response maximum is the negotiated ATT payload bound even
        // though each segment is deliberately written with a response.
        let maximumLength = UInt16(
            min(peripheral.maximumWriteValueLength(for: .withoutResponse), Int(UInt16.max))
        )
        do {
            let segments = try UMSHMobileCore.ulcpGattSegments(
                frame: frame,
                maximumValueLength: maximumLength
            )
            pendingWrites.append(contentsOf: segments.map(\.value))
        } catch {
            fault(RadioTransportProblem.unsendableFrame.problem)
            return
        }
        writeNext(on: peripheral)
    }

    func linkResetFraming() {
        reassembler.reset()
        pendingWrites.removeAll()
        writeInProgress = false
    }

    /// No reconnect: the session ends here, and the driver shows why.
    func linkInvalidate(retrying: Bool) {
        let name = deviceName
        if let peripheral, let central, central.state == .poweredOn,
           peripheral.state != .disconnected {
            central.cancelPeripheralConnection(peripheral)
        }
        releasePeripheral()
        // A failure with no problem of its own is the fault's. The device
        // is let go, so the failure names no device to return to.
        reportTransport(.failed, name: name)
    }

    /// Nothing is remembered: an administered device is not the phone's.
    func linkDidAttach() {}

    func linkDidReportName(_ name: String) {
        deviceName = name
        guard RadioAccessories.usesSystemPicker, name != lastCachedConfiguredName,
              let id = peripheral?.identifier else { return }
        lastCachedConfiguredName = name
        Task { await RadioAccessories.shared.rememberConfiguredName(name, for: id) }
    }

    func linkAbandonBinding() {}

    /// The setup flow ends the session itself once the device confirms.
    func linkDidEnterDfu() {}

    private func writeNext(on peripheral: CBPeripheral) {
        guard !writeInProgress, !pendingWrites.isEmpty, let frameIn else { return }
        writeInProgress = true
        peripheral.writeValue(pendingWrites.removeFirst(), for: frameIn, type: .withResponse)
    }

    /// The GATT attach is done: the link carries frames, and the driver
    /// starts the ULCP session over it.
    fileprivate func beginSynchronization(on peripheral: CBPeripheral) {
        guard let frameIn, frameIn.properties.contains(.write) else {
            fault(RadioTransportProblem.endpointUnwritable.problem)
            return
        }
        linkResetFraming()
        // The one radio this session reaches is the one the user chose.
        driver?.linkReady(boundRadio: true)
    }

    fileprivate func receive(_ value: Data) {
        do {
            guard let frame = try reassembler.push(segment: value) else { return }
            driver?.linkReceived(frame: frame)
        } catch {
            // A frame lost in reassembly ends the session, and over BLE the
            // session is the connection, for the reasons
            // `peripheral(_:didUpdateValueFor:error:)` gives in the
            // tethered connection.
            Self.logger.error(
                """
                administrative session: a frame from the device was lost; \
                closing the link \
                cause=\(UlcpFrameDiagnostic.cause(error), privacy: .public) \
                segment=\(value.count)B
                """
            )
            fault(RadioTransportProblem.linkLost.problem)
        }
    }
}

// MARK: - CBCentralManagerDelegate

extension AdministrativeDeviceSession: CBCentralManagerDelegate {
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            let waiters = bluetoothWaiters.values
            bluetoothWaiters.removeAll()
            for waiter in waiters { waiter.resume() }
        }
        guard central.state == .poweredOn else {
            if discoveryActive {
                stopDiscoveryOnQueue()
                discoveryRequested = true
            }
            if peripheral != nil {
                fault(RadioTransportProblem.bluetoothUnavailable.problem)
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
        guard owns(peripheral) else { return }
        Self.logger.notice(
            "event: administrative didConnect \(peripheral.identifier, privacy: .public)"
        )
        reportTransport(.attaching, name: deviceName)
        peripheral.discoverServices([RadioGatt.service])
    }

    func centralManager(
        _ central: CBCentralManager,
        didFailToConnect peripheral: CBPeripheral,
        error: (any Error)?
    ) {
        guard owns(peripheral) else { return }
        // No re-arm: an administrative connect is a foreground action that
        // either worked or did not.
        fault(error.map(MobileRadioProblem.system) ?? RadioTransportProblem.connectionFailed.problem)
    }

    func centralManager(
        _ central: CBCentralManager,
        didDisconnectPeripheral peripheral: CBPeripheral,
        error: (any Error)?
    ) {
        guard owns(peripheral) else { return }
        Self.logger.notice(
            """
            event: administrative didDisconnect \(peripheral.identifier, privacy: .public) \
            error=\(error?.localizedDescription ?? "none", privacy: .public)
            """
        )
        fault(RadioTransportProblem.linkLost.problem)
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
        guard owns(peripheral),
              invalidatedServices.contains(where: { $0.uuid == RadioGatt.service })
        else { return }
        Self.logger.notice(
            "event: administrative didModifyServices \(peripheral.identifier, privacy: .public)"
        )
        frameIn = nil
        frameOut = nil
        linkResetFraming()
        reportTransport(.attaching, name: deviceName)
        peripheral.discoverServices([RadioGatt.service])
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: (any Error)?) {
        guard owns(peripheral) else { return }
        if let error {
            fault(.system(error))
            return
        }
        guard let service = peripheral.services?
            .first(where: { $0.uuid == RadioGatt.service }) else {
            fault(RadioTransportProblem.serviceMissing.problem)
            return
        }
        peripheral.discoverCharacteristics([RadioGatt.frameIn, RadioGatt.frameOut], for: service)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didDiscoverCharacteristicsFor service: CBService,
        error: (any Error)?
    ) {
        guard owns(peripheral) else { return }
        if let error {
            fault(.system(error))
            return
        }
        frameIn = service.characteristics?.first { $0.uuid == RadioGatt.frameIn }
        frameOut = service.characteristics?.first { $0.uuid == RadioGatt.frameOut }
        guard frameIn != nil, let frameOut else {
            fault(RadioTransportProblem.serviceIncompatible.problem)
            return
        }
        // Enabling notifications is what triggers the system pairing prompt
        // on an unbonded device, so the link state says so.
        reportTransport(.pairing, name: deviceName)
        peripheral.setNotifyValue(true, for: frameOut)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateNotificationStateFor characteristic: CBCharacteristic,
        error: (any Error)?
    ) {
        guard owns(peripheral), characteristic.uuid == RadioGatt.frameOut else { return }
        if let error {
            fault(.system(error))
            return
        }
        guard characteristic.isNotifying else {
            fault(RadioTransportProblem.attachmentRefused.problem)
            return
        }
        beginSynchronization(on: peripheral)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didWriteValueFor characteristic: CBCharacteristic,
        error: (any Error)?
    ) {
        guard owns(peripheral), characteristic.uuid == RadioGatt.frameIn else { return }
        writeInProgress = false
        if let error {
            pendingWrites.removeAll()
            fault(.system(error))
            return
        }
        writeNext(on: peripheral)
    }

    func peripheral(
        _ peripheral: CBPeripheral,
        didUpdateValueFor characteristic: CBCharacteristic,
        error: (any Error)?
    ) {
        guard owns(peripheral), characteristic.uuid == RadioGatt.frameOut else { return }
        if let error {
            fault(.system(error))
            return
        }
        // An empty value carries no segment header; the reassembler
        // discards it and resets, as it does any other invalid segment.
        receive(characteristic.value ?? Data())
    }
}

/// Tells the session that its driver has an update. Runs on the driver's
/// thread; holds both weakly, so neither a retired session nor a retired
/// driver is kept alive, and an update from a driver the session has
/// replaced is recognized as such.
private final class AdministrativeDriverListener: MobileRadioDriverListener, @unchecked Sendable {
    private weak var session: AdministrativeDeviceSession?
    private weak var driver: MobileRadioDriver?

    init(session: AdministrativeDeviceSession, driver: MobileRadioDriver) {
        self.session = session
        self.driver = driver
    }

    func onUpdatePending() {
        guard let driver else { return }
        session?.driverDidAnnounceUpdate(driver)
    }
}
