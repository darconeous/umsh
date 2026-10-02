import AccessorySetupKit
@preconcurrency import CoreBluetooth
import Foundation
import Observation
import OSLog
import UIKit

/// The one app-wide owner of accessory authorization and legacy migration.
/// Neither companion nor administrative transports create a central until its
/// inventory permits it. Picker presentation is always an explicit UI action.
@MainActor
@Observable
final class RadioAccessories {
    static let shared = RadioAccessories()
    private static let logger = Logger(subsystem: "com.umsh.ios", category: "RadioAccessories")

    nonisolated static var usesSystemPicker: Bool {
        #if targetEnvironment(simulator)
        false
        #else
        !ProcessInfo.processInfo.isiOSAppOnMac
        #endif
    }

    private(set) var inventory = RadioAccessoryInventory()
    private var session: ASAccessorySession?
    private var sessionGeneration = UUID()
    private var observers: [UUID: AsyncStream<RadioAccessoryInventory>.Continuation] = [:]
    private var activationWaiters: [CheckedContinuation<Void, any Error>] = []
    private var pickerWaiter: CheckedContinuation<Void, any Error>?
    private var pickerError: (any Error)?
    private var pickerGeneration = UUID()
    private var pickerSelectedID: UUID?
    // Store the base type so the app still runs on iOS 18. These are populated
    // only by the filtered-discovery API available in iOS 26.1 and later.
    private var pickerDiscoveries = RadioPairingDiscoveries<ASAccessory>(catalog: .bundled)
    private var pickerUpdates = RadioPickerUpdates()
    private var pickerPublishScheduled = false
    private var pickerUpdateError: (any Error)?
    private var pickerDiscoveryReports = 0
    private var pickerNamedReports = 0
    #if DEBUG
    private static let nameTraceLogger = Logger(subsystem: "com.umsh.ios", category: "RadioPairingNames")
    private var nameTraceSession = "launch"
    private var nameTraceStarted = ProcessInfo.processInfo.systemUptime
    private var nameTraceSequence = 0
    private var nameTracePeripheralIDs: [UUID: Int] = [:]
    #endif
    private var setupState = RadioAccessorySetupState()
    private var revision: UInt64 = 0
    private let defaults: UserDefaults
    private let managedKey = "radio.accessories.managedIDs"
    private let namesKey = "radio.accessories.configuredNames"
    private var appIsActive = false
    private var activationRecovery = RadioActivationRecovery()
    private var recoveryToken = UUID()
    // Installed on the main actor, then only released by deinit. Foundation's
    // observer tokens are not Sendable; removal itself is thread-safe.
    @ObservationIgnored nonisolated(unsafe) private var lifecycleObservers: [NSObjectProtocol] = []

    init(defaults: UserDefaults = .standard) { self.defaults = defaults }

    deinit {
        for observer in lifecycleObservers { NotificationCenter.default.removeObserver(observer) }
    }

    nonisolated static func message(for error: any Error) -> String {
        if let radioError = error as? RadioConnectionError {
            switch radioError {
            case .operationRejected(let message): return message
            case .pairingRequired: return "Open the radio's pairing window and add it again."
            case .bluetoothUnavailable: return "Bluetooth is unavailable. Check that it is enabled."
            case .operationInProgress: return "Finish the current radio setup first."
            default: return "Could not connect to that radio. Check that it is powered on and nearby."
            }
        }
        return error.localizedDescription
    }

    private var legacyID: UUID? {
        (defaults.string(forKey: "radio.connectedUUID")
            ?? defaults.string(forKey: "radio.lastAttachedPeripheral")).flatMap(UUID.init(uuidString:))
    }

    func updates() -> AsyncStream<RadioAccessoryInventory> {
        let id = UUID()
        let stream = AsyncStream<RadioAccessoryInventory>(bufferingPolicy: .bufferingNewest(1)) { continuation in
            observers[id] = continuation
            continuation.yield(inventory)
            continuation.onTermination = { [weak self] _ in
                Task { @MainActor in self?.observers[id] = nil }
            }
        }
        start()
        return stream
    }

    private func start() {
        guard Self.usesSystemPicker else {
            inventory.ready = true
            publish()
            finishActivation()
            return
        }
        guard session == nil else { return }
        if lifecycleObservers.isEmpty {
            appIsActive = UIApplication.shared.applicationState == .active
            for (notification, active) in [
                (UIApplication.didBecomeActiveNotification, true),
                (UIApplication.willResignActiveNotification, false),
            ] {
                lifecycleObservers.append(NotificationCenter.default.addObserver(
                    forName: notification, object: nil, queue: .main
                ) { [weak self] _ in
                    MainActor.assumeIsolated {
                        guard let self else { return }
                        self.appIsActive = active
                        self.publish()
                        if active { self.recoverIfNeeded() }
                    }
                })
            }
        }
        inventory.problem = nil
        let session = ASAccessorySession()
        self.session = session
        let generation = UUID()
        sessionGeneration = generation
        session.activate(on: .main) { [weak self] event in
            MainActor.assumeIsolated {
                guard let self, self.sessionGeneration == generation else { return }
                self.handle(event)
            }
        }
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(8))
            guard let self, self.sessionGeneration == generation, !self.inventory.ready else { return }
            self.activationFailed(RadioConnectionError.operationTimedOut)
        }
    }

    /// Foreground entry and explicit Reconnect can restart a failed inventory
    /// activation without making the user open an unrelated setup picker.
    func recoverIfNeeded() {
        guard session == nil else { return }
        activationRecovery.reset()
        recoveryToken = UUID()
        start()
    }

    private func activationFailed(_ error: any Error) {
        sessionGeneration = UUID()
        session?.invalidate()
        session = nil
        inventory.ready = false
        inventory.problem = error.localizedDescription
        finishActivation(error: error)
        if setupState.isActive { finishPicker(.invalidated, error: error) }
        else { publish() }
        // Bounded recovery, not a permanent background polling loop.
        guard let delay = activationRecovery.nextDelay() else { return }
        let token = UUID()
        recoveryToken = token
        Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            guard let self, self.recoveryToken == token, self.session == nil else { return }
            self.start()
        }
    }

    private func activate() async throws {
        if inventory.ready { return }
        try await withCheckedThrowingContinuation { continuation in
            activationWaiters.append(continuation)
            start()
        }
    }

    private func publish() {
        revision += 1
        inventory.revision = revision
        inventory.appIsActive = appIsActive
        for observer in observers.values { observer.yield(inventory) }
    }

    private func finishActivation(error: (any Error)? = nil) {
        let waiters = activationWaiters
        activationWaiters.removeAll()
        for waiter in waiters {
            if let error { waiter.resume(throwing: error) }
            else { waiter.resume() }
        }
    }

    /// Exact names are diagnostic data: expose them only in Debug builds.
    /// Peripheral labels are local to this trace; object tokens distinguish
    /// preauthorization reports whose Bluetooth identifier is still nil.
    private func traceNames(
        _ event: String, accessory: ASAccessory? = nil, peripheralID: UUID? = nil,
        details: @autoclosure () -> String = ""
    ) {
        #if DEBUG
        let id = peripheralID ?? accessory?.bluetoothIdentifier
        var peripheral = "nil"
        if let id {
            if nameTracePeripheralIDs[id] == nil {
                nameTracePeripheralIDs[id] = nameTracePeripheralIDs.count + 1
            }
            peripheral = "P\(nameTracePeripheralIDs[id]!)"
        }
        let object = accessory.map { String(describing: ObjectIdentifier($0)) } ?? "nil"
        let displayName = Self.traceName(accessory?.displayName)
        let state = accessory.map { String(describing: $0.state) } ?? "nil"
        let elapsed = Int64((ProcessInfo.processInfo.systemUptime - nameTraceStarted) * 1_000)
        nameTraceSequence += 1
        let detail = details()
        Self.nameTraceLogger.notice("radio name trace: session=\(self.nameTraceSession, privacy: .public) seq=\(self.nameTraceSequence) elapsedMs=\(elapsed) event=\(event, privacy: .public) object=\(object, privacy: .public) peripheral=\(peripheral, privacy: .public) state=\(state, privacy: .public) displayName=\(displayName, privacy: .public) \(detail, privacy: .public)")
        #endif
    }

    private static func traceName(_ name: String?) -> String {
        guard let name else { return "nil" }
        // Quote and escape whitespace so truncation and empty names are visible.
        return "\(name.debugDescription)(utf8=\(name.utf8.count))"
    }

    private func refresh() {
        guard let session else { return }
        var names = defaults.dictionary(forKey: namesKey) as? [String: String] ?? [:]
        if let id = legacyID, let name = defaults.string(forKey: "radio.deviceName"),
           names[id.uuidString] == nil, !name.isEmpty {
            names[id.uuidString] = name
        }
        let authorized = session.accessories.compactMap { accessory -> DiscoveredRadio? in
            guard accessory.state == .authorized, let id = accessory.bluetoothIdentifier else { return nil }
            if setupState.isActive || pickerSelectedID == id {
                traceNames("inventory", accessory: accessory,
                           details: "appCachedName=\(Self.traceName(names[id.uuidString]))")
            }
            return DiscoveredRadio(id: id, name: names[id.uuidString] ?? accessory.displayName,
                                   rssiDBm: 127, isRemembered: true)
        }
        var managed = Set((defaults.stringArray(forKey: managedKey) ?? []).compactMap(UUID.init(uuidString:)))
        inventory = .reconcile(
            authorized: authorized, previouslyManaged: managed,
            legacyID: legacyID, legacyName: defaults.string(forKey: "radio.deviceName"),
            configuredNames: Dictionary(uniqueKeysWithValues: names.compactMap { key, name in
                UUID(uuidString: key).map { ($0, name) }
            })
        )
        inventory.pickerActive = setupState.isActive
        managed.formUnion(inventory.authorizedIDs)
        defaults.set(managed.map(\.uuidString).sorted(), forKey: managedKey)
        let retainedNames = Dictionary(uniqueKeysWithValues: inventory.configuredNames.map { ($0.key.uuidString, $0.value) })
        if retainedNames != defaults.dictionary(forKey: namesKey) as? [String: String] {
            defaults.set(retainedNames, forKey: namesKey)
        }
        publish()
    }

    /// Called only with names reported over the authenticated radio session.
    func rememberConfiguredName(_ name: String, for id: UUID) {
        traceNames("authenticated-name", accessory: session?.accessories.first { $0.bluetoothIdentifier == id },
                   peripheralID: id, details: "configuredName=\(Self.traceName(name)) authorized=\(inventory.authorizedIDs.contains(id)) destination=app-cache")
        guard inventory.authorizedIDs.contains(id), !name.isEmpty else { return }
        var names = defaults.dictionary(forKey: namesKey) as? [String: String] ?? [:]
        guard names[id.uuidString] != name else { return }
        names[id.uuidString] = name
        defaults.set(names, forKey: namesKey)
        refresh()
    }

    private func handle(_ event: ASAccessoryEvent) {
        Self.logger.debug("accessory event=\(event.eventType.rawValue) setupActive=\(self.setupState.isActive) authorized=\(self.inventory.authorizedIDs.count)")
        switch event.eventType {
        case .activated:
            if let error = event.error {
                activationFailed(error)
                return
            }
            recoveryToken = UUID()
            refresh()
            finishActivation()
            let generation = sessionGeneration
            Task { @MainActor [weak self] in
                try? await Task.sleep(for: .seconds(60))
                guard let self, self.sessionGeneration == generation, self.inventory.ready else { return }
                self.activationRecovery.reset()
            }
        case .accessoryAdded, .accessoryChanged, .accessoryRemoved:
            let nameEvent = event.eventType == .accessoryAdded ? "accessoryAdded"
                : event.eventType == .accessoryChanged ? "accessoryChanged" : "accessoryRemoved"
            traceNames(nameEvent, accessory: event.accessory, details: "pickerActive=\(setupState.isActive)")
            if inventory.pickerActive, event.eventType == .accessoryAdded {
                pickerSelectedID = event.accessory?.bluetoothIdentifier
            }
            refresh()
        case .accessoryDiscovered:
            if #available(iOS 26.1, *) { updateDiscoveredAccessory(event.accessory) }
        case .pickerDidPresent:
            traceNames("pickerDidPresent")
            pickerUpdates.isPresented = true
            if #available(iOS 26.1, *) { schedulePickerUpdate() }
        case .migrationComplete:
            if setupState.kind == .migration {
                finishPicker(.migrationComplete, error: event.error ?? pickerError)
            } else {
                refresh()
            }
        case .pickerSetupFailed:
            traceNames("pickerSetupFailed", accessory: event.accessory, details: "error=\(String(describing: event.error))")
            pickerError = event.error ?? RadioConnectionError.pairingRequired
        case .pickerDidDismiss:
            traceNames("pickerDidDismiss", peripheralID: pickerSelectedID)
            finishPicker(.pickerDismissed, error: pickerError ?? (pickerSelectedID == nil ? pickerUpdateError : nil))
        case .invalidated:
            let error = event.error ?? RadioConnectionError.bluetoothUnavailable
            activationFailed(error)
        default: break
        }
    }

    private func finishPicker(_ completion: RadioAccessorySetupState.Completion, error: (any Error)?) {
        guard setupState.finish(completion) else { return }
        traceNames("finish", peripheralID: pickerSelectedID,
                   details: "completion=\(completion) reports=\(pickerDiscoveryReports) namedReports=\(pickerNamedReports) entries=\(pickerDiscoveries.entries.count) error=\(String(describing: error))")
        Self.logger.notice("radio picker finished: discoveryReports=\(self.pickerDiscoveryReports) namedReports=\(self.pickerNamedReports) entries=\(self.pickerDiscoveries.entries.count) selected=\(self.pickerSelectedID != nil) updateFailed=\(self.pickerUpdateError != nil)")
        // Ignore a delayed completion callback from this showPicker request.
        pickerGeneration = UUID()
        let waiter = pickerWaiter
        pickerWaiter = nil
        pickerError = nil
        pickerDiscoveries.removeAll()
        pickerUpdates = RadioPickerUpdates()
        pickerPublishScheduled = false
        pickerUpdateError = nil
        inventory.pickerActive = setupState.isActive
        if session != nil { refresh() } else { publish() }
        if let error { waiter?.resume(throwing: error) }
        else { waiter?.resume() }
    }

    private func descriptor() -> ASDiscoveryDescriptor {
        let descriptor = ASDiscoveryDescriptor()
        descriptor.bluetoothServiceUUID = RadioGatt.service
        descriptor.supportedOptions = [.bluetoothPairingLE]
        return descriptor
    }

    @available(iOS 26.1, *)
    private func updateDiscoveredAccessory(_ accessory: ASAccessory?) {
        guard setupState.kind == .addition else { return }
        pickerDiscoveryReports += 1
        guard let accessory = accessory as? ASDiscoveredAccessory else {
            traceNames("discovery-invalid", accessory: accessory)
            Self.logger.error("Radio discovery event has no discovered accessory")
            return
        }
        let advertisement = accessory.bluetoothAdvertisementData
        let advertisedName = advertisement?[CBAdvertisementDataLocalNameKey] as? String
        let manufacturerData = advertisement?[CBAdvertisementDataManufacturerDataKey] as? Data
        let modelID = RadioPairingPresentation.modelID(manufacturerData: manufacturerData)
        let hasName = RadioPairingPresentation.name(advertisedName: advertisedName) != nil
        if hasName { pickerNamedReports += 1 }
        let keys = advertisement?.keys.map { String(describing: $0) }.sorted().joined(separator: ",") ?? "none"
        Self.logger.notice("radio discovery: report=\(self.pickerDiscoveryReports) hasBluetoothID=\(accessory.bluetoothIdentifier != nil) hasName=\(hasName) nameBytes=\(advertisedName?.utf8.count ?? 0) fields=\(keys, privacy: .public)")
        traceNames("discovery", accessory: accessory,
                   details: "report=\(pickerDiscoveryReports) advertisedName=\(Self.traceName(advertisedName)) manufacturerData=\(manufacturerData.map { $0.map { String(format: "%02x", $0) }.joined() } ?? "nil") modelName=\(Self.traceName(RadioBoardCatalog.bundled.board(modelID: modelID)?.name)) fields=\(keys)")
        let changed = pickerDiscoveries.update(
            accessory, bluetoothID: accessory.bluetoothIdentifier,
            advertisedName: advertisedName, modelID: modelID
        )
        traceNames("discovery-result", accessory: accessory,
                   details: "report=\(pickerDiscoveryReports) hasName=\(hasName) changed=\(changed) entries=\(pickerDiscoveries.entries.count)")
        guard changed else { return }
        pickerUpdates.changed()
        schedulePickerUpdate()
    }

    @available(iOS 26.1, *)
    private func schedulePickerUpdate() {
        guard setupState.kind == .addition, !pickerPublishScheduled else { return }
        pickerPublishScheduled = true
        let generation = pickerGeneration
        Task { @MainActor [weak self] in
            // Coalesce a discovery burst and return from the framework's
            // event callback before submitting the latest snapshot.
            try? await Task.sleep(for: .milliseconds(50))
            guard let self, self.pickerGeneration == generation else { return }
            self.pickerPublishScheduled = false
            self.submitDiscoveredAccessories()
        }
    }

    @available(iOS 26.1, *)
    private func submitDiscoveredAccessories() {
        guard setupState.kind == .addition, let session else { return }
        guard let attempt = pickerUpdates.begin() else { return }
        let items = pickerDiscoveries.entries.enumerated().compactMap { index, entry -> ASDiscoveredDisplayItem? in
            guard let discovered = entry.accessory as? ASDiscoveredAccessory else { return nil }
            let item = ASDiscoveredDisplayItem(
                name: entry.name ?? "UMSH radio", productImage: Self.pickerImage(model: entry.modelID),
                accessory: discovered
            )
            item.descriptor.supportedOptions = [.bluetoothPairingLE]
            traceNames("submit-item", accessory: discovered,
                       details: "attempt=\(attempt.number) revision=\(attempt.revision) entry=\(index) submittedName=\(Self.traceName(item.name))")
            return item
        }
        Self.logger.notice("updating radio picker: attempt=\(attempt.number) revision=\(attempt.revision) entries=\(items.count)")
        let generation = pickerGeneration
        session.updatePicker(showing: items) { [weak self] error in
            Task { @MainActor in
                self?.completePickerUpdate(attempt, generation: generation, error: error)
            }
        }
        // On a physical iPhone, ASK has displayed and paired an accessory
        // without invoking this completion. It cannot gate later discoveries
        // or justify a timeout error while the picker is working.
        Self.logger.notice("radio picker update submitted: attempt=\(attempt.number)")
        traceNames("update-returned", details: "attempt=\(attempt.number) revision=\(attempt.revision) entries=\(items.count)")
    }

    @available(iOS 26.1, *)
    private func completePickerUpdate(_ attempt: RadioPickerUpdates.Attempt, generation: UUID, error: (any Error)?) {
        // Log even stale callbacks, distinguishing API return from completion.
        traceNames("update-callback",
                   details: "request=\(generation.uuidString.prefix(8)) attempt=\(attempt.number) revision=\(attempt.revision) currentPicker=\(pickerGeneration == generation && setupState.kind == .addition) error=\(String(describing: error))")
        guard pickerGeneration == generation, setupState.kind == .addition else { return }
        let completion = pickerUpdates.complete(attempt, succeeded: error == nil)
        traceNames("update-result", details: "attempt=\(attempt.number) result=\(completion)")
        guard completion != .ignored else { return }
        pickerUpdateError = error
        if let error {
            let nsError = error as NSError
            Self.logger.error("Could not update radio setup names: attempt=\(attempt.number) domain=\(nsError.domain, privacy: .public) code=\(nsError.code) \(error.localizedDescription, privacy: .public)")
        } else {
            Self.logger.notice("radio picker update completed: attempt=\(attempt.number)")
        }
        switch completion {
        case .retry(let delay):
            Task { @MainActor [weak self] in
                try? await Task.sleep(for: .seconds(delay))
                guard let self, self.pickerGeneration == generation else { return }
                self.pickerUpdates.retryReady()
                self.schedulePickerUpdate()
            }
        case .updated:
            schedulePickerUpdate()
        case .exhausted, .ignored:
            break
        }
    }

    private static func pickerImage(model: UInt16? = nil) -> UIImage {
        if let name = RadioBoardCatalog.bundled.board(modelID: model)?.photo, let photo = UIImage(named: name) {
            return photo
        }
        return UIImage(systemName: "antenna.radiowaves.left.and.right")!
            .withTintColor(.systemBlue, renderingMode: .alwaysOriginal)
    }

    private func showPicker(migrating id: UUID? = nil) async throws {
        try await activate()
        try Task.checkCancellation()
        guard UIApplication.shared.applicationState == .active else {
            throw RadioConnectionError.operationRejected("Open the app to finish radio setup.")
        }
        guard let session, !setupState.isActive else { throw RadioConnectionError.operationInProgress }
        let image = Self.pickerImage()
        var filteredDiscovery = false
        if #available(iOS 26.1, *) {
            // Migration keeps its existing completion semantics and saved name.
            if id == nil {
                let settings = ASPickerDisplaySettings.default
                settings.options.insert(.filterDiscoveryResults)
                session.pickerDisplaySettings = settings
                filteredDiscovery = true
                Self.logger.debug("radio picker: filtered discovery enabled")
            } else {
                session.pickerDisplaySettings = nil
            }
        }
        let item: ASPickerDisplayItem
        if let id {
            let migration = ASMigrationDisplayItem(
                name: defaults.string(forKey: "radio.deviceName") ?? "UMSH radio",
                productImage: image, descriptor: descriptor()
            )
            migration.peripheralIdentifier = id
            item = migration
        } else {
            item = ASPickerDisplayItem(name: "UMSH radio", productImage: image, descriptor: descriptor())
        }
        guard setupState.begin(id == nil ? .addition : .migration) else {
            throw RadioConnectionError.operationInProgress
        }
        inventory.pickerActive = setupState.isActive
        pickerSelectedID = nil
        pickerDiscoveries.removeAll()
        pickerUpdates = RadioPickerUpdates()
        pickerPublishScheduled = false
        pickerUpdateError = nil
        pickerDiscoveryReports = 0
        pickerNamedReports = 0
        pickerError = nil
        let generation = UUID()
        pickerGeneration = generation
        #if DEBUG
        nameTraceSession = String(generation.uuidString.prefix(8))
        nameTraceStarted = ProcessInfo.processInfo.systemUptime
        nameTraceSequence = 0
        nameTracePeripheralIDs.removeAll()
        #endif
        traceNames("begin", peripheralID: id,
                   details: "kind=\(id == nil ? "addition" : "migration") iOS=\(UIDevice.current.systemVersion) filtered=\(filteredDiscovery) initialName=\(Self.traceName(item.name))")
        publish()
        try await withCheckedThrowingContinuation { continuation in
            pickerWaiter = continuation
            session.showPicker(for: [item]) { [weak self] error in
                // Success means presentation succeeded, not that the user
                // finished. Wait for pickerDidDismiss for additions, or
                // migrationComplete for a migration-only request.
                Task { @MainActor in
                    guard let self else { return }
                    self.traceNames("show-callback",
                                    details: "request=\(generation.uuidString.prefix(8)) currentPicker=\(self.pickerGeneration == generation) error=\(String(describing: error))")
                    guard self.pickerGeneration == generation, let error else { return }
                    self.finishPicker(.failed, error: error)
                }
            }
        }
    }

    @discardableResult
    func addRadio() async throws -> UUID? {
        try await activate()
        if inventory.migrationID != nil {
            return try await finishSetup()
        } else {
            try await showPicker()
            return pickerSelectedID
        }
    }

    /// A recovery button must not open Add Another Radio if another action
    /// completed the migration between rendering the button and handling it.
    func finishSetup() async throws -> UUID? {
        try await activate()
        guard let id = inventory.migrationID else { return nil }
        try await showPicker(migrating: id)
        return inventory.authorizedIDs.contains(id) ? id : nil
    }

    func prepareSelection(_ id: UUID) async throws -> RadioAccessoryInventory {
        try await activate()
        if inventory.migrationID == id { try await showPicker(migrating: id) }
        try Task.checkCancellation()
        guard inventory.permitsConnection(to: id) else {
            Self.logger.notice("selection blocked: ready=\(self.inventory.ready) setupActive=\(self.setupState.isActive) migrationPending=\(self.inventory.migrationID != nil) authorized=\(self.inventory.authorizedIDs.contains(id))")
            throw RadioConnectionError.operationRejected(
                inventory.connectionBlockDescription
                    ?? "This radio is no longer authorized. Open its pairing window and add it again."
            )
        }
        return inventory
    }

    func remove(_ id: UUID) async throws {
        try await activate()
        guard !inventory.pickerActive else { throw RadioConnectionError.operationInProgress }
        if let accessory = session?.accessories.first(where: { $0.bluetoothIdentifier == id }) {
            try await session?.removeAccessory(accessory)
        } else if inventory.migrationID == id {
            // Explicitly abandoning a legacy entry must not cause a new
            // migration prompt on every launch. This doesn't erase its bond.
            var managed = Set(defaults.stringArray(forKey: managedKey) ?? [])
            managed.insert(id.uuidString)
            defaults.set(managed.sorted(), forKey: managedKey)
        }
        refresh()
    }
}
