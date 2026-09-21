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
    private var setupState = RadioAccessorySetupState()
    private var revision: UInt64 = 0
    private let defaults: UserDefaults
    private let managedKey = "radio.accessories.managedIDs"
    private let namesKey = "radio.accessories.configuredNames"
    private var appIsActive = false
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

    private func refresh() {
        guard let session else { return }
        var names = defaults.dictionary(forKey: namesKey) as? [String: String] ?? [:]
        if let id = legacyID, let name = defaults.string(forKey: "radio.deviceName"),
           names[id.uuidString] == nil, !name.isEmpty {
            names[id.uuidString] = name
        }
        let authorized = session.accessories.compactMap { accessory -> DiscoveredRadio? in
            guard accessory.state == .authorized, let id = accessory.bluetoothIdentifier else { return nil }
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
                sessionGeneration = UUID()
                session?.invalidate()
                session = nil
                inventory.problem = error.localizedDescription
                publish()
                finishActivation(error: error)
                return
            }
            refresh()
            finishActivation()
        case .accessoryAdded, .accessoryChanged, .accessoryRemoved:
            if inventory.pickerActive, event.eventType == .accessoryAdded {
                pickerSelectedID = event.accessory?.bluetoothIdentifier
            }
            refresh()
        case .migrationComplete:
            if setupState.kind == .migration {
                finishPicker(.migrationComplete, error: event.error ?? pickerError)
            } else {
                refresh()
            }
        case .pickerSetupFailed:
            pickerError = event.error ?? RadioConnectionError.pairingRequired
        case .pickerDidDismiss:
            finishPicker(.pickerDismissed, error: pickerError)
        case .invalidated:
            let error = event.error ?? RadioConnectionError.bluetoothUnavailable
            sessionGeneration = UUID()
            session = nil
            inventory.ready = false
            inventory.problem = error.localizedDescription
            finishActivation(error: error)
            if setupState.isActive { finishPicker(.invalidated, error: error) }
            else { publish() }
        default: break
        }
    }

    private func finishPicker(_ completion: RadioAccessorySetupState.Completion, error: (any Error)?) {
        guard setupState.finish(completion) else { return }
        // Ignore a delayed completion callback from this showPicker request.
        pickerGeneration = UUID()
        let waiter = pickerWaiter
        pickerWaiter = nil
        pickerError = nil
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

    private func showPicker(migrating id: UUID? = nil) async throws {
        try await activate()
        try Task.checkCancellation()
        guard UIApplication.shared.applicationState == .active else {
            throw RadioConnectionError.operationRejected("Open the app to finish radio setup.")
        }
        guard let session, !setupState.isActive else { throw RadioConnectionError.operationInProgress }
        let image = UIImage(systemName: "antenna.radiowaves.left.and.right")!
            .withTintColor(.systemBlue, renderingMode: .alwaysOriginal)
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
        pickerError = nil
        let generation = UUID()
        pickerGeneration = generation
        publish()
        try await withCheckedThrowingContinuation { continuation in
            pickerWaiter = continuation
            session.showPicker(for: [item]) { [weak self] error in
                // Success means presentation succeeded, not that the user
                // finished. Wait for pickerDidDismiss for additions, or
                // migrationComplete for a migration-only request.
                Task { @MainActor in
                    guard let self, self.pickerGeneration == generation, let error else { return }
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
