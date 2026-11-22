import Foundation
import UMSHMobileCore

/// One device being managed, as the screens read it: a thin view over the
/// core's `MobileManagedDevice`, which holds the queue, the cache, the
/// readings and every rule about them.
///
/// Rebuilt from the core's published snapshot whenever the core says the
/// device changed (``deviceChanged()``, called by `AppRuntime`'s drain) and
/// after each call this model forwards, so a screen that awaits a call
/// reads its result at once. Several models may share one device: every
/// screen on a node gets its own handle on the same engine.
@MainActor
@Observable
final class ManageDeviceModel: ManagedDeviceObserver {
    /// The core's handle. Not observed: only the snapshot is.
    @ObservationIgnored nonisolated let device: MobileManagedDevice
    /// The engine's id, which the changes record names.
    @ObservationIgnored nonisolated let deviceID: UInt64
    /// Everything the core last published about the device.
    private(set) var snapshot: MobileManagedDeviceRecord
    /// What each category last read, rebuilt per snapshot.
    private(set) var readings: [UlcpManageCategory: RemoteCategoryReading] = [:]
    /// Values the device rejected on the last apply, by property, worded
    /// for the row that offered the value.
    private(set) var writeRefusals: [UlcpManageCategory: [UInt32: String]] = [:]
    /// A call the core refused outright (the core stopping, say), which no
    /// snapshot carries.
    private var refusedCall: MobileManagementProblem?

    /// The node's address, for the screens that show it. Empty for a radio
    /// with no identity of its own.
    let address: String
    /// What to call the device before it has said. The peer's own name.
    let fallbackName: String
    /// Run once, when the device confirms firmware update entry. The setup
    /// flow ends its session here, whichever screen asked for the entry.
    @ObservationIgnored var onEnteredDfu: (@MainActor () -> Void)?

    init(device: MobileManagedDevice, address: String, fallbackName: String) {
        self.device = device
        deviceID = device.id()
        self.address = address
        self.fallbackName = fallbackName
        snapshot = device.snapshot()
        rebuild(from: nil)
    }

    deinit { device.release() }

    /// This screen is done with the device. Idempotent; the last handle on
    /// a device to go relinquishes it.
    nonisolated func release() { device.release() }

    /// Read the core's snapshot again.
    func deviceChanged() {
        let next = device.snapshot()
        guard next.revision != snapshot.revision else { return }
        let previous = snapshot
        snapshot = next
        rebuild(from: previous)
        if next.enteredDfu, !previous.enteredDfu { onEnteredDfu?() }
    }

    private func rebuild(from previous: MobileManagedDeviceRecord?) {
        let earlier = Dictionary(
            (previous?.readings ?? []).map { ($0.category, $0.revision) },
            uniquingKeysWith: { first, _ in first }
        )
        var next: [UlcpManageCategory: RemoteCategoryReading] = [:]
        var refusals: [UlcpManageCategory: [UInt32: String]] = [:]
        for record in snapshot.readings {
            if let kept = readings[record.category], earlier[record.category] == record.revision {
                next[record.category] = kept
            } else {
                next[record.category] = RemoteCategoryReading(record)
            }
            if !record.refusals.isEmpty {
                refusals[record.category] = Dictionary(
                    record.refusals.map { ($0.propertyId, RefusalText.row($0.refusal)) },
                    uniquingKeysWith: { first, _ in first }
                )
            }
        }
        readings = next
        if refusals != writeRefusals { writeRefusals = refusals }
    }

    // MARK: - What the screens read

    var card: UlcpDeviceCardRecord? { snapshot.card }
    var cardAsOf: Date? { snapshot.cardAsOfMs.map(Date.init(storeMilliseconds:)) }
    var alert: RadioAlertState { RadioAlertState(snapshot.alert) }
    var isBusy: Bool { snapshot.busy }
    var enteredDfu: Bool { snapshot.enteredDfu }
    var problem: MobileManagementProblem? { snapshot.problem ?? refusedCall }
    var phoneNodeKey: Data? { snapshot.phoneNodeKey }
    var link: MobileManagementLink { snapshot.link }
    var usesBluetooth: Bool { snapshot.usesBluetooth }
    var offersFactoryReset: Bool { snapshot.offersFactoryReset }
    var phoneStandsForDevice: Bool { snapshot.phoneStandsForDevice }
    var supportsWifiStation: Bool { snapshot.supportsWifiStation }
    var supportsBluetoothPairing: Bool { snapshot.supportsBluetoothPairing }
    /// Whether this device says it can restart on command (`CAP_REBOOT`).
    var supportsRestart: Bool { card?.supportsReboot ?? false }
    /// What to show as the device's name: what it calls itself, then what
    /// this phone calls it.
    var displayName: String { card?.deviceName ?? fallbackName }
    /// What a scan heard, strongest first, one row per network.
    var heardNetworks: [MobileHeardNetworkRecord] { snapshot.heardNetworks }

    /// What one category covers on this device, or nothing when the device
    /// has none of it. Read off the card, so a section can be gated before
    /// its reading exists.
    func properties(of category: UlcpManageCategory) -> [UInt32] {
        snapshot.categories.first { $0.category == category }?.propertyIds ?? []
    }

    // MARK: - Reads

    func loadCard() async { await forward { try await $0.loadCard() } }
    func refreshCard() async { await forward { try await $0.refreshCard() } }
    func loadCategory(_ category: UlcpManageCategory) async {
        await forward { try await $0.loadCategory(category: category) }
    }
    func refreshCategory(_ category: UlcpManageCategory) async {
        await forward { try await $0.refreshCategory(category: category) }
    }

    // MARK: - Writes

    /// Write what an editor's draft changed, and save. The core judges the
    /// draft against the device as it is when the apply runs.
    func apply(_ draft: MobileManagementDraft) async -> MobileApplyOutcome {
        await forward(failed: MobileApplyOutcome(answered: false, result: .cancelled)) {
            try await $0.apply(draft: draft)
        }
    }

    func setClockNow() async { await forward { try await $0.setClockNow() } }
    func resetCounters() async { await forward { try await $0.resetCounters() } }

    func setKeys(_ desired: Set<Data>, table: MobileKeyTable) async {
        await forward { try await $0.setKeys(table: table, desired: Array(desired)) }
    }

    // MARK: - Wi-Fi

    func scanNetworks() async { await forward { try await $0.scanNetworks() } }

    func joinNetwork(
        ssid: Data, security: UInt8, hidden: Bool, credential: Data, offered: UInt16?
    ) async -> MobileWifiOutcome {
        await forward(failed: .cancelled) {
            try await $0.joinNetwork(
                ssid: ssid, security: security, hidden: hidden,
                credential: credential, offered: offered
            )
        }
    }

    func updateNetwork(
        ssid: Data, security: UInt8, hidden: Bool, autoJoin: Bool, credential: Data
    ) async -> MobileWifiOutcome {
        await forward(failed: .cancelled) {
            try await $0.updateNetwork(
                ssid: ssid, security: security, hidden: hidden,
                autoJoin: autoJoin, credential: credential
            )
        }
    }

    func joinKnownNetwork(ssid: Data) async {
        await forward { try await $0.joinKnownNetwork(ssid: ssid) }
    }
    func disconnectNetwork() async { await forward { try await $0.disconnectNetwork() } }
    func setAutoJoin(_ network: UlcpWifiNetworkRecord, _ autoJoin: Bool) async {
        await forward { try await $0.setAutoJoin(ssid: network.ssid, autoJoin: autoJoin) }
    }
    func forgetNetwork(ssid: Data) async {
        await forward { try await $0.forgetNetwork(ssid: ssid) }
    }

    // MARK: - Acting on the device

    func setAlert(_ state: RadioAlertState) async {
        await forward { try await $0.setAlert(state: state.wire) }
    }
    func enterDfu(_ mode: UlcpDfuMode) async { await forward { try await $0.enterDfu(mode: mode) } }
    func restart() async { await forward { try await $0.restart() } }
    func announce(_ kind: MobileAnnouncementKind, reach: MobileAnnouncementReach) async {
        await forward { try await $0.announce(kind: kind, reach: reach) }
    }
    func clearBluetoothPairings() async {
        await forward { try await $0.clearBluetoothPairings() }
    }
    func factoryReset() async { await forward { try await $0.factoryReset() } }

    // MARK: - Control

    /// The operator's Cancel: everything asked of the device and not yet
    /// finished, whichever screen asked.
    func cancel() { device.cancel() }

    func dismissProblem() {
        refusedCall = nil
        device.dismissProblem()
        deviceChanged()
    }

    /// Run one call on the device, then read what it published.
    @discardableResult
    private func forward(
        _ call: @Sendable (MobileManagedDevice) async throws -> MobileManagementOutcome
    ) async -> MobileManagementOutcome {
        await forward(failed: .cancelled, call)
    }

    private func forward<Outcome: Sendable>(
        failed: Outcome,
        _ call: @Sendable (MobileManagedDevice) async throws -> Outcome
    ) async -> Outcome {
        refusedCall = nil
        let outcome: Outcome
        do {
            outcome = try await call(device)
        } catch {
            refusedCall = Self.problem(for: error)
            outcome = failed
        }
        deviceChanged()
        return outcome
    }

    /// A call the device object itself refused, as the status bar words it.
    static func problem(for error: any Error) -> MobileManagementProblem {
        switch error as? MobileAppError {
        case .Busy: .busy
        case .Stopped: .stopped
        case .InvalidRequest: .invalidRequest
        case .NoOwner: .noOwner
        case .NotRunning: .notRunning
        case .NoRadio: .noRadio
        default: .other
        }
    }
}

/// What a managed device's change notice reaches.
@MainActor
protocol ManagedDeviceObserver: AnyObject {
    nonisolated var deviceID: UInt64 { get }
    func deviceChanged()
}

/// The live models, by the device they show, so the drain can tell each
/// that its device changed. Weak: a model lives as long as its screen.
@MainActor
final class ManagedDeviceRoutes {
    private struct Entry {
        weak var observer: (any ManagedDeviceObserver)?
    }

    private var entries: [UInt64: [Entry]] = [:]

    func register(_ observer: any ManagedDeviceObserver) {
        let id = observer.deviceID
        entries[id, default: []].removeAll { $0.observer == nil }
        entries[id, default: []].append(Entry(observer: observer))
    }

    /// Tell every live model on each of `ids` to read its device again.
    func route(_ ids: [UInt64]) {
        for id in Set(ids) {
            guard let live = entries[id] else { continue }
            let observers = live.compactMap(\.observer)
            if observers.isEmpty {
                entries[id] = nil
            } else {
                entries[id] = observers.map { Entry(observer: $0) }
                for observer in observers { observer.deviceChanged() }
            }
        }
    }
}
