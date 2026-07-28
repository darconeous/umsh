import SwiftUI
import UMSHMobileCore

/// What the operator is trying to accomplish, chosen before any device is
/// touched.
///
/// The goal never restricts what can be edited — every flow lands in the
/// same editor against the same device domain. What it changes is the
/// starting point: a tracker and a repeater differ by two properties, and
/// asking up front is cheaper than making someone infer which two.
enum DeviceSetupGoal: String, CaseIterable, Identifiable, Hashable {
    /// A node that reports its own position and does not forward.
    case tracker
    /// A node that forwards other people's traffic.
    case repeaterNode
    /// Adopt the device as this phone's companion radio.
    case companion
    /// Open the editor on whatever the device already is.
    case revisit

    var id: String { rawValue }

    var title: String {
        switch self {
        case .tracker: "Set up a tracker"
        case .repeaterNode: "Set up a repeater"
        case .companion: "Use as this phone's radio"
        case .revisit: "Change a device's settings"
        }
    }

    var detail: String {
        switch self {
        case .tracker:
            "A mobile node that carries its own identity and does not forward other traffic."
        case .repeaterNode:
            "A node that forwards traffic for the mesh, optionally limited to particular routing regions."
        case .companion:
            "Bind the device to this phone as its companion radio. This phone's messages go through it."
        case .revisit:
            "Connect to a device that is already set up and edit what it is doing."
        }
    }

    var symbol: String {
        switch self {
        case .tracker: "location.circle"
        case .repeaterNode: "arrow.triangle.branch"
        case .companion: "iphone.radiowaves.left.and.right"
        case .revisit: "slider.horizontal.3"
        }
    }

    var scanTitle: String {
        self == .companion ? "Choose a Radio" : "Choose a Device"
    }
}

/// The state behind the device-setup sheet.
///
/// This is a deliberate, contained exception to the app's no-view-model
/// rule. The flow owns a live BLE session whose lifetime spans several
/// pushed screens and must be torn down exactly once, no matter which
/// screen the user leaves from — that is object lifetime, not view state,
/// and modelling it as the latter is what makes leaked connections.
///
/// It is scoped to the sheet: nothing outside `Features/DeviceSetup`
/// observes it, and it is released when the sheet closes.
@MainActor
@Observable
final class AdminFlowController {
    enum Step: Hashable {
        case scan
        case configure
    }

    private(set) var goal: DeviceSetupGoal = .revisit
    var path: [Step] = []
    private(set) var snapshot = AdministeredDeviceSnapshot.idle
    private(set) var devices: [DiscoveredRadio] = []
    /// The device a connect or promotion is currently in flight for.
    private(set) var busyDevice: UUID?
    var problem: String?
    /// Set once the device has been adopted as the companion radio; the
    /// sheet closes on it, because from that point the ordinary companion
    /// screens own the device.
    private(set) var promoted = false
    /// A device awaiting confirmation that it should displace the radio
    /// this phone already uses.
    var pendingPromotion: UUID?

    /// The phone's current companion radio, so the flow can mark it in the
    /// scan list and warn before replacing it.
    let companionIdentifier: UUID?
    let companionName: String?

    private let hostIdentity: MeshPublicIdentity?
    private let promoteRadio: (UUID) async throws -> Void
    private let session = AdministrativeDeviceSession()
    private var snapshotTask: Task<Void, Never>?
    private var discoveryTask: Task<Void, Never>?

    init(
        hostIdentity: MeshPublicIdentity?,
        companionIdentifier: UUID?,
        companionName: String?,
        promoteRadio: @escaping (UUID) async throws -> Void
    ) {
        self.hostIdentity = hostIdentity
        self.companionIdentifier = companionIdentifier
        self.companionName = companionName
        self.promoteRadio = promoteRadio
    }

    var isBusy: Bool { busyDevice != nil }

    /// Whether administering `device` would fight the companion connection
    /// for the same peripheral.
    func isCompanion(_ device: DiscoveredRadio) -> Bool {
        device.id == companionIdentifier
    }

    // MARK: - Lifecycle

    func begin() async {
        guard snapshotTask == nil else { return }
        // Only for classifying the device's host key. An administrative
        // session never writes it.
        try? await session.useHostIdentity(hostIdentity)
        let session = session
        snapshotTask = Task { @MainActor [weak self] in
            for await next in await session.snapshots() {
                guard let self else { return }
                snapshot = next
                if next.linkState == .failed, let description = next.problemDescription {
                    problem = description
                }
            }
        }
    }

    /// Release the BLE session. Safe to call more than once and from a
    /// disappearing view.
    func end() async {
        discoveryTask?.cancel()
        discoveryTask = nil
        snapshotTask?.cancel()
        snapshotTask = nil
        await session.disconnect()
    }

    func choose(_ goal: DeviceSetupGoal) {
        self.goal = goal
        problem = nil
        path = [.scan]
    }

    // MARK: - Discovery

    func startDiscovery() {
        guard discoveryTask == nil else { return }
        let session = session
        let companion = companionIdentifier
        discoveryTask = Task { @MainActor [weak self] in
            for await list in await session.discover(companionIdentifier: companion) {
                self?.devices = list
            }
        }
    }

    func stopDiscovery() async {
        discoveryTask?.cancel()
        discoveryTask = nil
        devices = []
        await session.stopDiscovery()
    }

    // MARK: - Selection

    func select(_ device: DiscoveredRadio) async {
        guard busyDevice == nil else { return }
        busyDevice = device.id
        problem = nil
        defer { busyDevice = nil }
        if goal == .companion {
            requestPromotion(device.id)
            return
        }
        do {
            try await session.connect(device.id)
            path = [.scan, .configure]
        } catch {
            problem = """
                Could not set up that device. It may have moved out of range, \
                or it may not be a UMSH device.
                """
        }
    }

    /// Begin adopting `identifier`, asking first when doing so would
    /// displace the radio this phone is already using.
    func requestPromotion(_ identifier: UUID) {
        guard companionIdentifier != nil else {
            Task { await adoptAsCompanion(identifier) }
            return
        }
        pendingPromotion = identifier
    }

    func confirmPromotion() async {
        guard let identifier = pendingPromotion else { return }
        pendingPromotion = nil
        await adoptAsCompanion(identifier)
    }

    /// Hand the device over to the companion connection.
    ///
    /// The administrative link is dropped *first* — including its claim on
    /// the peripheral — so the companion path connects to a device nobody
    /// else is holding, and the registry never has a stale entry for a
    /// device the companion now owns.
    func adoptAsCompanion(_ identifier: UUID) async {
        do {
            await end()
            try await promoteRadio(identifier)
            promoted = true
        } catch {
            problem = """
                That device could not be adopted as this phone's radio. \
                Try again from the companion radio screen.
                """
        }
    }

    // MARK: - Configuration

    /// Write the configuration, then read the device back. Returns the
    /// device's own post-save state, or nil if the write did not land.
    func configure(_ configuration: UlcpDeviceConfigRecord) async -> UlcpSyncRecord? {
        problem = nil
        do {
            try await session.configureDevice(configuration)
            try await session.refresh()
            return snapshot.sync
        } catch {
            problem = """
                The device rejected these settings. Its previous configuration \
                is still in effect.
                """
            return nil
        }
    }
}

/// Guided setup for a device this phone is not tethered to.
///
/// Nothing here touches the companion radio: the sheet runs its own BLE
/// session, and the only path that changes which radio this phone uses is
/// the explicit "use as this phone's radio" choice.
struct DeviceSetupFlowView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var controller: AdminFlowController

    init(
        hostIdentity: MeshPublicIdentity?,
        companionIdentifier: UUID?,
        companionName: String?,
        promoteRadio: @escaping (UUID) async throws -> Void
    ) {
        _controller = State(
            initialValue: AdminFlowController(
                hostIdentity: hostIdentity,
                companionIdentifier: companionIdentifier,
                companionName: companionName,
                promoteRadio: promoteRadio
            )
        )
    }

    var body: some View {
        NavigationStack(path: $controller.path) {
            goalChooser
                .navigationDestination(for: AdminFlowController.Step.self) { step in
                    switch step {
                    case .scan:
                        DeviceScanView(controller: controller)
                    case .configure:
                        if let sync = controller.snapshot.sync {
                            DeviceConfigView(
                                controller: controller,
                                sync: sync,
                                finish: { dismiss() }
                            )
                        } else {
                            ContentUnavailableView(
                                "Configuration unavailable",
                                systemImage: "antenna.radiowaves.left.and.right.slash",
                                description: Text(
                                    "The device did not finish reporting its settings. Go back and connect to it again."
                                )
                            )
                        }
                    }
                }
        }
        .task { await controller.begin() }
        .onChange(of: controller.promoted) { _, promoted in
            if promoted { dismiss() }
        }
        .confirmationDialog(
            "Replace this phone's radio?",
            isPresented: Binding(
                get: { controller.pendingPromotion != nil },
                set: { if !$0 { controller.pendingPromotion = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Use This Device", role: .destructive) {
                Task { await controller.confirmPromotion() }
            }
            Button("Cancel", role: .cancel) { controller.pendingPromotion = nil }
        } message: {
            Text(controller.companionName.map {
                "This phone stops using \($0) and connects to the chosen device instead. \($0) keeps its own settings and Bluetooth pairing."
            } ?? "This phone connects to the chosen device instead of its current radio.")
        }
        .onDisappear {
            Task { await controller.end() }
        }
    }

    private var goalChooser: some View {
        List {
            Section {
                ForEach(DeviceSetupGoal.allCases) { goal in
                    Button { controller.choose(goal) } label: {
                        Label {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(goal.title)
                                    .foregroundStyle(.primary)
                                Text(goal.detail)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        } icon: {
                            Image(systemName: goal.symbol)
                        }
                    }
                }
            } header: {
                Text("What is this device for?")
            } footer: {
                Text("Setting up a device does not change which radio this phone uses, and the device is not claimed by this phone. Its own Bluetooth pairing still applies.")
            }

            if let companionName = controller.companionName {
                Section {
                    LabeledContent("This phone's radio", value: companionName)
                } footer: {
                    Text("The companion radio stays connected while you set up another device.")
                }
            }
        }
        .navigationTitle("Set Up a Device")
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
        }
    }
}
