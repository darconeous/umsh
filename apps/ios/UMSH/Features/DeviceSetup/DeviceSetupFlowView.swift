import SwiftUI
import UMSHMobileCore

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
        /// The goal's short sheet.
        case commission
        /// Every setting the device supports.
        case editor
    }

    private(set) var goal: DeviceSetupGoal = .revisit
    var plan: DeviceSetupPlan { goal.plan }
    var path: [Step] = []
    private(set) var snapshot = AdministeredDeviceSnapshot.idle
    private(set) var devices: [DiscoveredRadio] = []
    /// The configuration being edited, for as long as a device is attached.
    ///
    /// Owned here rather than by a screen because its lifetime is the
    /// session's, not any one view's — and because a navigation destination
    /// holding it as `@State` would fork it the moment a second screen
    /// pushed over the same device.
    private(set) var draft: DeviceConfigDraft?
    /// The device a connect is currently in flight for.
    private(set) var busyDevice: UUID?
    /// Its advertised name, captured at the tap: connecting stops the scan and
    /// empties the list, so by the time anything wants to say which device is
    /// being waited on, the row it came from is gone.
    private(set) var connectingName: String?
    var problem: String?

    /// The phone's current companion radio, so the flow can mark it in the
    /// scan list. It is never selectable here — the companion connection
    /// already holds that peripheral.
    let companionIdentifier: UUID?
    let companionName: String?
    /// The PHY a commissioned device is put on, taken from the phone's own
    /// radio.
    ///
    /// Captured when the sheet opens rather than sampled live. A mesh profile
    /// that changed halfway through a commissioning session would be worse
    /// than a slightly stale one — the operator would have no way to know
    /// which of the two any given device ended up on.
    let companionProfile: CompanionRadioProfile?

    private let hostIdentity: MeshPublicIdentity?
    private let saveDevicePeer: ((MeshPublicIdentity, String?, PeerRole) async -> Bool)?
    private let session = AdministrativeDeviceSession()
    private var snapshotTask: Task<Void, Never>?
    private var discoveryTask: Task<Void, Never>?

    init(
        hostIdentity: MeshPublicIdentity?,
        companionIdentifier: UUID?,
        companionName: String?,
        companionProfile: CompanionRadioProfile? = nil,
        saveDevicePeer: ((MeshPublicIdentity, String?, PeerRole) async -> Bool)? = nil
    ) {
        self.hostIdentity = hostIdentity
        self.companionIdentifier = companionIdentifier
        self.companionName = companionName
        self.companionProfile = companionProfile
        self.saveDevicePeer = saveDevicePeer
    }

    /// Record the device being configured as a peer, so the operator can
    /// find it in Peers after the sheet closes. Nothing about the setup
    /// session itself is persisted.
    func savePeer(role: PeerRole) async -> Bool {
        guard let saveDevicePeer, let identity = snapshot.deviceIdentity else { return false }
        return await saveDevicePeer(identity, snapshot.name, role)
    }

    var canSavePeer: Bool { saveDevicePeer != nil }

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

    /// This phone's own node key.
    ///
    /// Derived from the identity this session classifies host keys against
    /// rather than asked of the mesh session, which the setup sheet has no
    /// business holding: an address is that key rendered, so these are the
    /// same bytes `MobileMeshSession.nodePublicKey()` reports.
    private var phoneNodeKey: Data? {
        hostIdentity.flatMap {
            try? UMSHMobileCore.publicIdentityBytes(address: $0.canonicalAddress)
        }
    }

    /// Build the draft from what the device reported as it attached.
    private func makeDraft(_ sync: UlcpSyncRecord) -> DeviceConfigDraft {
        let plan = plan
        return DeviceConfigDraft(
            sync: sync,
            reportedName: snapshot.name,
            plan: plan,
            // The editor asks about every radio parameter directly, so it
            // opens on what the device already holds. Only a sheet that
            // decided the profile has one to explain.
            resolvedProfile: plan.isAbbreviated
                ? .resolve(companion: companionProfile, target: sync)
                : nil,
            phoneNodeKey: phoneNodeKey,
            writer: self
        )
    }

    /// Release the BLE session. Safe to call more than once and from a
    /// disappearing view.
    func end() async {
        draft = nil
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

    /// Open the full editor over the device that was just set up, on the same
    /// draft — which is the whole reason the draft is owned here.
    func reviewAllSettings() {
        guard path.last != .editor else { return }
        path.append(.editor)
    }

    /// Let go of this device and start again at the goal chooser, not the scan
    /// list: the next device may be a different kind of thing.
    func startOver() async {
        draft = nil
        problem = nil
        await session.disconnect()
        path = []
    }

    // MARK: - Discovery

    func startDiscovery() {
        guard discoveryTask == nil else { return }
        let session = session
        let companion = companionIdentifier
        discoveryTask = Task { @MainActor [weak self] in
            for await list in await session.discover(companionIdentifier: companion) {
                // Animated here rather than in the view: the list arrives
                // wholesale-replaced, so the view has no change to animate
                // unless the assignment itself carries a transaction.
                withAnimation(.easeInOut(duration: 0.2)) { self?.devices = list }
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
        connectingName = device.name
        problem = nil
        // Backing out of a device and picking another one must not inherit
        // the first one's unsaved edits.
        draft = nil
        // Pushed before the connect rather than after it. Connecting takes
        // seconds — longer against an unbonded device, which puts a system
        // pairing prompt in the way — and `connect` stops the scan, so leaving
        // the operator on the list means watching every device vanish under a
        // screen that claims to be searching for them.
        let step: Step = plan.isAbbreviated ? .commission : .editor
        path = [.scan, step]
        defer { busyDevice = nil }
        do {
            // `connect` resolves with what the device reported rather than
            // leaving this to read `snapshot`, which is mirrored by another
            // task and may still be carrying the pre-attach state.
            let sync = try await session.connect(device.id)
            // The operator may have left while this was in flight. A device
            // they walked away from has to be let go, not pushed at them.
            guard path.last == step else {
                await abandonSelection()
                return
            }
            guard let sync else {
                await refuse("""
                    That device connected but did not report its settings. \
                    It may be running firmware this app does not understand.
                    """)
                return
            }
            // A device that cannot do the thing being asked of it is refused
            // here rather than offered a sheet it would disappoint.
            if let blocker = plan.blocker(for: sync) {
                await refuse(blocker)
                return
            }
            draft = makeDraft(sync)
        } catch {
            guard path.last == step else {
                await abandonSelection()
                return
            }
            // The published snapshot carries the same explanation, but which
            // of the two lands first is not ordered, so this path states the
            // reason itself rather than leaving a generic message to win.
            await refuse(
                (error as? RadioConnectionError) == .pairingRequired
                    ? BluetoothErrorText.notPaired
                    : """
                        Could not set up that device. It may have moved out of \
                        range, or it may not be a UMSH device.
                        """
            )
        }
    }

    /// Send the operator back to the list with the reason this device is not
    /// going to work, and leave them able to pick another one.
    ///
    /// `busyDevice` is cleared before the pop, not after: the list treats a
    /// connect still in flight as something to cancel when it reappears, and
    /// an unwind that still looks busy would have it disconnect on top of the
    /// scan this is in the middle of restarting.
    private func refuse(_ reason: String) async {
        problem = reason
        busyDevice = nil
        path = [.scan]
        await disconnectAndResumeDiscovery()
    }

    private func resumeDiscovery() async {
        await stopDiscovery()
        startDiscovery()
    }

    /// Back out of a device that attached but will not be used, and put the
    /// operator back in front of the list.
    ///
    /// The disconnect is not optional: restarting the scan alone would leave
    /// the peripheral connected and its `AdminSessionRegistry` claim standing,
    /// so the device would keep refusing every later session — including the
    /// next attempt at this one.
    private func disconnectAndResumeDiscovery() async {
        await session.disconnect()
        await resumeDiscovery()
    }

    /// Release a device the operator stopped waiting for, and put the scan
    /// back only if that is where they are. They may have closed the sheet
    /// entirely, and restarting a scan behind a screen nobody is looking at
    /// would keep the radio busy for no one.
    private func abandonSelection() async {
        await session.disconnect()
        if path.last == .scan { await resumeDiscovery() }
    }

    /// Stop waiting for a device mid-connect.
    ///
    /// Disconnecting resolves the pending attach with a failure, so the
    /// selection unwinds through its own error path rather than being left to
    /// finish against a screen that is no longer there. Without it, backing out
    /// leaves the list untappable for as long as the attach budget runs.
    func cancelSelection() async {
        guard busyDevice != nil else { return }
        await session.disconnect()
    }

    // MARK: - Live device controls

    /// Start or stop the device's locate alert. Nothing about it is part of
    /// the configuration write, so it takes effect the moment it is tapped
    /// and is unaffected by applying or abandoning the form.
    func setAlert(_ state: RadioAlertState) async throws {
        try await session.setAlert(state)
    }

    /// Set the device's wall clock, or clear it. Like the alert this is
    /// live rather than configured: it takes effect on tap and is
    /// unaffected by applying or abandoning the form.
    func setTime(epochSeconds: UInt32?) async throws {
        try await session.setTime(epochSeconds: epochSeconds)
    }

    /// Sample where the device is, for the positioning section.
    ///
    /// Silent on failure: it runs on a timer behind a view, and a device
    /// that dropped out mid-poll is already reported by the link state.
    func refreshPositioning() async {
        _ = try? await session.refreshPositioning()
    }

    // MARK: - Configuration

    /// Write the configuration, then read the device back. Returns the
    /// device's own post-save state, or nil if the write did not land.
    ///
    /// The readback is what `refresh` answers with, not what has reached
    /// `snapshot` — the snapshot stream is drained by another task and could
    /// still be carrying the pre-write state when this returns.
    func configure(_ configuration: UlcpDeviceConfigRecord) async -> UlcpSyncRecord? {
        problem = nil
        do {
            try await session.configureDevice(configuration)
            return try await session.refresh()
        } catch {
            problem = Self.writeFailureText(error)
            return nil
        }
    }

    /// Bring the device's administrator list to `keys`.
    ///
    /// The device edits this list an item at a time, so the difference is
    /// applied item by item — and in this order, because a list at capacity
    /// takes a removal but not an addition, and an operator swapping one
    /// administrator for another should not have to know that.
    func setAdministrators(_ keys: [Data]) async throws {
        let desired = Set(keys)
        let current = Set(snapshot.sync?.devAdminKeys ?? [])
        for key in current.subtracting(desired) {
            try await session.setAdministrator(key, present: false)
        }
        for key in desired.subtracting(current) {
            try await session.setAdministrator(key, present: true)
        }
    }

    /// Why a write did not land, in terms that do not accuse the device of
    /// something it did not do.
    ///
    /// A refusal, a device that went quiet, and this app talking over itself
    /// leave the operator in three different places, and calling all three
    /// "the device rejected these settings" sends them looking for a fault in
    /// the two cases where there is none.
    private static func writeFailureText(_ error: any Error) -> String {
        switch error as? RadioConnectionError {
        case .operationTimedOut:
            """
            The device stopped answering while saving. It may or may not have \
            kept these settings — connect to it again and check.
            """
        case .operationInProgress:
            """
            The app was still reading from the device. Wait a moment and try \
            again; nothing was changed on it.
            """
        default:
            """
            The device rejected these settings. Its previous configuration \
            is still in effect.
            """
        }
    }
}

/// Every member already exists above with these signatures; the
/// conformances only narrow what a draft and a form are allowed to reach.
extension AdminFlowController: DeviceAdministering {}

/// Guided setup for a device this phone is not tethered to.
///
/// Nothing here touches the companion radio: the sheet runs its own BLE
/// session, and no path through it changes which radio this phone uses.
/// Adopting a radio belongs to the companion radio screen, which is the one
/// place that decision is made.
struct DeviceSetupFlowView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var controller: AdminFlowController
    /// Held on the view rather than the controller so it is re-read as the
    /// Peers list changes, instead of frozen when the sheet opened.
    private let isPeerSaved: (String) -> Bool
    private let peerActions: PeerActions

    init(
        hostIdentity: MeshPublicIdentity?,
        companionIdentifier: UUID?,
        companionName: String?,
        companionProfile: CompanionRadioProfile? = nil,
        saveDevicePeer: ((MeshPublicIdentity, String?, PeerRole) async -> Bool)? = nil,
        isPeerSaved: @escaping (String) -> Bool = { _ in false },
        peerActions: PeerActions = .unavailable
    ) {
        self.isPeerSaved = isPeerSaved
        self.peerActions = peerActions
        _controller = State(
            initialValue: AdminFlowController(
                hostIdentity: hostIdentity,
                companionIdentifier: companionIdentifier,
                companionName: companionName,
                companionProfile: companionProfile,
                saveDevicePeer: saveDevicePeer
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
                    case .commission:
                        settings(
                            sections: controller.plan.sections,
                            title: controller.plan.title,
                            applyTitle: controller.plan.applyTitle,
                            note: controller.draft.flatMap {
                                controller.plan.note(for: $0.sync)
                            },
                            isCommissioning: true
                        )
                    case .editor:
                        settings(
                            sections: DeviceSetupPlan.revisit.sections,
                            title: controller.snapshot.name ?? "Device",
                            applyTitle: "Apply",
                            note: nil,
                            isCommissioning: false
                        )
                    }
                }
        }
        .task { await controller.begin() }
        .onDisappear {
            Task { await controller.end() }
        }
    }

    /// The settings form over the live draft, or an explanation when the
    /// device never reported enough to build one.
    @ViewBuilder
    private func settings(
        sections: [DeviceSetupSection],
        title: String,
        applyTitle: String,
        note: String?,
        isCommissioning: Bool
    ) -> some View {
        if let draft = controller.draft {
            DeviceSettingsView(
                controller: controller,
                draft: draft,
                sections: sections,
                title: title,
                applyTitle: applyTitle,
                note: note,
                isCommissioning: isCommissioning,
                isPeerSaved: isPeerSaved,
                peerActions: peerActions,
                finish: { dismiss() }
            )
        } else if controller.isBusy {
            // The ordinary case for this screen's first seconds: the device is
            // attaching and there is nothing to edit yet.
            DeviceConnectingView(
                name: controller.connectingName,
                cancel: { controller.path = [.scan] }
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
