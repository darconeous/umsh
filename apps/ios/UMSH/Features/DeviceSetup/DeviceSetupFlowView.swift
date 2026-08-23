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
        /// The management screens every device gets, over this session.
        case editor
    }

    private(set) var goal: DeviceSetupGoal = .revisit
    var plan: DeviceSetupPlan { goal.plan }
    var path: [Step] = [] {
        didSet { releaseDeviceLeftBehind(oldValue) }
    }
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

    /// Build the draft from what the device reported as it attached. Only a
    /// commissioning goal has one — changing a device's settings edits the
    /// device itself, a screen at a time, rather than a draft of it.
    private func makeDraft(_ sync: UlcpSyncRecord) -> DeviceConfigDraft {
        DeviceConfigDraft(
            sync: sync,
            reportedName: snapshot.name,
            plan: plan,
            resolvedProfile: .resolve(companion: companionProfile, target: sync),
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

    /// Open the management screens over the device that was just set up, on
    /// the same session — so a commissioned device is inspected and adjusted
    /// through the screens every device gets, not a second form.
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
            //
            // A revisit attaches lazily: the management screens read the
            // device a screenful at a time, so an attach that read it
            // whole would spend exactly the time the lazy design exists
            // to save.
            let sync = try await session.connect(device.id, lazyAttach: goal == .revisit)
            // The operator may have left while this was in flight. A device
            // they walked away from has to be let go, not pushed at them.
            guard path.last == step else {
                await abandonSelection()
                return
            }
            if goal == .revisit {
                // No draft: the unified sheet keys everything on the
                // device's identity, which the attach preamble read and
                // the snapshot mirror is about to carry. The editor step
                // renders once it lands, and says so if it never does.
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

    /// Release a device the operator walked back from.
    ///
    /// Every forward transition manages the session itself, but the system
    /// Back button only moves `path` — and a device left attached holds the
    /// BLE link, stops advertising, and can never be offered by the scan
    /// list again, which is exactly where the operator lands next. A
    /// mid-connect back-out is not this: `select` observes the pop itself
    /// and unwinds through `abandonSelection`, which is what the busy
    /// guard leaves to it.
    private func releaseDeviceLeftBehind(_ oldValue: [Step]) {
        let settings: (Step) -> Bool = { $0 == .commission || $0 == .editor }
        guard oldValue.contains(where: settings),
              !path.contains(where: settings),
              busyDevice == nil,
              draft != nil || snapshot.identifier != nil
        else { return }
        draft = nil
        Task { [weak self] in
            guard let self else { return }
            await session.disconnect()
            if path.last == .scan { await resumeDiscovery() }
        }
    }

    // MARK: - The unified management sheet's backend

    /// The attached device as a peer row, which is what the unified
    /// management sheet keys its screens on. `nil` until the attach and
    /// the snapshot mirror have both landed.
    var managedPeer: PeerSummary? {
        guard snapshot.linkState == .attached, let identity = snapshot.deviceIdentity
        else { return nil }
        return PeerSummary(
            id: 0,
            identity: identity,
            alias: nil,
            advertisedName: snapshot.name,
            systemRole: nil,
            storedRole: .unknown
        )
    }

    /// The unified sheet's backend over this flow's own BLE session.
    ///
    /// Deliberately storeless: an administrative link refreshes every
    /// screen on sight, so a cache would only ever be one screen behind —
    /// and a bench flow that remembers nothing leaves nothing to go stale.
    var deviceManagement: DeviceManagementBackend {
        let session = session
        return DeviceManagementBackend(
            link: .administrative,
            fetch: { _, properties, _, _ in
                try await session.fetchProperties(properties)
            },
            write: { _, writes in
                try await session.writeProperties(writes)
            },
            save: { _ in try await session.saveDevice() },
            setAdministrator: { _, key, present in
                try await session.setAdministrator(key, present: present)
            },
            setPeer: { _, key, present in
                try await session.setPeer(key, present: present)
            },
            setAlert: { _, state in
                // The device answers on the session snapshot; what was
                // asked for stands until its own announcement corrects it.
                try await session.setAlert(state)
                return state
            },
            phoneNodeKey: { [key = phoneNodeKey] in key },
            loadCard: { _ in nil },
            saveCard: { _, _ in },
            forgetCache: { _ in },
            loadValues: { _, _ in [:] },
            saveValues: { _, _ in },
            propertyPushes: {
                AsyncStream { continuation in
                    let task = Task {
                        for await push in await session.propertyPushes() {
                            continuation.yield(push)
                        }
                        continuation.finish()
                    }
                    continuation.onTermination = { _ in task.cancel() }
                }
            }
        )
    }

    // MARK: - Live device controls

    /// Set the device's wall clock, or clear it. Live rather than
    /// configured: it takes effect on the spot and is unaffected by
    /// applying or abandoning the sheet.
    func setTime(epochSeconds: UInt32?) async throws {
        try await session.setTime(epochSeconds: epochSeconds)
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
                            }
                        )
                    case .editor:
                        managedDeviceScreen
                    }
                }
        }
        .task { await controller.begin() }
        .onDisappear {
            Task { await controller.end() }
        }
    }

    /// The unified management sheet over this flow's own session — the
    /// same screens a device gets over the mesh or on the companion link,
    /// reading the device a screenful at a time.
    @ViewBuilder
    private var managedDeviceScreen: some View {
        if let peer = controller.managedPeer {
            ManageDeviceScreen(
                peer: peer,
                management: controller.deviceManagement,
                browsing: setupBrowsing
            )
            .safeAreaInset(edge: .bottom) { savePeerBar(peer) }
        } else if controller.snapshot.linkState == .attached
            || controller.snapshot.linkState == .failed
            || controller.snapshot.linkState == .idle {
            ContentUnavailableView(
                "Configuration unavailable",
                systemImage: "antenna.radiowaves.left.and.right.slash",
                description: Text(
                    "The device did not finish reporting its settings. Go back and connect to it again."
                )
            )
        } else {
            DeviceConnectingView(
                name: controller.connectingName,
                cancel: { controller.path = [.scan] }
            )
        }
    }

    /// The one thing the setup flow offers around the sheet: recording the
    /// device in Peers, so the operator can find it again — and manage it
    /// over the mesh — after this session ends.
    @ViewBuilder
    private func savePeerBar(_ peer: PeerSummary) -> some View {
        if controller.canSavePeer, !isPeerSaved(peer.identity.canonicalAddress) {
            Button {
                Task { _ = await controller.savePeer(role: .unknown) }
            } label: {
                Label("Record in Peers", systemImage: "person.crop.circle.badge.plus")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .padding()
            .background(.bar)
        }
    }

    /// How the sheet's peer lists open a node from here: the same peer
    /// page they open anywhere else, minus the live radio and messaging
    /// context this sheet does not hold.
    private var setupBrowsing: RemotePeerBrowsing {
        RemotePeerBrowsing(knownPeers: peerActions.knownPeers) { peer in
            AnyView(
                PeerDetailView(
                    peer: peer,
                    radioSnapshot: .constant(.idle),
                    actions: peerActions
                )
            )
        }
    }

    /// The commissioning sheet over the live draft, or an explanation when
    /// the device never reported enough to build one.
    @ViewBuilder
    private func settings(
        sections: [DeviceSetupSection],
        title: String,
        applyTitle: String,
        note: String?
    ) -> some View {
        if let draft = controller.draft {
            DeviceSettingsView(
                controller: controller,
                draft: draft,
                sections: sections,
                title: title,
                applyTitle: applyTitle,
                note: note,
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
