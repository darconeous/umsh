import SwiftUI
import UMSHMobileCore

/// The state behind the device-setup sheet.
///
/// This is a deliberate, contained exception to the app's no-view-model
/// rule. The flow owns a live BLE session whose lifetime spans several
/// pushed screens and must be torn down exactly once, no matter which
/// screen the user leaves from—that is object lifetime, not view state,
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

    private(set) var intent: DeviceSetupIntent = .changeSettings
    var path: [Step] = [] {
        didSet { releaseDeviceLeftBehind(oldValue) }
    }
    private(set) var snapshot = AdministeredDeviceSnapshot.idle
    private(set) var devices: [DiscoveredRadio] = []
    /// The device being set up, for as long as one is attached under a goal.
    ///
    /// Owned here rather than by a screen because its lifetime is the
    /// session's, not any one view's—and because a navigation destination
    /// holding it as `@State` would fork it the moment a second screen
    /// pushed over the same device.
    private(set) var setup: DeviceSetupModel?
    /// The device a connect is currently in flight for.
    private(set) var busyDevice: UUID?
    /// Its advertised name, captured at the tap: connecting stops the scan and
    /// empties the list, so by the time anything wants to say which device is
    /// being waited on, the row it came from is gone.
    private(set) var connectingName: String?
    var problem: String?

    /// The phone's current companion radio, so the flow can mark it in the
    /// scan list. It is never selectable here—the companion connection
    /// already holds that peripheral.
    let companionIdentifier: UUID?
    let companionName: String?
    /// The radio profile a set-up device is put on, read from the phone's
    /// own radio once, when the sheet opens.
    ///
    /// Captured rather than sampled live. A mesh profile that changed
    /// halfway through a commissioning session would be worse than a
    /// slightly stale one—the operator would have no way to know which of
    /// the two any given device ended up on.
    private var companion: Task<MobileSetupCompanionRecord?, Never>?

    private let hostIdentity: MeshPublicIdentity?
    private let services: DeviceSetupServices?
    private let saveDevicePeer: ((MeshPublicIdentity, String?, PeerRole?) async throws -> Void)?
    private let session = AdministrativeDeviceSession()
    private var snapshotTask: Task<Void, Never>?
    private var discoveryTask: Task<Void, Never>?

    init(
        hostIdentity: MeshPublicIdentity?,
        companionIdentifier: UUID?,
        companionName: String?,
        services: DeviceSetupServices? = nil,
        saveDevicePeer: ((MeshPublicIdentity, String?, PeerRole?) async throws -> Void)? = nil
    ) {
        self.hostIdentity = hostIdentity
        self.companionIdentifier = companionIdentifier
        self.companionName = companionName
        self.services = services
        self.saveDevicePeer = saveDevicePeer
    }

    /// Record the device being configured as a peer, so the operator can
    /// find it in Peers after the sheet closes. Nothing about the setup
    /// session itself is persisted.
    func savePeer(role: PeerRole?) async throws {
        guard let saveDevicePeer, let identity = snapshot.deviceIdentity else {
            throw MobileAppError.InvalidRequest
        }
        try await saveDevicePeer(identity, snapshot.name, role)
    }

    var canSavePeer: Bool { saveDevicePeer != nil }

    var isBusy: Bool { busyDevice != nil }

    /// Whether administering `device` would fight the companion connection
    /// for the same peripheral.
    func isCompanion(_ device: DiscoveredRadio) -> Bool {
        device.id == companionIdentifier
    }

    // MARK: - Lifecycle

    #if DEBUG
    /// List the staged devices beside the phone with those found over
    /// Bluetooth, while staging is on.
    func useStagedDevices(_ devices: StagedAdministeredDevices?) async {
        await session.useStagedDevices(devices)
    }
    #endif

    func begin() async {
        guard snapshotTask == nil else { return }
        if companion == nil, let services {
            companion = Task { await services.companion() }
        }
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
    /// rather than asked of the core: an address is that key rendered, so
    /// these are the same bytes `MobileAppCore.phoneNodeKey()` reports.
    private var phoneNodeKey: Data? {
        hostIdentity.flatMap {
            try? UMSHMobileCore.publicIdentityBytes(address: $0.canonicalAddress)
        }
    }

    /// Let go of the device being set up, if there is one. An apply under
    /// way runs to its end in the core.
    private func releaseSetup() {
        setup?.release()
        setup = nil
    }

    /// Release the BLE session. Safe to call more than once and from a
    /// disappearing view.
    func end() async {
        releaseSetup()
        managed = nil
        discoveryTask?.cancel()
        discoveryTask = nil
        snapshotTask?.cancel()
        snapshotTask = nil
        await session.disconnect()
    }

    func choose(_ intent: DeviceSetupIntent) {
        self.intent = intent
        problem = nil
        path = [.scan]
    }

    /// Open the management screens over the device that was just set up, on
    /// the same session—so a commissioned device is inspected and adjusted
    /// through the screens every device gets, not a second form.
    func reviewAllSettings() {
        guard path.last != .editor else { return }
        path.append(.editor)
    }

    /// Let go of this device and start again at the goal chooser, not the scan
    /// list: the next device may be a different kind of thing.
    func startOver() async {
        releaseSetup()
        managed = nil
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

    /// Pairing already selected this device. It needn't advertise again to
    /// become a selectable scan row before the administrative session starts.
    func selectAuthorizedRadio(_ id: UUID) async throws {
        let inventory = try await RadioAccessories.shared.prepareSelection(id)
        guard let device = inventory.radios.first(where: { $0.id == id }) else {
            throw RadioConnectionError.operationRejected(String(
                localized: "This radio is no longer authorized.",
                comment: "Device setup: a paired radio chosen from the system picker is no longer available to this app."
            ))
        }
        guard !isCompanion(device) else {
            throw RadioConnectionError.operationRejected(String(
                localized: "Manage this phone's radio from its companion radio screen.",
                comment: "Device setup: the chosen radio is this phone's own, which is managed elsewhere."
            ))
        }
        await select(device)
    }

    func select(_ device: DiscoveredRadio) async {
        guard busyDevice == nil else { return }
        busyDevice = device.id
        connectingName = device.name
        problem = nil
        // Backing out of a device and picking another one must not inherit
        // the first one's unsaved edits.
        releaseSetup()
        managed = nil
        // Pushed before the connect rather than after it. Connecting takes
        // seconds—longer against an unbonded device, which puts a system
        // pairing prompt in the way—and `connect` stops the scan, so leaving
        // the operator on the list means watching every device vanish under a
        // screen that claims to be searching for them.
        let goal = intent.goal
        let step: Step = goal != nil ? .commission : .editor
        path = [.scan, step]
        defer { busyDevice = nil }
        do {
            // Changing a device's settings attaches lazily: the management
            // screens read the device a screenful at a time, so an attach
            // that read it whole would spend exactly the time the lazy
            // design exists to save. A setup reads it whole, because the
            // goal decides from everything the device reports.
            try await session.connect(device.id, lazyAttach: goal == nil)
            // The operator may have left while this was in flight. A device
            // they walked away from has to be let go, not pushed at them.
            guard path.last == step else {
                await abandonSelection()
                return
            }
            guard let goal else {
                // No setup: the unified sheet keys everything on the
                // device's identity, which the attach preamble read and
                // the snapshot mirror is about to carry. The editor step
                // renders once it lands, and says so if it never does.
                return
            }
            guard let services, let driver = await session.currentDriver() else {
                throw MobileAppError.NotRunning
            }
            let created = try await services.setUp(
                driver,
                goal,
                await companion?.value,
                phoneNodeKey
            )
            guard path.last == step else {
                created.release()
                await abandonSelection()
                return
            }
            let record = created.snapshot()
            // A device that cannot do the thing being asked of it is refused
            // here rather than offered a sheet it would disappoint.
            if let refusal = record.refusal {
                created.release()
                await refuse(String(localized: refusal.text))
                return
            }
            guard let draft = created.draft() else {
                created.release()
                await refuse(String(localized: MobileSetupRefusal.notReported.text))
                return
            }
            setup = DeviceSetupModel(setup: created, snapshot: record, draft: draft)
        } catch {
            guard path.last == step else {
                await abandonSelection()
                return
            }
            // The published snapshot carries the same explanation, but which
            // of the two lands first is not ordered, so this path states the
            // reason itself rather than leaving a generic message to win.
            // The core's own refusals have their own words.
            await refuse(
                error is MobileAppError
                    ? MobileAppError.message(for: error)
                    : RadioAccessories.message(for: error)
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
    /// so the device would keep refusing every later session—including the
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
    /// Back button only moves `path`—and a device left attached holds the
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
              setup != nil || snapshot.identifier != nil
        else { return }
        releaseSetup()
        managed = nil
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

    /// The device the management sheet last opened over this session.
    ///
    /// Held here rather than by the sheet so a confirmed firmware update
    /// entry ends the session even when the sheet that asked for it has
    /// already gone.
    private var managed: ManageDeviceModel?

    /// Open the unified management sheet over this flow's own BLE session.
    ///
    /// Storeless in the core: an administrative link refreshes every screen
    /// on sight, so a cache would only ever be one screen behind.
    func openManagement(
        using manage: @MainActor (MobileRadioDriver, Data?, PeerSummary) async throws -> ManageDeviceModel
    ) async throws -> ManageDeviceModel {
        guard let peer = managedPeer, let driver = await session.currentDriver() else {
            throw MobileAppError.Unreachable
        }
        let model = try await manage(driver, phoneNodeKey, peer)
        let session = session
        model.onEnteredDfu = { [weak self] in
            // The device is leaving UMSH; the link goes with it.
            self?.managed = nil
            Task { await session.disconnect() }
        }
        managed = model
        await session.forwardPushes(to: model.device)
        return model
    }
}

/// The session behind the setup sheet, as that sheet needs it.
///
/// A protocol rather than the controller itself so a sheet cannot reach the
/// BLE session: the device is written through the core's setup, never from
/// here.
@MainActor
protocol DeviceAdministering: AnyObject {
    /// The device as it stands, for the parts of the sheet that report
    /// rather than edit.
    var snapshot: AdministeredDeviceSnapshot { get }
    /// Whether this session can record the device in Peers.
    var canSavePeer: Bool { get }
    /// Record the device in Peers. A `nil` role keeps whatever kind it is
    /// already filed under.
    func savePeer(role: PeerRole?) async throws
    /// Open the management screens over the device just set up, and start
    /// again on another one: both are steps of the setup sheet's navigation.
    func reviewAllSettings()
    func startOver() async
}

/// Every member already exists above with these signatures; the
/// conformance only narrows what a form is allowed to reach.
extension AdminFlowController: DeviceAdministering {}

/// What the setup flow asks of the app's core: the phone's own radio
/// profile, read once when the sheet opens, and a setup over an attached
/// administrative driver.
struct DeviceSetupServices {
    var companion: @MainActor () async -> MobileSetupCompanionRecord?
    /// Set up the device `driver` is attached to as a goal, given the
    /// companion record and this phone's node key.
    var setUp: @MainActor (
        MobileRadioDriver, MobileSetupGoal, MobileSetupCompanionRecord?, Data?
    ) async throws -> MobileDeviceSetup
}

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
    @State private var failure: FailureNotice?
    #if DEBUG
    @Environment(\.stagedAdministeredDevices) private var stagedDevices
    #endif

    init(
        hostIdentity: MeshPublicIdentity?,
        companionIdentifier: UUID?,
        companionName: String?,
        services: DeviceSetupServices? = nil,
        saveDevicePeer: ((MeshPublicIdentity, String?, PeerRole?) async throws -> Void)? = nil,
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
                services: services,
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
                        settings
                    case .editor:
                        managedDeviceScreen
                    }
                }
        }
        .failureAlert($failure)
        .task {
            #if DEBUG
            await controller.useStagedDevices(stagedDevices)
            #endif
            await controller.begin()
        }
        .onDisappear {
            Task { await controller.end() }
        }
    }

    /// The unified management sheet over this flow's own session—the
    /// same screens a device gets over the mesh or on the companion link,
    /// reading the device a screenful at a time.
    @ViewBuilder
    private var managedDeviceScreen: some View {
        if let peer = controller.managedPeer {
            ManageDeviceScreen(browsing: setupBrowsing) {
                guard let manage = peerActions.manageAdministered else {
                    throw MobileAppError.NotRunning
                }
                return try await controller.openManagement(using: manage)
            }
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
    /// device in Peers, so the operator can find it again—and manage it
    /// over the mesh—after this session ends.
    @ViewBuilder
    private func savePeerBar(_ peer: PeerSummary) -> some View {
        if controller.canSavePeer, !isPeerSaved(peer.identity.canonicalAddress) {
            Button {
                Task {
                    // Recorded under no role of its own: a node already on
                    // file keeps the kind it was heard as.
                    do {
                        try await controller.savePeer(role: nil)
                    } catch {
                        failure = FailureNotice(String(localized: "Peer Not Saved", comment: "Alert title."), error)
                    }
                }
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

    /// The commissioning sheet over the device being set up, or an
    /// explanation when the device never reported enough to set one up.
    @ViewBuilder
    private var settings: some View {
        if let setup = controller.setup {
            DeviceSettingsView(
                controller: controller,
                model: setup,
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
                ForEach(DeviceSetupIntent.allCases) { intent in
                    Button { controller.choose(intent) } label: {
                        Label {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(intent.title)
                                    .foregroundStyle(.primary)
                                Text(intent.detail)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        } icon: {
                            Image(systemName: intent.symbol)
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
