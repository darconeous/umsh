import SwiftUI
import UMSHMobileCore

/// Everything managing a node over the mesh needs from the app's radio.
///
/// A bundle of closures for the same reason `PeerActions` is one: the peer
/// sheet is presented from several places, and threading four operations
/// through each of them one parameter at a time is how the same screen
/// ends up able to do different things depending on where it was opened.
struct RemoteDeviceManagement {
    /// Read the device whole, reporting the properties still to ask for.
    var read: (String, @escaping @Sendable (UInt32?) -> Void) async throws -> UlcpSyncRecord
    /// Write properties, answering with what the device says each is now
    /// worth.
    var write: (String, [MobileMeshPropertyWriteRecord]) async throws
        -> [MobileMeshManagementAnswerRecord]
    var save: (String) async throws -> Void
    var setAdministrator: (String, Data, Bool) async throws -> Void
    /// Make the device conspicuous, or stop it, answering with what it
    /// reports it is doing.
    var setAlert: (String, RadioAlertState) async throws -> RadioAlertState
    /// This phone's own node key, so the administrator list can say which
    /// entry is this phone.
    var phoneNodeKey: Data?
}

/// One device being configured across the mesh.
///
/// The same shape as `AdminFlowController` and deliberately almost none of
/// its substance: there is no link to hold open, no scan, nothing to tear
/// down. An operation is a handful of frames that either come back or do
/// not, so the whole lifecycle here is "read the device, edit, write it
/// back", and a failure is reported rather than recovered from.
@MainActor
@Observable
final class RemoteDeviceController: DeviceAdministering {
    private(set) var snapshot = AdministeredDeviceSnapshot.idle
    /// The configuration being edited, once the device has been read.
    private(set) var draft: DeviceConfigDraft?
    var problem: String?
    /// Properties the read has yet to ask for. Nil before the device has
    /// said what it can do, which is the one exchange with nothing to
    /// count.
    private(set) var propertiesRemaining: UInt32?
    private(set) var isReading = false
    /// Why the device could not be read, when it could not. Distinct from
    /// `problem`, which is about a write: this one leaves nothing on
    /// screen to edit.
    private(set) var readFailure: String?

    private let address: String
    private let deviceName: String?
    private let management: RemoteDeviceManagement

    init(peer: PeerSummary, management: RemoteDeviceManagement) {
        address = peer.identity.canonicalAddress
        deviceName = peer.displayName
        self.management = management
        snapshot.linkState = .attaching
        snapshot.name = peer.advertisedName
        snapshot.deviceIdentity = peer.identity
    }

    /// Read the device and build the form over it. Idempotent: a screen
    /// that reappears does not ask a device on a mast to say everything
    /// about itself a second time.
    func read() async {
        guard draft == nil, !isReading else { return }
        isReading = true
        readFailure = nil
        defer { isReading = false }
        do {
            let sync = try await management.read(address) { [weak self] remaining in
                Task { @MainActor in self?.propertiesRemaining = remaining }
            }
            adopt(sync)
            snapshot.linkState = .attached
            draft = DeviceConfigDraft(
                sync: sync,
                reportedName: sync.deviceName ?? deviceName,
                plan: .remote,
                // The editor asks about every radio parameter directly, so
                // it opens on what the device already holds — and copying
                // this phone's profile onto a device several hops away
                // would be copying it onto a device that can already hear
                // us.
                resolvedProfile: nil,
                phoneNodeKey: management.phoneNodeKey,
                writer: self
            )
        } catch {
            snapshot.linkState = .failed
            readFailure = Self.text(for: error)
        }
    }

    /// Read the device again, after a write or because the operator asked.
    func reread() async {
        draft = nil
        // Cleared here rather than left to `read`, so nothing renders the
        // last failure again on the way into the retry.
        readFailure = nil
        snapshot.linkState = .attaching
        await read()
    }

    private func adopt(_ sync: UlcpSyncRecord) {
        snapshot.sync = sync
        snapshot.name = sync.deviceName ?? snapshot.name
        // The readings the crawl asks for anyway. A device several hops
        // away answers these as readily as one on the bench — what differs
        // is that nothing here arrives unsolicited, so what is on screen is
        // what the last read found and nothing refreshes it behind the
        // operator's back.
        snapshot.batteryPercentage = sync.battery?.percentage.map(Int.init)
        snapshot.batteryVoltageMillivolts = sync.battery?.voltageMv.map(Int.init)
        snapshot.chargeState = sync.battery?.chargeState.map(RadioChargeState.init)
        snapshot.alert = sync.alert.map(RadioAlertState.init)
    }

    /// Make the device conspicuous, or stop it.
    ///
    /// The one control here that acts on the device rather than on its
    /// configuration, and the one worth the round trip: a node whose
    /// position is a week-old fix is found by making it beep.
    func setAlert(_ state: RadioAlertState) async throws {
        snapshot.alert = try await management.setAlert(address, state)
    }

    // MARK: - Writing

    func configure(_ configuration: UlcpDeviceConfigRecord) async -> UlcpSyncRecord? {
        problem = nil
        guard let reported = snapshot.sync else { return nil }
        do {
            let writes = try ulcpDeviceConfigWrites(
                configuration: configuration,
                reported: reported
            )
            let answers = try await management.write(address, writes)
            // Each position echoes what that property is now worth, so a
            // status where a value belonged is one setting the device would
            // not take — worth saying before the save claims success.
            let refused = answers.filter { $0.value == nil }
            guard refused.isEmpty else {
                problem = """
                    The device refused \(refused.count) of these settings. \
                    The rest are in effect but not saved.
                    """
                return nil
            }
            try await management.save(address)
            // Read back rather than trusting the echoes: they say what the
            // device is running, and the question after a save is what it
            // will come back with. Same question the local editor's
            // readback answers, and the same reason.
            let readback = try await management.read(address) { [weak self] remaining in
                Task { @MainActor in self?.propertiesRemaining = remaining }
            }
            adopt(readback)
            return readback
        } catch {
            problem = Self.text(for: error)
            return nil
        }
    }

    /// Bring the device's administrator list to `keys`, and persist it.
    ///
    /// Removals before additions, because a full list takes a removal but
    /// not an addition. This phone's own entry is never among the removals:
    /// taking it off would be the last request the device answered, and the
    /// save behind it would arrive from a node it no longer lists — which
    /// is why the form does not offer it over the mesh.
    func setAdministrators(_ keys: [Data]) async throws {
        let desired = Set(keys)
        let current = Set(snapshot.sync?.devAdminKeys ?? [])
        for key in current.subtracting(desired) {
            try await management.setAdministrator(address, key, false)
        }
        for key in desired.subtracting(current) {
            try await management.setAdministrator(address, key, true)
        }
        // The list is live the moment the device answers, and saved only
        // when it is told to save — unlike the Bluetooth path, where the
        // session chains the save behind each mutation.
        try await management.save(address)
        snapshot.sync?.devAdminKeys = keys
    }

    /// What went wrong, in terms an operator can act on.
    ///
    /// Silence is the case worth explaining: a device answers nothing at
    /// all to a node it does not list, so "no reply" and "not an
    /// administrator" arrive identically and the copy has to carry both.
    static func text(for error: any Error) -> String {
        switch error as? RemoteManagementError {
        case .noAnswer:
            """
            No response — this phone may not be an administrator of that \
            device, or the device may be out of reach.
            """
        case let .refused(status):
            "The device refused the request: \(ulcpStatusName(status: status))."
        case .unreadable:
            """
            The device answered with something this app could not read. It \
            may be running firmware this version does not understand.
            """
        case .unavailable, nil:
            """
            This phone has no radio to send through. Connect its companion \
            radio and try again.
            """
        }
    }
}

/// Manage one node over the mesh: read what it is, change it, save it.
///
/// Deliberately offered for any node, whether or not it has ever said it
/// accepts administrators — a device tells only the nodes it lists that it
/// can be managed at all, so hiding this would hide it exactly where it
/// works. What a device out of reach produces is the failure below, which
/// is a sentence rather than a dead end.
struct RemoteDeviceView: View {
    let peer: PeerSummary
    let peerActions: PeerActions
    @Environment(\.dismiss) private var dismiss
    @State private var controller: RemoteDeviceController

    init(peer: PeerSummary, management: RemoteDeviceManagement, peerActions: PeerActions) {
        self.peer = peer
        self.peerActions = peerActions
        _controller = State(
            initialValue: RemoteDeviceController(peer: peer, management: management)
        )
    }

    var body: some View {
        content
            .navigationTitle(controller.snapshot.name ?? peer.displayName)
            .navigationBarTitleDisplayMode(.inline)
            .task { await controller.read() }
    }

    @ViewBuilder
    private var content: some View {
        if let draft = controller.draft {
            DeviceSettingsView(
                controller: controller,
                draft: draft,
                sections: DeviceSetupPlan.remote.sections,
                title: controller.snapshot.name ?? peer.displayName,
                applyTitle: DeviceSetupPlan.remote.applyTitle,
                note: nil,
                isCommissioning: false,
                isPeerSaved: { _ in true },
                peerActions: peerActions,
                finish: { dismiss() }
            )
        } else if let failure = controller.readFailure {
            ContentUnavailableView {
                Label("No response", systemImage: "antenna.radiowaves.left.and.right.slash")
            } description: {
                Text(failure)
            } actions: {
                Button("Try Again") {
                    Task { await controller.reread() }
                }
            }
        } else {
            // Also the state before the read has started, which is a frame
            // or two: a screen that showed "no response" first and then
            // started asking would be accusing the device of a silence it
            // was never given the chance to break.
            readingProgress
        }
    }

    /// What the read is doing, counted in the only unit that means
    /// anything here: settings still to ask for. How many exchanges that
    /// takes is the device's decision, not this screen's.
    private var readingProgress: some View {
        VStack(spacing: 12) {
            ProgressView()
            Text("Reading the device over the mesh")
                .foregroundStyle(.secondary)
            if let remaining = controller.propertiesRemaining, remaining > 0 {
                Text("\(remaining) settings left")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}
