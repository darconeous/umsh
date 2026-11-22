import SwiftUI
import UMSHMobileCore

/// Manage one node over the mesh: what it is, and the way in to each group
/// of its settings.
///
/// Deliberately offered for any node, whether or not it has ever said it
/// accepts administrators—a device tells only the nodes it lists that it
/// can be managed at all, so hiding this would hide it exactly where it
/// works. What a device out of reach produces is a sentence rather than a
/// dead end.
///
/// The screen itself is nearly free: what a device is gets asked once and
/// remembered, so every opening after the first puts nothing on the air.
/// Nothing here refreshes on its own—a device several flood hops away
/// answers at the cost of everyone's airtime, and spending that is the
/// operator's call.
struct ManageDeviceScreen: View {
    let browsing: RemotePeerBrowsing
    /// The node's neighbor listing, which is asked for over the mesh.
    /// Nil for the attached radio, which is not reached that way.
    private let neighbors: AnyView?
    /// How to reach the device: the core hands back a handle on it.
    private let open: @MainActor () async throws -> ManageDeviceModel
    @State private var model: ManageDeviceModel?
    @State private var failure: String?
    @State private var lease = ManagementLease()

    init(
        browsing: RemotePeerBrowsing,
        neighbors: AnyView? = nil,
        open: @escaping @MainActor () async throws -> ManageDeviceModel
    ) {
        self.browsing = browsing
        self.neighbors = neighbors
        self.open = open
    }

    var body: some View {
        Group {
            if let model {
                ManageDeviceContent(model: model, browsing: browsing, neighbors: neighbors)
            } else if let failure {
                ContentUnavailableView {
                    Label(
                        LocalizedStringResource(
                            "Can't Manage This Device",
                            comment: "Managing a node: title shown when a device's settings could not be opened."
                        ),
                        systemImage: "exclamationmark.triangle"
                    )
                } description: {
                    Text(verbatim: failure)
                }
                .navigationTitle("Manage Device")
                .navigationBarTitleDisplayMode(.inline)
            } else {
                ProgressView()
                    .navigationTitle("Manage Device")
                    .navigationBarTitleDisplayMode(.inline)
            }
        }
        .task {
            guard model == nil else { return }
            do {
                let opened = try await open()
                lease.hold(opened)
                model = opened
            } catch {
                failure = MobileAppError.message(for: error)
            }
        }
    }
}

private struct ManageDeviceContent: View {
    let model: ManageDeviceModel
    let browsing: RemotePeerBrowsing
    let neighbors: AnyView?
    @State private var confirmsRestart = false
    @State private var confirmsFactoryReset = false
    @State private var confirmsDfu = false

    var body: some View {
        Form {
            ManageDeviceIdentitySection(model: model)
            if model.enteredDfu {
                Section {
                    Label("DFU entry confirmed", systemImage: "checkmark.circle")
                    Text("The device is leaving UMSH.")
                }
            } else if model.card != nil {
                ManageDeviceCategoriesSection(model: model, browsing: browsing)
                if let neighbors {
                    Section {
                        NavigationLink {
                            neighbors
                        } label: {
                            Label("Neighbors", systemImage: "antenna.radiowaves.left.and.right")
                        }
                    }
                }
                ManageDeviceLifecycleSection(
                    model: model,
                    confirmsRestart: $confirmsRestart,
                    confirmsFactoryReset: $confirmsFactoryReset,
                    confirmsDfu: $confirmsDfu
                )
            }
        }
        .sheet(isPresented: $confirmsDfu) {
            DfuEntrySheet(model: model)
        }
        .confirmationDialog(
            "Restart This Device?",
            isPresented: $confirmsRestart,
            titleVisibility: .visible
        ) {
            Button("Restart", role: .destructive) { Task { await model.restart() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The device power-cycles and keeps everything it has saved. It is off the air until it comes back, and anything relaying through it is too.")
        }
        .confirmationDialog(
            "Factory Reset This Device?",
            isPresented: $confirmsFactoryReset,
            titleVisibility: .visible
        ) {
            Button("Erase Everything and Restart", role: .destructive) {
                Task { await model.factoryReset() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Every setting, key, and pairing is erased, including the device's own identity—it comes back as a node nobody has met, at a different address, and has to be set up from scratch.")
        }
        // Not the device's name: it is on the row below, and a title that
        // repeats it spends the one line that could say where you are.
        .navigationTitle("Manage Device")
        .navigationBarTitleDisplayMode(.inline)
        .managementStatus(model)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if !model.enteredDfu {
                    Button {
                        Task { await model.refreshCard() }
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .disabled(model.isBusy)
                }
            }
        }
        .task { await model.loadCard() }
    }
}

private struct DfuEntrySheet: View {
    let model: ManageDeviceModel
    @Environment(\.dismiss) private var dismiss
    @State private var mode: UlcpDfuMode = .default

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(model.card?.deviceName ?? model.fallbackName)
                        .font(.headline)
                    if !model.address.isEmpty {
                        Text(model.address).font(.caption.monospaced())
                    }
                    Picker("DFU Method", selection: $mode) {
                        Text("Default DFU").tag(UlcpDfuMode.default)
                        Text("Serial/USB-CDC DFU").tag(UlcpDfuMode.serial)
                        Text("UF2 (File-copy) DFU").tag(UlcpDfuMode.uf2)
                        Text("BLE DFU").tag(UlcpDfuMode.ble)
                    }
                }
                Section {
                    Label("Device may become inaccessible", systemImage: "exclamationmark.triangle.fill")
                        .font(.headline)
                        .foregroundStyle(.red)
                    Text("This device will stop normal operation and may remain inaccessible indefinitely. Continue only if someone is ready to complete the firmware update using the selected method.")
                    if mode == .ble {
                        Text("The updater must be within Bluetooth range.")
                    }
                    Text("This action only enters DFU; it does not install firmware.")
                }
                Section {
                    Button("Enter DFU Mode", role: .destructive) {
                        Task {
                            await model.enterDfu(mode)
                            if model.enteredDfu { dismiss() }
                        }
                    }
                    if model.isBusy { ProgressView("Waiting for confirmation…") }
                    if let problem = model.problem {
                        Text(verbatim: ManagementProblemText.text(for: problem))
                            .foregroundStyle(.red)
                    }
                }
            }
            .disabled(model.isBusy)
            .navigationTitle("Enter DFU Mode")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.disabled(model.isBusy)
                }
            }
        }
        .interactiveDismissDisabled(model.isBusy)
    }
}

/// Lets go of a device once the screen managing it is gone for good.
///
/// Held in that screen's state, which outlives every category screen pushed
/// over it and goes when it is popped. The model itself cannot tell: the
/// screens and the calls in flight hold it.
final class ManagementLease {
    private var model: ManageDeviceModel?

    func hold(_ model: ManageDeviceModel) {
        self.model = model
    }

    deinit { model?.release() }
}

/// The nodes this phone has saved, and how to open one.
///
/// A device's peer and administrator lists are lists of nodes, so tapping
/// one should land where tapping a node lands anywhere else. The page is
/// built by the caller rather than here: it is the peer sheet, and this
/// screen is pushed from inside it.
struct RemotePeerBrowsing {
    let knownPeers: [PeerSummary]
    let open: @MainActor (PeerSummary) -> AnyView
}

/// One category row: what it is called, and what it opens.
///
/// A device is only offered the categories it has anything to say about—
/// a repeater with no receiver has no GNSS screen to fill, and a screen
/// that could only be empty is worse than no screen.
struct ManageDeviceCategory: Identifiable {
    let category: UlcpManageCategory
    let title: String
    let symbol: String
    let destination: @MainActor (ManageDeviceModel, RemotePeerBrowsing) -> AnyView

    var id: String { title }

    @MainActor
    static func offered(by model: ManageDeviceModel) -> [ManageDeviceCategory] {
        all.filter { !model.properties(of: $0.category).isEmpty }
    }

    private static let all: [ManageDeviceCategory] = [
        ManageDeviceCategory(
            category: .power,
            title: "Power",
            symbol: "battery.100"
        ) { model, _ in AnyView(RemotePowerScreen(model: model)) },
        ManageDeviceCategory(
            category: .sensors,
            title: "Sensors",
            symbol: "sun.max"
        ) { model, _ in AnyView(RemoteSensorsScreen(model: model)) },
        ManageDeviceCategory(
            category: .radio,
            title: "Radio",
            symbol: "antenna.radiowaves.left.and.right"
        ) { model, _ in AnyView(RemoteRadioEditor(model: model)) },
        ManageDeviceCategory(
            category: .statistics,
            title: "Statistics",
            symbol: "chart.bar"
        ) { model, _ in AnyView(RemoteStatisticsScreen(model: model)) },
        ManageDeviceCategory(
            category: .identity,
            title: "Identity",
            symbol: "person.text.rectangle"
        ) { model, _ in AnyView(RemoteIdentityEditor(model: model)) },
        ManageDeviceCategory(
            category: .gnss,
            title: "GNSS",
            symbol: "location"
        ) { model, _ in AnyView(RemoteGnssScreen(model: model)) },
        ManageDeviceCategory(
            category: .time,
            title: "Time",
            symbol: "clock"
        ) { model, _ in AnyView(RemoteTimeScreen(model: model)) },
        ManageDeviceCategory(
            category: .bluetooth,
            title: "Bluetooth",
            symbol: "dot.radiowaves.left.and.right"
        ) { model, _ in AnyView(RemoteBluetoothScreen(model: model)) },
        // Named "Wi-Fi" whether or not the device can join one: a device
        // that can only listen still has a Wi-Fi screen, and the screen
        // says what it can do rather than the row hedging about it.
        ManageDeviceCategory(
            category: .wifi,
            title: "Wi-Fi",
            symbol: "wifi"
        ) { model, _ in AnyView(RemoteWifiScreen(model: model)) },
        ManageDeviceCategory(
            category: .network,
            title: "Network",
            symbol: "network"
        ) { model, _ in AnyView(RemoteNetworkScreen(model: model)) },
        ManageDeviceCategory(
            category: .bridge,
            title: "Bridge",
            symbol: "point.3.connected.trianglepath.dotted"
        ) { model, _ in AnyView(RemoteBridgeScreen(model: model)) },
        ManageDeviceCategory(
            category: .repeater,
            title: "Repeater",
            symbol: "arrow.triangle.branch"
        ) { model, _ in AnyView(RemoteRepeaterEditor(model: model)) },
        ManageDeviceCategory(
            category: .peerNodes,
            title: "Peer Nodes",
            symbol: "person.2"
        ) { model, browsing in
            AnyView(RemotePeerNodesScreen(model: model, browsing: browsing))
        },
    ]
}

// MARK: - Shared category chrome

/// The toolbar, staleness line, and busy handling every category screen
/// wears.
///
/// Applied as a modifier rather than a wrapper view so each screen keeps its
/// own `Form` and its own sections: what these have in common is the way
/// they talk to the device, not their shape.
struct RemoteCategoryChrome: ViewModifier {
    let model: ManageDeviceModel
    let category: UlcpManageCategory
    let title: String
    /// What Apply does, and whether there is anything to apply. Read-only
    /// screens leave it nil and get a Refresh button alone.
    var apply: (() async -> MobileApplyOutcome)?
    /// What the screen's draft would do: Apply is offered for its edits,
    /// and leaving asks first while it holds edits or a value that cannot
    /// be applied—either is something the operator typed.
    var review: MobileDraftReviewRecord?
    /// What to warn about before applying, on a screen whose changes can
    /// put the device out of reach.
    ///
    /// Held here rather than in the screen so that every route to Apply
    /// passes it—a warning the toolbar button shows and the leaving-with-
    /// edits dialog skips is a warning that is not there when it matters.
    var applyWarning: (title: String, message: String)?

    @Environment(\.dismiss) private var dismiss
    @State private var isConfirmingExit = false
    @State private var isConfirmingApply = false
    /// Whether the apply now being confirmed was reached on the way out.
    @State private var leavesAfterApply = false

    private var hasEdits: Bool { review?.hasEdits == true }
    private var asksBeforeLeaving: Bool {
        hasEdits || review?.problems.isEmpty == false
    }

    func body(content: Content) -> some View {
        content
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .managementStatus(model)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        Task { await model.refreshCategory(category) }
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .disabled(model.isBusy)
                }
                // Alongside Refresh rather than on a bottom bar: these
                // screens are pushed inside a tab, and the tab bar owns
                // the bottom of the window.
                if apply != nil, hasEdits {
                    ToolbarItem(placement: .topBarTrailing) {
                        Button("Apply") { beginApply(leaving: false) }
                            .fontWeight(.semibold)
                            .disabled(model.isBusy)
                    }
                }
                // Leaving with edits in hand is worth interrupting: nothing
                // on this screen has reached the device, and a form that
                // silently discarded a change made three hops from a mast
                // would be the wrong kind of quiet.
                if asksBeforeLeaving {
                    ToolbarItem(placement: .topBarLeading) {
                        Button("Back") { isConfirmingExit = true }
                    }
                }
            }
            .navigationBarBackButtonHidden(asksBeforeLeaving)
            .confirmationDialog(
                "You have unapplied changes.",
                isPresented: $isConfirmingExit,
                titleVisibility: .visible
            ) {
                if apply != nil, hasEdits {
                    Button("Apply and Go Back") { beginApply(leaving: true) }
                }
                Button("Discard Changes", role: .destructive) { dismiss() }
                Button("Keep Editing", role: .cancel) {}
            }
            .confirmationDialog(
                applyWarning?.title ?? "",
                isPresented: $isConfirmingApply,
                titleVisibility: .visible
            ) {
                Button(applyWarning?.title ?? String(localized: "Apply"), role: .destructive) { runApply() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(applyWarning?.message ?? "")
            }
            .task { await model.loadCategory(category) }
    }

    /// Warn first where a screen asked for it, and otherwise just apply.
    private func beginApply(leaving: Bool) {
        leavesAfterApply = leaving
        if applyWarning != nil {
            isConfirmingApply = true
        } else {
            runApply()
        }
    }

    /// Apply, and leave if that was asked for and the edits are safely on
    /// the device. A refused apply stays so the row's refusal can be read
    /// beside the device's value; a failed or canceled one stays because
    /// the screen holds the only copy of the edits.
    private func runApply() {
        guard let apply else { return }
        Task {
            let outcome = await apply()
            guard leavesAfterApply else { return }
            switch outcome.result {
            case .applied, .nothingToApply: dismiss()
            case .invalid, .refused, .cancelled, .skipped, .failed: break
            }
        }
    }
}

extension View {
    func remoteCategoryChrome(
        model: ManageDeviceModel,
        category: UlcpManageCategory,
        title: String,
        apply: (() async -> MobileApplyOutcome)? = nil,
        review: MobileDraftReviewRecord? = nil,
        applyWarning: (title: String, message: String)? = nil
    ) -> some View {
        modifier(
            RemoteCategoryChrome(
                model: model,
                category: category,
                title: title,
                apply: apply,
                review: review,
                applyWarning: applyWarning
            )
        )
    }
}
