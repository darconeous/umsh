import SwiftUI
import UMSHMobileCore

/// Manage one node over the mesh: what it is, and the way in to each group
/// of its settings.
///
/// Deliberately offered for any node, whether or not it has ever said it
/// accepts administrators — a device tells only the nodes it lists that it
/// can be managed at all, so hiding this would hide it exactly where it
/// works. What a device out of reach produces is a sentence rather than a
/// dead end.
///
/// The screen itself is nearly free: what a device is gets asked once and
/// remembered, so every opening after the first puts nothing on the air.
/// Nothing here refreshes on its own — a device several flood hops away
/// answers at the cost of everyone's airtime, and spending that is the
/// operator's call.
struct ManageDeviceScreen: View {
    let browsing: RemotePeerBrowsing
    @State private var model: ManageDeviceModel
    @State private var confirmsRestart = false
    @State private var confirmsFactoryReset = false

    init(peer: PeerSummary, management: DeviceManagementBackend, browsing: RemotePeerBrowsing) {
        self.browsing = browsing
        _model = State(initialValue: ManageDeviceModel(peer: peer, management: management))
    }

    var body: some View {
        Form {
            identitySection
            if model.card != nil {
                categoriesSection
                lifecycleSection
            }
            if let problem = model.problem {
                Section { Text(problem).foregroundStyle(.red) }
            }
        }
        .confirmationDialog(
            "Restart this device?",
            isPresented: $confirmsRestart,
            titleVisibility: .visible
        ) {
            Button("Restart", role: .destructive) { Task { await model.restart() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The device power-cycles and keeps everything it has saved. It is off the air until it comes back, and anything relaying through it is too.")
        }
        .confirmationDialog(
            "Factory reset this device?",
            isPresented: $confirmsFactoryReset,
            titleVisibility: .visible
        ) {
            Button("Erase Everything and Restart", role: .destructive) {
                Task { await model.factoryReset() }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Every setting, key, and pairing is erased, including the device's own identity — it comes back as a node nobody has met, at a different address, and has to be set up from scratch.")
        }
        // Not the device's name: it is on the row below, and a title that
        // repeats it spends the one line that could say where you are.
        .navigationTitle("Manage Device")
        .navigationBarTitleDisplayMode(.inline)
        .disabled(model.isBusy)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                if model.isBusy {
                    ProgressView()
                } else {
                    Button {
                        Task { await model.refreshCard() }
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                }
            }
        }
        .task { await model.loadCard() }
        // Held by this screen for the whole visit: category screens push
        // on top of it, so their readings follow the device's own
        // announcements for as long as any of them is up.
        .task { await model.observePushes() }
    }

    @ViewBuilder
    private var identitySection: some View {
        Section {
            if let card = model.card {
                LabeledContent("Name", value: card.deviceName ?? model.fallbackName)
                if let model = card.deviceModel {
                    LabeledContent("Model", value: model)
                }
                LabeledContent("Firmware", value: card.deviceVersion ?? "Not reported")
                if card.supportsAlert {
                    findButton
                }
            } else if model.isBusy {
                ProgressView("Asking the device what it is")
                    .frame(maxWidth: .infinity)
            } else {
                // Reached when the first card fetch failed. The problem
                // section below says why, and the toolbar's refresh is how
                // to try again.
                Text("This device has not said what it is yet.")
                    .foregroundStyle(.secondary)
            }
        } footer: {
            if let asOf = model.cardAsOf {
                Text("Asked \(asOf.formatted(.relative(presentation: .named))).")
            }
        }
    }

    /// The one control here that acts on the device rather than on its
    /// settings — and the one worth a round trip, because a node whose last
    /// known position is a week-old fix is found by making it beep.
    private var findButton: some View {
        Button {
            Task { await model.setAlert(model.alert == .locating ? .none : .locating) }
        } label: {
            Label(
                model.alert == .locating ? "Stop Locating" : "Find This Device",
                systemImage: model.alert == .locating ? "bell.slash" : "bell"
            )
        }
    }

    private var categoriesSection: some View {
        Section {
            ForEach(ManageDeviceCategory.offered(by: model)) { entry in
                NavigationLink {
                    entry.destination(model, browsing)
                } label: {
                    Label(entry.title, systemImage: entry.symbol)
                }
            }
        }
    }

    /// The controls that act on the device rather than on any one group of
    /// its settings.
    ///
    /// Restart is offered wherever the device answers at all — the node
    /// most worth restarting is the one nobody can walk to — and only when
    /// the device says it can (`CAP_REBOOT`), the way the locate button
    /// waits on `CAP_ALERT`. A factory reset is offered only where the
    /// device is in hand: it destroys the identity this screen is addressed
    /// to, so over the mesh there would be no device left to tell whether
    /// it worked, and no way back if it was the wrong one.
    @ViewBuilder
    private var lifecycleSection: some View {
        if model.supportsRestart || model.offersFactoryReset {
            Section {
                if model.supportsRestart {
                    Button("Restart This Device…", role: .destructive) {
                        confirmsRestart = true
                    }
                }
                if model.offersFactoryReset {
                    Button("Factory Reset…", role: .destructive) {
                        confirmsFactoryReset = true
                    }
                }
            } footer: {
                Text(model.offersFactoryReset
                     ? "A restart keeps everything the device has saved. A factory reset keeps nothing, the device's own identity included."
                     : "A restart keeps everything the device has saved. Erasing a device is only offered while it is connected to this phone.")
            }
        }
    }
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
/// A device is only offered the categories it has anything to say about —
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
    var apply: (() async -> Void)?
    var hasEdits = false
    /// What to warn about before applying, on a screen whose changes can
    /// put the device out of reach.
    ///
    /// Held here rather than in the screen so that every route to Apply
    /// passes it — a warning the toolbar button shows and the leaving-with-
    /// edits dialog skips is a warning that is not there when it matters.
    var applyWarning: (title: String, message: String)?

    @Environment(\.dismiss) private var dismiss
    @State private var isConfirmingExit = false
    @State private var isConfirmingApply = false
    /// Whether the apply now being confirmed was reached on the way out.
    @State private var leavesAfterApply = false

    func body(content: Content) -> some View {
        content
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .disabled(model.isBusy)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    if model.isBusy {
                        ProgressView()
                    } else {
                        Button {
                            Task { await model.refreshCategory(category) }
                        } label: {
                            Label("Refresh", systemImage: "arrow.clockwise")
                        }
                    }
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
                if hasEdits {
                    ToolbarItem(placement: .topBarLeading) {
                        Button("Back") { isConfirmingExit = true }
                    }
                }
            }
            .navigationBarBackButtonHidden(hasEdits)
            .confirmationDialog(
                "You have unapplied changes.",
                isPresented: $isConfirmingExit,
                titleVisibility: .visible
            ) {
                if apply != nil {
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
                Button(applyWarning?.title ?? "Apply", role: .destructive) { runApply() }
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

    private func runApply() {
        guard let apply else { return }
        Task {
            await apply()
            if leavesAfterApply { dismiss() }
        }
    }
}

extension View {
    func remoteCategoryChrome(
        model: ManageDeviceModel,
        category: UlcpManageCategory,
        title: String,
        apply: (() async -> Void)? = nil,
        hasEdits: Bool = false,
        applyWarning: (title: String, message: String)? = nil
    ) -> some View {
        modifier(
            RemoteCategoryChrome(
                model: model,
                category: category,
                title: title,
                apply: apply,
                hasEdits: hasEdits,
                applyWarning: applyWarning
            )
        )
    }
}

/// What a screen is showing and how old it is.
///
/// Every category screen carries one: values prefilled from the cache are
/// the device as it was last seen, and presenting that as current is the
/// one thing a design built on caching must not do.
struct RemoteReadingFooter: View {
    let reading: RemoteCategoryReading?
    let isBusy: Bool

    var body: some View {
        if isBusy {
            Text("Asking the device…")
        } else if let asOf = reading?.asOf {
            Text(
                reading?.isFresh == true
                    ? "Read from the device just now."
                    : "Last read \(asOf.formatted(.relative(presentation: .named)))."
            )
        } else {
            Text("Nothing read yet. Tap Refresh to ask the device.")
        }
    }
}
