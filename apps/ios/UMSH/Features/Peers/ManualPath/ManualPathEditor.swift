import SwiftUI

/// One repeater on a manual path being edited.
struct ManualPathHop: Identifiable, Hashable {
    let id = UUID()
    let hint: MeshRouterHint
    /// The node chosen, when it was picked from a list rather than typed.
    var node: PeerSummary?
    var enteredByHand = false
    /// How the previous hop heard it, when it was picked from that hop's
    /// neighbor listing.
    var signal: String?

    /// The node this hop names: the one chosen, else the one its hint most
    /// plausibly is.
    func named(among peers: [PeerSummary]) -> PeerSummary? {
        node ?? RouterHintNaming.match(hint, among: peers)
    }
}

extension MeshRouterHint {
    /// The two bytes as four hex digits, the form a hint is typed in.
    var hexText: String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}

/// A hop drawn the way a neighbor listing draws a node: the known node's
/// name and avatar, or the hint and a gray hexagon.
struct ManualPathHopRow: View {
    let hop: ManualPathHop
    let knownPeers: [PeerSummary]

    var body: some View {
        var detail: [String] = []
        if hop.enteredByHand { detail.append("Entered by hand · \(hop.hint.hexText)") }
        if let signal = hop.signal { detail.append(signal) }
        return RouterHintRow(hint: hop.hint, named: hop.named(among: knownPeers), detail: detail)
    }
}

/// Choose the repeaters a node is reached through, and how long the choice
/// stands ahead of anything the mesh teaches.
struct ManualPathEditor: View {
    let peer: PeerSummary
    let actions: PeerActions
    let radioName: String?
    let onSaved: () -> Void

    /// The most repeaters a source route carries.
    static let maximumHops = 15

    @Environment(\.dismiss) private var dismiss
    @State private var hops: [ManualPathHop]
    @State private var floodHops: UInt8
    @State private var hold = ManualPathHold.standard
    @State private var isAddingHop = false
    @State private var isPinging = false
    @State private var pingResult: PeerPingResult?
    @State private var isSaving = false
    @State private var saveFailed = false

    init(
        peer: PeerSummary,
        route: PeerRoute?,
        actions: PeerActions,
        radioName: String?,
        onSaved: @escaping () -> Void
    ) {
        self.peer = peer
        self.actions = actions
        self.radioName = radioName
        self.onSaved = onSaved
        _hops = State(initialValue: (route?.hints ?? []).map { ManualPathHop(hint: $0) })
        _floodHops = State(initialValue: route?.heldFloodHops ?? ManualPath.standardFloodHops)
    }

    var body: some View {
        NavigationStack {
            List {
                pathSection
                testSection
                holdSection
                if saveFailed {
                    Section {
                        Text("This phone's routing did not take the path. Check the radio and try again.")
                            .foregroundStyle(.red)
                    }
                }
            }
            .environment(\.editMode, .constant(.active))
            .navigationTitle("Manual Path")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    if isSaving {
                        ProgressView()
                    } else {
                        Button("Save") { Task { await save() } }
                            .disabled(actions.setManualPath == nil)
                    }
                }
            }
            .sheet(isPresented: $isAddingHop) {
                AddHopScreen(destination: peer, actions: actions, hops: $hops)
            }
            .onChange(of: path) { _, _ in pingResult = nil }
        }
    }

    private var pathSection: some View {
        Section {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text("This phone")
                    if let radioName {
                        Text("Sent through \(radioName)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } icon: {
                Image(systemName: "iphone.gen3").foregroundStyle(.secondary)
            }
            .moveDisabled(true)
            .deleteDisabled(true)
            ForEach(hops) { hop in
                ManualPathHopRow(hop: hop, knownPeers: actions.knownPeers)
            }
            .onMove { hops.move(fromOffsets: $0, toOffset: $1) }
            .onDelete { hops.remove(atOffsets: $0) }
            if hops.count < Self.maximumHops {
                Button {
                    isAddingHop = true
                } label: {
                    Label("Add Hop…", systemImage: "plus.circle.fill")
                }
                .moveDisabled(true)
                .deleteDisabled(true)
            }
            Stepper(value: $floodHops, in: 0...ManualPath.maximumFloodHops) {
                LabeledContent(hops.isEmpty ? "Flood" : "Then flood", value: Self.floodText(floodHops))
            }
            .moveDisabled(true)
            .deleteDisabled(true)
            PeerRow(peer: peer, size: .compact)
                .moveDisabled(true)
                .deleteDisabled(true)
        } header: {
            HStack {
                Text("Path to \(peer.displayName)")
                Spacer()
                Text(Self.hopsText(hops.count + 1))
            }
        }
    }

    @ViewBuilder
    private var testSection: some View {
        if actions.pingAlongPath != nil {
            Section("Test") {
                Button {
                    Task { await ping() }
                } label: {
                    Label(isPinging ? "Pinging…" : "Ping Along Path", systemImage: "wave.3.right")
                }
                .disabled(isPinging)
                if let pingResult {
                    pingResultRows(pingResult)
                }
            }
        }
    }

    @ViewBuilder
    private func pingResultRows(_ result: PeerPingResult) -> some View {
        switch result {
        case let .reply(reply):
            Label("Reply in \(reply.roundTripMilliseconds) ms", systemImage: "checkmark.circle.fill")
                .foregroundStyle(.green)
            if let rssi = reply.rssiDBm {
                LabeledContent("RSSI (last hop)", value: "\(rssi) dBm")
            }
            if let snr = reply.signalToNoiseCentibels {
                LabeledContent("SNR (last hop)", value: String(format: "%.1f dB", Double(snr) / 10))
            }
        case .timedOut:
            Label("Timed out", systemImage: "clock.badge.exclamationmark")
                .foregroundStyle(.orange)
        case let .unavailable(reason):
            Label(reason, systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
        }
    }

    private var holdSection: some View {
        Section {
            Picker("Hold for", selection: $hold) {
                ForEach(ManualPathHold.allCases) { option in
                    Text(option.title).tag(option)
                }
            }
            .pickerStyle(.menu)
            LabeledContent("Until") {
                Text(Date.now.addingTimeInterval(hold.duration), format: .dateTime.weekday(.abbreviated).hour().minute())
            }
        } header: {
            Text("Hold")
        } footer: {
            Text("Then a learned path can replace it.")
        }
    }

    private func ping() async {
        guard let pingAlongPath = actions.pingAlongPath, !isPinging else { return }
        isPinging = true
        defer { isPinging = false }
        pingResult = await pingAlongPath(peer, path)
    }

    private func save() async {
        guard let setManualPath = actions.setManualPath, !isSaving else { return }
        isSaving = true
        defer { isSaving = false }
        saveFailed = false
        if await setManualPath(peer, path, hold) {
            onSaved()
            dismiss()
        } else {
            saveFailed = true
        }
    }

    private var path: ManualPath {
        ManualPath(hops: hops.map(\.hint), floodHops: floodHops)
    }

    static func hopsText(_ hops: Int) -> String {
        "\(hops) hop\(hops == 1 ? "" : "s")"
    }

    /// A flood allowance as a row value: none, or how many hops.
    static func floodText(_ hops: UInt8) -> String {
        hops == 0 ? "Off" : hopsText(Int(hops))
    }
}
