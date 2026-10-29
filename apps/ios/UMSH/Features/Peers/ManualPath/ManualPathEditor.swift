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
        if hop.enteredByHand {
            detail.append(String(
                localized: "Entered by hand · \(hop.hint.hexText)",
                comment: "Under a repeater typed into a manual path. The placeholder is its hint in hex."
            ))
        }
        if let signal = hop.signal { detail.append(signal) }
        return RouterHintRow(hint: hop.hint, named: hop.named(among: knownPeers), detail: detail)
    }
}

/// A manual path being edited: the repeaters a node is reached through, how
/// far the frame may flood past them, and how long the choice stands ahead of
/// anything the mesh teaches.
///
/// Held apart from the view so the Route screen can edit in place: its own
/// list shows these sections while editing and its route otherwise.
@MainActor @Observable
final class ManualPathDraft {
    /// The most repeaters a source route carries.
    static let maximumHops = 15

    var hops: [ManualPathHop]
    var floodHops: UInt8
    var hold = ManualPathHold.standard
    var pingResult: PeerPingResult?
    var isPinging = false
    var isSaving = false
    var saveFailed = false

    init(route: PeerRoute?) {
        hops = (route?.hints ?? []).map { ManualPathHop(hint: $0) }
        floodHops = route?.heldFloodHops ?? ManualPath.standardFloodHops
    }

    var path: ManualPath {
        ManualPath(hops: hops.map(\.hint), floodHops: floodHops)
    }

    /// Ping down the path as it stands, installing nothing.
    func ping(_ peer: PeerSummary, actions: PeerActions) async {
        guard let pingAlongPath = actions.pingAlongPath, !isPinging else { return }
        isPinging = true
        defer { isPinging = false }
        pingResult = await pingAlongPath(peer, path)
    }

    /// Hold the path, answering whether the phone's routing took it.
    func save(_ peer: PeerSummary, actions: PeerActions) async -> Bool {
        guard let setManualPath = actions.setManualPath, !isSaving else { return false }
        isSaving = true
        defer { isSaving = false }
        saveFailed = !(await setManualPath(peer, path, hold))
        return !saveFailed
    }
}

/// The sections of a manual path being edited, for a list in edit mode.
struct ManualPathEditSections: View {
    @Bindable var draft: ManualPathDraft
    let peer: PeerSummary
    let actions: PeerActions
    let radioName: String?

    @State private var isAddingHop = false

    var body: some View {
        pathSection
        testSection
        holdSection
        if draft.saveFailed {
            Section {
                Text("This phone's routing did not take the path. Check the radio and try again.", comment: "Shown when saving a manual path failed.")
                    .foregroundStyle(.red)
            }
        }
    }

    private var pathSection: some View {
        Section {
            PathRail(stops: [PathRailStop(id: 0, kind: .phone(radioName: radioName))], legs: [])
                .moveDisabled(true)
                .deleteDisabled(true)
            ForEach(draft.hops) { hop in
                ManualPathHopRow(hop: hop, knownPeers: actions.knownPeers)
            }
            .onMove { draft.hops.move(fromOffsets: $0, toOffset: $1) }
            .onDelete { draft.hops.remove(atOffsets: $0) }
            if draft.hops.count < ManualPathDraft.maximumHops {
                Button {
                    isAddingHop = true
                } label: {
                    Label {
                        Text("Add Hop…", comment: "Button: add a repeater to a manual path.")
                    } icon: {
                        Image(systemName: "plus.circle.fill")
                    }
                }
                .moveDisabled(true)
                .deleteDisabled(true)
                .accessibilityIdentifier("route.edit.addHop")
            }
            Stepper(value: $draft.floodHops, in: 0...ManualPath.maximumFloodHops) {
                LabeledContent {
                    Text(verbatim: RoutePresentation.floodText(draft.floodHops))
                } label: {
                    if draft.hops.isEmpty {
                        Text("Flood", comment: "Stepper label: how far a manual path floods from the start.")
                    } else {
                        Text("Then flood", comment: "Stepper label: how far a manual path floods past its last repeater.")
                    }
                }
            }
            .moveDisabled(true)
            .deleteDisabled(true)
            PeerRow(peer: peer, size: .compact)
                .moveDisabled(true)
                .deleteDisabled(true)
        } header: {
            HStack {
                Text("Path", comment: "Section header: the repeaters a route goes through.")
                Spacer()
                Text(verbatim: RoutePresentation.hopsText(draft.hops.count + 1))
            }
        }
        .sheet(isPresented: $isAddingHop) {
            AddHopScreen(destination: peer, actions: actions, hops: $draft.hops)
        }
        .onChange(of: draft.path) { _, _ in draft.pingResult = nil }
    }

    @ViewBuilder
    private var testSection: some View {
        if actions.pingAlongPath != nil {
            Section {
                Button {
                    Task { await draft.ping(peer, actions: actions) }
                } label: {
                    Label {
                        Text("Ping Along Path", comment: "Button: test a manual path before saving it.")
                    } icon: {
                        Image(systemName: "wave.3.right")
                    }
                }
                .disabled(draft.isPinging)
                .accessibilityIdentifier("route.edit.ping")
                if draft.isPinging {
                    ProgressView()
                } else if let result = draft.pingResult {
                    pingResultRow(result)
                }
            } header: {
                Text("Test", comment: "Section header: try a manual path before saving it.")
            }
        }
    }

    @ViewBuilder
    private func pingResultRow(_ result: PeerPingResult) -> some View {
        switch result {
        case let .reply(reply):
            LabeledContent {
                if let reading = SignalPresentation.readingText(
                    rssiDBm: reply.rssiDBm,
                    snrCentibels: reply.signalToNoiseCentibels
                ) {
                    Text(verbatim: reading)
                }
            } label: {
                Label {
                    Text(verbatim: PingSheet.secondsText(Double(reply.roundTripMilliseconds) / 1_000))
                } icon: {
                    Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                }
            }
        case .canceled:
            EmptyView()
        case .timedOut:
            Label {
                Text("No reply", comment: "Ping result: nothing came back.")
            } icon: {
                Image(systemName: "exclamationmark.circle.fill")
            }
            .foregroundStyle(.orange)
        case let .unavailable(reason):
            Label {
                Text(verbatim: reason)
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
            }
            .foregroundStyle(.red)
        }
    }

    private var holdSection: some View {
        Section {
            Picker(selection: $draft.hold) {
                ForEach(ManualPathHold.allCases) { option in
                    Text(verbatim: option.title).tag(option)
                }
            } label: {
                Text("Hold for", comment: "Picker label: how long a manual path stands.")
            }
            .pickerStyle(.menu)
            LabeledContent {
                Text(Date.now.addingTimeInterval(draft.hold.duration), format: .dateTime.weekday(.abbreviated).hour().minute())
            } label: {
                Text("Until", comment: "Row label: when a manual path's hold ends.")
            }
        } header: {
            Text("Hold", comment: "Section header: how long a manual path stands.")
        } footer: {
            Text("Then a learned path can replace it.", comment: "Footer under a manual path's hold.")
        }
    }
}
