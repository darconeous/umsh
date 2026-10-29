import SwiftUI

/// The held route, offered for replacement by the path the mesh taught while
/// it was failing. Asked once per saved path: closing the sheet without
/// switching keeps the manual path and settles the question.
struct LearnedPathPromptSheet: View {
    let peer: PeerSummary
    /// The held route, carrying its learned rival.
    let route: PeerRoute
    let actions: PeerActions

    @Environment(\.dismiss) private var dismiss
    @State private var isSwitching = false
    @State private var didDecide = false

    var body: some View {
        NavigationStack {
            List {
                Section {
                    Text(manualPathText)
                    Label(
                        "No ack on the last \(route.fallbackAcks) send\(route.fallbackAcks == 1 ? "" : "s")",
                        systemImage: "xmark.circle"
                    )
                    .foregroundStyle(.orange)
                } header: {
                    header("Manual", hops: route.heldFloodFromStart.map(Int.init) ?? route.hints.count + 1)
                }
                if let candidate = route.candidate {
                    Section {
                        Text(candidate.hints.isEmpty ? "Direct" : pathText(candidate.hints))
                        Label("Carried the flooded acks", systemImage: "checkmark.circle")
                            .foregroundStyle(.green)
                    } header: {
                        header("Learned", hops: candidate.hopCount.map(Int.init) ?? candidate.hints.count + 1)
                    }
                }
            }
            // Pinned, so both choices show at the medium detent however
            // long the paths run.
            .safeAreaInset(edge: .bottom) {
                VStack(spacing: 10) {
                    Button {
                        Task { await useLearned() }
                    } label: {
                        Text(isSwitching ? "Switching…" : "Use Learned Path")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isSwitching)
                    Button {
                        dismiss()
                    } label: {
                        Text("Keep Manual Path").frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.bordered)
                }
                .controlSize(.large)
                .padding()
                .background(.bar)
            }
            .navigationTitle("Switch to the learned path?")
            .navigationBarTitleDisplayMode(.inline)
        }
        .presentationDetents([.medium, .large])
        .onDisappear {
            guard !didDecide else { return }
            Task { await actions.keepManualPath?(peer) }
        }
    }

    private func header(_ title: String, hops: Int) -> some View {
        HStack {
            Text(title)
            Spacer()
            Text(verbatim: RoutePresentation.hopsText(hops))
        }
    }

    private var manualPathText: String {
        if !route.hints.isEmpty { return pathText(route.hints) }
        return route.heldFloodFromStart == nil
            ? String(localized: "Direct", comment: "Route kind: in radio range, no repeaters.")
            : String(localized: "Flood", comment: "Route kind: every repeater rebroadcasts the frame. A routing term, not water.")
    }

    private func pathText(_ hints: [MeshRouterHint]) -> String {
        hints.map { RouterHintNaming.label($0, among: actions.knownPeers) }.joined(separator: " › ")
    }

    private func useLearned() async {
        guard let adopt = actions.adoptLearnedPath, !isSwitching else { return }
        isSwitching = true
        defer { isSwitching = false }
        if await adopt(peer) {
            didDecide = true
            dismiss()
        }
    }
}
