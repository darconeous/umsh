import Foundation
import SwiftUI

struct NetworkView: View {
    @Binding var radioSnapshot: RadioSnapshot
    let peers: [PeerSummary]
    let inspectPeerIdentity: (String) async -> Result<MeshNodeURIPreview, MeshEngineError>
    let savePeer: (MeshPublicIdentity, PeerImportDetails) async -> Void
    let startConversation: ((PeerSummary) async -> DirectConversationSummary?)?
    let updateDraft: ((Int64, String) async -> Void)?
    let pingPeer: ((PeerSummary) async -> PeerPingResult)?
    @State private var presentation: NetworkPresentation = .list
    @State private var showsAddPeer = false

    var body: some View {
        VStack(spacing: 0) {
            Picker("Presentation", selection: $presentation) {
                Text("List").tag(NetworkPresentation.list)
                Text("Map").tag(NetworkPresentation.map)
            }
            .pickerStyle(.segmented)
            .padding()

            switch presentation {
            case .list: peerList
            case .map:
                ContentUnavailableView {
                    Label("No reported locations", systemImage: "map")
                } description: {
                    Text("Locations reported by observed nodes will appear here with their precision and age.")
                }
            }
        }
        .navigationTitle("Network")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("Add peer", systemImage: "person.badge.plus") { showsAddPeer = true }
            }
        }
        .sheet(isPresented: $showsAddPeer) {
            NavigationStack {
                NodeImportView(
                    inspectPeerIdentity: inspectPeerIdentity,
                    save: { identity, details, _ in
                        await savePeer(identity, details)
                        showsAddPeer = false
                    }
                )
            }
        }
    }

    @ViewBuilder
    private var peerList: some View {
        if peers.isEmpty {
            ContentUnavailableView {
                Label("No known nodes", systemImage: "point.3.connected.trianglepath.dotted")
            } description: {
                Text("Import a peer or start a bounded discovery session.")
            } actions: {
                Button("Discover peers") {}
                    .buttonStyle(.borderedProminent)
            }
        } else {
            List {
                let radios = peers.filter(\.isCompanionRadio)
                if !radios.isEmpty {
                    Section("Saved radio") {
                        ForEach(radios) { peer in peerLink(peer) }
                    }
                }
                let contacts = peers.filter { !$0.isCompanionRadio && $0.isContact }
                if !contacts.isEmpty {
                    Section("Contacts") {
                        ForEach(contacts) { peer in peerLink(peer) }
                    }
                }
                let recent = peers.filter { !$0.isCompanionRadio && !$0.isContact }
                if !recent.isEmpty {
                    Section("Known nodes") {
                        ForEach(recent) { peer in peerLink(peer) }
                    }
                }
                Section {
                    Button("Discover peers") {}
                } footer: {
                    Text("Discovery is bounded and may not find every nearby node.")
                }
            }
            .listStyle(.insetGrouped)
        }
    }

    private func peerLink(_ peer: PeerSummary) -> some View {
        NavigationLink {
            PeerDetailView(
                peer: peer,
                radioSnapshot: $radioSnapshot,
                startConversation: startConversation,
                updateDraft: updateDraft,
                pingPeer: pingPeer
            )
        } label: {
            HStack(spacing: 12) {
                PeerAvatar(hint: peer.identity.hint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(peer.displayName)
                    Text(peer.isCompanionRadio
                         ? "Companion radio identity · \(peer.identity.hint.text)"
                         : peer.identity.hint.text)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }
}

struct PeerDetailView: View {
    let peer: PeerSummary
    @Binding var radioSnapshot: RadioSnapshot
    let startConversation: ((PeerSummary) async -> DirectConversationSummary?)?
    let updateDraft: ((Int64, String) async -> Void)?
    let pingPeer: ((PeerSummary) async -> PeerPingResult)?

    @State private var openedConversation: DirectConversationSummary?
    @State private var isOpeningConversation = false
    @State private var isPinging = false
    @State private var pingStatus: PeerPingStatus?
    @State private var feedbackTitle = ""
    @State private var feedbackMessage = ""
    @State private var showsFeedback = false

    init(
        peer: PeerSummary,
        radioSnapshot: Binding<RadioSnapshot>,
        startConversation: ((PeerSummary) async -> DirectConversationSummary?)? = nil,
        updateDraft: ((Int64, String) async -> Void)? = nil,
        pingPeer: ((PeerSummary) async -> PeerPingResult)? = nil
    ) {
        self.peer = peer
        _radioSnapshot = radioSnapshot
        self.startConversation = startConversation
        self.updateDraft = updateDraft
        self.pingPeer = pingPeer
    }

    var body: some View {
        List {
            Section {
                HStack(spacing: 16) {
                    PeerAvatar(hint: peer.identity.hint, diameter: 64)
                    VStack(alignment: .leading) {
                        Text(peer.displayName).font(.title2.bold())
                        Text(peer.isCompanionRadio ? "Companion radio identity" : "UMSH peer")
                            .foregroundStyle(.secondary)
                    }
                }
                LabeledContent("Type", value: peer.isCompanionRadio ? "Companion radio identity" : peer.kind.label)
                LabeledContent("Node hint", value: peer.identity.hint.text)
            }

            Section("Identity") {
                CanonicalAddressView(address: peer.identity.canonicalAddress)
            }

            if startConversation != nil, pingPeer != nil {
                Section("Actions") {
                    HStack(spacing: 12) {
                        Button {
                            Task { await openConversation() }
                        } label: {
                            Label("Message", systemImage: "message")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isOpeningConversation)

                        Button {
                            Task { await ping() }
                        } label: {
                            Label(isPinging ? "Pinging…" : "Ping", systemImage: "wave.3.right")
                                .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .disabled(isPinging)
                    }

                    if let pingStatus {
                        LabeledContent(isPinging ? "Ping" : "Last ping") {
                            Label(pingStatus.message, systemImage: pingStatus.symbolName)
                                .foregroundStyle(pingStatus.color)
                        }
                        if case let .reply(reply) = pingStatus {
                            LabeledContent("Round trip", value: "\(reply.roundTripMilliseconds) ms")
                            LabeledContent("Hop count", value: reply.hopCountText)
                            LabeledContent("Route path") {
                                Text(reply.routePathText)
                                    .multilineTextAlignment(.trailing)
                                    .textSelection(.enabled)
                            }
                            if let rssi = reply.rssiDBm {
                                LabeledContent("RSSI (last hop)", value: "\(rssi) dBm")
                            }
                            if let snr = reply.signalToNoiseCentibels {
                                LabeledContent("SNR (last hop)", value: Self.decibels(snr))
                            }
                            if let linkQuality = reply.linkQuality {
                                LabeledContent("Link quality (last hop)", value: "\(linkQuality)")
                            }
                        }
                    }
                }
            }

            if peer.isCompanionRadio {
                Section {
                    Text("This peer is managed by the saved radio and cannot be removed separately.")
                        .foregroundStyle(.secondary)
                    LabeledContent("Radio", value: radioSnapshot.name ?? "Saved companion radio")
                }
            }
        }
        .navigationTitle(peer.displayName)
        .navigationDestination(item: $openedConversation) { conversation in
            DirectConversationView(
                conversation: conversation,
                radioSnapshot: radioSnapshot,
                updateDraft: updateDraft ?? { _, _ in }
            )
        }
        .alert(feedbackTitle, isPresented: $showsFeedback) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(feedbackMessage)
        }
    }

    private func openConversation() async {
        guard let startConversation else { return }
        guard !isOpeningConversation else { return }
        isOpeningConversation = true
        defer { isOpeningConversation = false }
        if let conversation = await startConversation(peer) {
            openedConversation = conversation
        } else {
            feedbackTitle = "Conversation unavailable"
            feedbackMessage = "The app could not create a direct conversation for this peer."
            showsFeedback = true
        }
    }

    private func ping() async {
        guard let pingPeer else { return }
        guard !isPinging else { return }
        isPinging = true
        pingStatus = .pinging
        defer { isPinging = false }
        switch await pingPeer(peer) {
        case let .reply(reply):
            pingStatus = .reply(reply)
        case .timedOut:
            pingStatus = .timedOut
        case let .unavailable(reason):
            pingStatus = .unavailable(reason: reason)
        }
    }

    private static func decibels(_ centibels: Int16) -> String {
        String(format: "%.2f dB", Double(centibels) / 100)
    }
}

private enum PeerPingStatus: Equatable {
    case pinging
    case reply(PeerPingReply)
    case timedOut
    case unavailable(reason: String)

    var message: String {
        switch self {
        case .pinging: "Waiting for reply…"
        case let .reply(reply): "Reply in \(reply.roundTripMilliseconds) ms"
        case .timedOut: "Timed out"
        case let .unavailable(reason): reason
        }
    }

    var symbolName: String {
        switch self {
        case .pinging: "clock"
        case .reply: "checkmark.circle.fill"
        case .timedOut: "clock.badge.exclamationmark"
        case .unavailable: "exclamationmark.triangle.fill"
        }
    }

    var color: Color {
        switch self {
        case .pinging: .secondary
        case .reply: .green
        case .timedOut: .orange
        case .unavailable: .red
        }
    }
}

private extension PeerPingReply {
    var hopCountText: String {
        hopCount.map(String.init) ?? "Not reported"
    }

    var routePathText: String {
        let intermediates = routeHints.map { hint in
            hint.map { String(format: "%02X", $0) }.joined()
        }
        if intermediates.isEmpty {
            return hopCount == 1 ? "Phone → Peer (direct)" : "Not reported"
        }
        return (["Phone"] + intermediates + ["Peer"]).joined(separator: " → ")
    }
}

private enum NetworkPresentation: Hashable {
    case list
    case map
}
