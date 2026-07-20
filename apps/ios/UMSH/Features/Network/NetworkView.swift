import Foundation
import SwiftUI

struct NetworkView: View {
    @Binding var radioSnapshot: RadioSnapshot
    @Binding var conversations: [DirectConversationSummary]
    let peers: [PeerSummary]
    let inspectPeerIdentity: (String) async -> Result<MeshNodeURIPreview, MeshEngineError>
    let savePeer: (MeshNodeURIPreview, PeerImportDetails) async -> Void
    let startConversation: ((PeerSummary) async -> DirectConversationSummary?)?
    let updateDraft: ((Int64, String) async -> Void)?
    let sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)?
    var messageActions: ChatMessageActions = .unavailable
    let pingPeer: ((PeerSummary) async -> PeerPingResult)?
    var updateAlias: ((PeerSummary, String?) async -> Bool)? = nil
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
                    save: { preview, details, _ in
                        await savePeer(preview, details)
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
                conversations: $conversations,
                startConversation: startConversation,
                updateDraft: updateDraft,
                sendMessage: sendMessage,
                messageActions: messageActions,
                pingPeer: pingPeer,
                updateAlias: updateAlias
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
    @Binding var conversations: [DirectConversationSummary]
    let startConversation: ((PeerSummary) async -> DirectConversationSummary?)?
    let updateDraft: ((Int64, String) async -> Void)?
    let sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)?
    let messageActions: ChatMessageActions
    let pingPeer: ((PeerSummary) async -> PeerPingResult)?
    let updateAlias: ((PeerSummary, String?) async -> Bool)?

    @State private var openedConversation: DirectConversationSummary?
    @State private var isOpeningConversation = false
    @State private var isPinging = false
    @State private var pingStatus: PeerPingStatus?
    @State private var feedbackTitle = ""
    @State private var feedbackMessage = ""
    @State private var showsFeedback = false
    // The pushed view keeps its own copy so a saved alias is visible
    // immediately even though the parent's peer list refreshes later.
    @State private var currentAlias: String?
    @State private var isEditingAlias = false
    @State private var aliasDraft = ""

    init(
        peer: PeerSummary,
        radioSnapshot: Binding<RadioSnapshot>,
        conversations: Binding<[DirectConversationSummary]> = .constant([]),
        startConversation: ((PeerSummary) async -> DirectConversationSummary?)? = nil,
        updateDraft: ((Int64, String) async -> Void)? = nil,
        sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)? = nil,
        messageActions: ChatMessageActions = .unavailable,
        pingPeer: ((PeerSummary) async -> PeerPingResult)? = nil,
        updateAlias: ((PeerSummary, String?) async -> Bool)? = nil
    ) {
        self.peer = peer
        _radioSnapshot = radioSnapshot
        _conversations = conversations
        self.startConversation = startConversation
        self.updateDraft = updateDraft
        self.sendMessage = sendMessage
        self.messageActions = messageActions
        self.pingPeer = pingPeer
        self.updateAlias = updateAlias
        _currentAlias = State(initialValue: peer.alias)
    }

    var body: some View {
        List {
            Section {
                HStack(spacing: 16) {
                    PeerAvatar(hint: peer.identity.hint, diameter: 64)
                    VStack(alignment: .leading) {
                        Text(displayedName).font(.title2.bold())
                        Text(peer.isCompanionRadio ? "Companion radio identity" : "UMSH peer")
                            .foregroundStyle(.secondary)
                    }
                }
                LabeledContent("Type", value: peer.isCompanionRadio ? "Companion radio identity" : peer.kind.label)
                LabeledContent("Node hint", value: peer.identity.hint.text)
                if updateAlias != nil {
                    LabeledContent("Alias") {
                        Button {
                            aliasDraft = currentAlias ?? ""
                            isEditingAlias = true
                        } label: {
                            HStack(spacing: 6) {
                                Text(currentAlias ?? "None")
                                    .foregroundStyle(currentAlias == nil ? .secondary : .primary)
                                Image(systemName: "pencil")
                                    .font(.caption)
                            }
                        }
                    }
                }
            }

            Section("Identity") {
                IdentityShareView(uri: peer.identity.nodeURI)
                CanonicalAddressView(address: peer.identity.canonicalAddress)
            }

            if let advertised = peer.advertisedIdentity {
                Section {
                    AdvertisedIdentityRows(identity: advertised)
                } header: {
                    Text("Advertised identity")
                } footer: {
                    Text(advertised.signature == .valid
                         ? "These details were published and signed by the peer."
                         : "These details were published by the peer but are not authenticated.")
                }
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
        .navigationTitle(displayedName)
        .alert("Alias", isPresented: $isEditingAlias) {
            TextField("Alias", text: $aliasDraft)
                .textInputAutocapitalization(.words)
            Button("Save") {
                Task { await saveAlias() }
            }
            if currentAlias != nil {
                Button("Remove Alias", role: .destructive) {
                    aliasDraft = ""
                    Task { await saveAlias() }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The alias is a private name stored only on this phone.")
        }
        .navigationDestination(item: $openedConversation) { conversation in
            if let conversation = binding(for: conversation.id) {
                DirectConversationView(
                    conversation: conversation,
                    radioSnapshot: radioSnapshot,
                    updateDraft: updateDraft ?? { _, _ in },
                    sendMessage: sendMessage ?? { _, _ in .failed("Messaging is unavailable.") },
                    messageActions: messageActions,
                    updateAlias: updateAlias
                )
            }
        }
        .alert(feedbackTitle, isPresented: $showsFeedback) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(feedbackMessage)
        }
    }

    private var displayedName: String {
        currentAlias
            ?? peer.advertisedName
            ?? (peer.isCompanionRadio ? "Companion radio" : peer.identity.hint.text)
    }

    private func saveAlias() async {
        guard let updateAlias else { return }
        let trimmed = aliasDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        let newAlias = trimmed.isEmpty ? nil : trimmed
        if await updateAlias(peer, newAlias) {
            currentAlias = newAlias
        } else {
            feedbackTitle = "Alias not saved"
            feedbackMessage = "The alias could not be stored. Try again."
            showsFeedback = true
        }
    }

    private func binding(for conversationID: Int64) -> Binding<DirectConversationSummary>? {
        guard let fallback = conversations.first(where: { $0.id == conversationID }) else { return nil }
        return Binding(
            get: {
                conversations.first(where: { $0.id == conversationID }) ?? fallback
            },
            set: { updated in
                guard let index = conversations.firstIndex(where: { $0.id == conversationID }) else {
                    return
                }
                conversations[index] = updated
            }
        )
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
        String(format: "%.1f dB", Double(centibels) / 10)
    }
}

/// Rows describing a decoded advertised node identity. Shared by the peer
/// sheet and the import preview.
struct AdvertisedIdentityRows: View {
    let identity: MeshNodeIdentity

    var body: some View {
        if let name = identity.name {
            LabeledContent("Name", value: name)
        }
        LabeledContent("Role", value: identity.roleLabel)
        if !identity.capabilities.isEmpty {
            LabeledContent("Capabilities") {
                Text(identity.capabilities.joined(separator: ", "))
                    .multilineTextAlignment(.trailing)
            }
        }
        if let latitude = identity.latitude, let longitude = identity.longitude {
            LabeledContent("Location") {
                VStack(alignment: .trailing) {
                    Text(Self.coordinate(latitude, longitude))
                        .textSelection(.enabled)
                    if let precision = identity.locationPrecision {
                        Text("within \(Self.precisionLabel(precision))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        if let altitude = identity.altitudeMeters {
            LabeledContent("Altitude", value: "\(altitude) m")
        }
        if let timestamp = identity.timestamp {
            LabeledContent("Reported") {
                Text(
                    Date(timeIntervalSince1970: TimeInterval(timestamp)),
                    format: .dateTime.year().month().day().hour().minute()
                )
            }
        }
        LabeledContent("Authenticity") {
            switch identity.signature {
            case .valid:
                Label("Signed by this node", systemImage: "checkmark.seal.fill")
                    .foregroundStyle(.green)
            case .unsigned:
                Label("Not signed", systemImage: "seal")
                    .foregroundStyle(.secondary)
            case .invalid:
                Label("Signature invalid", systemImage: "xmark.seal.fill")
                    .foregroundStyle(.red)
            }
        }
    }

    private static func coordinate(_ latitude: Double, _ longitude: Double) -> String {
        String(format: "%.4f°, %.4f°", latitude, longitude)
    }

    /// Approximate equator cell size for each grid-code precision.
    private static func precisionLabel(_ precision: UInt8) -> String {
        switch precision {
        case 1: "about 2,500 km"
        case 2: "about 156 km"
        case 3: "about 10 km"
        case 4: "about 610 m"
        case 5: "about 38 m"
        case 6: "about 2.4 m"
        default: "about 15 cm"
        }
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
