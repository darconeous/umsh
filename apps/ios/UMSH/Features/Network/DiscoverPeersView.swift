import Foundation
import SwiftUI

/// A bounded discovery session for nearby nodes.
///
/// Discovery works two ways at once. Actively, the Ask button sends a MAC
/// Identity Request as one zero-hop direct broadcast — repeaters never carry
/// it, keeping the blast radius to the nodes actually in range — carrying
/// this phone's full address so matching nodes reply straight back with
/// their identities. Nothing is transmitted until the user asks. Passively,
/// the session collects the announcements nodes make on their own. Either way the results are a live filter over
/// the same peer records everything else uses — a node heard here lands in
/// the transient tier, and Save is an ordinary promote.
struct DiscoverPeersView: View {
    @Binding var radioSnapshot: RadioSnapshot
    @Binding var conversations: [DirectConversationSummary]
    let peers: [PeerSummary]
    var peerActions: PeerActions = .unavailable
    let updateDraft: ((Int64, String) async -> Void)?
    let sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)?
    var messageActions: ChatMessageActions = .unavailable
    /// Broadcast this phone's signed identity; returns a failure message or
    /// nil. Offered behind a confirmation that previews what is sent.
    var advertiseIdentity: (() async -> String?)? = nil
    /// The name the announcement carries, for the confirmation preview.
    var advertisedName: String = ""
    /// Drop every transient row nothing depends on.
    var clearDiscoveredNodes: (() async -> Void)? = nil
    /// Send one zero-hop Identity Request asking matching nodes in range to
    /// identify themselves. Returns whether it was handed to the radio.
    var solicitNearbyIdentities: ((PeerRole?) async -> Bool)? = nil
    /// Hands a freshly created conversation to the app root after this
    /// sheet dismisses itself.
    var openConversation: (DirectConversationSummary) -> Void = { _ in }

    @Environment(\.dismiss) private var dismiss
    @State private var startedAt = Date()
    @State private var endsAt = Date().addingTimeInterval(DiscoverPeersView.sessionDuration)
    @State private var stoppedEarly = false
    @State private var showsAnnounceConfirmation = false
    @State private var announceNotice: String?
    @State private var didAnnounce = false
    @State private var showsClearConfirmation = false
    @State private var roleFilter: PeerRole?
    @State private var isSoliciting = false
    @State private var lastSolicitedAt: Date?
    @State private var solicitNotice: String?

    /// How long one listening session runs.
    static let sessionDuration: TimeInterval = 120

    /// Minimum spacing between solicitations — one ask is one broadcast,
    /// and mashing the button must not become airtime.
    static let solicitCooldown: TimeInterval = 10

    var body: some View {
        NavigationStack {
            TimelineView(.periodic(from: .now, by: 1)) { context in
                let remaining = max(0, endsAt.timeIntervalSince(context.date))
                let listening = !stoppedEarly && remaining > 0
                List {
                    sessionSection(remaining: remaining, listening: listening)
                    solicitSection(now: context.date)
                    resultsSection(listening: listening)
                    announceSection
                }
                .listStyle(.insetGrouped)
            }
            .navigationTitle("Discover Peers")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                if clearDiscoveredNodes != nil {
                    ToolbarItem(placement: .topBarTrailing) {
                        Menu {
                            Button("Clear Discovered Nodes", role: .destructive) {
                                showsClearConfirmation = true
                            }
                        } label: {
                            Label("More", systemImage: "ellipsis.circle")
                        }
                    }
                }
            }
            .confirmationDialog(
                "Announce your identity?",
                isPresented: $showsAnnounceConfirmation,
                titleVisibility: .visible
            ) {
                Button("Announce") {
                    Task { await announce() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(announcePreview)
            }
            .confirmationDialog(
                "Clear discovered nodes?",
                isPresented: $showsClearConfirmation,
                titleVisibility: .visible
            ) {
                Button("Clear Discovered Nodes", role: .destructive) {
                    Task { await clearDiscoveredNodes?() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Removes every node heard over the air that is not saved, has no conversation, and is not stored on the radio. Saved nodes are untouched.")
            }
        }
    }

    // MARK: - Sections

    @ViewBuilder
    private func sessionSection(remaining: TimeInterval, listening: Bool) -> some View {
        Section {
            HStack(spacing: 12) {
                if listening {
                    ProgressView(
                        value: DiscoverPeersView.sessionDuration - remaining,
                        total: DiscoverPeersView.sessionDuration
                    )
                    Text(Self.countdown(remaining))
                        .font(.body.monospacedDigit())
                        .foregroundStyle(.secondary)
                } else {
                    Label("Session ended", systemImage: "clock.badge.checkmark")
                        .foregroundStyle(.secondary)
                    Spacer()
                }
                Button(listening ? "Stop" : "Listen Again") {
                    if listening {
                        stoppedEarly = true
                    } else {
                        startedAt = Date()
                        endsAt = Date().addingTimeInterval(DiscoverPeersView.sessionDuration)
                        stoppedEarly = false
                    }
                }
                .buttonStyle(.bordered)
            }
        } footer: {
            Text(radioListening
                 ? "Listening for nodes that announce themselves. This is a bounded session, not a directory of the mesh."
                 : "Connect a companion radio set up for this phone to hear nearby nodes.")
        }
    }

    /// The active half of discovery: one zero-hop Identity Request that
    /// matching nodes in direct range answer with a unicast identity.
    @ViewBuilder
    private func solicitSection(now: Date) -> some View {
        if solicitNearbyIdentities != nil {
            Section {
                Picker("Ask", selection: $roleFilter) {
                    Text("All nodes").tag(PeerRole?.none)
                    ForEach(PeerRole.selectable) { role in
                        Text(role.label).tag(PeerRole?.some(role))
                    }
                }
                Button {
                    Task { await solicit() }
                } label: {
                    Label("Ask Nearby Nodes to Identify", systemImage: "wave.3.right")
                }
                .disabled(!radioListening || isSoliciting || cooldownRemaining(now) > 0)
            } footer: {
                if let footer = solicitFooter(now: now) {
                    Text(footer)
                }
            }
        }
    }

    private func cooldownRemaining(_ now: Date) -> TimeInterval {
        guard let lastSolicitedAt else { return 0 }
        return max(0, Self.solicitCooldown - now.timeIntervalSince(lastSolicitedAt))
    }

    private func solicitFooter(now: Date) -> String? {
        if let solicitNotice {
            return solicitNotice
        }
        if !radioListening {
            return "Connect a companion radio set up for this phone to ask."
        }
        let cooldown = cooldownRemaining(now)
        if cooldown > 0 {
            return "Asked — replies appear below. Ask again in \(Int(cooldown.rounded(.up))) s."
        }
        return nil
    }

    private func solicit() async {
        guard let solicitNearbyIdentities, !isSoliciting else { return }
        isSoliciting = true
        defer { isSoliciting = false }
        if await solicitNearbyIdentities(roleFilter) {
            lastSolicitedAt = Date()
            solicitNotice = nil
        } else {
            solicitNotice = "The request could not be sent. Check that the companion radio is connected."
        }
    }

    @ViewBuilder
    private func resultsSection(listening: Bool) -> some View {
        Section("Heard this session") {
            let found = results
            if found.isEmpty {
                Text(listening
                     ? "Nothing heard yet."
                     : "Nothing was heard this session.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(found) { peer in resultRow(peer) }
            }
        }
    }

    @ViewBuilder
    private var announceSection: some View {
        if advertiseIdentity != nil {
            Section {
                Button {
                    showsAnnounceConfirmation = true
                } label: {
                    Label(
                        didAnnounce ? "Announce Again" : "Announce My Identity",
                        systemImage: "dot.radiowaves.left.and.right"
                    )
                }
                .disabled(!radioListening)
            } footer: {
                if let announceNotice {
                    Text(announceNotice)
                } else if !radioListening {
                    Text("Connect a companion radio set up for this phone to announce your identity.")
                } else if didAnnounce {
                    Text("Announced. Nearby nodes that heard it may announce themselves in reply.")
                } else {
                    Text("Broadcasts your signed identity so nearby nodes can record you. Nothing is sent until you confirm.")
                }
            }
        }
    }

    private func resultRow(_ peer: PeerSummary) -> some View {
        NavigationLink {
            PeerDetailView(
                peer: peer,
                radioSnapshot: $radioSnapshot,
                conversations: $conversations,
                actions: peerActions,
                updateDraft: updateDraft,
                sendMessage: sendMessage,
                messageActions: messageActions
            )
        } label: {
            HStack(spacing: 12) {
                PeerAvatar(hint: peer.identity.hint)
                VStack(alignment: .leading, spacing: 2) {
                    Text(peer.displayName)
                    Text(peer.isSaved
                         ? "Saved · \(peer.identity.hint.text)"
                         : "Heard \(Self.heardLabel(peer.lastHeard)) · \(peer.identity.hint.text)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .swipeActions(edge: .leading, allowsFullSwipe: false) {
            if !peer.isSaved, peerActions.promoteToSaved != nil {
                Button {
                    Task { _ = await peerActions.promoteToSaved?(peer) }
                } label: {
                    Label("Save", systemImage: "square.and.arrow.down")
                }
                .tint(.blue)
            }
        }
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            if peerActions.startConversation != nil {
                Button {
                    Task { await message(peer) }
                } label: {
                    Label("Message", systemImage: "message")
                }
                .tint(.green)
            }
        }
    }

    // MARK: - Data

    /// Nodes whose identity announcements landed during this session,
    /// newest first. No second pipeline: `applyReceivedAdvertisement`
    /// already persisted them, so the session is just a time window over
    /// the live peer list.
    private var results: [PeerSummary] {
        peers
            .filter {
                !$0.isUlcpDevice
                    && $0.advertisedIdentity != nil
                    && ($0.lastHeard ?? .distantPast) >= startedAt
            }
            .sorted {
                ($0.lastHeard ?? .distantPast) > ($1.lastHeard ?? .distantPast)
            }
    }

    private var radioListening: Bool {
        (radioSnapshot.linkState == .attached || radioSnapshot.linkState == .ready)
            && radioSnapshot.hostState == .matchesCurrentIdentity
    }

    private var announcePreview: String {
        let name = advertisedName.isEmpty
            ? "without a name — only your address and hint"
            : "as \"\(advertisedName)\""
        return "Broadcasts your signed public identity \(name) to every node in range, and repeaters may carry it further. It contains no private keys and cannot be unsent."
    }

    private func announce() async {
        guard let advertiseIdentity else { return }
        announceNotice = await advertiseIdentity()
        if announceNotice == nil {
            didAnnounce = true
        }
    }

    private func message(_ peer: PeerSummary) async {
        guard let startConversation = peerActions.startConversation else { return }
        guard let conversation = await startConversation(peer) else { return }
        dismiss()
        openConversation(conversation)
    }

    private static func countdown(_ remaining: TimeInterval) -> String {
        let seconds = Int(remaining.rounded())
        return String(format: "%d:%02d", seconds / 60, seconds % 60)
    }

    private static func heardLabel(_ date: Date?) -> String {
        guard let date else { return "this session" }
        return date.formatted(.relative(presentation: .named))
    }
}
