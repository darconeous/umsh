import Foundation
import SwiftUI
import UMSHMobileCore

/// A live view of the nodes heard while this sheet is open.
///
/// Discovery works two ways at once. Actively, the Ask button sends a MAC
/// Identity Request carrying this phone's full address, so matching nodes
/// reply straight back with their identities. Nothing is transmitted until
/// the user asks. Passively, the sheet shows the announcements nodes make on
/// their own. Either way the results are a live filter over the same peer
/// records everything else uses—a node heard here lands in the transient
/// tier, and Save is an ordinary promote.
///
/// Where the ask goes is the `vantage`. By default it is one zero-hop direct
/// broadcast: repeaters never carry it, so the blast radius is exactly the
/// nodes in range. Given a vantage it is steered down that route instead and
/// answered by whatever is in range of where it lands, which is the only way
/// to find nodes this phone cannot hear. It is never flooded—nothing would
/// bound how many nodes answered.
///
/// The radio listens whenever it is attached, so this sheet starts and stops
/// nothing: `startedAt` is only the lower bound of the window it displays.
struct DiscoverPeersView: View {
    @Binding var radioSnapshot: RadioSnapshot
    @Binding var conversations: [DirectConversationSummary]
    let peers: [PeerSummary]
    var peerActions: PeerActions = .unavailable
    var messageActions: ChatMessageActions = .unavailable
    /// Broadcast this phone's signed identity; throws why it did not go.
    /// Offered behind a confirmation that previews what is sent.
    var advertiseIdentity: (() async throws -> Void)? = nil
    /// The name the announcement carries, for the confirmation preview.
    var advertisedName: String = ""
    /// Drop every transient row nothing depends on.
    var clearDiscoveredNodes: (() async throws -> Void)? = nil
    /// Send one Identity Request asking matching nodes to identify
    /// themselves—in this phone's own range, or in range of the vantage's
    /// landing point. Returns once it was handed to the radio.
    var solicitNearbyIdentities: ((PeerRole?, SolicitVantage?) async throws -> Void)? = nil
    /// Where the ask is aimed; nil is this phone's own neighborhood. A
    /// binding because the sheet is presented once at the app root and
    /// re-aimed by deep links from peer pages—`@State` seeded from a
    /// parameter would keep the first value forever.
    @Binding var vantage: SolicitVantage?
    /// Hands a freshly created conversation to the app root after this
    /// sheet dismisses itself.
    var openConversation: (DirectConversationSummary) -> Void = { _ in }

    @Environment(\.dismiss) private var dismiss
    /// Pushed peer pages. Owned here so re-aiming from one can pop back to
    /// the control that shows the change.
    @State private var path: [PeerSummary] = []
    /// Lower bound of the displayed window: nodes heard since the sheet opened.
    @State private var startedAt = Date()
    @State private var showsAnnounceConfirmation = false
    @State private var didAnnounce = false
    @State private var showsClearConfirmation = false
    @State private var roleFilter: PeerRole?
    @State private var isSoliciting = false
    @State private var lastSolicitedAt: Date?
    @State private var solicitNotice: String?
    @State private var failure: FailureNotice?

    /// Minimum spacing between solicitations—one ask is one broadcast,
    /// and mashing the button must not become airtime.
    static let solicitCooldown: TimeInterval = 40

    var body: some View {
        NavigationStack(path: $path) {
            // The tick drives only the solicit cooldown.
            TimelineView(.periodic(from: .now, by: 1)) { context in
                List {
                    solicitSection(now: context.date)
                    resultsSection
                    announceSection
                }
                .listStyle(.insetGrouped)
            }
            .navigationDestination(for: PeerSummary.self) { peer in
                PeerDetailView(
                    peer: peer,
                    radioSnapshot: $radioSnapshot,
                    conversations: $conversations,
                    actions: peerActions,
                    messageActions: messageActions
                )
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
                "Announce Your Identity?",
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
                "Clear Discovered Nodes?",
                isPresented: $showsClearConfirmation,
                titleVisibility: .visible
            ) {
                Button("Clear Discovered Nodes", role: .destructive) {
                    Task {
                        await $failure.attempt(String(localized: "Nodes Not Cleared", comment: "Alert title.")) {
                            try await clearDiscoveredNodes?()
                        }
                    }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("Removes every node heard over the air that is not saved, has no conversation, and is not stored on the radio. Saved nodes are untouched.")
            }
            .failureAlert($failure)
        }
        // Outside the NavigationStack so both the root list and any pushed
        // peer page are descendants, and the nearest-ancestor rule points
        // both at this sheet rather than the app root's opener. A peer page
        // pushed from a result can therefore re-aim the sheet it is already
        // inside; the root's version would set an already-true presentation
        // flag and silently do nothing but swap the vantage behind a page the
        // user is still reading.
        //
        // Not `dismiss()` then reopen: re-presenting a sheet while one is
        // dismissing gets swallowed.
        .environment(\.askNearbyIdentities) { newVantage in
            vantage = newVantage
            // Back to the root, where the control that just changed lives.
            path.removeAll()
        }
    }

    // MARK: - Sections

    /// The active half of discovery: one Identity Request that matching nodes
    /// in range of the chosen vantage answer with a unicast identity.
    @ViewBuilder
    private func solicitSection(now: Date) -> some View {
        if solicitNearbyIdentities != nil {
            Section {
                vantageRow
                Picker("Ask", selection: $roleFilter) {
                    Text("All nodes").tag(PeerRole?.none)
                    ForEach(PeerRole.selectable) { role in
                        Text(role.label).tag(PeerRole?.some(role))
                    }
                }
                Button {
                    Task { await solicit() }
                } label: {
                    Label(askButtonTitle, systemImage: "wave.3.right")
                }
                .disabled(!radioListening || isSoliciting || cooldownRemaining(now) > 0)
            } footer: {
                if let footer = solicitFooter(now: now) {
                    Text(footer)
                }
            }
        }
    }

    /// Where the ask goes. Always shown, even with nothing to choose: a row
    /// that appears only once a vantage is set would leave the default
    /// unstated, and clearing one would read as the control breaking.
    ///
    /// Clearing *is* selecting "Nearby", which is why there is no separate
    /// destructive button and why the remote option stays there to flip back
    /// to.
    @ViewBuilder
    private var vantageRow: some View {
        if let vantage {
            Picker("Where to ask", selection: $vantage) {
                Text("Nearby—direct").tag(SolicitVantage?.none)
                Text(Self.vantageLabel(vantage)).tag(SolicitVantage?.some(vantage))
            }
        } else {
            LabeledContent("Where to ask", value: "Nearby—direct")
        }
    }

    private static func vantageLabel(_ vantage: SolicitVantage) -> String {
        String(
            localized: "\(vantage.repeaters.count) hops to \(vantage.peerName)",
            comment: "Where a Discover ask goes: the hops it takes to reach a peer. Has plural variants."
        )
    }

    private var askButtonTitle: String {
        guard let vantage else {
            return String(localized: "Ask Nearby Nodes to Identify", comment: "Button: ask the nodes in range to identify themselves.")
        }
        return String(
            localized: "Ask Nodes Near \(vantage.peerName) to Identify",
            comment: "Button: ask the nodes in range of a peer to identify themselves. The placeholder is the peer's name."
        )
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
            return String(
                localized: "Connect a companion radio set up for this phone to ask.",
                comment: "Footer under Discover's ask when no radio can send it."
            )
        }
        let cooldown = cooldownRemaining(now)
        if cooldown > 0 {
            // One cooldown covers both kinds of ask: each is a transmission
            // whatever it is aimed at, so re-aiming does not buy a free one.
            let wait = Duration.seconds(Int(cooldown.rounded(.up)))
                .formatted(.units(allowed: [.seconds], width: .abbreviated))
            return String(
                localized: "Asked—replies appear below. Ask again in \(wait).",
                comment: "Footer under Discover's ask after it was sent. The placeholder is a duration, such as 40 sec."
            )
        }
        return vantageFooter
    }

    /// What a steered ask actually reaches, said plainly. The nodes that
    /// answer are whatever the *landing point* can hear, which is not the same
    /// as what the named peer knows about—and when the landing point is the
    /// peer itself, that rests on it forwarding at all.
    private var vantageFooter: String? {
        guard let vantage else { return nil }
        // Hops to the landing node, which is the route's last hint: one
        // transmission per hint.
        let hops = vantage.repeaters.count
        let peer = vantage.peerName
        switch (vantage.landsAtPeer, vantage.evidence) {
        case (true, .yes):
            return String(
                localized: "Sent \(hops) hops to \(peer), which answers along with whatever else is in range of it—not of this phone.",
                comment: "Footer under Discover's ask aimed at a peer known to repeat. Has plural variants."
            )
        case (true, _):
            // Aimed at the peer on no evidence it repeats. Say so: if it does
            // not forward, the ask simply goes unanswered.
            return String(
                localized: "Sent \(hops) hops to \(peer). This phone has never heard what \(peer) is, so this only reaches anything if it forwards traffic; if it does not, nothing answers.",
                comment: "Footer under Discover's ask aimed at a peer not known to repeat. Has plural variants."
            )
        case (false, _):
            guard let landing = vantage.landingRepeater else { return nil }
            let name = RouterHintNaming.label(landing, among: peerActions.knownPeers)
            return String(
                localized: "This phone has no evidence \(peer) repeats, so the ask stops at \(name), the last repeater on the way there, and is answered by whatever is in range of it. \(RouterHintNaming.ambiguityNote)",
                comment: "Footer under Discover's ask that stops short of a peer. The first placeholder is the peer, the second the repeater it stops at, the last a sentence about guessed repeater names."
            )
        }
    }

    private func solicit() async {
        guard let solicitNearbyIdentities, !isSoliciting else { return }
        isSoliciting = true
        defer { isSoliciting = false }
        do {
            try await solicitNearbyIdentities(roleFilter, vantage)
            lastSolicitedAt = Date()
            solicitNotice = nil
        } catch {
            solicitNotice = MobileAppError.message(for: error)
        }
    }


    @ViewBuilder
    private var resultsSection: some View {
        Section {
            let found = results
            if found.isEmpty {
                Text("Nothing heard yet.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(found) { peer in resultRow(peer) }
            }
        } header: {
            Text("Heard since opened")
        } footer: {
            Text(radioListening
                 ? "Nodes that announce themselves appear here while this stays open. This is a live window, not a directory of the mesh."
                 : "Connect a companion radio set up for this phone to hear nearby nodes.")
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
                if !radioListening {
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
        // Value-based so a pushed page can be popped programmatically, which
        // is how re-aiming from one gets back to the control it changed.
        NavigationLink(value: peer) {
            PeerRow(
                peer: peer,
                subtitle: [
                    peer.isSaved ? "Saved" : "Heard \(Self.heardLabel(peer.lastHeard))",
                    peer.roleLabel,
                ].compactMap { $0 }.joined(separator: " · ")
            )
        }
        .swipeActions(edge: .leading, allowsFullSwipe: false) {
            if !peer.isSaved, peerActions.promoteToSaved != nil {
                Button {
                    Task {
                        await $failure.attempt(String(localized: "Peer Not Saved", comment: "Alert title.")) {
                            try await peerActions.promoteToSaved?(peer)
                        }
                    }
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

    private var radioListening: Bool { radioSnapshot.carriesThisPhone }

    private var announcePreview: String {
        let name = advertisedName.isEmpty
            ? "without a name—only your address and hint"
            : "as \"\(advertisedName)\""
        return "Broadcasts your signed public identity \(name) to every node in range, and repeaters may carry it further. It contains no private keys and cannot be unsent."
    }

    private func announce() async {
        guard let advertiseIdentity else { return }
        let sent = await $failure.attempt(
            String(localized: "Identity Not Advertised", comment: "Alert title: this phone's identity advertisement did not go out. The message says why.")
        ) {
            try await advertiseIdentity()
        }
        if sent { didAnnounce = true }
    }

    private func message(_ peer: PeerSummary) async {
        guard let startConversation = peerActions.startConversation else { return }
        do {
            let conversation = try await startConversation(peer)
            dismiss()
            openConversation(conversation)
        } catch {
            failure = FailureNotice(String(localized: "Conversation Unavailable", comment: "Alert title."), error)
        }
    }

    private static func heardLabel(_ date: Date?) -> String {
        guard let date else { return "just now" }
        return date.formatted(.relative(presentation: .named))
    }
}

extension EnvironmentValues {
    /// Opens Discover Peers with its "Where to ask" control preset to the
    /// given vantage.
    ///
    /// An environment closure rather than a parameter because `PeerDetailView`
    /// is built from seven places and most of them have no business knowing
    /// this sheet exists; and rather than a `PeerActions` field because
    /// everything in that bundle is an operation on a peer, while this is a
    /// navigation intent. Same shape and the same reasoning as
    /// `openRadioDetail`.
    ///
    /// Nil when nothing above the view can present the sheet: a peer page
    /// reached from Settings or device setup hides the action rather than
    /// offering one that goes nowhere.
    @Entry var askNearbyIdentities: ((SolicitVantage?) -> Void)? = nil
}
