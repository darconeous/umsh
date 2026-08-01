import Foundation
import SwiftUI

struct PeerDetailView: View {
    /// The entry as it stood when this view was pushed. Anchors identity, and
    /// stands in if the peer is removed while the view is open.
    private let pushedPeer: PeerSummary

    /// This peer as it stands now. A peer's details change while this view is
    /// open — an identity response lands, or a reply teaches a route — and a
    /// value captured at push time would show none of it. Resolved by address
    /// so call sites that construct a synthetic summary (the radio's own
    /// identity, a device being set up) still converge on the stored row.
    private var peer: PeerSummary {
        actions.knownPeers.first {
            $0.identity.canonicalAddress == pushedPeer.identity.canonicalAddress
        } ?? pushedPeer
    }

    @Binding var radioSnapshot: RadioSnapshot
    @Binding var conversations: [DirectConversationSummary]
    /// What this sheet can do with the node. One bundle so the sheet is the
    /// same wherever it is opened from.
    let actions: PeerActions
    let updateDraft: ((Int64, String) async -> Void)?
    let sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)?
    let messageActions: ChatMessageActions
    /// Offered when this node may not exist locally yet — a device the
    /// phone is configuring, say. Saving records it in Peers and sends
    /// nothing to the node.
    let savePeer: (() async -> Bool)?
    /// Whether that record already exists. The action is offered only when
    /// it does not; the row still says where the node stands, because a
    /// section that simply vanishes on save reads as a failure.
    let isPeerSaved: Bool

    @State private var openedConversation: DirectConversationSummary?
    @State private var isOpeningConversation = false
    @State private var isPinging = false
    @State private var pingStatus: PeerPingStatus?
    @State private var isFetchingIdentity = false
    @State private var feedbackTitle = ""
    @State private var feedbackMessage = ""
    @State private var showsFeedback = false
    @State private var identityRequest: IdentityRequestState?
    // The pushed view keeps its own copy so a saved alias is visible
    // immediately even though the parent's peer list refreshes later.
    @State private var currentAlias: String?
    // Same reasoning for the favorite switch: the toggle must flip the
    // moment it is tapped, not when the parent's peer list refresh
    // eventually reaches this pushed view.
    @State private var currentFavorite: Bool
    @State private var isEditingAlias = false
    @State private var aliasDraft = ""
    @State private var isSavingPeer = false
    @State private var didSavePeer = false
    @State private var savePeerFailed = false
    @State private var route: PeerRoute?
    @State private var isResettingRoute = false
    @State private var routeWasAlreadyClear = false
    @State private var showsRemovalDialog = false
    @State private var isMutatingDevicePeer = false
    @State private var devicePeerNotice: String?
    @Environment(\.dismiss) private var dismiss

    init(
        peer: PeerSummary,
        radioSnapshot: Binding<RadioSnapshot>,
        conversations: Binding<[DirectConversationSummary]> = .constant([]),
        actions: PeerActions = .unavailable,
        updateDraft: ((Int64, String) async -> Void)? = nil,
        sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)? = nil,
        messageActions: ChatMessageActions = .unavailable,
        savePeer: (() async -> Bool)? = nil,
        isPeerSaved: Bool = false
    ) {
        self.pushedPeer = peer
        _radioSnapshot = radioSnapshot
        _conversations = conversations
        self.actions = actions
        self.updateDraft = updateDraft
        self.sendMessage = sendMessage
        self.messageActions = messageActions
        self.savePeer = savePeer
        self.isPeerSaved = isPeerSaved
        _currentAlias = State(initialValue: peer.alias)
        _currentFavorite = State(initialValue: peer.isFavorite)
    }

    var body: some View {
        List {
            Section {
                HStack(spacing: 16) {
                    PeerAvatar(hint: peer.identity.hint, diameter: 64)
                    VStack(alignment: .leading) {
                        Text(displayedName).font(.title2.bold())
                        Text(peer.isUlcpDevice ? "Companion radio identity" : "UMSH peer")
                            .foregroundStyle(.secondary)
                    }
                }
                // The node's own claim, refreshed whenever a fresher identity
                // lands — not a local category anyone has to keep correct.
                LabeledContent("Role", value: peer.role.label)
                LabeledContent("Node hint", value: peer.identity.hint.text)
                // The one-line answer to "how does this phone reach it?",
                // above the fold; the Route section below has the detail.
                LabeledContent("Route", value: Self.routeSummary(route))
                if let lastHeard = peer.lastHeard {
                    LabeledContent("Last heard") {
                        Text(lastHeard, format: .relative(presentation: .named))
                    }
                }
                if actions.setFavorite != nil, isStoredLocally, peer.isSaved, !peer.isUlcpDevice {
                    Toggle("Favorite", isOn: Binding(
                        get: { currentFavorite },
                        set: { newValue in
                            currentFavorite = newValue
                            Task {
                                if await actions.setFavorite?(peer, newValue) != true {
                                    currentFavorite = !newValue
                                }
                            }
                        }
                    ))
                }
                if actions.updateAlias != nil {
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
                    // A reply to an Identity Request is a MIC-authenticated
                    // unicast and deliberately carries no signature of its
                    // own, so "unsigned" alone does not mean "unattributable".
                    Text(peer.advertisedIdentityIsAttributable
                         ? "These details are claims made by the peer. Nothing here is independently verified."
                         : "These details are unsigned, so they may not have come from the peer at all. Nothing here is independently verified.")
                }
            }

            if actions.startConversation != nil || actions.ping != nil {
                Section("Actions") {
                    HStack(spacing: 12) {
                        if actions.startConversation != nil {
                            Button {
                                Task { await openConversation() }
                            } label: {
                                Label("Message", systemImage: "message")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(isOpeningConversation)
                        }

                        if actions.ping != nil {
                            Button {
                                Task { await ping() }
                            } label: {
                                Label(isPinging ? "Pinging…" : "Ping", systemImage: "wave.3.right")
                                    .frame(maxWidth: .infinity)
                            }
                            .buttonStyle(.bordered)
                            .disabled(isPinging)
                        }
                    }

                    if actions.fetchIdentity != nil {
                        Button {
                            Task { await fetchPeerIdentity() }
                        } label: {
                            Label(
                                isFetchingIdentity ? "Fetching identity…" : "Fetch identity",
                                systemImage: "person.crop.circle.badge.questionmark"
                            )
                            .frame(maxWidth: .infinity)
                        }
                        .buttonStyle(.bordered)
                        .disabled(isFetchingIdentity)

                        if let identityRequest {
                            identityRequestStatus(identityRequest)
                        }
                    }

                    if let pingStatus {
                        LabeledContent(isPinging ? "Ping" : "Last ping") {
                            IconedValue(pingStatus.message, systemImage: pingStatus.symbolName)
                                .foregroundStyle(pingStatus.color)
                        }
                        if case let .reply(reply) = pingStatus {
                            LabeledContent("Round trip", value: "\(reply.roundTripMilliseconds) ms")
                            LabeledContent("Hop count", value: reply.hopCountText)
                            routePath(for: reply)
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

            routeSection

            if peer.isUlcpDevice {
                Section {
                    Text("This peer is managed by the saved radio and cannot be removed separately.")
                        .foregroundStyle(.secondary)
                    LabeledContent("Radio", value: radioSnapshot.name ?? "Saved companion radio")
                }
            }

            if !peer.isSaved, !peer.isUlcpDevice, isStoredLocally,
               actions.promoteToSaved != nil {
                Section {
                    Button {
                        Task { _ = await actions.promoteToSaved?(peer) }
                    } label: {
                        Label("Save Peer", systemImage: "square.and.arrow.down")
                    }
                } footer: {
                    Text("This node was heard over the air but is not saved. Saving records it on this phone so it appears in Peers.")
                }
            }

            storedOnSection

            removalSection

            if let savePeer {
                Section {
                    if isPeerSaved || didSavePeer {
                        Label("Saved to Peers", systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.secondary)
                    } else {
                        Button {
                            Task { await save(with: savePeer) }
                        } label: {
                            Label("Save Peer", systemImage: "square.and.arrow.down")
                        }
                        .disabled(isSavingPeer)
                    }
                } footer: {
                    if savePeerFailed {
                        Text("This node could not be saved. Its identity is unchanged either way.")
                    } else if isPeerSaved || didSavePeer {
                        Text("This node is recorded on this phone. Rename it, favorite it, or remove it from Peers.")
                    } else {
                        Text("Records this node on this phone so it can be found in Peers later. Nothing is sent to the node.")
                    }
                }
            }
        }
        .navigationTitle(displayedName)
        // Anything inbound from this peer is what teaches the MAC a route, so
        // the cached route on screen is stale exactly when we hear from them.
        // `lastHeard` moves on every such event, which makes it the trigger.
        .task(id: RouteRefreshKey(address: peer.identity.canonicalAddress, lastHeard: peer.lastHeard)) {
            await loadRoute()
        }
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
                ConversationThreadView(
                    conversation: conversation,
                    radioSnapshot: radioSnapshot,
                    updateDraft: updateDraft ?? { _, _ in },
                    sendMessage: { item, body in
                        guard case let .direct(conversation) = item, let sendMessage else {
                            return .failed("Messaging is unavailable.")
                        }
                        return await sendMessage(conversation, body)
                    },
                    messageActions: messageActions,
                    peerActions: actions,
                    conversations: $conversations
                )
            }
        }
        .alert(feedbackTitle, isPresented: $showsFeedback) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(feedbackMessage)
        }
        .confirmationDialog(
            "Remove \(displayedName)?",
            isPresented: $showsRemovalDialog,
            titleVisibility: .visible
        ) {
            if hasConversation {
                if actions.demoteToTransient != nil {
                    Button("Remove Peer") {
                        Task { _ = await actions.demoteToTransient?(peer) }
                    }
                }
                if actions.deletePeerAndConversation != nil {
                    Button("Delete Peer and Conversation", role: .destructive) {
                        Task { await deleteAndDismiss(actions.deletePeerAndConversation) }
                    }
                }
            } else if actions.deletePeer != nil {
                Button("Delete Peer", role: .destructive) {
                    Task { await deleteAndDismiss(actions.deletePeer) }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(hasConversation
                 ? "Removing the peer keeps its conversation and message history, and the node stays findable through search. Deleting the peer and conversation erases the message history too."
                 : "The node's record is deleted from this phone. Nothing is sent to the node.")
        }
    }

    /// Whether this node has a stored row at all. The sheet can be opened on
    /// a synthetic summary — a device being set up, the radio's own identity
    /// before it is recorded — and those have nothing to favorite or remove.
    private var isStoredLocally: Bool {
        actions.knownPeers.contains {
            $0.identity.canonicalAddress == pushedPeer.identity.canonicalAddress
        }
    }

    private var hasConversation: Bool {
        conversations.contains {
            $0.peer.identity.canonicalAddress == peer.identity.canonicalAddress
        }
    }

    /// Which identities hold this node's public key, and the controls to
    /// change each independently. The radio's device identity is its own
    /// UMSH node; without a peer's public key it cannot reach that peer by
    /// unicast, which is what the footer explains.
    @ViewBuilder
    private var storedOnSection: some View {
        if isStoredLocally, !peer.isUlcpDevice,
           actions.addToDeviceIdentity != nil || actions.removeFromDeviceIdentity != nil {
            Section {
                LabeledContent("This phone") {
                    if peer.isSaved {
                        Text("Saved")
                    } else if actions.promoteToSaved != nil {
                        Button("Save") {
                            Task { _ = await actions.promoteToSaved?(peer) }
                        }
                    } else {
                        Text("Not saved")
                    }
                }
                LabeledContent("Companion radio") {
                    if isOnDeviceIdentity {
                        Button("Remove") {
                            Task { await mutateDevicePeer(add: false) }
                        }
                        .disabled(devicePeerControlsUnavailable || isMutatingDevicePeer)
                    } else {
                        Button("Add") {
                            Task { await mutateDevicePeer(add: true) }
                        }
                        .disabled(
                            devicePeerControlsUnavailable
                                || deviceListFull
                                || isMutatingDevicePeer
                        )
                    }
                }
            } header: {
                Text("Stored on")
            } footer: {
                Text(storedOnFooter)
            }
        }
    }

    /// Whether the radio's device identity holds this key. The live radio
    /// read-back wins when present — `radioSnapshot` is a binding, so it
    /// stays current inside this pushed view — and the stored cache flag
    /// covers a disconnected radio.
    private var isOnDeviceIdentity: Bool {
        if let addresses = radioSnapshot.provisioning?.devPeerAddresses {
            return addresses.contains(peer.identity.canonicalAddress)
        }
        return peer.isOnDeviceIdentity
    }

    private var radioAttachedForThisPhone: Bool {
        (radioSnapshot.linkState == .attached || radioSnapshot.linkState == .ready)
            && radioSnapshot.hostState == .matchesCurrentIdentity
    }

    private var radioSupportsDeviceIdentity: Bool {
        radioSnapshot.provisioning?.supportsDeviceIdentity == true
    }

    /// A radio that advertises the capability can still refuse the list
    /// itself. Editing one this phone cannot read would be editing blind:
    /// every write would be a guess about what is already there.
    private var radioReportsDevicePeers: Bool {
        radioSnapshot.provisioning?.devPeerAddresses != nil
    }

    private var deviceListFull: Bool {
        (radioSnapshot.provisioning?.devPeerAddresses?.count ?? 0) >= devicePeerCapacity
    }

    private var devicePeerControlsUnavailable: Bool {
        !radioAttachedForThisPhone || !radioSupportsDeviceIdentity || !radioReportsDevicePeers
    }

    private var storedOnFooter: String {
        var lines = [
            "The radio's own node identity can only communicate with peers whose public keys it holds. Add your own key, for example, so you can manage the radio remotely later."
        ]
        if let devicePeerNotice {
            lines.append(devicePeerNotice)
        } else if !radioAttachedForThisPhone {
            lines.append("Connect a companion radio set up for this phone to change what it stores.")
        } else if !radioSupportsDeviceIdentity {
            lines.append("This radio does not support storing peers on its device identity.")
        } else if !radioReportsDevicePeers {
            lines.append("This radio would not report what its device identity already stores, so this phone cannot change it.")
        } else if deviceListFull, !isOnDeviceIdentity {
            lines.append("The radio's peer list is full (\(devicePeerCapacity) of \(devicePeerCapacity)) — remove one from the radio first.")
        }
        return lines.joined(separator: " ")
    }

    private func mutateDevicePeer(add: Bool) async {
        guard !isMutatingDevicePeer else { return }
        isMutatingDevicePeer = true
        defer { isMutatingDevicePeer = false }
        devicePeerNotice = nil
        let outcome = add
            ? await actions.addToDeviceIdentity?(peer)
            : await actions.removeFromDeviceIdentity?(peer)
        switch outcome {
        case .success, nil:
            break
        case .deviceFull:
            devicePeerNotice = "The radio's peer list is full (\(devicePeerCapacity) of \(devicePeerCapacity)) — remove one from the radio first."
        case .radioUnavailable:
            devicePeerNotice = "Connect a companion radio set up for this phone to change what it stores."
        case .unsupported:
            devicePeerNotice = "This radio does not support storing peers on its device identity."
        case .failed:
            devicePeerNotice = "The radio rejected the change. Try again."
        }
    }

    /// Removal is offered for any stored node except the saved radio, whose
    /// release path is Forget Radio in Settings.
    @ViewBuilder
    private var removalSection: some View {
        if isStoredLocally, !peer.isUlcpDevice, peer.isSaved,
           actions.demoteToTransient != nil || actions.deletePeer != nil {
            Section {
                Button(role: .destructive) {
                    showsRemovalDialog = true
                } label: {
                    Label(
                        hasConversation ? "Remove Peer…" : "Delete Peer…",
                        systemImage: "trash"
                    )
                }
            } footer: {
                Text(hasConversation
                     ? "Removing keeps the conversation; the node leaves the Peers list but stays findable through search."
                     : "Deletes this node's record from this phone. Nothing is sent to the node.")
            }
        }
    }

    private func deleteAndDismiss(_ action: ((PeerSummary) async -> Bool)?) async {
        guard let action else { return }
        if await action(peer) {
            dismiss()
        } else {
            feedbackTitle = "Peer not deleted"
            feedbackMessage = "The node could not be deleted. Try again."
            showsFeedback = true
        }
    }

    private var displayedName: String {
        currentAlias
            ?? peer.advertisedName
            ?? (peer.isUlcpDevice ? "Companion radio" : peer.identity.hint.text)
    }

    private func saveAlias() async {
        guard let updateAlias = actions.updateAlias else { return }
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

    private func save(with savePeer: () async -> Bool) async {
        guard !isSavingPeer, !didSavePeer else { return }
        isSavingPeer = true
        defer { isSavingPeer = false }
        savePeerFailed = false
        if await savePeer() {
            didSavePeer = true
        } else {
            savePeerFailed = true
        }
    }

    /// A peer sheet only ever opens a direct transcript, so the shared
    /// thread view's conversation binding is wrapped here rather than the
    /// sheet carrying the mixed list.
    private func binding(for conversationID: Int64) -> Binding<ConversationListItem>? {
        guard let fallback = conversations.first(where: { $0.id == conversationID }) else { return nil }
        return Binding(
            get: {
                .direct(conversations.first(where: { $0.id == conversationID }) ?? fallback)
            },
            set: { updated in
                guard case let .direct(conversation) = updated,
                      let index = conversations.firstIndex(where: { $0.id == conversationID })
                else { return }
                conversations[index] = conversation
            }
        )
    }

    private func openConversation() async {
        guard let startConversation = actions.startConversation else { return }
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
        guard let pingPeer = actions.ping else { return }
        guard !isPinging else { return }
        isPinging = true
        pingStatus = .pinging
        defer { isPinging = false }
        switch await pingPeer(peer) {
        case let .reply(reply):
            pingStatus = .reply(reply)
            // A reply is exactly what teaches the MAC a route, so the cached
            // one on screen is stale the moment a ping lands.
            routeWasAlreadyClear = false
            await loadRoute()
        case .timedOut:
            pingStatus = .timedOut
        case let .unavailable(reason):
            pingStatus = .unavailable(reason: reason)
        }
    }

    /// Ask the peer for its identity.
    ///
    /// The reply arrives asynchronously and lands in the Advertised identity
    /// section on its own, so this reports inline rather than raising a modal
    /// the reader has to dismiss before they can see the answer arrive.
    private func fetchPeerIdentity() async {
        guard let fetchIdentity = actions.fetchIdentity else { return }
        guard !isFetchingIdentity else { return }
        isFetchingIdentity = true
        defer { isFetchingIdentity = false }
        // Remembered so a reply that changes nothing is still recognisable as
        // a reply.
        let asked = peer.advertisedIdentity
        identityRequest = await fetchIdentity(peer) ? .awaiting(asked) : .unavailable
    }

    /// Where an Identity Request stands.
    enum IdentityRequestState: Equatable {
        /// Handed to the transport. Carries the identity held at that moment,
        /// so a reply is recognisable even when it restates what we knew.
        case awaiting(MeshNodeIdentity?)
        /// No mesh session to ask through.
        case unavailable
    }

    /// Inline progress for an Identity Request. The reply lands in the
    /// Advertised identity section above, so this only has to say whether one
    /// is still outstanding.
    @ViewBuilder
    private func identityRequestStatus(_ state: IdentityRequestState) -> some View {
        switch state {
        case let .awaiting(asked):
            if peer.advertisedIdentity != asked {
                Label("Identity updated.", systemImage: "checkmark.circle")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                Label("Asked. Details update above when the peer replies.", systemImage: "clock")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        case .unavailable:
            Label(
                "Connect a companion radio set up for this phone before asking a peer for its identity.",
                systemImage: "exclamationmark.triangle"
            )
            .font(.caption)
            .foregroundStyle(.secondary)
        }
    }

    /// What this phone will do with the next frame addressed to this peer,
    /// and the one control that changes it.
    ///
    /// A learned route is the usual explanation for traffic that takes a
    /// stale path after the mesh moves, so it is worth showing plainly and
    /// worth being able to discard without touching keys or history.
    @ViewBuilder
    private var routeSection: some View {
        Section {
            if let route {
                LabeledContent("Next send", value: Self.routeSummary(route))
                if !route.hints.isEmpty {
                    routeHopRows(cachedRouteHops(route))
                }
                if !route.floodRegions.isEmpty {
                    LabeledContent("Regions") {
                        Text(route.floodRegions.map(RegionCodeText.label).joined(separator: ", "))
                            .multilineTextAlignment(.trailing)
                    }
                }
                if actions.resetRoute != nil {
                    Button(role: .destructive) {
                        Task { await resetRoute() }
                    } label: {
                        Label(
                            isResettingRoute ? "Resetting…" : "Reset route",
                            systemImage: "arrow.counterclockwise"
                        )
                    }
                    .disabled(isResettingRoute || route.kind == .unknown || route.kind == .unavailable)
                }
            } else {
                HStack(spacing: 8) {
                    ProgressView()
                    Text("Reading route…")
                        .foregroundStyle(.secondary)
                }
            }
        } header: {
            Text("Route")
        } footer: {
            Text(routeFooter)
        }
    }

    private var routeFooter: String {
        if routeWasAlreadyClear {
            return "There was no route to reset. The next message floods until a reply teaches this phone a path."
        }
        switch route?.kind {
        case .unavailable:
            return "This phone has no mesh session to ask. Attach a companion radio set up for this identity to see how it would reach this node."
        case .unknown, nil:
            return "Nothing learned yet. The next message floods until a reply teaches this phone a path."
        default:
            return "Learned from this node's last reply. Resetting forgets the path — keys, counters, and messages are untouched — and the next message floods again."
        }
    }

    /// The one-line form, shared by the summary row and the Route section.
    /// `nil` is the moment before the first read resolves.
    private static func routeSummary(_ route: PeerRoute?) -> String {
        guard let route else { return "Reading…" }
        return switch route.kind {
        case .unavailable:
            "Unavailable"
        case .unknown:
            "Not learned yet"
        case .direct:
            "Direct"
        case .source:
            route.hints.isEmpty
                ? "Direct (empty source route)"
                : "Source route · \(route.hints.count) router\(route.hints.count == 1 ? "" : "s")"
        case .flood:
            route.floodHops.map { "Flood · \($0) hop\($0 == 1 ? "" : "s")" } ?? "Flood"
        }
    }

    private func loadRoute() async {
        // No wired-up reader is itself an answer: nothing can be asked.
        guard let loadRoute = actions.loadRoute else {
            route = .unavailable
            return
        }
        route = await loadRoute(peer)
    }

    private func resetRoute() async {
        guard let resetRoute = actions.resetRoute, !isResettingRoute else { return }
        isResettingRoute = true
        defer { isResettingRoute = false }
        routeWasAlreadyClear = !(await resetRoute(peer))
        await loadRoute()
    }

    /// The route a ping reply travelled, one node per line. Intermediate
    /// routers are identified only by a two-byte hint, so any name shown for
    /// one is a guess drawn from the nodes this phone already knows.
    @ViewBuilder
    private func routePath(for reply: PeerPingReply) -> some View {
        let hops = routeHops(for: reply)
        VStack(alignment: .leading, spacing: 10) {
            Text("Route path")
            if hops.isEmpty {
                Text("Not reported")
                    .foregroundStyle(.secondary)
            } else {
                routeHopRows(hops)
            }
        }
        .textSelection(.enabled)
    }

    /// One line per node, shared by the ping result and the cached route.
    @ViewBuilder
    private func routeHopRows(_ hops: [RouteHop]) -> some View {
        ForEach(Array(hops.enumerated()), id: \.offset) { _, hop in
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: hop.symbolName)
                    .foregroundStyle(.secondary)
                    .frame(width: 22)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(hop.title)
                    if let detail = hop.detail {
                        Text(detail)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .accessibilityElement(children: .combine)
        }
        if hops.contains(where: \.isNamedByHint) {
            Text("Router names are matched by a two-byte hint and may not be the node shown.")
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func routeHops(for reply: PeerPingReply) -> [RouteHop] {
        // Nothing to draw when the reply carried neither routers nor a hop
        // count: an empty list is not evidence of a direct path.
        guard !reply.routeHints.isEmpty || reply.hopCount != nil else { return [] }
        var hops = [originHop]
        hops.append(contentsOf: reply.routeHints.map(routerHop))

        // A traced reply names every router it crossed; a flooded one only
        // counts them. Stand in for the difference rather than letting a
        // counted-but-unnamed hop read as a direct link.
        let unnamed = reply.hopCount.map { Int($0) - 1 - reply.routeHints.count } ?? 0
        if unnamed > 0 {
            hops.append(
                RouteHop(
                    title: unnamed == 1 ? "One unnamed router" : "\(unnamed) unnamed routers",
                    detail: "Counted by the reply, but not identified",
                    symbolName: "questionmark.circle"
                )
            )
        }

        hops.append(destinationHop(isDirect: reply.hopCount == 1))
        return hops
    }

    /// The same picture for the route the MAC has cached: what the *next*
    /// frame will do, rather than what the last reply did.
    private func cachedRouteHops(_ route: PeerRoute) -> [RouteHop] {
        [originHop] + route.hints.map(routerHop) + [destinationHop(isDirect: route.isDirect)]
    }

    private var originHop: RouteHop {
        RouteHop(
            title: "This phone",
            detail: radioSnapshot.name.map { "Sent through \($0)" } ?? "Sent through the companion radio",
            symbolName: "iphone.gen3"
        )
    }

    private func destinationHop(isDirect: Bool) -> RouteHop {
        RouteHop(
            title: displayedName,
            detail: isDirect
                ? "\(peer.identity.hint.text) · direct, no routers"
                : peer.identity.hint.text,
            symbolName: "target"
        )
    }

    /// Put what name we can to one router hint. A hint is 16 bits of a public
    /// key, so it narrows the field rather than identifying a node: a single
    /// match is named, several matches are counted, and a match that only
    /// exists among repeater-capable nodes is preferred over a bare one.
    private func routerHop(_ hint: MeshRouterHint) -> RouteHop {
        let candidates = actions.knownPeers.filter { hint.matches($0.identity) }
        let repeaters = candidates.filter(\.isLikelyRepeater)
        let named = repeaters.count == 1 ? repeaters.first
            : (candidates.count == 1 ? candidates.first : nil)

        guard let named else {
            let detail: String
            switch (candidates.count, repeaters.count) {
            case (0, _):
                detail = "Router · not a node this phone knows"
            case let (_, matched) where matched > 1:
                detail = "Router · matches \(matched) known repeaters"
            case let (total, _):
                detail = "Router · matches \(total) known nodes"
            }
            return RouteHop(title: hint.text, detail: detail, symbolName: "antenna.radiowaves.left.and.right")
        }

        return RouteHop(
            title: named.displayName,
            detail: named.isLikelyRepeater
                ? "\(hint.text) · likely this repeater"
                : "\(hint.text) · likely this node, not a known repeater",
            symbolName: "antenna.radiowaves.left.and.right",
            isNamedByHint: true
        )
    }

    private static func decibels(_ centibels: Int16) -> String {
        String(format: "%.1f dB", Double(centibels) / 10)
    }
}

/// One node on a rendered route path.
private struct RouteHop {
    let title: String
    let detail: String?
    let symbolName: String
    /// Whether `title` is a name guessed from a router hint rather than a
    /// node this phone addressed directly.
    var isNamedByHint = false
}

/// An icon-and-text value for the trailing side of a `LabeledContent` row.
///
/// Deliberately not a `Label`: as `LabeledContent`'s value a `Label` reports
/// an unbounded height, so the enclosing list row grows to fill the rest of
/// the screen and leaves a large blank area under the section. An explicit
/// stack renders identically and measures to its content.
private struct IconedValue: View {
    let text: String
    let systemImage: String

    init(_ text: String, systemImage: String) {
        self.text = text
        self.systemImage = systemImage
    }

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: systemImage)
                .accessibilityHidden(true)
            Text(text)
                .multilineTextAlignment(.trailing)
        }
    }
}

/// What the peer detail view watches to decide the cached route needs
/// re-reading: the peer it is showing, and the last time anything was heard
/// from them.
private struct RouteRefreshKey: Hashable {
    let address: String
    let lastHeard: Date?
}

/// A signature notice for an advertised identity, shown only when the
/// signature does not verify.
///
/// A good signature deliberately renders nothing. It proves only that the
/// keypair which *is* this address asserted these claims about itself, which
/// is no evidence the claims are true — a node can sign a fabricated name or
/// location as easily as a real one. A "verified" badge invites far more
/// trust than that supports, so the affirmative case stays silent and only a
/// failure, which is genuinely decision-relevant at import time, speaks up.
struct AdvertisedIdentityWarning: View {
    let identity: MeshNodeIdentity

    var body: some View {
        switch identity.signature {
        case .valid:
            EmptyView()
        case .unsigned:
            Label(
                "These details carry no signature, so they may not have come from this node at all.",
                systemImage: "exclamationmark.triangle"
            )
            .font(.caption)
            .foregroundStyle(.secondary)
        case .invalid:
            Label(
                "The signature on these details does not verify. Do not rely on them.",
                systemImage: "exclamationmark.triangle.fill"
            )
            .font(.caption)
            .foregroundStyle(.red)
        }
    }
}

/// Rows describing a decoded advertised node identity: the peer's own claims
/// about itself, none of them independently verified. Shared by the peer
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
}
