import CoreLocation
import Foundation
import SwiftUI

/// A node's page: its name, what can be done with it, the facts people check,
/// where it is, and the rest of what this phone knows about it.
///
/// Ordered by how often each part is wanted. Ping and the route have screens
/// of their own, opened from here.
struct PeerDetailView: View {
    /// The entry as it stood when this view was pushed. Anchors identity, and
    /// stands in if the peer is removed while the view is open.
    private let pushedPeer: PeerSummary

    /// This peer as it stands now. A peer's details change while this view is
    /// open—an identity response lands, or a reply teaches a route—and a
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
    /// What this page can do with the node. One bundle so the page is the
    /// same wherever it is opened from.
    let actions: PeerActions
    let updateDraft: ((Int64, String) async -> AppOperationResult)?
    let sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)?
    let messageActions: ChatMessageActions
    /// Set when the page is opened from the conversation it would otherwise
    /// open: Message goes back there instead of pushing a second copy.
    let returnToConversation: (() -> Void)?

    @State private var destination: PeerPageDestination?
    @State private var isOpeningConversation = false
    @State private var showsPing = false
    /// This visit's pings, kept here so closing and reopening the Ping sheet
    /// keeps them.
    @State private var pingHistory: [PingRecord] = []
    @State private var showsShare = false
    @State private var isRefreshingIdentity = false
    @State private var feedback: Feedback?
    // The pushed view keeps its own copy so a saved alias is visible
    // immediately even though the parent's peer list refreshes later.
    @State private var currentAlias: String?
    // Same reasoning for the favorite: the star must flip the moment it is
    // tapped, not when the parent's peer list refresh reaches this view.
    @State private var currentFavorite: Bool
    /// What the watch switch was just set to, held only until the stored row
    /// catches up. Unlike the favorite flag, this one also clears itself—
    /// the watch coming due disarms it—so the stored value wins the moment
    /// it moves rather than the local copy standing in indefinitely.
    @State private var pendingWatch: Bool?
    /// What the Messages switch was just set to, until the store reloads.
    @State private var pendingConversationNotifications: Bool?
    /// What is in the name field. Empty means the peer has no name of this
    /// phone's choosing and goes by whatever it advertises, which is what
    /// the field shows as its placeholder.
    @State private var nameDraft: String
    @FocusState private var isNamingFocused: Bool
    @State private var route: PeerRoute?
    @State private var distance: PeerDistance?
    @State private var messageCount: Int?
    @State private var showsClearDialog = false
    @State private var showsRemovalDialog = false
    @Environment(\.dismiss) private var dismiss
    @Environment(\.showOnMap) private var showOnMap
    @Environment(\.readPhonePositionIfAuthorized) private var readPhonePositionIfAuthorized

    init(
        peer: PeerSummary,
        radioSnapshot: Binding<RadioSnapshot>,
        conversations: Binding<[DirectConversationSummary]> = .constant([]),
        actions: PeerActions = .unavailable,
        updateDraft: ((Int64, String) async -> AppOperationResult)? = nil,
        sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)? = nil,
        messageActions: ChatMessageActions = .unavailable,
        returnToConversation: (() -> Void)? = nil
    ) {
        self.pushedPeer = peer
        _radioSnapshot = radioSnapshot
        _conversations = conversations
        self.actions = actions
        self.updateDraft = updateDraft
        self.sendMessage = sendMessage
        self.messageActions = messageActions
        self.returnToConversation = returnToConversation
        _currentAlias = State(initialValue: peer.alias)
        _nameDraft = State(initialValue: peer.alias ?? "")
        _currentFavorite = State(initialValue: peer.isFavorite)
    }

    var body: some View {
        List {
            Section {
                hero
                    .frame(maxWidth: .infinity)
                    .cardListRow()
                if !verbs.isEmpty {
                    ActionTileRow {
                        ForEach(verbs, id: \.self) { verb in
                            ActionTile(
                                title: verb.title,
                                systemImage: verb.systemImage,
                                isBusy: isBusy(verb)
                            ) {
                                perform(verb)
                            }
                            .accessibilityIdentifier(verb.accessibilityIdentifier)
                        }
                    }
                    .cardListRow()
                }
                if offersAddToPeers {
                    Button {
                        Task { _ = await actions.promoteToSaved?(peer) }
                    } label: {
                        Label {
                            Text("Add to Peers", comment: "Button: save a node this phone has only heard of.")
                        } icon: {
                            Image(systemName: "person.crop.circle.badge.plus")
                        }
                        // A list row tints a label's icon with the accent
                        // color, the button's own fill, which hides it.
                        .foregroundStyle(.white)
                        .font(.headline)
                        .frame(maxWidth: .infinity, minHeight: 34)
                    }
                    .buttonStyle(.borderedProminent)
                    .accessibilityIdentifier("peer.addToPeers")
                    .cardListRow()
                }
                PeerGlanceStrip(
                    lastHeard: peer.lastHeard,
                    routeText: RoutePresentation.briefText(route),
                    distance: distance,
                    openRoute: route == nil ? nil : { destination = .route }
                )
                .cardListRow()
                if let mapNode {
                    PeerMapCard(
                        node: mapNode,
                        reportedAt: peer.advertisedIdentityReceivedAt,
                        open: showOnMap.map { show in { show(peer) } }
                    )
                    .cardListRow()
                }
            }

            notificationsSection
            aboutSection
            destructiveSection
        }
        // No navigation title: the name is the first thing on the page, and
        // printing it twice reads as two different facts.
        .navigationBarTitleDisplayMode(.inline)
        .contentMargins(.top, 0, for: .scrollContent)
        .toolbar { toolbar }
        // Return commits the name, and so does scrolling away from it. But
        // leaving the screen outright is the case worth catching: a name
        // typed and then navigated away from is one the operator believes
        // they gave this node.
        .scrollDismissesKeyboard(.interactively)
        .onDisappear { Task { await saveName() } }
        // Anything inbound from this peer is what teaches the MAC a route, so
        // the cached route on screen is stale exactly when we hear from them.
        .task(id: RouteRefreshKey(address: peer.identity.canonicalAddress, lastHeard: peer.lastHeard)) {
            await loadRoute()
        }
        .task(id: DistanceKey(peer: location, radio: radioSnapshot.position)) {
            await measureDistance()
        }
        .task(id: conversation?.messageRevision) {
            guard let conversation else { return }
            messageCount = await messageActions.countMessages(conversation.conversationAddress)
        }
        .task(id: isRefreshingIdentity) {
            // A request is shown as outstanding for as long as a reply could
            // take, or until one lands—whichever is first.
            guard isRefreshingIdentity else { return }
            try? await Task.sleep(for: HintDiscoveryButton.wait)
            isRefreshingIdentity = false
        }
        .onChange(of: peer.advertisedIdentity) { _, _ in isRefreshingIdentity = false }
        .onChange(of: peer.notifyWhenHeard) { _, _ in
            // The stored row moved: either the write landed, or the watch
            // came due and disarmed itself while this page was open.
            pendingWatch = nil
        }
        .navigationDestination(item: $destination) { destination in
            destinationView(destination)
        }
        .sheet(isPresented: $showsPing) {
            PingSheet(
                peer: peer,
                actions: actions,
                radioName: radioSnapshot.name,
                history: $pingHistory,
                browsing: peerBrowsing,
                onRouteChanged: { Task { await loadRoute() } }
            )
        }
        .sheet(isPresented: $showsShare) {
            PeerShareSheet(peer: peer)
        }
        .alert(
            feedback?.title ?? "",
            isPresented: Binding(get: { feedback != nil }, set: { if !$0 { feedback = nil } })
        ) {
            Button(role: .cancel) {} label: { Text("OK", comment: "Dismisses an alert.") }
        } message: {
            Text(feedback?.message ?? "")
        }
        .transientNoticePresenter()
    }

    // MARK: Hero

    private var hero: some View {
        IdentityHeader(style: .hero) { diameter in
            PeerAvatar(peer: peer, diameter: diameter)
        } content: {
            VStack(spacing: 4) {
                if actions.updateAlias != nil, !peer.isUlcpDevice {
                    // Emptied, it goes back to the name the node advertises
                    // for itself, which is what having no name of our own
                    // means.
                    TextField(text: $nameDraft) {
                        Text(verbatim: advertisedName)
                    }
                    .font(.title.bold())
                    .multilineTextAlignment(.center)
                    .textInputAutocapitalization(.words)
                    .autocorrectionDisabled()
                    .submitLabel(.done)
                    .focused($isNamingFocused)
                    .onSubmit { Task { await saveName() } }
                    .onChange(of: isNamingFocused) { _, focused in
                        if !focused { Task { await saveName() } }
                    }
                    // Sitting there, this is a label and reads like one—the
                    // advertised name in full strength, not the gray of a
                    // field waiting to be filled. The gray placeholder
                    // beneath is uncovered only once editing starts, where it
                    // means "nothing set".
                    .overlay {
                        if !isNamingFocused, nameDraft.isEmpty {
                            Text(verbatim: advertisedName)
                                .font(.title.bold())
                                .foregroundStyle(.primary)
                                .allowsHitTesting(false)
                        }
                    }
                    .accessibilityIdentifier("peer.name")
                } else {
                    Text(verbatim: displayedName)
                        .font(.title.bold())
                        .multilineTextAlignment(.center)
                }
                if let subtitle {
                    Text(verbatim: subtitle)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                }
            }
        }
        .padding(.top, 4)
    }

    /// What the node is, and the name it gives itself when this phone calls
    /// it something else: "Chat · “Ridge Medic”".
    private var subtitle: String? {
        if peer.isUlcpDevice {
            return String(localized: "Companion radio", comment: "Under the name of the companion radio's own identity.")
        }
        let role = peer.role == .unknown ? nil : peer.role.label
        let hidden = currentAlias != nil ? peer.advertisedName : nil
        switch (role, hidden) {
        case let (role?, name?) where name != currentAlias:
            return String(
                localized: "\(role) · “\(name)”",
                comment: "Under a renamed node's name: its role, then the name it advertises for itself."
            )
        case let (nil, name?) where name != currentAlias:
            return String(
                localized: "“\(name)”",
                comment: "Under a renamed node's name: the name it advertises for itself."
            )
        default:
            return role
        }
    }

    private var displayedName: String {
        currentAlias ?? advertisedName
    }

    /// What the node calls itself, for a phone that has not renamed it.
    private var advertisedName: String {
        peer.advertisedName
            ?? (peer.isUlcpDevice
                ? String(localized: "Companion radio", comment: "Name of the companion radio's own identity, when it advertises none.")
                : peer.identity.hint.text)
    }

    // MARK: Verbs

    private var verbs: [PeerVerb] {
        PeerVerb.offered(for: peer, availability: PeerVerb.Availability(actions))
    }

    private func isBusy(_ verb: PeerVerb) -> Bool {
        switch verb {
        case .identify: isRefreshingIdentity
        case .message: isOpeningConversation
        default: false
        }
    }

    private func perform(_ verb: PeerVerb) {
        switch verb {
        case .identify:
            Task { await refreshIdentity() }
        case .message:
            if let returnToConversation {
                returnToConversation()
            } else {
                Task { await openConversation() }
            }
        case .ping:
            showsPing = true
        case .neighbors:
            destination = .neighbors
        case .manage:
            destination = .manage
        }
    }

    /// A node heard of but not kept: a link opened, a hint looked up.
    private var offersAddToPeers: Bool {
        !peer.isSaved && !peer.isUlcpDevice && isStoredLocally && actions.promoteToSaved != nil
    }

    // MARK: Sections

    @ViewBuilder
    private var notificationsSection: some View {
        let offersMessages = conversation != nil && actions.setConversationNotifications != nil
        // A one-shot watch, offered wherever a row exists to hold it—
        // transient nodes included, since a node heard once and not saved is
        // exactly the kind one waits to hear again. Not the attached radio.
        let offersWatch = actions.setNotifyWhenHeard != nil && isStoredLocally && !peer.isUlcpDevice
        if offersMessages || offersWatch {
            Section {
                if offersMessages, let conversation {
                    Toggle(isOn: Binding(
                        get: { pendingConversationNotifications ?? conversation.notificationsEnabled },
                        set: { enabled in
                            pendingConversationNotifications = enabled
                            Task {
                                await actions.setConversationNotifications?(conversation, enabled)
                                // The store has reloaded by now, so hand the
                                // switch back to it—including when the write
                                // failed and the old value is the answer.
                                pendingConversationNotifications = nil
                            }
                        }
                    )) {
                        Text("Messages", comment: "Switch: notify for this node's messages.")
                    }
                    .accessibilityIdentifier("peer.notify.messages")
                }
                if offersWatch {
                    Toggle(isOn: Binding(
                        get: { pendingWatch ?? peer.notifyWhenHeard },
                        set: { newValue in
                            pendingWatch = newValue
                            Task {
                                if await actions.setNotifyWhenHeard?(peer, newValue) != true {
                                    pendingWatch = nil
                                }
                            }
                        }
                    )) {
                        Text("Next Time Heard", comment: "Switch: notify once, the next time anything is heard from this node.")
                    }
                    .accessibilityIdentifier("peer.notify.nextHeard")
                }
            } header: {
                Text("Notifications", comment: "Section header on a peer page.")
            }
        }
    }

    private var aboutSection: some View {
        Section {
            CanonicalAddressView(address: peer.identity.canonicalAddress)
            if let capabilities = peer.advertisedCapabilities, !capabilities.isEmpty {
                LabeledContent {
                    Text(verbatim: capabilities.listText)
                        .multilineTextAlignment(.trailing)
                } label: {
                    Text("Capabilities", comment: "Row label: what a node advertises it can do.")
                }
                .accessibilityIdentifier("peer.capabilities")
            }
            if !peer.isUlcpDevice {
                advertisedRow
            }
            if let identity = peer.advertisedIdentity, !peer.advertisedIdentityIsAttributable {
                AdvertisedIdentityWarning(identity: identity)
            }
            if peer.isUlcpDevice {
                LabeledContent {
                    Text(verbatim: radioSnapshot.name ?? "—")
                } label: {
                    Text("Radio", comment: "Row label: the companion radio this identity belongs to.")
                }
            }
        } header: {
            Text("About", comment: "Section header on a peer page.")
        }
    }

    /// When the node last told this phone who it is, and the way to ask
    /// again.
    private var advertisedRow: some View {
        LabeledContent {
            HStack(spacing: 12) {
                if let receivedAt = peer.advertisedIdentityReceivedAt {
                    AgeText(since: receivedAt)
                } else if peer.advertisedIdentity != nil {
                    Text("Imported", comment: "Advertised row value: the identity came from a link or QR code, not the air.")
                } else {
                    Text("Never", comment: "Advertised row value: the node has not said who it is.")
                }
                if actions.fetchIdentity != nil, !peer.isUlcpDevice {
                    if isRefreshingIdentity {
                        ProgressView()
                            .accessibilityLabel(Text("Waiting for a reply", comment: "VoiceOver label for a request in flight."))
                    } else {
                        Button {
                            Task { await refreshIdentity() }
                        } label: {
                            Image(systemName: "arrow.clockwise")
                                .accessibilityLabel(Text("Ask Again", comment: "VoiceOver label: ask a node for its identity again."))
                        }
                        .buttonStyle(.borderless)
                        .accessibilityIdentifier("peer.advertised.refresh")
                    }
                }
            }
        } label: {
            Text("Advertised", comment: "Row label: when the node last said who it is.")
        }
    }

    @ViewBuilder
    private var destructiveSection: some View {
        let offersClear = conversation != nil
        // Removal is offered for any stored node except the radio's own,
        // whose release path is Forget Radio in Settings.
        let offersRemoval = isStoredLocally && !peer.isUlcpDevice && peer.isSaved
            && (actions.demoteToTransient != nil || actions.deletePeer != nil)
        if offersClear || offersRemoval {
            Section {
                if offersClear {
                    Button(role: .destructive) {
                        showsClearDialog = true
                    } label: {
                        Label {
                            Text("Clear Messages…", comment: "Button: erase this node's conversation history.")
                        } icon: {
                            Image(systemName: "trash")
                        }
                    }
                    .disabled(messageCount == 0)
                    .accessibilityIdentifier("peer.clearMessages")
                    .confirmationDialog(
                        Text("Clear all messages?", comment: "Confirmation title."),
                        isPresented: $showsClearDialog,
                        titleVisibility: .visible
                    ) {
                        Button(role: .destructive) {
                            Task { await clearMessages() }
                        } label: {
                            Text("Clear \(messageCount ?? 0) Messages", comment: "Confirms erasing a conversation. Has plural variants.")
                        }
                        Button(role: .cancel) {} label: { Text("Cancel", comment: "Cancels a confirmation.") }
                    } message: {
                        Text("Erased from this phone only. \(displayedName) keeps their copy.", comment: "Confirmation message for clearing a conversation. The placeholder is the node's name.")
                    }
                }
                if offersRemoval {
                    Button(role: .destructive) {
                        showsRemovalDialog = true
                    } label: {
                        Label {
                            Text("Remove Peer…", comment: "Button: take this node off the Peers list or delete it.")
                        } icon: {
                            Image(systemName: "minus.circle")
                        }
                    }
                    .accessibilityIdentifier("peer.remove")
                    .confirmationDialog(
                        Text("Remove \(displayedName)?", comment: "Confirmation title. The placeholder is the node's name."),
                        isPresented: $showsRemovalDialog,
                        titleVisibility: .visible
                    ) {
                        removalButtons
                    } message: {
                        if conversation != nil {
                            Text("Removing keeps the conversation. Deleting erases it too.", comment: "Confirmation message for removing a node that has a conversation.")
                        } else {
                            Text("Nothing is sent to the node.", comment: "Confirmation message for deleting a node.")
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var removalButtons: some View {
        if conversation != nil {
            if actions.demoteToTransient != nil {
                Button {
                    Task { _ = await actions.demoteToTransient?(peer) }
                } label: {
                    Text("Remove Peer", comment: "Confirms taking a node off the Peers list, keeping its conversation.")
                }
            }
            if actions.deletePeerAndConversation != nil {
                Button(role: .destructive) {
                    Task { await deleteAndDismiss(actions.deletePeerAndConversation) }
                } label: {
                    Text("Delete Peer and Conversation", comment: "Confirms deleting a node and its messages.")
                }
            }
        } else if actions.deletePeer != nil {
            Button(role: .destructive) {
                Task { await deleteAndDismiss(actions.deletePeer) }
            } label: {
                Text("Delete Peer", comment: "Confirms deleting a node.")
            }
        }
        Button(role: .cancel) {} label: { Text("Cancel", comment: "Cancels a confirmation.") }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItemGroup(placement: .topBarTrailing) {
            if actions.setFavorite != nil, isStoredLocally, peer.isSaved, !peer.isUlcpDevice {
                Button {
                    toggleFavorite()
                } label: {
                    Image(systemName: currentFavorite ? "star.fill" : "star")
                }
                .accessibilityLabel(Text("Favorite", comment: "VoiceOver label for the favorite star."))
                .accessibilityValue(currentFavorite
                    ? Text("On", comment: "VoiceOver value of a switch-like control.")
                    : Text("Off", comment: "VoiceOver value of a switch-like control."))
                .accessibilityIdentifier("peer.favorite")
            }
            Button {
                showsShare = true
            } label: {
                Image(systemName: "square.and.arrow.up")
            }
            .accessibilityLabel(Text("Share", comment: "VoiceOver label for the button that shares a node's link."))
            .accessibilityIdentifier("peer.share")
        }
    }

    // MARK: Destinations

    @ViewBuilder
    private func destinationView(_ destination: PeerPageDestination) -> some View {
        switch destination {
        case let .conversation(opened):
            if let conversation = binding(for: opened.id) {
                ConversationThreadView(
                    conversation: conversation,
                    radioSnapshot: radioSnapshot,
                    updateDraft: updateDraft ?? { _, _ in
                        .failure(.unavailable(String(localized: "Saving is unavailable.", comment: "Error when a draft cannot be stored.")))
                    },
                    sendMessage: { item, body in
                        guard case let .direct(conversation) = item, let sendMessage else {
                            return .failed(String(localized: "Messaging is unavailable.", comment: "Error when a message cannot be sent at all."))
                        }
                        return await sendMessage(conversation, body)
                    },
                    messageActions: messageActions,
                    peerActions: actions,
                    conversations: $conversations,
                    // Direct chats only, which is all this view holds.
                    unreadElsewhere: conversations
                        .filter { $0.id != opened.id }
                        .reduce(0) { $0 + $1.unreadCount }
                )
            }
        case .route:
            RouteScreen(
                peer: peer,
                actions: actions,
                radioName: radioSnapshot.name,
                browsing: peerBrowsing,
                onRouteChanged: { Task { await loadRoute() } }
            )
        case .neighbors:
            PeerRepeatersScreen(peer: peer, actions: actions, browsing: peerBrowsing)
        case .manage:
            if let management = actions.manageDevice {
                ManageDeviceScreen(peer: peer, management: management(peer), browsing: peerBrowsing)
            }
        }
    }

    /// How a screen opened from here opens another node: by pushing this
    /// same page for it.
    private var peerBrowsing: RemotePeerBrowsing {
        RemotePeerBrowsing(knownPeers: actions.knownPeers) { peer in
            AnyView(
                PeerDetailView(
                    peer: peer,
                    radioSnapshot: $radioSnapshot,
                    conversations: $conversations,
                    actions: actions,
                    updateDraft: updateDraft,
                    sendMessage: sendMessage,
                    messageActions: messageActions
                )
            )
        }
    }

    // MARK: State

    /// Whether this node has a stored row at all. The page can be opened on
    /// a synthetic summary—a device being set up, the radio's own identity
    /// before it is recorded—and those have nothing to favorite or remove.
    private var isStoredLocally: Bool {
        actions.knownPeers.contains {
            $0.identity.canonicalAddress == pushedPeer.identity.canonicalAddress
        }
    }

    private var conversation: DirectConversationSummary? {
        conversations.first {
            $0.peer.identity.canonicalAddress == peer.identity.canonicalAddress
        }
    }

    /// The node as the Map tab draws it, when it has said where it is.
    private var mapNode: MapNode? {
        MapNode.nodes(peers: [peer], neighborReports: []).first
    }

    /// Where the node says it is. The radio's own identity is left out: it
    /// is this phone's position, not a peer's.
    private var location: PeerLocation? {
        guard !peer.isUlcpDevice,
              let identity = peer.advertisedIdentity,
              let latitude = identity.latitude,
              let longitude = identity.longitude
        else { return nil }
        return PeerLocation(
            latitude: latitude,
            longitude: longitude,
            cellMeters: identity.locationPrecision.flatMap { LocationPresentation.cellMeters(precisionBytes: $0) }
        )
    }

    // MARK: Actions

    private func toggleFavorite() {
        let newValue = !currentFavorite
        currentFavorite = newValue
        Task {
            if await actions.setFavorite?(peer, newValue) != true {
                currentFavorite = !newValue
            }
        }
    }

    /// Store what is in the name field, blank meaning no name of our own.
    ///
    /// Called on every commit—submitting and leaving the field both—so
    /// it returns early when nothing moved rather than writing the same
    /// name back each time the field loses focus.
    private func saveName() async {
        guard let updateAlias = actions.updateAlias else { return }
        let trimmed = nameDraft.trimmingCharacters(in: .whitespacesAndNewlines)
        let newAlias = trimmed.isEmpty ? nil : trimmed
        guard newAlias != currentAlias else { return }
        if await updateAlias(peer, newAlias) {
            currentAlias = newAlias
            nameDraft = newAlias ?? ""
        } else {
            // Put the field back to what the peer is actually called, so it
            // does not go on showing a name nothing stored.
            nameDraft = currentAlias ?? ""
            feedback = Feedback(
                title: String(localized: "Name not saved", comment: "Alert title."),
                message: String(localized: "The name could not be stored. Try again.", comment: "Alert message.")
            )
        }
    }

    /// A peer page only ever opens a direct transcript, so the shared
    /// thread view's conversation binding is wrapped here rather than the
    /// page carrying the mixed list.
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
        guard let startConversation = actions.startConversation, !isOpeningConversation else { return }
        isOpeningConversation = true
        defer { isOpeningConversation = false }
        if let conversation = await startConversation(peer) {
            destination = .conversation(conversation)
        } else {
            feedback = Feedback(
                title: String(localized: "Conversation unavailable", comment: "Alert title."),
                message: String(localized: "A conversation with this node could not be started.", comment: "Alert message.")
            )
        }
    }

    /// Ask the node who it is. The answer lands in the page on its own, so
    /// all this shows is that a request is outstanding.
    private func refreshIdentity() async {
        guard let fetchIdentity = actions.fetchIdentity, !isRefreshingIdentity else { return }
        if await fetchIdentity(peer) {
            isRefreshingIdentity = true
        } else {
            feedback = Feedback(
                title: String(localized: "Not sent", comment: "Alert title: a request could not go out."),
                message: String(localized: "Connect a companion radio set up for this phone.", comment: "Alert message when no radio can send.")
            )
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

    /// How far the node is: from this phone when location access was already
    /// granted, else from the companion radio's own fix, else unknown.
    private func measureDistance() async {
        guard location != nil, let identity = peer.advertisedIdentity else {
            distance = nil
            return
        }
        if let reading = await readPhonePositionIfAuthorized?() {
            distance = PeerDistance(
                from: (reading.coordinate.latitude, reading.coordinate.longitude, nil),
                to: identity
            )
        } else if let radio = MapSelfPosition(radioPosition: radioSnapshot.position) {
            distance = PeerDistance(from: (radio.latitude, radio.longitude, radio.cellMeters), to: identity)
        } else {
            distance = nil
        }
    }

    private func clearMessages() async {
        guard let conversation else { return }
        await messageActions.clearMessages(conversation.conversationAddress)
        messageCount = await messageActions.countMessages(conversation.conversationAddress)
    }

    private func deleteAndDismiss(_ action: ((PeerSummary) async -> Bool)?) async {
        guard let action else { return }
        if await action(peer) {
            dismiss()
        } else {
            feedback = Feedback(
                title: String(localized: "Peer not deleted", comment: "Alert title."),
                message: String(localized: "The node could not be deleted. Try again.", comment: "Alert message.")
            )
        }
    }
}

/// Where a peer page navigates to.
enum PeerPageDestination: Hashable {
    case conversation(DirectConversationSummary)
    case route
    case neighbors
    case manage
}

/// A node's reported cell.
private struct PeerLocation: Hashable {
    let latitude: Double
    let longitude: Double
    let cellMeters: Double?
}

private struct Feedback {
    let title: String
    let message: String
}

/// What the page watches to decide the cached route needs re-reading: the
/// peer it is showing, and the last time anything was heard from them.
private struct RouteRefreshKey: Hashable {
    let address: String
    let lastHeard: Date?
}

/// What the distance is measured between.
private struct DistanceKey: Equatable {
    let peer: PeerLocation?
    let radio: RadioPosition?
}
