import Foundation
import SwiftUI
import UIKit

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

    /// How a screen pushed from here opens another node: by pushing this
    /// same page for it. Everything one needs is already in hand here,
    /// which is why the sheet builds it rather than passing the parts on.
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
    /// What is in the name field. Empty means the peer has no name of this
    /// phone's choosing and goes by whatever it advertises, which is what
    /// the field shows as its placeholder.
    @State private var nameDraft: String
    @FocusState private var isNamingFocused: Bool
    @State private var isSavingPeer = false
    @State private var didSavePeer = false
    @State private var savePeerFailed = false
    @State private var route: PeerRoute?
    @State private var isResettingRoute = false
    @State private var routeWasAlreadyClear = false
    /// A router named by one of this page's paths, pushed from its menu.
    @State private var routerPendingDetail: PeerSummary?
    /// Routers this page has asked to identify themselves, by hint. Kept for
    /// the life of the page only: the answer, when it comes, renames the row
    /// on its own.
    @State private var askedRouters: Set<Data> = []
    /// Opens Discover Peers aimed at this node. Nil when nothing above this
    /// view can present that sheet.
    @Environment(\.askNearbyIdentities) private var askNearbyIdentities
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
        _nameDraft = State(initialValue: peer.alias ?? "")
        _currentFavorite = State(initialValue: peer.isFavorite)
    }

    var body: some View {
        List {
            Section {
                // The name is the field, edited where it is shown, so there
                // is no second row saying the same name again under another
                // word. The hint is not written out either — the avatar is
                // the hint, drawn.
                HStack(spacing: 16) {
                    PeerAvatar(hint: peer.identity.hint, diameter: 64)
                    VStack(alignment: .leading) {
                        if actions.updateAlias != nil {
                            // Emptied, it goes back to the name the node
                            // advertises for itself, which is what having no
                            // name of our own means.
                            TextField(advertisedName, text: $nameDraft)
                                .font(.title2.bold())
                                .textInputAutocapitalization(.words)
                                .autocorrectionDisabled()
                                .submitLabel(.done)
                                .focused($isNamingFocused)
                                .onSubmit { Task { await saveName() } }
                                .onChange(of: isNamingFocused) { _, focused in
                                    if !focused { Task { await saveName() } }
                                }
                                // Sitting there, this is a label and reads
                                // like one — the advertised name in full
                                // strength, not the gray of a field waiting
                                // to be filled. The gray placeholder beneath
                                // is uncovered only once editing starts,
                                // where it means "nothing set".
                                .overlay(alignment: .leading) {
                                    if !isNamingFocused, nameDraft.isEmpty {
                                        Text(advertisedName)
                                            .font(.title2.bold())
                                            .foregroundStyle(.primary)
                                            .allowsHitTesting(false)
                                    }
                                }
                        } else {
                            Text(displayedName).font(.title2.bold())
                        }
                        // The node's own claim, refreshed whenever a fresher
                        // identity lands — not a local category anyone has to
                        // keep correct.
                        Text(peer.isUlcpDevice ? "Companion radio identity" : peer.role.label)
                            .foregroundStyle(.secondary)
                    }
                }
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

            if actions.startConversation != nil || actions.ping != nil
                || actions.manageDevice != nil {
                Section("Actions") {
                    HStack(spacing: 12) {
                        if actions.startConversation != nil {
                            Button {
                                Task { await openConversation() }
                            } label: {
                                // A Button's label inside a Form row is tinted
                                // with the accent color, which the prominent
                                // style overrides for the title but not for the
                                // icon — leaving a blue glyph on a blue fill.
                                Label("Message", systemImage: "message.fill")
                                    .foregroundStyle(.white)
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

                    // Offered whether or not this node has ever said it
                    // takes orders from anyone: a device tells only its own
                    // administrators that it can be managed at all, so
                    // hiding this behind what the mesh has heard would hide
                    // it exactly where it works. Silence is the answer, and
                    // the screen behind this says so in a sentence.
                    if let management = actions.manageDevice, !peer.isUlcpDevice {
                        NavigationLink {
                            ManageDeviceScreen(
                                peer: peer,
                                management: management,
                                browsing: peerBrowsing
                            )
                        } label: {
                            Label("Manage Device", systemImage: "slider.horizontal.3")
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
        // No navigation title: the name is already the first thing on the
        // screen, beside the avatar, and printing it twice was reading as
        // two different facts. Inline, so the bar does not go on reserving
        // the height a large title would have taken — and with the list's
        // own top margin dropped, since that margin exists to separate the
        // content from a title this screen does not have.
        .navigationBarTitleDisplayMode(.inline)
        .contentMargins(.top, 0, for: .scrollContent)
        // Return commits the name, and so does scrolling away from it. But
        // leaving the screen outright is the case worth catching: a name
        // typed and then navigated away from is one the operator believes
        // they gave this node.
        .scrollDismissesKeyboard(.interactively)
        .onDisappear { Task { await saveName() } }
        // Anything inbound from this peer is what teaches the MAC a route, so
        // the cached route on screen is stale exactly when we hear from them.
        // `lastHeard` moves on every such event, which makes it the trigger.
        .task(id: RouteRefreshKey(address: peer.identity.canonicalAddress, lastHeard: peer.lastHeard)) {
            await loadRoute()
        }
        .navigationDestination(item: $openedConversation) { opened in
            if let conversation = binding(for: opened.id) {
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
                    conversations: $conversations,
                    // Direct chats only, which is all this view holds. A
                    // channel with unread messages is not counted here.
                    unreadElsewhere: conversations
                        .filter { $0.id != opened.id }
                        .reduce(0) { $0 + $1.unreadCount }
                )
            }
        }
        // A router named by one of this page's paths. Pushing this view onto
        // itself is safe: it re-resolves its peer by address every render.
        .navigationDestination(item: $routerPendingDetail) { router in
            PeerDetailView(
                peer: router,
                radioSnapshot: $radioSnapshot,
                conversations: $conversations,
                actions: actions,
                updateDraft: updateDraft,
                sendMessage: sendMessage,
                messageActions: messageActions
            )
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
        if actions.manageDevice != nil {
            // The other half of the same arrangement, and the half people
            // look for: this list is who the radio can reach, and Manage
            // Device is what reaching a node is for.
            lines.append("Managing this node from here instead is under Manage Device, above — it works if the node lists this phone as one of its administrators.")
        }
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
        currentAlias ?? advertisedName
    }

    /// What the node calls itself, for a phone that has not renamed it.
    private var advertisedName: String {
        peer.advertisedName
            ?? (peer.isUlcpDevice ? "Companion radio" : peer.identity.hint.text)
    }

    /// Store what is in the name field, blank meaning no name of our own.
    ///
    /// Called on every commit — submitting and leaving the field both — so
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
            feedbackTitle = "Name not saved"
            feedbackMessage = "The name could not be stored. Try again."
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
                if let askNearbyIdentities {
                    let vantage = SolicitVantage(peer: peer, route: route)
                    Button {
                        askNearbyIdentities(vantage)
                    } label: {
                        Label("Ask Near This Node", systemImage: "wave.3.right")
                    }
                    .disabled(vantage == nil)
                    if let reason = Self.askNearbyUnavailableReason(route: route, peer: peer) {
                        Text(reason)
                            .font(.caption)
                            .foregroundStyle(.secondary)
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

    /// Why the ask cannot be aimed here, in the terms of what the operator
    /// would do about it. `nil` when it can.
    private static func askNearbyUnavailableReason(route: PeerRoute, peer: PeerSummary) -> String? {
        guard SolicitVantage(peer: peer, route: route) == nil else { return nil }
        switch route.kind {
        case .unavailable:
            return "Attach a companion radio set up for this phone to ask from here."
        case .unknown:
            return "Nothing learned yet. Ping or message this node to teach this phone a path, then ask from here."
        case .flood:
            return "A flooded route counts routers without naming them, so there is no path to steer down. Ping this node to learn one."
        case .direct, .source:
            return "This node is in direct range and does not repeat, so asking nearby already reaches everything it could."
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
    ///
    /// Emitted as sibling rows rather than a stack inside one row, matching
    /// the cached route below. A hop carries its own context menu, and a menu
    /// needs a row: several of them sharing one cell makes the lift preview
    /// mask a handful of disconnected slivers out of the middle of it.
    @ViewBuilder
    private func routePath(for reply: PeerPingReply) -> some View {
        let hops = routeHops(for: reply)
        Text("Route path")
        if hops.isEmpty {
            Text("Not reported")
                .foregroundStyle(.secondary)
        } else {
            routeHopRows(hops)
        }
    }

    /// One line per node, shared by the ping result and the cached route.
    ///
    /// An intermediate router carries a menu, since a two-byte hint is the
    /// most a route ever says about one and the node behind it can be asked.
    @ViewBuilder
    private func routeHopRows(_ hops: [RouteHop]) -> some View {
        ForEach(Array(hops.enumerated()), id: \.offset) { _, hop in
            if hop.hint == nil {
                // Nothing to ask of an endpoint, so the long press can go to
                // selection here.
                hopRow(hop)
                    .textSelection(.enabled)
            } else {
                // Selection is a long press too, and it wins the gesture where
                // both are offered — the conflict `copyable` documents,
                // resolved the same way: the menu takes the press and carries
                // the Copy itself.
                hopRow(hop)
                    // Full width so the whole row is the target.
                    //
                    // Deliberately no `contextMenuPreview` content shape: that
                    // pins the lift to this view's frame, which is the text
                    // and nothing else, and the platter comes up a thin strip
                    // instead of a row. Left alone, the lift takes the list
                    // cell with its insets, which is what a row should do.
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contextMenu { routerHopMenu(hop) }
            }
        }
        if hops.contains(where: \.isNamedByHint) {
            Text(RouterHintNaming.ambiguityNote)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private func hopRow(_ hop: RouteHop) -> some View {
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
                if let hint = hop.hint, askedRouters.contains(hint.bytes) {
                    // A router hint names one node, so the responder answers
                    // at once rather than holding its reply the way it does
                    // for an ask a crowd might answer. What is left is the
                    // round trip: several LoRa hops, each with its own
                    // channel-activity backoff.
                    Text("Asked—waiting for a reply")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .accessibilityElement(children: .combine)
    }

    /// What can be done about one router on a path. Empty for the endpoints
    /// and for hops the reply only counted, which leaves those rows with no
    /// menu at all.
    @ViewBuilder
    private func routerHopMenu(_ hop: RouteHop) -> some View {
        if let hint = hop.hint {
            if let named = hop.named {
                Button {
                    routerPendingDetail = named
                } label: {
                    Label("See node", systemImage: "person.crop.circle")
                }
            }
            if let identifyRouter = actions.identifyRouter {
                Button {
                    Task {
                        // Marked only once the radio has it, so the caption
                        // never claims an ask that never went out.
                        guard await identifyRouter(hint, hop.precedingRouters) else { return }
                        askedRouters.insert(hint.bytes)
                        // The caption is a timed state, not a latched one, and
                        // this is how long a round trip is worth waiting on: a
                        // hint-filtered reply is sent immediately, so what is
                        // left is travel over a few hops. Clearing on a reply
                        // instead would leave the failure case claiming an
                        // answer was still coming, and gating on the row having
                        // a name would suppress the caption exactly when a
                        // named-by-guess row is asked to confirm itself.
                        try? await Task.sleep(for: .seconds(15))
                        askedRouters.remove(hint.bytes)
                    }
                } label: {
                    Label("Discover", systemImage: "wave.3.right")
                }
            }
            // Carried here because this menu takes the long press that would
            // otherwise select the row's text.
            Button("Copy", systemImage: "doc.on.doc") {
                // The row's own text, which is what the selection it displaced
                // would have yielded.
                UIPasteboard.general.string = hop.title
            }
        }
    }

    private func routeHops(for reply: PeerPingReply) -> [RouteHop] {
        // Nothing to draw when the reply carried neither routers nor a hop
        // count: an empty list is not evidence of a direct path.
        guard !reply.routeHints.isEmpty || reply.hopCount != nil else { return [] }
        var hops = [originHop]
        hops.append(contentsOf: routerHops(reply.routeHints))

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
        [originHop] + routerHops(route.hints) + [destinationHop(isDirect: route.isDirect)]
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
    private func routerHop(_ hint: MeshRouterHint, precededBy preceding: [MeshRouterHint]) -> RouteHop {
        guard let named = RouterHintNaming.match(hint, among: actions.knownPeers) else {
            let candidates = actions.knownPeers.filter { hint.matches($0.identity) }
            let repeaters = candidates.filter(\.isLikelyRepeater)
            let detail: String
            switch (candidates.count, repeaters.count) {
            case (0, _):
                detail = "Router · not a node this phone knows"
            case let (_, matched) where matched > 1:
                detail = "Router · matches \(matched) known repeaters"
            case let (total, _):
                detail = "Router · matches \(total) known nodes"
            }
            return RouteHop(
                title: hint.text,
                detail: detail,
                symbolName: "antenna.radiowaves.left.and.right",
                hint: hint,
                precedingRouters: preceding
            )
        }

        return RouteHop(
            title: named.displayName,
            detail: named.isLikelyRepeater
                ? "\(hint.text) · likely this repeater"
                : "\(hint.text) · likely this node, not a known repeater",
            symbolName: "antenna.radiowaves.left.and.right",
            isNamedByHint: true,
            hint: hint,
            named: named,
            precedingRouters: preceding
        )
    }

    /// The routers on a path, each told which ones come before it.
    private func routerHops(_ hints: [MeshRouterHint]) -> [RouteHop] {
        hints.enumerated().map { index, hint in
            routerHop(hint, precededBy: Array(hints.prefix(index)))
        }
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
    /// The hint this row was drawn from, when the row is an intermediate
    /// router. Nil for the two endpoints and for hops that were only counted,
    /// which is what scopes the row's menu to nodes there is something to ask.
    var hint: MeshRouterHint?
    /// The node the hint most plausibly names, if any — the same guess that
    /// produced `title`, kept rather than flattened into it.
    var named: PeerSummary?
    /// The routers ahead of this one, in send order: the path an ask has to be
    /// steered down to land one hop short, where this router can answer it.
    var precedingRouters: [MeshRouterHint] = []
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
            let cellMeters = identity.locationPrecision
                .flatMap { LocationPresentation.cellMeters(precisionBytes: $0) }
            LabeledContent("Location") {
                VStack(alignment: .trailing) {
                    Text(
                        LocationPresentation.coordinateText(
                            latitude: latitude,
                            longitude: longitude,
                            cellMeters: cellMeters
                        )
                    )
                    if let cellMeters {
                        Text("within \(LocationPresentation.cellLabel(meters: cellMeters))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .coordinateActions(
                latitude: latitude,
                longitude: longitude,
                fractionDigits: LocationPresentation.coordinateDecimals(cellMeters: cellMeters),
                pinName: identity.name
            )
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
    /// A reply without a count is not one that failed to report — it arrived
    /// source-routed with no trace, so it crossed hops nobody recorded. Say
    /// that, rather than a number nobody measured.
    var hopCountText: String {
        hopCount.map { $0 == 1 ? "1 (direct)" : String($0) } ?? "Unknown source route"
    }
}
