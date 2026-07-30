import SwiftUI
import OSLog
import UIKit
import UMSHMobileCore

@MainActor
struct AppRootView: View {
    private static let logger = Logger(subsystem: "com.umsh.ios", category: "AppRoot")
    @State private var selectedTab: AppTab = .conversations
    @State private var radioSnapshot = RadioSnapshot.idle
    @State private var showsRadioDetail = false
    @State private var localIdentity: LocalIdentitySnapshot?
    @State private var identityError: IdentityVaultError?
    @State private var isLoadingIdentity = true
    @State private var peers: [PeerSummary] = []
    @State private var conversations: [DirectConversationSummary] = []
    @State private var openedConversation: DirectConversationSummary?
    @State private var incomingPeerImport: IncomingPeerImport?
    @State private var advertisedName = ""
    /// Whether this phone answers nearby nodes' identity requests. The
    /// preference outlives the mesh session, which starts discoverable, so
    /// it is reapplied on every session install.
    @AppStorage("phone.discoverable") private var phoneDiscoverable = true
    /// Bookkeeping that must survive body re-evaluation without itself being
    /// a source of invalidation. A reference held in `@State` is never
    /// reassigned, so mutating it costs nothing in the view graph.
    @State private var coordinator = AppStateCoordinator()

    private let meshEngine: RustMeshEngine
    private let identityVault: KeychainIdentityVault
    private let applicationStore: SQLiteApplicationStore?
    /// Why ``applicationStore`` is nil, when it is. Every store call site
    /// degrades to a silent no-op without one, which renders as an account
    /// with no contacts and no way to add any — indistinguishable from real
    /// data loss. Keeping the reason lets the UI say what actually happened.
    private let applicationStoreError: (any Error)?
    private let radioConnection: any RadioConnection
    private let notificationService = ChatNotificationService()

    init(radioConnection: any RadioConnection = CoreBluetoothRadioConnection()) {
        let meshEngine = RustMeshEngine()
        self.meshEngine = meshEngine
        identityVault = KeychainIdentityVault(meshEngine: meshEngine)
        self.radioConnection = radioConnection
        do {
            applicationStore = try SQLiteApplicationStore.applicationStore()
            applicationStoreError = nil
        } catch {
            applicationStore = nil
            applicationStoreError = error
            Self.logger.error(
                "Could not open the application store: \(String(describing: error), privacy: .public)"
            )
        }
    }

    /// The one set of peer operations every peer sheet gets, wherever it is
    /// opened from. Built here because this is the only place that holds the
    /// store, the radio, and the mesh engine together.
    private var peerActions: PeerActions {
        PeerActions(
            knownPeers: peers,
            startConversation: startConversation,
            ping: pingPeer,
            fetchIdentity: fetchIdentity,
            updateAlias: updateAlias,
            loadRoute: peerRoute,
            resetRoute: clearPeerRoute,
            setFavorite: setPeerFavorite,
            promoteToSaved: promotePeerToSaved,
            demoteToTransient: demotePeerToTransient,
            deletePeer: deletePeer,
            deletePeerAndConversation: deletePeerAndConversation,
            addToDeviceIdentity: { peer in
                await mutateDeviceIdentityPeer(peer, add: true)
            },
            removeFromDeviceIdentity: { peer in
                await mutateDeviceIdentityPeer(peer, add: false)
            }
        )
    }

    var body: some View {
        if let applicationStoreError {
            // Deliberately replaces the whole interface rather than banner-ing
            // over it. Without a store the conversation and peer lists render
            // empty and every save silently fails, so anything that still looks
            // like the normal app is actively telling the user their data is
            // gone. It is not; it is unread.
            StorageUnavailableView(error: applicationStoreError)
        } else {
            mainInterface
        }
    }

    private var mainInterface: some View {
        TabView(selection: $selectedTab) {
            NavigationStack {
                ConversationsView(
                    conversations: $conversations,
                    radioSnapshot: radioSnapshot,
                    inspectPeerIdentity: inspectPeerIdentity,
                    savePeer: savePeer,
                    updateDraft: updateDraft,
                    sendMessage: sendMessage,
                    messageActions: ChatMessageActions(edit: editMessage, delete: deleteMessage),
                    deleteConversation: deleteConversation,
                    peerActions: peerActions,
                    openedConversation: $openedConversation
                )
                    .appRadioToolbar(radioSnapshot) {
                        showsRadioDetail = true
                    }
            }
            .tabItem {
                Label("Conversations", systemImage: "bubble.left.and.bubble.right")
            }
            .tag(AppTab.conversations)

            NavigationStack {
                NetworkView(
                    radioSnapshot: $radioSnapshot,
                    conversations: $conversations,
                    peers: peers,
                    inspectPeerIdentity: inspectPeerIdentity,
                    savePeer: { preview, details, startConversation in
                        await savePeer(preview, details: details, startConversation: startConversation)
                    },
                    openConversation: { conversation in
                        selectedTab = .conversations
                        openedConversation = conversation
                    },
                    peerActions: peerActions,
                    updateDraft: updateDraft,
                    sendMessage: sendMessage,
                    messageActions: ChatMessageActions(edit: editMessage, delete: deleteMessage),
                    advertiseIdentity: advertiseIdentity,
                    advertisedName: advertisedName,
                    clearDiscoveredNodes: clearDiscoveredNodes,
                    solicitNearbyIdentities: solicitNearbyIdentities
                )
                    .appRadioToolbar(radioSnapshot) {
                        showsRadioDetail = true
                    }
            }
            .tabItem {
                Label("Network", systemImage: "point.3.connected.trianglepath.dotted")
            }
            .tag(AppTab.network)

            NavigationStack {
                SettingsView(
                    identity: localIdentity,
                    identityError: identityError,
                    isLoadingIdentity: isLoadingIdentity,
                    createIdentity: createIdentity,
                    advertisedName: advertisedName,
                    saveAdvertisedName: saveAdvertisedName,
                    advertiseIdentity: advertiseIdentity,
                    identityShareURI: identityShareURI,
                    phoneDiscoverable: phoneDiscoverable,
                    setPhoneDiscoverable: { enabled in
                        phoneDiscoverable = enabled
                        await pushPhoneDiscoverability()
                    },
                    radioSnapshot: $radioSnapshot,
                    connectRadio: connectRadio,
                    reconnectRadio: reconnectRadio,
                    claimRadio: claimRadio,
                    refreshRadio: refreshRadio,
                    configureRadio: configureRadio,
                    disconnectRadio: disconnectRadio,
                    forgetRadio: forgetRadio,
                    factoryResetRadio: factoryResetRadio,
                    discoverRadios: discoverRadios,
                    selectRadio: selectRadio,
                    stopDiscovery: stopRadioDiscovery,
                    saveDevicePeer: saveAdministeredDevice,
                    isPeerSaved: { address in
                        peers.contains { $0.identity.canonicalAddress == address }
                    },
                    peerActions: peerActions,
                    conversations: $conversations,
                    updateDraft: updateDraft,
                    sendMessage: sendMessage,
                    messageActions: ChatMessageActions(edit: editMessage, delete: deleteMessage)
                )
                    .appRadioToolbar(radioSnapshot) {
                        showsRadioDetail = true
                    }
            }
            .tabItem {
                Label("Settings", systemImage: "gearshape")
            }
            .tag(AppTab.settings)
        }
        .onOpenURL { url in
            guard url.scheme?.lowercased() == "umsh" else { return }
            incomingPeerImport = IncomingPeerImport(uri: url.absoluteString)
        }
        .sheet(item: $incomingPeerImport) { item in
            NavigationStack {
                NodeImportView(
                    inspectPeerIdentity: inspectPeerIdentity,
                    save: { preview, details, startConversation in
                        let conversation = await savePeer(
                            preview,
                            details: details,
                            startConversation: startConversation
                        )
                        incomingPeerImport = nil
                        if startConversation, let conversation {
                            selectedTab = .conversations
                            openedConversation = conversation
                        }
                    },
                    initialInput: item.uri
                )
            }
        }
        .sheet(isPresented: $showsRadioDetail) {
            NavigationStack {
                RadioDetailView(
                    snapshot: $radioSnapshot,
                    connect: connectRadio,
                    reconnect: reconnectRadio,
                    claim: claimRadio,
                    refresh: refreshRadio,
                    configure: configureRadio,
                    disconnect: disconnectRadio,
                    forget: forgetRadio,
                    factoryReset: factoryResetRadio,
                    discoverRadios: discoverRadios,
                    selectRadio: selectRadio,
                    stopDiscovery: stopRadioDiscovery,
                    peerActions: peerActions,
                    conversations: $conversations,
                    updateDraft: updateDraft,
                    sendMessage: sendMessage,
                    messageActions: ChatMessageActions(edit: editMessage, delete: deleteMessage)
                )
            }
        }
        .task {
            await loadIdentity()
        }
        .task {
            for await snapshot in await radioConnection.snapshots() {
                // A snapshot is published for every ULCP frame the radio
                // sends, so the same state arrives many times a second while
                // the link is busy. Writing `@State` unconditionally would
                // re-evaluate the whole tab tree — transcript included — on
                // each one, which is felt as stutter while typing.
                if radioSnapshot != snapshot {
                    radioSnapshot = snapshot
                }
                if snapshot.linkState == .attached {
                    // The first successful attach is the first moment a
                    // message notification has concrete meaning.
                    notificationService.requestAuthorizationIfNeeded()
                }
                await synchronizeRadioPeer(from: snapshot)
            }
        }
        .task {
            for await update in await radioConnection.chatUpdates() {
                await applyChatUpdate(update)
            }
        }
        .task {
            for await advertisement in await radioConnection.advertisementEvents() {
                await applyReceivedAdvertisement(advertisement)
            }
        }
        .task {
            for await heard in await radioConnection.peerHeardEvents() {
                await applyPeerHeard(heard)
            }
        }
        .task {
            for await peerAddress in notificationService.conversationOpens {
                await openConversationFromNotification(peerAddress: peerAddress)
            }
        }
        .environment(
            \.visibleConversationReporter,
            VisibleConversationReporter(
                appeared: { [notificationService] address in
                    notificationService.setVisibleConversation(peerAddress: address)
                },
                disappeared: { [notificationService] address in
                    notificationService.clearVisibleConversation(ifMatching: address)
                }
            )
        )
    }

    @MainActor
    private func openConversationFromNotification(peerAddress: String) async {
        selectedTab = .conversations
        if conversations.first(where: {
            $0.peer.identity.canonicalAddress == peerAddress
        }) == nil {
            await reloadApplicationState()
        }
        guard let conversation = conversations.first(where: {
            $0.peer.identity.canonicalAddress == peerAddress
        }) else { return }
        openedConversation = conversation
    }

    /// Persist a node-identity bundle heard over the air, whether it arrived
    /// as a broadcast advertisement or as the reply to an Identity Request.
    ///
    /// A broadcast frame is unauthenticated at the MAC layer, so it is stored
    /// only when its embedded signature verifies against the claimed sender
    /// key — anything else could be spoofed by any nearby transmitter. An
    /// Identity Request reply is a unicast the MAC already authenticated and
    /// carries no signature of its own, so it is stored on that basis.
    @MainActor
    private func applyReceivedAdvertisement(_ advertisement: RadioAdvertisementEvent) async {
        guard let applicationStore, let localIdentity else { return }
        guard let identity = try? await meshEngine.decodeNodeIdentity(
            address: advertisement.peerAddress,
            payload: advertisement.payload
        ), advertisement.isTrustworthy(given: identity.signature) else { return }
        do {
            try await applicationStore.upsertPeer(
                ownerIdentityID: localIdentity.id,
                publicAddress: advertisement.peerAddress,
                alias: nil,
                advertisedName: identity.name,
                // The node's own statement of what it is, refreshed on every
                // bundle so the recorded role tracks the node.
                nodeKind: PeerRole(roleCode: identity.roleCode).rawValue,
                advertisement: advertisement.payload,
                advertisementAuthenticated: advertisement.sourceAuthenticated
            )
            await touchLastHeard(advertisement.peerAddress)
            // An over-the-air row lands in the transient tier, which stays
            // bounded: oldest-heard evictable transients drop past the cap.
            try await applicationStore.enforceTransientRetention(
                ownerIdentityID: localIdentity.id
            )
            await reloadApplicationState()
        } catch {
            Self.logger.error("Failed to persist received advertisement")
        }
    }

    /// Record that a saved peer was on the air.
    ///
    /// A beacon carries no payload, so this is the only trace it leaves: no
    /// advertisement, no message, no ping reply. Presence needs no
    /// authentication to be worth recording — the claim being made is only
    /// "a frame naming this node was accepted", and a spoofer gains nothing
    /// by making a node look reachable. Nothing is created here: a node this
    /// phone has never saved has no row, and hearing it is not a reason to
    /// start keeping one.
    @MainActor
    private func applyPeerHeard(_ heard: RadioPeerHeardEvent) async {
        guard let peer = heard.resolve(among: peers) else { return }
        // Reloading the whole application state for every accepted frame
        // would be a full transcript read per packet. Skip the write and the
        // reload when the recorded instant would not visibly move.
        if let lastHeard = peer.lastHeard, Date().timeIntervalSince(lastHeard) < 1 { return }
        await touchLastHeard(peer.identity.canonicalAddress)
        await reloadApplicationState()
    }

    @MainActor
    private func loadIdentity() async {
        isLoadingIdentity = true
        defer { isLoadingIdentity = false }
        do {
            localIdentity = try await identityVault.loadIdentity()
            try await radioConnection.useHostIdentity(localIdentity?.publicIdentity)
            try await installMeshSession()
            await prepareApplicationState()
            await prepareChatState()
            await loadAdvertisedName()
            await pushPhoneDiscoverability()
            if localIdentity != nil {
                await radioConnection.autoConnect()
            }
            identityError = nil
        } catch let error as IdentityVaultError {
            identityError = error
        } catch {
            identityError = .keychainFailure
        }
    }

    @MainActor
    private func createIdentity() async {
        isLoadingIdentity = true
        defer { isLoadingIdentity = false }
        do {
            localIdentity = try await identityVault.createIdentity()
            try await radioConnection.useHostIdentity(localIdentity?.publicIdentity)
            try await installMeshSession()
            await prepareApplicationState()
            await prepareChatState()
            await loadAdvertisedName()
            await pushPhoneDiscoverability()
            identityError = nil
        } catch let error as IdentityVaultError {
            identityError = error
        } catch {
            identityError = .keychainFailure
        }
    }

    @MainActor
    private func loadAdvertisedName() async {
        guard let applicationStore, let localIdentity else { return }
        advertisedName = (try? await applicationStore.localAdvertisedName(
            ownerIdentityID: localIdentity.id
        ).flatMap { $0 }) ?? ""
    }

    private func saveAdvertisedName(_ name: String) async {
        guard let applicationStore, let localIdentity else { return }
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        try? await applicationStore.updateLocalAdvertisedName(
            ownerIdentityID: localIdentity.id,
            name: trimmed.isEmpty ? nil : trimmed
        )
        advertisedName = trimmed
        // The identity-request responder carries the same name; keep it
        // current.
        await pushPhoneDiscoverability()
    }

    /// Hand the stored discoverability preference and display name to the
    /// mesh session's identity-request responder. Best-effort: with no
    /// session yet, the next install reapplies it.
    private func pushPhoneDiscoverability() async {
        await radioConnection.setPhoneDiscoverable(
            phoneDiscoverable,
            name: advertisedName.isEmpty ? nil : advertisedName
        )
    }

    /// Broadcast a signed identity advertisement. Returns a user-facing
    /// failure message, or nil on success.
    private func advertiseIdentity() async -> String? {
        do {
            let name = advertisedName.isEmpty ? nil : advertisedName
            try await radioConnection.advertiseIdentity(name: name)
            return nil
        } catch {
            return "The advertisement could not be sent. Check that the companion radio is connected."
        }
    }

    /// The shareable identity URI: bundle-bearing (name, role, capabilities,
    /// signed) when the mesh session can sign, bare public key otherwise.
    private func identityShareURI() async -> String {
        guard let localIdentity else { return "" }
        let bare = localIdentity.publicIdentity.nodeURI
        let name = advertisedName.isEmpty ? nil : advertisedName
        guard let bundle = try? await radioConnection.signIdentityBundle(name: name),
              let uri = try? nodeUriWithIdentity(
                  address: localIdentity.publicIdentity.canonicalAddress,
                  identityPayload: bundle
              )
        else { return bare }
        return uri
    }

    private func connectRadio() async {
        do {
            try await radioConnection.connect()
        } catch {
            // Connection failures are published as radio snapshots so every
            // screen presents the same state and recovery action.
        }
    }

    private func reconnectRadio() async {
        await radioConnection.reconnect()
    }

    private func discoverRadios() async -> AsyncStream<[DiscoveredRadio]> {
        await radioConnection.discoverRadios()
    }

    private func selectRadio(_ id: UUID) async throws {
        try await radioConnection.selectRadio(id)
    }

    private func stopRadioDiscovery() async {
        await radioConnection.stopDiscovery()
    }

    private func disconnectRadio() async {
        await radioConnection.disconnect()
    }

    private func forgetRadio() async {
        await radioConnection.forget()
    }

    private func factoryResetRadio() async throws {
        try await radioConnection.factoryReset()
    }

    private func claimRadio() async {
        do {
            try await radioConnection.claimForCurrentIdentity()
        } catch {
            // The adapter publishes a shared failure snapshot when an active
            // claim fails. Preconditions leave the existing snapshot intact.
        }
    }

    private func configureRadio(_ settings: RadioSettings) async throws {
        try await radioConnection.configure(settings)
    }

    private func refreshRadio() async {
        if let refreshed = try? await radioConnection.refresh() {
            radioSnapshot = refreshed
        }
    }

    private func inspectPeerIdentity(_ input: String) async -> Result<MeshNodeURIPreview, MeshEngineError> {
        do {
            return .success(try await meshEngine.inspectPeerIdentity(input))
        } catch let error as MeshEngineError {
            return .failure(error)
        } catch {
            return .failure(.coreFailure)
        }
    }

    private func savePeer(
        _ preview: MeshNodeURIPreview,
        details: PeerImportDetails,
        startConversation: Bool
    ) async -> DirectConversationSummary? {
        guard let applicationStore, let localIdentity else { return nil }
        let identity = preview.publicIdentity
        do {
            try await applicationStore.upsertPeer(
                ownerIdentityID: localIdentity.id,
                publicAddress: identity.canonicalAddress,
                alias: details.alias,
                advertisedName: preview.identity?.name,
                // The role comes from the bundle, not the operator. An
                // imported payload is only ever handed over with a verified
                // signature, so it needs no MAC authentication to be believed.
                isSaved: true,
                nodeKind: preview.identity.map { PeerRole(roleCode: $0.roleCode).rawValue },
                advertisement: preview.identityPayload
            )
            if startConversation {
                _ = try await applicationStore.ensureDirectConversation(
                    ownerIdentityID: localIdentity.id,
                    peerAddress: identity.canonicalAddress
                )
            }
            await reloadApplicationState()
            try await radioConnection.registerChatPeers([identity.canonicalAddress])
            return conversations.first { $0.peer.identity.canonicalAddress == identity.canonicalAddress }
        } catch {
            return nil
        }
    }

    /// Record a device the phone has been configuring as an ordinary peer.
    ///
    /// Deliberately not a chat peer: a repeater is infrastructure the operator
    /// wants to find again, not someone to talk to. Starting a conversation
    /// with it remains an ordinary Network action.
    private func saveAdministeredDevice(
        _ identity: MeshPublicIdentity,
        name: String?,
        role: PeerRole
    ) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            try await applicationStore.upsertPeer(
                ownerIdentityID: localIdentity.id,
                publicAddress: identity.canonicalAddress,
                alias: nil,
                advertisedName: name,
                isSaved: true,
                nodeKind: role.rawValue
            )
            await reloadApplicationState()
            return true
        } catch {
            return false
        }
    }

    private struct IncomingPeerImport: Identifiable {
        let id = UUID()
        let uri: String
    }

    private func updateAlias(_ peer: PeerSummary, _ alias: String?) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            try await applicationStore.updateNodeAlias(
                ownerIdentityID: localIdentity.id,
                publicAddress: peer.identity.canonicalAddress,
                alias: alias
            )
            await reloadApplicationState()
            return true
        } catch {
            return false
        }
    }

    private func setPeerFavorite(_ peer: PeerSummary, _ favorite: Bool) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            try await applicationStore.setPeerFavorite(
                ownerIdentityID: localIdentity.id,
                publicAddress: peer.identity.canonicalAddress,
                isFavorite: favorite
            )
            await reloadApplicationState()
            return true
        } catch {
            return false
        }
    }

    private func promotePeerToSaved(_ peer: PeerSummary) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            try await applicationStore.promotePeerToSaved(
                ownerIdentityID: localIdentity.id,
                publicAddress: peer.identity.canonicalAddress
            )
            await reloadApplicationState()
            return true
        } catch {
            return false
        }
    }

    /// Take a peer off the local identity while keeping its row, history, and
    /// searchability. The mesh session keeps the peer registered when a
    /// conversation exists — chat continuity is the point of demoting.
    private func demotePeerToTransient(_ peer: PeerSummary) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            try await applicationStore.demotePeerToTransient(
                ownerIdentityID: localIdentity.id,
                publicAddress: peer.identity.canonicalAddress
            )
            await reloadApplicationState()
            return true
        } catch {
            return false
        }
    }

    private func deletePeer(_ peer: PeerSummary) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            guard try await applicationStore.deletePeer(
                ownerIdentityID: localIdentity.id,
                publicAddress: peer.identity.canonicalAddress
            ) else { return false }
            await removeMeshPeer(peer)
            await reloadApplicationState()
            return true
        } catch {
            return false
        }
    }

    private func deletePeerAndConversation(_ peer: PeerSummary) async -> Bool {
        guard let applicationStore, let localIdentity else { return false }
        do {
            guard try await applicationStore.deletePeerAndConversation(
                ownerIdentityID: localIdentity.id,
                publicAddress: peer.identity.canonicalAddress
            ) else { return false }
            await removeMeshPeer(peer)
            await reloadApplicationState()
            return true
        } catch {
            return false
        }
    }

    /// Best-effort MAC-layer removal behind a store delete. A disconnected
    /// radio is not an error: the store is the authority, and
    /// `prepareChatState` rebuilds the registry from it on the next attach.
    private func removeMeshPeer(_ peer: PeerSummary) async {
        try? await radioConnection.removeChatPeers([peer.identity.canonicalAddress])
    }

    /// Add or remove one peer on the radio's device identity. The device is
    /// the authority; on success the local flag is updated as a cache so the
    /// UI answers immediately, and the attach-edge reconcile keeps it honest.
    private func mutateDeviceIdentityPeer(
        _ peer: PeerSummary,
        add: Bool
    ) async -> DevicePeerActionOutcome {
        guard let publicKey = try? publicIdentityBytes(
            address: peer.identity.canonicalAddress
        ) else { return .failed }
        do {
            if add {
                try await radioConnection.addDevicePeer(publicKey)
            } else {
                try await radioConnection.removeDevicePeer(publicKey)
            }
            if let applicationStore, let localIdentity {
                try? await applicationStore.setPeerOnDeviceIdentity(
                    ownerIdentityID: localIdentity.id,
                    publicAddress: peer.identity.canonicalAddress,
                    isOnDeviceIdentity: add
                )
            }
            await reloadApplicationState()
            return .success
        } catch let error as DevicePeerError {
            return switch error {
            case .radioUnavailable: .radioUnavailable
            case .deviceFull: .deviceFull
            case .unsupported: .unsupported
            case .failed: .failed
            }
        } catch {
            return .failed
        }
    }

    /// One zero-hop broadcast Identity Request for the Discover sheet:
    /// nodes in direct radio range that match the role filter reply with
    /// their identities, which land through `applyReceivedAdvertisement`.
    /// Returns whether the request was handed to the radio.
    private func solicitNearbyIdentities(_ roleFilter: PeerRole?) async -> Bool {
        guard radioSnapshot.linkState == .attached || radioSnapshot.linkState == .ready,
              radioSnapshot.hostState == .matchesCurrentIdentity
        else { return false }
        do {
            try await radioConnection.requestNearbyIdentities(roleFilter: roleFilter?.roleCode)
            return true
        } catch {
            return false
        }
    }

    /// Drop every transient row nothing depends on, from the Discover
    /// sheet's overflow. Saved peers, conversations, device-identity rows,
    /// and the companion radio are untouched by the store's guards.
    private func clearDiscoveredNodes() async {
        guard let applicationStore, let localIdentity else { return }
        try? await applicationStore.clearTransientPeers(ownerIdentityID: localIdentity.id)
        await reloadApplicationState()
    }

    private func updateDraft(_ conversationID: Int64, _ text: String) async {
        guard let applicationStore, let localIdentity else { return }
        try? await applicationStore.updateDraft(
            ownerIdentityID: localIdentity.id,
            conversationID: conversationID,
            text: text
        )
        if let index = conversations.firstIndex(where: { $0.id == conversationID }) {
            conversations[index].draftText = text
        }
    }

    private func sendMessage(
        _ conversation: DirectConversationSummary,
        _ body: String
    ) async -> MessageSendResult {
        await performChatCompose(conversation, clearsDraft: true) { clientToken in
            try await radioConnection.composeText(
                peerAddress: conversation.peer.identity.canonicalAddress,
                clientToken: clientToken,
                body: body
            )
        }
    }

    private func editMessage(
        _ conversation: DirectConversationSummary,
        _ message: ChatMessageSummary,
        _ newBody: String
    ) async -> MessageSendResult {
        await performChatCompose(conversation, clearsDraft: false) { clientToken in
            try await radioConnection.composeEdit(
                peerAddress: conversation.peer.identity.canonicalAddress,
                clientToken: clientToken,
                original: originalRef(message),
                body: newBody
            )
        }
    }

    private func deleteMessage(
        _ conversation: DirectConversationSummary,
        _ message: ChatMessageSummary
    ) async -> MessageSendResult {
        await performChatCompose(conversation, clearsDraft: false) { clientToken in
            try await radioConnection.composeDelete(
                peerAddress: conversation.peer.identity.canonicalAddress,
                clientToken: clientToken,
                original: originalRef(message)
            )
        }
    }

    /// The engine accepts either the live handle (same facade session) or
    /// the persisted wire identity (after an app restart); send both and let
    /// Rust pick, so the transcript never has to care which run composed a
    /// message.
    private func originalRef(_ message: ChatMessageSummary) -> MobileChatOriginalRef {
        MobileChatOriginalRef(
            sessionId: UInt64(message.sessionID) ?? 0,
            handle: message.handle,
            wireId: message.wireID,
            epoch: message.epoch
        )
    }

    private func performChatCompose(
        _ conversation: DirectConversationSummary,
        clearsDraft: Bool,
        compose: (UInt32) async throws -> MobileChatComposeBatchRecord
    ) async -> MessageSendResult {
        guard let applicationStore, let localIdentity else {
            return .failed("The local identity or message database is unavailable.")
        }
        guard radioSnapshot.linkState == .attached || radioSnapshot.linkState == .ready,
              radioSnapshot.hostState == .matchesCurrentIdentity
        else { return .failed("Connect a companion radio configured for this phone before sending.") }
        do {
            let batch = try await compose(UInt32.random(in: 1...UInt32.max))
            do {
                try await applicationStore.commitChatComposeBatch(
                    ownerIdentityID: localIdentity.id,
                    batch: batch
                )
                // The compose mutation is now durable. Publish that optimistic
                // row immediately; radio transmission and delivery evidence
                // can update its state afterward without making the user
                // refresh or wait for the transport round trip.
                await reloadApplicationState()
            } catch {
                Self.logger.error("Could not persist chat compose batch: \(String(describing: error), privacy: .public)")
                let checkpoints = (try? await applicationStore.chatCheckpoints(
                    ownerIdentityID: localIdentity.id
                )) ?? []
                try? await radioConnection.rejectChatBatch(
                    batch.batchId,
                    checkpoints: checkpoints
                )
                return .failed("The message could not be saved locally: \(error)")
            }
            do {
                try await radioConnection.commitChatBatch(batch.batchId)
            } catch {
                Self.logger.error("Could not release chat batch to radio: \(String(describing: error), privacy: .public)")
                try? await applicationStore.markChatComposeBatchFailed(
                    ownerIdentityID: localIdentity.id,
                    batch: batch
                )
                await reloadApplicationState()
                return .failed("The message could not be queued for transmission: \(error)")
            }
            if clearsDraft {
                try await applicationStore.updateDraft(
                    ownerIdentityID: localIdentity.id,
                    conversationID: conversation.id,
                    text: ""
                )
            }
            await reloadApplicationState()
            guard let updated = conversations.first(where: { $0.id == conversation.id }) else {
                return .failed("The message was saved, but the conversation could not be refreshed.")
            }
            return .sent(updated)
        } catch {
            Self.logger.error("Could not compose chat message: \(String(describing: error), privacy: .public)")
            return .failed("The message could not be composed: \(error)")
        }
    }

    private func deleteConversation(_ conversation: DirectConversationSummary) async {
        guard let applicationStore, let localIdentity else { return }
        do {
            try await applicationStore.deleteDirectConversation(
                ownerIdentityID: localIdentity.id,
                conversationID: conversation.id
            )
            await reloadApplicationState()
        } catch {
            Self.logger.error("Could not delete conversation \(conversation.id): \(String(describing: error), privacy: .public)")
        }
    }

    private func startConversation(_ peer: PeerSummary) async -> DirectConversationSummary? {
        guard let applicationStore, let localIdentity else { return nil }
        do {
            _ = try await applicationStore.ensureDirectConversation(
                ownerIdentityID: localIdentity.id,
                peerAddress: peer.identity.canonicalAddress
            )
            await reloadApplicationState()
            try await radioConnection.registerChatPeers([peer.identity.canonicalAddress])
            return conversations.first {
                $0.peer.identity.canonicalAddress == peer.identity.canonicalAddress
            }
        } catch {
            return nil
        }
    }

    private func pingPeer(_ peer: PeerSummary) async -> PeerPingResult {
        guard radioSnapshot.linkState == .attached || radioSnapshot.linkState == .ready else {
            return .unavailable(reason: "Connect a configured companion radio to ping this peer.")
        }
        guard radioSnapshot.hostState == .matchesCurrentIdentity else {
            return .unavailable(reason: "Set up this radio for the current phone identity before pinging peers.")
        }
        do {
            switch try await radioConnection.ping(
                peerAddress: peer.identity.canonicalAddress
            ) {
            case let .reply(reply):
                // A pong is evidence we heard from the peer; a timeout is not.
                await touchLastHeard(peer.identity.canonicalAddress)
                await reloadApplicationState()
                return .reply(
                    PeerPingReply(
                        roundTripMilliseconds: reply.roundTripMilliseconds,
                        hopCount: reply.hopCount,
                        routeHints: await renderRouterHints(reply.routeHints),
                        rssiDBm: reply.rssiDBm,
                        signalToNoiseCentibels: reply.signalToNoiseCentibels,
                        linkQuality: reply.linkQuality
                    )
                )
            case .timedOut:
                return .timedOut
            }
        } catch {
            return .unavailable(reason: "The Rust mesh session could not send this ping.")
        }
    }

    /// Report the route this phone will use for the next frame to `peer`.
    /// A radio that cannot answer reads as nothing learned, which is what an
    /// unreachable MAC effectively means for the next send.
    private func peerRoute(_ peer: PeerSummary) async -> PeerRoute {
        guard let route = try? await radioConnection.peerRoute(
            peerAddress: peer.identity.canonicalAddress
        ) else { return .unavailable }
        let kind: PeerRoute.Kind = switch route.kind {
        case .unknown: .unknown
        case .direct: .direct
        case .source: .source
        case .flood: .flood
        }
        return PeerRoute(
            kind: kind,
            hints: await renderRouterHints(route.hints),
            floodHops: route.floodHops,
            floodRegions: route.floodRegions
        )
    }

    /// Discard a peer's learned route. Returns whether one was held, so the
    /// UI can distinguish a reset from a no-op.
    private func clearPeerRoute(_ peer: PeerSummary) async -> Bool {
        (try? await radioConnection.clearPeerRoute(
            peerAddress: peer.identity.canonicalAddress
        )) ?? false
    }

    /// Render wire router hints for display. A hint the core rejects — a
    /// wrong-width option, say — is dropped rather than shown as raw bytes:
    /// the route reads as incomplete, which it is.
    private func renderRouterHints(_ hints: [Data]) async -> [MeshRouterHint] {
        var rendered: [MeshRouterHint] = []
        rendered.reserveCapacity(hints.count)
        for hint in hints {
            guard let routerHint = try? await meshEngine.renderRouterHint(hint) else {
                Self.logger.error("Dropping a \(hint.count)-byte router hint from a ping route")
                continue
            }
            rendered.append(routerHint)
        }
        return rendered
    }

    /// Solicit a peer's current identity over the mesh. The response is not
    /// awaited here — it returns asynchronously as a node-identity
    /// advertisement, captured by `applyReceivedAdvertisement`, which upserts
    /// the fresh bundle and refreshes the sheet. Returns whether the request
    /// was sent, for a brief UI confirmation.
    private func fetchIdentity(_ peer: PeerSummary) async -> Bool {
        guard radioSnapshot.linkState == .attached || radioSnapshot.linkState == .ready,
              radioSnapshot.hostState == .matchesCurrentIdentity
        else { return false }
        do {
            try await radioConnection.requestIdentity(
                peerAddress: peer.identity.canonicalAddress
            )
            return true
        } catch {
            return false
        }
    }

    /// Record that we just heard from a peer by any inbound evidence. Safe to
    /// call for peers not yet saved locally — the store no-ops on a missing
    /// row. Callers reload application state afterward to surface the change.
    private func touchLastHeard(_ peerAddress: String) async {
        guard let applicationStore, let localIdentity else { return }
        try? await applicationStore.touchLastHeard(
            ownerIdentityID: localIdentity.id,
            publicAddress: peerAddress,
            at: Date()
        )
    }

    private func installMeshSession() async throws {
        let session = try await meshEngine.meshSession()
        await radioConnection.useMeshSession(session)
    }

    private func prepareChatState() async {
        guard let applicationStore, let localIdentity else { return }
        do {
            let checkpoints = try await applicationStore.chatCheckpoints(
                ownerIdentityID: localIdentity.id
            )
            // Register only the peers chat actually involves: those with a
            // conversation, plus every checkpointed stream. Registering every
            // stored row would grow with the transient tier and can exceed
            // the mesh session's peer table.
            let addresses = Set(
                conversations.map(\.peer.identity.canonicalAddress)
                    + checkpoints.map(\.peerAddress)
            )
            try await radioConnection.prepareChat(
                peerAddresses: addresses.sorted(),
                checkpoints: checkpoints
            )
        } catch {
            // Chat stays unavailable until the durable state can be restored.
        }
    }

    private func applyChatUpdate(_ update: RadioChatUpdate) async {
        guard let applicationStore, let localIdentity else { return }
        // A background BLE wake gives a short grace window; the assertion
        // keeps iOS from suspending us between persisting the batch and
        // acknowledging it. Worst case on expiry is a duplicate re-apply,
        // which the store tolerates.
        let assertion = UIApplication.shared.beginBackgroundTask(withName: "umsh.chat.apply")
        defer {
            if assertion != .invalid {
                UIApplication.shared.endBackgroundTask(assertion)
            }
        }
        for diagnostic in update.diagnostics {
            Self.logger.warning("Rust chat diagnostic: \(diagnostic, privacy: .public)")
        }
        do {
            if !update.mutations.isEmpty {
                try await applicationStore.applyChatMutations(
                    ownerIdentityID: localIdentity.id,
                    mutations: update.mutations
                )
                for peerAddress in Set(update.mutations.compactMap(\.peerAddress)) {
                    _ = try await applicationStore.ensureDirectConversation(
                        ownerIdentityID: localIdentity.id,
                        peerAddress: peerAddress
                    )
                }
            }
            if !update.deliveries.isEmpty {
                try await applicationStore.applyChatDeliveries(
                    ownerIdentityID: localIdentity.id,
                    deliveries: update.deliveries
                )
            }
            for lookup in update.archiveLookups {
                let payload = try? await applicationStore.chatArchive(
                    ownerIdentityID: localIdentity.id,
                    lookup: lookup
                )
                try await radioConnection.applyChatArchiveResult(
                    requestID: lookup.requestId,
                    kind: payload == nil ? .unknown : .found,
                    payload: payload ?? Data()
                )
            }
            // Last-heard evidence beyond chat inserts: an inbound message and a
            // delivery ack both prove we heard from the peer. Deliveries carry
            // no address, so resolve them from the acked message's conversation.
            var heardFrom: Set<String> = []
            for mutation in update.mutations where mutation.direction == .inbound {
                if let peerAddress = mutation.peerAddress { heardFrom.insert(peerAddress) }
            }
            for delivery in update.deliveries where delivery.state == .acknowledged {
                if let peerAddress = try? await applicationStore.peerAddressForMessage(
                    ownerIdentityID: localIdentity.id,
                    sessionID: delivery.sessionId,
                    handle: delivery.handle
                ) {
                    heardFrom.insert(peerAddress)
                }
            }
            let heardAt = Date()
            for peerAddress in heardFrom {
                try? await applicationStore.touchLastHeard(
                    ownerIdentityID: localIdentity.id,
                    publicAddress: peerAddress,
                    at: heardAt
                )
            }
            try await radioConnection.acknowledgeChatBatch(update.batchID)
            if !update.mutations.isEmpty || !update.deliveries.isEmpty {
                await reloadApplicationState()
            }
            await postNotifications(for: update.mutations)
        } catch {
            // Effects remain idempotent and can safely be applied again if
            // the Rust facade re-emits them.
            Self.logger.error(
                "Could not apply chat update batch \(update.batchID, privacy: .public): \(String(describing: error), privacy: .public)"
            )
        }
    }

    /// Notify whenever the engine flags a mutation `notify == true` — the
    /// single, authoritative signal covering single-frame arrivals, fragment
    /// completion, the 30 s fragment deadline, and late backfills. Never fires
    /// for local echoes, placeholders, or control frames (the engine never
    /// sets `notify` on those). The flag can ride an `UpdateBody` (which omits
    /// peer/body), so the target is resolved from durable storage by handle.
    /// Runs only after the batch reached storage; the willPresent delegate
    /// suppresses the banner when that conversation is visible in the
    /// foreground. A redelivered batch can repeat a banner; accepted worst case.
    private func postNotifications(for mutations: [MobileChatMutationRecord]) async {
        guard let applicationStore, let localIdentity else { return }
        for mutation in mutations where mutation.notify {
            guard let target = try? await applicationStore.chatNotificationTarget(
                ownerIdentityID: localIdentity.id,
                sessionID: mutation.sessionId,
                handle: mutation.handle
            ) else { continue }
            let displayName = peers.first {
                $0.identity.canonicalAddress == target.peerAddress
            }?.displayName ?? String(target.peerAddress.prefix(10))
            notificationService.postInboundMessage(
                peerAddress: target.peerAddress,
                displayName: displayName,
                body: target.body
            )
        }
    }

    private func prepareApplicationState() async {
        guard let applicationStore, let localIdentity else { return }
        do {
            try await applicationStore.migrateLegacyPrimaryIdentity(
                to: localIdentity.id,
                publicAddress: localIdentity.publicIdentity.canonicalAddress
            )
            try await applicationStore.upsertIdentity(
                id: localIdentity.id,
                publicAddress: localIdentity.publicIdentity.canonicalAddress
            )
            // Runs before any compose in this process, so every 'pending'
            // outbound row is an orphan from a previous launch.
            try await applicationStore.failStalePendingMessages(
                ownerIdentityID: localIdentity.id
            )
            await synchronizeRadioPeer(from: radioSnapshot)
            await reloadApplicationState()
        } catch {
            peers = []
            conversations = []
        }
    }

    private func synchronizeRadioPeer(from snapshot: RadioSnapshot) async {
        guard snapshot.linkState == .attached || snapshot.linkState == .ready,
              snapshot.hostState == .matchesCurrentIdentity,
              let radioIdentity = snapshot.deviceIdentity,
              let identifier = snapshot.localIdentifier,
              let applicationStore,
              let localIdentity
        else {
            // Re-persist on the next attach: a reconnect can bring a
            // different radio, or the same one under a new name.
            coordinator.synchronizedRadioPeer = nil
            coordinator.lastReconciledDevicePeers = nil
            return
        }
        // The radio's device-identity peer list, read back on attach. The
        // device is the authority; the store rows only cache it. Gated on
        // the last reconciled list so the steady snapshot stream costs
        // nothing.
        if let addresses = snapshot.provisioning?.devPeerAddresses,
           coordinator.lastReconciledDevicePeers != addresses {
            do {
                try await applicationStore.reconcileDeviceIdentityPeers(
                    ownerIdentityID: localIdentity.id,
                    addresses: addresses
                )
                coordinator.lastReconciledDevicePeers = addresses
                await reloadApplicationState()
            } catch {
                // The cache stays stale until the next attach retries.
            }
        }
        // Only the four facts below reach storage. Every other part of a
        // snapshot — duty cycle, queue depth, battery — changes constantly
        // while the radio works, and re-running an fsync-backed write plus a
        // full application-state reload behind each of those is what made the
        // UI feel like it was waiting on the radio.
        let record = SynchronizedRadioPeer(
            ownerIdentityID: localIdentity.id,
            publicAddress: radioIdentity.canonicalAddress,
            advertisedName: snapshot.name,
            radioIdentifier: identifier.uuidString
        )
        guard coordinator.synchronizedRadioPeer != record else { return }
        do {
            try await applicationStore.upsertUlcpDevicePeer(
                ownerIdentityID: record.ownerIdentityID,
                publicAddress: record.publicAddress,
                advertisedName: record.advertisedName,
                radioIdentifier: record.radioIdentifier
            )
            coordinator.synchronizedRadioPeer = record
            await reloadApplicationState()
        } catch {
            // The live radio remains usable; persistence failure must not
            // synthesize or duplicate a peer in memory.
        }
    }

    /// Reload every peer and transcript from storage.
    ///
    /// A reload reads the full message history of every conversation and
    /// decodes an identity bundle per peer, so overlapping callers (a chat
    /// batch landing while a send is committing) used to multiply that work.
    /// Callers arriving before a queued reload has begun join it instead of
    /// adding another; a caller arriving mid-reload gets a fresh one chained
    /// behind it. Either way `await` still returns only once state observed
    /// after the call has been published, which senders rely on.
    private func reloadApplicationState() async {
        if let pending = coordinator.pendingReload {
            await pending.value
            return
        }
        let running = coordinator.runningReload
        let task = Task { @MainActor in
            await running?.value
            coordinator.pendingReload = nil
            await performApplicationStateReload()
        }
        coordinator.pendingReload = task
        coordinator.runningReload = task
        await task.value
    }

    private func performApplicationStateReload() async {
        guard let applicationStore, let localIdentity else { return }
        do {
            let storedPeers = try await applicationStore.listNodes(ownerIdentityID: localIdentity.id)
            var mappedPeers: [Int64: PeerSummary] = [:]
            for stored in storedPeers {
                guard let identity = try? await meshEngine.inspectPublicIdentity(stored.publicAddress) else {
                    continue
                }
                let advertisedIdentity: MeshNodeIdentity? = await {
                    guard let payload = stored.advertisement else { return nil }
                    return try? await meshEngine.decodeNodeIdentity(
                        address: stored.publicAddress,
                        payload: payload
                    )
                }()
                mappedPeers[stored.id] = PeerSummary(
                    id: stored.id,
                    identity: identity,
                    alias: stored.alias,
                    advertisedName: stored.advertisedName,
                    systemRole: stored.systemRole,
                    storedRole: stored.nodeKind.flatMap(PeerRole.init(rawValue:)) ?? .unknown,
                    advertisedIdentity: advertisedIdentity,
                    advertisedIdentityAuthenticated: stored.advertisementAuthenticated,
                    lastHeard: stored.lastHeardAt,
                    isSaved: stored.isSaved,
                    isFavorite: stored.isFavorite,
                    isOnDeviceIdentity: stored.onDeviceIdentity
                )
            }
            let storedConversations = try await applicationStore.listDirectConversations(
                ownerIdentityID: localIdentity.id
            )
            // Assign only on a real change: most reloads are triggered by
            // radio or chat activity that leaves the displayed state
            // identical, and an equal-value `@State` write still invalidates
            // every view below the root.
            let mappedPeerList = storedPeers.compactMap { mappedPeers[$0.id] }
            if peers != mappedPeerList {
                peers = mappedPeerList
            }
            var mappedConversations: [DirectConversationSummary] = []
            for stored in storedConversations {
                guard let peer = mappedPeers[stored.node.id] else { continue }
                let messages = (try? await applicationStore.chatMessages(
                    ownerIdentityID: localIdentity.id,
                    peerAddress: peer.identity.canonicalAddress
                )) ?? []
                mappedConversations.append(
                    DirectConversationSummary(
                        id: stored.id,
                        peer: peer,
                        draftText: stored.draftText,
                        messages: messages.map {
                            ChatMessageSummary(
                                id: $0.id,
                                body: $0.body,
                                isOutbound: $0.outbound,
                                deliveryState: $0.deliveryState,
                                isDeleted: $0.isDeleted,
                                isEdited: $0.isEdited,
                                sessionID: $0.sessionID,
                                handle: $0.handle,
                                wireID: $0.wireID,
                                epoch: $0.epoch,
                                isGapPlaceholder: $0.isGapPlaceholder,
                                isUnavailable: $0.isUnavailable,
                                isReceivedLate: $0.receivedLate,
                                isDeliveredLate: $0.deliveredLate,
                                originalBody: $0.originalBody,
                                createdAtMilliseconds: $0.createdAtMilliseconds
                            )
                        }
                    )
                )
            }
            if conversations != mappedConversations {
                conversations = mappedConversations
            }
        } catch {
            if !peers.isEmpty { peers = [] }
            if !conversations.isEmpty { conversations = [] }
        }
    }
}

/// Mutable, non-visual bookkeeping for `AppRootView`. Held by reference so
/// updating it never invalidates the view graph.
@MainActor
private final class AppStateCoordinator {
    var synchronizedRadioPeer: SynchronizedRadioPeer?
    /// The device-identity peer list last written into the store's cache
    /// flags, so the steady snapshot stream reconciles only on real change.
    var lastReconciledDevicePeers: [String]?
    /// A reload that has been queued but has not begun reading storage yet;
    /// later callers can safely join it.
    var pendingReload: Task<Void, Never>?
    /// The most recently queued reload, joined or not. New reloads chain
    /// behind it so two never read and publish state concurrently.
    var runningReload: Task<Void, Never>?
}

/// The subset of a radio snapshot that reaches persistent storage.
private struct SynchronizedRadioPeer: Equatable {
    let ownerIdentityID: String
    let publicAddress: String
    let advertisedName: String?
    let radioIdentifier: String
}

private enum AppTab: Hashable {
    case conversations
    case network
    case settings
}

private extension View {
    func appRadioToolbar(
        _ snapshot: RadioSnapshot,
        action: @escaping () -> Void
    ) -> some View {
        toolbar {
            ToolbarItem(placement: .principal) {
                RadioToolbarItem(snapshot: snapshot, action: action)
            }
        }
        .safeAreaInset(edge: .top, spacing: 0) {
            if snapshot.problemDescription != nil {
                RadioProblemBanner(snapshot: snapshot, action: action)
            }
        }
    }
}

#Preview {
    AppRootView(radioConnection: FakeRadioConnection())
}
