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

    private let meshEngine: RustMeshEngine
    private let identityVault: KeychainIdentityVault
    private let applicationStore = try? SQLiteApplicationStore.applicationStore()
    private let radioConnection: any RadioConnection
    private let notificationService = ChatNotificationService()

    init(radioConnection: any RadioConnection = CoreBluetoothRadioConnection()) {
        let meshEngine = RustMeshEngine()
        self.meshEngine = meshEngine
        identityVault = KeychainIdentityVault(meshEngine: meshEngine)
        self.radioConnection = radioConnection
    }

    var body: some View {
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
                    updateAlias: updateAlias,
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
                    savePeer: { preview, details in
                        _ = await savePeer(preview, details: details, startConversation: false)
                    },
                    startConversation: startConversation,
                    updateDraft: updateDraft,
                    sendMessage: sendMessage,
                    messageActions: ChatMessageActions(edit: editMessage, delete: deleteMessage),
                    pingPeer: pingPeer,
                    updateAlias: updateAlias
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
                    stopDiscovery: stopRadioDiscovery
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
                    stopDiscovery: stopRadioDiscovery
                )
            }
        }
        .task {
            await loadIdentity()
        }
        .task {
            for await snapshot in await radioConnection.snapshots() {
                radioSnapshot = snapshot
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

    /// Persist an over-the-air advertisement. A broadcast frame is
    /// unauthenticated at the MAC layer, so only bundles whose embedded
    /// signature verifies against the claimed sender key are stored;
    /// anything else could be spoofed by any nearby transmitter.
    @MainActor
    private func applyReceivedAdvertisement(_ advertisement: RadioAdvertisementEvent) async {
        guard let applicationStore, let localIdentity else { return }
        guard let identity = try? await meshEngine.decodeNodeIdentity(
            address: advertisement.peerAddress,
            payload: advertisement.payload
        ), identity.signature == .valid else { return }
        do {
            try await applicationStore.upsertPeer(
                ownerIdentityID: localIdentity.id,
                publicAddress: advertisement.peerAddress,
                alias: nil,
                advertisedName: identity.name,
                isContact: false,
                advertisement: advertisement.payload
            )
            await reloadApplicationState()
        } catch {
            Self.logger.error("Failed to persist received advertisement")
        }
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
                isContact: details.isContact,
                nodeKind: details.kind.rawValue,
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
                return .reply(
                    PeerPingReply(
                        roundTripMilliseconds: reply.roundTripMilliseconds,
                        hopCount: reply.hopCount,
                        routeHints: reply.routeHints,
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
            let addresses = Set(
                peers.map(\.identity.canonicalAddress)
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
            try await radioConnection.acknowledgeChatBatch(update.batchID)
            if !update.mutations.isEmpty || !update.deliveries.isEmpty {
                await reloadApplicationState()
            }
            postNotifications(for: update.mutations)
        } catch {
            // Effects remain idempotent and can safely be applied again if
            // the Rust facade re-emits them.
            Self.logger.error(
                "Could not apply chat update batch \(update.batchID, privacy: .public): \(String(describing: error), privacy: .public)"
            )
        }
    }

    /// Notify for newly inserted, complete inbound messages — never for
    /// local echoes, delivery-state changes, edits, or deletions. Runs only
    /// after the batch reached durable storage; the willPresent delegate
    /// suppresses the banner when that conversation is visible in the
    /// foreground. A batch redelivered after a failed acknowledgement can
    /// repeat a banner; that is the accepted worst case.
    @MainActor
    private func postNotifications(for mutations: [MobileChatMutationRecord]) {
        for mutation in mutations {
            guard mutation.kind == .insert,
                  mutation.direction == .inbound,
                  mutation.complete != false,
                  let peerAddress = mutation.peerAddress,
                  let body = mutation.body,
                  !body.isEmpty
            else { continue }
            let displayName = peers.first {
                $0.identity.canonicalAddress == peerAddress
            }?.displayName ?? String(peerAddress.prefix(10))
            notificationService.postInboundMessage(
                peerAddress: peerAddress,
                displayName: displayName,
                body: body
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
        else { return }
        do {
            try await applicationStore.upsertCompanionRadioPeer(
                ownerIdentityID: localIdentity.id,
                publicAddress: radioIdentity.canonicalAddress,
                advertisedName: snapshot.name,
                radioIdentifier: identifier.uuidString
            )
            await reloadApplicationState()
        } catch {
            // The live radio remains usable; persistence failure must not
            // synthesize or duplicate a peer in memory.
        }
    }

    private func reloadApplicationState() async {
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
                    isContact: stored.isContact,
                    systemRole: stored.systemRole,
                    kind: stored.nodeKind.flatMap(PeerKind.init(rawValue:)) ?? .unknown,
                    advertisedIdentity: advertisedIdentity
                )
            }
            let storedConversations = try await applicationStore.listDirectConversations(
                ownerIdentityID: localIdentity.id
            )
            peers = storedPeers.compactMap { mappedPeers[$0.id] }
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
                                epoch: $0.epoch
                            )
                        }
                    )
                )
            }
            conversations = mappedConversations
        } catch {
            peers = []
            conversations = []
        }
    }
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
                CompanionToolbarItem(snapshot: snapshot, action: action)
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
