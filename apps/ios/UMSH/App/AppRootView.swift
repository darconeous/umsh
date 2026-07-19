import SwiftUI

@MainActor
struct AppRootView: View {
    @State private var selectedTab: AppTab = .conversations
    @State private var radioSnapshot = RadioSnapshot.idle
    @State private var showsRadioDetail = false
    @State private var localIdentity: LocalIdentitySnapshot?
    @State private var identityError: IdentityVaultError?
    @State private var isLoadingIdentity = true
    @State private var peers: [PeerSummary] = []
    @State private var conversations: [DirectConversationSummary] = []

    private let identityVault = KeychainIdentityVault(meshEngine: RustMeshEngine())
    private let peerMeshEngine = RustMeshEngine()
    private let applicationStore = try? SQLiteApplicationStore.applicationStore()
    private let radioConnection: any RadioConnection

    init(radioConnection: any RadioConnection = CoreBluetoothRadioConnection()) {
        self.radioConnection = radioConnection
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            NavigationStack {
                ConversationsView(
                    conversations: conversations,
                    radioSnapshot: radioSnapshot,
                    inspectNodeURI: inspectNodeURI,
                    savePeer: savePeer,
                    updateDraft: updateDraft
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
                NetworkView(radioSnapshot: $radioSnapshot, peers: peers)
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
                    radioSnapshot: $radioSnapshot,
                    connectRadio: connectRadio,
                    claimRadio: claimRadio,
                    disconnectRadio: disconnectRadio
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
        .sheet(isPresented: $showsRadioDetail) {
            NavigationStack {
                RadioDetailView(
                    snapshot: $radioSnapshot,
                    connect: connectRadio,
                    claim: claimRadio,
                    disconnect: disconnectRadio
                )
            }
        }
        .task {
            await loadIdentity()
        }
        .task {
            for await snapshot in await radioConnection.snapshots() {
                radioSnapshot = snapshot
                await synchronizeRadioPeer(from: snapshot)
            }
        }
    }

    @MainActor
    private func loadIdentity() async {
        isLoadingIdentity = true
        defer { isLoadingIdentity = false }
        do {
            localIdentity = try await identityVault.loadIdentity()
            try await radioConnection.useHostIdentity(localIdentity?.publicIdentity)
            await prepareApplicationState()
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
            await prepareApplicationState()
            identityError = nil
        } catch let error as IdentityVaultError {
            identityError = error
        } catch {
            identityError = .keychainFailure
        }
    }

    private func connectRadio() async {
        do {
            try await radioConnection.connect()
        } catch {
            // Connection failures are published as radio snapshots so every
            // screen presents the same state and recovery action.
        }
    }

    private func disconnectRadio() async {
        await radioConnection.disconnect()
    }

    private func claimRadio() async {
        do {
            try await radioConnection.claimForCurrentIdentity()
        } catch {
            // The adapter publishes a shared failure snapshot when an active
            // claim fails. Preconditions leave the existing snapshot intact.
        }
    }

    private func inspectNodeURI(_ uri: String) async -> Result<MeshNodeURIPreview, MeshEngineError> {
        do {
            return .success(try await peerMeshEngine.inspectNodeURI(uri))
        } catch let error as MeshEngineError {
            return .failure(error)
        } catch {
            return .failure(.coreFailure)
        }
    }

    private func savePeer(
        _ identity: MeshPublicIdentity,
        startConversation: Bool
    ) async -> DirectConversationSummary? {
        guard let applicationStore, let localIdentity else { return nil }
        do {
            try await applicationStore.upsertPeer(
                ownerIdentityID: localIdentity.id,
                publicAddress: identity.canonicalAddress,
                alias: nil,
                isContact: !startConversation
            )
            if startConversation {
                _ = try await applicationStore.ensureDirectConversation(
                    ownerIdentityID: localIdentity.id,
                    peerAddress: identity.canonicalAddress
                )
            }
            await reloadApplicationState()
            return conversations.first { $0.peer.identity.canonicalAddress == identity.canonicalAddress }
        } catch {
            return nil
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
                guard let identity = try? await peerMeshEngine.inspectPublicIdentity(stored.publicAddress) else {
                    continue
                }
                mappedPeers[stored.id] = PeerSummary(
                    id: stored.id,
                    identity: identity,
                    alias: stored.alias,
                    advertisedName: stored.advertisedName,
                    isContact: stored.isContact,
                    systemRole: stored.systemRole
                )
            }
            let storedConversations = try await applicationStore.listDirectConversations(
                ownerIdentityID: localIdentity.id
            )
            peers = storedPeers.compactMap { mappedPeers[$0.id] }
            conversations = storedConversations.compactMap { stored in
                guard let peer = mappedPeers[stored.node.id] else { return nil }
                return DirectConversationSummary(
                    id: stored.id,
                    peer: peer,
                    draftText: stored.draftText
                )
            }
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
