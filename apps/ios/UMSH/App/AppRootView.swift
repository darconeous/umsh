import SwiftUI

/// The app's interface: tabs, sheets, and navigation over a running
/// ``AppRuntime``.
///
/// Everything with a lifetime longer than a screen — the store, the identity,
/// the mesh session, the radio streams — belongs to the runtime, which the
/// app delegate owns and starts at launch. This view reads it, hands its
/// operations to the feature views as the closure bundles they already take,
/// and holds only what is genuinely about what is on screen right now.
@MainActor
struct AppRootView: View {
    /// The pipeline this interface shows. `@Bindable` so the child views
    /// that mutate a summary in place still get the Bindings they take.
    @Bindable var runtime: AppRuntime

    @State private var selectedTab: AppTab = .conversations
    @State private var showsRadioDetail = false
    @State private var showsDiscovery = false
    /// Where the Discover sheet's next ask is aimed. Held here because the
    /// sheet lives here, and because a peer page deep-linking into an already
    /// open sheet has to be able to re-aim it.
    @State private var discoveryVantage: SolicitVantage?
    @State private var openedConversation: DirectConversationSummary?
    @State private var openedChannelConversation: ChannelConversationSummary?
    @State private var incomingPeerImport: IncomingPeerImport?
    @State private var pendingPeerImport: PendingPeerImport?
    @State private var incomingChannelImport: IncomingChannelImport?
    /// Read here as well as in the runtime: this is the control the Settings
    /// screen binds to, while the runtime is what acts on it.
    @AppStorage("phone.discoverable") private var phoneDiscoverable = true

    private var notificationService: ChatNotificationService { .shared }

    /// The runtime's channel operations with the one navigating action
    /// filled in, since where a channel's conversation opens is this view's
    /// business rather than the pipeline's.
    private var channelManagementActions: ChannelActions {
        runtime.channelActions { conversation in
            openedChannelConversation = conversation
            selectedTab = .conversations
        }
    }

    var body: some View {
        if let applicationStoreError = runtime.applicationStoreError {
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

    /// Whether launch bootstrap has yet to finish. It ends only once the
    /// identity is unlocked, the mesh session is installed, and the first
    /// store read has published — so a list that is empty while this holds
    /// has not been read yet, rather than having nothing in it.
    private var isBootstrapping: Bool { runtime.isLoadingIdentity }

    private var mainInterface: some View {
        TabView(selection: $selectedTab) {
            NavigationStack {
                ConversationsView(
                    items: runtime.conversationItems,
                    conversations: $runtime.conversations,
                    channels: runtime.channels,
                    peers: runtime.peers,
                    radioSnapshot: runtime.radioSnapshot,
                    isLoading: isBootstrapping,
                    inspectPeerIdentity: runtime.inspectPeerIdentity,
                    savePeer: runtime.savePeer,
                    updateDraft: runtime.updateDraft,
                    updateChannelDraft: runtime.updateChannelDraft,
                    sendMessage: runtime.sendMessage,
                    messageActions: ChatMessageActions(
                        edit: runtime.editMessage,
                        delete: runtime.deleteMessage,
                        react: runtime.reactToMessage,
                        clearMessages: runtime.clearConversationMessages,
                        countMessages: runtime.countConversationMessages
                    ),
                    deleteConversation: runtime.deleteConversation,
                    peerActions: runtime.peerActions,
                    channelActions: ChannelConversationActions(
                        start: runtime.startChannelConversation,
                        startAfterJoin: runtime.startConversationAfterJoin,
                        delete: runtime.deleteChannelConversation,
                        requestMemberIdentity: runtime.requestMemberIdentity,
                        setNotifications: runtime.setChannelNotifications
                    ),
                    channelManagementActions: channelManagementActions,
                    markRead: runtime.markConversationRead,
                    openedConversation: $openedConversation,
                    openedChannelConversation: $openedChannelConversation
                )
                    .appRadioToolbar(runtime.radioSnapshot) {
                        showsRadioDetail = true
                    }
            }
            .tabItem {
                Label("Conversations", systemImage: "bubble.left.and.bubble.right")
            }
            .tag(AppTab.conversations)

            NavigationStack {
                PeersView(
                    radioSnapshot: $runtime.radioSnapshot,
                    conversations: $runtime.conversations,
                    peers: runtime.peers,
                    isLoading: isBootstrapping,
                    inspectPeerIdentity: runtime.inspectPeerIdentity,
                    savePeer: { preview, details, startConversation in
                        await runtime.savePeer(preview, details: details, startConversation: startConversation)
                    },
                    openConversation: { conversation in
                        selectedTab = .conversations
                        openedConversation = conversation
                    },
                    peerActions: runtime.peerActions,
                    updateDraft: runtime.updateDraft,
                    sendMessage: { conversation, body in
                        await runtime.sendMessage(.direct(conversation), body)
                    },
                    messageActions: ChatMessageActions(
                        edit: runtime.editMessage,
                        delete: runtime.deleteMessage,
                        react: runtime.reactToMessage,
                        clearMessages: runtime.clearConversationMessages,
                        countMessages: runtime.countConversationMessages
                    ),
                    discoverPeers: { openDiscovery(nil) }
                )
                    .appRadioToolbar(runtime.radioSnapshot) {
                        showsRadioDetail = true
                    }
            }
            .tabItem {
                Label("Peers", systemImage: "point.3.connected.trianglepath.dotted")
            }
            .tag(AppTab.peers)

            NavigationStack {
                NodeMapView(
                    radioSnapshot: $runtime.radioSnapshot,
                    conversations: $runtime.conversations,
                    peers: runtime.peers,
                    isLoading: isBootstrapping,
                    peerActions: runtime.peerActions,
                    updateDraft: runtime.updateDraft,
                    sendMessage: { conversation, body in
                        await runtime.sendMessage(.direct(conversation), body)
                    },
                    messageActions: ChatMessageActions(
                        edit: runtime.editMessage,
                        delete: runtime.deleteMessage,
                        react: runtime.reactToMessage,
                        clearMessages: runtime.clearConversationMessages,
                        countMessages: runtime.countConversationMessages
                    ),
                    openPeersList: { selectedTab = .peers },
                    openConversation: { conversation in
                        selectedTab = .conversations
                        openedConversation = conversation
                    },
                    discoverPeers: { openDiscovery(nil) },
                    refreshPosition: runtime.refreshRadioPosition
                )
                    .appRadioToolbar(runtime.radioSnapshot) {
                        showsRadioDetail = true
                    }
            }
            .tabItem {
                Label("Map", systemImage: "map")
            }
            .tag(AppTab.map)

            NavigationStack {
                SettingsView(
                    identity: runtime.localIdentity,
                    identityError: runtime.identityError,
                    isLoadingIdentity: runtime.isLoadingIdentity,
                    createIdentity: runtime.createIdentity,
                    advertisedName: runtime.advertisedName,
                    saveAdvertisedName: runtime.saveAdvertisedName,
                    advertiseIdentity: runtime.advertiseIdentity,
                    identityShareURI: runtime.identityShareURI,
                    phoneDiscoverable: phoneDiscoverable,
                    setPhoneDiscoverable: { enabled in
                        phoneDiscoverable = enabled
                        await runtime.pushPhoneDiscoverability()
                    },
                    radioSnapshot: $runtime.radioSnapshot,
                    connectRadio: runtime.connectRadio,
                    reconnectRadio: runtime.reconnectRadio,
                    claimRadio: runtime.claimRadio,
                    refreshRadio: runtime.refreshRadio,
                    disconnectRadio: runtime.disconnectRadio,
                    forgetRadio: runtime.forgetRadio,
                    factoryResetRadio: runtime.factoryResetRadio,
                    discoverRadios: runtime.discoverRadios,
                    selectRadio: runtime.selectRadio,
                    stopDiscovery: runtime.stopRadioDiscovery,
                    saveDevicePeer: runtime.saveAdministeredDevice,
                    isPeerSaved: { address in
                        runtime.peers.contains { $0.identity.canonicalAddress == address }
                    },
                    peerActions: runtime.peerActions,
                    conversations: $runtime.conversations,
                    updateDraft: runtime.updateDraft,
                    sendMessage: { conversation, body in
                        await runtime.sendMessage(.direct(conversation), body)
                    },
                    messageActions: ChatMessageActions(
                        edit: runtime.editMessage,
                        delete: runtime.deleteMessage,
                        react: runtime.reactToMessage,
                        clearMessages: runtime.clearConversationMessages,
                        countMessages: runtime.countConversationMessages
                    ),
                    channels: runtime.channels,
                    unknownDeviceChannels: runtime.unknownDeviceChannels,
                    channelActions: channelManagementActions,
                    seedMessages: runtime.seedGeneratedMessages,
                    stagedPeerSendsMessage: runtime.stagedPeerSendsMessage,
                    stagedPeerReacts: runtime.stagedPeerReacts,
                    stagedDropTransmissions: runtime.stagedDropTransmissions
                )
                    .appRadioToolbar(runtime.radioSnapshot) {
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
            let uri = url.absoluteString
            // `cs:` and `ck:` are channels; everything else stays on the peer
            // path, which also handles bare addresses and unknown forms.
            let isChannel = ["umsh:cs:", "umsh:ck:"].contains {
                uri.lowercased().hasPrefix($0)
            }
            if isChannel {
                incomingChannelImport = IncomingChannelImport(uri: uri)
                selectedTab = .settings
            } else {
                incomingPeerImport = IncomingPeerImport(uri: uri)
            }
        }
        .sheet(item: $incomingChannelImport) { item in
            NavigationStack {
                ChannelJoinView(actions: channelManagementActions, initialInput: item.uri)
            }
        }
        .sheet(item: $incomingPeerImport, onDismiss: completePendingPeerImport) { item in
            NavigationStack {
                NodeImportView(
                    inspectPeerIdentity: runtime.inspectPeerIdentity,
                    save: { preview, details, startConversation in
                        // Held until onDismiss: see PendingPeerImport.
                        pendingPeerImport = PendingPeerImport(
                            preview: preview,
                            details: details,
                            startConversation: startConversation
                        )
                        incomingPeerImport = nil
                    },
                    initialInput: item.uri
                )
            }
        }
        .sheet(isPresented: $showsRadioDetail) {
            NavigationStack {
                RadioDetailView(
                    snapshot: $runtime.radioSnapshot,
                    connect: runtime.connectRadio,
                    reconnect: runtime.reconnectRadio,
                    claim: runtime.claimRadio,
                    refresh: runtime.refreshRadio,
                    disconnect: runtime.disconnectRadio,
                    forget: runtime.forgetRadio,
                    factoryReset: runtime.factoryResetRadio,
                    discoverRadios: runtime.discoverRadios,
                    selectRadio: runtime.selectRadio,
                    stopDiscovery: runtime.stopRadioDiscovery,
                    peerActions: runtime.peerActions,
                    conversations: $runtime.conversations,
                    updateDraft: runtime.updateDraft,
                    sendMessage: { conversation, body in
                        await runtime.sendMessage(.direct(conversation), body)
                    },
                    messageActions: ChatMessageActions(
                        edit: runtime.editMessage,
                        delete: runtime.deleteMessage,
                        react: runtime.reactToMessage,
                        clearMessages: runtime.clearConversationMessages,
                        countMessages: runtime.countConversationMessages
                    )
                )
            }
        }
        // Presented here rather than in Peers and Map, which each had their
        // own copy: a peer page deep-linking into it has to reach one sheet,
        // not whichever tab happened to open it.
        .sheet(isPresented: $showsDiscovery) {
            DiscoverPeersView(
                radioSnapshot: $runtime.radioSnapshot,
                conversations: $runtime.conversations,
                peers: runtime.peers,
                peerActions: runtime.peerActions,
                updateDraft: runtime.updateDraft,
                sendMessage: { conversation, body in
                    await runtime.sendMessage(.direct(conversation), body)
                },
                messageActions: ChatMessageActions(
                    edit: runtime.editMessage,
                    delete: runtime.deleteMessage,
                    react: runtime.reactToMessage,
                    clearMessages: runtime.clearConversationMessages,
                    countMessages: runtime.countConversationMessages
                ),
                advertiseIdentity: runtime.advertiseIdentity,
                advertisedName: runtime.advertisedName,
                clearDiscoveredNodes: runtime.clearDiscoveredNodes,
                solicitNearbyIdentities: runtime.solicitNearbyIdentities,
                vantage: $discoveryVantage,
                openConversation: { conversation in
                    showsDiscovery = false
                    selectedTab = .conversations
                    openedConversation = conversation
                }
            )
        }
        .fullScreenCover(isPresented: $runtime.shouldPresentOnboarding) {
            if let localIdentity = runtime.localIdentity {
                OnboardingView(
                    identity: localIdentity,
                    advertisedName: runtime.advertisedName,
                    saveAdvertisedName: runtime.saveAdvertisedName,
                    discoverRadios: runtime.discoverRadios,
                    selectRadio: runtime.selectRadio,
                    stopDiscovery: runtime.stopRadioDiscovery,
                    finish: { runtime.completeOnboarding() }
                )
            }
        }
        // The only stream this view consumes itself: a notification tap is
        // navigation, and navigation is the one thing the runtime has no
        // business doing. Everything else the pipeline listens to is
        // subscribed by the runtime, which outlives this view and every
        // scene it belongs to.
        .task {
            for await address in notificationService.conversationOpens() {
                await openConversationFromNotification(conversationAddress: address)
            }
        }
        // Every path into a transcript gets the same reader — the
        // conversations list, a peer's profile, a notification tap — without
        // each one carrying it as a parameter.
        .environment(\.transcriptLoader, runtime.transcriptLoader)
        .environment(
            \.visibleConversationReporter,
            VisibleConversationReporter(
                appeared: { [notificationService] address in
                    notificationService.setVisibleConversation(conversationAddress: address)
                },
                disappeared: { [notificationService] address in
                    notificationService.clearVisibleConversation(ifMatching: address)
                }
            )
        )
        // Any region editor below this — the setup sheet, the remote
        // repeater screen — can ask what covers a place, and read where
        // this phone is to ask about. Both are seams rather than data: the
        // database answers, and nothing it is asked about is stored.
        .environment(\.regionService, runtime.regionService)
        .environment(\.readPhonePosition) { await runtime.locationService.readOnce() }
        // A composer with no radio behind it offers the way to attach one, and
        // the sheet that does it lives here.
        .environment(\.openRadioDetail) { showsRadioDetail = true }
        // Any peer page below this — in Peers, on the Map, in a transcript's
        // info view — can aim discovery at the node it is showing. The
        // Discover sheet overrides this for its own subtree, so a peer page
        // reached from inside it re-aims that sheet instead.
        .environment(\.askNearbyIdentities, openDiscovery)
    }

    /// Run the import the incoming-URI sheet accepted, now that its
    /// dismissal has revealed whichever list the new row animates into.
    @MainActor
    private func completePendingPeerImport() {
        guard let pending = pendingPeerImport else { return }
        pendingPeerImport = nil
        Task {
            let conversation = await runtime.savePeer(
                pending.preview,
                details: pending.details,
                startConversation: pending.startConversation
            )
            if pending.startConversation, let conversation {
                selectedTab = .conversations
                openedConversation = conversation
            }
        }
    }

    /// Open Discover Peers with its ask aimed at `vantage` — nil for this
    /// phone's own neighborhood.
    @MainActor
    private func openDiscovery(_ vantage: SolicitVantage?) {
        discoveryVantage = vantage
        showsDiscovery = true
    }

    @MainActor
    private func openConversationFromNotification(conversationAddress: String) async {
        selectedTab = .conversations
        if AppRuntime.isChannelAddress(conversationAddress) {
            if runtime.channelConversations.first(where: {
                $0.conversationAddress == conversationAddress
            }) == nil {
                await runtime.reloadApplicationState()
            }
            openedChannelConversation = runtime.channelConversations.first {
                $0.conversationAddress == conversationAddress
            }
            return
        }
        if runtime.conversations.first(where: {
            $0.peer.identity.canonicalAddress == conversationAddress
        }) == nil {
            await runtime.reloadApplicationState()
        }
        guard let conversation = runtime.conversations.first(where: {
            $0.peer.identity.canonicalAddress == conversationAddress
        }) else { return }
        openedConversation = conversation
    }

    private struct IncomingPeerImport: Identifiable {
        let id = UUID()
        let uri: String
    }

    private struct IncomingChannelImport: Identifiable {
        let id = UUID()
        let uri: String
    }
}

private enum AppTab: Hashable {
    case conversations
    case peers
    case map
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
            // Animated inside the inset, over the banner alone: an
            // `.animation` on the outside would reach the whole tab tree and
            // animate whatever else changed in the same update.
            //
            // Keyed on whether there is a problem at all, not on the snapshot:
            // snapshots republish many times a second while the link is busy,
            // and the banner's text changing under a steady problem is not an
            // arrival.
            Group {
                if snapshot.problemDescription != nil {
                    RadioProblemBanner(snapshot: snapshot, action: action)
                        .transition(.move(edge: .top).combined(with: .opacity))
                }
            }
            .animation(UMSHAnimation.accessory, value: snapshot.problemDescription != nil)
        }
    }
}

#Preview {
    // Unstarted on purpose: a preview wants the interface, not a bootstrap
    // that opens the real store and asks the Keychain for an identity.
    AppRootView(runtime: AppRuntime(radioConnection: FakeRadioConnection()))
}
