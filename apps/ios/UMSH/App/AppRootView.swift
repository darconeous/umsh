import CoreLocation
import CryptoKit
import SwiftUI
import OSLog
import UIKit
import UMSHMobileCore

@MainActor
struct AppRootView: View {
    private static let logger = Logger(subsystem: "com.umsh.ios", category: "AppRoot")
    /// Chat has its own category because it is the part with a queue in it:
    /// composing, transmitting and applying happen on separate schedules, so
    /// a stuck message is only diagnosable from the sequence.
    private static let chatLogger = Logger(subsystem: "com.umsh.ios", category: "Chat")
    /// How many times to retry a chat batch before dropping it. Three attempts
    /// over the redelivery pump's two-second period is long enough to ride out
    /// a busy moment and short enough that a wedged session recovers while the
    /// user is still looking at it.
    private static let chatBatchAttemptLimit = 3
    @Environment(\.scenePhase) private var scenePhase
    @State private var selectedTab: AppTab = .conversations
    @State private var radioSnapshot = RadioSnapshot.idle
    @State private var showsRadioDetail = false
    @State private var localIdentity: LocalIdentitySnapshot?
    @State private var identityError: IdentityVaultError?
    @State private var isLoadingIdentity = true
    @State private var peers: [PeerSummary] = []
    @State private var conversations: [DirectConversationSummary] = []
    @State private var channelConversations: [ChannelConversationSummary] = []
    @State private var channels: [ChannelSummary] = []
    /// Channels the radio's device identity holds that this phone has no key
    /// for, so they can be shown as present without being named.
    @State private var unknownDeviceChannels: [UnknownDeviceChannel] = []
    @State private var openedConversation: DirectConversationSummary?
    @State private var openedChannelConversation: ChannelConversationSummary?
    @State private var incomingPeerImport: IncomingPeerImport?
    @State private var incomingChannelImport: IncomingChannelImport?
    @State private var advertisedName = ""
    /// Whether this phone answers nearby nodes' identity requests. The
    /// preference outlives the mesh session, which starts discoverable, so
    /// it is reapplied on every session install.
    @AppStorage("phone.discoverable") private var phoneDiscoverable = true
    /// How often this phone announces itself unasked, in seconds, with 0
    /// for never. Both default to off: a radio is deployed to be part of
    /// the mesh, but a phone is carried, and putting its identity on the
    /// air on a timer is a decision rather than a default.
    @AppStorage("phone.advertIntervalSeconds") private var phoneAdvertInterval = 0
    @AppStorage("phone.beaconIntervalSeconds") private var phoneBeaconInterval = 0
    /// Whether this phone's identity carries its location, and at what
    /// cell size. Off by default for the same reason the schedules are:
    /// where a phone is, is where its owner is, and putting that on the
    /// air is a decision rather than a default.
    @AppStorage("phone.shareLocation") private var phoneSharesLocation = false
    @AppStorage("phone.locationPrecision") private var phoneLocationPrecision = 5
    /// The one CoreLocation seam; a reference in `@State`, never
    /// reassigned, like the bookkeeping below.
    @State private var locationService = PhoneLocationService()
    /// The last cell pushed into the mesh session, kept so a session
    /// reinstall — which starts with none — can resume with it rather
    /// than waiting for the phone to move.
    @State private var sharedLocation: MobileMeshSharedLocationRecord?
    /// Bookkeeping that must survive body re-evaluation without itself being
    /// a source of invalidation. A reference held in `@State` is never
    /// reassigned, so mutating it costs nothing in the view graph.
    @State private var coordinator = AppStateCoordinator()

    private let meshEngine: RustMeshEngine
    private let identityVault: KeychainIdentityVault
    private let channelKeyVault = KeychainChannelKeyVault()
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

    /// The channel operations the Channels tab is built from, assembled here
    /// for the same reason as `peerActions`.
    private var channelActions: ChannelActions {
        ChannelActions(
            preview: previewChannel,
            join: joinChannel,
            rejoin: { channel in
                await setChannelPhoneMembership(channel, joined: true)
            },
            leave: leaveChannel,
            createPrivate: createPrivateChannel,
            updateDetails: updateChannelDetails,
            setDeviceMembership: setChannelDeviceMembership,
            invitation: channelInvitation,
            revealKey: { channel in
                try? await channelKeyVault.loadKey(channelID: channel.id)
            },
            enterConversation: { channel in
                openedChannelConversation = await startChannelConversation(channel)
                selectedTab = .conversations
            },
            parseRegion: { text in try? await meshEngine.regionCode(from: text) },
            describeRegion: { code in try? await meshEngine.regionDescription(code) }
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

    /// Whether launch bootstrap has yet to finish. It ends only once the
    /// identity is unlocked, the mesh session is installed, and the first
    /// store read has published — so a list that is empty while this holds
    /// has not been read yet, rather than having nothing in it.
    private var isBootstrapping: Bool { isLoadingIdentity }

    private var mainInterface: some View {
        TabView(selection: $selectedTab) {
            NavigationStack {
                ConversationsView(
                    items: conversationItems,
                    conversations: $conversations,
                    channels: channels,
                    peers: peers,
                    radioSnapshot: radioSnapshot,
                    isLoading: isBootstrapping,
                    inspectPeerIdentity: inspectPeerIdentity,
                    savePeer: savePeer,
                    updateDraft: updateDraft,
                    updateChannelDraft: updateChannelDraft,
                    sendMessage: sendMessage,
                    messageActions: ChatMessageActions(
                        edit: editMessage,
                        delete: deleteMessage,
                        clearMessages: clearConversationMessages,
                        countMessages: countConversationMessages
                    ),
                    deleteConversation: deleteConversation,
                    peerActions: peerActions,
                    channelActions: ChannelConversationActions(
                        start: startChannelConversation,
                        startAfterJoin: startConversationAfterJoin,
                        delete: deleteChannelConversation,
                        requestMemberIdentity: requestMemberIdentity,
                        setNotifications: setChannelNotifications
                    ),
                    channelManagementActions: channelActions,
                    markRead: markConversationRead,
                    openedConversation: $openedConversation,
                    openedChannelConversation: $openedChannelConversation
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
                PeersView(
                    radioSnapshot: $radioSnapshot,
                    conversations: $conversations,
                    peers: peers,
                    isLoading: isBootstrapping,
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
                    sendMessage: { conversation, body in
                        await sendMessage(.direct(conversation), body)
                    },
                    messageActions: ChatMessageActions(
                        edit: editMessage,
                        delete: deleteMessage,
                        clearMessages: clearConversationMessages,
                        countMessages: countConversationMessages
                    ),
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
                Label("Peers", systemImage: "point.3.connected.trianglepath.dotted")
            }
            .tag(AppTab.peers)

            NavigationStack {
                NodeMapView(
                    radioSnapshot: $radioSnapshot,
                    conversations: $conversations,
                    peers: peers,
                    isLoading: isBootstrapping,
                    peerActions: peerActions,
                    updateDraft: updateDraft,
                    sendMessage: { conversation, body in
                        await sendMessage(.direct(conversation), body)
                    },
                    messageActions: ChatMessageActions(
                        edit: editMessage,
                        delete: deleteMessage,
                        clearMessages: clearConversationMessages,
                        countMessages: countConversationMessages
                    ),
                    openPeersList: { selectedTab = .peers },
                    openConversation: { conversation in
                        selectedTab = .conversations
                        openedConversation = conversation
                    },
                    advertiseIdentity: advertiseIdentity,
                    advertisedName: advertisedName,
                    clearDiscoveredNodes: clearDiscoveredNodes,
                    solicitNearbyIdentities: solicitNearbyIdentities,
                    refreshPosition: refreshRadioPosition
                )
                    .appRadioToolbar(radioSnapshot) {
                        showsRadioDetail = true
                    }
            }
            .tabItem {
                Label("Map", systemImage: "map")
            }
            .tag(AppTab.map)

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
                    sendMessage: { conversation, body in
                        await sendMessage(.direct(conversation), body)
                    },
                    messageActions: ChatMessageActions(
                        edit: editMessage,
                        delete: deleteMessage,
                        clearMessages: clearConversationMessages,
                        countMessages: countConversationMessages
                    ),
                    channels: channels,
                    unknownDeviceChannels: unknownDeviceChannels,
                    channelActions: channelActions,
                    seedMessages: seedGeneratedMessages
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
                ChannelJoinView(actions: channelActions, initialInput: item.uri)
            }
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
                    refreshPosition: refreshRadioPosition,
                    configure: configureRadio,
                    disconnect: disconnectRadio,
                    forget: forgetRadio,
                    factoryReset: factoryResetRadio,
                    setAlert: setRadioAlert,
                    setTime: setRadioTime,
                    configurePositioning: configureRadioPositioning,
                    configureAdvertising: configureRadioAdvertising,
                    discoverRadios: discoverRadios,
                    selectRadio: selectRadio,
                    stopDiscovery: stopRadioDiscovery,
                    peerActions: peerActions,
                    conversations: $conversations,
                    updateDraft: updateDraft,
                    sendMessage: { conversation, body in
                        await sendMessage(.direct(conversation), body)
                    },
                    messageActions: ChatMessageActions(
                        edit: editMessage,
                        delete: deleteMessage,
                        clearMessages: clearConversationMessages,
                        countMessages: countConversationMessages
                    )
                )
            }
        }
        .task {
            await loadIdentity()
        }
        // The identity is read once at launch, and a launch is not always a
        // moment when it can be read: iOS relaunches the app in the background
        // for a ULCP event, and before the phone's first unlock the Keychain
        // refuses the item outright. That attempt is the only one the view
        // makes, so without these the process runs to its end with no identity
        // — no mesh session, and a radio parked on a host decision the app
        // cannot make.
        .onReceive(
            NotificationCenter.default
                .publisher(for: UIApplication.protectedDataDidBecomeAvailableNotification)
                .receive(on: DispatchQueue.main)
        ) { _ in
            // Fires while still in the background: the phone being unlocked is
            // enough to finish bootstrap and attach, without waiting for the
            // user to open the app.
            Task { await retryIdentityLoadIfNeeded() }
        }
        .onChange(of: scenePhase) { _, phase in
            guard phase == .active else { return }
            Task { await retryIdentityLoadIfNeeded() }
        }
        // One task per schedule, keyed so a changed interval restarts it
        // rather than waiting out the old one. Both stop when the app
        // does, which is the honest bound: nothing here can keep the
        // phone talking to the mesh while iOS has it suspended.
        .task(id: phoneAdvertInterval) {
            await runAnnouncementSchedule(seconds: phoneAdvertInterval) {
                try await radioConnection.advertiseIdentityScheduled(
                    name: advertisedName.isEmpty ? nil : advertisedName
                )
            }
        }
        .task(id: phoneBeaconInterval) {
            await runAnnouncementSchedule(seconds: phoneBeaconInterval) {
                try await radioConnection.sendBeacon()
            }
        }
        // Keyed on one Int so either change — the toggle or the cell
        // size — restarts the readings; zero is "off", which no precision
        // can be.
        .task(id: phoneSharesLocation ? phoneLocationPrecision : 0) {
            await applyLocationSharing()
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
                await synchronizeRadioChannels(from: snapshot)
                await reconcileHostChannels()
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
            for await address in notificationService.conversationOpens {
                await openConversationFromNotification(conversationAddress: address)
            }
        }
        // Every path into a transcript gets the same reader — the conversations
        // list, a peer's profile, a notification tap — without each one
        // carrying it as a parameter.
        .environment(\.transcriptLoader, transcriptLoader)
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
        // A composer with no radio behind it offers the way to attach one, and
        // the sheet that does it lives here.
        .environment(\.openRadioDetail) { showsRadioDetail = true }
    }

    @MainActor
    private func openConversationFromNotification(conversationAddress: String) async {
        selectedTab = .conversations
        if Self.isChannelAddress(conversationAddress) {
            if channelConversations.first(where: {
                $0.conversationAddress == conversationAddress
            }) == nil {
                await reloadApplicationState()
            }
            openedChannelConversation = channelConversations.first {
                $0.conversationAddress == conversationAddress
            }
            return
        }
        if conversations.first(where: {
            $0.peer.identity.canonicalAddress == conversationAddress
        }) == nil {
            await reloadApplicationState()
        }
        guard let conversation = conversations.first(where: {
            $0.peer.identity.canonicalAddress == conversationAddress
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

    /// Re-run bootstrap after a failed identity load, once the reason for the
    /// failure may have passed.
    ///
    /// Scoped to attempts that actually failed: a phone with no identity yet
    /// reports success with none, and is waiting on onboarding rather than on
    /// anything a retry could change. `isLoadingIdentity` guards against
    /// overlapping with the launch attempt or with a retry already running —
    /// bootstrap installs the mesh session and rebuilds application state, so
    /// two at once would be two sessions.
    @MainActor
    private func retryIdentityLoadIfNeeded() async {
        guard identityError != nil, localIdentity == nil, !isLoadingIdentity else { return }
        Self.logger.notice("Retrying the identity load after an earlier failure")
        await loadIdentity()
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
        // The same name rides our group messages. A channel member may hold
        // no identity for us at all, so without it we arrive as a bare hint.
        // Unaffected by the discoverable preference: that governs answering
        // identity requests, not signing what we say.
        try? await radioConnection.setChatDisplayName(advertisedName)
        // The shared location rides the same reinstall rail: a fresh
        // session holds none, and the last accepted cell is what it
        // should resume with rather than waiting for the phone to move.
        await radioConnection.setAdvertisedLocation(sharedLocation)
    }

    /// Start or stop location readings to match the stored preference.
    ///
    /// The readings only need to be good to the disclosed cell, so the
    /// chosen precision sizes both the accuracy asked of CoreLocation and
    /// how far the phone must move before a new cell is pushed. Each
    /// reading goes to the mesh session immediately — the session holds
    /// exactly one current cell, so there is no backlog to manage — and
    /// switching off clears the session's copy rather than letting the
    /// last position linger in every later advertisement.
    private func applyLocationSharing() async {
        guard phoneSharesLocation else {
            locationService.stop()
            if sharedLocation != nil {
                sharedLocation = nil
                await radioConnection.setAdvertisedLocation(nil)
            }
            return
        }
        let precision = UInt8(clamping: phoneLocationPrecision)
        // A precision change must not wait for the phone to move: the
        // retained reading is re-disclosed at the new cell size now, or
        // the old — possibly finer — cell would stay on the air until a
        // fresh reading cleared the new distance filter.
        if var record = sharedLocation, record.precisionBytes != precision {
            record.precisionBytes = precision
            sharedLocation = record
            await radioConnection.setAdvertisedLocation(record)
        }
        let cellMeters = LocationPresentation.cellMeters(precisionBytes: precision) ?? 40
        locationService.start(
            cellMeters: cellMeters,
            onReading: { reading in
                let record = MobileMeshSharedLocationRecord(
                    latitudeDegrees: reading.coordinate.latitude,
                    longitudeDegrees: reading.coordinate.longitude,
                    precisionBytes: precision
                )
                sharedLocation = record
                Task { await radioConnection.setAdvertisedLocation(record) }
            },
            onAuthorizationLost: {
                // Access revoked in iOS Settings while sharing: readings
                // stop arriving, and the last cell must not outlive the
                // permission it was read under. A later re-grant resumes
                // readings and re-shares on its own.
                sharedLocation = nil
                Task { await radioConnection.setAdvertisedLocation(nil) }
            }
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

    /// Sleep out one interval, send, repeat, until the task is cancelled.
    ///
    /// The first send waits a full interval rather than firing at launch:
    /// an app opened and closed repeatedly would otherwise transmit on
    /// every launch, which is the one thing an interval is supposed to
    /// prevent. A failed send is skipped rather than retried — the next
    /// interval is the retry, and there is no backlog worth keeping.
    ///
    /// Each period is scattered later by up to a quarter, as on the radio,
    /// so that phones sharing a schedule do not transmit together. Only
    /// ever later: the chosen interval stays the shortest gap between two
    /// announcements. `Double.random` draws from the system generator,
    /// which is seeded from the same entropy the Keychain relies on.
    private func runAnnouncementSchedule(
        seconds: Int,
        send: @escaping () async throws -> Void
    ) async {
        guard seconds > 0 else { return }
        while !Task.isCancelled {
            let scatter = Double.random(in: 0...(Double(seconds) * announcementJitterFraction))
            do {
                try await Task.sleep(for: .seconds(Double(seconds) + scatter))
            } catch {
                return
            }
            try? await send()
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

    private func setRadioAlert(_ state: RadioAlertState) async throws {
        try await radioConnection.setAlert(state)
    }

    private func setRadioTime(_ epochSeconds: UInt32?) async throws {
        try await radioConnection.setTime(epochSeconds: epochSeconds)
    }

    private func configureRadioPositioning(
        _ gnss: UlcpGnssSettingsRecord?,
        _ timeZoneOffsetMinutes: Int16?
    ) async throws {
        try await radioConnection.configurePositioning(
            gnss: gnss,
            timeZoneOffsetMinutes: timeZoneOffsetMinutes
        )
    }

    private func configureRadioAdvertising(_ advert: UlcpAdvertSettingsRecord?) async throws {
        try await radioConnection.configureAdvertising(advert)
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

    /// Sample the radio's position, for a screen that is showing one.
    ///
    /// Failures are swallowed on purpose: this runs on a timer behind a
    /// view, and a radio that walked out of range mid-poll is a state the
    /// link already reports. An error banner per missed sample would say
    /// the same thing once a minute.
    private func refreshRadioPosition() async {
        if let refreshed = try? await radioConnection.refreshPositioning() {
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
            // Best effort, for the same reason as in `startConversation`: the
            // peer and any conversation are already on disk, and an unattached
            // radio must not turn that into a failed import.
            try? await radioConnection.registerChatPeers([identity.canonicalAddress])
            return conversations.first { $0.peer.identity.canonicalAddress == identity.canonicalAddress }
        } catch {
            return nil
        }
    }

    /// Record a device the phone has been configuring as an ordinary peer.
    ///
    /// Deliberately not a chat peer: a repeater is infrastructure the operator
    /// wants to find again, not someone to talk to. Starting a conversation
    /// with it remains an ordinary Peers action.
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

    private struct IncomingChannelImport: Identifiable {
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

    // MARK: - Channels

    /// Resolve typed input — a public channel name or a pasted `umsh:cs:` /
    /// `umsh:ck:` URI — into a preview, with whatever local context the user
    /// needs to see before committing.
    private func previewChannel(_ input: String) async -> Result<ChannelPreview, MeshEngineError> {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return .failure(.invalidChannelURI) }
        do {
            let preview = trimmed.lowercased().hasPrefix("umsh:")
                ? try await meshEngine.inspectChannelURI(trimmed)
                : try await meshEngine.inspectChannelName(trimmed)
            let digest = Self.keyDigest(preview.key)
            let existing = try await storedChannel(keyDigest: digest)
            let resolvedName = preview.displayName ?? preview.canonicalName
            // Two channels may share a name with different keys, which is
            // legitimate and worth seeing before joining.
            let conflict = channels.first { channel in
                channel.id != existing?.id
                    && resolvedName != nil
                    && channel.title.caseInsensitiveCompare(resolvedName!) == .orderedSame
            }
            return .success(
                ChannelPreview(preview: preview, existing: existing, nameConflict: conflict)
            )
        } catch let error as MeshEngineError {
            return .failure(error)
        } catch {
            return .failure(.coreFailure)
        }
    }

    /// Join on the phone identity, or update local details when the key is
    /// already held. Registering with the MAC is what actually makes traffic
    /// arrive; the radio's host table is reconciled behind it.
    private func joinChannel(
        _ preview: MeshChannelPreview,
        details: ChannelDetails
    ) async -> ChannelActionOutcome {
        guard let applicationStore, let localIdentity else { return .failed }
        let digest = Self.keyDigest(preview.key)
        do {
            if let existing = try await storedChannel(keyDigest: digest) {
                _ = await updateChannelDetails(existing, details: details)
                if !existing.joinedPhone {
                    return await setChannelPhoneMembership(existing, joined: true)
                }
                await reloadApplicationState()
                return .success
            }

            let id = UUID()
            // The key goes to the Keychain first: a row whose key cannot be
            // read is a channel that silently does nothing.
            try await channelKeyVault.storeKey(preview.key, channelID: id)
            let channel = StoredChannel(
                id: id,
                ownerIdentityID: localIdentity.id,
                kind: preview.kind == .namedPublic ? .named : .privateKey,
                canonicalName: preview.canonicalName,
                // The channel's own name comes from the invitation or what was
                // typed; the alias is this user's override on top of it.
                name: preview.displayName,
                alias: details.alias,
                channelIDHex: Self.hex(preview.channelID),
                tint: preview.tint,
                regionCode: details.regionCode ?? preview.regionCode,
                maxFloodHops: details.maxFloodHops ?? preview.maxFloodHops.map(Int.init),
                joinedPhone: true,
                joinedDevice: false,
                notificationsEnabled: details.notificationsEnabled,
                joinedAt: Date()
            )
            do {
                try await applicationStore.insertChannel(channel, keyDigest: digest)
            } catch {
                try? await channelKeyVault.deleteKey(channelID: id)
                throw error
            }
            let registered = await registerChannelKeys([preview.key])
            guard registered else {
                try? await applicationStore.deleteChannel(id: id)
                try? await channelKeyVault.deleteKey(channelID: id)
                return .phoneFull
            }
            // Derived here, from the key in hand, because the address map is
            // otherwise only rebuilt at session start — without this entry,
            // "Enter Conversation" and inbound traffic cannot find the
            // channel until the app relaunches.
            if let address = try? await meshEngine.channelConversationAddress(key: preview.key) {
                coordinator.channelAddresses[id] = address
            }
            await reloadApplicationState()
            await reconcileHostChannels()
            return .success
        } catch {
            return .failed
        }
    }

    /// Create a private channel from a freshly generated key.
    private func createPrivateChannel(
        name: String,
        details: ChannelDetails
    ) async -> ChannelActionOutcome {
        let key = await meshEngine.generateChannelKey()
        guard let channelID = try? await meshEngine.deriveChannelID(key: key),
              let tint = try? await meshEngine.deriveChannelTint(key: key)
        else {
            return .failed
        }
        return await joinChannel(
            MeshChannelPreview(
                kind: .privateKey,
                canonicalName: nil,
                key: key,
                channelID: channelID,
                tint: tint,
                displayName: name,
                maxFloodHops: details.maxFloodHops.map(UInt8.init),
                regionCode: details.regionCode
            ),
            details: details
        )
    }

    /// Leave on the phone identity. A private channel's key cannot be
    /// recovered afterwards, so its row and key are deleted together; a named
    /// or built-in channel keeps its row so it can be offered again.
    private func leaveChannel(_ channel: ChannelSummary) async -> ChannelActionOutcome {
        guard let applicationStore, let localIdentity else { return .failed }
        let key = try? await channelKeyVault.loadKey(channelID: channel.id)
        if let key {
            try? await radioConnection.removeChannels([key])
        }
        // The group chat cannot outlive membership: without the key there is
        // nothing to send with, and nothing further will arrive.
        if let conversation = channelConversations.first(where: { $0.channel.id == channel.id }) {
            try? await applicationStore.deleteChannelConversation(
                ownerIdentityID: localIdentity.id,
                conversationID: conversation.id
            )
        }
        coordinator.channelAddresses[channel.id] = nil
        do {
            if channel.kind == .builtin {
                try await applicationStore.setChannelMembership(
                    id: channel.id,
                    joinedPhone: false,
                    joinedDevice: channel.joinedDevice
                )
            } else if channel.joinedDevice {
                // Still joined on the device: keep the row and the key, since
                // removing it from the device later needs the key as selector.
                try await applicationStore.setChannelMembership(
                    id: channel.id,
                    joinedPhone: false,
                    joinedDevice: true
                )
            } else {
                try await applicationStore.deleteChannel(id: channel.id)
                try? await channelKeyVault.deleteKey(channelID: channel.id)
            }
            await reloadApplicationState()
            await reconcileHostChannels()
            return .success
        } catch {
            return .failed
        }
    }

    private func setChannelPhoneMembership(
        _ channel: ChannelSummary,
        joined: Bool
    ) async -> ChannelActionOutcome {
        guard let applicationStore,
              let key = try? await channelKeyVault.loadKey(channelID: channel.id)
        else { return .failed }
        if joined {
            guard await registerChannelKeys([key]) else { return .phoneFull }
        } else {
            try? await radioConnection.removeChannels([key])
        }
        do {
            try await applicationStore.setChannelMembership(
                id: channel.id,
                joinedPhone: joined,
                joinedDevice: channel.joinedDevice
            )
            // The address map is otherwise only rebuilt at session start, and
            // leaving cleared this entry — a rejoin that skipped it would
            // leave the channel unreachable from chat until relaunch.
            if joined, let address = try? await meshEngine.channelConversationAddress(key: key) {
                coordinator.channelAddresses[channel.id] = address
            } else if !joined {
                coordinator.channelAddresses[channel.id] = nil
            }
            await reloadApplicationState()
            if joined, channel.canonicalName == "public" {
                // Rejoining public restores its always-present conversation,
                // the same invariant session start establishes.
                await ensurePublicConversation()
                await reloadApplicationState()
            }
            await reconcileHostChannels()
            return .success
        } catch {
            return .failed
        }
    }

    /// Add or remove the channel on the companion radio's own device identity,
    /// which is membership for the radio, not for this phone.
    private func setChannelDeviceMembership(
        _ channel: ChannelSummary,
        joined: Bool
    ) async -> ChannelActionOutcome {
        guard let applicationStore,
              let key = try? await channelKeyVault.loadKey(channelID: channel.id)
        else { return .failed }
        do {
            if joined {
                try await radioConnection.addDeviceChannel(key)
            } else {
                try await radioConnection.removeDeviceChannel(key)
            }
            try? await applicationStore.setChannelMembership(
                id: channel.id,
                joinedPhone: channel.joinedPhone,
                joinedDevice: joined
            )
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

    private func updateChannelDetails(
        _ channel: ChannelSummary,
        details: ChannelDetails
    ) async -> Bool {
        guard let applicationStore else { return false }
        do {
            try await applicationStore.updateChannelDetails(
                id: channel.id,
                alias: details.alias,
                regionCode: details.regionCode,
                maxFloodHops: details.maxFloodHops,
                notificationsEnabled: details.notificationsEnabled
            )
            await reloadApplicationState()
            return true
        } catch {
            return false
        }
    }

    /// Toggle a channel's banners from inside its conversation, where the
    /// question actually comes up. Everything else the user set stays put:
    /// this is one field of the same local details the Channels tab edits.
    private func setChannelNotifications(_ channel: ChannelSummary, _ enabled: Bool) async {
        _ = await updateChannelDetails(
            channel,
            details: ChannelDetails(
                alias: channel.alias,
                regionCode: channel.regionCode,
                maxFloodHops: channel.maxFloodHops,
                notificationsEnabled: enabled
            )
        )
    }

    /// Build the URI that invites someone else to this channel. A named
    /// channel shares only its name; a private one shares the key itself.
    ///
    /// The name goes out written the way it is read — `umsh:cs:Trail%20Crew`,
    /// not the folded form. Recipients percent-decode first and canonicalize
    /// after, so casing travels without changing which channel is meant.
    private func channelInvitation(_ channel: ChannelSummary) async -> String? {
        guard let key = try? await channelKeyVault.loadKey(channelID: channel.id) else {
            return nil
        }
        // The alias is this phone's label and stays here; what goes out is the
        // channel's own name.
        let sharedName = channel.name ?? channel.canonicalName
        return try? await meshEngine.formatChannelInvitation(
            key: key,
            name: channel.invitationIsSecret ? nil : sharedName,
            displayName: channel.invitationIsSecret ? channel.name : nil,
            // A protocol-fixed ceiling is not a recommendation to pass on: the
            // recipient derives it from the channel exactly as this phone did.
            maxFloodHops: channel.protocolMaxFloodHops == nil
                ? channel.maxFloodHops.map(UInt8.init)
                : nil,
            regionCode: channel.regionCode
        )
    }

    private func storedChannel(keyDigest: String) async throws -> ChannelSummary? {
        guard let applicationStore, let localIdentity else { return nil }
        let stored = try await applicationStore.channel(
            ownerIdentityID: localIdentity.id,
            keyDigest: keyDigest
        )
        return stored.map(Self.summary(from:))
    }

    /// Register keys with the phone's MAC, reporting whether they all fit.
    private func registerChannelKeys(_ keys: [Data]) async -> Bool {
        do {
            try await radioConnection.registerChannels(keys)
            return true
        } catch {
            return false
        }
    }

    /// Give the radio the channel keys the phone identity has joined, so it
    /// can recognize and queue that traffic while the phone is away.
    ///
    /// Bookkeeping between the app and its own radio: no part of it is a user
    /// setting, and a radio that cannot hold them all still leaves the phone
    /// fully able to use every channel while attached.
    private func reconcileHostChannels() async {
        guard radioSnapshot.linkState == .attached || radioSnapshot.linkState == .ready,
              radioSnapshot.hostState == .matchesCurrentIdentity,
              radioSnapshot.provisioning?.supportsHostKeys == true
        else {
            coordinator.lastReconciledHostChannels = nil
            return
        }
        var keys: [Data] = []
        // Deterministic priority, so a radio that cannot hold every key holds
        // the same ones each time rather than whichever arrived first.
        for channel in channels.filter(\.joinedPhone).sorted(by: Self.hostChannelPriority) {
            if let key = try? await channelKeyVault.loadKey(channelID: channel.id) {
                keys.append(key)
            }
        }
        guard coordinator.lastReconciledHostChannels != keys else { return }
        do {
            try await radioConnection.reconcileHostChannels(keys)
            coordinator.lastReconciledHostChannels = keys
        } catch {
            // Retried on the next attach or membership change.
        }
    }

    /// `public` and `EMERGENCY` first, then the most recently joined.
    private static func hostChannelPriority(_ lhs: ChannelSummary, _ rhs: ChannelSummary) -> Bool {
        if (lhs.kind == .builtin) != (rhs.kind == .builtin) {
            return lhs.kind == .builtin
        }
        return (lhs.joinedAt ?? .distantPast) > (rhs.joinedAt ?? .distantPast)
    }

    /// Ensure `public` and `EMERGENCY` exist for this identity.
    ///
    /// Both start joined with notifications off: they are the channels a new
    /// user is expected to be reachable on, but neither should announce
    /// itself before the user has any reason to care. Leaving either clears
    /// the joined flags without deleting the row, which is what lets the join
    /// flow offer them back.
    private func ensureBuiltinChannels() async {
        guard let applicationStore, let localIdentity else { return }
        // Written the way the protocol names them. Only the canonicalized
        // form reaches the key derivation, so the casing here is purely how
        // the channels are labelled.
        for name in ["Public", "EMERGENCY"] {
            guard let preview = try? await meshEngine.inspectChannelName(name) else { continue }
            let digest = Self.keyDigest(preview.key)
            guard (try? await applicationStore.channel(
                ownerIdentityID: localIdentity.id,
                keyDigest: digest
            )) ?? nil == nil else { continue }
            let id = UUID()
            do {
                try await channelKeyVault.storeKey(preview.key, channelID: id)
                try await applicationStore.insertChannel(
                    StoredChannel(
                        id: id,
                        ownerIdentityID: localIdentity.id,
                        kind: .builtin,
                        canonicalName: preview.canonicalName,
                        name: preview.displayName,
                        alias: nil,
                        channelIDHex: Self.hex(preview.channelID),
                        tint: preview.tint,
                        regionCode: nil,
                        maxFloodHops: nil,
                        joinedPhone: true,
                        joinedDevice: false,
                        notificationsEnabled: false,
                        joinedAt: Date()
                    ),
                    keyDigest: digest
                )
            } catch {
                try? await channelKeyVault.deleteKey(channelID: id)
            }
        }
    }

    /// Register every phone-joined channel with a freshly built mesh session.
    /// The session starts with an empty channel table, so this is what makes
    /// membership survive a relaunch.
    private func replayChannelMembership() async {
        var keys: [Data] = []
        for channel in channels where channel.joinedPhone {
            if let key = try? await channelKeyVault.loadKey(channelID: channel.id) {
                keys.append(key)
            }
        }
        // Registration has to precede chat restore: a channel checkpoint can
        // only be understood once its key is held.
        _ = await registerChannelKeys(keys)
        await refreshChannelAddresses()
        await ensurePublicConversation()
        await reloadApplicationState()
    }

    /// The public channel is where an off-grid conversation starts when the
    /// user has nobody's key yet, so its chat is always there to open. Every
    /// other channel waits to be asked.
    private func ensurePublicConversation() async {
        guard let applicationStore, let localIdentity else { return }
        guard let channel = channels.first(where: {
            $0.canonicalName == "public" && $0.joinedPhone
        }), let address = coordinator.channelAddresses[channel.id] else { return }
        _ = try? await applicationStore.ensureChannelConversation(
            ownerIdentityID: localIdentity.id,
            channelID: channel.id,
            conversationAddress: address
        )
    }

    /// Derive each joined channel's conversation address once, so the rest of
    /// the app can match a record to a channel without touching Keychain.
    private func refreshChannelAddresses() async {
        var addresses: [UUID: String] = [:]
        for channel in channels where channel.joinedPhone {
            guard let key = try? await channelKeyVault.loadKey(channelID: channel.id),
                  let address = try? await meshEngine.channelConversationAddress(key: key)
            else { continue }
            addresses[channel.id] = address
        }
        coordinator.channelAddresses = addresses
    }

    /// Reconcile the device's channel list into the local cache flags, and
    /// collect the identifiers this phone cannot name.
    private func synchronizeRadioChannels(from snapshot: RadioSnapshot) async {
        guard snapshot.linkState == .attached || snapshot.linkState == .ready,
              snapshot.hostState == .matchesCurrentIdentity,
              let applicationStore
        else {
            coordinator.lastReconciledDeviceChannels = nil
            if !unknownDeviceChannels.isEmpty { unknownDeviceChannels = [] }
            return
        }
        guard let identifiers = snapshot.provisioning?.devChannelIDs,
              coordinator.lastReconciledDeviceChannels != identifiers
        else { return }

        // The device reports identifiers only, so naming them means deriving
        // an identifier from each key this phone holds and matching.
        var identified: Set<Data> = []
        for channel in channels {
            guard let key = try? await channelKeyVault.loadKey(channelID: channel.id),
                  let derived = try? await meshEngine.deriveChannelID(key: key)
            else { continue }
            let onDevice = identifiers.contains(derived)
            if onDevice { identified.insert(derived) }
            if channel.joinedDevice != onDevice {
                try? await applicationStore.setChannelMembership(
                    id: channel.id,
                    joinedPhone: channel.joinedPhone,
                    joinedDevice: onDevice
                )
            }
        }
        let unknown = identifiers
            .filter { !identified.contains($0) }
            .map(UnknownDeviceChannel.init(identifier:))
        if unknownDeviceChannels != unknown { unknownDeviceChannels = unknown }
        coordinator.lastReconciledDeviceChannels = identifiers
        await reloadApplicationState()
    }

    private static func summary(from stored: StoredChannel) -> ChannelSummary {
        ChannelSummary(
            id: stored.id,
            kind: stored.kind,
            canonicalName: stored.canonicalName,
            name: stored.name,
            alias: stored.alias,
            channelIDHex: stored.channelIDHex,
            tint: stored.tint,
            regionCode: stored.regionCode,
            maxFloodHops: stored.maxFloodHops,
            joinedPhone: stored.joinedPhone,
            joinedDevice: stored.joinedDevice,
            notificationsEnabled: stored.notificationsEnabled,
            joinedAt: stored.joinedAt
        )
    }

    /// One-way commitment to a channel key, used to recognize a key the store
    /// already holds without the store ever seeing the key itself.
    private static func keyDigest(_ key: Data) -> String {
        hex(Data(SHA256.hash(data: key)))
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
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
        _ conversation: ConversationListItem,
        _ body: String
    ) async -> MessageSendResult {
        await performChatCompose(conversation, clearsDraft: true) { clientToken in
            try await radioConnection.composeText(
                conversationAddress: conversation.conversationAddress,
                clientToken: clientToken,
                body: body
            )
        }
    }

    private func editMessage(
        _ conversation: ConversationListItem,
        _ message: ChatMessageSummary,
        _ newBody: String
    ) async -> MessageSendResult {
        await performChatCompose(conversation, clearsDraft: false) { clientToken in
            try await radioConnection.composeEdit(
                conversationAddress: conversation.conversationAddress,
                clientToken: clientToken,
                original: originalRef(message),
                body: newBody
            )
        }
    }

    private func deleteMessage(
        _ conversation: ConversationListItem,
        _ message: ChatMessageSummary
    ) async -> MessageSendResult {
        await performChatCompose(conversation, clearsDraft: false) { clientToken in
            try await radioConnection.composeDelete(
                conversationAddress: conversation.conversationAddress,
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

    /// Which kind of conversation a log line is about. Never the address
    /// itself: a peer address identifies a person, and the console is not the
    /// place to publish who this phone talks to.
    private static func conversationKindLabel(_ conversation: ConversationListItem) -> String {
        switch conversation {
        case .direct: "direct"
        case .channel: "channel"
        }
    }

    private func performChatCompose(
        _ conversation: ConversationListItem,
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
                //
                // The bump has to precede the reload: the reload stamps the
                // revision into the summary it publishes, and the open
                // transcript takes its cue to re-read from that stamp.
                coordinator.bumpChatRevisions([conversation.conversationAddress])
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
                let fragments = batch.mutations.compactMap(\.fragmentCount).max() ?? 1
                Self.chatLogger.info(
                    """
                    Composed \(Self.conversationKindLabel(conversation), privacy: .public) message \
                    handle \(batch.mutations.first?.handle ?? 0, privacy: .public) \
                    in batch \(batch.batchId, privacy: .public): \
                    \(fragments, privacy: .public) fragment(s), \
                    \(batch.archives.count, privacy: .public) archive(s); released to radio
                    """
                )
            } catch {
                Self.chatLogger.error("Could not release chat batch to radio: \(String(describing: error), privacy: .public)")
                try? await applicationStore.markChatComposeBatchFailed(
                    ownerIdentityID: localIdentity.id,
                    batch: batch
                )
                coordinator.bumpChatRevisions([conversation.conversationAddress])
                await reloadApplicationState()
                return .failed("The message could not be queued for transmission: \(error)")
            }
            if clearsDraft {
                switch conversation {
                case let .direct(direct):
                    try await applicationStore.updateDraft(
                        ownerIdentityID: localIdentity.id,
                        conversationID: direct.id,
                        text: ""
                    )
                case let .channel(channel):
                    try await applicationStore.updateChannelDraft(
                        ownerIdentityID: localIdentity.id,
                        conversationID: channel.id,
                        text: ""
                    )
                }
            }
            await reloadApplicationState()
            guard let updated = conversationItems.first(where: { $0.id == conversation.id }) else {
                return .failed("The message was saved, but the conversation could not be refreshed.")
            }
            return .sent(updated)
        } catch {
            Self.logger.error("Could not compose chat message: \(String(describing: error), privacy: .public)")
            return .failed("The message could not be composed: \(error)")
        }
    }

    /// Every conversation, both kinds, most recent traffic first.
    ///
    /// A channel with newer messages belongs above a quiet direct chat, so the
    /// two are ordered together rather than grouped.
    private var conversationItems: [ConversationListItem] {
        let items = conversations.map(ConversationListItem.direct)
            + channelConversations.map(ConversationListItem.channel)
        return items.sorted { first, second in
            if first.lastActivityMilliseconds != second.lastActivityMilliseconds {
                return first.lastActivityMilliseconds > second.lastActivityMilliseconds
            }
            return first.title.localizedCaseInsensitiveCompare(second.title) == .orderedAscending
        }
    }

    /// Open a channel's group conversation, creating it the first time.
    private func startChannelConversation(
        _ channel: ChannelSummary
    ) async -> ChannelConversationSummary? {
        guard let applicationStore, let localIdentity else { return nil }
        guard let address = coordinator.channelAddresses[channel.id] else { return nil }
        do {
            _ = try await applicationStore.ensureChannelConversation(
                ownerIdentityID: localIdentity.id,
                channelID: channel.id,
                conversationAddress: address
            )
            await reloadApplicationState()
            return channelConversations.first { $0.channel.id == channel.id }
        } catch {
            Self.logger.error(
                "Could not open channel conversation: \(String(describing: error), privacy: .public)"
            )
            return nil
        }
    }

    /// Open the conversation for a channel that was just joined, resolving
    /// the freshly stored row from the key the invitation carried.
    private func startConversationAfterJoin(
        _ preview: MeshChannelPreview
    ) async -> ChannelConversationSummary? {
        await refreshChannelAddresses()
        guard let channel = (try? await storedChannel(keyDigest: Self.keyDigest(preview.key)))
            ?? nil
        else { return nil }

        return await startChannelConversation(channel)
    }

    private func deleteChannelConversation(_ conversation: ChannelConversationSummary) async {
        guard let applicationStore, let localIdentity else { return }
        do {
            try await applicationStore.deleteChannelConversation(
                ownerIdentityID: localIdentity.id,
                conversationID: conversation.id
            )
            await reloadApplicationState()
        } catch {
            Self.logger.error(
                "Could not delete channel conversation \(conversation.id): \(String(describing: error), privacy: .public)"
            )
        }
    }

    private func updateChannelDraft(_ conversationID: Int64, _ text: String) async {
        guard let applicationStore, let localIdentity else { return }
        try? await applicationStore.updateChannelDraft(
            ownerIdentityID: localIdentity.id,
            conversationID: conversationID,
            text: text
        )
        if let index = channelConversations.firstIndex(where: { $0.id == conversationID }) {
            channelConversations[index].draftText = text
        }
    }

    /// Mark a conversation read. Driven by the transcript appearing, so the
    /// badge clears when the user actually looks at it.
    private func markConversationRead(_ address: String) async {
        guard let applicationStore, let localIdentity else { return }
        try? await applicationStore.markConversationRead(
            ownerIdentityID: localIdentity.id,
            conversationAddress: address
        )
        await reloadApplicationState()
    }

    private func requestMemberIdentity(
        _ conversation: ChannelConversationSummary,
        _ hint: Data
    ) async {
        try? await radioConnection.requestIdentityByHint(
            conversationAddress: conversation.conversationAddress,
            hint: hint
        )
    }

    /// Erase a conversation's transcript, keeping the conversation. Local
    /// only: nothing is sent, so everyone else keeps their copy.
    ///
    /// Addressed rather than keyed by row so one path serves both kinds, and
    /// `@Sendable` because it is handed to views as a bare closure.
    @Sendable
    private func clearConversationMessages(_ address: String) async {
        guard let applicationStore, let localIdentity else { return }
        do {
            try await applicationStore.clearConversationMessages(
                ownerIdentityID: localIdentity.id,
                conversationAddress: address
            )
            coordinator.bumpChatRevisions([address])
            await reloadApplicationState()
        } catch {
            Self.logger.error(
                "Could not clear conversation messages: \(String(describing: error), privacy: .public)"
            )
        }
    }

    /// Bounded transcript reads for whichever thread view is open.
    ///
    /// The window lives in the thread view rather than here: the ordinary way
    /// into a transcript is a navigation destination the app root never sees,
    /// so hoisting it would mean tracking push and pop for no other reason.
    private var transcriptLoader: TranscriptLoader {
        TranscriptLoader(
            newest: newestTranscriptPage,
            older: olderTranscriptPage,
            newer: newerTranscriptPage,
            around: focusedTranscriptPage
        )
    }

    @Sendable
    private func newestTranscriptPage(_ address: String, _ limit: Int) async -> TranscriptPage {
        guard let applicationStore, let localIdentity else { return .empty }
        return await transcriptPage(
            try? await applicationStore.chatMessagePage(
                ownerIdentityID: localIdentity.id,
                conversationAddress: address,
                newest: limit
            )
        ) ?? .empty
    }

    @Sendable
    private func olderTranscriptPage(
        _ address: String,
        _ cursor: ChatMessageCursor,
        _ limit: Int
    ) async -> TranscriptPage {
        guard let applicationStore, let localIdentity else { return .empty }
        return await transcriptPage(
            try? await applicationStore.chatMessagePage(
                ownerIdentityID: localIdentity.id,
                conversationAddress: address,
                before: cursor,
                limit: limit
            )
        ) ?? .empty
    }

    @Sendable
    private func newerTranscriptPage(
        _ address: String,
        _ cursor: ChatMessageCursor,
        _ including: Bool,
        _ limit: Int
    ) async -> TranscriptPage {
        guard let applicationStore, let localIdentity else { return .empty }
        return await transcriptPage(
            try? await applicationStore.chatMessagePage(
                ownerIdentityID: localIdentity.id,
                conversationAddress: address,
                after: cursor,
                including: including,
                limit: limit
            )
        ) ?? .empty
    }

    @Sendable
    private func focusedTranscriptPage(
        _ address: String,
        _ messageID: String,
        _ radius: Int
    ) async -> TranscriptPage? {
        guard let applicationStore, let localIdentity,
              let reference = Self.messageReference(messageID)
        else { return nil }
        let stored = try? await applicationStore.chatMessageWindow(
            ownerIdentityID: localIdentity.id,
            conversationAddress: address,
            around: reference.sessionID,
            handle: reference.handle,
            radius: radius
        )
        // A nil read and a nil window mean the same thing to the caller: this
        // message is not somewhere the transcript can go.
        guard let stored else { return nil }
        return await transcriptPage(stored)
    }

    /// Map one bounded read for display, resolving the sender hints that page
    /// needs. A page is at most a few hundred rows, so hint rendering is
    /// bounded by what is about to be on screen rather than by stored history.
    private func transcriptPage(_ stored: StoredChatMessagePage?) async -> TranscriptPage? {
        guard let stored else { return nil }
        let nodeHints = await renderedNodeHints(in: stored.messages)
        return TranscriptPage(
            messages: stored.messages.map { Self.messageSummary(from: $0, nodeHints: nodeHints) },
            hasOlder: stored.hasOlder,
            hasNewer: stored.hasNewer
        )
    }

    /// Split a `ChatMessageSummary.id` back into the durable identity it was
    /// built from. The transcript names messages this way throughout, so a
    /// search result can be handed straight back as an anchor.
    private static func messageReference(
        _ messageID: String
    ) -> (sessionID: String, handle: UInt32)? {
        guard let separator = messageID.lastIndex(of: ":"),
              let handle = UInt32(messageID[messageID.index(after: separator)...])
        else { return nil }
        return (String(messageID[..<separator]), handle)
    }

    /// Record which conversations a chat batch changed, so an open transcript
    /// re-reads its window.
    ///
    /// Not everything in a batch names its conversation. A body edit or a
    /// tombstone identifies its message by durable handle alone, and a delivery
    /// carries only the handle it acknowledges, so both are resolved from the
    /// row already in storage. Deliveries arrive per fragment, so identical
    /// handles are collapsed first: each distinct message is worth one lookup,
    /// not one per fragment.
    private func noteChatMessagesChanged(by update: RadioChatUpdate) async {
        guard let applicationStore, let localIdentity else { return }
        var addresses = Set(update.mutations.compactMap(\.conversationAddress))
        addresses.formUnion(update.senderResolutions.map(\.conversationAddress))

        var unresolved: Set<ChatMessageKey> = []
        for mutation in update.mutations where mutation.conversationAddress == nil {
            unresolved.insert(ChatMessageKey(sessionID: mutation.sessionId, handle: mutation.handle))
        }
        for delivery in update.deliveries {
            unresolved.insert(ChatMessageKey(sessionID: delivery.sessionId, handle: delivery.handle))
        }
        var unresolvable = false
        for key in unresolved {
            if let address = try? await applicationStore.conversationAddressForMessage(
                ownerIdentityID: localIdentity.id,
                sessionID: key.sessionID,
                handle: key.handle
            ) {
                addresses.insert(address)
            } else {
                unresolvable = true
            }
        }
        if unresolvable {
            // A change to a message this phone cannot place. Refreshing every
            // open transcript costs one bounded query; not refreshing the right
            // one leaves it showing something that is no longer true.
            addresses.formUnion(conversations.map(\.conversationAddress))
            addresses.formUnion(channelConversations.map(\.conversationAddress))
        }
        coordinator.bumpChatRevisions(addresses)
    }

    #if DEBUG
    /// Fill a conversation with generated messages, so a transcript can be
    /// exercised at a size no test account reaches by hand.
    @Sendable
    private func seedGeneratedMessages(_ address: String, _ count: Int) async {
        guard let applicationStore, let localIdentity else { return }
        try? await applicationStore.seedGeneratedMessages(
            ownerIdentityID: localIdentity.id,
            conversationAddress: address,
            count: count
        )
        coordinator.bumpChatRevisions([address])
        await reloadApplicationState()
    }
    #else
    private var seedGeneratedMessages: ((String, Int) async -> Void)? { nil }
    #endif

    /// How many messages a conversation holds, for the info sheet. The only
    /// aggregate that walks a whole transcript, so it is answered here rather
    /// than carried on every summary through every reload.
    @Sendable
    private func countConversationMessages(_ address: String) async -> Int {
        guard let applicationStore, let localIdentity else { return 0 }
        return (try? await applicationStore.chatMessageCount(
            ownerIdentityID: localIdentity.id,
            conversationAddress: address
        )) ?? 0
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
            // Telling the radio is an optimization for the attached case, not
            // part of creating the conversation: with no radio there is
            // nothing to tell, and `prepareChatState` registers every
            // conversation peer on the next attach anyway. Letting it fail the
            // whole operation would leave a conversation that exists on disk
            // but that nothing ever opens.
            try? await radioConnection.registerChatPeers([peer.identity.canonicalAddress])
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
            // Channel streams are checkpointed too, but a channel is not a
            // peer and must not be registered as one.
            let addresses = Set(
                conversations.map(\.peer.identity.canonicalAddress)
                    + checkpoints.map(\.conversationAddress)
                        .filter { !Self.isChannelAddress($0) }
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
            Self.chatLogger.warning("Core chat diagnostic: \(diagnostic, privacy: .public)")
        }
        Self.chatLogger.debug(
            """
            Chat batch \(update.batchID, privacy: .public) arrived: \
            \(update.mutations.count, privacy: .public) mutation(s), \
            \(update.deliveries.count, privacy: .public) delivery(s), \
            \(update.archiveLookups.count, privacy: .public) archive lookup(s), \
            \(update.senderResolutions.count, privacy: .public) sender resolution(s)
            """
        )
        for delivery in update.deliveries {
            Self.chatLogger.debug(
                """
                Delivery handle \(delivery.handle, privacy: .public)\
                \(delivery.fragmentIndex.map { " fragment \($0)" } ?? "", privacy: .public) \
                → \(String(describing: delivery.state), privacy: .public)
                """
            )
        }
        do {
            if !update.mutations.isEmpty {
                try await applicationStore.applyChatMutations(
                    ownerIdentityID: localIdentity.id,
                    mutations: update.mutations
                )
                for address in Set(update.mutations.compactMap(\.conversationAddress)) {
                    if Self.isChannelAddress(address) {
                        // A group message opens its conversation the same way
                        // a direct one does: the user joined the channel, so
                        // traffic in it is expected.
                        guard let channel = channels.first(where: {
                            coordinator.channelAddresses[$0.id] == address
                        }) else { continue }
                        _ = try await applicationStore.ensureChannelConversation(
                            ownerIdentityID: localIdentity.id,
                            channelID: channel.id,
                            conversationAddress: address
                        )
                    } else {
                        _ = try await applicationStore.ensureDirectConversation(
                            ownerIdentityID: localIdentity.id,
                            peerAddress: address
                        )
                    }
                }
            }
            for resolution in update.senderResolutions {
                try? await applicationStore.applySenderResolution(
                    ownerIdentityID: localIdentity.id,
                    conversationAddress: resolution.conversationAddress,
                    senderHint: Data(resolution.senderHint),
                    senderAddress: resolution.senderAddress
                )
            }
            if !update.deliveries.isEmpty {
                try await applicationStore.applyChatDeliveries(
                    ownerIdentityID: localIdentity.id,
                    deliveries: update.deliveries
                )
            }
            await noteChatMessagesChanged(by: update)
            for lookup in update.archiveLookups {
                let payload = try? await applicationStore.chatArchive(
                    ownerIdentityID: localIdentity.id,
                    lookup: lookup
                )
                // Answering someone else's repair request is best effort: it
                // travels over the radio link, which can be gone. Letting that
                // failure escape would leave the batch unacknowledged and stall
                // every later update behind a frame we cannot resend anyway.
                do {
                    try await radioConnection.applyChatArchiveResult(
                        requestID: lookup.requestId,
                        kind: payload == nil ? .unknown : .found,
                        payload: payload ?? Data()
                    )
                } catch {
                    Self.chatLogger.warning(
                        """
                        Archive lookup \(lookup.requestId, privacy: .public) went unanswered: \
                        \(String(describing: error), privacy: .public)
                        """
                    )
                }
            }
            // Last-heard evidence beyond chat inserts: an inbound message and a
            // delivery ack both prove we heard from the peer. Deliveries carry
            // no address, so resolve them from the acked message's conversation.
            var heardFrom: Set<String> = []
            for mutation in update.mutations where mutation.direction == .inbound {
                // In a channel the conversation is not a peer; the sender is,
                // once their hint has resolved to a real address.
                if let address = mutation.senderAddress {
                    heardFrom.insert(address)
                } else if let address = mutation.conversationAddress,
                          !Self.isChannelAddress(address) {
                    heardFrom.insert(address)
                }
            }
            for delivery in update.deliveries where delivery.state == .acknowledged {
                if let address = try? await applicationStore.conversationAddressForMessage(
                    ownerIdentityID: localIdentity.id,
                    sessionID: delivery.sessionId,
                    handle: delivery.handle
                ), !Self.isChannelAddress(address) {
                    heardFrom.insert(address)
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
            coordinator.chatBatchFailures = nil
            Self.chatLogger.debug(
                "Applied chat batch \(update.batchID, privacy: .public)"
            )
            if !update.mutations.isEmpty || !update.deliveries.isEmpty {
                await reloadApplicationState()
            }
            await postNotifications(for: update.mutations)
        } catch {
            // Effects remain idempotent, so the core re-offering this batch is
            // a real chance to recover from a transient failure.
            let attempts = coordinator.chatBatchFailures.map {
                $0.id == update.batchID ? $0.count + 1 : 1
            } ?? 1
            coordinator.chatBatchFailures = (id: update.batchID, count: attempts)
            Self.chatLogger.error(
                """
                Could not apply chat batch \(update.batchID, privacy: .public) \
                (attempt \(attempts, privacy: .public) of \(Self.chatBatchAttemptLimit, privacy: .public), \
                \(update.mutations.count, privacy: .public) mutation(s), \
                \(update.deliveries.count, privacy: .public) delivery(s)): \
                \(String(describing: error), privacy: .public)
                """
            )
            guard attempts >= Self.chatBatchAttemptLimit else { return }
            // The core holds one batch at a time and will not release the next
            // until this one is acknowledged. Dropping a batch loses the
            // updates it carried — stale rows, a message stuck on "Sending" —
            // but keeping it would freeze every conversation for the rest of
            // the session, which is the worse of the two.
            Self.chatLogger.fault(
                """
                Abandoning chat batch \(update.batchID, privacy: .public) after \
                \(attempts, privacy: .public) failed attempts; its updates are lost. \
                Conversation state may be stale until the next session.
                """
            )
            try? await radioConnection.acknowledgeChatBatch(update.batchID)
            coordinator.chatBatchFailures = nil
            await reloadApplicationState()
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
            if Self.isChannelAddress(target.conversationAddress) {
                guard let channel = channels.first(where: {
                    coordinator.channelAddresses[$0.id] == target.conversationAddress
                }) else { continue }
                // Muting a channel silences its banners. The messages still
                // arrive and still count as unread.
                guard channel.notificationsEnabled else { continue }
                notificationService.postInboundMessage(
                    conversationAddress: target.conversationAddress,
                    displayName: channel.title,
                    // A group message is from someone in particular, and the
                    // banner is unreadable without saying who.
                    sender: memberName(
                        address: target.senderAddress,
                        handle: target.senderHandle,
                        hint: target.senderHint
                    ),
                    body: target.body
                )
            } else {
                let displayName = peers.first {
                    $0.identity.canonicalAddress == target.conversationAddress
                }?.displayName ?? String(target.conversationAddress.prefix(10))
                notificationService.postInboundMessage(
                    conversationAddress: target.conversationAddress,
                    displayName: displayName,
                    sender: nil,
                    body: target.body
                )
            }
        }
    }

    /// What to call a channel member, in descending order of authority: the
    /// name we have given them or heard them advertise, then the name they
    /// attached to the message, then their address, then the bare hint.
    ///
    /// A message-borne name is the sender's unverified claim — anyone holding
    /// the channel key can write anything there — so it never displaces a
    /// name this phone established for a peer it actually knows.
    private func memberName(address: String?, handle: String?, hint: Data?) -> String {
        if let address, let peer = peers.first(where: {
            $0.identity.canonicalAddress == address
        }) {
            return peer.displayName
        }
        if let handle, !handle.isEmpty { return handle }
        if let address { return String(address.prefix(10)) }
        guard let hint else { return "Unknown member" }
        return "Member \(hint.map { String(format: "%02x", $0) }.joined())"
    }

    /// Whether an address names a channel's group conversation rather than a
    /// peer. The facade's own prefix, checked in one place.
    static func isChannelAddress(_ address: String) -> Bool {
        address.hasPrefix("ch:")
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
            // outbound row is an orphan from a previous launch. No transcript
            // can be open this early, so the rows it rewrites need no revision
            // bump — the first reload below publishes them.
            try await applicationStore.failStalePendingMessages(
                ownerIdentityID: localIdentity.id
            )
            await ensureBuiltinChannels()
            await synchronizeRadioPeer(from: radioSnapshot)
            await reloadApplicationState()
            // The mesh session starts with an empty channel table, so
            // membership only survives a relaunch by being replayed into it.
            await replayChannelMembership()
            await reconcileHostChannels()
        } catch {
            peers = []
            conversations = []
            channels = []
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
            let storedChannels = try await applicationStore.channels(
                ownerIdentityID: localIdentity.id
            )
            let mappedChannels = storedChannels.map(Self.summary(from:))
            if channels != mappedChannels {
                channels = mappedChannels
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
                mappedConversations.append(
                    DirectConversationSummary(
                        id: stored.id,
                        peer: peer,
                        draftText: stored.draftText,
                        lastMessage: Self.previewMessage(from: stored.lastMessage),
                        unreadCount: stored.unreadCount,
                        createdAtMilliseconds: stored.createdAtMilliseconds,
                        messageRevision: coordinator.chatRevisions[
                            peer.identity.canonicalAddress
                        ] ?? 0
                    )
                )
            }
            if conversations != mappedConversations {
                conversations = mappedConversations
            }

            let storedChannelConversations = try await applicationStore.listChannelConversations(
                ownerIdentityID: localIdentity.id
            )
            let channelsByID = Dictionary(
                mappedChannels.map { ($0.id, $0) },
                uniquingKeysWith: { first, _ in first }
            )
            var mappedChannelConversations: [ChannelConversationSummary] = []
            for stored in storedChannelConversations {
                // A conversation whose channel was left has no key to send
                // with and no name to show, so it is not listed.
                guard let channel = channelsByID[stored.channelID], channel.joinedPhone else {
                    continue
                }
                mappedChannelConversations.append(
                    ChannelConversationSummary(
                        id: stored.id,
                        channel: channel,
                        conversationAddress: stored.conversationAddress,
                        draftText: stored.draftText,
                        lastMessage: Self.previewMessage(from: stored.lastMessage),
                        unreadCount: stored.unreadCount,
                        createdAtMilliseconds: stored.createdAtMilliseconds,
                        messageRevision: coordinator.chatRevisions[
                            stored.conversationAddress
                        ] ?? 0
                    )
                )
            }
            if channelConversations != mappedChannelConversations {
                channelConversations = mappedChannelConversations
            }
        } catch {
            if !peers.isEmpty { peers = [] }
            if !conversations.isEmpty { conversations = [] }
            if !channelConversations.isEmpty { channelConversations = [] }
        }
    }

    private static func messageSummary(
        from stored: StoredChatMessage,
        nodeHints: [Data: MeshNodeHint] = [:]
    ) -> ChatMessageSummary {
        ChatMessageSummary(
            id: stored.id,
            body: stored.body,
            isOutbound: stored.outbound,
            deliveryState: stored.deliveryState,
            isDeleted: stored.isDeleted,
            isEdited: stored.isEdited,
            sessionID: stored.sessionID,
            handle: stored.handle,
            wireID: stored.wireID,
            epoch: stored.epoch,
            cursor: stored.cursor,
            isGapPlaceholder: stored.isGapPlaceholder,
            isUnavailable: stored.isUnavailable,
            isReceivedLate: stored.receivedLate,
            isDeliveredLate: stored.deliveredLate,
            originalBody: stored.originalBody,
            createdAtMilliseconds: stored.createdAtMilliseconds,
            senderAddress: stored.senderAddress,
            senderHint: stored.senderHint,
            senderHandle: stored.senderHandle,
            senderNodeHint: stored.senderHint.flatMap { nodeHints[$0] },
            reception: stored.reception
        )
    }

    private static func previewMessage(
        from stored: StoredConversationPreview?
    ) -> ConversationPreviewMessage? {
        stored.map { preview in
            ConversationPreviewMessage(
                createdAtMilliseconds: preview.createdAtMilliseconds,
                body: preview.body,
                isOutbound: preview.isOutbound,
                isDeleted: preview.isDeleted,
                senderAddress: preview.senderAddress,
                senderHint: preview.senderHint
            )
        }
    }

    /// Render every distinct sender hint in a transcript page once, so each
    /// group bubble can carry its sender's avatar without re-deriving it per
    /// row. Rendering is an FFI round trip and the answer never changes, so the
    /// coordinator keeps what it has already resolved for the whole session.
    private func renderedNodeHints(in messages: [StoredChatMessage]) async -> [Data: MeshNodeHint] {
        for hint in Set(messages.compactMap(\.senderHint))
        where coordinator.renderedNodeHints[hint] == nil {
            if let value = try? await meshEngine.renderNodeHint(hint) {
                coordinator.renderedNodeHints[hint] = value
            }
        }
        return coordinator.renderedNodeHints
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
    /// The device-identity channel identifiers last reconciled, gating the
    /// same way.
    var lastReconciledDeviceChannels: [Data]?
    /// The channel keys last provisioned to the radio's host table, so
    /// reconciling is free when nothing has changed.
    var lastReconciledHostChannels: [Data]?
    /// Each joined channel's conversation address, derived from its key when
    /// the key is unlocked. Kept here rather than on `ChannelSummary` because
    /// deriving it needs the key, which the summary deliberately never holds.
    var channelAddresses: [UUID: String] = [:]
    /// A reload that has been queued but has not begun reading storage yet;
    /// later callers can safely join it.
    var pendingReload: Task<Void, Never>?
    /// The most recently queued reload, joined or not. New reloads chain
    /// behind it so two never read and publish state concurrently.
    var runningReload: Task<Void, Never>?
    /// How many times the current chat batch has failed to apply. The core
    /// hands out one batch at a time and holds it until acknowledged, so a
    /// batch that can never be applied would otherwise stall every later
    /// chat update — delivery receipts included — for the whole session.
    var chatBatchFailures: (id: UInt64, count: Int)?
    /// How many times each conversation's stored messages have changed.
    ///
    /// An open transcript holds a bounded window rather than the whole history,
    /// so it has to be told when to re-read. Stamping this into the summary
    /// makes the reload that already publishes the summary carry the news, with
    /// no second channel to keep in step.
    ///
    /// Deliberately not bumped by marking a conversation read: that moves the
    /// unread badge, which rides the summary directly, and re-reading a
    /// transcript every time one is opened is the cost this exists to avoid.
    var chatRevisions: [String: Int] = [:]
    /// Rendered forms of every sender hint seen this session. Deriving one is
    /// an FFI round trip and the answer never changes, so a transcript page
    /// pays for each distinct hint at most once per process.
    var renderedNodeHints: [Data: MeshNodeHint] = [:]

    /// Record that these conversations' messages changed. Callers that cannot
    /// resolve which conversation a change belongs to pass every address they
    /// know: a redundant bounded re-read costs one query, while a missed one
    /// leaves an open transcript showing stale messages.
    func bumpChatRevisions(_ addresses: some Sequence<String>) {
        for address in addresses {
            chatRevisions[address, default: 0] += 1
        }
    }
}

/// A message's durable identity, for collapsing repeated references to it
/// within one batch — deliveries name the same message once per fragment.
private struct ChatMessageKey: Hashable {
    let sessionID: UInt64
    let handle: UInt32
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
            if snapshot.problemDescription != nil {
                RadioProblemBanner(snapshot: snapshot, action: action)
            }
        }
    }
}

#Preview {
    AppRootView(radioConnection: FakeRadioConnection())
}
