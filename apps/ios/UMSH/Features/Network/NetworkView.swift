import Foundation
import SwiftUI

struct NetworkView: View {
    @Binding var radioSnapshot: RadioSnapshot
    @Binding var conversations: [DirectConversationSummary]
    let peers: [PeerSummary]
    let inspectPeerIdentity: (String) async -> Result<MeshNodeURIPreview, MeshEngineError>
    /// Same shape Conversations uses, so an import here can open the new
    /// transcript instead of silently dropping the "Message" intent.
    let savePeer: (MeshNodeURIPreview, PeerImportDetails, Bool) async -> DirectConversationSummary?
    /// Hands a freshly created conversation to the app root, which switches
    /// to the Conversations tab and pushes the transcript.
    var openConversation: (DirectConversationSummary) -> Void = { _ in }
    var peerActions: PeerActions = .unavailable
    let updateDraft: ((Int64, String) async -> Void)?
    let sendMessage: ((DirectConversationSummary, String) async -> MessageSendResult)?
    var messageActions: ChatMessageActions = .unavailable
    /// Broadcast this phone's signed identity, for the Discover sheet's
    /// Announce action. Returns a failure message or nil.
    var advertiseIdentity: (() async -> String?)? = nil
    /// The name that announcement carries, for its confirmation preview.
    var advertisedName: String = ""
    /// Drop every transient row nothing depends on.
    var clearDiscoveredNodes: (() async -> Void)? = nil
    /// Send one zero-hop Identity Request soliciting nearby nodes.
    var solicitNearbyIdentities: ((PeerRole?) async -> Bool)? = nil
    @State private var presentation: NetworkPresentation = .list
    @State private var showsAddPeer = false
    @State private var showsDiscovery = false
    @AppStorage("network.sort") private var sortOrder: NetworkSortOrder = .alphabetic
    @State private var roleFilter: NetworkRoleFilter = .all
    @State private var searchText = ""
    @State private var peerPendingRemoval: PeerSummary?

    var body: some View {
        VStack(spacing: 0) {
            Picker("Presentation", selection: $presentation) {
                Text("List").tag(NetworkPresentation.list)
                Text("Map").tag(NetworkPresentation.map)
            }
            .pickerStyle(.segmented)
            .padding()

            switch presentation {
            case .list: peerList
            case .map:
                ContentUnavailableView {
                    Label("No reported locations", systemImage: "map")
                } description: {
                    Text("Locations reported by observed nodes will appear here with their precision and age.")
                }
            }
        }
        .navigationTitle("Network")
        .searchable(text: $searchText, prompt: "Name, alias, address, or hint")
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                sortAndFilterMenu
            }
            ToolbarItem(placement: .topBarTrailing) {
                Button("Add peer", systemImage: "person.badge.plus") { showsAddPeer = true }
            }
        }
        .sheet(isPresented: $showsAddPeer) {
            NavigationStack {
                NodeImportView(
                    inspectPeerIdentity: inspectPeerIdentity,
                    save: { preview, details, startConversation in
                        let conversation = await savePeer(preview, details, startConversation)
                        showsAddPeer = false
                        if startConversation, let conversation {
                            openConversation(conversation)
                        }
                    }
                )
            }
        }
        .sheet(isPresented: $showsDiscovery) {
            DiscoverPeersView(
                radioSnapshot: $radioSnapshot,
                conversations: $conversations,
                peers: peers,
                peerActions: peerActions,
                updateDraft: updateDraft,
                sendMessage: sendMessage,
                messageActions: messageActions,
                advertiseIdentity: advertiseIdentity,
                advertisedName: advertisedName,
                clearDiscoveredNodes: clearDiscoveredNodes,
                solicitNearbyIdentities: solicitNearbyIdentities,
                openConversation: { conversation in
                    showsDiscovery = false
                    openConversation(conversation)
                }
            )
        }
        .confirmationDialog(
            peerPendingRemoval.map { Text("Remove \($0.displayName)?") } ?? Text("Remove peer?"),
            isPresented: Binding(
                get: { peerPendingRemoval != nil },
                set: { if !$0 { peerPendingRemoval = nil } }
            ),
            titleVisibility: .visible,
            presenting: peerPendingRemoval
        ) { peer in
            if hasConversation(peer) {
                if peerActions.demoteToTransient != nil {
                    Button("Remove Peer") {
                        Task { _ = await peerActions.demoteToTransient?(peer) }
                    }
                }
                if peerActions.deletePeerAndConversation != nil {
                    Button("Delete Peer and Conversation", role: .destructive) {
                        Task { _ = await peerActions.deletePeerAndConversation?(peer) }
                    }
                }
            } else if peerActions.deletePeer != nil {
                Button("Delete Peer", role: .destructive) {
                    Task { _ = await peerActions.deletePeer?(peer) }
                }
            }
            Button("Cancel", role: .cancel) {}
        } message: { peer in
            Text(hasConversation(peer)
                 ? "Removing the peer keeps its conversation and message history, and the node stays findable through search. Deleting the peer and conversation erases the message history too."
                 : "The node's record is deleted from this phone. Nothing is sent to the node.")
        }
    }

    // MARK: - List

    @ViewBuilder
    private var peerList: some View {
        if peers.isEmpty {
            ContentUnavailableView {
                Label("No known nodes", systemImage: "point.3.connected.trianglepath.dotted")
            } description: {
                Text("Import a peer to get started, or listen for nodes announcing themselves nearby.")
            } actions: {
                Button("Discover peers") { showsDiscovery = true }
                    .buttonStyle(.borderedProminent)
            }
        } else if isSearching {
            searchResults
        } else {
            List {
                let radios = arranged(visiblePeers.filter(\.isUlcpDevice))
                if !radios.isEmpty {
                    Section("Saved radio") {
                        ForEach(radios) { peer in peerRow(peer) }
                    }
                }
                let favorites = arranged(visiblePeers.filter { !$0.isUlcpDevice && $0.isFavorite })
                if !favorites.isEmpty {
                    Section("Favorites") {
                        ForEach(favorites) { peer in peerRow(peer) }
                    }
                }
                let saved = arranged(
                    visiblePeers.filter { !$0.isUlcpDevice && !$0.isFavorite }
                )
                if !saved.isEmpty {
                    Section("Saved nodes") {
                        ForEach(saved) { peer in peerRow(peer) }
                    }
                }
                if visiblePeers.isEmpty {
                    Section {
                        Text("No saved nodes. Nodes heard over the air appear in search until you save them.")
                            .foregroundStyle(.secondary)
                    }
                }
                Section {
                    Button("Discover peers") { showsDiscovery = true }
                } footer: {
                    Text("A bounded listening session for nodes announcing themselves nearby.")
                }
            }
            .listStyle(.insetGrouped)
        }
    }

    /// Search spans every recorded node, including the transient tier the
    /// main list hides — that is the deliberate way discovered-but-unsaved
    /// nodes stay reachable.
    private var searchResults: some View {
        List {
            let saved = arranged(visiblePeers.filter { matchesSearch($0) })
            if !saved.isEmpty {
                Section("Saved") {
                    ForEach(saved) { peer in peerRow(peer) }
                }
            }
            let discovered = arranged(
                peers.filter { !$0.isSaved && !$0.isUlcpDevice && matchesSearch($0) }
            )
            if !discovered.isEmpty {
                Section {
                    ForEach(discovered) { peer in peerRow(peer) }
                } header: {
                    Text("Discovered nodes")
                } footer: {
                    Text("Heard over the air but not saved. Swipe to save one, or open it for details.")
                }
            }
            if saved.isEmpty && discovered.isEmpty {
                Section {
                    Text("No nodes match this search.")
                        .foregroundStyle(.secondary)
                }
            }
        }
        .listStyle(.insetGrouped)
    }

    // MARK: - Rows

    private func peerRow(_ peer: PeerSummary) -> some View {
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
                PeerAvatar(hint: peer.identity.hint, showsFavoriteStar: peer.isFavorite)
                VStack(alignment: .leading, spacing: 2) {
                    Text(peer.displayName)
                    Text(subtitle(for: peer))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
        }
        .swipeActions(edge: .leading, allowsFullSwipe: false) {
            if peer.isSaved, !peer.isUlcpDevice, peerActions.setFavorite != nil {
                Button {
                    Task { _ = await peerActions.setFavorite?(peer, !peer.isFavorite) }
                } label: {
                    Label(
                        peer.isFavorite ? "Unfavorite" : "Favorite",
                        systemImage: peer.isFavorite ? "star.slash" : "star"
                    )
                }
                .tint(.yellow)
            }
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
            if isRemovable(peer) {
                Button(role: .destructive) {
                    peerPendingRemoval = peer
                } label: {
                    Label("Remove", systemImage: "trash")
                }
            }
        }
    }

    private func subtitle(for peer: PeerSummary) -> String {
        if peer.isUlcpDevice {
            return "Companion radio identity · \(peer.identity.hint.text)"
        }
        if !peer.isSaved {
            return "Discovered · \(peer.identity.hint.text)"
        }
        return peer.identity.hint.text
    }

    /// The saved radio's release path is Forget Radio; every other row can
    /// at least be demoted, so removal is offered whenever the app root
    /// wired the closures at all.
    private func isRemovable(_ peer: PeerSummary) -> Bool {
        guard !peer.isUlcpDevice else { return false }
        if hasConversation(peer) {
            return peerActions.demoteToTransient != nil
                || peerActions.deletePeerAndConversation != nil
        }
        return peerActions.deletePeer != nil
    }

    private func hasConversation(_ peer: PeerSummary) -> Bool {
        conversations.contains {
            $0.peer.identity.canonicalAddress == peer.identity.canonicalAddress
        }
    }

    // MARK: - Sort & filter

    private var sortAndFilterMenu: some View {
        Menu {
            Picker("Sort", selection: $sortOrder) {
                ForEach(NetworkSortOrder.allCases) { order in
                    Text(order.label).tag(order)
                }
            }
            .pickerStyle(.inline)
            Picker("Show", selection: $roleFilter) {
                ForEach(NetworkRoleFilter.allCases) { filter in
                    Text(filter.label).tag(filter)
                }
            }
            .pickerStyle(.inline)
            Divider()
            Button("Discover Peers", systemImage: "dot.radiowaves.left.and.right") {
                showsDiscovery = true
            }
        } label: {
            Label(
                "Sort and filter",
                systemImage: roleFilter == .all
                    ? "line.3.horizontal.decrease.circle"
                    : "line.3.horizontal.decrease.circle.fill"
            )
        }
    }

    private var visiblePeers: [PeerSummary] {
        peers.filter { $0.isSaved || $0.isUlcpDevice }
    }

    private var isSearching: Bool {
        !searchText.trimmingCharacters(in: .whitespaces).isEmpty
    }

    /// Filter then sort one section's rows.
    private func arranged(_ peers: [PeerSummary]) -> [PeerSummary] {
        let filtered = peers.filter { passesRoleFilter($0) }
        switch sortOrder {
        case .alphabetic:
            return filtered.sorted {
                let comparison = $0.displayName.localizedCaseInsensitiveCompare($1.displayName)
                if comparison != .orderedSame { return comparison == .orderedAscending }
                return $0.id < $1.id
            }
        case .recentlyHeard:
            return filtered.sorted {
                switch ($0.lastHeard, $1.lastHeard) {
                case let (first?, second?) where first != second: return first > second
                case (.some, .none): return true
                case (.none, .some): return false
                default: return $0.id < $1.id
                }
            }
        case .latestMessage:
            let latest = latestMessageByAddress
            return filtered.sorted {
                let first = latest[$0.identity.canonicalAddress] ?? 0
                let second = latest[$1.identity.canonicalAddress] ?? 0
                if first != second { return first > second }
                return $0.id < $1.id
            }
        }
    }

    private var latestMessageByAddress: [String: Int64] {
        var latest: [String: Int64] = [:]
        for conversation in conversations {
            guard let newest = conversation.messages.map(\.createdAtMilliseconds).max() else {
                continue
            }
            latest[conversation.peer.identity.canonicalAddress] = newest
        }
        return latest
    }

    private func passesRoleFilter(_ peer: PeerSummary) -> Bool {
        // The saved radio anchors the list whatever the filter says.
        if peer.isUlcpDevice { return true }
        switch roleFilter {
        case .all:
            return true
        case .peopleAndText:
            return peer.role == .chat || hasConversation(peer)
        case .sensors:
            return peer.role == .sensor || peer.role == .tracker
        case .repeatersAndBridges:
            return peer.role == .bridge || peer.isLikelyRepeater
        }
    }

    private func matchesSearch(_ peer: PeerSummary) -> Bool {
        let query = searchText.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else { return true }
        let textOptions: String.CompareOptions = [.caseInsensitive, .diacriticInsensitive]
        if let alias = peer.alias, alias.range(of: query, options: textOptions) != nil {
            return true
        }
        if let name = peer.advertisedName, name.range(of: query, options: textOptions) != nil {
            return true
        }
        // Addresses are exact base58, so only a prefix (or the whole string,
        // pasted) is a meaningful match — substring hits would be noise.
        if peer.identity.canonicalAddress.hasPrefix(query) { return true }
        if peer.identity.hint.text.range(of: query, options: .caseInsensitive) != nil {
            return true
        }
        return false
    }
}

private enum NetworkPresentation: Hashable {
    case list
    case map
}

private enum NetworkSortOrder: String, CaseIterable, Identifiable {
    case alphabetic
    case recentlyHeard
    case latestMessage

    var id: Self { self }

    var label: String {
        switch self {
        case .alphabetic: "Alphabetical"
        case .recentlyHeard: "Recently heard"
        case .latestMessage: "Latest message"
        }
    }
}

private enum NetworkRoleFilter: String, CaseIterable, Identifiable {
    case all
    case peopleAndText
    case sensors
    case repeatersAndBridges

    var id: Self { self }

    var label: String {
        switch self {
        case .all: "All"
        case .peopleAndText: "People & text"
        case .sensors: "Sensors"
        case .repeatersAndBridges: "Repeaters & bridges"
        }
    }
}
