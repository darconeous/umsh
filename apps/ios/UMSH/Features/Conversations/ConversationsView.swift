import SwiftUI
import UIKit

struct ConversationsView: View {
    /// Both kinds of conversation, already ordered by the app root. Direct
    /// chats and channel group chats live in one list: a channel with newer
    /// traffic belongs above a quiet direct chat, not in a section of its own.
    let items: [ConversationListItem]
    @Binding var conversations: [DirectConversationSummary]
    let channels: [ChannelSummary]
    /// Every saved peer, for naming channel members. Wider than
    /// `conversations`: a member can be a peer this phone knows without a
    /// direct chat ever having been opened.
    var peers: [PeerSummary] = []
    let radioSnapshot: RadioSnapshot
    /// Whether launch bootstrap is still running, so the list can say it is
    /// still reading rather than claim there is nothing to read. The stored
    /// conversations arrive well after first paint — identity, then store —
    /// and an empty list is otherwise indistinguishable from a loaded one.
    var isLoading = false
    let inspectPeerIdentity: (String) async -> Result<MeshNodeURIPreview, MeshEngineError>
    let savePeer: (MeshNodeURIPreview, PeerImportDetails, Bool) async -> DirectConversationSummary?
    let updateDraft: (Int64, String) async -> Void
    var updateChannelDraft: (Int64, String) async -> Void = { _, _ in }
    let sendMessage: (ConversationListItem, String) async -> MessageSendResult
    var messageActions: ChatMessageActions = .unavailable
    var deleteConversation: (DirectConversationSummary) async -> Void = { _ in }
    var peerActions: PeerActions = .unavailable
    var channelActions: ChannelConversationActions = .unavailable
    /// Channel management, for joining one from here and for the channel
    /// sheet an open group conversation leads to.
    var channelManagementActions: ChannelActions = .unavailable
    var markRead: (String) async -> Void = { _ in }
    // Owned by the app root so URL-scheme imports can open a transcript
    // directly from outside this view.
    @Binding var openedConversation: DirectConversationSummary?
    @Binding var openedChannelConversation: ChannelConversationSummary?

    /// One presentation state for both sheets: two `.sheet(isPresented:)`
    /// modifiers on the same view fight, and only the last one presents.
    @State private var presentedSheet: NewConversationSheet?
    @State private var conversationPendingDeletion: DirectConversationSummary?
    @State private var channelConversationPendingDeletion: ChannelConversationSummary?
    @State private var searchText = ""

    var body: some View {
        List {
            if isSearching {
                searchResults
            } else if items.isEmpty, isLoading {
                ContentUnavailableView {
                    ProgressView()
                        .accessibilityLabel("Loading conversations")
                } description: {
                    Text("Loading conversations…")
                }
            } else if items.isEmpty {
                ContentUnavailableView {
                    Label("No conversations", systemImage: "bubble.left.and.bubble.right")
                } description: {
                    Text("Start a conversation with a peer, or open one in a channel you have joined.")
                } actions: {
                    Button("New Message…") { presentedSheet = .peerImport }
                        .buttonStyle(.borderedProminent)
                    Button("New Channel Chat…") { presentedSheet = .channelChooser }
                }
            } else {
                // No section header: the tab already says what this list is,
                // and splitting by kind would break the ordering rule.
                ForEach(items) { item in
                    NavigationLink(value: item.id) {
                        ConversationRow(item: item)
                    }
                    .swipeActions(edge: .trailing) {
                        // Not role: .destructive — that role animates the row
                        // away on the tap, and this button only asks. The row
                        // must stand still behind the confirmation dialog.
                        Button("Delete", systemImage: "trash") {
                            switch item {
                            case let .direct(conversation):
                                conversationPendingDeletion = conversation
                            case let .channel(conversation):
                                channelConversationPendingDeletion = conversation
                            }
                        }
                        .tint(.red)
                    }
                }
            }
        }
        // See the note in PeersView. Keyed on the identities alone, not the
        // whole items array: a conversation's summary changes on every
        // message, delivery receipt and draft keystroke, and animating the
        // list for those would put the rows in motion while the user types.
        // What is worth animating is a row arriving or leaving.
        .animation(UMSHAnimation.list, value: items.map(\.id))
        .navigationTitle("Conversations")
        // Hidden until the list is dragged down, which is where a reader
        // looking for someone reaches for it. Conversations, peers, and joined
        // channels — not messages: finding a message is a separate feature,
        // and this one is about reaching somewhere, whether or not a
        // conversation there exists yet.
        .searchable(text: $searchText, prompt: "Name, alias, address, or hint")
        .navigationDestination(for: String.self) { itemID in
            if let conversation = binding(for: itemID) {
                ConversationThreadView(
                    conversation: conversation,
                    radioSnapshot: radioSnapshot,
                    updateDraft: updateDraft,
                    updateChannelDraft: updateChannelDraft,
                    sendMessage: sendMessage,
                    messageActions: messageActions,
                    peerActions: peerActions,
                    channelActions: channelActions,
                    channelManagementActions: channelManagementActions,
                    markRead: markRead,
                    conversations: $conversations,
                    peers: peers,
                    unreadElsewhere: unreadCount(excluding: itemID)
                )
            }
        }
        .navigationDestination(item: $openedConversation) { conversation in
            if let conversation = binding(for: "direct:\(conversation.id)") {
                ConversationThreadView(
                    conversation: conversation,
                    radioSnapshot: radioSnapshot,
                    updateDraft: updateDraft,
                    updateChannelDraft: updateChannelDraft,
                    sendMessage: sendMessage,
                    messageActions: messageActions,
                    peerActions: peerActions,
                    channelActions: channelActions,
                    channelManagementActions: channelManagementActions,
                    markRead: markRead,
                    conversations: $conversations,
                    peers: peers,
                    unreadElsewhere: unreadCount(excluding: "direct:\(conversation.id)")
                )
            }
        }
        .navigationDestination(item: $openedChannelConversation) { conversation in
            if let conversation = binding(for: "channel:\(conversation.id)") {
                ConversationThreadView(
                    conversation: conversation,
                    radioSnapshot: radioSnapshot,
                    updateDraft: updateDraft,
                    updateChannelDraft: updateChannelDraft,
                    sendMessage: sendMessage,
                    messageActions: messageActions,
                    peerActions: peerActions,
                    channelActions: channelActions,
                    channelManagementActions: channelManagementActions,
                    markRead: markRead,
                    conversations: $conversations,
                    peers: peers,
                    unreadElsewhere: unreadCount(excluding: "channel:\(conversation.id)")
                )
            }
        }
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button("New Message…") { presentedSheet = .peerImport }
                    Button("New Channel Chat…") { presentedSheet = .channelChooser }
                } label: {
                    Label("New", systemImage: "square.and.pencil")
                }
            }
        }
        .confirmationDialog(
            "Delete this conversation?",
            isPresented: Binding(
                get: { conversationPendingDeletion != nil },
                set: { if !$0 { conversationPendingDeletion = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Delete Conversation", role: .destructive) {
                if let conversation = conversationPendingDeletion {
                    conversationPendingDeletion = nil
                    Task { await deleteConversation(conversation) }
                }
            }
        } message: {
            Text("The message history on this phone is removed. The peer keeps their copy.")
        }
        .confirmationDialog(
            channelConversationPendingDeletion.map { "Leave “\($0.channel.title)” chat?" } ?? "",
            isPresented: Binding(
                get: { channelConversationPendingDeletion != nil },
                set: { if !$0 { channelConversationPendingDeletion = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Leave Conversation", role: .destructive) {
                if let conversation = channelConversationPendingDeletion {
                    channelConversationPendingDeletion = nil
                    Task { await channelActions.delete(conversation) }
                }
            }
        } message: {
            Text("The messages on this phone are removed. You stay in the channel, and a new message opens this conversation again.")
        }
        .sheet(item: $presentedSheet) { sheet in
            NavigationStack {
                switch sheet {
                case .peerImport:
                    NodeImportView(
                        inspectPeerIdentity: inspectPeerIdentity,
                        save: { preview, details, startConversation in
                            let conversation = await savePeer(preview, details, startConversation)
                            presentedSheet = nil
                            if startConversation {
                                openedConversation = conversation
                            }
                        }
                    )
                case .channelChooser:
                    ChannelChatChooserView(
                        channels: channelsWithoutConversation,
                        actions: channelManagementActions,
                        start: { channel in
                            presentedSheet = nil
                            openedChannelConversation = await channelActions.start(channel)
                        },
                        startAfterJoin: { preview in
                            presentedSheet = nil
                            openedChannelConversation = await channelActions.startAfterJoin(preview)
                        }
                    )
                }
            }
        }
    }

    private var isSearching: Bool {
        !searchText.trimmingCharacters(in: .whitespaces).isEmpty
    }

    /// What the query finds, in the order it is most likely wanted:
    /// conversations that already exist, then the peers and channels one could
    /// be started with.
    ///
    /// Somewhere the user already talks is almost always what they were
    /// reaching for, so those rows come first and look exactly as they do in
    /// the list proper. Everything below them is an offer to start something,
    /// which is the part the list itself cannot help with.
    ///
    /// Peer results span the transient tier the Peers list hides: a node heard
    /// over the air is reachable, so it is findable. The phone's own companion
    /// radio is left out; it is hardware, not a correspondent.
    @ViewBuilder
    private var searchResults: some View {
        let existing = items.filter { matchesSearch($0) }
        let startablePeers = peers
            .filter { peer in
                !peer.isUlcpDevice
                    && peer.matches(searchQuery: searchText)
                    && existingConversation(with: peer) == nil
            }
            .sorted {
                let comparison = $0.displayName.localizedCaseInsensitiveCompare($1.displayName)
                if comparison != .orderedSame { return comparison == .orderedAscending }
                return $0.id < $1.id
            }
        let startableChannels = channelsWithoutConversation
            .filter { $0.matches(searchQuery: searchText) }
            .sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        let savedPeers = startablePeers.filter(\.isSaved)
        let discoveredPeers = startablePeers.filter { !$0.isSaved }

        if existing.isEmpty && startablePeers.isEmpty && startableChannels.isEmpty {
            Section {
                Text("Nothing matches this search.")
                    .foregroundStyle(.secondary)
            }
        }
        if !existing.isEmpty {
            // Ordered as the list orders itself: most recent activity first.
            Section("Conversations") {
                ForEach(existing) { item in
                    NavigationLink(value: item.id) {
                        ConversationRow(item: item)
                    }
                }
            }
        }
        if !savedPeers.isEmpty {
            Section("Peers") {
                ForEach(savedPeers) { peer in peerSearchRow(peer) }
            }
        }
        if !startableChannels.isEmpty {
            Section {
                ForEach(startableChannels) { channel in channelSearchRow(channel) }
            } header: {
                Text("Channels")
            } footer: {
                Text("Joined, with no conversation open yet.")
            }
        }
        if !discoveredPeers.isEmpty {
            Section {
                ForEach(discoveredPeers) { peer in peerSearchRow(peer) }
            } header: {
                Text("Discovered nodes")
            } footer: {
                Text("Heard over the air but not saved. Opening a conversation with one works the same way.")
            }
        }
    }

    private func matchesSearch(_ item: ConversationListItem) -> Bool {
        switch item {
        case let .direct(conversation): conversation.peer.matches(searchQuery: searchText)
        case let .channel(conversation): conversation.channel.matches(searchQuery: searchText)
        }
    }

    private func peerSearchRow(_ peer: PeerSummary) -> some View {
        searchRow {
            Task { await openConversation(with: peer) }
        } label: {
            PeerAvatar(hint: peer.identity.hint, showsFavoriteStar: peer.isFavorite)
            VStack(alignment: .leading, spacing: 2) {
                Text(peer.displayName)
                    .foregroundStyle(.primary)
                Text(peer.identity.hint.text)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func channelSearchRow(_ channel: ChannelSummary) -> some View {
        searchRow {
            Task { await openConversation(in: channel) }
        } label: {
            ChannelAvatar(channel: channel, size: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text(channel.title)
                    .foregroundStyle(.primary)
                Text("\(channel.kindLabel) · \(channel.channelIDHex)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func searchRow<Label: View>(
        action: @escaping () -> Void,
        @ViewBuilder label: () -> Label
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 12) { label() }
                // A plain button is only as tappable as its label is wide,
                // which for a name and a subtitle is nowhere near the row.
                // Rows are tapped anywhere along them.
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }

    /// Open the conversation with a searched-for node, creating it when this
    /// is the first time. Creating is what makes the search useful, so it is
    /// not a separate confirmed step.
    private func openConversation(with peer: PeerSummary) async {
        var conversation = existingConversation(with: peer)
        if conversation == nil {
            // Creating can report failure after the row itself was written, so
            // look again rather than leaving the tap with nothing to show for
            // itself.
            conversation = await peerActions.startConversation?(peer)
                ?? existingConversation(with: peer)
        }
        guard let conversation else { return }
        searchText = ""
        openedConversation = conversation
    }

    /// The same for a joined channel. Searching one out is a request to talk
    /// in it, so the group chat is created the way joining through the compose
    /// menu creates one.
    private func openConversation(in channel: ChannelSummary) async {
        guard let conversation = await channelActions.start(channel) else { return }
        searchText = ""
        openedChannelConversation = conversation
    }

    private func existingConversation(with peer: PeerSummary) -> DirectConversationSummary? {
        conversations.first {
            $0.peer.identity.canonicalAddress == peer.identity.canonicalAddress
        }
    }

    /// Joined channels the user has no conversation in yet. Joining a channel
    /// does not start a chat, so these are the ones there is something to
    /// offer for.
    private var channelsWithoutConversation: [ChannelSummary] {
        let existing = Set(items.compactMap { item -> UUID? in
            if case let .channel(conversation) = item { return conversation.channel.id }
            return nil
        })
        return channels.filter { $0.joinedPhone && !existing.contains($0.id) }
    }

    /// What is waiting everywhere but here, for the pill on an open
    /// transcript's back button. The one being read is excluded because
    /// opening it is what marks it read, and a count that includes it would
    /// tick down under the reader.
    private func unreadCount(excluding itemID: String) -> Int {
        items.reduce(0) { total, item in
            item.id == itemID ? total : total + item.unreadCount
        }
    }

    private func binding(for itemID: String) -> Binding<ConversationListItem>? {
        guard let fallback = items.first(where: { $0.id == itemID }) else { return nil }
        return Binding(
            get: { items.first(where: { $0.id == itemID }) ?? fallback },
            set: { updated in
                // The list is derived state owned by the app root; a thread
                // view's local edit is republished by the reload that follows
                // the write it came from.
                guard case let .direct(conversation) = updated,
                      let index = conversations.firstIndex(where: { $0.id == conversation.id })
                else { return }
                conversations[index] = conversation
            }
        )
    }
}

/// Which way into a new conversation the user chose.
private enum NewConversationSheet: String, Identifiable {
    case peerImport
    case channelChooser

    var id: String { rawValue }
}

private struct ConversationRow: View {
    let item: ConversationListItem

    var body: some View {
        HStack(spacing: 12) {
            switch item {
            case let .direct(conversation):
                PeerAvatar(hint: conversation.peer.identity.hint)
            case let .channel(conversation):
                ChannelAvatar(channel: conversation.channel, size: 40)
            }
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(item.title)
                        .fontWeight(item.unreadCount > 0 ? .semibold : .regular)
                    if isMuted {
                        Image(systemName: "bell.slash")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                            .accessibilityLabel("Notifications off")
                    }
                    Spacer()
                    if let timestamp {
                        Text(timestamp)
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                    if item.unreadCount > 0 {
                        Circle()
                            .fill(Color.accentColor)
                            .frame(width: 9, height: 9)
                            .accessibilityLabel("\(item.unreadCount) unread")
                    }
                }
                Text(preview)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
    }

    private var isMuted: Bool {
        switch item {
        case let .channel(conversation): !conversation.channel.notificationsEnabled
        case let .direct(conversation): !conversation.notificationsEnabled
        }
    }

    private var timestamp: String? {
        guard let last = item.lastMessage, last.createdAtMilliseconds > 0 else { return nil }
        let date = Date(timeIntervalSince1970: Double(last.createdAtMilliseconds) / 1000)
        return date.formatted(.relative(presentation: .numeric, unitsStyle: .narrow))
    }

    private var preview: String {
        if !item.draftText.isEmpty {
            return "Draft: \(item.draftText)"
        }
        guard let last = item.lastMessage else { return "No messages yet" }
        if last.isDeleted { return "Message deleted" }
        if last.isOutbound { return "You: \(last.body)" }
        // In a group the body alone does not say who is talking.
        if case .channel = item {
            let sender = last.senderAddress.map { String($0.prefix(6)) }
                ?? last.senderHintLabel
                ?? "Unknown"
            return "\(sender): \(last.body)"
        }
        return last.body
    }
}

/// Reports which conversation transcript is on screen, so notification
/// presentation can suppress banners for messages the user is already
/// looking at. Injected from the app root; the transcript view reports its
/// own visibility so every navigation path (conversation list, network
/// peer sheet, programmatic opens) is covered.
struct VisibleConversationReporter: Sendable {
    var appeared: @Sendable (String) -> Void = { _ in }
    var disappeared: @Sendable (String) -> Void = { _ in }
}

extension EnvironmentValues {
    @Entry var visibleConversationReporter = VisibleConversationReporter()
    /// Reads a bounded slice of whichever transcript is open. In the
    /// environment rather than passed down, because a transcript is reached
    /// from several places — the conversations list, a peer's profile, a
    /// notification tap — and none of the views in between have any use for it.
    @Entry var transcriptLoader = TranscriptLoader.unavailable
    /// Opens the radio sheet from wherever a view found the radio to be what
    /// was missing. In the environment for the same reason as the loader: the
    /// sheet belongs to the app root, and none of the views between it and a
    /// composer that has nothing to send with has any use for it.
    @Entry var openRadioDetail: @MainActor () -> Void = {}
}
