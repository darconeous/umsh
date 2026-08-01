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
                        Button("Delete", systemImage: "trash", role: .destructive) {
                            switch item {
                            case let .direct(conversation):
                                conversationPendingDeletion = conversation
                            case let .channel(conversation):
                                channelConversationPendingDeletion = conversation
                            }
                        }
                    }
                }
            }
        }
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
                    peers: peers
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
                    peers: peers
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
                    peers: peers
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
        if case let .channel(conversation) = item {
            return !conversation.channel.notificationsEnabled
        }
        return false
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
}

/// Where the reader is in an open transcript, and what the last gesture has
/// already done.
///
/// Held by reference for the same reason the app root keeps its bookkeeping
/// that way: these change continuously while a finger is down, and none of them
/// is drawn. As view state, each write would invalidate a non-lazy stack of
/// hundreds of bubbles on every frame of a drag.
@MainActor
private final class TranscriptScrollState {
    /// Following the live edge is an explicit, sticky mode. Appending a row can
    /// temporarily increase the measured distance from the bottom before the
    /// compensating scroll runs; that layout change must not look like the user
    /// scrolled away. Only user-driven scrolling can leave follow mode.
    var followsLatestMessage = true
    var userIsScrolling = false
    var distanceFromBottom: CGFloat = 0
    var viewportHeight: CGFloat = 0
    var contentHeight: CGFloat = 0
    /// How far the viewport sits below the top of the content, kept for
    /// restoring the viewport arithmetically after the window is edited around
    /// it. Zero at rest at the top: measured in the same space as
    /// `ScrollPosition.scrollTo(y:)`, which counts from the content's top, not
    /// the inset-relative `contentOffset`.
    var offsetFromContentTop: CGFloat = 0
    /// How far the top of the window sits above the viewport. Derived rather
    /// than observed: one geometry reading feeds every distance.
    var distanceFromTop: CGFloat {
        max(0, contentHeight - viewportHeight - distanceFromBottom)
    }
    /// At most one automatic page per gesture, so a single long pull cannot
    /// walk backward through the whole history.
    var pagedThisGesture = false
    /// The transcript is at rest — no finger down, no momentum, no bounce.
    /// Only then does growing the content above the viewport leave the reader
    /// where they were: with a finger down the pan gesture owns the offset
    /// outright, and during deceleration or the rubber-band settle the system
    /// is animating toward a point in the *old* content — either way the
    /// prepended rows shove the viewport a page up the history. Pages that
    /// arrive while the transcript is moving wait in `pendingOlderPage`.
    var isSettled = true
    var pendingOlderPage: PendingOlderPage?

    /// A page of older rows read while the transcript was moving, with the
    /// cursor the window began at when it was requested — the proof it still
    /// belongs to this window when it is finally applied.
    struct PendingOlderPage {
        let page: TranscriptPage
        let front: ChatMessageCursor
    }
}

/// Both distances the transcript reacts to, read in one observation.
///
/// Whole points on every axis: sub-pixel measurement jitter feeding a
/// state-write → layout → state-write loop is what wedged this view before.
private struct TranscriptScrollMetrics: Equatable {
    let distanceFromBottom: CGFloat
    /// How far the reader has pulled past the top. Zero unless overscrolling.
    let overscrollAboveTop: CGFloat
    let viewportHeight: CGFloat
    let contentHeight: CGFloat
    let offsetFromContentTop: CGFloat
}

/// Which row to put back under the reader after the window grows above them.
/// The generation makes two restores to the same row distinct changes, so the
/// second one still fires.
private struct TranscriptRestoreAnchor: Equatable {
    var messageID: String?
    var generation = 0
    /// Carry on to the live edge once the anchor is in place. Set when
    /// returning from far up the history: landing just short of the end first
    /// gives the animation a short distance to travel instead of a jump
    /// through thousands of messages that were never loaded.
    var thenScrollToBottom = false

    func moved(to id: String?, thenScrollToBottom: Bool = false) -> TranscriptRestoreAnchor {
        TranscriptRestoreAnchor(
            messageID: id,
            generation: generation + 1,
            thenScrollToBottom: thenScrollToBottom
        )
    }
}

/// The marker at a window edge that has more behind it.
///
/// Fixed height whether or not it is spinning: this sits at the boundary a page
/// lands on, and a row that changes size there moves the content the scroll
/// restore is trying to hold still.
private struct TranscriptEdgeSpinner: View {
    let isLoading: Bool

    var body: some View {
        ProgressView()
            .opacity(isLoading ? 1 : 0)
            .frame(height: 28)
            .frame(maxWidth: .infinity)
    }
}

/// Offered when the window does not hold the newest messages, which is the one
/// state where scrolling down does not eventually arrive at the present.
private struct JumpToLatestButton: View {
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Label("Jump to Latest", systemImage: "arrow.down.to.line")
                .font(.footnote.weight(.medium))
                .padding(.horizontal, 12)
                .padding(.vertical, 7)
                .background(.regularMaterial, in: Capsule())
        }
        .buttonStyle(.plain)
        .padding(.bottom, 8)
        .shadow(radius: 3, y: 1)
    }
}

/// One open transcript, whichever kind of conversation it belongs to.
///
/// Direct chats and channel group chats differ in who is on the other end,
/// not in how a transcript behaves — scrolling, composing, editing, and
/// delivery all work the same — so they share this view and the channel case
/// adds only what a group needs: a sender over each inbound bubble, and a way
/// to ask an unidentified member who they are.
struct ConversationThreadView: View {
    private static let bottomAnchorID = "chat-transcript-bottom"

    // The hysteresis around follow mode; see `TranscriptScrollState`.
    private static let stopFollowingDistance: CGFloat = 360
    private static let resumeFollowingDistance: CGFloat = 240
    /// How far past the top the reader has to pull before the next page of
    /// history loads — far enough that it reads as asking for more, rather than
    /// as the bounce at the end of an ordinary flick.
    private static let edgePagingOverscroll: CGFloat = 48
    /// Approaching the bottom of a window that is not at the live edge loads
    /// forward, so reading back down to the present is continuous.
    private static let edgePagingDistanceFromBottom: CGFloat = 240
    /// How close to the top of the window the reader has to be for trimming
    /// its far end to be worth the correction it costs.
    private static let trimProximityToTop: CGFloat = 200
    private static let olderEdgeID = "chat-transcript-older-edge"
    private static let newerEdgeID = "chat-transcript-newer-edge"

    @Binding var conversation: ConversationListItem
    let radioSnapshot: RadioSnapshot
    let updateDraft: (Int64, String) async -> Void
    let updateChannelDraft: (Int64, String) async -> Void
    let sendMessage: (ConversationListItem, String) async -> MessageSendResult
    let messageActions: ChatMessageActions
    let peerActions: PeerActions
    let channelActions: ChannelConversationActions
    /// Channel management, for the channel sheet the group conversation's
    /// info sheet leads to.
    let channelManagementActions: ChannelActions
    /// Called when the transcript appears, so its unread badge clears at the
    /// moment the user actually looks at it.
    let markRead: (String) async -> Void
    /// The full conversation list, handed to the peer profile sheet so its
    /// own "Message" push lands on a real transcript instead of a blank
    /// destination.
    @Binding var conversations: [DirectConversationSummary]
    /// Every saved peer, for naming channel members: a member can be a peer
    /// this phone knows without a direct chat ever having been opened.
    let peers: [PeerSummary]

    @State private var draft: String
    @State private var showsConversationInfo = false
    @State private var showsBlockedReason = false
    @State private var sendFailureMessage: String?
    @State private var editingMessage: ChatMessageSummary?
    @State private var editDraft = ""
    @State private var deletingMessage: ChatMessageSummary?
    @State private var inspectedMember: ChannelMember?
    @State private var inspectedMessage: ChatMessageSummary?
    @Environment(\.visibleConversationReporter) private var visibleConversationReporter
    @Environment(\.transcriptLoader) private var transcriptLoader
    @State private var transcript = TranscriptWindow()
    /// Where the reader is, held by reference so that following a scroll costs
    /// nothing to draw. Every one of these changes many times per drag, and as
    /// view state each write would invalidate the transcript and re-diff every
    /// row in the window on every frame — none of them is something the
    /// transcript renders.
    @State private var scroll = TranscriptScrollState()
    /// Bumped by every change that should carry the reader to the live edge,
    /// and by nothing else. Follow is decided where the window is mutated
    /// rather than inferred from the result: a page of history arriving at the
    /// top and a message arriving at the bottom are indistinguishable as diffs,
    /// and only one of them means "scroll".
    @State private var scrollToBottomRequest = 0
    @State private var scrollToBottomScheduled = false
    /// Which row to put back under the reader after a page lands above them,
    /// and a counter so two restores to the same row still both fire.
    @State private var restoreAnchor = TranscriptRestoreAnchor()
    /// Programmatic offset control, used only to hold the viewport still while
    /// the window is edited around it. Never configured to track anything: the
    /// offset fields of a `ScrollPosition` are written by programmatic scrolls
    /// only, so this costs a state write per correction, not per scroll frame.
    @State private var scrollPosition = ScrollPosition()

    init(
        conversation: Binding<ConversationListItem>,
        radioSnapshot: RadioSnapshot,
        updateDraft: @escaping (Int64, String) async -> Void,
        updateChannelDraft: @escaping (Int64, String) async -> Void = { _, _ in },
        sendMessage: @escaping (ConversationListItem, String) async -> MessageSendResult,
        messageActions: ChatMessageActions = .unavailable,
        peerActions: PeerActions = .unavailable,
        channelActions: ChannelConversationActions = .unavailable,
        channelManagementActions: ChannelActions = .unavailable,
        markRead: @escaping (String) async -> Void = { _ in },
        conversations: Binding<[DirectConversationSummary]> = .constant([]),
        peers: [PeerSummary] = []
    ) {
        _conversation = conversation
        self.radioSnapshot = radioSnapshot
        self.updateDraft = updateDraft
        self.updateChannelDraft = updateChannelDraft
        self.sendMessage = sendMessage
        self.messageActions = messageActions
        self.peerActions = peerActions
        self.channelActions = channelActions
        self.channelManagementActions = channelManagementActions
        self.markRead = markRead
        _conversations = conversations
        self.peers = peers
        _draft = State(initialValue: conversation.wrappedValue.draftText)
    }

    /// The peer on the other end, for a direct conversation. A channel has
    /// members rather than a counterpart, so this is nil there and every
    /// peer-specific affordance keys off it.
    private var peer: PeerSummary? {
        if case let .direct(direct) = conversation { return direct.peer }
        return nil
    }

    private var channelConversation: ChannelConversationSummary? {
        if case let .channel(channel) = conversation { return channel }
        return nil
    }

    var body: some View {
        VStack(spacing: 0) {
            // Gated on the summary rather than the window: the summary knows
            // synchronously whether anything was ever said here, so a long
            // transcript does not flash "No messages yet" before its first
            // page lands.
            if conversation.lastMessage == nil {
                ContentUnavailableView {
                    Label("No messages yet", systemImage: "bubble.left")
                } description: {
                    Text(emptyStateDescription)
                }
                .frame(maxHeight: .infinity)
            } else if !transcript.hasLoadedOnce {
                // Hold the scroll view back until its first page exists.
                // `defaultScrollAnchor(.bottom)` positions content the scroll
                // view already has; given an empty stack that fills in a moment
                // later, it has nothing to anchor and the transcript opens at
                // the top of the window instead of at the newest message.
                ProgressView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        // A plain VStack, deliberately: LazyVStack re-measures
                        // rows as they enter the viewport, and combined with
                        // an animated scrollTo to a bottom anchor plus the
                        // geometry observer below, oscillating row heights
                        // can wedge the main thread in a layout loop (screen
                        // renders but touches never deliver). What keeps that
                        // affordable is the window: only a bounded slice of a
                        // conversation is ever built.
                        VStack(spacing: 10) {
                            // Fixed height, and always present when there is
                            // history behind the window: a row that changes
                            // size at the top edge while a page is landing
                            // fights the scroll restore below.
                            if transcript.hasOlder {
                                TranscriptEdgeSpinner(isLoading: transcript.isLoadingOlder)
                                    .id(Self.olderEdgeID)
                            }
                            let lastOutboundID = transcript.lastOutboundID
                            ForEach(transcript.rows) { item in
                                switch item {
                                case let .message(message):
                                    ChatMessageBubble(
                                        message: message,
                                        isMostRecentOutbound: message.id == lastOutboundID,
                                        // Only a group message needs to say
                                        // who sent it; a direct one has one
                                        // possible sender.
                                        senderLabel: isChannel && !message.isOutbound
                                            ? memberName(for: message)
                                            : nil,
                                        senderHint: isChannel && !message.isOutbound
                                            ? message.senderNodeHint
                                            : nil,
                                        onEdit: message.isOutbound && !message.isDeleted
                                            ? {
                                                editDraft = message.body
                                                editingMessage = message
                                            }
                                            : nil,
                                        onDelete: message.isOutbound && !message.isDeleted
                                            ? { deletingMessage = message }
                                            : nil,
                                        onShowDetails: { inspectedMessage = message },
                                        onShowSender: isChannel && !message.isOutbound
                                            ? { inspectedMember = member(for: message) }
                                            : nil
                                    )
                                    // Every bubble measures a UITextView, so
                                    // an unrelated invalidation (a radio
                                    // snapshot, a keystroke in the composer)
                                    // would otherwise re-measure the whole
                                    // non-lazy transcript.
                                    .equatable()
                                    .id(item.id)
                                case let .gap(_, count):
                                    GapPlaceholderBubble(count: count)
                                        .id(item.id)
                                }
                            }
                            if transcript.hasNewer {
                                TranscriptEdgeSpinner(isLoading: transcript.isLoadingNewer)
                                    .id(Self.newerEdgeID)
                            }
                            Color.clear
                                .frame(height: 1)
                                .id(Self.bottomAnchorID)
                        }
                        .padding()
                    }
                    .defaultScrollAnchor(.bottom)
                    // Keyboard show/hide resizes the container; keep the
                    // reader's distance from the bottom constant instead of
                    // the default top-anchored offset, which hides the
                    // newest messages behind the keyboard.
                    .defaultScrollAnchor(.bottom, for: .sizeChanges)
                    .scrollPosition($scrollPosition)
                    .onScrollGeometryChange(for: TranscriptScrollMetrics.self) { geometry in
                        // One observer for both edges. A second would be a
                        // second state write into the same layout pass, and
                        // whole-point granularity on both keeps sub-pixel
                        // measurement jitter out of a state-write → layout →
                        // state-write feedback loop.
                        TranscriptScrollMetrics(
                            distanceFromBottom: max(
                                0,
                                geometry.contentSize.height - geometry.visibleRect.maxY
                            ).rounded(),
                            overscrollAboveTop: max(
                                0,
                                -(geometry.contentOffset.y + geometry.contentInsets.top)
                            ).rounded(),
                            viewportHeight: geometry.containerSize.height.rounded(),
                            contentHeight: geometry.contentSize.height.rounded(),
                            offsetFromContentTop: (geometry.contentOffset.y
                                + geometry.contentInsets.top).rounded()
                        )
                    } action: { _, metrics in
                        scroll.distanceFromBottom = metrics.distanceFromBottom
                        updateFollowState(
                            distanceFromBottom: metrics.distanceFromBottom,
                            userDriven: scroll.userIsScrolling
                        )
                        respondToScroll(metrics, proxy: proxy)
                    }
                    .onScrollPhaseChange { _, phase in
                        switch phase {
                        case .tracking, .interacting, .decelerating:
                            scroll.isSettled = false
                            scroll.userIsScrolling = true
                            updateFollowState(
                                distanceFromBottom: scroll.distanceFromBottom,
                                userDriven: true
                            )
                        case .idle:
                            scroll.isSettled = true
                            scroll.userIsScrolling = false
                            // One page per gesture; a new gesture re-arms it.
                            scroll.pagedThisGesture = false
                            // Nothing is moving, so neither the prepend's
                            // restore nor the trim's has anything to fight.
                            // A prepend chains its own trim once its restore
                            // has landed, so only one of these runs here.
                            if !applyPendingOlderPage() {
                                trimTranscriptIfNeeded()
                            }
                        case .animating:
                            scroll.isSettled = false
                            scroll.userIsScrolling = false
                        }
                    }
                    .onChange(of: scrollToBottomRequest) { _, _ in
                        scheduleScrollToBottom(proxy, animated: transcript.hasLoadedOnce)
                    }
                    .onChange(of: restoreAnchor) { _, anchor in
                        guard let id = anchor.messageID else { return }
                        // After a page lands above the reader, put the row they
                        // were looking at back where it was. Never animated:
                        // this is a correction, not a movement. The hop lets
                        // SwiftUI measure the new rows before the target is
                        // resolved, the same deferral the bottom scroll uses.
                        DispatchQueue.main.async {
                            proxy.scrollTo(id, anchor: .top)
                            guard anchor.thenScrollToBottom else { return }
                            // Chained rather than requested alongside: issued
                            // together the two resolve in one tick and the
                            // pre-position wins, stopping the transcript short
                            // of the live edge it was asked to return to.
                            DispatchQueue.main.async {
                                withAnimation {
                                    proxy.scrollTo(Self.bottomAnchorID, anchor: .bottom)
                                }
                            }
                        }
                    }
                }
                .frame(maxHeight: .infinity)
                .overlay(alignment: .bottom) {
                    if transcript.hasNewer {
                        JumpToLatestButton { Task { await jumpToLatest() } }
                    }
                }
            }

            Divider()
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .bottom, spacing: 8) {
                    ZStack(alignment: .topLeading) {
                        HardwareAwareMessageEditor(
                            text: $draft,
                            onHardwareReturn: { Task { await send() } }
                        )
                        if draft.isEmpty {
                            Text("Message \(conversation.title)")
                                .foregroundStyle(.tertiary)
                                .padding(.horizontal, 9)
                                .padding(.vertical, 8)
                                .allowsHitTesting(false)
                        }
                    }
                    .background {
                        RoundedRectangle(cornerRadius: 6)
                            .stroke(Color(uiColor: .separator), lineWidth: 0.5)
                    }
                        .task(id: draft) {
                            try? await Task.sleep(for: .milliseconds(250))
                            guard !Task.isCancelled else { return }
                            switch conversation {
                            case let .direct(direct):
                                await updateDraft(direct.id, draft)
                            case let .channel(channel):
                                await updateChannelDraft(channel.id, draft)
                            }
                        }
                    Button("Send", systemImage: "arrow.up.circle.fill") {
                        Task { await send() }
                    }
                    .labelStyle(.iconOnly)
                    .font(.title2)
                    .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                if let blockedReason {
                    Label(blockedReason, systemImage: "exclamationmark.circle")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            .padding()
            .background(.bar)
        }
        .navigationTitle(conversation.title)
        .navigationBarTitleDisplayMode(.inline)
        // Keyed on the revision, so a reload that changed no messages here —
        // a peer heard, another conversation's traffic, this one being marked
        // read — costs nothing.
        .task(id: conversation.messageRevision) { await refreshTranscript() }
        .onAppear {
            visibleConversationReporter.appeared(conversation.conversationAddress)
            Task { await markRead(conversation.conversationAddress) }
        }
        .onDisappear {
            visibleConversationReporter.disappeared(conversation.conversationAddress)
            // Again on the way out: anything that arrived while the
            // transcript was on screen was seen, and must not leave a badge.
            Task { await markRead(conversation.conversationAddress) }
        }
        .toolbar {
            // The avatar replaces the plain title, as in Messages; tapping it
            // opens the conversation's own sheet, which is where the peer or
            // channel behind it is reached from. The navigation title above
            // still labels the back button and accessibility focus.
            ToolbarItem(placement: .principal) {
                Button {
                    showsConversationInfo = true
                } label: {
                    VStack(spacing: 1) {
                        if let peer {
                            PeerAvatar(hint: peer.identity.hint, diameter: 28)
                        } else if let channelConversation {
                            ChannelAvatar(channel: channelConversation.channel, size: 28)
                        }
                        Text(conversation.title)
                            .font(.caption2)
                            .foregroundStyle(.primary)
                            .lineLimit(1)
                    }
                }
                .buttonStyle(.plain)
                .accessibilityLabel("\(conversation.title) details")
            }
        }
        .sheet(isPresented: $showsConversationInfo) {
            NavigationStack {
                Group {
                    if case let .direct(direct) = conversation {
                        DirectConversationDetailView(
                            conversation: direct,
                            radioSnapshot: radioSnapshot,
                            conversations: $conversations,
                            peerActions: peerActions,
                            messageActions: messageActions,
                            updateDraft: updateDraft,
                            sendMessage: { conversation, body in
                                await sendMessage(.direct(conversation), body)
                            },
                            clearMessages: clearMessages,
                            countMessages: countMessages
                        )
                    } else if let channelConversation {
                        ChannelConversationDetailView(
                            conversation: channelConversation,
                            radioSnapshot: radioSnapshot,
                            channelActions: channelManagementActions,
                            setNotifications: channelActions.setNotifications,
                            clearMessages: clearMessages,
                            countMessages: countMessages
                        )
                    }
                }
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { showsConversationInfo = false }
                    }
                }
            }
        }
        .sheet(item: $inspectedMember) { member in
            NavigationStack {
                ChannelMemberSheet(
                    member: member,
                    knownPeer: memberPeer(for: member),
                    requestIdentity: channelConversation.map { conversation in
                        { hint in
                            await channelActions.requestMemberIdentity(conversation, hint)
                        }
                    },
                    dismiss: { inspectedMember = nil }
                )
            }
        }
        .sheet(item: $inspectedMessage) { message in
            NavigationStack {
                MessageDetailsSheet(message: message) { inspectedMessage = nil }
            }
        }
        .alert("Message not sent", isPresented: $showsBlockedReason) {
            Button("OK", role: .cancel) {}
        } message: {
            Text((sendFailureMessage ?? blockedReason ?? "The message could not be queued.") + " Your draft has been preserved.")
        }
        .sheet(item: $editingMessage) { message in
            MessageEditSheet(
                originalBody: message.body,
                text: $editDraft,
                save: { newBody in
                    editingMessage = nil
                    await edit(message, newBody: newBody)
                },
                cancel: { editingMessage = nil }
            )
        }
        .confirmationDialog(
            "Delete this message?",
            isPresented: Binding(
                get: { deletingMessage != nil },
                set: { if !$0 { deletingMessage = nil } }
            ),
            titleVisibility: .visible
        ) {
            Button("Delete for everyone", role: .destructive) {
                if let message = deletingMessage {
                    deletingMessage = nil
                    Task { await delete(message) }
                }
            }
        } message: {
            Text(deleteMessageWarning)
        }
    }

    private func edit(_ message: ChatMessageSummary, newBody: String) async {
        let body = newBody.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !body.isEmpty, body != message.body else { return }
        switch await messageActions.edit(conversation, message, body) {
        case let .sent(updated):
            conversation = updated
        case let .failed(reason):
            sendFailureMessage = reason
            showsBlockedReason = true
        }
    }

    private func delete(_ message: ChatMessageSummary) async {
        switch await messageActions.delete(conversation, message) {
        case let .sent(updated):
            conversation = updated
        case let .failed(reason):
            sendFailureMessage = reason
            showsBlockedReason = true
        }
    }

    /// Bring the window up to date with storage.
    ///
    /// What "up to date" means depends on where the reader is. Following the
    /// live edge, the window *slides* there — a re-read of the extent it
    /// already holds would strand a follower behind a batch that landed more
    /// messages than the window has slack for. Reading history, the extent is
    /// re-read in place instead, so edits, deletions and delivery changes
    /// appear without the ground moving.
    private func refreshTranscript() async {
        let revision = conversation.messageRevision
        guard transcript.loadedRevision != revision else { return }
        let address = conversation.conversationAddress

        guard transcript.hasLoadedOnce, let oldest = transcript.oldestCursor else {
            let page = await transcriptLoader.newest(address, TranscriptWindow.pageSize)
            guard !Task.isCancelled else { return }
            // The scroll view is built for the first time around this content,
            // so its bottom anchor opens on the newest message with no scroll
            // command to race the layout of a whole page of bubbles.
            transcript.replace(with: page, revision: revision)
            await fillViewportIfShort()
            return
        }

        if scroll.followsLatestMessage && !transcript.hasNewer {
            let page = await transcriptLoader.newest(address, TranscriptWindow.pageSize)
            guard !Task.isCancelled else { return }
            transcript.replace(with: page, revision: revision)
            scrollToBottomRequest += 1
            return
        }

        // Re-read exactly what is held. With unloaded messages already beyond
        // the window, asking for slack would creep the bottom edge forward on
        // every refresh with rows the reader never asked to see.
        let slack = transcript.hasNewer ? 0 : 32
        let page = await transcriptLoader.newer(
            address,
            oldest,
            true,
            min(transcript.messages.count + slack, TranscriptWindow.capacity)
        )
        guard !Task.isCancelled else { return }
        transcript.replace(with: page, revision: revision)
    }

    /// Page backward until the content is at least tall enough to scroll.
    ///
    /// A window shorter than the viewport cannot be pulled, so the gesture that
    /// would load more history can never happen — the reader would be stuck
    /// with whatever the first page held and no way to ask for the rest.
    private func fillViewportIfShort() async {
        guard transcript.hasOlder, !transcript.isLoadingOlder else { return }
        guard scroll.contentHeight > 0, scroll.viewportHeight > 0 else { return }
        guard scroll.contentHeight < scroll.viewportHeight else { return }
        await loadOlder()
    }

    /// Take one page of older messages.
    ///
    /// No scroll correction: the rows land above the reader and
    /// `defaultScrollAnchor(.bottom, for: .sizeChanges)` holds the content
    /// already on screen where it is. Issuing a `scrollTo` here instead would
    /// land mid-gesture and cancel the very flick that asked for the page.
    ///
    /// The anchor only compensates when nothing else is steering the offset,
    /// though. A finger down, momentum, or the rubber-band settle all move the
    /// viewport toward a point in the *old* content, and a prepend applied
    /// under any of them dumps the reader a page up the history — so a page
    /// that arrives while the transcript is moving is parked and applied by
    /// the phase handler once it comes to rest.
    private func loadOlder() async {
        guard transcript.hasOlder, !transcript.isLoadingOlder else { return }
        guard let oldest = transcript.oldestCursor else { return }
        transcript.isLoadingOlder = true

        let page = await transcriptLoader.older(
            conversation.conversationAddress,
            oldest,
            TranscriptWindow.pageSize
        )
        // The window may have been replaced while the read was in flight
        // (jump-to-latest, focus). Rows older than a cursor the window no
        // longer starts at belong to nothing on screen.
        guard !Task.isCancelled, !page.messages.isEmpty,
              transcript.oldestCursor == oldest else {
            transcript.isLoadingOlder = false
            return
        }
        if scroll.isSettled {
            applyOlderPage(page)
        } else {
            scroll.pendingOlderPage = .init(page: page, front: oldest)
        }
    }

    /// Apply a page that arrived while the transcript was moving. Reports
    /// whether it did, since the restore it schedules has to finish before
    /// anything else may measure the reader's position.
    @discardableResult
    private func applyPendingOlderPage() -> Bool {
        guard let pending = scroll.pendingOlderPage else { return false }
        scroll.pendingOlderPage = nil
        guard transcript.oldestCursor == pending.front else {
            transcript.isLoadingOlder = false
            return false
        }
        applyOlderPage(pending.page)
        return true
    }

    private func applyOlderPage(_ page: TranscriptPage) {
        let offsetBefore = scroll.offsetFromContentTop
        let heightBefore = scroll.contentHeight
        var transaction = Transaction()
        transaction.disablesAnimations = true
        withTransaction(transaction) {
            transcript.prepend(page)
            transcript.isLoadingOlder = false
        }
        // However much the content grew above the viewport is exactly how far
        // the rows on screen moved down; putting the offset there is what
        // holds them still. Trimming waits for that to land: it measures where
        // the reader is, and until the restore runs that is the old position.
        restoreViewport(
            to: { heightAfter in offsetBefore + (heightAfter - heightBefore) },
            then: { trimTranscriptIfNeeded() }
        )
    }

    /// Put the viewport back over the rows it was showing after the window was
    /// edited around it.
    ///
    /// SwiftUI's scroll anchors do not compensate for content growing above a
    /// transcript resting at its top — the new rows land above offset zero and
    /// the viewport ends up a page back in the history — so the offset is
    /// restored arithmetically instead, from the one fact layout has to settle
    /// first: the content's new height. The hop waits for that layout;
    /// `target` then computes the offset that leaves the same rows on screen.
    /// Setting an absolute offset also cannot double-correct if an anchor did
    /// compensate.
    private func restoreViewport(
        attempt: Int = 0,
        to target: @escaping (_ contentHeightAfter: CGFloat) -> CGFloat,
        then completion: (() -> Void)? = nil
    ) {
        let heightBefore = scroll.contentHeight
        DispatchQueue.main.async {
            // The geometry observer reports the post-edit height once layout
            // runs. If it has not yet, give it another turn — but never stall
            // forever on an edit that happened not to change the height.
            if scroll.contentHeight == heightBefore, attempt < 3 {
                restoreViewport(attempt: attempt + 1, to: target, then: completion)
                return
            }
            var transaction = Transaction()
            transaction.disablesAnimations = true
            withTransaction(transaction) {
                scrollPosition.scrollTo(y: target(scroll.contentHeight))
            }
            guard let completion else { return }
            // One more turn, so whatever runs next reads the position this
            // scroll produced rather than the one it replaced.
            DispatchQueue.main.async(execute: completion)
        }
    }

    /// Give back the newest messages once the window has outgrown its budget.
    ///
    /// Deferred to a resting transcript on purpose: this shrinks the content
    /// below the reader, which the bottom scroll anchor answers by pulling
    /// everything up, so it needs a correction — and a correction is only
    /// invisible when nothing is moving.
    private func trimTranscriptIfNeeded() {
        guard transcript.exceedsCapacity, !transcript.isLoadingOlder else { return }
        // Only while the reader is up near the top, which is where paging
        // backward leaves them: everything trimmed is then far below the
        // viewport. An over-capacity window is not worth touching someone's
        // reading position for, and the next pause at the top collects it.
        guard scroll.distanceFromTop <= Self.trimProximityToTop else { return }
        let offsetBefore = scroll.offsetFromContentTop
        var transaction = Transaction()
        transaction.disablesAnimations = true
        var trimmed = false
        withTransaction(transaction) { trimmed = transcript.trimToCapacity() }
        guard trimmed else { return }
        // Content removed below the viewport moves nothing above it: the
        // right offset afterwards is the one it already had.
        restoreViewport { _ in offsetBefore }
    }

    /// Take one page of newer messages. Nothing to restore: the rows land below
    /// the viewport, where they move nothing already on screen.
    private func loadNewer() async {
        guard transcript.hasNewer, !transcript.isLoadingNewer else { return }
        guard let newest = transcript.newestCursor else { return }
        transcript.isLoadingNewer = true
        defer { transcript.isLoadingNewer = false }

        let page = await transcriptLoader.newer(
            conversation.conversationAddress,
            newest,
            false,
            TranscriptWindow.pageSize
        )
        guard !Task.isCancelled else { return }
        transcript.append(page)
    }

    /// Return to the live edge from a window that does not hold it.
    ///
    /// The window is replaced rather than paged forward — the reader may be
    /// thousands of messages back — but it is not cut to the bottom either.
    /// Pre-positioning just above the newest messages and then animating home
    /// reads as arriving somewhere, which is what the reader asked for.
    private func landAtLiveEdge() async {
        let page = await transcriptLoader.newest(
            conversation.conversationAddress,
            TranscriptWindow.pageSize
        )
        guard !Task.isCancelled, !page.messages.isEmpty else { return }
        var transaction = Transaction()
        transaction.disablesAnimations = true
        withTransaction(transaction) {
            transcript.replace(with: page, revision: conversation.messageRevision)
        }
        scroll.followsLatestMessage = true
        // Put the reader just short of the end, then glide in. The two steps
        // are chained through the restore handler rather than issued together:
        // as separate requests they resolve in the same run-loop tick and the
        // pre-position wins, leaving the transcript stopped short.
        let runway = 12
        if page.messages.count > runway {
            restoreAnchor = restoreAnchor.moved(
                to: page.messages[page.messages.count - runway].id,
                thenScrollToBottom: true
            )
        } else {
            scrollToBottomRequest += 1
        }
    }

    private func jumpToLatest() async {
        await landAtLiveEdge()
    }

    /// Open the window on a particular message, for a search result that has to
    /// be shown in its context rather than at the end of the conversation.
    func focus(messageID: String) async {
        guard let page = await transcriptLoader.around(
            conversation.conversationAddress,
            messageID,
            TranscriptWindow.focusRadius
        ) else { return }
        guard !Task.isCancelled else { return }
        // Off before the window is published: its bottom is not the live edge,
        // so nothing here should be chasing it.
        scroll.followsLatestMessage = false
        var transaction = Transaction()
        transaction.disablesAnimations = true
        withTransaction(transaction) {
            transcript.replace(with: page, revision: conversation.messageRevision)
        }
        restoreAnchor = restoreAnchor.moved(to: messageID)
    }

    /// React to where the reader has got to: pull past an edge and the page
    /// behind it loads.
    private func respondToScroll(_ metrics: TranscriptScrollMetrics, proxy: ScrollViewProxy) {
        scroll.viewportHeight = metrics.viewportHeight
        scroll.contentHeight = metrics.contentHeight
        scroll.offsetFromContentTop = metrics.offsetFromContentTop
        guard scroll.userIsScrolling, !scroll.pagedThisGesture else { return }
        if metrics.overscrollAboveTop >= Self.edgePagingOverscroll, transcript.hasOlder {
            scroll.pagedThisGesture = true
            Task { await loadOlder() }
        } else if transcript.hasNewer,
                  metrics.distanceFromBottom <= Self.edgePagingDistanceFromBottom {
            scroll.pagedThisGesture = true
            Task { await loadNewer() }
        }
    }

    /// At most one scroll command per run-loop tick. After a send, both the
    /// messages change and the explicit scroll request fire together; two
    /// simultaneous animated scrollTo calls fight each other and churn
    /// layout while the transcript is still settling.
    private func scheduleScrollToBottom(_ proxy: ScrollViewProxy, animated: Bool = true) {
        guard !scrollToBottomScheduled else { return }
        scrollToBottomScheduled = true
        DispatchQueue.main.async {
            scrollToBottomScheduled = false
            if animated {
                withAnimation {
                    proxy.scrollTo(Self.bottomAnchorID, anchor: .bottom)
                }
            } else {
                proxy.scrollTo(Self.bottomAnchorID, anchor: .bottom)
            }
        }
    }

    private func updateFollowState(distanceFromBottom: CGFloat, userDriven: Bool) {
        // A window with messages beyond it has no live edge to follow: reaching
        // its bottom is reaching the end of what is loaded, not the end of the
        // conversation, and re-arming here would chase a moving target.
        guard !transcript.hasNewer else {
            scroll.followsLatestMessage = false
            return
        }
        if distanceFromBottom <= Self.resumeFollowingDistance {
            scroll.followsLatestMessage = true
        } else if userDriven && distanceFromBottom >= Self.stopFollowingDistance {
            scroll.followsLatestMessage = false
        }
    }

    private func send() async {
        sendFailureMessage = nil
        let body = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !body.isEmpty else { return }
        guard blockedReason == nil else {
            showsBlockedReason = true
            return
        }
        switch await sendMessage(conversation, body) {
        case let .sent(updatedConversation):
            conversation = updatedConversation
            draft = ""
            if transcript.hasNewer {
                // Sent from up in the history, where the new message is not
                // even loaded. Bring the live edge in and land on it, rather
                // than scrolling to the bottom of a window that does not hold
                // what was just sent.
                await landAtLiveEdge()
            } else {
                // Sending is an explicit navigation to the new item, unlike a
                // passive update while reading older history.
                scroll.followsLatestMessage = true
                scrollToBottomRequest += 1
            }
        case let .failed(message):
            sendFailureMessage = message
            showsBlockedReason = true
        }
    }

    /// Erase this conversation's transcript, closing the sheet the action was
    /// taken from: what that sheet described is gone, and leaving it open
    /// would sit a "Clear All Messages" button over an empty conversation.
    private func clearMessages() async {
        showsConversationInfo = false
        await messageActions.clearMessages(conversation.conversationAddress)
    }

    private func countMessages() async -> Int {
        await messageActions.countMessages(conversation.conversationAddress)
    }

    private var isChannel: Bool { channelConversation != nil }

    private var emptyStateDescription: String {
        if let peer {
            return "Messages with \(peer.displayName) will appear here."
        }
        return "Messages sent to this channel by anyone holding its key will appear here."
    }

    private var deleteMessageWarning: String {
        if let peer {
            return "A deletion is broadcast to \(peer.displayName) and cannot be undone."
        }
        return "A deletion is broadcast to everyone in this channel and cannot be undone."
    }

    /// What to call whoever sent a group message, in descending order of
    /// authority: a peer we know, then the name they attached to the message,
    /// then their address, then the bare hint.
    ///
    /// The message-borne name is the sender's own unverified claim — the
    /// channel MIC proves membership, not identity, so anyone with the key
    /// can write any name there. It is useful precisely when we know nothing
    /// else, and must never displace a name this phone established itself.
    private func memberName(for message: ChatMessageSummary) -> String {
        if let address = message.senderAddress, let peer = knownPeer(address: address) {
            return peer.displayName
        }
        if let handle = message.senderHandle, !handle.isEmpty { return handle }
        if let address = message.senderAddress { return String(address.prefix(10)) }
        guard let hint = message.senderHintLabel else { return "Unknown member" }
        return "Member \(hint)"
    }

    /// A peer this phone has saved, whether or not a direct chat with them
    /// exists.
    private func knownPeer(address: String) -> PeerSummary? {
        peers.first { $0.identity.canonicalAddress == address }
            ?? conversations.first { $0.peer.identity.canonicalAddress == address }?.peer
    }

    private func member(for message: ChatMessageSummary) -> ChannelMember? {
        guard let hint = message.senderHint else { return nil }
        return ChannelMember(
            hint: hint,
            address: message.senderAddress,
            handle: message.senderHandle,
            displayName: memberName(for: message)
        )
    }

    private func memberPeer(for member: ChannelMember) -> PeerSummary? {
        guard let address = member.address else { return nil }
        return knownPeer(address: address)
    }

    private var blockedReason: String? {
        guard radioSnapshot.linkState == .attached || radioSnapshot.linkState == .ready else {
            return "Connect a configured companion radio to send."
        }
        guard radioSnapshot.hostState == .matchesCurrentIdentity else {
            return "Set up this radio for the current phone identity to send."
        }
        return nil
    }
}

/// UITextView keeps the software keyboard's Return key as a newline while
/// making physical-keyboard Return a send shortcut. SwiftUI's multiline
/// TextField consumes physical Return before `onKeyPress`, so it cannot
/// reliably express this distinction on its own.
private struct HardwareAwareMessageEditor: UIViewRepresentable {
    @Binding var text: String
    let onHardwareReturn: () -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(text: $text)
    }

    func makeUIView(context: Context) -> HardwareAwareTextView {
        let textView = HardwareAwareTextView()
        textView.delegate = context.coordinator
        textView.backgroundColor = .clear
        textView.font = .preferredFont(forTextStyle: .body)
        textView.adjustsFontForContentSizeCategory = true
        textView.textContainerInset = UIEdgeInsets(top: 7, left: 4, bottom: 7, right: 4)
        textView.isScrollEnabled = true
        textView.onHardwareReturn = onHardwareReturn
        return textView
    }

    func updateUIView(_ textView: HardwareAwareTextView, context: Context) {
        if textView.text != text {
            textView.text = text
        }
        textView.onHardwareReturn = onHardwareReturn
    }

    func sizeThatFits(
        _ proposal: ProposedViewSize,
        uiView: HardwareAwareTextView,
        context: Context
    ) -> CGSize? {
        guard let width = proposal.width else { return nil }
        let measured = uiView.sizeThatFits(
            CGSize(width: width, height: .greatestFiniteMagnitude)
        )
        let lineHeight = uiView.font?.lineHeight ?? 17
        let minimumHeight = lineHeight + 14
        let maximumHeight = lineHeight * 6 + 14
        return CGSize(
            width: width,
            height: min(max(measured.height, minimumHeight), maximumHeight)
        )
    }

    final class Coordinator: NSObject, UITextViewDelegate {
        @Binding private var text: String

        init(text: Binding<String>) {
            _text = text
        }

        func textViewDidChange(_ textView: UITextView) {
            text = textView.text
        }
    }
}

private final class HardwareAwareTextView: UITextView {
    var onHardwareReturn: (() -> Void)?

    override var keyCommands: [UIKeyCommand]? {
        let send = UIKeyCommand(
            input: "\r",
            modifierFlags: [],
            action: #selector(sendFromHardwareKeyboard)
        )
        send.wantsPriorityOverSystemBehavior = true

        let newline = UIKeyCommand(
            input: "\r",
            modifierFlags: [.shift],
            action: #selector(insertNewlineFromHardwareKeyboard)
        )
        newline.wantsPriorityOverSystemBehavior = true
        return [send, newline]
    }

    @objc private func sendFromHardwareKeyboard() {
        onHardwareReturn?()
    }

    @objc private func insertNewlineFromHardwareKeyboard() {
        insertText("\n")
    }
}

private struct MessageEditSheet: View {
    let originalBody: String
    @Binding var text: String
    let save: (String) async -> Void
    let cancel: () -> Void

    @FocusState private var editorFocused: Bool

    private var trimmed: String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    var body: some View {
        NavigationStack {
            TextEditor(text: $text)
                .focused($editorFocused)
                .padding(8)
                .navigationTitle("Edit Message")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { cancel() }
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Save") {
                            Task { await save(trimmed) }
                        }
                        .disabled(trimmed.isEmpty || trimmed == originalBody)
                    }
                }
                .onAppear { editorFocused = true }
        }
        .presentationDetents([.medium, .large])
    }
}

/// A placeholder bubble for a known sequence gap: an indeterminate spinner in
/// an inbound-styled bubble, holding the missing message's ordered position
/// until a repair fills or resolves it. One bubble stands for a whole run of
/// adjacent gaps.
private struct GapPlaceholderBubble: View {
    let count: Int

    var body: some View {
        HStack(alignment: .bottom) {
            ProgressView()
                .controlSize(.small)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
                .background(Color.secondary.opacity(0.14))
                .clipShape(RoundedRectangle(cornerRadius: 16))
                .accessibilityLabel(
                    count > 1 ? "Waiting for \(count) missing messages" : "Waiting for a missing message"
                )
            Spacer(minLength: 44)
        }
    }
}

private struct ChatMessageBubble: View, @MainActor Equatable {
    let message: ChatMessageSummary
    /// Quiet states (Delivered/Sent) only annotate the newest outbound
    /// message; older ones would repeat the same information on every row.
    var isMostRecentOutbound = false
    /// Who sent this, in a group conversation. Absent for a direct chat,
    /// where every inbound bubble has the same sender.
    var senderLabel: String?
    /// The sender's hint, which is what their avatar is derived from.
    var senderHint: MeshNodeHint?
    var onEdit: (() -> Void)?
    var onDelete: (() -> Void)?
    var onShowDetails: (() -> Void)?
    var onShowSender: (() -> Void)?

    @State private var showsOriginalBody = false

    /// The closures are not comparable, but they are derived from the message
    /// and only their presence changes what the menu offers; a bubble whose
    /// message and delivery annotation are unchanged renders identically.
    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.message == rhs.message
            && lhs.isMostRecentOutbound == rhs.isMostRecentOutbound
            && lhs.senderLabel == rhs.senderLabel
            && lhs.senderHint == rhs.senderHint
            && (lhs.onEdit == nil) == (rhs.onEdit == nil)
            && (lhs.onDelete == nil) == (rhs.onDelete == nil)
    }

    private var isFailed: Bool {
        message.deliveryState?.lowercased() == "failed"
    }

    var body: some View {
        if message.isDeleted {
            // A tombstone, not a message: no bubble, no menu, no captions.
            Text(message.isOutbound ? "You deleted a message" : "Message deleted")
                .font(.caption)
                .italic()
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: message.isOutbound ? .trailing : .leading)
                .padding(.horizontal, 8)
        } else if message.isUnavailable {
            // A gap whose repair failed: a subtle loss marker in its slot.
            Text("Message unavailable")
                .font(.caption)
                .italic()
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 8)
        } else {
            HStack(alignment: .bottom) {
                if message.isOutbound { Spacer(minLength: 44) }
                VStack(alignment: message.isOutbound ? .trailing : .leading, spacing: 2) {
                    if let senderLabel {
                        Button {
                            onShowSender?()
                        } label: {
                            HStack(spacing: 4) {
                                // The same deterministic avatar this member
                                // gets everywhere else: derived from the hint
                                // their frames carry, so it is stable before
                                // anyone knows who they are.
                                if let senderHint {
                                    PeerAvatar(hint: senderHint, diameter: 16)
                                }
                                Text(senderLabel)
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                        }
                        .buttonStyle(.plain)
                        .disabled(onShowSender == nil)
                        .padding(.horizontal, 4)
                    }
                    HStack(spacing: 6) {
                        bubble
                        if isFailed {
                            Image(systemName: "exclamationmark.circle.fill")
                                .font(.title3)
                                .foregroundStyle(.red)
                                .accessibilityLabel("Message not delivered")
                        }
                    }
                    if let caption {
                        Text(caption)
                            .font(.caption2)
                            .fontWeight(isFailed ? .semibold : .regular)
                            .foregroundStyle(isFailed ? AnyShapeStyle(.red) : AnyShapeStyle(.secondary))
                            .padding(.horizontal, 4)
                    }
                }
                if !message.isOutbound { Spacer(minLength: 44) }
            }
        }
    }

    private var bubble: some View {
        SelectableMessageText(text: message.body)
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(message.isOutbound ? Color.accentColor.opacity(0.18) : Color.secondary.opacity(0.14))
            .clipShape(RoundedRectangle(cornerRadius: 16))
            .contentShape(.contextMenuPreview, RoundedRectangle(cornerRadius: 16))
            .contextMenu {
                Button("Copy", systemImage: "doc.on.doc") {
                    UIPasteboard.general.string = message.body
                }
                if message.originalBody != nil {
                    Button("View Original", systemImage: "clock.arrow.circlepath") {
                        showsOriginalBody = true
                    }
                }
                if let onEdit {
                    Button("Edit", systemImage: "pencil", action: onEdit)
                }
                if let onShowDetails {
                    Button("Details", systemImage: "info.circle", action: onShowDetails)
                }
                if let onDelete {
                    Button("Delete", systemImage: "trash", role: .destructive, action: onDelete)
                }
            }
            .alert("Original Message", isPresented: $showsOriginalBody) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(message.originalBody ?? "")
            }
    }

    private var caption: String? {
        var parts: [String] = []
        if message.isEdited { parts.append("Edited") }
        if message.isReceivedLate { parts.append("Received late") }
        if message.isOutbound, let label = deliveryLabel { parts.append(label) }
        return parts.isEmpty ? nil : parts.joined(separator: " · ")
    }

    private var deliveryLabel: String? {
        guard let state = message.deliveryState else { return nil }
        switch state.lowercased() {
        case "failed": return "Not Delivered"
        case "acknowledged":
            // A recovery from failure is noteworthy on its own row, unlike a
            // routine "Delivered" which only annotates the newest message.
            if message.isDeliveredLate { return "Delivered Late" }
            return isMostRecentOutbound ? "Delivered" : nil
        case "sent": return isMostRecentOutbound ? "Sent" : nil
        default: return "Sending…"
        }
    }
}

/// UITextView-backed message body: pointer-driven selection (mouse or
/// trackpad drag, double-click for a word) works like any ordinary text,
/// which SwiftUI's `.textSelection(.enabled)` does not provide inside a
/// scroll view. Long presses are left to the bubble's context menu, as in
/// Messages; touch users select through the menu or a double tap.
private struct SelectableMessageText: UIViewRepresentable {
    let text: String

    func makeUIView(context: Context) -> BubbleTextView {
        let view = BubbleTextView()
        view.isEditable = false
        view.isSelectable = true
        view.isScrollEnabled = false
        view.backgroundColor = .clear
        view.textContainerInset = .zero
        view.textContainer.lineFragmentPadding = 0
        view.font = .preferredFont(forTextStyle: .body)
        view.adjustsFontForContentSizeCategory = true
        view.dataDetectorTypes = .link
        return view
    }

    func updateUIView(_ view: BubbleTextView, context: Context) {
        if view.text != text {
            view.text = text
        }
    }

    func sizeThatFits(
        _ proposal: ProposedViewSize,
        uiView: BubbleTextView,
        context: Context
    ) -> CGSize? {
        var width = proposal.width ?? .greatestFiniteMagnitude
        guard width > 0 else { return nil }
        if width.isFinite {
            // Propose whole points. Fractional widths make UITextView's
            // wrapping non-reproducible across layout passes, and any
            // non-convergent answer here can wedge SwiftUI in a layout loop.
            width = width.rounded(.down)
        }
        let measured = uiView.sizeThatFits(
            CGSize(width: width, height: .greatestFiniteMagnitude)
        )
        return CGSize(
            width: min(measured.width.rounded(.up), width),
            height: measured.height.rounded(.up)
        )
    }
}

final class BubbleTextView: UITextView {
    override func gestureRecognizerShouldBegin(
        _ gestureRecognizer: UIGestureRecognizer
    ) -> Bool {
        // Long press must fall through to the SwiftUI context menu on the
        // bubble; only pointer and double-tap selection stay on the text.
        if gestureRecognizer is UILongPressGestureRecognizer { return false }
        return super.gestureRecognizerShouldBegin(gestureRecognizer)
    }
}
