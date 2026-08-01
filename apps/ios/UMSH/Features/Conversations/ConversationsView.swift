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
    var channelImportActions: ChannelActions = .unavailable
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

    var body: some View {
        List {
            if items.isEmpty {
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
                        actions: channelImportActions,
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
        guard let last = item.messages.last, last.createdAtMilliseconds > 0 else { return nil }
        let date = Date(timeIntervalSince1970: Double(last.createdAtMilliseconds) / 1000)
        return date.formatted(.relative(presentation: .numeric, unitsStyle: .narrow))
    }

    private var preview: String {
        if !item.draftText.isEmpty {
            return "Draft: \(item.draftText)"
        }
        guard let last = item.messages.last else { return "No messages yet" }
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
}

/// A transcript row: a real message, or a collapsed run of one-or-more
/// consecutive gap placeholders shown as a single spinner.
private enum TranscriptItem: Identifiable {
    case message(ChatMessageSummary)
    case gap(id: String, count: Int)

    var id: String {
        switch self {
        case let .message(message): return message.id
        case let .gap(id, _): return "gap:\(id)"
        }
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

    /// Collapse consecutive gap placeholders into a single `.gap` item so no
    /// two spinner bubbles ever render adjacently. The run's stable id is its
    /// first placeholder handle, keeping SwiftUI diffing cheap.
    fileprivate static func transcriptItems(_ messages: [ChatMessageSummary]) -> [TranscriptItem] {
        var items: [TranscriptItem] = []
        var runStart: String?
        var runCount = 0
        func flushGap() {
            if let start = runStart, runCount > 0 {
                items.append(.gap(id: start, count: runCount))
            }
            runStart = nil
            runCount = 0
        }
        for message in messages {
            if message.isGapPlaceholder {
                // A placeholder the engine deleted was filled by an edit (the
                // missing frame was an edit, not a standalone bubble): it no
                // longer holds a slot, so drop it. Any still-pending neighbors
                // stay contiguous and keep the collapsed spinner.
                if message.isDeleted { continue }
                if runStart == nil { runStart = message.id }
                runCount += 1
            } else {
                flushGap()
                items.append(.message(message))
            }
        }
        flushGap()
        return items
    }
    // Following the live edge is an explicit, sticky mode. Appending a row can
    // temporarily increase the measured distance from the bottom before the
    // compensating scroll runs; that layout change must not look like the user
    // scrolled away. Only user-driven scrolling can leave follow mode.
    private static let stopFollowingDistance: CGFloat = 360
    private static let resumeFollowingDistance: CGFloat = 240

    @Binding var conversation: ConversationListItem
    let radioSnapshot: RadioSnapshot
    let updateDraft: (Int64, String) async -> Void
    let updateChannelDraft: (Int64, String) async -> Void
    let sendMessage: (ConversationListItem, String) async -> MessageSendResult
    let messageActions: ChatMessageActions
    let peerActions: PeerActions
    let channelActions: ChannelConversationActions
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
    @State private var showsPeerProfile = false
    @State private var showsBlockedReason = false
    @State private var sendFailureMessage: String?
    @State private var editingMessage: ChatMessageSummary?
    @State private var editDraft = ""
    @State private var deletingMessage: ChatMessageSummary?
    @State private var inspectedMember: ChannelMember?
    @State private var inspectedMessage: ChatMessageSummary?
    @Environment(\.visibleConversationReporter) private var visibleConversationReporter
    @State private var followsLatestMessage = true
    @State private var userIsScrollingTranscript = false
    @State private var transcriptDistanceFromBottom: CGFloat = 0
    @State private var outgoingScrollRequest = 0
    @State private var scrollToBottomScheduled = false

    init(
        conversation: Binding<ConversationListItem>,
        radioSnapshot: RadioSnapshot,
        updateDraft: @escaping (Int64, String) async -> Void,
        updateChannelDraft: @escaping (Int64, String) async -> Void = { _, _ in },
        sendMessage: @escaping (ConversationListItem, String) async -> MessageSendResult,
        messageActions: ChatMessageActions = .unavailable,
        peerActions: PeerActions = .unavailable,
        channelActions: ChannelConversationActions = .unavailable,
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
            if conversation.messages.isEmpty {
                ContentUnavailableView {
                    Label("No messages yet", systemImage: "bubble.left")
                } description: {
                    Text(emptyStateDescription)
                }
                .frame(maxHeight: .infinity)
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        // A plain VStack, deliberately: LazyVStack re-measures
                        // rows as they enter the viewport, and combined with
                        // an animated scrollTo to a bottom anchor plus the
                        // geometry observer below, oscillating row heights
                        // can wedge the main thread in a layout loop (screen
                        // renders but touches never deliver).
                        VStack(spacing: 10) {
                            let lastOutboundID = conversation.messages.last(
                                where: { $0.isOutbound && !$0.isDeleted }
                            )?.id
                            ForEach(Self.transcriptItems(conversation.messages)) { item in
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
                    .onAppear {
                        guard !conversation.messages.isEmpty else { return }
                        // Initial presentation always opens at the newest
                        // message. Conditional auto-follow applies only after
                        // the reader has had a chance to scroll upward.
                        scheduleScrollToBottom(proxy, animated: false)
                    }
                    .onScrollGeometryChange(for: CGFloat.self) { geometry in
                        // Whole-point granularity: sub-pixel measurement
                        // jitter must not feed a state-write → layout →
                        // state-write feedback loop.
                        max(0, geometry.contentSize.height - geometry.visibleRect.maxY)
                            .rounded()
                    } action: { _, distance in
                        transcriptDistanceFromBottom = distance
                        updateFollowState(
                            distanceFromBottom: distance,
                            userDriven: userIsScrollingTranscript
                        )
                    }
                    .onScrollPhaseChange { _, phase in
                        switch phase {
                        case .tracking, .interacting, .decelerating:
                            userIsScrollingTranscript = true
                            updateFollowState(
                                distanceFromBottom: transcriptDistanceFromBottom,
                                userDriven: true
                            )
                        case .idle, .animating:
                            userIsScrollingTranscript = false
                        }
                    }
                    .onChange(of: conversation.messages) { _, messages in
                        guard !messages.isEmpty, followsLatestMessage else { return }
                        // Follow inserts as well as live body/delivery-state
                        // mutations. Deferring lets SwiftUI finish measuring
                        // the changed final bubble before targeting the edge.
                        scheduleScrollToBottom(proxy)
                    }
                    .onChange(of: outgoingScrollRequest) { _, _ in
                        // Sending is an explicit navigation to the new item,
                        // unlike a passive update while reading older history.
                        followsLatestMessage = true
                        scheduleScrollToBottom(proxy)
                    }
                }
                .frame(maxHeight: .infinity)
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
            // opens the peer's profile. The navigation title above still
            // labels the back button and accessibility focus.
            ToolbarItem(placement: .principal) {
                Button {
                    showsPeerProfile = true
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
        .sheet(isPresented: $showsPeerProfile) {
            NavigationStack {
                Group {
                    if let peer {
                        PeerDetailView(
                            peer: peer,
                            radioSnapshot: .constant(radioSnapshot),
                            conversations: $conversations,
                            actions: peerActions,
                            updateDraft: updateDraft,
                            sendMessage: { conversation, body in
                                await sendMessage(.direct(conversation), body)
                            },
                            messageActions: messageActions
                        )
                    } else if let channelConversation {
                        ChannelConversationDetailView(
                            conversation: channelConversation,
                            setNotifications: channelActions.setNotifications
                        )
                    }
                }
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { showsPeerProfile = false }
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
        if distanceFromBottom <= Self.resumeFollowingDistance {
            followsLatestMessage = true
        } else if userDriven && distanceFromBottom >= Self.stopFollowingDistance {
            followsLatestMessage = false
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
            outgoingScrollRequest += 1
        case let .failed(message):
            sendFailureMessage = message
            showsBlockedReason = true
        }
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
