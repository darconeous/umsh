import SwiftUI
import UIKit

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

    /// Which member's sheet is open, named by the one thing about them that
    /// cannot change. Everything else — their address, their name, whether
    /// they are a peer at all — is answered from the transcript at render, so
    /// the sheet is never older than what the transcript knows.
    private struct InspectedMember: Identifiable, Equatable {
        let hint: Data
        var id: Data { hint }
    }

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
    /// What is waiting in the conversations this one is covering, counted by
    /// whoever opened it — the pill on the back button, as in Messages.
    let unreadElsewhere: Int

    @State private var draft: String
    @State private var showsConversationInfo = false
    @State private var showsBlockedReason = false
    @State private var sendFailureMessage: String?
    @State private var editingMessage: ChatMessageSummary?
    @State private var editDraft = ""
    @State private var deletingMessage: ChatMessageSummary?
    @State private var inspectedMember: InspectedMember?
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
        peers: [PeerSummary] = [],
        unreadElsewhere: Int = 0
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
        self.unreadElsewhere = unreadElsewhere
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
                        // Spacing comes from each row instead of the stack: a
                        // run of messages from one sender closes up, and the
                        // gap between runs stays open. Both are decided where
                        // the rows are derived, so neither is measured here on
                        // every frame of a scroll.
                        VStack(spacing: 0) {
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
                                case let .message(message, presentation):
                                    ChatMessageBubble(
                                        message: message,
                                        presentation: presentation,
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
                                            ? {
                                                inspectedMember = message.senderHint
                                                    .map(InspectedMember.init)
                                            }
                                            : nil
                                    )
                                    // Every bubble measures a UITextView, so
                                    // an unrelated invalidation (a radio
                                    // snapshot, a keystroke in the composer)
                                    // would otherwise re-measure the whole
                                    // non-lazy transcript.
                                    .equatable()
                                    .padding(.top, presentation.topSpacing)
                                    .id(item.id)
                                case let .dateSeparator(_, date):
                                    TranscriptDateSeparator(date: date)
                                        .id(item.id)
                                case let .gap(_, count):
                                    GapPlaceholderBubble(
                                        count: count,
                                        reservesAvatarGutter: isChannel
                                    )
                                    .padding(.top, MessagePresentation.looseSpacing)
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
        }
        // The composer floats over the transcript rather than sitting below
        // it, so the newest messages run to the bottom of the screen and pass
        // under the bar as they scroll — as in Messages. An inset rather than
        // an overlay, so the scroll view keeps its content clear of the bar on
        // its own, and the empty and loading states get the same treatment.
        .safeAreaInset(edge: .bottom) {
            MessageComposer(
                draft: $draft,
                placeholder: "Message \(conversation.title)",
                blocked: composerBlock,
                canSend: canSendNow,
                send: { await send() }
            )
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
        }
        // A conversation is a place, not a tab: Messages gives the transcript
        // the whole screen, and the way back is the navigation bar.
        .toolbarVisibility(.hidden, for: .tabBar)
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
        // The header is this view's own rather than the navigation bar's. An
        // inline bar squeezes its principal item into the height it would
        // rather give — around 67pt of content — which is not enough for an
        // avatar and a name at the sizes Messages uses. This is the same
        // arrangement as the composer at the other edge, and being a safe-area
        // inset it starts below the status bar, clear of the Dynamic Island.
        .toolbar(.hidden, for: .navigationBar)
        .safeAreaInset(edge: .top) { header }
        .background { InteractivePopGestureRestorer() }
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
        .sheet(item: $inspectedMember) { inspected in
            // Resolved here rather than at the tap, so an identity arriving
            // while the sheet is open reaches it.
            let member = member(hint: inspected.hint)
            NavigationStack {
                ChannelMemberSheet(
                    member: member,
                    knownPeer: memberPeer(for: member),
                    requestIdentity: channelConversation.map { conversation in
                        { hint in
                            await channelActions.requestMemberIdentity(conversation, hint)
                        }
                    },
                    dismiss: { inspectedMember = nil },
                    conversations: $conversations,
                    radioSnapshot: radioSnapshot,
                    peerActions: peerActions,
                    messageActions: messageActions,
                    updateDraft: updateDraft,
                    sendMessage: { conversation, body in
                        await sendMessage(.direct(conversation), body)
                    }
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

    /// Who the conversation is with, floating over the transcript: the avatar
    /// with the name tucked up under it, and the way back on the left.
    private var header: some View {
        ZStack {
            // Boxed in from both sides so a long name truncates inside its
            // pill rather than running under the back button and off the
            // screen. The minimum clears the back control at its widest —
            // chevron plus a "99+" pill.
            HStack(spacing: 0) {
                Spacer(minLength: 72)
                Button {
                    showsConversationInfo = true
                } label: {
                    // The name overlaps the avatar, as in Messages, so the two
                    // read as one piece rather than as a caption under a
                    // picture.
                    VStack(spacing: -6) {
                        Group {
                            if let peer {
                                PeerAvatar(hint: peer.identity.hint, diameter: 54)
                            } else if let channelConversation {
                                ChannelAvatar(channel: channelConversation.channel, size: 54)
                            }
                        }
                        .zIndex(1)
                        ConversationTitlePill(title: conversation.title)
                    }
                }
                .buttonStyle(.plain)
                .accessibilityLabel("\(conversation.title) details")
                Spacer(minLength: 72)
            }

            HStack {
                UnreadBackButton(unreadElsewhere: unreadElsewhere)
                Spacer()
            }
        }
        .padding(.horizontal, 12)
        // Room below the controls for the bar to fade out in.
        .padding(.bottom, 22)
        .fadingBar(edge: .top)
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

    /// Who a member is *now*, rebuilt from the window every time this view
    /// updates rather than captured when their avatar was tapped.
    ///
    /// A channel message carries a hint; the address behind it can arrive
    /// minutes later, in the identity response this sheet is the place to ask
    /// for. That response backfills the sender of every stored message from
    /// the same hint and bumps the conversation's revision, so re-reading the
    /// window is what lets an answer turn into a peer while the sheet is still
    /// open — a value captured at the tap never could.
    private func member(hint: Data) -> ChannelMember {
        // Any of their messages will do once resolution has landed, since it
        // fills them all in; preferring one that names an address keeps a
        // straggler stored before that from hiding a resolved sibling.
        var chosen: ChatMessageSummary?
        for case let .message(message, _) in transcript.rows
        where message.senderHint == hint {
            if message.senderAddress != nil {
                chosen = message
                break
            }
            if chosen == nil { chosen = message }
        }
        guard let chosen else {
            // Everything they said has left the window while the sheet was
            // open. The hint is still theirs, and still worth asking about.
            let label = hint.map { String(format: "%02x", $0) }.joined()
            return ChannelMember(
                hint: hint,
                address: nil,
                handle: nil,
                displayName: "Member \(label)"
            )
        }
        return ChannelMember(
            hint: hint,
            address: chosen.senderAddress,
            handle: chosen.senderHandle,
            displayName: memberName(for: chosen)
        )
    }

    private func memberPeer(for member: ChannelMember) -> PeerSummary? {
        guard let address = member.address else { return nil }
        return knownPeer(address: address)
    }

    /// Link states with no radio in hand: nothing attached, and nothing in the
    /// middle of attaching. Only these unseat the composer field. The states
    /// along the attachment pipeline — connecting, reconnecting, synchronizing
    /// and the rest — keep it, so a momentary BLE drop cannot yank the
    /// keyboard out from under a half-typed message.
    private var radioIsAbsent: Bool {
        switch radioSnapshot.linkState {
        case .idle, .unavailable, .scanning, .discovered, .waitingForRadio, .failed:
            true
        default:
            false
        }
    }

    /// Host states that are settled answers rather than steps on the way to
    /// one. `.unknown` and `.claiming` are moments in a resolution and do not
    /// unseat the field either.
    private var hostIsSettledElsewhere: Bool {
        switch radioSnapshot.hostState {
        case .unsupported, .unclaimed, .belongsToAnotherIdentity, .localIdentityUnavailable:
            true
        case .unknown, .claiming, .matchesCurrentIdentity:
            false
        }
    }

    /// Why the composer cannot take a message, if it cannot. Both cases end at
    /// the same sheet — one to attach a radio, one to set the attached one up
    /// for this identity — so both offer a way into it.
    private var composerBlock: ComposerBlock? {
        if radioIsAbsent {
            return ComposerBlock(
                reason: "Connect a companion radio to send messages",
                actionLabel: "Connect Radio"
            )
        }
        if hostIsSettledElsewhere {
            return ComposerBlock(
                reason: "Set up this radio for the current phone identity to send messages",
                actionLabel: "Radio Settings"
            )
        }
        return nil
    }

    /// Whether a message sent this instant can actually go somewhere. False
    /// through the transient link states, where the field stays but the send
    /// button waits with it.
    private var canSendNow: Bool {
        (radioSnapshot.linkState == .attached || radioSnapshot.linkState == .ready)
            && radioSnapshot.hostState == .matchesCurrentIdentity
    }

    /// The same condition as a sentence, for the alert a blocked send raises.
    private var blockedReason: String? {
        if let composerBlock { return composerBlock.reason }
        if !canSendNow { return "The companion radio is still connecting." }
        return nil
    }
}

/// The glass capsule the system puts under a toolbar control, for the controls
/// this header draws itself. Without it they read as inert text and icons
/// rather than as things to tap.
private struct ToolbarPill: ViewModifier {
    @ViewBuilder
    func body(content: Content) -> some View {
        if #available(iOS 26.0, *) {
            content.glassEffect(.regular, in: Capsule())
        } else {
            content.background(.regularMaterial, in: Capsule())
        }
    }
}

private extension View {
    func toolbarPill() -> some View { modifier(ToolbarPill()) }
}

/// A bar that dissolves into the transcript rather than ending in a line.
///
/// Both of a transcript's bars float over the messages, so both have content
/// running underneath them. Given a flat edge that content is visibly chopped
/// in half; fading the bar out lets it pass under the way it does beneath the
/// system's own bars.
struct FadingBar: ViewModifier {
    /// The screen edge the bar is anchored to. The fade runs from there
    /// toward the transcript.
    let edge: VerticalEdge

    func body(content: Content) -> some View {
        content.background {
            Rectangle()
                .fill(.bar)
                .mask {
                    LinearGradient(
                        stops: [
                            .init(color: .black, location: 0),
                            .init(color: .black, location: 0.72),
                            .init(color: .clear, location: 1)
                        ],
                        startPoint: edge == .top ? .top : .bottom,
                        endPoint: edge == .top ? .bottom : .top
                    )
                }
                .ignoresSafeArea(edges: edge == .top ? .top : .bottom)
        }
    }
}

extension View {
    func fadingBar(edge: VerticalEdge) -> some View {
        modifier(FadingBar(edge: edge))
    }
}

/// The conversation's name as it sits under its avatar, carrying the chevron
/// that says the name leads somewhere.
struct ConversationTitlePill: View {
    let title: String

    var body: some View {
        HStack(spacing: 3) {
            Text(title)
                .font(.headline.weight(.heavy))
                .foregroundStyle(.primary)
                .lineLimit(1)
            // An explicit grey rather than `.secondary`: inside a button the
            // hierarchy collapses to the label's own colour, and the chevron
            // comes out as dark as the name beside it.
            Image(systemName: "chevron.right")
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(Color(uiColor: .systemGray))
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 5)
        .toolbarPill()
    }
}

/// The Messages back control: a chevron, and a count of what is waiting in the
/// conversations this transcript is covering.
struct UnreadBackButton: View {
    let unreadElsewhere: Int

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Button {
            dismiss()
        } label: {
            HStack(spacing: 4) {
                Image(systemName: "chevron.backward")
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.primary)
                if unreadElsewhere > 0 {
                    Text(count)
                        .font(.footnote.weight(.semibold))
                        .foregroundStyle(.white)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 1)
                        .background(Color.accentColor, in: Capsule())
                }
            }
            .padding(.horizontal, 11)
            .padding(.vertical, 7)
            .toolbarPill()
        }
        .buttonStyle(.plain)
        .accessibilityLabel(
            unreadElsewhere > 0
                ? "Back, \(unreadElsewhere) unread elsewhere"
                : "Back"
        )
    }

    /// Past a certain size a count stops being read and starts being noise.
    private var count: String {
        unreadElsewhere > 99 ? "99+" : "\(unreadElsewhere)"
    }
}

/// Puts the swipe-from-the-edge pop gesture back.
///
/// Hiding the system back button — which the unread pill requires, since the
/// system one cannot carry it — takes the gesture with it. This re-delegates
/// the navigation controller's own recognizer, and hands the delegate back on
/// the way out so nothing outside this transcript inherits ours.
///
/// Contained whole so it can be deleted the day SwiftUI lets a custom back
/// button keep the gesture on its own.
struct InteractivePopGestureRestorer: UIViewControllerRepresentable {
    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeUIViewController(context: Context) -> UIViewController {
        Controller(coordinator: context.coordinator)
    }

    func updateUIViewController(_ controller: UIViewController, context: Context) {}

    final class Coordinator: NSObject, UIGestureRecognizerDelegate {
        weak var navigation: UINavigationController?

        /// Anything but the root: popping the last controller off leaves the
        /// stack empty and the bar in a state nothing can recover from.
        func gestureRecognizerShouldBegin(_ recognizer: UIGestureRecognizer) -> Bool {
            (navigation?.viewControllers.count ?? 0) > 1
        }
    }

    /// A zero-sized controller, present only to reach the navigation
    /// controller — which exists no earlier than the moment this one is added
    /// to the hierarchy.
    private final class Controller: UIViewController {
        private let coordinator: Coordinator
        private weak var navigation: UINavigationController?
        private weak var previousDelegate: UIGestureRecognizerDelegate?

        init(coordinator: Coordinator) {
            self.coordinator = coordinator
            super.init(nibName: nil, bundle: nil)
            view.isUserInteractionEnabled = false
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) { fatalError("never loaded from a nib") }

        override func didMove(toParent parent: UIViewController?) {
            super.didMove(toParent: parent)
            guard parent != nil else {
                navigation?.interactivePopGestureRecognizer?.delegate = previousDelegate
                navigation = nil
                return
            }
            guard let navigation = navigationController,
                  let recognizer = navigation.interactivePopGestureRecognizer,
                  recognizer.delegate !== coordinator
            else { return }
            self.navigation = navigation
            previousDelegate = recognizer.delegate
            coordinator.navigation = navigation
            recognizer.delegate = coordinator
        }
    }
}
