import Foundation
import OSLog
import UMSHMobileCore

extension AppRuntime {
    // MARK: - Chat

    /// The chat operations every transcript gets, wherever it is opened
    /// from.
    var messageActions: ChatMessageActions {
        ChatMessageActions(
            saveDraft: { address, text in await self.updateDraft(address, text) },
            markRead: { address in await self.markConversationRead(address) },
            send: { conversation, submitted, forwardSecret in
                try await self.sendMessage(conversation, submitted, forwardSecret: forwardSecret)
            },
            reply: replyToMessage,
            edit: editMessage,
            delete: deleteMessage,
            toggleReaction: toggleReaction,
            resend: resendMessage,
            requestMissing: requestMissingMessages,
            clearMessages: clearConversationMessages,
            countMessages: countConversationMessages
        )
    }

    /// A chat command on one conversation, then its transcript and the
    /// conversation lists read again, whether or not it went: a message kept
    /// as not delivered must show before the caller says so.
    func runChat<T: Sendable>(
        _ address: String,
        _ body: @Sendable (MobileAppCore) async throws -> T
    ) async throws -> T {
        guard let core else { throw MobileAppError.NotRunning }
        do {
            let value = try await body(core)
            await redraw(address)
            return value
        } catch {
            await redraw(address)
            throw error
        }
    }

    /// Read the transcript at `address` and the conversation lists again,
    /// before the caller scrolls: the core's own word of the change reaches
    /// the drain later.
    private func redraw(_ address: String) async {
        coordinator.bumpChatRevisions([address])
        await reloadConversationState()
    }

    /// Send into `conversation`. With `clearDraft`, the composer's text as
    /// submitted: the core keeps it as the draft until the message is kept,
    /// then clears the draft if it still reads the same. The draft store
    /// drops saves of that text from then on, unless the send is refused with
    /// nothing kept.
    private func compose(
        _ conversation: ConversationListItem,
        _ request: MobileAppChatRequest,
        clearDraft: String?
    ) async throws {
        // A save of older text still on its way must land before the core
        // writes the submitted text, or it would follow it; a save of the
        // submitted text itself is dropped from here on, or it could follow
        // the core's clear.
        guard let core else { throw MobileAppError.NotRunning }
        let address = conversation.conversationAddress
        var submission: ConversationDraftStore.Submission?
        if let clearDraft, let key = draftKey(address) {
            submission = await drafts.submit(clearDraft, for: key)
        }
        var refusal: (any Error)?
        do {
            try await core.sendChat(address: address, request: request, clearDraft: clearDraft)
        } catch {
            refusal = error
        }
        if let submission {
            if let refusal, !Self.wasKept(refusal) {
                // Refused with nothing kept: the words stay the draft.
                drafts.withdraw(submission)
            } else {
                // Kept, and the core cleared the draft: text held as
                // unsaved from before the tap must not come back as a draft.
                drafts.forget(submission)
            }
        }
        // Whether or not it went: a message kept as not delivered must show
        // before the caller says so.
        await redraw(address)
        if let refusal { throw refusal }
    }

    /// Whether a send that failed with `error` still kept its message, as
    /// not delivered.
    private static func wasKept(_ error: any Error) -> Bool {
        if case .MessageNotQueued = error as? MobileAppError { return true }
        return false
    }

    private func draftKey(_ address: String) -> ConversationDraftKey? {
        localIdentity.map { ConversationDraftKey(owner: $0.id, address: address) }
    }

    /// Keep what the composer holds for the conversation at `address`. The
    /// lists show it at once, and keep showing it while it is unsaved.
    @discardableResult
    func updateDraft(_ address: String, _ text: String) async -> AppOperationResult {
        guard let key = draftKey(address) else {
            return .failure(.unavailable(String(
                localized: "The local identity is unavailable.",
                comment: "Error when a draft cannot be stored because no identity is loaded."
            )))
        }
        // Words just sent: the core holds this draft, and the list follows it.
        if drafts.isSubmitted(text, for: key) { return .success(()) }
        let result = await drafts.save(text, for: key)
        guard localIdentity?.id == key.owner else { return .failure(.cancelled) }
        // Retain unsaved text in memory, without reporting persistence success.
        let shown = drafts.pendingText(for: key) ?? text
        if let index = conversations.firstIndex(where: { $0.conversationAddress == address }) {
            conversations[index].draftText = shown
        } else if let index = channelConversations.firstIndex(where: { $0.conversationAddress == address }) {
            channelConversations[index].draftText = shown
        }
        return result
    }

    /// Send the composer's text, untrimmed as it stood, under forward
    /// secrecy as `forwardSecret` says the composer showed it.
    func sendMessage(
        _ conversation: ConversationListItem,
        _ submitted: String,
        forwardSecret: Bool
    ) async throws {
        try await compose(
            conversation,
            .typed(text: submitted, forwardSecret: forwardSecret),
            clearDraft: submitted
        )
    }

    /// Send a reply typed into a notification, on the phone or a paired
    /// watch.
    ///
    /// Runs with no scene, often in a process the reply action itself just
    /// launched: bootstrap and the radio link are awaited, briefly, rather
    /// than assumed. A reply that cannot go out is never queued for later:
    /// one refused with nothing kept lands under the conversation's draft,
    /// and a notification says what became of it. The draft the user left
    /// there is not the reply, so the send leaves it alone.
    func deliverNotificationReply(conversationAddress: String, text: String) async -> Bool {
        // A cold launch is still opening the store and reading the identity.
        await waitUntil(timeout: .seconds(10)) {
            self.applicationStore != nil && self.localIdentity != nil
        }
        var item = conversationItem(for: conversationAddress)
        if item == nil {
            await reloadApplicationState()
            item = conversationItem(for: conversationAddress)
        }
        guard let item else {
            notificationService.postReplyFailure(
                conversationAddress: conversationAddress,
                displayName: "UMSH",
                savedAsDraft: false
            )
            return false
        }
        // A radio behind a background wake can still be dialing; give the
        // link the launch it is already making before giving up on it.
        await waitUntil(timeout: .seconds(15)) {
            self.lifecycle == .running && self.radioSnapshot.carriesThisPhone
        }
        do {
            try await compose(item, .typed(text: text, forwardSecret: nil), clearDraft: nil)
            return true
        } catch {
            Self.chatLogger.warning(
                "Notification reply not sent: \(String(describing: error), privacy: .public)"
            )
            notificationService.postReplyFailure(
                conversationAddress: conversationAddress,
                displayName: item.title,
                savedAsDraft: await keepUnsentReply(text, at: conversationAddress, refusal: error)
            )
            return false
        }
    }

    /// Keep the words of a reply that did not go out, under whatever draft
    /// the conversation holds: both are words the user typed and has not
    /// sent. Not when the transcript already holds it, or the conversation
    /// is not stored. Reports whether they were kept.
    ///
    /// A session that no longer holds the peer or channel refuses the send
    /// with `NotFound` while the conversation is still stored, so the core's
    /// own lookup decides, not the refusal.
    private func keepUnsentReply(_ text: String, at address: String, refusal: any Error) async -> Bool {
        if case .MessageNotQueued = refusal as? MobileAppError { return false }
        guard let core else { return false }
        // A composer starts from the lists' draft and takes in the additions
        // newer than when it opened, so the lists must not show the words
        // before the addition says so. In turn with the reloads, none can
        // publish the stored draft between the write and the addition.
        return await inReloadOrder {
            do {
                try await core.appendDraft(address: address, text: text)
            } catch MobileAppError.NotFound {
                return false
            } catch {
                Self.chatLogger.error(
                    "Notification reply not kept: \(String(describing: error), privacy: .public)"
                )
                return false
            }
            await self.performApplicationStateReload(includingPeers: false)
            self.draftAdditionSequence += 1
            self.draftAdditions.append(DraftAddition(
                sequence: self.draftAdditionSequence,
                address: address,
                text: text
            ))
            self.draftAdditions.removeFirst(max(0, self.draftAdditions.count - Self.draftAdditionsKept))
            return true
        }
    }

    private func conversationItem(for conversationAddress: String) -> ConversationListItem? {
        if Self.isChannelAddress(conversationAddress) {
            return channelConversations
                .first { $0.conversationAddress == conversationAddress }
                .map(ConversationListItem.channel)
        }
        return conversations
            .first { $0.peer.identity.canonicalAddress == conversationAddress }
            .map(ConversationListItem.direct)
    }

    /// Wait for a main-actor condition to hold, or for the deadline. The
    /// states involved—bootstrap fields, the radio snapshot—publish no
    /// completion signal to await, and a coarse poll is enough for the two
    /// launch-scale waits a notification reply performs.
    private func waitUntil(timeout: Duration, _ condition: () -> Bool) async {
        let deadline = ContinuousClock.now + timeout
        while !condition(), ContinuousClock.now < deadline {
            try? await Task.sleep(for: .milliseconds(200))
        }
    }

    /// Send `submitted` in reply to `message`, as ``sendMessage(_:_:forwardSecret:)``
    /// sends. Where the original can no longer be named the text goes as a
    /// plain message, as it does from a communicator.
    func replyToMessage(
        _ conversation: ConversationListItem,
        _ message: ChatMessageSummary,
        _ submitted: String,
        _ forwardSecret: Bool
    ) async throws {
        try await compose(
            conversation,
            .reply(target: message.reference, text: submitted, forwardSecret: forwardSecret),
            clearDraft: submitted
        )
    }

    func editMessage(
        _ conversation: ConversationListItem,
        _ message: ChatMessageSummary,
        _ newBody: String
    ) async throws {
        try await compose(conversation, .edit(message: message.reference, text: newBody), clearDraft: nil)
    }

    func deleteMessage(
        _ conversation: ConversationListItem,
        _ message: ChatMessageSummary
    ) async throws {
        try await compose(conversation, .delete(message: message.reference), clearDraft: nil)
    }

    /// React to a message with `reaction`, or withdraw it if it is already
    /// this phone's. The core decides which from the message as it stands
    /// when it sends, so a menu drawn before an earlier tap landed still
    /// does what it shows.
    func toggleReaction(
        _ conversation: ConversationListItem,
        _ message: ChatMessageSummary,
        _ reaction: MobileReaction
    ) async throws {
        try await compose(
            conversation,
            .toggleReaction(message: message.reference, reaction: reaction),
            clearDraft: nil
        )
    }

    /// Put a message delivery gave up on back on the air.
    ///
    /// While peers can still place it, its unacknowledged fragments go again
    /// under its original wire ID: a peer who received it and lost only the
    /// acknowledgment drops the duplicate, and one who never received it gets
    /// an ordinary message, notification and all. Otherwise its words go as a
    /// new message, which replaces the failed one at the bottom.
    ///
    /// `forwardSecret` is the user's choice for a message that went under
    /// forward secrecy: under it, the core uses the session held or asks the
    /// peer for a new one and the frames wait on it; without it, they go now
    /// and the row says so.
    func resendMessage(
        _ conversation: ConversationListItem,
        _ message: ChatMessageSummary,
        _ forwardSecret: Bool
    ) async throws -> MobileAppResent {
        let address = conversation.conversationAddress
        let reference = message.reference
        return try await runChat(address) {
            try await $0.resend(address: address, message: reference, forwardSecret: forwardSecret)
        }
    }

    /// Ask for missing messages no repair is under way for, one request
    /// each; the engine paces them. A gap that can no longer be asked for is
    /// resolved as unavailable rather than left to be tapped again.
    func requestMissingMessages(
        _ conversation: ConversationListItem,
        _ messages: [ChatMessageSummary]
    ) async throws {
        let address = conversation.conversationAddress
        let references = messages.map(\.reference)
        try await runChat(address) {
            try await $0.requestMissing(address: address, messages: references)
        }
    }

    /// Every conversation, both kinds, most recent traffic first.
    ///
    /// A channel with newer messages belongs above a quiet direct chat, so the
    /// two are ordered together rather than grouped.
    var conversationItems: [ConversationListItem] {
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
    func startChannelConversation(
        _ channel: ChannelSummary
    ) async throws -> ChannelConversationSummary {
        let id = channel.id.uuidString
        let address = try await run { try await $0.openChannelConversation(id: id) }
        return try channelConversation(at: address)
    }

    /// The channel conversation a command just returned the address of.
    func channelConversation(at address: String) throws -> ChannelConversationSummary {
        guard let conversation = channelConversations.first(where: { $0.conversationAddress == address }) else {
            throw MobileAppError.NotFound
        }
        return conversation
    }

    /// Leave a channel's group chat: its transcript goes, the membership
    /// stays.
    func deleteChannelConversation(_ conversation: ChannelConversationSummary) async throws {
        try await run { try await $0.deleteConversation(address: conversation.conversationAddress) }
    }

    /// Mark a conversation read. Driven by the transcript appearing, so the
    /// badge clears when the user actually looks at it. The lists follow
    /// the core's word that the count changed.
    func markConversationRead(_ address: String) async {
        guard let core, localIdentity != nil else { return }
        do {
            try await core.markRead(address: address, throughMs: nil)
            if failedReadAddress == address {
                failedReadAddress = nil
                stateLoadError = nil
            }
        } catch {
            Self.logger.error("Could not mark read: \(String(describing: error), privacy: .public)")
            failedReadAddress = address
            stateLoadError = .persistence(String(
                localized: "The conversation could not be marked as read.",
                comment: "Banner when opening a conversation could not clear its unread count."
            ))
        }
    }

    func retryStateLoad() async {
        if let failedReadAddress { await markConversationRead(failedReadAddress) }
        else { await reloadApplicationState() }
    }

    /// The user agreed to `EMERGENCY`'s warning. The core holds the
    /// agreement that gates its commands, and says per conversation whether
    /// one is still needed. Throws when the core does not take it, so
    /// nothing that waited on it goes.
    func certifyEmergency() throws {
        guard let core else { throw MobileAppError.NotRunning }
        try core.certifyEmergency()
    }

    /// Ask a channel member known only by their hint to identify themselves.
    func requestMemberIdentity(
        _ conversation: ChannelConversationSummary,
        _ hint: Data
    ) async throws {
        try await ask {
            try await $0.requestMemberIdentity(address: conversation.conversationAddress, hint: hint)
        }
    }

    /// Erase a conversation's transcript, keeping the conversation. Local
    /// only: nothing is sent, so everyone else keeps their copy.
    ///
    /// Addressed rather than keyed by row so one path serves both kinds, and
    /// `@Sendable` because it is handed to views as a bare closure.
    @Sendable
    func clearConversationMessages(_ address: String) async throws {
        try await runChat(address) { try await $0.clearMessages(address: address) }
    }

    /// Bounded transcript reads for whichever thread view is open.
    ///
    /// The window lives in the thread view rather than here: the ordinary way
    /// into a transcript is a navigation destination the app root never sees,
    /// so hoisting it would mean tracking push and pop for no other reason.
    var transcriptLoader: TranscriptLoader {
        TranscriptLoader(
            newest: newestTranscriptPage,
            older: olderTranscriptPage,
            newer: newerTranscriptPage,
            around: focusedTranscriptPage
        )
    }

    @Sendable
    private func newestTranscriptPage(_ address: String, _ limit: Int) async -> TranscriptPage {
        await transcriptPage {
            try $0.transcriptNewest(conversationAddress: address, limit: UInt32(clamping: limit))
        } ?? .empty
    }

    @Sendable
    private func olderTranscriptPage(
        _ address: String,
        _ cursor: ChatMessageCursor,
        _ limit: Int
    ) async -> TranscriptPage {
        await transcriptPage {
            try $0.transcriptBefore(
                conversationAddress: address,
                cursor: MobileStoredChatCursorRecord(cursor),
                limit: UInt32(clamping: limit)
            )
        } ?? .empty
    }

    @Sendable
    private func newerTranscriptPage(
        _ address: String,
        _ cursor: ChatMessageCursor,
        _ including: Bool,
        _ limit: Int
    ) async -> TranscriptPage {
        await transcriptPage {
            try $0.transcriptAfter(
                conversationAddress: address,
                cursor: MobileStoredChatCursorRecord(cursor),
                including: including,
                limit: UInt32(clamping: limit)
            )
        } ?? .empty
    }

    @Sendable
    private func focusedTranscriptPage(
        _ address: String,
        _ messageID: String,
        _ radius: Int
    ) async -> TranscriptPage? {
        guard let reference = MobileStoredChatMessageRefRecord(messageID: messageID) else { return nil }
        // A failed read and a missing message mean the same thing to the
        // caller: this message is not somewhere the transcript can go.
        return await transcriptPage {
            try $0.transcriptAround(
                conversationAddress: address,
                message: reference,
                radius: UInt32(clamping: radius)
            )
        }
    }

    /// One bounded transcript read, mapped for display; `nil` when it could
    /// not be made.
    private func transcriptPage(
        _ query: @escaping @Sendable (MobileAppCore) throws -> MobileAppTranscriptPageRecord?
    ) async -> TranscriptPage? {
        guard let record = try? await read(query) else { return nil }
        return TranscriptPage(record, peers: peers)
    }

    /// How many messages a conversation holds, for the info sheet. The only
    /// aggregate that walks a whole transcript, so it is answered here rather
    /// than carried on every summary through every reload.
    @Sendable
    func countConversationMessages(_ address: String) async -> Int {
        (try? await read { Int(try $0.messageCount(conversationAddress: address)) }) ?? 0
    }

    /// Delete a direct conversation and its history. The core sheds the
    /// peer's key from the radio: a closed conversation takes its custody
    /// with it.
    func deleteConversation(_ conversation: DirectConversationSummary) async throws {
        try await run { try await $0.deleteConversation(address: conversation.conversationAddress) }
    }
}
