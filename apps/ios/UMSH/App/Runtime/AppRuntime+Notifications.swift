import Foundation
import UMSHMobileCore

extension AppRuntime {
    /// Tell the user a peer they were waiting on was heard.
    private func postPeerHeard(_ peerAddress: String) {
        let peer = peers.first { $0.identity.canonicalAddress == peerAddress }
        notificationService.postPeerHeard(
            peerAddress: peerAddress,
            displayName: peer?.displayName ?? String(peerAddress.prefix(10))
        )
    }

    // MARK: - Notifications

    /// Say what the core decided is worth saying. Which arrivals notify—
    /// mutes, silent tests, batching—is the core's call; the words are
    /// this side's. The willPresent delegate suppresses the banner when
    /// that conversation is visible in the foreground.
    func post(_ notification: MobileNotificationEventRecord) {
        switch notification {
        case let .message(conversation, channelId, senderAddress, senderHandle, senderHint, body, isStatus, reaction):
            let text = reaction.map { Self.reactionLine($0.reaction, on: $0.targetBody) } ?? body
            if let channelId {
                let channel = channel(withID: channelId)
                // A group message is from someone in particular, and the
                // banner is unreadable without saying who.
                let sender = memberName(address: senderAddress, handle: senderHandle, hint: senderHint)
                // The sender's saved avatar rides along when the member is a
                // peer this phone knows; an unknown member styles without one.
                let senderPeer = senderAddress.flatMap(peer(withAddress:))
                notificationService.postInboundMessage(
                    conversationAddress: conversation,
                    displayName: channel?.title ?? Self.unnamedChannelTitle,
                    sender: sender,
                    senderAddress: senderAddress,
                    senderHint: senderPeer?.identity.hint,
                    channel: channel?.avatarStyle,
                    offersReply: channel?.isEmergency != true,
                    body: isStatus ? statusLine(name: sender, body: text) : text
                )
            } else {
                let peer = peer(withAddress: conversation)
                let displayName = peer?.displayName ?? String(conversation.prefix(10))
                notificationService.postInboundMessage(
                    conversationAddress: conversation,
                    displayName: displayName,
                    sender: nil,
                    senderAddress: conversation,
                    senderHint: peer?.identity.hint,
                    channel: nil,
                    offersReply: true,
                    body: isStatus ? statusLine(name: displayName, body: text) : text
                )
            }
        case let .summary(conversation, channelId, count):
            notificationService.postInboundMessageSummary(
                conversationAddress: conversation,
                displayName: notificationTitle(conversation, channelID: channelId),
                count: Int(count)
            )
        case let .deliveryFailure(conversation, channelId, body, undelivered):
            // The transcript already marks it failed, and the delegate
            // suppresses the banner when that transcript is on screen—so
            // this speaks up exactly when nobody was watching it happen,
            // which over a mesh is the normal case.
            notificationService.postDeliveryFailure(
                conversationAddress: conversation,
                displayName: notificationTitle(conversation, channelID: channelId),
                quotedBody: Self.quotedBody(body, limit: Self.failureQuoteLimit),
                undelivered: undelivered
            )
        case let .peerHeard(address):
            postPeerHeard(address)
        }
    }

    /// What a notification about `conversation` is titled: its channel's
    /// name, or its peer's.
    private func notificationTitle(_ conversation: String, channelID: String?) -> String {
        if let channelID {
            return channel(withID: channelID)?.title ?? Self.unnamedChannelTitle
        }
        return peer(withAddress: conversation)?.displayName ?? String(conversation.prefix(10))
    }

    /// The title for a channel this phone has not read yet.
    private static var unnamedChannelTitle: String {
        String(
            localized: "New message",
            comment: "Notification title for a channel message, when the channel's name is not known yet."
        )
    }

    private func channel(withID id: String) -> ChannelSummary? {
        guard let id = UUID(uuidString: id) else { return nil }
        return channels.first { $0.id == id }
    }

    private func peer(withAddress address: String) -> PeerSummary? {
        peers.first { $0.identity.canonicalAddress == address }
    }

    /// A reaction, said out loud: what was done, the glyph it renders as, and
    /// the message it landed on.
    private static func reactionLine(_ reaction: MobileReaction?, on target: String) -> String {
        let glyph = ReactionEmoji.glyph(for: reaction)
        let quoted = quotedBody(target, limit: reactionQuoteLimit)
        return String(
            localized: "Reacted \(glyph) to \(quoted)",
            comment: "Notification body for a reaction to one of your messages: the reaction's emoji, then your message in quotation marks."
        )
    }

    /// A message as a notification *refers* to it, rather than shows it: one
    /// line, in quotation marks, clipped to about what a banner holds before
    /// it wraps. The quotation marks are what distinguish naming a message
    /// from delivering one—a failure notice that simply printed the text
    /// would read like the message arriving.
    private static func quotedBody(_ body: String, limit: Int) -> String {
        let flattened = body
            .replacingOccurrences(of: "\n", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard flattened.count > limit else {
            return String(
                localized: "“\(flattened)”",
                comment: "A message quoted in a notification. Use your language's quotation marks."
            )
        }
        let clipped = flattened.prefix(limit - 1).trimmingCharacters(in: .whitespaces)
        return String(
            localized: "“\(clipped)…”",
            comment: "A message quoted in a notification, cut short. Use your language's quotation marks and ellipsis."
        )
    }

    /// Roughly what one line of a banner holds at the default text size,
    /// once the quotation marks are paid for. A failure notice is a whole
    /// line of its own, so it gets the budget; a reaction has already spent
    /// a third of the line saying who did what, and wraps to a second line
    /// rather than clipping the quote down to nothing.
    private static let failureQuoteLimit = 36
    private static let reactionQuoteLimit = 48

    /// What to call a channel member, in descending order of authority: the
    /// name we have given them or heard them advertise, then the name they
    /// attached to the message, then their address, then the bare hint.
    ///
    /// A message-borne name is the sender's unverified claim—anyone holding
    /// the channel key can write anything there—so it never displaces a
    /// name this phone established for a peer it actually knows.
    private func memberName(address: String?, handle: String?, hint: String?) -> String {
        if let address, let peer = peer(withAddress: address) {
            return peer.displayName
        }
        if let handle, !handle.isEmpty { return handle }
        if let address { return String(address.prefix(10)) }
        guard let hint else {
            return String(localized: "Unknown member", comment: "A channel message's sender, when nothing names them.")
        }
        return String(
            localized: "Member \(hint)",
            comment: "A channel message's sender, named by their node hint. The placeholder is the hint, which is not translated."
        )
    }

    /// Whether an address names a channel's group conversation rather than a
    /// peer. The facade's own prefix, checked in one place.
    static func isChannelAddress(_ address: String) -> Bool {
        address.hasPrefix("ch:")
    }
}
