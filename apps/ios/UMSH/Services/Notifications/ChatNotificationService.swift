import Foundation
import Intents
import os
import UIKit
@preconcurrency import UserNotifications

/// Local notifications for inbound chat messages.
///
/// Notifications are posted only after a message has reached durable
/// storage (the caller invokes `postInboundMessage` from the chat-apply
/// pipeline, after persistence succeeds). Suppression for the currently
/// visible conversation happens at presentation time via the
/// `UNUserNotificationCenterDelegate`, so a message that arrives while its
/// transcript is open in the foreground shows nothing, while the same
/// message with the app backgrounded banners normally.
final class ChatNotificationService: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
    /// One instance for the process, matching the one delegate slot on
    /// `UNUserNotificationCenter`. The root view is a value SwiftUI rebuilds
    /// freely; constructing a service per rebuild handed the delegate to a
    /// fresh instance that had never been told which transcript is open, so
    /// the visible conversation bannered itself.
    static let shared = ChatNotificationService()

    private static let logger = Logger(subsystem: "com.umsh.ios", category: "Notifications")
    private static let conversationAddressKey = "umsh.conversationAddress"
    private static let messageCategoryIdentifier = "umsh.chat.message"
    private static let replyActionIdentifier = "umsh.chat.reply"

    /// Peer address of the conversation currently on screen, if any.
    /// Read from the delegate callbacks; written by the UI on navigation.
    private let visibleConversation = OSAllocatedUnfairLock<String?>(initialState: nil)

    /// The live subscriber's continuation, if any, and the conversation a
    /// tap asked for while there was none. See `conversationOpens()`.
    private let conversationOpenState = OSAllocatedUnfairLock<ConversationOpenState>(
        initialState: ConversationOpenState()
    )

    private struct ConversationOpenState {
        var continuation: AsyncStream<String>.Continuation?
        var pending: String?
    }

    private let authorizationRequested = OSAllocatedUnfairLock(initialState: false)

    /// Who sends a reply typed into a notification, and any replies typed
    /// before anyone was installed to send them. The handler is the runtime's,
    /// installed by `start()` and removed by `stop()`; a reply that races a
    /// DEBUG runtime swap waits here instead of vanishing.
    private let replyState = OSAllocatedUnfairLock<ReplyState>(initialState: ReplyState())

    private struct ReplyState {
        var handler: (@Sendable (String, String) async -> Bool)?
        var pending: [(conversationAddress: String, text: String)] = []
    }

    private override init() {
        super.init()
        UNUserNotificationCenter.current().delegate = self
        // Chat notifications carry an inline text-input Reply. Registering
        // the category is also what makes the mirrored notification on a
        // paired Apple Watch answerable by dictation or scribble.
        let reply = UNTextInputNotificationAction(
            identifier: Self.replyActionIdentifier,
            title: "Reply",
            options: [],
            textInputButtonTitle: "Send",
            textInputPlaceholder: "Message"
        )
        UNUserNotificationCenter.current().setNotificationCategories([
            UNNotificationCategory(
                identifier: Self.messageCategoryIdentifier,
                actions: [reply],
                intentIdentifiers: [],
                options: []
            )
        ])
        // A transcript left open while the app was backgrounded banners its
        // arrivals (correctly — nobody was looking), but coming back through
        // the app icon re-reveals it without an appearance event. Foreground
        // entry is that missing moment: whatever is visible is now seen.
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(applicationWillEnterForeground),
            name: UIApplication.willEnterForegroundNotification,
            object: nil
        )
    }

    @objc private func applicationWillEnterForeground() {
        if let visible = visibleConversation.withLock({ $0 }) {
            removeDeliveredNotifications(conversationAddress: visible)
        }
    }

    /// Peer addresses of tapped message notifications. The UI consumes this
    /// stream and routes to the conversation. Each call starts a fresh
    /// subscription and ends any previous one: the consuming task lives in the
    /// interface and restarts when the interface is rebuilt, and a stream its
    /// cancelled predecessor had terminated would swallow every later tap.
    ///
    /// A tap that arrives before anyone is subscribed is held rather than
    /// dropped. Tapping a notification is exactly what launches a terminated
    /// app, and this delegate is answering while the interface it routes
    /// through is still being built.
    func conversationOpens() -> AsyncStream<String> {
        AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
            conversationOpenState.withLock { state in
                state.continuation?.finish()
                state.continuation = continuation
                if let pending = state.pending {
                    state.pending = nil
                    continuation.yield(pending)
                }
            }
        }
    }

    func setVisibleConversation(conversationAddress: String?) {
        visibleConversation.withLock { $0 = conversationAddress }
        // Opening the transcript is also the moment its delivered
        // notifications go stale: everything they announce is now on screen,
        // and they should not linger in Notification Center as unread bait.
        if let conversationAddress {
            removeDeliveredNotifications(conversationAddress: conversationAddress)
        }
    }

    /// Withdraw delivered notifications for a conversation the user is now
    /// reading. Identifiers are random, so membership is decided by the
    /// conversation address each notification carries in its `userInfo`.
    private func removeDeliveredNotifications(conversationAddress: String) {
        let center = UNUserNotificationCenter.current()
        center.getDeliveredNotifications { delivered in
            let stale = delivered
                .filter {
                    $0.request.content.userInfo[Self.conversationAddressKey] as? String
                        == conversationAddress
                }
                .map(\.request.identifier)
            if !stale.isEmpty {
                center.removeDeliveredNotifications(withIdentifiers: stale)
            }
        }
    }

    /// Clear only if this conversation is still the visible one. When the
    /// user switches transcripts, the new view's appearance can precede the
    /// old view's disappearance; the stale disappearance must not erase the
    /// fresh state.
    func clearVisibleConversation(ifMatching conversationAddress: String) {
        visibleConversation.withLock { visible in
            if visible == conversationAddress {
                visible = nil
            }
        }
    }

    /// Install who sends notification replies, and drain any typed while no
    /// one could. The handler returns whether the reply was delivered; the
    /// caller keeps the process alive around it.
    func installReplyHandler(_ handler: @escaping @Sendable (String, String) async -> Bool) {
        let held = replyState.withLock { state in
            state.handler = handler
            defer { state.pending.removeAll() }
            return state.pending
        }
        for reply in held {
            Task { _ = await handler(reply.conversationAddress, reply.text) }
        }
    }

    func clearReplyHandler() {
        replyState.withLock { $0.handler = nil }
    }

    /// Ask for notification permission the first time a radio attaches —
    /// the first moment a notification has concrete meaning. The system
    /// remembers the user's answer; a denied state is never re-prompted.
    func requestAuthorizationIfNeeded() {
        let alreadyRequested = authorizationRequested.withLock { requested in
            defer { requested = true }
            return requested
        }
        guard !alreadyRequested else { return }
        UNUserNotificationCenter.current().requestAuthorization(
            options: [.alert, .sound]
        ) { _, error in
            if let error {
                Self.logger.error(
                    "Notification authorization failed: \(error.localizedDescription, privacy: .public)"
                )
            }
        }
    }

    /// Post a notification for a durably persisted inbound message.
    ///
    /// `sender` names who sent it within a group conversation, where the
    /// title is the channel and the body alone would not say who is talking.
    /// A direct message needs no sender: the title already is one. The
    /// identity parameters feed the communication styling — the sender's
    /// avatar and chat grouping — and the title/subtitle stay behind them as
    /// the fallback for anywhere that styling does not reach.
    ///
    /// `channel` is what makes this a group message: it names the room, and
    /// its badge becomes the icon, so the notification says where as well as
    /// who.
    func postInboundMessage(
        conversationAddress: String,
        displayName: String,
        sender: String?,
        senderAddress: String?,
        senderHint: MeshNodeHint?,
        channel: AvatarStyle?,
        body: String
    ) {
        let content = UNMutableNotificationContent()
        content.title = displayName
        if let sender {
            content.subtitle = sender
        }
        content.body = body
        content.sound = .default
        content.threadIdentifier = conversationAddress
        content.categoryIdentifier = Self.messageCategoryIdentifier
        content.userInfo = [Self.conversationAddressKey: conversationAddress]
        let styled = communicationContent(
            from: content,
            conversationAddress: conversationAddress,
            displayName: displayName,
            sender: sender,
            senderAddress: senderAddress,
            senderHint: senderHint,
            channel: channel,
            body: body
        )
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: styled,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request) { error in
            if let error {
                Self.logger.error(
                    "Could not post message notification: \(error.localizedDescription, privacy: .public)"
                )
            }
        }
    }

    /// Tell the user a notification reply did not go out.
    ///
    /// Failed sends are never silently queued; from a notification or a
    /// watch there is no transcript on screen to say so, so this is where
    /// the failure surfaces. Tapping it opens the transcript where the
    /// preserved draft is waiting.
    func postReplyFailure(conversationAddress: String, displayName: String) {
        postFailure(
            conversationAddress: conversationAddress,
            title: displayName,
            body: "Your reply couldn't be sent. It's saved as a draft."
        )
    }

    /// Tell the user a message that had been sent is not going to arrive.
    ///
    /// The transcript marks it failed either way; this is for when nobody is
    /// looking at the transcript, which over a mesh is most of the time.
    /// `quotedBody` names the message rather than repeating it, so the
    /// notice cannot be misread as the message itself having arrived.
    func postDeliveryFailure(
        conversationAddress: String,
        displayName: String,
        quotedBody: String
    ) {
        postFailure(
            conversationAddress: conversationAddress,
            title: "Unable to deliver message to \(displayName)",
            body: quotedBody
        )
    }

    /// A notice about the app's own trouble, deliberately unlike a message.
    ///
    /// No communication styling: nothing here was said by a person, and
    /// dressing it as a message would put a face and a name on the app's own
    /// bad news. No reply action either — answering a failure notice with
    /// more undeliverable text helps nobody. It threads with the
    /// conversation it concerns, so it groups where it belongs and a tap
    /// opens the transcript.
    private func postFailure(conversationAddress: String, title: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        content.sound = .default
        content.threadIdentifier = conversationAddress
        content.userInfo = [Self.conversationAddressKey: conversationAddress]
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request) { error in
            if let error {
                Self.logger.error(
                    "Could not post failure notification: \(error.localizedDescription, privacy: .public)"
                )
            }
        }
    }

    /// Restyle a chat notification as a communication notification: the
    /// sender's avatar as the icon, messages grouped as a conversation.
    /// Requires the communication-notifications entitlement; without it (or
    /// on any styling failure) the plain content stands.
    private func communicationContent(
        from content: UNMutableNotificationContent,
        conversationAddress: String,
        displayName: String,
        sender: String?,
        senderAddress: String?,
        senderHint: MeshNodeHint?,
        channel: AvatarStyle?,
        body: String
    ) -> UNNotificationContent {
        let handle = senderAddress ?? conversationAddress
        // A group message shows the room it came from, not the face that
        // spoke: the speaker is already the title, and the channel is the
        // one thing the phone's banner otherwise never says.
        let image: INImage?
        if let channel {
            image = avatarImage(channel, design: .rounded)
        } else {
            image = senderHint.flatMap { avatarImage(.peer(hint: $0), design: .monospaced) }
        }
        let person = INPerson(
            personHandle: INPersonHandle(value: handle, type: .unknown),
            nameComponents: nil,
            displayName: sender ?? displayName,
            image: image,
            contactIdentifier: nil,
            customIdentifier: handle
        )
        let intent = INSendMessageIntent(
            recipients: channel == nil ? nil : [Self.mePerson()],
            outgoingMessageType: .outgoingMessageText,
            content: body,
            speakableGroupName: channel == nil
                ? nil
                : INSpeakableString(spokenPhrase: displayName),
            conversationIdentifier: conversationAddress,
            serviceName: nil,
            sender: person,
            attachments: nil
        )
        let interaction = INInteraction(intent: intent, response: nil)
        interaction.direction = .incoming
        interaction.donate(completion: nil)
        do {
            let styled = try content.updating(from: intent)
            // Styling titles the notification with whoever is speaking, which
            // is right, but it leaves the subtitle alone — and the subtitle
            // was carrying the speaker's name as the unstyled fallback. Left
            // as-is, a channel message names the sender twice and the channel
            // not at all. The room belongs on that second line.
            guard channel != nil,
                  let mutable = styled.mutableCopy() as? UNMutableNotificationContent
            else { return styled }
            mutable.subtitle = displayName
            return mutable
        } catch {
            Self.logger.error(
                "Communication styling failed: \(error.localizedDescription, privacy: .public)"
            )
            return content
        }
    }

    /// The local user, as the nominal recipient a group intent requires.
    /// Nothing about this phone's identity belongs in it: the intent is
    /// styling, not a message. Built per call — `INPerson` is not Sendable,
    /// so it cannot sit in a shared static.
    private static func mePerson() -> INPerson {
        INPerson(
            personHandle: INPersonHandle(value: "me", type: .unknown),
            nameComponents: nil,
            displayName: nil,
            image: nil,
            contactIdentifier: nil,
            customIdentifier: nil,
            isMe: true
        )
    }

    /// One avatar, drawn the way the app draws it, in UIKit strokes —
    /// notification content cannot host a SwiftUI view.
    ///
    /// Always a circle, including for a channel, whose badge is a rounded
    /// square everywhere else in the app. The system masks this image to a
    /// circle regardless, so drawing one is the difference between a shape
    /// that was meant and a square with its corners cut off.
    private func avatarImage(
        _ style: AvatarStyle,
        design: UIFontDescriptor.SystemDesign
    ) -> INImage? {
        let diameter: CGFloat = 96
        let format = UIGraphicsImageRendererFormat()
        format.scale = 2
        let renderer = UIGraphicsImageRenderer(
            size: CGSize(width: diameter, height: diameter),
            format: format
        )
        let frame = CGRect(x: 0, y: 0, width: diameter, height: diameter)
        let image = renderer.image { context in
            style.fill.setFill()
            context.cgContext.fillEllipse(in: frame)
            draw(style, in: frame, design: design)
        }
        guard let data = image.pngData() else { return nil }
        return INImage(imageData: data)
    }

    /// Stack an avatar's glyph lines in its box, centered as a group.
    private func draw(
        _ style: AvatarStyle,
        in frame: CGRect,
        design: UIFontDescriptor.SystemDesign
    ) {
        let lines = style.lines.filter { !$0.isEmpty }
        guard !lines.isEmpty else { return }
        let size = frame.width
        let base = UIFont.systemFont(ofSize: size * style.fontRatio, weight: .semibold)
        let font = base.fontDescriptor.withDesign(design).map {
            UIFont(descriptor: $0, size: size * style.fontRatio)
        } ?? base
        let paragraph = NSMutableParagraphStyle()
        paragraph.alignment = .center
        let attributes: [NSAttributedString.Key: Any] = [
            .font: font,
            .foregroundColor: style.text,
            .paragraphStyle: paragraph,
        ]
        let spacing = size * style.lineSpacingRatio
        let totalHeight = font.lineHeight * CGFloat(lines.count)
            + spacing * CGFloat(lines.count - 1)
        var y = frame.minY + (frame.height - totalHeight) / 2
        for line in lines {
            (line as NSString).draw(
                in: CGRect(x: frame.minX, y: y, width: size, height: font.lineHeight),
                withAttributes: attributes
            )
            y += font.lineHeight + spacing
        }
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        let conversationAddress = notification.request.content
            .userInfo[Self.conversationAddressKey] as? String
        let visible = visibleConversation.withLock { $0 }
        if let conversationAddress, conversationAddress == visible {
            // The transcript is on screen; the message is already visible.
            completionHandler([])
        } else {
            completionHandler([.banner, .sound])
        }
    }

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        let conversationAddress = response.notification.request.content
            .userInfo[Self.conversationAddressKey] as? String
        // An inline reply — typed on the notification, or dictated on a
        // paired watch. The app may have just been launched for exactly
        // this, with no scene; the send runs under a background assertion
        // and the system callback is answered only once it settles.
        if response.actionIdentifier == Self.replyActionIdentifier,
           let textResponse = response as? UNTextInputNotificationResponse,
           let conversationAddress {
            let text = textResponse.userText.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !text.isEmpty else {
                completionHandler()
                return
            }
            let handler = replyState.withLock { state in
                if state.handler == nil {
                    state.pending.append((conversationAddress, text))
                }
                return state.handler
            }
            guard let handler else {
                // Held for the next installReplyHandler; the system callback
                // cannot wait for it.
                completionHandler()
                return
            }
            // The completion is safe to carry to the main actor — the system
            // wants it called once, from anywhere — but it is not marked
            // Sendable, so say so explicitly.
            nonisolated(unsafe) let completion = completionHandler
            Task { @MainActor in
                let assertion = UIApplication.shared.beginBackgroundTask(withName: "umsh.chat.reply")
                _ = await handler(conversationAddress, text)
                completion()
                if assertion != .invalid {
                    UIApplication.shared.endBackgroundTask(assertion)
                }
            }
            return
        }
        if let conversationAddress {
            conversationOpenState.withLock { state in
                if let continuation = state.continuation {
                    continuation.yield(conversationAddress)
                } else {
                    state.pending = conversationAddress
                }
            }
        }
        completionHandler()
    }
}
