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
    func postInboundMessage(
        conversationAddress: String,
        displayName: String,
        sender: String?,
        senderAddress: String?,
        senderHint: MeshNodeHint?,
        isGroup: Bool,
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
            isGroup: isGroup,
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
    /// the failure surfaces. Threaded with the conversation, and tapping it
    /// opens the transcript where the preserved draft is waiting. No reply
    /// category: answering a failure notice with more undeliverable text
    /// helps nobody.
    func postReplyFailure(conversationAddress: String, displayName: String) {
        let content = UNMutableNotificationContent()
        content.title = displayName
        content.body = "Your reply couldn't be sent. It's saved as a draft."
        content.sound = .default
        content.threadIdentifier = conversationAddress
        content.userInfo = [Self.conversationAddressKey: conversationAddress]
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request, withCompletionHandler: nil)
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
        isGroup: Bool,
        body: String
    ) -> UNNotificationContent {
        let handle = senderAddress ?? conversationAddress
        let person = INPerson(
            personHandle: INPersonHandle(value: handle, type: .unknown),
            nameComponents: nil,
            displayName: sender ?? displayName,
            image: senderHint.flatMap { avatarImage($0) },
            contactIdentifier: nil,
            customIdentifier: handle
        )
        let intent = INSendMessageIntent(
            recipients: isGroup ? [Self.mePerson()] : nil,
            outgoingMessageType: .outgoingMessageText,
            content: body,
            speakableGroupName: isGroup ? INSpeakableString(spokenPhrase: displayName) : nil,
            conversationIdentifier: conversationAddress,
            serviceName: nil,
            sender: person,
            attachments: nil
        )
        let interaction = INInteraction(intent: intent, response: nil)
        interaction.direction = .incoming
        interaction.donate(completion: nil)
        do {
            return try content.updating(from: intent)
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

    /// The sender's avatar as the app draws it: the hint's color, the hint's
    /// four characters in two stacked pairs (PeerAvatar, in UIKit strokes —
    /// notification content cannot host a SwiftUI view).
    private func avatarImage(_ hint: MeshNodeHint) -> INImage? {
        let bytes = Array(hint.bytes.prefix(3))
        guard bytes.count == 3 else { return nil }
        let red = CGFloat(bytes[0]) / 255
        let green = CGFloat(bytes[1]) / 255
        let blue = CGFloat(bytes[2]) / 255
        func linear(_ component: CGFloat) -> CGFloat {
            component <= 0.04045
                ? component / 12.92
                : pow((component + 0.055) / 1.055, 2.4)
        }
        let luminance = 0.2126 * linear(red) + 0.7152 * linear(green) + 0.0722 * linear(blue)
        let textColor: UIColor = luminance < 0.179 ? .white : .black

        let diameter: CGFloat = 96
        let format = UIGraphicsImageRendererFormat()
        format.scale = 2
        let renderer = UIGraphicsImageRenderer(
            size: CGSize(width: diameter, height: diameter),
            format: format
        )
        let image = renderer.image { context in
            UIColor(red: red, green: green, blue: blue, alpha: 1).setFill()
            context.cgContext.fillEllipse(
                in: CGRect(x: 0, y: 0, width: diameter, height: diameter)
            )
            let characters = Array(hint.text)
            let lines = [String(characters.prefix(2)), String(characters.dropFirst(2))]
            let font = UIFont.monospacedSystemFont(ofSize: diameter * 0.30, weight: .semibold)
            let paragraph = NSMutableParagraphStyle()
            paragraph.alignment = .center
            let attributes: [NSAttributedString.Key: Any] = [
                .font: font,
                .foregroundColor: textColor,
                .paragraphStyle: paragraph,
            ]
            let spacing = -diameter * 0.08
            let totalHeight = font.lineHeight * 2 + spacing
            var y = (diameter - totalHeight) / 2
            for line in lines where !line.isEmpty {
                (line as NSString).draw(
                    in: CGRect(x: 0, y: y, width: diameter, height: font.lineHeight),
                    withAttributes: attributes
                )
                y += font.lineHeight + spacing
            }
        }
        guard let data = image.pngData() else { return nil }
        return INImage(imageData: data)
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
