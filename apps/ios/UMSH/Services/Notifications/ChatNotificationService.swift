import Foundation
import os
import UserNotifications

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
    private static let logger = Logger(subsystem: "com.umsh.ios", category: "Notifications")
    private static let peerAddressKey = "umsh.peerAddress"

    /// Peer address of the conversation currently on screen, if any.
    /// Read from the delegate callbacks; written by the UI on navigation.
    private let visiblePeerAddress = OSAllocatedUnfairLock<String?>(initialState: nil)

    /// Peer addresses of tapped message notifications, newest-wins. The UI
    /// consumes this stream and routes to the conversation.
    let conversationOpens: AsyncStream<String>
    private let conversationOpenContinuation: AsyncStream<String>.Continuation

    private let authorizationRequested = OSAllocatedUnfairLock(initialState: false)

    override init() {
        (conversationOpens, conversationOpenContinuation) = AsyncStream.makeStream(
            bufferingPolicy: .bufferingNewest(1)
        )
        super.init()
        UNUserNotificationCenter.current().delegate = self
    }

    func setVisibleConversation(peerAddress: String?) {
        visiblePeerAddress.withLock { $0 = peerAddress }
    }

    /// Clear only if this conversation is still the visible one. When the
    /// user switches transcripts, the new view's appearance can precede the
    /// old view's disappearance; the stale disappearance must not erase the
    /// fresh state.
    func clearVisibleConversation(ifMatching peerAddress: String) {
        visiblePeerAddress.withLock { visible in
            if visible == peerAddress {
                visible = nil
            }
        }
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
    func postInboundMessage(peerAddress: String, displayName: String, body: String) {
        let content = UNMutableNotificationContent()
        content.title = displayName
        content.body = body
        content.sound = .default
        content.threadIdentifier = peerAddress
        content.userInfo = [Self.peerAddressKey: peerAddress]
        let request = UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
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

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        let peerAddress = notification.request.content
            .userInfo[Self.peerAddressKey] as? String
        let visible = visiblePeerAddress.withLock { $0 }
        if let peerAddress, peerAddress == visible {
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
        let peerAddress = response.notification.request.content
            .userInfo[Self.peerAddressKey] as? String
        if let peerAddress {
            conversationOpenContinuation.yield(peerAddress)
        }
        completionHandler()
    }
}
