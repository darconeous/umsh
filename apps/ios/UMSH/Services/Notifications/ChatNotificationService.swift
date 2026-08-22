import Foundation
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

    /// Peer address of the conversation currently on screen, if any.
    /// Read from the delegate callbacks; written by the UI on navigation.
    private let visibleConversation = OSAllocatedUnfairLock<String?>(initialState: nil)

    /// The live subscriber's continuation, if any. See `conversationOpens()`.
    private let conversationOpenContinuation =
        OSAllocatedUnfairLock<AsyncStream<String>.Continuation?>(initialState: nil)

    private let authorizationRequested = OSAllocatedUnfairLock(initialState: false)

    private override init() {
        super.init()
        UNUserNotificationCenter.current().delegate = self
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
    /// root view and restarts when the root's identity changes, and a stream
    /// its cancelled predecessor had terminated would swallow every later tap.
    func conversationOpens() -> AsyncStream<String> {
        AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
            conversationOpenContinuation.withLock { current in
                current?.finish()
                current = continuation
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
    /// A direct message needs no sender: the title already is one.
    func postInboundMessage(
        conversationAddress: String,
        displayName: String,
        sender: String?,
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
        content.userInfo = [Self.conversationAddressKey: conversationAddress]
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
        if let conversationAddress {
            conversationOpenContinuation.withLock { $0 }?.yield(conversationAddress)
        }
        completionHandler()
    }
}
