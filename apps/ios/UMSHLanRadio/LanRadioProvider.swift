import Foundation
import NetworkExtension
import OSLog
import UMSHMobileCore
import UserNotifications

/// Hosts the LAN virtual radio while the phone is on a listed network.
///
/// The system starts this extension when the phone joins a network the
/// app listed and stops it when the phone leaves, whatever the app is
/// doing. The radio goes on receiving, acknowledging for its host, and
/// queueing while the app is suspended, and the app attaches to it over
/// the local socket in the App Group container when it runs. Its state
/// is touched only on its own queue.
final class LanRadioProvider: NEAppPushProvider, @unchecked Sendable {
    private static let logger = Logger(subsystem: "com.voria.umsh.app.lan-radio", category: "provider")

    /// How long to wait before trying again when the radio cannot start,
    /// as while the app still hosts it in its own process.
    private static let retryDelaySeconds: TimeInterval = 5

    private let queue = DispatchQueue(label: "com.voria.umsh.lan-radio.provider")
    private var radio: MobileVirtualRadio?
    private var running = false

    override func start() {
        queue.async { [self] in
            Self.logger.notice("starting the LAN virtual radio")
            running = true
            startRadio()
        }
    }

    override func stop(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        queue.async { [self] in
            Self.logger.notice("stopping the LAN virtual radio: \(reason.rawValue)")
            running = false
            radio?.stop()
            radio = nil
            completionHandler()
        }
    }

    private func startRadio() {
        guard running, radio == nil else { return }
        do {
            try FileManager.default.createDirectory(
                at: VirtualRadioPaths.stateDirectory,
                withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]
            )
            // Being on a listed network is choosing the LAN, so the radio
            // comes up listening whatever it saved.
            radio = try MobileVirtualRadio.serve(
                stateDir: VirtualRadioPaths.stateDirectory.path,
                socketPath: VirtualRadioPaths.socketPath,
                enablePhy: true,
                listener: QueuedNotifier()
            )
        } catch {
            Self.logger.error("the LAN virtual radio could not start: \(String(describing: error))")
            queue.asyncAfter(deadline: .now() + Self.retryDelaySeconds) { [weak self] in
                self?.startRadio()
            }
        }
    }
}

/// Tells the user of frames that arrive while the app is away.
private final class QueuedNotifier: MobileVirtualRadioListener, @unchecked Sendable {
    func onQueued(notice: MobileQueuedNoticeRecord) {
        guard notice.cue else { return }
        let content = UNMutableNotificationContent()
        switch notice.`class` {
        case .direct:
            content.body = String(localized: "New message")
        case .group:
            content.body = String(localized: "New channel message")
        }
        content.sound = .default
        content.threadIdentifier = "lan-radio"
        UNUserNotificationCenter.current().add(UNNotificationRequest(
            identifier: UUID().uuidString,
            content: content,
            trigger: nil
        ))
    }
}
