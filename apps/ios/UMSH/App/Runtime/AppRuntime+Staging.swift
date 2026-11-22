import Foundation
import OSLog
import UIKit
import UMSHMobileCore

extension AppRuntime {
    #if DEBUG
    /// Rewrite the staged mesh, when this root is the staging one.
    ///
    /// Runs before every start rather than only on a first launch, because
    /// the staged timeline is written relative to now: reseeding is what
    /// keeps the newest message reading "4 minutes ago" in a screenshot
    /// taken next month. Every write is keyed, so repeating it replaces
    /// rather than accumulates.
    func seedStagedContentIfNeeded(owner: String) async {
        guard isStaging, !isDetached, let writeStagedSeed else { return }
        // Kept, because canceling does not stop it: the seed writes in
        // several steps, and an erase of the staged store must not land
        // between them.
        let seed = Task {
            do {
                try await writeStagedSeed(owner)
            } catch {
                Self.logger.error(
                    "Could not seed staged content: \(String(describing: error), privacy: .public)"
                )
            }
        }
        stagedSeed = seed
        await seed.value
    }

    /// Wait for a staged seed this runtime began to finish writing. Once
    /// it is detached, it begins no other.
    func stagedSeedFinished() async {
        await stagedSeed?.value
    }
    #else
    func seedStagedContentIfNeeded(owner: String) async {}
    #endif

    #if DEBUG
    /// Fill a conversation with generated messages, so a transcript can be
    /// exercised at a size no test account reaches by hand.
    @Sendable
    func seedGeneratedMessages(_ address: String, _ count: Int) async throws {
        try await runChat(address) {
            try await $0.generateMessages(address: address, count: UInt32(clamping: count))
        }
    }
    #else
    var seedGeneratedMessages: ((String, Int) async throws -> Void)? { nil }
    #endif

    #if DEBUG
    /// What a staged peer says when asked to speak, cycled so repeated tests
    /// stay tellable apart.
    private static let stagedPeerLines = [
        "Radio check—you copy?",
        "Heading up the ridge now.",
        "Found the cache, all good.",
        "Back at basecamp before dark.",
    ]

    /// Staging only: the staged devices device setup offers beside the
    /// ones it finds over Bluetooth.
    var stagedAdministeredDevices: StagedAdministeredDevices? {
        (radioConnection as? StagingRadioConnection)?.administeredDevices
    }

    /// Staging only: a staged peer opens Add Peer, so it shows on Nearby,
    /// or asks the phone to exchange.
    func stagedPeerMeets(asking: Bool) {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        Task { await staging.stagedPeerMeets(asking: asking) }
    }

    /// Staging only: have a staged peer react to the phone's last message,
    /// after the same delay and for the same reason as a staged message.
    func stagedPeerReacts() {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        // As another client spells them on the wire.
        let token = ["<3", "+1", "-1", "ha", "!", "?"].randomElement() ?? "+1"
        Task {
            let assertion = UIApplication.shared.beginBackgroundTask(
                withName: "umsh.staging.delayed-reaction"
            )
            try? await Task.sleep(for: .seconds(5))
            await staging.stagedPeerReacts(body: token)
            if assertion != .invalid {
                UIApplication.shared.endBackgroundTask(assertion)
            }
        }
    }

    /// Staging only: have a staged peer reply to the phone's last message,
    /// after the same delay as a staged reaction.
    func stagedPeerReplies() {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        Task {
            let assertion = UIApplication.shared.beginBackgroundTask(
                withName: "umsh.staging.delayed-reply"
            )
            try? await Task.sleep(for: .seconds(5))
            await staging.stagedPeerReplies(body: "Sounds good, see you there.")
            if assertion != .invalid {
                UIApplication.shared.endBackgroundTask(assertion)
            }
        }
    }

    /// Staging only: make the radio drop everything handed to it, so sends
    /// fail the way they would over a link that has gone.
    func stagedDropTransmissions(_ dropping: Bool) {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        staging.setTransmissionsFailing(dropping)
    }

    /// Staging only: put the managed remote device out of reach, so the
    /// screens that ask across the mesh show what silence looks like.
    func stagedRemoteDevicesReachable(_ reachable: Bool) {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        staging.setRemoteDeviceReachable(reachable)
    }

    /// Staging only: have a staged peer message this phone after a short
    /// delay—long enough to background the app or lock the screen, which
    /// is the point of testing a notification. A no-op on a real radio.
    ///
    /// `onChannel` sends to the staged group chat instead of this phone. The
    /// two are worth testing separately: a group message names a channel and
    /// a speaker where a direct one names only a peer, and that difference is
    /// exactly what a notification has to carry.
    /// Staging only: have a staged peer say three things on the staged channel
    /// with the middle one lost on the air, leaving a gap in the transcript.
    func stagedPeerLosesChannelMessage() {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        let lines = Self.stagedPeerLines.shuffled()
        Task { await staging.stagedPeerLosesChannelMessage(bodies: (lines[0], lines[1], lines[2])) }
    }

    func stagedPeerSendsMessage(onChannel: Bool) {
        guard let staging = radioConnection as? StagingRadioConnection else { return }
        let line = Self.stagedPeerLines[
            Int.random(in: 0..<Self.stagedPeerLines.count)
        ]
        Task {
            // The whole point is pressing this and leaving the app, and a
            // backgrounded process suspends before a bare sleep expires.
            // The assertion keeps it running through the delay and the
            // staged peer's in-process send.
            let assertion = UIApplication.shared.beginBackgroundTask(
                withName: "umsh.staging.delayed-send"
            )
            try? await Task.sleep(for: .seconds(5))
            await staging.stagedPeerSendsMessage(body: line, onChannel: onChannel)
            if assertion != .invalid {
                UIApplication.shared.endBackgroundTask(assertion)
            }
        }
    }
    #else
    var stagedPeerSendsMessage: ((Bool) -> Void)? { nil }
    var stagedPeerLosesChannelMessage: (() -> Void)? { nil }
    var stagedPeerReacts: (() -> Void)? { nil }
    var stagedPeerReplies: (() -> Void)? { nil }
    var stagedPeerMeets: ((Bool) -> Void)? { nil }
    var stagedDropTransmissions: ((Bool) -> Void)? { nil }
    var stagedRemoteDevicesReachable: ((Bool) -> Void)? { nil }
    #endif
}
