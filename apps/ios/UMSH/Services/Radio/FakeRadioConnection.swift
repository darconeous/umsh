import Foundation
import UMSHMobileCore

actor FakeRadioConnection: RadioConnection {
    private var snapshot: RadioSnapshot
    private var continuations: [UUID: AsyncStream<RadioSnapshot>.Continuation] = [:]
    private var frameContinuations: [UUID: AsyncStream<RadioReceivedFrame>.Continuation] = [:]

    init(snapshot: RadioSnapshot = .previewReady) {
        self.snapshot = snapshot
    }

    func snapshots() -> AsyncStream<RadioSnapshot> {
        let initial = snapshot
        return AsyncStream { continuation in
            let id = UUID()
            continuations[id] = continuation
            continuation.yield(initial)
            continuation.onTermination = { [weak self] _ in
                Task { await self?.removeContinuation(id) }
            }
        }
    }

    func receivedFrames() -> AsyncStream<RadioReceivedFrame> {
        AsyncStream { continuation in
            let id = UUID()
            frameContinuations[id] = continuation
            continuation.onTermination = { [weak self] _ in
                Task { await self?.removeFrameContinuation(id) }
            }
        }
    }

    func connect() async throws {
        publish(.previewReady)
    }

    func useHostIdentity(_ identity: MeshPublicIdentity?) async throws {}

    func useMeshSession(_ session: MobileMeshSession?) async {}

    func autoConnect() async {}

    func claimForCurrentIdentity() async throws {
        publish(.previewReady)
    }

    func refresh() async throws -> RadioSnapshot {
        publish(snapshot)
        return snapshot
    }

    func configure(_ settings: RadioSettings) async throws {
        var updated = snapshot
        updated.name = settings.deviceName ?? updated.name
        if let provisioning = updated.provisioning {
            updated.provisioning = RadioProvisioningSummary(
                capabilityCount: provisioning.capabilityCount,
                hasHostFiltering: provisioning.hasHostFiltering,
                supportsOfflineQueue: provisioning.supportsOfflineQueue,
                supportsDelegatedAcknowledgements: provisioning.supportsDelegatedAcknowledgements,
                supportsDeviceName: provisioning.supportsDeviceName,
                supportsLoRa: provisioning.supportsLoRa,
                supportsDutyCycleLimit: provisioning.supportsDutyCycleLimit,
                phyEnabled: provisioning.phyEnabled,
                frequencyKHz: settings.frequencyKHz,
                transmitPowerDBm: settings.transmitPowerDBm,
                bandwidthHz: settings.bandwidthHz,
                spreadingFactor: settings.spreadingFactor,
                codingRateDenominator: settings.codingRateDenominator,
                dutyCycleNow: provisioning.dutyCycleNow,
                dutyCycleLimit: settings.dutyCycleLimit,
                saved: true,
                queuedFrames: provisioning.queuedFrames,
                droppedFrames: provisioning.droppedFrames,
                filterCount: provisioning.filterCount,
                hostChannelCount: provisioning.hostChannelCount,
                hostPeerCount: provisioning.hostPeerCount,
                autoAcknowledgementEnabled: provisioning.autoAcknowledgementEnabled
            )
        }
        publish(updated)
    }

    func ping(peerAddress: String) async throws -> RadioPingResult {
        .reply(
            RadioPingReply(
                roundTripMilliseconds: 42,
                hopCount: 2,
                routeHints: [Data([0x12, 0x34])],
                rssiDBm: -72,
                signalToNoiseCentibels: 650,
                linkQuality: 180
            )
        )
    }

    func disconnect() async {
        publish(.disconnected)
    }

    func publish(_ newSnapshot: RadioSnapshot) {
        snapshot = newSnapshot
        for continuation in continuations.values {
            continuation.yield(newSnapshot)
        }
    }

    func publish(_ frame: RadioReceivedFrame) {
        for continuation in frameContinuations.values {
            continuation.yield(frame)
        }
    }

    private func removeContinuation(_ id: UUID) {
        continuations[id] = nil
    }

    private func removeFrameContinuation(_ id: UUID) {
        frameContinuations[id] = nil
    }
}
