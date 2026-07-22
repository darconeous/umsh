import Foundation
import UMSHMobileCore

actor FakeRadioConnection: RadioConnection {
    private var snapshot: RadioSnapshot
    private var continuations: [UUID: AsyncStream<RadioSnapshot>.Continuation] = [:]
    private var frameContinuations: [UUID: AsyncStream<RadioReceivedFrame>.Continuation] = [:]
    private var chatContinuations: [UUID: AsyncStream<RadioChatUpdate>.Continuation] = [:]

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

    func chatUpdates() -> AsyncStream<RadioChatUpdate> {
        AsyncStream { continuation in
            let id = UUID()
            chatContinuations[id] = continuation
            continuation.onTermination = { [weak self] _ in
                Task { await self?.removeChatContinuation(id) }
            }
        }
    }

    func advertisementEvents() -> AsyncStream<RadioAdvertisementEvent> {
        AsyncStream { _ in }
    }

    func advertiseIdentity(name: String?) async throws {
        throw RadioConnectionError.identityUnavailable
    }

    func signIdentityBundle(name: String?) async throws -> Data {
        throw RadioConnectionError.identityUnavailable
    }

    func connect() async throws {
        publish(.previewReady)
    }

    func discoverRadios() -> AsyncStream<[DiscoveredRadio]> {
        AsyncStream { continuation in
            continuation.yield([])
            continuation.yield([
                DiscoveredRadio(
                    id: UUID(uuidString: "F2A1073A-2FF5-4D85-B71D-6A81031A9C25")!,
                    name: "T-Echo",
                    rssiDBm: -47,
                    isRemembered: true
                ),
                DiscoveredRadio(
                    id: UUID(uuidString: "0B4F2C10-1111-4222-9333-444455556666")!,
                    name: "T-1000-E",
                    rssiDBm: -72,
                    isRemembered: false
                ),
            ])
            continuation.finish()
        }
    }

    func selectRadio(_ id: UUID) async throws {
        publish(.previewReady)
    }

    func stopDiscovery() async {}

    func useHostIdentity(_ identity: MeshPublicIdentity?) async throws {}

    func useMeshSession(_ session: MobileMeshSession?) async {}

    func autoConnect() async {}

    func reconnect() async {
        publish(.previewReady)
    }

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
                phyEnabled: settings.phyEnabled,
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

    func prepareChat(
        peerAddresses: [String],
        checkpoints: [MobileChatCheckpointRecord]
    ) async throws {}

    func registerChatPeers(_ peerAddresses: [String]) async throws {}

    func composeText(
        peerAddress: String,
        clientToken: UInt32,
        body: String
    ) async throws -> MobileChatComposeBatchRecord {
        throw RadioConnectionError.incompatibleProtocol
    }

    func composeEdit(
        peerAddress: String,
        clientToken: UInt32,
        original: MobileChatOriginalRef,
        body: String
    ) async throws -> MobileChatComposeBatchRecord {
        throw RadioConnectionError.incompatibleProtocol
    }

    func composeDelete(
        peerAddress: String,
        clientToken: UInt32,
        original: MobileChatOriginalRef
    ) async throws -> MobileChatComposeBatchRecord {
        throw RadioConnectionError.incompatibleProtocol
    }

    func commitChatBatch(_ batchID: UInt64) async throws {}

    func rejectChatBatch(
        _ batchID: UInt64,
        checkpoints: [MobileChatCheckpointRecord]
    ) async throws {}

    func applyChatArchiveResult(
        requestID: UInt32,
        kind: MobileChatArchiveResultKind,
        payload: Data
    ) async throws {}

    func acknowledgeChatBatch(_ batchID: UInt64) async throws {}

    func disconnect() async {
        publish(.disconnected)
    }

    func forget() async {
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

    private func removeChatContinuation(_ id: UUID) {
        chatContinuations[id] = nil
    }
}
