import Foundation
import UMSHMobileCore

actor FakeRadioConnection: RadioConnection {
    private var snapshot: RadioSnapshot
    private var continuations: [UUID: AsyncStream<RadioSnapshot>.Continuation] = [:]
    private var frameContinuations: [UUID: AsyncStream<RadioReceivedFrame>.Continuation] = [:]
    private var chatContinuations: [UUID: AsyncStream<RadioChatUpdate>.Continuation] = [:]
    /// Lets a preview exercise reset: the canned route is reported once and
    /// then reads as forgotten, as a real one would.
    private var routeCleared = false
    /// Stands in for the phone MAC's channel table.
    private var registeredChannelKeys: Set<Data> = []

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

    func peerHeardEvents() -> AsyncStream<RadioPeerHeardEvent> {
        AsyncStream { _ in }
    }

    func advertiseIdentity(name: String?) async throws {
        throw RadioConnectionError.identityUnavailable
    }

    func advertiseIdentityScheduled(name: String?) async throws {
        throw RadioConnectionError.identityUnavailable
    }

    func sendBeacon() async throws {
        throw RadioConnectionError.identityUnavailable
    }

    func setPhoneDiscoverable(_ enabled: Bool, name: String?) async {}

    func requestIdentity(peerAddress: String) async throws {
        throw RadioConnectionError.identityUnavailable
    }

    func requestNearbyIdentities(roleFilter: UInt8?) async throws {}

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

    func refreshPositioning() async throws -> RadioSnapshot {
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
                supportsBattery: provisioning.supportsBattery,
                phyEnabled: settings.phyEnabled,
                frequencyKHz: settings.frequencyKHz,
                transmitPowerDBm: settings.transmitPowerDBm,
                bandwidthHz: settings.bandwidthHz,
                spreadingFactor: settings.spreadingFactor,
                codingRateDenominator: settings.codingRateDenominator,
                dutyCycleNow: provisioning.dutyCycleNow,
                dutyCycleLimit: settings.dutyCycleLimit,
                saved: .current,
                queuedFrames: provisioning.queuedFrames,
                droppedFrames: provisioning.droppedFrames,
                filterCount: provisioning.filterCount,
                hostChannelCount: provisioning.hostChannelCount,
                hostPeerCount: provisioning.hostPeerCount,
                autoAcknowledgementEnabled: provisioning.autoAcknowledgementEnabled,
                supportsDeviceIdentity: provisioning.supportsDeviceIdentity,
                devPeerAddresses: provisioning.devPeerAddresses
            )
        }
        publish(updated)
    }

    func addDevicePeer(_ publicKey: Data) async throws {
        try mutateDevicePeers(publicKey) { addresses, address in
            guard !addresses.contains(address) else { return }
            guard addresses.count < devicePeerCapacity else {
                throw DevicePeerError.deviceFull
            }
            addresses.append(address)
        }
    }

    func removeDevicePeer(_ publicKey: Data) async throws {
        try mutateDevicePeers(publicKey) { addresses, address in
            addresses.removeAll { $0 == address }
        }
    }

    func addDeviceChannel(_ channelKey: Data) async throws {
        try mutateDeviceChannels(channelKey) { identifiers, identifier in
            guard !identifiers.contains(identifier) else { return }
            guard identifiers.count < deviceChannelCapacity else {
                throw DevicePeerError.deviceFull
            }
            identifiers.append(identifier)
        }
    }

    func removeDeviceChannel(_ channelKey: Data) async throws {
        try mutateDeviceChannels(channelKey) { identifiers, identifier in
            identifiers.removeAll { $0 == identifier }
        }
    }

    func registerChannels(_ channelKeys: [Data]) async throws {
        registeredChannelKeys.formUnion(channelKeys)
    }

    func removeChannels(_ channelKeys: [Data]) async throws {
        registeredChannelKeys.subtract(channelKeys)
    }

    func reconcileHostChannels(_ channelKeys: [Data]) async throws {
        guard var provisioning = snapshot.provisioning, provisioning.supportsHostKeys else {
            return
        }
        provisioning.hostChannelCount = channelKeys.count
        var updated = snapshot
        updated.provisioning = provisioning
        publish(updated)
    }

    private func mutateDeviceChannels(
        _ channelKey: Data,
        _ mutate: (inout [Data], Data) throws -> Void
    ) rethrows {
        guard var provisioning = snapshot.provisioning,
              provisioning.supportsDeviceIdentity
        else { return }
        // The device reports identifiers, never keys.
        let identifier = (try? deriveChannelId(key: channelKey)) ?? Data(channelKey.prefix(2))
        var identifiers = provisioning.devChannelIDs ?? []
        try mutate(&identifiers, identifier)
        provisioning.devChannelIDs = identifiers
        var updated = snapshot
        updated.provisioning = provisioning
        publish(updated)
    }

    private func mutateDevicePeers(
        _ publicKey: Data,
        _ mutate: (inout [String], String) throws -> Void
    ) rethrows {
        guard var provisioning = snapshot.provisioning,
              provisioning.supportsDeviceIdentity
        else { return }
        let address = (try? inspectPublicIdentityBytes(publicKey: publicKey).canonicalAddress)
            ?? publicKey.base64EncodedString()
        var addresses = provisioning.devPeerAddresses ?? []
        try mutate(&addresses, address)
        provisioning.devPeerAddresses = addresses
        var updated = snapshot
        updated.provisioning = provisioning
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

    /// Mirrors the fake ping: one router on the way to the peer, so the route
    /// section has something to render in previews.
    func peerRoute(peerAddress: String) async throws -> RadioPeerRoute {
        routeCleared
            ? .unknown
            : RadioPeerRoute(
                kind: .source,
                hints: [Data([0x12, 0x34])],
                floodHops: nil,
                floodRegions: []
            )
    }

    func clearPeerRoute(peerAddress: String) async throws -> Bool {
        defer { routeCleared = true }
        return !routeCleared
    }

    func prepareChat(
        peerAddresses: [String],
        checkpoints: [MobileChatCheckpointRecord]
    ) async throws {}

    func registerChatPeers(_ peerAddresses: [String]) async throws {}

    func removeChatPeers(_ peerAddresses: [String]) async throws {}

    func requestIdentityByHint(conversationAddress: String, hint: Data) async throws {}

    func setChatDisplayName(_ name: String) async throws {}

    func composeText(
        conversationAddress: String,
        clientToken: UInt32,
        body: String
    ) async throws -> MobileChatComposeBatchRecord {
        throw RadioConnectionError.incompatibleProtocol
    }

    func composeEdit(
        conversationAddress: String,
        clientToken: UInt32,
        original: MobileChatOriginalRef,
        body: String
    ) async throws -> MobileChatComposeBatchRecord {
        throw RadioConnectionError.incompatibleProtocol
    }

    func composeDelete(
        conversationAddress: String,
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

    func factoryReset() async throws {
        publish(.disconnected)
    }

    func setAlert(_ state: RadioAlertState) async throws {
        var updated = snapshot
        updated.alert = state
        publish(updated)
    }

    func configurePositioning(
        gnss: UlcpGnssSettingsRecord?,
        timeZoneOffsetMinutes: Int16?
    ) async throws {
        var updated = snapshot
        updated.provisioning?.gnss = gnss
        updated.provisioning?.timeZoneOffsetMinutes = timeZoneOffsetMinutes
        publish(updated)
    }

    func configureAdvertising(_ advert: UlcpAdvertSettingsRecord?) async throws {
        var updated = snapshot
        updated.provisioning?.advert = advert
        publish(updated)
    }

    func setTime(epochSeconds: UInt32?) async throws {
        var updated = snapshot
        updated.clock = RadioClock(
            date: epochSeconds.map { Date(timeIntervalSince1970: TimeInterval($0)) },
            readAt: .now
        )
        publish(updated)
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
