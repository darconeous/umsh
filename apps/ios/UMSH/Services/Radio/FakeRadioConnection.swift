import Foundation
import UMSHMobileCore

/// The ether around a fake radio: takes whatever the phone's mesh session
/// transmits and delivers whatever the rest of the fabricated mesh says back.
///
/// A `FakeRadioConnection` with no air is a radio in an empty room — sends
/// complete without ever being heard, which is all a preview needs. Staging
/// hangs a whole mesh of real Rust sessions on this seam.
protocol FakeRadioAir: Sendable {
    /// Install the handler that carries mesh traffic back to the phone.
    func attach(onAir: @escaping @Sendable ([MobileMeshRxRecord]) -> Void) async
    /// Tell the mesh who the phone is, so peers can address it by name.
    func registerPhone(address: String) async
    /// One of the phone's frames hits the air.
    func transmit(_ data: Data) async
}

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
    /// What surrounds this radio. Without one, transmitted frames vanish.
    private let air: (any FakeRadioAir)?
    /// The same Rust session a real radio would drive. When the app installs
    /// one, the chat surface below stops pretending and delegates to it.
    private var meshSession: MobileMeshSession?
    private var wakeListener: FakeMeshSessionWakeListener?
    /// Frames on their way to the air, drained in order by one task so
    /// concurrent pumps cannot interleave a batch.
    private var airOutbox: [Data] = []
    private var airDrainer: Task<Void, Never>?
    private var lastYieldedChatBatchID: UInt64?
    private var lastChatBatchYield: ContinuousClock.Instant?
    private var chatRedelivery: Task<Void, Never>?

    init(snapshot: RadioSnapshot = .previewReady, air: (any FakeRadioAir)? = nil) {
        self.snapshot = snapshot
        self.air = air
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

    func setAdvertisedLocation(_ location: MobileMeshSharedLocationRecord?) async {}

    func setPhoneDiscoverable(_ enabled: Bool, name: String?) async {}

    func requestIdentity(peerAddress: String) async throws {
        throw RadioConnectionError.identityUnavailable
    }

    func requestNearbyIdentities(
        roleFilter: UInt8?,
        nodeHint: Data?,
        sourceRoute: [Data]
    ) async throws {}

    func signIdentityBundle(name: String?) async throws -> Data {
        throw RadioConnectionError.identityUnavailable
    }

    func connect() async throws {
        publish(snapshot)
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
        publish(snapshot)
    }

    func stopDiscovery() async {}

    func useHostIdentity(_ identity: MeshPublicIdentity?) async throws {
        if let identity {
            await air?.registerPhone(address: identity.canonicalAddress)
        }
    }

    func useMeshSession(_ session: MobileMeshSession?) async {
        meshSession = session
        guard let session else {
            wakeListener = nil
            return
        }
        let listener = FakeMeshSessionWakeListener(connection: self)
        wakeListener = listener
        session.setWakeListener(listener: listener)
        // Channel keys can arrive before the session does; replay them so the
        // session's channel table matches what the app believes it registered.
        if !registeredChannelKeys.isEmpty {
            try? await session.registerChannels(keys: Array(registeredChannelKeys))
        }
        if let air {
            await air.attach { [weak self] records in
                guard let self else { return }
                Task { await self.receiveAirFrames(records) }
            }
        }
        pump()
    }

    func autoConnect() async {}

    func reconnect() async {
        publish(snapshot)
    }

    func claimForCurrentIdentity() async throws {
        publish(snapshot)
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
        guard let meshSession, !channelKeys.isEmpty else { return }
        try await meshSession.registerChannels(keys: channelKeys)
    }

    func removeChannels(_ channelKeys: [Data]) async throws {
        registeredChannelKeys.subtract(channelKeys)
        guard let meshSession, !channelKeys.isEmpty else { return }
        try await meshSession.removeChannels(keys: channelKeys)
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
    ) async throws {
        guard let meshSession else { return }
        try await meshSession.registerPeers(peerAddresses: peerAddresses)
        try await meshSession.restoreChat(checkpoints: checkpoints)
    }

    func registerChatPeers(_ peerAddresses: [String]) async throws {
        guard let meshSession else { return }
        try await meshSession.registerPeers(peerAddresses: peerAddresses)
    }

    func removeChatPeers(_ peerAddresses: [String]) async throws {
        guard let meshSession else { return }
        try await meshSession.removePeers(peerAddresses: peerAddresses)
    }

    func requestIdentityByHint(conversationAddress: String, hint: Data) async throws {
        guard let meshSession else { return }
        try await meshSession.requestIdentityByHint(
            conversationAddress: conversationAddress,
            hint: hint
        )
        pump()
    }

    func setChatDisplayName(_ name: String) async throws {
        guard let meshSession else { return }
        try await meshSession.setChatDisplayName(name: name)
    }

    func composeText(
        conversationAddress: String,
        clientToken: UInt32,
        body: String
    ) async throws -> MobileChatComposeBatchRecord {
        guard let meshSession else { throw RadioConnectionError.incompatibleProtocol }
        return try await meshSession.composeText(
            conversationAddress: conversationAddress,
            clientToken: clientToken,
            body: body
        )
    }

    func composeEdit(
        conversationAddress: String,
        clientToken: UInt32,
        original: MobileChatOriginalRef,
        body: String
    ) async throws -> MobileChatComposeBatchRecord {
        guard let meshSession else { throw RadioConnectionError.incompatibleProtocol }
        return try await meshSession.composeEdit(
            conversationAddress: conversationAddress,
            clientToken: clientToken,
            original: original,
            body: body
        )
    }

    func composeDelete(
        conversationAddress: String,
        clientToken: UInt32,
        original: MobileChatOriginalRef
    ) async throws -> MobileChatComposeBatchRecord {
        guard let meshSession else { throw RadioConnectionError.incompatibleProtocol }
        return try await meshSession.composeDelete(
            conversationAddress: conversationAddress,
            clientToken: clientToken,
            original: original
        )
    }

    func composeReaction(
        conversationAddress: String,
        clientToken: UInt32,
        target: MobileChatRegardingRef,
        body: String
    ) async throws -> MobileChatComposeBatchRecord {
        guard let meshSession else { throw RadioConnectionError.incompatibleProtocol }
        return try await meshSession.composeReaction(
            conversationAddress: conversationAddress,
            clientToken: clientToken,
            target: target,
            body: body
        )
    }

    func commitChatBatch(_ batchID: UInt64) async throws {
        guard let meshSession else { return }
        try await meshSession.commitChatBatch(batchId: batchID)
        pump()
    }

    func rejectChatBatch(
        _ batchID: UInt64,
        checkpoints: [MobileChatCheckpointRecord]
    ) async throws {
        guard let meshSession else { return }
        try await meshSession.rejectChatBatch(batchId: batchID, checkpoints: checkpoints)
    }

    func applyChatArchiveResult(
        requestID: UInt32,
        kind: MobileChatArchiveResultKind,
        payload: Data
    ) async throws {
        guard let meshSession else { return }
        try meshSession.applyChatArchiveResult(
            requestId: requestID,
            kind: kind,
            payload: payload
        )
        pump()
    }

    func acknowledgeChatBatch(_ batchID: UInt64) async throws {
        guard let meshSession else { return }
        try meshSession.acknowledgeChatBatch(batchId: batchID)
        pump()
    }

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

    // MARK: - Mesh session pump

    /// Drain the Rust session the way a real radio link would: transmitted
    /// frames complete instantly (a fake radio's airtime is free), traffic
    /// goes to the air, and chat batches surface to the app.
    func pump() {
        guard let meshSession else { return }
        let update = meshSession.pollUpdate()
        if !update.outboundFrames.isEmpty {
            for frame in update.outboundFrames {
                try? meshSession.completeOutboundFrame(frameId: frame.id, transmitted: true)
            }
            queueForAir(update.outboundFrames.map(\.data))
        }
        yieldChatUpdate(from: update)
    }

    private func queueForAir(_ frames: [Data]) {
        guard air != nil, !frames.isEmpty else { return }
        airOutbox.append(contentsOf: frames)
        guard airDrainer == nil else { return }
        airDrainer = Task { await drainAir() }
    }

    private func drainAir() async {
        while !airOutbox.isEmpty {
            let frame = airOutbox.removeFirst()
            await air?.transmit(frame)
        }
        airDrainer = nil
    }

    /// Frames the surrounding mesh sends back to this radio.
    private func receiveAirFrames(_ records: [MobileMeshRxRecord]) {
        guard let meshSession else { return }
        for record in records {
            try? meshSession.receive(frame: record)
            let frame = RadioReceivedFrame(
                data: record.data,
                rssiDBm: record.rssiDbm.map(Int.init),
                linkQuality: record.lqi,
                signalToNoiseCentibels: record.snrCb.map(Int.init),
                wasBuffered: false,
                wasAcknowledgedByRadio: false,
                ageSeconds: 0
            )
            for continuation in frameContinuations.values {
                continuation.yield(frame)
            }
        }
        pump()
    }

    /// Same delivery discipline as the real connection: a batch is yielded
    /// once, then re-yielded every couple of seconds until the app
    /// acknowledges it — an unacknowledged batch stalls every batch behind it.
    private func yieldChatUpdate(from update: MobileMeshSessionUpdateRecord) {
        guard let batchID = update.chatBatchId else { return }
        let now = ContinuousClock.now
        let retryDue = lastChatBatchYield.map { now - $0 > .seconds(2) } ?? true
        guard batchID != lastYieldedChatBatchID || retryDue else { return }
        lastYieldedChatBatchID = batchID
        lastChatBatchYield = now
        let chatUpdate = RadioChatUpdate(
            batchID: batchID,
            mutations: update.chatMutations,
            deliveries: update.chatDeliveries,
            archiveLookups: update.chatArchiveLookups,
            senderResolutions: update.chatSenderResolutions,
            diagnostics: update.chatDiagnostics
        )
        for continuation in chatContinuations.values {
            continuation.yield(chatUpdate)
        }
        chatRedelivery?.cancel()
        chatRedelivery = Task { [weak self] in
            try? await Task.sleep(for: .seconds(2.5))
            guard !Task.isCancelled else { return }
            await self?.pump()
        }
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

/// Bridges the Rust session's pending-update announcement back into the
/// actor. Runs on the Rust worker thread; holds the connection weakly so a
/// retired session cannot keep it alive.
private final class FakeMeshSessionWakeListener: MobileMeshWakeListener, @unchecked Sendable {
    private weak var connection: FakeRadioConnection?

    init(connection: FakeRadioConnection) {
        self.connection = connection
    }

    func onUpdatePending() {
        guard let connection else { return }
        Task { await connection.pump() }
    }
}
