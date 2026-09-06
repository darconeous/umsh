import Foundation
import UMSHMobileCore

/// The ether around a fake radio: takes whatever the phone's mesh session
/// transmits and delivers whatever the rest of the fabricated mesh says back.
///
/// A `FakeRadioConnection` with no air is a radio in an empty room—sends
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
    /// The device the remote-management screens manage. Writes land on it,
    /// so a preview can change a setting and see the change stick.
    private var managedDevice = FakeManagedDevice()
    private var remoteDeviceReachable = true
    /// Screens listening for what this device announces on its own. Only
    /// the local link has any: a device pushes to the host it is attached
    /// to and to nobody else.
    private var pushContinuations:
        [UUID: AsyncStream<UlcpPropertyPushRecord>.Continuation] = [:]
    /// The scan or the link change now playing out, so a second one
    /// replaces it rather than interleaving with it.
    private var wifiTheater: Task<Void, Never>?
    /// Staging only: swallow every outbound frame, as a dead link would.
    private var transmissionsFail = false

    init(
        snapshot: RadioSnapshot = .previewReady,
        air: (any FakeRadioAir)? = nil,
        wifiScanOnly: Bool = false
    ) {
        self.snapshot = snapshot
        self.air = air
        managedDevice = FakeManagedDevice(scanOnly: wifiScanOnly)
    }

    /// Ask the staging air to have a staged peer message the phone. A no-op
    /// on any other air—previews have no peers to speak as.
    func stagedPeerSendsMessage(body: String, onChannel: Bool) async {
        #if DEBUG
        await (air as? StagingMeshAir)?.sendFromPeer(body: body, onChannel: onChannel)
        #endif
    }

    /// Ask the staging air to have a staged peer react to the phone's last
    /// message to it.
    func stagedPeerReacts(body: String) async {
        #if DEBUG
        await (air as? StagingMeshAir)?.reactFromPeer(body: body)
        #endif
    }

    /// Fail everything handed to this radio, as a link that has dropped
    /// would. The session hears that the transmission did not happen and
    /// gives up on the message, which is what a delivery failure is.
    ///
    /// A standing state rather than a one-shot: acknowledgements are frames
    /// too, so a single-use switch would be spent on the ack for whatever
    /// arrived next rather than on the message being tested.
    func setTransmissionsFailing(_ failing: Bool) {
        transmissionsFail = failing
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

    /// The administrator list is not mirrored on `RadioProvisioningSummary`
    ///—nothing in the app reads the phone's *own* radio's administrators,
    /// because managing that radio is what the local link is for. Accepting
    /// the mutation silently keeps a preview from reporting a failure that
    /// says nothing about the app.
    func addDeviceAdmin(_ publicKey: Data) async throws {}

    func removeDeviceAdmin(_ publicKey: Data) async throws {}

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

    func reconcileHostPeerKeys(_ entries: [HostPeerKeyEntryRecord]) async throws {
        guard var provisioning = snapshot.provisioning, provisioning.supportsHostKeys else {
            return
        }
        provisioning.hostPeerCount = min(entries.count, Int(ulcpMaxHostPeers()))
        var updated = snapshot
        updated.provisioning = provisioning
        publish(updated)
    }

    /// Nothing in the snapshot describes the mute tables, and nothing in the
    /// app reads them back—they steer a sound a simulated radio does not
    /// make—so the fake accepts them and keeps nothing.
    func reconcileHostMutes(channelIdentifiers: [Data], peerKeys: [Data]) async throws {}

    func setHostAutoAcknowledgement(_ enabled: Bool) async throws {
        guard var provisioning = snapshot.provisioning,
              provisioning.autoAcknowledgementEnabled != nil
        else { return }
        provisioning.autoAcknowledgementEnabled = enabled
        var updated = snapshot
        updated.provisioning = provisioning
        publish(updated)
    }

    func drainOfflineQueue() async throws {
        guard var provisioning = snapshot.provisioning, provisioning.supportsOfflineQueue else {
            return
        }
        provisioning.queuedFrames = 0
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

    /// The phone's own node key, fabricated so the management screens can
    /// tell "this phone" apart from any other administrator.
    func nodePublicKey() async -> Data? { FakeManagedDevice.phoneKey }

    /// Make every remote-management operation report a device out of
    /// reach, which is the state these screens are built to survive.
    ///
    /// The canned device answers by default, because a preview of a
    /// settings screen that can only show a timeout is a preview of
    /// nothing.
    func setRemoteDeviceReachable(_ reachable: Bool) {
        remoteDeviceReachable = reachable
    }

    func fetchRemoteProperties(
        peerAddress: String,
        propertyIDs: [UInt32],
        multiHint: Bool,
        progress: (@Sendable (UInt32?) -> Void)?
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        try await answerAsIfOverTheAir()
        progress?(0)
        return propertyIDs.map { property in
            MobileMeshManagementAnswerRecord(
                propertyId: property,
                value: managedDevice.values[property],
                // A property the canned device holds no value for is one
                // it does not implement, which is a refusal rather than
                // silence.
                statusCode: managedDevice.values[property] == nil ? Self.propertyNotFound : nil
            )
        }
    }

    func writeRemoteProperties(
        peerAddress: String,
        writes: [MobileMeshPropertyWriteRecord]
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        try await answerAsIfOverTheAir()
        return applyWrites(writes)
    }

    func saveRemoteDevice(peerAddress: String) async throws {
        try await answerAsIfOverTheAir()
    }

    func setRemoteDeviceAdmin(
        peerAddress: String,
        publicKey: Data,
        present: Bool
    ) async throws {
        try await answerAsIfOverTheAir()
        managedDevice.setKey(publicKey, present: present, in: ulcpProperties.devAdmins)
    }

    func setRemoteDevicePeer(
        peerAddress: String,
        publicKey: Data,
        present: Bool
    ) async throws {
        try await answerAsIfOverTheAir()
        managedDevice.setKey(publicKey, present: present, in: ulcpProperties.devPeers)
    }

    func setRemoteAlert(
        peerAddress: String,
        state: RadioAlertState
    ) async throws -> RadioAlertState {
        try await answerAsIfOverTheAir()
        return state
    }

    func resetRemoteDevice(peerAddress: String, scope: MobileMeshResetScope) async throws {
        try await answerAsIfOverTheAir()
    }

    func clearRemoteBluetoothBonds(peerAddress: String) async throws {
        try await answerAsIfOverTheAir()
        managedDevice.values[ulcpProperties.bleBondCount] = Data([0])
        // Clearing opens a pairing window, and the window is a property
        // the next refresh reads back.
        managedDevice.values[ulcpProperties.blePairing] = Data([1])
    }

    // MARK: - Managing the staging companion itself

    /// The staging companion answers the local management path from the
    /// same canned device the mesh path serves, minus the on-air delay:
    /// a local link answering instantly is the behavior being staged.
    func fetchCompanionProperties(
        _ propertyIDs: [UInt32]
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        propertyIDs.map { property in
            MobileMeshManagementAnswerRecord(
                propertyId: property,
                value: managedDevice.values[property],
                statusCode: managedDevice.values[property] == nil ? Self.propertyNotFound : nil
            )
        }
    }

    func writeCompanionProperties(
        _ writes: [MobileMeshPropertyWriteRecord]
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        applyWrites(writes)
    }

    func saveCompanionDevice() async throws {}

    /// What the staged device announces on its own.
    ///
    /// Nothing volunteers anything here except the Wi-Fi scan, which has
    /// no other way to arrive: a device reports each access point as it
    /// hears it, and a screen that waited for the whole table would show
    /// nothing until the scan ended.
    func companionPropertyPushes() async -> AsyncStream<UlcpPropertyPushRecord> {
        // Registered here rather than inside the stream's build closure:
        // that closure is not actor-isolated, so what it writes to an
        // actor's storage does not necessarily land there, and a listener
        // that silently fails to register is a scan that never arrives.
        let id = UUID()
        let (stream, continuation) = AsyncStream<UlcpPropertyPushRecord>.makeStream()
        pushContinuations[id] = continuation
        continuation.onTermination = { [weak self] _ in
            Task { await self?.dropPushListener(id) }
        }
        return stream
    }

    private func dropPushListener(_ id: UUID) {
        pushContinuations[id] = nil
    }

    private func push(
        _ property: UInt32,
        _ value: Data,
        kind: UlcpPropertyPushKind = .is
    ) {
        let record = UlcpPropertyPushRecord(
            propertyId: property,
            value: value,
            kind: kind
        )
        for continuation in pushContinuations.values { continuation.yield(record) }
    }

    // MARK: - Writing to the staged device

    /// Take a batch of writes as a device would.
    ///
    /// Most of them are echoed back verbatim, which is what a device that
    /// accepted them does; the one thing a real device does that this
    /// cannot is clamp a value it holds differently. The Wi-Fi ones are
    /// not settings that simply land: starting a scan, switching the
    /// station off, and choosing a network all set something in motion,
    /// and what the screens are worth testing against is that motion.
    private func applyWrites(
        _ writes: [MobileMeshPropertyWriteRecord]
    ) -> [MobileMeshManagementAnswerRecord] {
        writes.map { write in
            switch beginWifiEffect(of: write) {
            case .refused(let status):
                MobileMeshManagementAnswerRecord(
                    propertyId: write.propertyId,
                    value: nil,
                    statusCode: status
                )
            case .handled:
                MobileMeshManagementAnswerRecord(
                    propertyId: write.propertyId,
                    value: write.value,
                    statusCode: nil
                )
            case .store:
                store(write)
            }
        }
    }

    private func store(_ write: MobileMeshPropertyWriteRecord) -> MobileMeshManagementAnswerRecord {
        managedDevice.values[write.propertyId] = write.value
        return MobileMeshManagementAnswerRecord(
            propertyId: write.propertyId,
            value: write.value,
            statusCode: nil
        )
    }

    /// What a write does to the staged device beyond landing on it.
    private enum WriteOutcome {
        /// An ordinary setting: hold the value and echo it.
        case store
        /// Something the device now owns, and will report as it happens.
        case handled
        /// The device will not take it, and says why.
        case refused(UInt32)
    }

    /// Start whatever one write sets in motion, or say why the device
    /// will not take it.
    private func beginWifiEffect(of write: MobileMeshPropertyWriteRecord) -> WriteOutcome {
        let id = ulcpProperties
        switch write.propertyId {
        case id.wifiScanning:
            guard write.value.first == 1 else { return .store }
            // Nothing to scan with while the radio is off, which is what
            // `STATUS_INVALID_STATE` says. A device that only ever scans
            // has no station to have switched off.
            guard !managedDevice.joinsNetworks
                || managedDevice.values[id.wifiEnabled]?.first == 1
            else { return .refused(4) }
            // The scan raises the flag itself, on its own announcement,
            // so this write is answered rather than stored.
            play { await $0.runScan() }
            return .handled
        case id.wifiEnabled:
            let enabling = write.value.first == 1
            play { await $0.settleLink(up: enabling) }
            return .store
        case id.wifiNetwork:
            guard managedDevice.knowsNetwork(ssid: write.value) else { return .refused(20) }
            play { [selected = write.value] in await $0.settleLink(up: !selected.isEmpty) }
            return .store
        default:
            return .store
        }
    }

    /// Run one Wi-Fi sequence, replacing whatever was playing.
    private func play(_ act: @escaping @Sendable (FakeRadioConnection) async -> Void) {
        wifiTheater?.cancel()
        wifiTheater = Task { [weak self] in
            guard let self else { return }
            await act(self)
        }
    }

    /// A scan, in the order the chapter puts it on the air: the table
    /// cleared, the flag raised, one access point at a time as the device
    /// hears them, and the flag dropped.
    ///
    /// One BSSID is reported twice at different strengths, because a host
    /// that appended rather than replacing by key would show it twice and
    /// nothing else here would catch that.
    private func runScan() async {
        let id = ulcpProperties
        managedDevice.values[id.wifiScanResults] = Data()
        push(id.wifiScanResults, Data())
        managedDevice.values[id.wifiScanning] = Data([1])
        push(id.wifiScanning, Data([1]))
        var heard = Data()
        for result in Self.stagedAccessPoints {
            try? await Task.sleep(for: .milliseconds(320))
            guard !Task.isCancelled else { return }
            heard += FakeManagedDevice.item(result)
            managedDevice.values[id.wifiScanResults] = heard
            push(id.wifiScanResults, result, kind: .inserted)
        }
        try? await Task.sleep(for: .milliseconds(320))
        guard !Task.isCancelled else { return }
        managedDevice.values[id.wifiScanning] = Data([0])
        push(id.wifiScanning, Data([0]))
    }

    /// Bring the link and the IP stack to where a write just sent them.
    ///
    /// Down is immediate, because dropping an association is. Coming back
    /// is not: the device associates, then the network hands it an
    /// address, and both stages are visible because a screen that skipped
    /// them would never render either.
    private func settleLink(up: Bool) async {
        let id = ulcpProperties
        guard managedDevice.joinsNetworks else { return }
        guard up else {
            setLink(Data([0, 0]))
            setFamilies(state: 1)
            return
        }
        setLink(Data([1, 0]))
        setFamilies(state: 1)
        try? await Task.sleep(for: .seconds(1))
        guard !Task.isCancelled else { return }
        setLink(
            Data([2, 0]) + Data(FakeManagedDevice.baseStation)
                + UInt16(2_437).littleEndianData
        )
        setFamilies(state: 2)
        try? await Task.sleep(for: .seconds(1))
        guard !Task.isCancelled else { return }
        setFamilies(state: 3)
        push(id.wifiRssi, managedDevice.values[id.wifiRssi] ?? Data())
    }

    private func setLink(_ value: Data) {
        managedDevice.values[ulcpProperties.wifiLink] = value
        push(ulcpProperties.wifiLink, value)
    }

    /// Move both families to one readiness at once: they are on the same
    /// link, and it is the link that just moved.
    private func setFamilies(state: UInt8) {
        for property in [ulcpProperties.ipv4State, ulcpProperties.ipv6State] {
            managedDevice.values[property] = Data([state])
            push(property, Data([state]))
        }
    }

    /// Six access points around the staged device, with the base station
    /// heard twice: once from the far side of the ridge and once close
    /// in, which is one network and not two.
    private static let stagedAccessPoints: [Data] = [
        FakeManagedDevice.scanResult(
            modes: FakeManagedDevice.modes([2]),
            frequencyMHz: 2_437,
            rssiDBm: -74,
            bssid: FakeManagedDevice.baseStation,
            ssid: "Ridgeline Base"
        ),
        FakeManagedDevice.scanResult(
            modes: FakeManagedDevice.modes([2, 3]),
            frequencyMHz: 5_180,
            rssiDBm: -61,
            bssid: [0xA4, 0x2B, 0xB0, 0x5C, 0x11, 0x02],
            ssid: "Ridgeline Base"
        ),
        FakeManagedDevice.scanResult(
            modes: FakeManagedDevice.modes([3]),
            frequencyMHz: 5_955,
            rssiDBm: -68,
            bssid: [0x08, 0x9E, 0x01, 0x77, 0x43, 0x0A],
            ssid: "Tallac Field"
        ),
        FakeManagedDevice.scanResult(
            modes: FakeManagedDevice.modes([0, 1]),
            frequencyMHz: 2_462,
            rssiDBm: -80,
            bssid: [0x3C, 0x22, 0xFB, 0x10, 0x9C, 0x55],
            ssid: "Trailhead Guest"
        ),
        FakeManagedDevice.scanResult(
            modes: FakeManagedDevice.modes([6]),
            frequencyMHz: 5_240,
            rssiDBm: -77,
            bssid: [0xF0, 0x9F, 0xC2, 0x04, 0x18, 0x21],
            ssid: "TahoeNet-Staff"
        ),
        // Nameless, and the strongest thing in the room: an access point
        // that is not advertising what it is called.
        FakeManagedDevice.scanResult(
            modes: FakeManagedDevice.modes([2]),
            frequencyMHz: 2_412,
            rssiDBm: -52,
            bssid: [0x9C, 0x3D, 0xCF, 0x88, 0x00, 0x7E,],
            ssid: ""
        ),
        // The base station again, heard closer this time, so a host that
        // appends instead of replacing by BSSID shows it twice.
        FakeManagedDevice.scanResult(
            modes: FakeManagedDevice.modes([2]),
            frequencyMHz: 2_437,
            rssiDBm: -55,
            bssid: FakeManagedDevice.baseStation,
            ssid: "Ridgeline Base"
        ),
    ]

    // MARK: - The staged device's network table

    func addDeviceWifiNetwork(_ item: Data) async throws {
        try refuse(managedDevice.insertNetwork(item))
    }

    func removeDeviceWifiNetwork(ssid: Data) async throws {
        try refuse(managedDevice.removeNetwork(ssid: ssid))
    }

    func setRemoteWifiNetwork(
        peerAddress: String,
        item: Data,
        present: Bool
    ) async throws {
        try await answerAsIfOverTheAir()
        try refuse(
            present
                ? managedDevice.insertNetwork(item)
                : managedDevice.removeNetwork(ssid: item)
        )
    }

    /// Turn a device's refusal into the error a screen reports, treating
    /// `ITEM_NOT_FOUND` as the request already satisfied.
    private func refuse(_ status: UInt32?) throws {
        guard let status, status != 20 else { return }
        throw RemoteManagementError.refused(status: status)
    }

    /// `STATUS_PROP_NOT_FOUND`: how a device says it does not hold a
    /// property it was asked for.
    private static let propertyNotFound: UInt32 = 13

    /// Refuse when the canned device is switched out of reach, and
    /// otherwise take long enough that a screen's in-flight state is
    /// visible rather than a flicker.
    private func answerAsIfOverTheAir() async throws {
        guard remoteDeviceReachable else { throw RemoteManagementError.noAnswer }
        try? await Task.sleep(for: .milliseconds(400))
    }

    /// Mirrors the fake ping: one router on the way to the peer, so the route
    /// section has something to render in previews.
    func peerRoute(peerAddress: String) async throws -> RadioPeerRoute {
        routeCleared
            ? .unknown
            : RadioPeerRoute(
                kind: .source,
                hints: [Data([0x12, 0x34])],
                hopCount: 2,
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

    func reboot() async throws {
        // Same visible consequence as the real thing: the link drops while
        // the radio is away. Nothing staged is erased—that is the whole
        // difference between this and the factory reset above.
        publish(.disconnected)
    }

    func clearBluetoothBonds() async throws {
        // The real radio answers before it drops the bonds, so the staged
        // one answers and stays up: the disconnect that follows on
        // hardware is the transport's doing, not this command's.
        managedDevice.values[ulcpProperties.bleBondCount] = Data([0])
        managedDevice.values[ulcpProperties.blePairing] = Data([1])
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
            let transmitted = !transmissionsFail
            for frame in update.outboundFrames {
                try? meshSession.completeOutboundFrame(
                    frameId: frame.id,
                    transmitted: transmitted
                )
            }
            // Frames that never went out never reach the air either.
            if transmitted {
                queueForAir(update.outboundFrames.map(\.data))
            }
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
    /// acknowledges it—an unacknowledged batch stalls every batch behind it.
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

/// A plausible tracker for the remote-management screens to manage.
///
/// Everything here is the octets a real device would put on the air,
/// decoded by the same Rust reducers the real path uses—so a preview
/// exercises the actual decode rather than a hand-built record that could
/// be shaped however the screen happens to want.
struct FakeManagedDevice: Sendable {
    /// What this phone's own node key is, so an administrators list can
    /// show one row as "this phone".
    /// Distinct leading octets rather than one byte repeated: a node's hint
    /// is the front of its key, and the avatar's color comes from the hint—
    /// so keys of all 0x11 render a row of near-black circles that look like
    /// a bug in the avatar.
    static let phoneKey = Data([0x3C, 0x8E, 0xD1]) + Data(repeating: 0x11, count: 29)
    private static let otherAdminKey = Data([0xC7, 0x52, 0x9A]) + Data(repeating: 0x22, count: 29)
    private static let peerKey = Data([0x6B, 0xD4, 0x38]) + Data(repeating: 0x33, count: 29)

    /// Everything the device would answer, keyed by property.
    var values: [UInt32: Data]

    /// Whether this device has a station to join networks with, or only
    /// the receiver to hear them.
    ///
    /// The second kind is a real device: a tracker that scans for access
    /// points to fix its position by has every reason to report what it
    /// heard and no way to associate with any of it. The Wi-Fi screen has
    /// to render for both, so both are stageable.
    let joinsNetworks: Bool

    init(scanOnly: Bool = false) {
        joinsNetworks = !scanOnly
        let id = ulcpProperties
        values = [
            id.caps: scanOnly ? Self.scanOnlyCapabilities : Self.capabilities,
            id.deviceVersion: Data("fw-2026.08.11".utf8),
            id.deviceModel: Data("T1000-E".utf8),
            id.deviceName: Data("Ridgeline".utf8),
            // Flags, then 4.11 V, 78%, charging.
            id.battery: Data([0b111, 0x0F, 0x10, 78, 1]),
            id.phyEnabled: Data([1]),
            id.frequency: UInt32(906_875).littleEndianData,
            id.transmitPower: Data([22]),
            id.loraBandwidth: UInt32(250_000).littleEndianData,
            id.loraSpreadingFactor: Data([11]),
            id.loraCodingRate: Data([5]),
            // Fractions of UInt16.max: 1% used against a 10% limit.
            id.dutyCycleNow: UInt16(655).littleEndianData,
            id.dutyCycleLimit: UInt16(6_553).littleEndianData,
            id.statTxPackets: UInt32(1_284).littleEndianData,
            id.statTxChannelBusy: UInt32(37).littleEndianData,
            id.statRxPackets: UInt32(8_912).littleEndianData,
            id.statRxBadCrc: UInt32(46).littleEndianData,
            id.statRxNonUmsh: UInt32(119).littleEndianData,
            id.statRxAccepted: UInt32(2_405).littleEndianData,
            id.statForwarded: UInt32(1_733).littleEndianData,
            id.statForwardDropped: UInt32(82).littleEndianData,
            id.statForwardCancelled: UInt32(14).littleEndianData,
            id.uptime: UInt32(172_800).littleEndianData,
            id.identRole: Data([1]),
            id.identMobile: Data([0]),
            // Four octets of cell—about 600 m across—over Mount Tallac,
            // where the staging mesh puts this repeater. Altitude is two
            // octets because 2967 does not fit in one.
            id.identLocation: Data([0xB2, 0x7A, 0x59, 0x58]),
            id.identAltitude: Data([0x97, 0x0B]),
            id.devDiscoverable: Data([1]),
            id.gnssIdentUpdate: Data([0]),
            id.gnssIdentPrecision: Data([4]),
            // Twelve hours and one hour.
            id.advertInterval: UInt32(43_200).littleEndianData,
            id.beaconInterval: UInt32(3_600).littleEndianData,
            id.startupBeacon: Data([1]),
            id.gnssEnabled: Data([1]),
            id.gnssTimeTrust: Data([1]),
            id.bleEnabled: Data([1]),
            // Two paired phones, so Clear Pairings has something to say
            // it is forgetting.
            id.bleBondCount: Data([2]),
            // Attached: this fake stands in for a radio this phone is
            // talking to, and the property reports the session asking it.
            id.bleLink: Data([2]),
            // The pairing window starts closed, so the toggle has a state
            // to move away from.
            id.blePairing: Data([0]),
            // A clock a few seconds behind the phone's, so the Time screen
            // has a drift to state, and Pacific daylight time to state it in.
            id.time: UInt32(Date.now.timeIntervalSince1970 - 4).littleEndianData,
            id.tzOffset: Int16(-420).littleEndianData,
            // The receiver's own view, by property number: these five are
            // read through the decoded fix rather than named individually
            // by any screen, so there is nothing to borrow the numbers
            // from. A 3D fix on the same summit, held finer than the
            // identity advertises it.
            89: Data([0xB2, 0x7A, 0x59, 0x58, 0x8C, 0x1B]),
            90: Int32(2_967).littleEndianData,
            91: Data([2]),
            92: UInt16(41).littleEndianData,
            93: Data([9, 14]),
            id.repeaterEnabled: Data([1]),
            id.repeaterRegions: Data([3]) + Data("SJC".utf8),
            // Empty: this device never tags what arrives untagged.
            id.repeaterDefaultRegion: Data(),
            id.repeaterMinRssi: Int16(-115).littleEndianData,
            id.repeaterMinSnr: Data(),
            id.devPeers: Self.peerKey,
            id.devAdmins: Self.phoneKey + Self.otherAdminKey,
            // A scan every device can run, whether or not it can join
            // what it hears.
            id.wifiScanning: Data([0]),
            id.wifiScanResults: Data(),
        ]
        guard joinsNetworks else { return }
        for (property, value) in Self.stationValues { values[property] = value }
    }

    /// What a device with a station holds beyond the scan: the known
    /// networks, which one it is on, and the IP stack that follows.
    private static var stationValues: [UInt32: Data] {
        let id = ulcpProperties
        return [
            id.wifiEnabled: Data([1]),
            id.wifiNetworks: item(networkEntry("Ridgeline Base", security: 2))
                + item(networkEntry("Tallac Field", security: 3, hidden: true)),
            id.wifiNetwork: Data("Ridgeline Base".utf8),
            // Up on the base station, on channel 6.
            id.wifiLink: Data([2, 0]) + Data(baseStation) + UInt16(2_437).littleEndianData,
            id.wifiRssi: Int8(-58).littleEndianData,
            id.wifiMac: Data([0x2C, 0xF4, 0x32, 0x11, 0x22, 0x33]),
            id.ipv4State: Data([3]),
            id.ipv4Config: Data([1]),
            id.ipv4Address: Data([192, 168, 1, 42]) + Data([24]) + Data([192, 168, 1, 1]),
            id.ipv6State: Data([3]),
            id.ipv6Config: Data([1]),
            // A global address the router advertised, and the router
            // itself at its link-local address, which is where a router
            // normally is.
            id.ipv6Addresses: item(
                Data([0]) + globalV6 + Data([64])
            ) + item(Data([1]) + linkLocalV6),
            // Nothing configured, and the router doing the resolving.
            id.ipDns: Data(),
            id.ipResolvers: item(Data([192, 168, 1, 1])),
        ]
    }

    /// The access point the staged device is associated with.
    static let baseStation: [UInt8] = [0xA4, 0x2B, 0xB0, 0x5C, 0x11, 0x01]
    private static let globalV6 = Data([
        0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x1F, 0x42,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2A,
    ])
    private static let linkLocalV6 = Data([
        0xFE, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ])

    // MARK: - Wi-Fi octets

    /// One item of a multiple-value property.
    ///
    /// The length prefix is a packed unsigned integer, which is one octet
    /// for anything shorter than 128—and every item this device reports
    /// is far shorter than that.
    static func item(_ payload: Data) -> Data {
        Data([UInt8(payload.count)]) + payload
    }

    /// One known network as a device reports it: flags, mode, the SSID's
    /// length, and the SSID. Never a credential—the reported form does
    /// not carry one, which is the whole reason the table is edited an
    /// item at a time.
    static func networkEntry(
        _ ssid: String,
        security: UInt8,
        hidden: Bool = false
    ) -> Data {
        let name = Data(ssid.utf8)
        return Data([hidden ? 1 : 0, security, UInt8(name.count)]) + name
    }

    /// One access point a scan heard.
    static func scanResult(
        modes: UInt16,
        frequencyMHz: UInt16,
        rssiDBm: Int8,
        bssid: [UInt8],
        ssid: String
    ) -> Data {
        let name = Data(ssid.utf8)
        return modes.littleEndianData
            + frequencyMHz.littleEndianData
            + Int8(rssiDBm).littleEndianData
            + Data(bssid)
            + name
    }

    /// The bit for one `WIFI_SEC_*` mode, as a scan result reports the
    /// set it heard.
    static func modes(_ codes: [UInt8]) -> UInt16 {
        codes.reduce(into: UInt16(0)) { set, code in set |= 1 << UInt16(code) }
    }

    /// The known networks, split back into items.
    var networkEntries: [Data] {
        Self.splitItems(values[ulcpProperties.wifiNetworks] ?? Data())
    }

    /// Take one network the host offered, by the rules the chapter gives
    /// a device, answering with the status a refusal would carry.
    ///
    /// The refusals are the interesting half: this device has no WPA3, so
    /// it answers `UNIMPLEMENTED` and the join sheet offers the next mode
    /// down; it holds four networks, so a fifth is `NOMEM`; and a
    /// passphrase the mode cannot use is `INVALID_ARGUMENT` even though
    /// the phone checked it first, because the phone checking is a
    /// courtesy and the device deciding is the contract.
    mutating func insertNetwork(_ item: Data) -> UInt32? {
        guard item.count >= 3 else { return 3 }
        let security = item[item.startIndex + 1]
        let nameLength = Int(item[item.startIndex + 2])
        guard item.count >= 3 + nameLength else { return 3 }
        let ssid = item.subdata(in: item.startIndex + 3 ..< item.startIndex + 3 + nameLength)
        let credential = item.subdata(in: item.startIndex + 3 + nameLength ..< item.endIndex)
        guard security != 3 else { return 2 }
        if security == 2 || security == 4 {
            guard (8...63).contains(credential.count) else { return 3 }
        }
        var entries = networkEntries
        let replacing = entries.firstIndex { Self.ssid(ofEntry: $0) == ssid }
        if replacing == nil, entries.count >= 4 { return 11 }
        // Never the credential: a device stores it, and the table it
        // reports has never carried one.
        let reported = Data([item[item.startIndex], security, UInt8(nameLength)]) + ssid
        if let replacing {
            entries[replacing] = reported
        } else {
            entries.append(reported)
        }
        values[ulcpProperties.wifiNetworks] = entries.reduce(into: Data()) { $0 += Self.item($1) }
        return nil
    }

    /// Forget one network by name, answering `ITEM_NOT_FOUND` for one this
    /// device does not hold.
    mutating func removeNetwork(ssid: Data) -> UInt32? {
        var entries = networkEntries
        guard let position = entries.firstIndex(where: { Self.ssid(ofEntry: $0) == ssid })
        else { return 20 }
        entries.remove(at: position)
        values[ulcpProperties.wifiNetworks] = entries.reduce(into: Data()) { $0 += Self.item($1) }
        // Forgetting the network in use drops the link with it.
        if values[ulcpProperties.wifiNetwork] == ssid {
            values[ulcpProperties.wifiNetwork] = Data()
        }
        return nil
    }

    /// Whether this device knows a network by that name. An empty name is
    /// the deselection every device accepts.
    func knowsNetwork(ssid: Data) -> Bool {
        ssid.isEmpty || networkEntries.contains { Self.ssid(ofEntry: $0) == ssid }
    }

    /// The SSID out of one reported entry.
    private static func ssid(ofEntry entry: Data) -> Data {
        guard entry.count >= 3 else { return Data() }
        let length = Int(entry[entry.startIndex + 2])
        guard entry.count >= 3 + length else { return Data() }
        return entry.subdata(in: entry.startIndex + 3 ..< entry.startIndex + 3 + length)
    }

    /// A multiple-value property's octets, back into the items that built
    /// it. Single-octet length prefixes, as ``item(_:)`` writes.
    private static func splitItems(_ value: Data) -> [Data] {
        var items: [Data] = []
        var cursor = value.startIndex
        while cursor < value.endIndex {
            let length = Int(value[cursor])
            let start = value.index(after: cursor)
            guard let end = value.index(start, offsetBy: length, limitedBy: value.endIndex)
            else { break }
            items.append(value.subdata(in: start ..< end))
            cursor = end
        }
        return items
    }

    /// Add or drop one key in a fixed-width key table.
    mutating func setKey(_ key: Data, present: Bool, in property: UInt32) {
        var keys = stride(from: 0, to: values[property]?.count ?? 0, by: 32).map { offset in
            values[property]!.subdata(in: offset ..< offset + 32)
        }
        keys.removeAll { $0 == key }
        if present { keys.append(key) }
        values[property] = keys.reduce(into: Data()) { $0 += $1 }
    }

    /// `PROP_CAPS` for a fully-featured tracker: duty limit (16), save
    /// (36), device identity (37), device name (38), battery (39),
    /// repeater (40), identity (41), alert (42), administrators (43),
    /// clock (44), receiver (45), advertisement (46), batched commands
    /// (49), Bluetooth (50), restart (51), statistics (52), Wi-Fi scanning
    /// (53), the Wi-Fi station (54), IPv4 (55), IPv6 (56), and the LoRa
    /// modem (515, which needs two PUI octets).
    ///
    /// Bond management has no capability of its own: this fake claims it
    /// by answering `PROP_BLE_BOND_COUNT` rather than by listing a code.
    private static let capabilities = Data([
        0x10, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x83, 0x04,
    ])

    /// The same tracker with a receiver and no station: it lists Wi-Fi
    /// scanning (53) and neither the station nor either IP family, which
    /// is the shape a device that scans to place itself really has.
    private static let scanOnlyCapabilities = Data([
        0x10, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x83, 0x04,
    ])
}

private extension FixedWidthInteger {
    /// The octets ULCP puts this on the air as.
    var littleEndianData: Data {
        withUnsafeBytes(of: littleEndian) { Data($0) }
    }
}
