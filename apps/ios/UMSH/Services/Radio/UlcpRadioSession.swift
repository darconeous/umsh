import Foundation
import OSLog
import UMSHMobileCore

/// What to say in the log when a ULCP frame is refused.
///
/// A refusal that reaches the log as prose alone is unactionable: the
/// cause the Rust core named, the frame's own structure, and the octets
/// all exist at the point of failure and are worth carrying.
///
/// Cause and structure are logged `.public` — they are what a bug report
/// needs and neither carries user content. The octets are `.private`: a
/// ULCP payload is message plaintext.
enum UlcpFrameDiagnostic {
    /// The stable cause name for an error out of the Rust core.
    ///
    /// `MobileError` is a Swift enum, so bridging it through `NSError`
    /// the way `BluetoothErrorText` does would yield a synthesized domain
    /// and an ordinal. The case name is the diagnostic.
    static func cause(_ error: any Error) -> String {
        if let error = error as? MobileError {
            return String(describing: error)
        }
        return BluetoothErrorText.diagnostic(error)
    }

    /// The frame's header, command, and lengths, named by the Rust core
    /// so the log reads `PropIs` rather than `6`.
    static func structure(_ frame: Data) -> String {
        describeUlcpFrame(bytes: frame)
    }

    /// Bounded hex for the octets themselves. Truncated because a frame
    /// runs to 512 bytes and the head is where framing faults live.
    static func hex(_ bytes: Data, limit: Int = 64) -> String {
        let shown = bytes.prefix(limit).map { String(format: "%02x", $0) }.joined()
        return bytes.count > limit ? "\(shown)… (\(bytes.count)B)" : shown
    }
}

/// One transport carrying whole ULCP frames.
///
/// The session above it owns the protocol; a link owns only the physical
/// connection, the framing that transport requires (GATT segmentation,
/// HDLC-Lite on a byte stream), and whatever write pacing the medium
/// needs. Every call happens on the session's queue.
protocol UlcpFrameLink: AnyObject {
    /// True while the transport can carry frames right now.
    var linkIsReady: Bool { get }

    /// The identity to show for this radio: the bound peripheral over
    /// BLE, a synthesized one for transports with nothing to discover.
    /// Feeds `RadioSnapshot.localIdentifier`.
    var linkID: UUID? { get }

    /// What to call this radio before it reports its own name.
    var linkName: String? { get }

    /// True when the radio on the other end is the one the app is bound
    /// to. A transport that reaches exactly one radio is always bound to
    /// it; BLE can be connected to a radio it has not adopted.
    var linkIsBoundRadio: Bool { get }

    /// True when this transport will bring the link back by itself after
    /// an invalidate. A session with no standing reconnect behind it
    /// must not report a fault as transient: nothing would undo it, and
    /// the failure the user needs to see would never be published.
    var linkCanReconnect: Bool { get }

    /// Queue one complete ULCP frame.
    ///
    /// `rawTransactionID` tags the write carrying a raw transmit, so a
    /// transport that learns of a write failure can fail that
    /// transaction alone. Links with no per-write completion ignore it
    /// and report the whole link lost instead.
    func linkSend(frame: Data, rawTransactionID: UInt8?)

    /// Discard partly-framed input and anything queued to send. Called
    /// when a session starts, so nothing from the one before it can
    /// merge into the new session's first frame.
    func linkResetFraming()

    /// Tear the transport down: the session state behind it is no longer
    /// trustworthy.
    ///
    /// `retrying` says whether the session intends to come back. When it
    /// does, the transport takes its ordinary link-loss path — the
    /// standing reconnect, the reconnecting state — because that is what
    /// this is. When it does not, the transport stops trying and
    /// preserves the failure the session has already published, which an
    /// ordinary disconnect notice would otherwise overwrite.
    func linkInvalidate(retrying: Bool)

    /// The session reached `.attached`. Where a transport persists which
    /// radio the app is bound to, this is when it does so.
    func linkDidAttach()

    /// The radio reported its own name, which outranks whatever the
    /// transport had cached.
    func linkDidReportName(_ name: String)

    /// The radio is erasing itself and will reboot. Drop the binding,
    /// but leave the link up: the command still has to reach the wire.
    func linkAbandonBinding()
}

/// Everything a companion radio session does above its transport: the
/// ULCP handshake, the property model, the mesh pump, and every
/// operation the app performs against a radio.
///
/// Subclasses supply the link — and, with it, discovery, connection
/// lifecycle, and whatever the transport persists. This class never
/// names a transport.
class UlcpRadioSession: NSObject, @unchecked Sendable {
    /// The one queue everything runs on. Injected so a transport whose
    /// callbacks already arrive on a queue of its own (CoreBluetooth's,
    /// for one) can hand that same queue over rather than hop.
    let sessionQueue: DispatchQueue

    /// The transport, set by the subclass that is also the link.
    private(set) weak var link: (any UlcpFrameLink)?

    /// Bumped whenever the link comes up or goes down. Delayed work
    /// captures the value and compares it before acting, so a watchdog
    /// or deadline armed against one link cannot fire against the next.
    private(set) var linkGeneration: UInt64 = 0

    /// Reconnects left to spend on a fatal protocol fault.
    ///
    /// Most of these faults are one bad frame — a corrupted segment, a
    /// response that arrived after its transaction was retired — and the
    /// link comes back clean. A radio whose firmware genuinely disagrees
    /// with this app fails the same way every time, so the budget is
    /// small: reconnecting past it only hides the disagreement behind
    /// three teardowns instead of one.
    ///
    /// Refilled by an attach that *held*, so a fault after hours of
    /// healthy session gets its own budget rather than inheriting a spent
    /// one — while a radio that attaches and immediately faults cannot
    /// refill its way into reconnecting forever.
    private var fatalFaultRetriesRemaining = UlcpRadioSession.fatalFaultRetryBudget

    /// Monotonic stamp of the attach edge, against which that holding is
    /// measured. Uptime rather than wall clock: a clock adjustment must
    /// not decide whether a session counted.
    private var attachedAtUptimeNanoseconds: UInt64?

    init(sessionQueue: DispatchQueue) {
        self.sessionQueue = sessionQueue
        super.init()
    }

    /// Long enough for a several-hop LoRa round trip, but short enough that a
    /// silent peer does not leave the peer page waiting for half a minute.
    static let peerPingTimeoutMilliseconds: UInt64 = 8_000
    static let logger = Logger(subsystem: "com.umsh.ios", category: "UlcpDevice")
    static let maximumRawTransmitBusyRetries = 20
    /// Reconnects a fatal protocol fault is worth before the failure sticks.
    static let fatalFaultRetryBudget = 2
    /// How long an attach must hold before it earns a fresh retry budget.
    /// Below this, the attach is part of the failure rather than proof
    /// against it — a radio that attaches and immediately faults would
    /// otherwise refill its budget on every cycle and never give up.
    static let fatalFaultBudgetRefillSeconds: UInt64 = 60
    // The current mobile MAC needs the device's physical TX completion
    // before starting its ACK clock. A larger ULCP window is unsafe until the
    // device itself owns the inter-frame receive/ACK window.
    static let maximumRawTransmitsInFlight = 1
    /// Budget for one frame's physical transmission, from handing it to the
    /// device to the device saying what became of it.
    ///
    /// Generous beside the worst legitimate case — a maximum-size frame at
    /// the slowest spreading factor, after the device's channel-activity
    /// backoff — because expiring early fails a send that would have
    /// succeeded. It exists because the Rust MAC awaits this completion
    /// while holding the coordinator borrow: a device that accepts a frame
    /// and then never reports it parks every later send, ping, and identity
    /// request behind it for as long as the link stays up. The deadline
    /// bounds that to one frame, loudly.
    static let rawTransmitTimeoutSeconds: TimeInterval = 30

    struct PendingRawFrame {
        var data: Data
        var meshFrameID: UInt64
        /// TX_FLAG_NOCCA: transmit without the device's channel-activity
        /// check. Set by the Rust MAC for immediate acks.
        var nocca: Bool
        var busyRetries = 0
        /// Identifies this submission to its timeout, so a watchdog armed for
        /// an earlier use of the same transaction ID cannot expire a later
        /// one. Assigned when the frame goes in flight.
        var watchdogToken: UInt64 = 0
    }

    struct ManagementWaiter {
        let continuation: CheckedContinuation<MobileMeshManagementEventRecord, any Error>
        /// Called for every progress report, and never after the exchange
        /// resolves.
        let progress: (@Sendable (UInt32?) -> Void)?
    }


    var snapshot = RadioSnapshot.idle
    var continuations: [UUID: AsyncStream<RadioSnapshot>.Continuation] = [:]
    var frameContinuations: [UUID: AsyncStream<RadioReceivedFrame>.Continuation] = [:]
    var chatContinuations: [UUID: AsyncStream<RadioChatUpdate>.Continuation] = [:]
    var advertisementContinuations:
        [UUID: AsyncStream<RadioAdvertisementEvent>.Continuation] = [:]
    var peerHeardContinuations:
        [UUID: AsyncStream<RadioPeerHeardEvent>.Continuation] = [:]
    let ulcpSession = MobileUlcpSession()
    var syncAttempt = UUID()
    var selectedHostKey: Data?
    var refreshInProgress = false
    var refreshWaiters: [CheckedContinuation<RadioSnapshot, any Error>] = []
    var configurationWaiter: CheckedContinuation<Void, any Error>?
    var devicePeerWaiter: CheckedContinuation<Void, any Error>?
    var meshSession: MobileMeshSession?
    var pingWaiters: [UInt64: CheckedContinuation<RadioPingResult, any Error>] = [:]
    /// Callers awaiting a node-management exchange, by operation id.
    ///
    /// Shaped like `pingWaiters` because the operations are shaped alike —
    /// the Rust worker owns the timeout and reports the outcome as an event
    /// — with one addition: a whole-device read reports its progress along
    /// the way, and the handler for that has to outlive each report.
    var managementWaiters: [UInt64: ManagementWaiter] = [:]
    /// The one outstanding local management exchange — a property fetch,
    /// write pass, or save against the companion radio itself — resolved
    /// by the session update that carries its completion. One at a time
    /// because the Rust session runs one at a time.
    var localManagementWaiter:
        CheckedContinuation<UlcpLocalManagementEventRecord, any Error>?
    var propertyPushContinuations:
        [UUID: AsyncStream<UlcpPropertyPushRecord>.Continuation] = [:]
    var meshPumpGeneration = UUID()
    var meshPumpScheduled = false
    /// The last logged reason the mesh pump declined to run, so a wake storm
    /// against a parked link logs one line per state instead of one per wake.
    var lastReportedPumpDeferral: String?
    var pendingRawFrames: [PendingRawFrame] = []
    var rawTransmitsInFlight: [UInt8: PendingRawFrame] = [:]
    var nextRawTransmitWatchdogToken: UInt64 = 0
    /// Transactions the watchdog gave up on. A device that answers after the
    /// deadline is answering about a frame already failed, which is worth a
    /// line in the log but must not read as a protocol violation — that would
    /// tear down a link whose only fault was being slow.
    var abandonedRawTransactions: Set<UInt8> = []
    var lastYieldedChatBatchID: UInt64?
    var lastChatBatchYield = DispatchTime.distantFuture
    var autoEnableAttemptedGeneration: UInt64?
    var autoClaimAttemptedGeneration: UInt64?
    var hostKeyRestartAttemptedGeneration: UInt64?
    var framesAwaitingMeshSession: [MobileMeshRxRecord] = []
    static let maximumFramesAwaitingMeshSession = 32

    // periodic producer into unbounded memory growth (the default AsyncStream
    // policy buffers everything ever yielded until read).

    func snapshots() async -> AsyncStream<RadioSnapshot> {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                let initial = snapshot
                // Snapshots are absolute state: only the newest matters.
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
                    let id = UUID()
                    continuations[id] = continuation
                    continuation.yield(initial)
                    continuation.onTermination = { [weak self] _ in
                        self?.sessionQueue.async { [weak self] in
                            self?.continuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    func receivedFrames() async -> AsyncStream<RadioReceivedFrame> {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { continuation in
                    let id = UUID()
                    frameContinuations[id] = continuation
                    continuation.onTermination = { [weak self] _ in
                        self?.sessionQueue.async { [weak self] in
                            self?.frameContinuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    func chatUpdates() async -> AsyncStream<RadioChatUpdate> {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                // The Rust facade replays an unacknowledged batch on every
                // poll, so a dropped element is always re-delivered; only the
                // newest pending batch needs to sit in the buffer.
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
                    let id = UUID()
                    chatContinuations[id] = continuation
                    continuation.onTermination = { [weak self] _ in
                        self?.sessionQueue.async { [weak self] in
                            self?.chatContinuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    func advertisementEvents() async -> AsyncStream<RadioAdvertisementEvent> {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                // Advertisements are sparse; a small bounded buffer rides out
                // a briefly busy consumer without unbounded growth.
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(16)) { continuation in
                    let id = UUID()
                    advertisementContinuations[id] = continuation
                    continuation.onTermination = { [weak self] _ in
                        self?.sessionQueue.async { [weak self] in
                            self?.advertisementContinuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    func peerHeardEvents() async -> AsyncStream<RadioPeerHeardEvent> {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                // One event per accepted frame, so this is the busiest of the
                // event streams. Dropping the oldest under back-pressure is
                // right for presence: a stale sighting is worth less than the
                // one that superseded it.
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(64)) { continuation in
                    let id = UUID()
                    peerHeardContinuations[id] = continuation
                    continuation.onTermination = { [weak self] _ in
                        self?.sessionQueue.async { [weak self] in
                            self?.peerHeardContinuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    func advertiseIdentity(name: String?) async throws {
        let session = try await currentMeshSession()
        try await session.advertiseIdentity(
            name: name,
            timestamp: UInt32(clamping: Int(Date.now.timeIntervalSince1970))
        )
    }

    func advertiseIdentityScheduled(name: String?) async throws {
        let session = try await currentMeshSession()
        try await session.advertiseIdentityScheduled(
            name: name,
            timestamp: UInt32(clamping: Int(Date.now.timeIntervalSince1970))
        )
    }

    func sendBeacon() async throws {
        try await currentMeshSession().sendBeacon()
    }

    func setAdvertisedLocation(_ location: MobileMeshSharedLocationRecord?) async {
        guard let session = try? await currentMeshSession() else { return }
        try? await session.setAdvertisedLocation(location: location)
    }

    func setPhoneDiscoverable(_ enabled: Bool, name: String?) async {
        guard let session = try? await currentMeshSession() else { return }
        try? await session.setDiscoverable(enabled: enabled, name: name)
    }

    func requestIdentity(peerAddress: String) async throws {
        let session = try await currentMeshSession()
        try await session.requestIdentity(peerAddress: peerAddress)
    }

    func requestNearbyIdentities(
        roleFilter: UInt8?,
        nodeHint: Data?,
        sourceRoute: [Data]
    ) async throws {
        let session = try await currentMeshSession()
        try await session.discoverIdentities(
            roleCode: roleFilter,
            capabilityBits: nil,
            nodeHint: nodeHint,
            sourceRoute: sourceRoute
        )
    }

    func requestIdentityByHint(conversationAddress: String, hint: Data) async throws {
        let session = try await currentMeshSession()
        try await session.requestIdentityByHint(
            conversationAddress: conversationAddress,
            hint: hint
        )
    }

    func setChatDisplayName(_ name: String) async throws {
        let session = try await currentMeshSession()
        try await session.setChatDisplayName(name: name)
    }

    func peerRoute(peerAddress: String) async throws -> RadioPeerRoute {
        let session = try await currentMeshSession()
        return RadioPeerRoute(try await session.peerRoute(peerAddress: peerAddress))
    }

    func clearPeerRoute(peerAddress: String) async throws -> Bool {
        let session = try await currentMeshSession()
        return try await session.clearPeerRoute(peerAddress: peerAddress)
    }

    func signIdentityBundle(name: String?) async throws -> Data {
        let session = try await currentMeshSession()
        return try await session.signIdentityBundle(
            name: name,
            timestamp: UInt32(clamping: Int(Date.now.timeIntervalSince1970))
        )
    }


    func useHostIdentity(_ identity: MeshPublicIdentity?) async throws {
        let hostKey: Data?
        if let identity {
            hostKey = try UMSHMobileCore.publicIdentityBytes(
                address: identity.canonicalAddress
            )
        } else {
            hostKey = nil
        }
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                let hadKey = selectedHostKey != nil
                selectedHostKey = hostKey
                // A restored or standing-pending link can attach before app
                // bootstrap supplies the phone identity. The ULCP
                // session then classifies the host with no key and parks at
                // awaitingHost ("Phone identity unavailable") with nothing
                // to re-judge it. Restart synchronization now that the key
                // exists; a genuinely different owner still parks for the
                // user's decision.
                if hostKey != nil, !hadKey,
                   snapshot.linkState == .awaitingHost,
                   link?.linkIsReady == true {
                    beginSynchronization()
                }
                result.resume()
            }
        }
    }

    func useMeshSession(_ session: MobileMeshSession?) async {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                Self.logger.notice(
                    """
                    mesh session \(session == nil ? "cleared" : self.meshSession == nil ? "installed" : "replaced", privacy: .public); \
                    replaying \(self.framesAwaitingMeshSession.count, privacy: .public) held frame(s)
                    """
                )
                meshSession?.clearWakeListener()
                meshSession = session
                meshPumpGeneration = UUID()
                meshPumpScheduled = false
                // Batch IDs restart per session; the delivery gate must not
                // suppress a fresh session's first batches.
                lastYieldedChatBatchID = nil
                lastChatBatchYield = .distantFuture
                // Push, not poll: the Rust worker announces pending updates
                // (outbound frames, ping/advertisement events, chat batches)
                // through this listener, so no polling cadence exists. If
                // data is already pending, the listener fires immediately.
                session?.setWakeListener(listener: MeshSessionWakeListener(session: self))
                if let session {
                    for record in framesAwaitingMeshSession {
                        try? session.receive(frame: record)
                    }
                }
                framesAwaitingMeshSession.removeAll()
                result.resume()
            }
        }
    }

    /// Called by the Rust worker (on its own thread) whenever `pollUpdate`
    /// has new data. Hop to the Bluetooth queue and drain.
    fileprivate func meshSessionDidAnnounceUpdate() {
        sessionQueue.async { [weak self] in
            self?.scheduleMeshPump()
        }
    }

    func claimForCurrentIdentity() async throws {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, any Error>) in
            sessionQueue.async { [self] in
                do {
                    try claimForCurrentIdentityOnQueue()
                    result.resume()
                } catch {
                    result.resume(throwing: error)
                }
            }
        }
    }

    func claimForCurrentIdentityOnQueue() throws {
        guard link?.linkIsReady == true, let selectedHostKey else {
            Self.logger.error(
                """
                claim: precondition failed — link=\(self.link != nil, privacy: .public) \
                ready=\(self.link?.linkIsReady == true, privacy: .public) \
                hostKey=\(self.selectedHostKey != nil, privacy: .public)
                """
            )
            throw RadioConnectionError.identityUnavailable
        }
        guard snapshot.hostState == .unclaimed || snapshot.hostState == .belongsToAnotherIdentity
        else {
            Self.logger.error(
                "claim: refused from host state \(String(describing: self.snapshot.hostState), privacy: .public)"
            )
            throw RadioConnectionError.takeoverNotAllowed
        }

        Self.logger.notice(
            "claim: writing host key from state \(String(describing: self.snapshot.hostState), privacy: .public)"
        )
        do {
            try applySessionUpdate(
                ulcpSession.claim(hostKey: selectedHostKey)
            )
        } catch {
            reportOperationFailure("The radio could not replace its configured host", name: link?.linkName)
            throw RadioConnectionError.incompatibleProtocol
        }
    }

    func configure(_ settings: RadioSettings) async throws {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, any Error>) in
            sessionQueue.async { [self] in
                guard link?.linkIsReady == true else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                guard configurationWaiter == nil, !refreshInProgress else {
                    result.resume(throwing: RadioConnectionError.operationInProgress)
                    return
                }
                configurationWaiter = result
                do {
                    let record = UlcpRadioSettingsRecord(
                        deviceName: settings.deviceName,
                        phyEnabled: settings.phyEnabled,
                        frequencyKhz: settings.frequencyKHz,
                        transmitPowerDbm: settings.transmitPowerDBm,
                        bandwidthHz: settings.bandwidthHz,
                        spreadingFactor: settings.spreadingFactor,
                        codingRateDenom: settings.codingRateDenominator,
                        dutyCycleLimit: settings.dutyCycleLimit
                    )
                    try applySessionUpdate(
                        ulcpSession.configure(settings: record)
                    )
                } catch {
                    finishConfiguration(throwing: error)
                }
            }
        }
    }

    func configurePositioning(
        gnss: UlcpGnssSettingsRecord?,
        timeZoneOffsetMinutes: Int16?
    ) async throws {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, any Error>) in
            sessionQueue.async { [self] in
                guard link?.linkIsReady == true else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                guard configurationWaiter == nil, !refreshInProgress else {
                    result.resume(throwing: RadioConnectionError.operationInProgress)
                    return
                }
                configurationWaiter = result
                do {
                    try applySessionUpdate(
                        ulcpSession.configurePositioning(
                            gnss: gnss,
                            tzOffsetMin: timeZoneOffsetMinutes
                        )
                    )
                } catch {
                    finishConfiguration(throwing: error)
                }
            }
        }
    }

    func configureAdvertising(_ advert: UlcpAdvertSettingsRecord?) async throws {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, any Error>) in
            sessionQueue.async { [self] in
                guard link?.linkIsReady == true else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                guard configurationWaiter == nil, !refreshInProgress else {
                    result.resume(throwing: RadioConnectionError.operationInProgress)
                    return
                }
                configurationWaiter = result
                do {
                    try applySessionUpdate(
                        ulcpSession.configureAdvertising(advert: advert)
                    )
                } catch {
                    finishConfiguration(throwing: error)
                }
            }
        }
    }

    func addDevicePeer(_ publicKey: Data) async throws {
        try await performDevicePeerOperation { session in
            try session.insertDevicePeer(publicKey: publicKey)
        }
    }

    func removeDevicePeer(_ publicKey: Data) async throws {
        try await performDevicePeerOperation { session in
            try session.removeDevicePeer(publicKey: publicKey)
        }
    }

    func addDeviceAdmin(_ publicKey: Data) async throws {
        try await performDevicePeerOperation { session in
            try session.insertDeviceAdmin(publicKey: publicKey)
        }
    }

    func removeDeviceAdmin(_ publicKey: Data) async throws {
        try await performDevicePeerOperation { session in
            try session.removeDeviceAdmin(publicKey: publicKey)
        }
    }

    func addDeviceChannel(_ channelKey: Data) async throws {
        try await performDevicePeerOperation { session in
            try session.insertDeviceChannelKey(channelKey: channelKey)
        }
    }

    func removeDeviceChannel(_ channelKey: Data) async throws {
        try await performDevicePeerOperation { session in
            try session.removeDeviceChannelKey(channelKey: channelKey)
        }
    }

    func registerChannels(_ channelKeys: [Data]) async throws {
        guard !channelKeys.isEmpty else { return }
        try await currentMeshSession().registerChannels(keys: channelKeys)
    }

    func removeChannels(_ channelKeys: [Data]) async throws {
        guard !channelKeys.isEmpty else { return }
        try await currentMeshSession().removeChannels(keys: channelKeys)
    }

    func reconcileHostChannels(_ channelKeys: [Data]) async throws {
        try await performDevicePeerOperation(requiringDeviceIdentity: false) { session in
            try session.reconcileHostChannelKeys(keys: channelKeys)
        }
    }

    func drainOfflineQueue() async throws {
        try await performDevicePeerOperation(requiringDeviceIdentity: false) { session in
            try session.drainQueue()
        }
    }

    /// One `PROP_DEV_PEERS` mutation at a time, resolved by the update that
    /// carries its outcome. The Rust session requires an otherwise-idle
    /// attached session, so a mutation racing chat traffic reports
    /// `operationInProgress` rather than interleaving.
    ///
    /// Host-domain work sets `requiringDeviceIdentity` to false: it needs
    /// `CAP_HOST_KEYS`, which the Rust session checks for itself.
    func performDevicePeerOperation(
        requiringDeviceIdentity: Bool = true,
        _ operation: @escaping (MobileUlcpSession) throws -> UlcpSessionUpdateRecord
    ) async throws {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, any Error>) in
            sessionQueue.async { [self] in
                guard link?.linkIsReady == true,
                      snapshot.linkState == .attached || snapshot.linkState == .ready,
                      snapshot.hostState == .matchesCurrentIdentity
                else {
                    result.resume(throwing: DevicePeerError.radioUnavailable)
                    return
                }
                guard !requiringDeviceIdentity
                        || snapshot.provisioning?.supportsDeviceIdentity == true
                else {
                    result.resume(throwing: DevicePeerError.unsupported)
                    return
                }
                guard devicePeerWaiter == nil, configurationWaiter == nil, !refreshInProgress
                else {
                    result.resume(throwing: RadioConnectionError.operationInProgress)
                    return
                }
                devicePeerWaiter = result
                do {
                    try applySessionUpdate(operation(ulcpSession))
                } catch {
                    finishDevicePeerOperation(throwing: RadioConnectionError.operationInProgress)
                }
            }
        }
    }

    func finishDevicePeerOperation(throwing error: (any Error)?) {
        guard let waiter = devicePeerWaiter else { return }
        devicePeerWaiter = nil
        if let error {
            waiter.resume(throwing: error)
        } else {
            waiter.resume()
        }
    }

    /// Map a completed device-domain mutation's status to its caller-facing
    /// outcome. `ALREADY` and `ITEM_NOT_FOUND` are idempotent successes —
    /// the device holds (or lacks) the key exactly as requested. A failed
    /// chained save leaves the mutation live; the existing `saved` warning
    /// in Radio Detail covers persistence.
    func devicePeerOutcome(_ error: UlcpOperationErrorRecord?) -> (any Error)? {
        guard let error else { return nil }
        if error.operation.hasPrefix("save device") { return nil }
        if error.statusName.hasSuffix("ALREADY") || error.statusName.hasSuffix("ITEM_NOT_FOUND") {
            return nil
        }
        if error.statusName.hasSuffix("NOMEM") {
            return DevicePeerError.deviceFull
        }
        return DevicePeerError.failed(error.statusName)
    }

    func setAlert(_ state: RadioAlertState) async throws {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, any Error>) in
            sessionQueue.async { [self] in
                guard link?.linkIsReady == true else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                Self.logger.notice("action: user set locate alert to \(state.rawValue)")
                do {
                    try applySessionUpdate(
                        ulcpSession.setAlert(state: state.wire)
                    )
                    result.resume()
                } catch {
                    result.resume(throwing: RadioConnectionError.incompatibleProtocol)
                }
            }
        }
    }

    func setTime(epochSeconds: UInt32?) async throws {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, any Error>) in
            sessionQueue.async { [self] in
                guard link?.linkIsReady == true else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                Self.logger.notice(
                    "action: user \(epochSeconds == nil ? "cleared" : "set") the radio clock"
                )
                do {
                    try applySessionUpdate(
                        ulcpSession.setTime(epochSeconds: epochSeconds)
                    )
                    result.resume()
                } catch {
                    result.resume(throwing: RadioConnectionError.incompatibleProtocol)
                }
            }
        }
    }

    func factoryReset() async throws {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, any Error>) in
            sessionQueue.async { [self] in
                guard link?.linkIsReady == true else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                Self.logger.notice("action: user pressed Factory Reset")
                do {
                    try applySessionUpdate(ulcpSession.factoryReset())
                } catch {
                    result.resume(throwing: RadioConnectionError.incompatibleProtocol)
                    return
                }
                // The radio erases all state and reboots, dropping the link
                // itself. Abandon the binding so the app does not auto-reconnect
                // to the now-blank device — but do NOT cancel the connection
                // here: leaving the live link up lets the command's GATT write
                // flush before the radio's own reboot performs the disconnect.
                // (Set after applySessionUpdate, which re-remembers an attached
                // radio; clearing afterward wins.)
                link?.linkAbandonBinding()
                result.resume()
            }
        }
    }

    func reboot() async throws {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<Void, any Error>) in
            sessionQueue.async { [self] in
                guard link?.linkIsReady == true else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                Self.logger.notice("action: user pressed Restart Radio")
                do {
                    try applySessionUpdate(ulcpSession.reboot())
                } catch {
                    result.resume(throwing: RadioConnectionError.incompatibleProtocol)
                    return
                }
                // The link drops when the radio restarts, and the same
                // flush argument as the factory reset applies: leave the
                // connection up so the GATT write lands. The binding is
                // deliberately *kept* — the radio coming back is the same
                // radio, with the same bond and the same host key, and
                // reconnecting to it is the whole point.
                result.resume()
            }
        }
    }

    func ping(peerAddress: String) async throws -> RadioPingResult {
        try await withCheckedThrowingContinuation {
            (result: CheckedContinuation<RadioPingResult, any Error>) in
            sessionQueue.async { [self] in
                guard let meshSession,
                      link?.linkIsReady == true,
                      snapshot.linkState == .attached,
                      snapshot.hostState == .matchesCurrentIdentity
                else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                do {
                    let operation = try meshSession.ping(
                        peerAddress: peerAddress,
                        timeoutMs: Self.peerPingTimeoutMilliseconds
                    )
                    pingWaiters[operation] = result
                } catch {
                    result.resume(throwing: error)
                }
            }
        }
    }

    // MARK: - Managing another node over the mesh

    /// One outstanding node-management exchange.

    func nodePublicKey() async -> Data? {
        await withCheckedContinuation { (result: CheckedContinuation<Data?, Never>) in
            sessionQueue.async { [self] in
                result.resume(returning: meshSession?.nodePublicKey())
            }
        }
    }

    func fetchRemoteProperties(
        peerAddress: String,
        propertyIDs: [UInt32],
        multiHint: Bool,
        progress: (@Sendable (UInt32?) -> Void)?
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        guard !propertyIDs.isEmpty else { return [] }
        let event = try await performManagement(progress: progress) { session in
            try session.beginManagementFetch(
                peerAddress: peerAddress,
                propertyIds: propertyIDs,
                multiHint: multiHint
            )
        }
        // A read that comes back with nothing at all did not reach the
        // device: a device that answered said something about every
        // property it was asked for, refusals included.
        guard !event.answers.isEmpty else { throw RemoteManagementError.unreadable }
        return event.answers
    }

    func writeRemoteProperties(
        peerAddress: String,
        writes: [MobileMeshPropertyWriteRecord]
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        var remaining = writes
        var answers: [MobileMeshManagementAnswerRecord] = []
        while !remaining.isEmpty {
            let batch = remaining
            let event = try await performManagement { session in
                try session.beginManagementSetMany(peerAddress: peerAddress, writes: batch)
            }
            // A device stops before the answer it is composing would
            // overflow, so a short reply is the ordinary case rather than a
            // fault — but a reply with nothing in it says the first write
            // alone would not fit, and reissuing it would loop forever.
            guard !event.answers.isEmpty else { throw RemoteManagementError.unreadable }
            answers.append(contentsOf: event.answers)
            remaining.removeFirst(min(event.answers.count, remaining.count))
        }
        return answers
    }

    /// Restart or wipe a device across the mesh.
    ///
    /// The reset-class commands are answered by nothing: the device acts and
    /// the MAC acknowledgment is the confirmation, so `.acknowledged` is
    /// success rather than a shortfall and there is no status to require.
    /// The one reply any of them produces is a refusal — a device without
    /// `CAP_REBOOT` saying it cannot restart — and that is worth surfacing.
    func resetRemoteDevice(peerAddress: String, scope: MobileMeshResetScope) async throws {
        let event = try await performManagement { session in
            try session.beginManagementReset(peerAddress: peerAddress, scope: scope)
        }
        if let status = event.statusCode {
            try Self.requireSuccess(status)
        }
    }

    func clearRemoteBluetoothBonds(peerAddress: String) async throws {
        // Forgetting every host is the bond count written to zero, so this
        // is an ordinary property write and the device echoes the count it
        // now holds. A refusal arrives as a status in place of that value.
        let answers = try await writeRemoteProperties(
            peerAddress: peerAddress,
            writes: [
                MobileMeshPropertyWriteRecord(
                    propertyId: ulcpManagedPropertyIds().bleBondCount,
                    value: Data([0])
                )
            ]
        )
        guard let answer = answers.first else { throw RemoteManagementError.unreadable }
        if answer.value == nil {
            throw RemoteManagementError.refused(status: answer.statusCode ?? 0)
        }
    }

    func saveRemoteDevice(peerAddress: String) async throws {
        let event = try await performManagement { session in
            try session.beginManagementSave(peerAddress: peerAddress)
        }
        try Self.requireSuccess(event.statusCode)
    }

    func setRemoteDeviceAdmin(
        peerAddress: String,
        publicKey: Data,
        present: Bool
    ) async throws {
        let event = try await performManagement { session in
            present
                ? try session.beginManagementInsertAdmin(
                    peerAddress: peerAddress,
                    publicKey: publicKey
                )
                : try session.beginManagementRemoveAdmin(
                    peerAddress: peerAddress,
                    publicKey: publicKey
                )
        }
        try Self.requireTableEdit(event)
    }

    func setRemoteDevicePeer(
        peerAddress: String,
        publicKey: Data,
        present: Bool
    ) async throws {
        let event = try await performManagement { session in
            present
                ? try session.beginManagementInsertPeer(
                    peerAddress: peerAddress,
                    publicKey: publicKey
                )
                : try session.beginManagementRemovePeer(
                    peerAddress: peerAddress,
                    publicKey: publicKey
                )
        }
        try Self.requireTableEdit(event)
    }

    /// Read the answer to a one-entry table edit.
    ///
    /// The device answers with the list as it now stands, or with a status
    /// where that list belonged. `ALREADY` and `ITEM_NOT_FOUND` are the
    /// request already satisfied, as on the bench path.
    private static func requireTableEdit(_ event: MobileMeshManagementEventRecord) throws {
        guard let answer = event.answers.first else {
            try requireSuccess(event.statusCode)
            return
        }
        if let status = answer.statusCode {
            try requireSuccess(status)
        }
    }

    func setRemoteAlert(
        peerAddress: String,
        state: RadioAlertState
    ) async throws -> RadioAlertState {
        let event = try await performManagement { session in
            try session.beginManagementSetAlert(
                peerAddress: peerAddress,
                state: state.wire
            )
        }
        guard let answer = event.answers.first else {
            try Self.requireSuccess(event.statusCode)
            throw RemoteManagementError.unreadable
        }
        if let status = answer.statusCode {
            try Self.requireSuccess(status)
        }
        // A write is echoed with what the device is now doing, and that is
        // the answer worth showing: a device may refuse to start an alert
        // it has no way to make, and one already running restarts its own
        // deadline rather than reporting anything new.
        guard let value = answer.value,
              let reported = try? inspectUlcpAlert(value: value)
        else { throw RemoteManagementError.unreadable }
        return RadioAlertState(reported)
    }

    /// Treat as success anything that leaves the device holding what was
    /// asked for.
    ///
    /// `ALREADY` and `ITEM_NOT_FOUND` are a complaint about a request that
    /// was already satisfied — the same reading `devicePeerOutcome` gives
    /// them on the local link, and for the same reason: an operator asked
    /// for a state, not for a change.
    static func requireSuccess(_ status: UInt32?) throws {
        guard let status, status != 0 else { return }
        let name = ulcpStatusName(status: status)
        guard !name.hasSuffix("ALREADY"), !name.hasSuffix("ITEM_NOT_FOUND") else { return }
        throw RemoteManagementError.refused(status: status)
    }

    // MARK: - Managing the companion radio itself

    /// Read named properties from the companion radio over the local link.
    ///
    /// The local counterpart of `fetchRemoteProperties`: same answers,
    /// same refusal semantics, no mesh in between. `multiHint` has no
    /// local meaning — single reads already pipeline on a fast link.
    func fetchCompanionProperties(
        _ propertyIDs: [UInt32]
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        guard !propertyIDs.isEmpty else { return [] }
        let event = try await performLocalManagement { session in
            try session.beginPropertyFetch(propertyIds: propertyIDs)
        }
        return event.answers
    }

    /// Write properties to the companion radio, in the given order.
    func writeCompanionProperties(
        _ writes: [MobileMeshPropertyWriteRecord]
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        guard !writes.isEmpty else { return [] }
        let event = try await performLocalManagement { session in
            try session.beginPropertyWrites(writes: writes)
        }
        return event.answers
    }

    /// Persist the companion radio's live configuration.
    func saveCompanionDevice() async throws {
        let event = try await performLocalManagement { session in
            try session.beginSave()
        }
        try Self.requireSuccess(event.statusCode)
    }

    func clearBluetoothBonds() async throws {
        Self.logger.notice("action: user cleared the radio's Bluetooth pairings")
        // The bond count written to zero. The radio answers before it drops
        // the bonds, so this completes normally and the disconnect arrives
        // afterward on its own. The binding is kept: this is the same
        // radio, and the operator's next move is pairing with it again.
        let answers = try await writeCompanionProperties([
            MobileMeshPropertyWriteRecord(
                propertyId: ulcpManagedPropertyIds().bleBondCount,
                value: Data([0])
            )
        ])
        guard let answer = answers.first else { throw RemoteManagementError.unreadable }
        if answer.value == nil {
            throw RemoteManagementError.refused(status: answer.statusCode ?? 0)
        }
    }

    /// Values the companion radio announces on its own, verbatim.
    func companionPropertyPushes() async -> AsyncStream<UlcpPropertyPushRecord> {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                // Pushes are sparse — battery, alert, the occasional fix —
                // and each merges independently, so a small bounded buffer
                // rides out a busy consumer without unbounded growth.
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(16)) { continuation in
                    let id = UUID()
                    propertyPushContinuations[id] = continuation
                    continuation.onTermination = { [weak self] _ in
                        self?.sessionQueue.async { [weak self] in
                            self?.propertyPushContinuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    /// Run one local management exchange to completion.
    ///
    /// Errors wear `RemoteManagementError` so the management screens read
    /// this path and the mesh path with the same copy. The stranded and
    /// link-down paths release the waiter the same way they release
    /// everything else.
    func performLocalManagement(
        _ start: @escaping (MobileUlcpSession) throws -> UlcpSessionUpdateRecord
    ) async throws -> UlcpLocalManagementEventRecord {
        try await withCheckedThrowingContinuation {
            (result: CheckedContinuation<UlcpLocalManagementEventRecord, any Error>) in
            sessionQueue.async { [self] in
                guard link?.linkIsReady == true, snapshot.linkState == .attached else {
                    result.resume(throwing: RemoteManagementError.unavailable)
                    return
                }
                guard localManagementWaiter == nil else {
                    result.resume(throwing: RemoteManagementError.unavailable)
                    return
                }
                localManagementWaiter = result
                do {
                    // An immediate completion — a save with nothing to ask —
                    // resolves the waiter inside this call.
                    try applySessionUpdate(start(ulcpSession))
                } catch {
                    finishLocalManagement(throwing: RemoteManagementError.unavailable)
                }
            }
        }
    }

    func finishLocalManagement(with event: UlcpLocalManagementEventRecord) {
        guard let waiter = localManagementWaiter else { return }
        localManagementWaiter = nil
        waiter.resume(returning: event)
    }

    func finishLocalManagement(throwing error: any Error) {
        guard let waiter = localManagementWaiter else { return }
        localManagementWaiter = nil
        waiter.resume(throwing: error)
    }

    /// Run one node-management exchange to completion.
    ///
    /// Unlike a ULCP operation over the local link, several of these can be
    /// in flight — the Rust worker refuses a second device outright and
    /// answers for it, so there is nothing to serialize here.
    func performManagement(
        progress: (@Sendable (UInt32?) -> Void)? = nil,
        _ start: @escaping (MobileMeshSession) throws -> UInt64
    ) async throws -> MobileMeshManagementEventRecord {
        let event = try await withCheckedThrowingContinuation {
            (result: CheckedContinuation<MobileMeshManagementEventRecord, any Error>) in
            sessionQueue.async { [self] in
                guard let meshSession,
                      link?.linkIsReady == true,
                      snapshot.linkState == .attached,
                      snapshot.hostState == .matchesCurrentIdentity
                else {
                    result.resume(throwing: RemoteManagementError.unavailable)
                    return
                }
                do {
                    let operation = try start(meshSession)
                    managementWaiters[operation] = ManagementWaiter(
                        continuation: result,
                        progress: progress
                    )
                } catch {
                    result.resume(throwing: RemoteManagementError.unavailable)
                }
            }
        }
        switch event.outcome {
        case .replied, .acknowledged:
            return event
        case .timedOut:
            throw RemoteManagementError.noAnswer
        case .failed:
            throw RemoteManagementError.unreadable
        case .progress:
            // Progress never resolves a waiter; reaching here would mean the
            // pump resumed one with a report rather than an ending.
            throw RemoteManagementError.unreadable
        }
    }

    func prepareChat(
        peerAddresses: [String],
        checkpoints: [MobileChatCheckpointRecord]
    ) async throws {
        let session = try await currentMeshSession()
        try await session.registerPeers(peerAddresses: peerAddresses)
        try await session.restoreChat(checkpoints: checkpoints)
    }

    func registerChatPeers(_ peerAddresses: [String]) async throws {
        let session = try await currentMeshSession()
        try await session.registerPeers(peerAddresses: peerAddresses)
    }

    func removeChatPeers(_ peerAddresses: [String]) async throws {
        let session = try await currentMeshSession()
        try await session.removePeers(peerAddresses: peerAddresses)
    }

    func composeText(
        conversationAddress: String,
        clientToken: UInt32,
        body: String
    ) async throws -> MobileChatComposeBatchRecord {
        let session = try await currentMeshSession()
        return try await session.composeText(
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
        let session = try await currentMeshSession()
        return try await session.composeEdit(
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
        let session = try await currentMeshSession()
        return try await session.composeDelete(
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
        let session = try await currentMeshSession()
        return try await session.composeReaction(
            conversationAddress: conversationAddress,
            clientToken: clientToken,
            target: target,
            body: body
        )
    }

    func commitChatBatch(_ batchID: UInt64) async throws {
        let session = try await currentMeshSession()
        try await session.commitChatBatch(batchId: batchID)
    }

    func rejectChatBatch(
        _ batchID: UInt64,
        checkpoints: [MobileChatCheckpointRecord]
    ) async throws {
        let session = try await currentMeshSession()
        try await session.rejectChatBatch(batchId: batchID, checkpoints: checkpoints)
    }

    func applyChatArchiveResult(
        requestID: UInt32,
        kind: MobileChatArchiveResultKind,
        payload: Data
    ) async throws {
        let session = try await currentMeshSession()
        try session.applyChatArchiveResult(requestId: requestID, kind: kind, payload: payload)
    }

    func acknowledgeChatBatch(_ batchID: UInt64) async throws {
        let session = try await currentMeshSession()
        try session.acknowledgeChatBatch(batchId: batchID)
    }

    func refresh() async throws -> RadioSnapshot {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<RadioSnapshot, any Error>) in
            sessionQueue.async { [self] in
                guard link?.linkIsReady == true else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                guard configurationWaiter == nil else {
                    result.resume(throwing: RadioConnectionError.operationInProgress)
                    return
                }
                refreshWaiters.append(result)
                guard !refreshInProgress else { return }
                refreshInProgress = true
                do {
                    try applySessionUpdate(ulcpSession.refresh())
                } catch {
                    finishRefresh(throwing: error)
                }
            }
        }
    }

    func refreshPositioning() async throws -> RadioSnapshot {
        try await withCheckedThrowingContinuation { (result: CheckedContinuation<RadioSnapshot, any Error>) in
            sessionQueue.async { [self] in
                guard link?.linkIsReady == true else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                guard configurationWaiter == nil else {
                    result.resume(throwing: RadioConnectionError.operationInProgress)
                    return
                }
                // Shares the refresh waiters, because it shares the
                // machinery: both are a bounded read whose completion is
                // the same event. A caller polling this cannot starve a
                // full refresh — it joins it.
                refreshWaiters.append(result)
                guard !refreshInProgress else { return }
                refreshInProgress = true
                do {
                    try applySessionUpdate(ulcpSession.refreshPositioning())
                } catch {
                    finishRefresh(throwing: error)
                }
            }
        }
    }


    func publish(
        state: RadioLinkState,
        name: String? = nil,
        localIdentifier: UUID? = nil
    ) {
        publish(
            RadioSnapshot(
                linkState: state,
                name: name,
                localIdentifier: localIdentifier,
                batteryPercentage: nil,
                batteryVoltageMillivolts: nil,
                chargeState: nil,
                batteryReadAt: nil,
                deviceIdentity: nil,
                hostState: .unknown,
                provisioning: nil,
                problemDescription: nil
            )
        )
    }

    /// Whether the attach now ending lasted long enough to count as a
    /// working session, and so to earn this fault a fresh retry budget.
    ///
    /// A session that never attached, or attached and fell over inside
    /// the window, is one continuing failure and keeps spending the
    /// budget it started with.
    private func attachHeldLongEnoughToEarnFreshRetries() -> Bool {
        guard let attachedAt = attachedAtUptimeNanoseconds else { return false }
        let held = DispatchTime.now().uptimeNanoseconds &- attachedAt
        return held >= Self.fatalFaultBudgetRefillSeconds * 1_000_000_000
    }

    /// Tear down a ULCP link only when its framing or session state is
    /// no longer trustworthy. Ordinary ULCP status failures and rejected
    /// operations must never come through this path.
    ///
    /// The teardown is not the same as giving up. Most of these faults
    /// are one bad frame, so the first few spend a retry and come back
    /// through the transport's ordinary reconnect; only once the budget
    /// is gone does the failure stick and the UI report it.
    ///
    /// `detail` names the cause and the frame's structure for the log;
    /// `bytes` are the octets that caused it. Neither reaches the UI —
    /// `message` is the only part a user sees.
    func terminateConnectionForFatalProtocolError(
        _ message: String,
        detail: String? = nil,
        bytes: Data? = nil,
        name: String? = nil
    ) {
        let octets = bytes.map { UlcpFrameDiagnostic.hex($0) } ?? "none"
        if attachHeldLongEnoughToEarnFreshRetries() {
            fatalFaultRetriesRemaining = Self.fatalFaultRetryBudget
        }
        attachedAtUptimeNanoseconds = nil
        let retrying = fatalFaultRetriesRemaining > 0 && link?.linkCanReconnect == true
        if retrying { fatalFaultRetriesRemaining -= 1 }
        Self.logger.fault(
            """
            Fatal ULCP error: \(message, privacy: .public) \
            \(detail ?? "cause unrecorded", privacy: .public) \
            octets=\(octets, privacy: .private) \
            retries-left=\(self.fatalFaultRetriesRemaining, privacy: .public)
            """
        )
        finishPendingOperations(throwing: RadioConnectionError.incompatibleProtocol)
        abandonOutstandingMeshFrames()
        syncAttempt = UUID()
        _ = ulcpSession.reset()
        // A retry is a reconnect, and says so. Publishing `.failed` for a
        // teardown the app is about to undo would flash an error the user
        // cannot act on and that resolves itself a moment later.
        snapshot.linkState = retrying ? .reconnecting : .failed
        snapshot.name = name ?? snapshot.name
        snapshot.localIdentifier = link?.linkID ?? snapshot.localIdentifier
        snapshot.problemDescription = retrying ? nil : message
        publish(snapshot)
        // The transport drops whatever it had queued and takes the
        // connection down, either to bring it back or to leave the
        // failure just published standing.
        link?.linkInvalidate(retrying: retrying)
    }

    /// Report a failed operation without disturbing the transport or the
    /// ULCP session. A connected radio remains connected.
    func reportOperationFailure(_ message: String, name: String? = nil) {
        Self.logger.error("ULCP operation failed: \(message, privacy: .public)")
        snapshot.name = name ?? snapshot.name
        snapshot.problemDescription = message
        publish(snapshot)
    }

    /// The radio the app is bound to (the persisted `connectedUUID`). Used for
    /// display and as the auto-reconnect target. Distinct from
    /// `shouldAutoConnect`: the app can remember a radio it is deliberately
    /// disconnected from.

    func publishDisconnected(name: String? = nil, problem: String? = "Radio disconnected") {
        publish(
            RadioSnapshot(
                linkState: .idle,
                name: name,
                localIdentifier: link?.linkID,
                batteryPercentage: nil,
                batteryVoltageMillivolts: nil,
                chargeState: nil,
                batteryReadAt: nil,
                deviceIdentity: nil,
                hostState: .unknown,
                provisioning: nil,
                problemDescription: problem
            )
        )
    }

    func beginSynchronization() {
        Self.logger.notice(
            "begin synchronization: hostKey=\(self.selectedHostKey != nil, privacy: .public)"
        )
        // Whatever the transport was part-way through belongs to the
        // session being replaced, not the one starting here.
        link?.linkResetFraming()
        // The session started below cannot answer for transactions submitted
        // to the one it replaces. Frames carried across the boundary would
        // wait on completions that can never arrive — or collide with the new
        // session's transaction IDs, which reads as a protocol violation.
        abandonOutstandingMeshFrames()
        do {
            try applySessionUpdate(
                ulcpSession.begin(selectedHostKey: selectedHostKey)
            )
        } catch {
            terminateConnectionForFatalProtocolError(
                "The ULCP session could not start",
                detail: "cause=\(UlcpFrameDiagnostic.cause(error)) stage=begin",
                name: link?.linkName
            )
        }
    }


    func applySessionUpdate(
        _ update: UlcpSessionUpdateRecord
    ) throws {
        syncAttempt = UUID()
        let previousLinkState = snapshot.linkState
        let previousHostState = snapshot.hostState
        snapshot.linkState = switch update.snapshot.phase {
        case .idle: .attaching
        case .synchronizing: .synchronizing
        case .awaitingHost: .awaitingHost
        case .claiming: .provisioning
        case .configuring: .configuring
        case .attached: .attached
        }
        snapshot.hostState = switch update.snapshot.hostOwnership {
        case .unknown: .unknown
        case .localIdentityUnavailable: .localIdentityUnavailable
        case .unsupported: .unsupported
        case .unclaimed: .unclaimed
        case .ours: .matchesCurrentIdentity
        case .otherHost: .belongsToAnotherIdentity
        }
        // Session updates arrive per ULCP frame, many per second on a busy
        // link; log the state machine only when it actually moves.
        if snapshot.linkState != previousLinkState || snapshot.hostState != previousHostState {
            Self.logger.notice(
                """
                ulcp: link \(String(describing: previousLinkState), privacy: .public)→\
                \(String(describing: self.snapshot.linkState), privacy: .public) \
                host \(String(describing: previousHostState), privacy: .public)→\
                \(String(describing: self.snapshot.hostState), privacy: .public) \
                generation=\(update.snapshot.generation, privacy: .public) \
                waiting=\(update.waitingForResponses, privacy: .public)
                """
            )
        }
        if snapshot.linkState == .attached, previousLinkState != .attached {
            // The Rust session's wake is an edge, not a level: a frame queued
            // while the link was down announced itself exactly once, into a
            // pump that declined to run. Reopening the gate must re-arm the
            // drain, or that frame waits in the outbound queue forever with
            // the MAC coordinator borrow — and every mesh command — parked
            // behind it.
            scheduleMeshPump()
            // Stamped here, read at the next fault: how long this attach
            // held is what says whether that fault is a new incident or
            // the same one still going.
            attachedAtUptimeNanoseconds = DispatchTime.now().uptimeNanoseconds
        }
        // The device's own answer is the only authoritative name; record it
        // so every disconnected screen can use it instead of the
        // transport's cached one, which does not follow a rename.
        if let reported = update.snapshot.deviceName, link?.linkIsBoundRadio == true {
            link?.linkDidReportName(reported)
        }
        snapshot.name = update.snapshot.deviceName ?? snapshot.name ?? link?.linkName
        if let deviceKey = update.snapshot.deviceKey {
            let identity = try UMSHMobileCore.inspectPublicIdentityBytes(publicKey: deviceKey)
            snapshot.deviceIdentity = MeshPublicIdentity(
                canonicalAddress: identity.canonicalAddress,
                hint: MeshNodeHint(bytes: identity.hint.bytes, text: identity.hint.text)
            )
        } else {
            snapshot.deviceIdentity = nil
        }
        // Present only on the update that carries a new measurement — from
        // a read we asked for, or from the radio publishing one on its own
        // (a charge-state change, or the level moving). Absent means no
        // news, so the previous reading and its timestamp stand rather than
        // a minutes-old value being restamped as current.
        if let battery = update.snapshot.battery {
            snapshot.batteryPercentage = battery.percentage.map(Int.init)
            snapshot.batteryVoltageMillivolts = battery.voltageMv.map(Int.init)
            snapshot.chargeState = battery.chargeState.map(RadioChargeState.init)
            snapshot.batteryReadAt = .now
        }
        // Unlike battery, carried on every update: the radio ends an
        // alert on its own — a button press or its deadline — and the
        // button has to follow the radio, not what we last asked for.
        snapshot.alert = update.snapshot.alert.map(RadioAlertState.init)
        // Reported once, like battery: an epoch means nothing without the
        // instant it arrived, so the reading is stamped here and the
        // previous one stands when no news comes.
        if let time = update.snapshot.time {
            snapshot.clock = RadioClock(
                date: time.epochSeconds.map { Date(timeIntervalSince1970: TimeInterval($0)) },
                readAt: .now
            )
        }
        // Mirrored like the alert: a position is state, and a pin does not
        // disappear because an unrelated property arrived.
        snapshot.position = update.snapshot.gnss.map(RadioPosition.init)
        snapshot.provisioning = update.snapshot.provisioning.map {
            RadioProvisioningSummary(
                capabilityCount: Int($0.capabilityCount),
                hasHostFiltering: $0.hasHostFiltering,
                supportsOfflineQueue: $0.supportsOfflineQueue,
                supportsDelegatedAcknowledgements: $0.supportsDelegatedAck,
                supportsDeviceName: $0.supportsDeviceName,
                supportsLoRa: $0.supportsLora,
                supportsDutyCycleLimit: $0.supportsDutyCycleLimit,
                supportsBattery: $0.supportsBattery,
                phyEnabled: $0.phyEnabled,
                frequencyKHz: $0.frequencyKhz,
                transmitPowerDBm: $0.transmitPowerDbm,
                bandwidthHz: $0.bandwidthHz,
                spreadingFactor: $0.spreadingFactor,
                codingRateDenominator: $0.codingRateDenom,
                dutyCycleNow: $0.dutyCycleNow,
                dutyCycleLimit: $0.dutyCycleLimit,
                saved: $0.saved,
                queuedFrames: $0.queuedFrames.map(Int.init),
                droppedFrames: $0.droppedFrames,
                filterCount: $0.filterCount.map(Int.init),
                hostChannelCount: $0.hostChannelCount.map(Int.init),
                hostPeerCount: $0.hostPeerCount.map(Int.init),
                autoAcknowledgementEnabled: $0.autoAck,
                supportsDeviceIdentity: $0.supportsDeviceIdentity,
                devPeerAddresses: $0.devPeerKeys.map { keys in
                    keys.compactMap {
                        try? UMSHMobileCore.inspectPublicIdentityBytes(publicKey: $0)
                            .canonicalAddress
                    }
                },
                devChannelIDs: $0.devChannelIds,
                // The host key tables are read exactly when the radio
                // advertises CAP_HOST_KEYS, so a reported count is the
                // capability.
                supportsHostKeys: $0.hostChannelCount != nil,
                supportsTime: $0.supportsTime,
                supportsGnss: $0.supportsGnss,
                supportsAdvert: $0.supportsAdvert,
                timeZoneOffsetMinutes: $0.tzOffsetMin,
                gnss: $0.gnss,
                advert: $0.advert
            )
        }
        snapshot.problemDescription = nil

        let operationErrorMessage = update.operationError.map {
            "\($0.operation) failed: \($0.statusName) (\($0.statusCode))"
        }
        if let operationErrorMessage {
            Self.logger.error("ULCP operation rejected: \(operationErrorMessage, privacy: .public)")
            // A device-peer mutation reports through its own waiter — NOMEM
            // is an inline answer for that UI, not a radio problem banner.
            if devicePeerWaiter == nil {
                snapshot.problemDescription = operationErrorMessage
            }
        }

        let shouldAutoEnable = update.snapshot.phase == .attached
            && update.snapshot.provisioning?.phyEnabled == false
            && (update.snapshot.hostOwnership == .ours
                || update.snapshot.hostOwnership == .unsupported)
            && !update.waitingForResponses
            && autoEnableAttemptedGeneration != update.snapshot.generation
        if shouldAutoEnable {
            autoEnableAttemptedGeneration = update.snapshot.generation
        }

        // The host domain is volatile: the radio boots with no host key, so
        // every power cycle would otherwise park at awaitingHost and demand
        // "Set Up for This Phone" again. Binding a radio in the app (picking
        // it, or completing an attach) is the user's decision; once bound,
        // the phone simply takes the radio — even from another host, since
        // the last claim legitimately wins. One attempt per transport
        // generation: a rejected claim falls back to the manual buttons
        // instead of looping.
        let shouldAutoClaim = update.snapshot.phase == .awaitingHost
            && (update.snapshot.hostOwnership == .unclaimed
                || update.snapshot.hostOwnership == .otherHost)
            && selectedHostKey != nil
            && link?.linkIsBoundRadio == true
            && !update.waitingForResponses
            && autoClaimAttemptedGeneration != update.snapshot.generation
        if shouldAutoClaim {
            autoClaimAttemptedGeneration = update.snapshot.generation
        }

        // The transport attaches on Bluetooth's schedule, not the app's: the
        // central is recreated at launch so a background relaunch can be
        // restored, and synchronization begins the moment the radio's
        // notifications are enabled. That can be before app bootstrap has
        // read the phone identity out of the Keychain, in which case the
        // session began with no host key and parked here with nothing to
        // re-judge it. `useHostIdentity` restarts a session that is already
        // parked when the key lands; this covers the opposite ordering — the
        // key arrived while the first synchronization was still in flight, so
        // the parked state is stale the moment it is reported. One attempt
        // per generation, and a restart carrying a key cannot classify the
        // host as unavailable again.
        let shouldRestartForHostKey = update.snapshot.phase == .awaitingHost
            && update.snapshot.hostOwnership == .localIdentityUnavailable
            && selectedHostKey != nil
            && !update.waitingForResponses
            && hostKeyRestartAttemptedGeneration != update.snapshot.generation
        if shouldRestartForHostKey {
            hostKeyRestartAttemptedGeneration = update.snapshot.generation
        }

        var rawTransmitDelay: TimeInterval?
        if let result = update.rawTransmitResult {
            if var submission = rawTransmitsInFlight.removeValue(forKey: result.transactionId) {
                switch result.disposition {
                case .sent:
                    Self.logger.info(
                        """
                        raw transmit sent: transaction \(result.transactionId, privacy: .public) \
                        mesh frame \(submission.meshFrameID, privacy: .public)
                        """
                    )
                    completeMeshFrame(submission.meshFrameID, transmitted: true)
                    rawTransmitDelay = 0
                case .retry:
                    submission.busyRetries += 1
                    if submission.busyRetries <= Self.maximumRawTransmitBusyRetries {
                        Self.logger.notice(
                            "Raw transmit temporarily busy; retry \(submission.busyRetries, privacy: .public)"
                        )
                        pendingRawFrames.insert(submission, at: 0)
                        rawTransmitDelay = 0.1
                    } else {
                        completeMeshFrame(submission.meshFrameID, transmitted: false)
                        let message = "Radio remained busy; send was not transmitted"
                        Self.logger.error(
                            "Raw transmit rejected: \(result.statusName, privacy: .public) (\(result.statusCode, privacy: .public))"
                        )
                        snapshot.problemDescription = message
                        rawTransmitDelay = 0
                    }
                case .rejected:
                    completeMeshFrame(submission.meshFrameID, transmitted: false)
                    Self.logger.error(
                        "Raw transmit rejected: \(result.statusName, privacy: .public) (\(result.statusCode, privacy: .public))"
                    )
                    snapshot.problemDescription = "Radio rejected the transmission: \(result.statusName)"
                    rawTransmitDelay = 0
                }
            } else if abandonedRawTransactions.remove(result.transactionId) != nil {
                // The watchdog already failed this frame's ticket. The device
                // is late, not wrong: keep the link, and keep draining the
                // queue that was waiting behind it.
                Self.logger.error(
                    """
                    raw transmit answered after its deadline: transaction \
                    \(result.transactionId, privacy: .public) \
                    (\(result.statusName, privacy: .public))
                    """
                )
                rawTransmitDelay = 0
            } else {
                Self.logger.fault(
                    """
                    raw transmit result for unknown transaction \
                    \(result.transactionId, privacy: .public) \
                    (\(result.statusName, privacy: .public)); \
                    inFlight=\(self.rawTransmitsInFlight.keys.sorted(), privacy: .public)
                    """
                )
                throw RadioConnectionError.incompatibleProtocol
            }
        }

        for received in update.receivedFrames {
            let record = MobileMeshRxRecord(
                data: received.data,
                rssiDbm: received.rssiDbm,
                lqi: received.lqi,
                snrCb: received.snrCb,
                wasBuffered: received.wasBuffered,
                wasAcknowledged: received.wasAcknowledged,
                ageSeconds: received.ageSeconds
            )
            if let meshSession {
                try meshSession.receive(frame: record)
            } else {
                // A restored background link can deliver frames before app
                // bootstrap installs the Rust session. Hold a bounded,
                // newest-wins window for replay; anything dropped is
                // ordinary RF loss to the protocol's repair path.
                framesAwaitingMeshSession.append(record)
                if framesAwaitingMeshSession.count > Self.maximumFramesAwaitingMeshSession {
                    framesAwaitingMeshSession.removeFirst(
                        framesAwaitingMeshSession.count - Self.maximumFramesAwaitingMeshSession
                    )
                }
            }
            let frame = RadioReceivedFrame(
                data: received.data,
                rssiDBm: received.rssiDbm.map(Int.init),
                linkQuality: received.lqi,
                signalToNoiseCentibels: received.snrCb.map(Int.init),
                wasBuffered: received.wasBuffered,
                wasAcknowledgedByRadio: received.wasAcknowledged,
                ageSeconds: received.ageSeconds
            )
            for continuation in frameContinuations.values {
                continuation.yield(frame)
            }
        }

        if let event = update.managementEvent {
            finishLocalManagement(with: event)
        }
        for push in update.pushedProperties {
            for continuation in propertyPushContinuations.values {
                continuation.yield(push)
            }
        }

        for frame in update.outboundFrames {
            link?.linkSend(
                frame: frame,
                rawTransactionID: update.outboundFrames.count == 1
                    ? update.rawTransmitStartedTransactionId
                    : nil
            )
        }
        if update.snapshot.phase == .attached {
            // A completed attach is the app's declaration of intent to stay
            // bound to this radio: remember it and arm auto-reconnect.
            link?.linkDidAttach()
        }
        publish(snapshot)

        // Delayed work is armed against the link that produced this
        // update. Comparing the generation on the way back in is what
        // keeps it from acting on whatever link came after.
        let generation = linkGeneration

        if shouldAutoEnable, let provisioning = update.snapshot.provisioning {
            sessionQueue.async { [weak self] in
                self?.enableAttachedPhy(
                    provisioning: provisioning,
                    deviceName: update.snapshot.deviceName,
                    generation: generation
                )
            }
        }

        if shouldRestartForHostKey {
            sessionQueue.async { [weak self] in
                guard let self, self.linkGeneration == generation,
                      self.link?.linkIsReady == true,
                      self.selectedHostKey != nil,
                      self.snapshot.linkState == .awaitingHost
                else { return }
                Self.logger.notice(
                    "Radio parked without a phone identity that has since arrived; re-synchronizing"
                )
                self.beginSynchronization()
            }
        }

        if shouldAutoClaim {
            sessionQueue.async { [weak self] in
                guard let self, self.linkGeneration == generation,
                      self.link?.linkIsReady == true else { return }
                Self.logger.notice("Bound radio awaiting a host decision; claiming automatically")
                // A failed claim already reports through the snapshot; the
                // manual buttons remain as the fallback path.
                try? self.claimForCurrentIdentityOnQueue()
            }
        }

        if let rawTransmitDelay {
            sessionQueue.asyncAfter(deadline: .now() + rawTransmitDelay) { [weak self] in
                guard let self, self.linkGeneration == generation else { return }
                do {
                    try self.startRawTransmits()
                } catch {
                    self.dropPendingRawFrame(
                        reason: "The ULCP session rejected an outbound frame before transmission",
                        name: link?.linkName
                    )
                }
            }
        }

        if !update.waitingForResponses, update.snapshot.phase == .attached {
            if refreshInProgress {
                finishRefresh(
                    throwing: operationErrorMessage.map(RadioConnectionError.operationRejected)
                )
            }
            if configurationWaiter != nil {
                finishConfiguration(
                    throwing: operationErrorMessage.map(RadioConnectionError.operationRejected)
                )
            }
            if devicePeerWaiter != nil {
                finishDevicePeerOperation(throwing: devicePeerOutcome(update.operationError))
            }
        }

        // Raw PHY completion can legitimately take longer than the control
        // plane's synchronization timeout at slow LoRa settings. It has its
        // own ordered queue and must never tear down a healthy BLE session.
        guard update.waitingForResponses, !update.rawTransmitPending else { return }
        let attempt = syncAttempt
        let phaseAtSchedule = snapshot.linkState
        sessionQueue.asyncAfter(deadline: .now() + 8) { [weak self] in
            guard let self, self.link != nil, self.syncAttempt == attempt else {
                return
            }
            Self.logger.fault(
                """
                ulcp: no response for 8s — parked at \
                \(String(describing: phaseAtSchedule), privacy: .public), now \
                \(String(describing: self.snapshot.linkState), privacy: .public) \
                host \(String(describing: self.snapshot.hostState), privacy: .public) \
                link=\(self.link?.linkIsReady == true, privacy: .public)
                """
            )
            self.reportOperationFailure(
                "The companion radio did not finish synchronizing",
                name: link?.linkName
            )
            self.finishStrandedOperations()
        }
    }

    /// Release callers waiting on a control exchange the device stopped
    /// answering.
    ///
    /// These waiters are otherwise resolved only by an update that says the
    /// device is no longer working on anything, or by a teardown — so on a
    /// link that stays up while the device goes quiet, nothing resolves them
    /// and the caller's `await` never returns. `operationTimedOut` is the
    /// honest answer: unlike a rejection, it does not claim to know whether
    /// the device acted on the request.
    func finishStrandedOperations() {
        if refreshInProgress || !refreshWaiters.isEmpty {
            Self.logger.error("refresh stranded by a silent radio; failing it")
            finishRefresh(throwing: RadioConnectionError.operationTimedOut)
        }
        if configurationWaiter != nil {
            Self.logger.error("configuration stranded by a silent radio; failing it")
            finishConfiguration(throwing: RadioConnectionError.operationTimedOut)
        }
        if devicePeerWaiter != nil {
            Self.logger.error("device-identity mutation stranded by a silent radio; failing it")
            finishDevicePeerOperation(
                throwing: DevicePeerError.failed("The radio did not answer")
            )
        }
        if localManagementWaiter != nil {
            Self.logger.error("local management stranded by a silent radio; failing it")
            finishLocalManagement(throwing: RemoteManagementError.noAnswer)
        }
    }

    /// Coalesced immediate drain of the Rust session. There is no polling
    /// cadence: pumps are triggered by the session's wake listener, by
    /// inbound BLE data, and by the one-shot chat-batch redelivery timer.
    func scheduleMeshPump() {
        guard !meshPumpScheduled else { return }
        meshPumpScheduled = true
        let generation = meshPumpGeneration
        sessionQueue.async { [weak self] in
            guard let self else { return }
            self.meshPumpScheduled = false
            guard self.meshPumpGeneration == generation else { return }
            self.pumpMeshSession()
        }
    }

    /// One-shot delayed pump so an unacknowledged chat batch is redelivered.
    /// Deliberately bypasses the immediate-pump coalescing flag: a pending
    /// delayed pump must never absorb (and thereby delay) a wake-triggered
    /// immediate pump.
    func scheduleChatBatchRedelivery() {
        let generation = meshPumpGeneration
        sessionQueue.asyncAfter(deadline: .now() + 2.1) { [weak self] in
            guard let self, self.meshPumpGeneration == generation else { return }
            self.pumpMeshSession()
        }
    }

    func currentMeshSession() async throws -> MobileMeshSession {
        try await withCheckedThrowingContinuation { result in
            sessionQueue.async { [self] in
                guard let meshSession else {
                    result.resume(throwing: RadioConnectionError.identityUnavailable)
                    return
                }
                result.resume(returning: meshSession)
            }
        }
    }

    func pumpMeshSession() {
        guard let meshSession,
              link?.linkIsReady == true,
              snapshot.linkState == .attached
        else {
            // A declined pump strands the Rust worker's outbound frames until
            // the link recovers; without this line that wait is invisible.
            let reason = "session=\(meshSession != nil)"
                + " ready=\(link?.linkIsReady == true)"
                + " link=\(String(describing: snapshot.linkState))"
            if reason != lastReportedPumpDeferral {
                lastReportedPumpDeferral = reason
                Self.logger.notice("mesh pump deferred: \(reason, privacy: .public)")
            }
            return
        }
        if lastReportedPumpDeferral != nil {
            lastReportedPumpDeferral = nil
            Self.logger.notice("mesh pump resumed")
        }
        do {
            let update = meshSession.pollUpdate()
            pendingRawFrames.append(contentsOf: update.outboundFrames.map {
                PendingRawFrame(data: $0.data, meshFrameID: $0.id, nocca: $0.nocca)
            })
            try startRawTransmits()
            for event in update.pingEvents {
                guard let waiter = pingWaiters.removeValue(forKey: event.operationId) else {
                    continue
                }
                switch event.outcome {
                case .reply:
                    waiter.resume(
                        returning: .reply(
                            RadioPingReply(
                                roundTripMilliseconds: event.roundTripMilliseconds ?? 0,
                                hopCount: event.hopCount,
                                routeHints: event.routeHints,
                                rssiDBm: event.rssiDbm,
                                signalToNoiseCentibels: event.snrCentibels,
                                linkQuality: event.lqi
                            )
                        )
                    )
                case .timedOut:
                    waiter.resume(returning: .timedOut)
                case .failed:
                    waiter.resume(throwing: RadioConnectionError.incompatibleProtocol)
                }
            }
            for event in update.managementEvents {
                // A progress report leaves the waiter in place: several
                // arrive for one operation, and exactly one ending follows.
                if event.outcome == .progress {
                    managementWaiters[event.operationId]?
                        .progress?(event.propertiesRemaining)
                    continue
                }
                managementWaiters.removeValue(forKey: event.operationId)?
                    .continuation.resume(returning: event)
            }
            for event in update.advertisementEvents {
                let advertisement = RadioAdvertisementEvent(
                    peerAddress: event.peerAddress,
                    payload: event.payload,
                    sourceAuthenticated: event.sourceAuthenticated
                )
                for continuation in advertisementContinuations.values {
                    continuation.yield(advertisement)
                }
            }
            for event in update.peerHeardEvents {
                let heard = RadioPeerHeardEvent(
                    peerAddress: event.peerAddress,
                    nodeHint: event.nodeHint,
                    sourceAuthenticated: event.sourceAuthenticated
                )
                for continuation in peerHeardContinuations.values {
                    continuation.yield(heard)
                }
            }
            // A batch id is issued only for a batch that has events in it, so
            // its presence is the whole condition. Testing the event lists
            // instead would drop any batch made only of a kind this check
            // forgot — and a batch that is never delivered is never
            // acknowledged, which stalls every later batch behind it.
            if let chatBatchID = update.chatBatchId {
                // The facade replays a batch until it is acknowledged, and a
                // wake-triggered pump can run several times in quick
                // succession. Deliver a given batch once; if the consumer
                // fails to acknowledge it, the one-shot redelivery pump
                // re-yields it every couple of seconds until it does.
                let now = DispatchTime.now()
                let isRetryDue = lastChatBatchYield < now
                    && now.uptimeNanoseconds - lastChatBatchYield.uptimeNanoseconds
                        > 2_000_000_000
                if chatBatchID != lastYieldedChatBatchID || isRetryDue {
                    lastYieldedChatBatchID = chatBatchID
                    lastChatBatchYield = now
                    let chatUpdate = RadioChatUpdate(
                        batchID: chatBatchID,
                        mutations: update.chatMutations,
                        deliveries: update.chatDeliveries,
                        archiveLookups: update.chatArchiveLookups,
                        senderResolutions: update.chatSenderResolutions,
                        diagnostics: update.chatDiagnostics
                    )
                    for continuation in chatContinuations.values {
                        continuation.yield(chatUpdate)
                    }
                    scheduleChatBatchRedelivery()
                }
            }
        } catch {
            for waiter in pingWaiters.values {
                waiter.resume(throwing: RadioConnectionError.incompatibleProtocol)
            }
            pingWaiters.removeAll()
            for waiter in managementWaiters.values {
                waiter.continuation.resume(throwing: RemoteManagementError.unavailable)
            }
            managementWaiters.removeAll()
            reportOperationFailure(
                "The Rust mesh session could not use the companion radio: \(error)",
                name: link?.linkName
            )
        }
    }

    /// Fill the device's target-sized transmit window. The device retains
    /// complete frames and serializes the physical LoRa radio; transaction IDs
    /// correlate completions even when a later submission is rejected early.
    func startRawTransmits() throws {
        while rawTransmitsInFlight.count < Self.maximumRawTransmitsInFlight,
              let submission = pendingRawFrames.first
        {
            let update = try ulcpSession.transmitRaw(data: submission.data, nocca: submission.nocca)
            guard let transactionID = update.rawTransmitStartedTransactionId,
                  rawTransmitsInFlight[transactionID] == nil
            else {
                Self.logger.fault(
                    """
                    raw transmit could not start: transaction \
                    \(update.rawTransmitStartedTransactionId.map(String.init) ?? "none", privacy: .public) \
                    inFlight=\(self.rawTransmitsInFlight.keys.sorted(), privacy: .public)
                    """
                )
                throw RadioConnectionError.incompatibleProtocol
            }
            Self.logger.info(
                """
                raw transmit started: transaction \(transactionID, privacy: .public) \
                mesh frame \(submission.meshFrameID, privacy: .public) \
                \(submission.data.count, privacy: .public) bytes nocca=\(submission.nocca, privacy: .public)
                """
            )
            nextRawTransmitWatchdogToken += 1
            let watchdogToken = nextRawTransmitWatchdogToken
            var inFlight = submission
            inFlight.watchdogToken = watchdogToken
            pendingRawFrames.removeFirst()
            // This transaction ID now belongs to a live submission, whatever
            // an earlier use of it was abandoned for.
            abandonedRawTransactions.remove(transactionID)
            rawTransmitsInFlight[transactionID] = inFlight
            do {
                try applySessionUpdate(update)
            } catch {
                rawTransmitsInFlight.removeValue(forKey: transactionID)
                pendingRawFrames.insert(submission, at: 0)
                throw error
            }
            scheduleRawTransmitWatchdog(
                transactionID: transactionID,
                watchdogToken: watchdogToken
            )
        }
    }

    /// Give up on a frame the device accepted and then never reported.
    ///
    /// The link is left alone: it is still up, and the device may well handle
    /// the next frame normally. Only this frame's delivery ticket is failed,
    /// which is what releases the Rust MAC's coordinator borrow and lets the
    /// rest of the mesh session proceed. Logged as a fault because a device
    /// reaching this deadline is a real device-side defect, not a normal
    /// outcome to be absorbed quietly.
    func scheduleRawTransmitWatchdog(transactionID: UInt8, watchdogToken: UInt64) {
        sessionQueue.asyncAfter(deadline: .now() + Self.rawTransmitTimeoutSeconds) { [weak self] in
            guard let self,
                  let submission = self.rawTransmitsInFlight[transactionID],
                  submission.watchdogToken == watchdogToken
            else { return }
            Self.logger.fault(
                """
                raw transmit timed out after \(Self.rawTransmitTimeoutSeconds, privacy: .public)s: \
                transaction \(transactionID, privacy: .public) \
                mesh frame \(submission.meshFrameID, privacy: .public) \
                \(submission.data.count, privacy: .public) bytes; failing its ticket so the \
                mesh session can continue
                """
            )
            self.rawTransmitsInFlight.removeValue(forKey: transactionID)
            self.abandonedRawTransactions.insert(transactionID)
            self.completeMeshFrame(submission.meshFrameID, transmitted: false)
            self.reportOperationFailure(
                "The radio did not report what happened to a transmission"
            )
            guard self.link?.linkIsReady == true else { return }
            do {
                try self.startRawTransmits()
            } catch {
                self.dropPendingRawFrame(
                    reason: "The ULCP session rejected an outbound frame before transmission",
                    name: link?.linkName
                )
            }
        }
    }

    /// Drop one unsendable frame and keep the BLE link/session intact. The
    /// Rust delivery ticket will time out as failed; later queued frames may
    /// still proceed.
    func dropPendingRawFrame(reason: String, name: String?) {
        if !pendingRawFrames.isEmpty {
            let dropped = pendingRawFrames.removeFirst()
            completeMeshFrame(dropped.meshFrameID, transmitted: false)
        }
        reportOperationFailure(reason, name: name)
        guard link?.linkIsReady == true else { return }
        do {
            try startRawTransmits()
        } catch {
            // Continue draining without turning an unsendable frame into a
            // recursive transport failure.
            let name = link?.linkName
            sessionQueue.async { [weak self] in
                self?.dropPendingRawFrame(
                    reason: "The ULCP session rejected an outbound frame before transmission",
                    name: name
                )
            }
        }
    }

    func completeMeshFrame(_ frameID: UInt64, transmitted: Bool) {
        do {
            try meshSession?.completeOutboundFrame(
                frameId: frameID,
                transmitted: transmitted
            )
        } catch {
            // A stale completion is diagnostic, never a reason to tear down a
            // healthy BLE attachment.
            Self.logger.error(
                "Could not complete mesh frame \(frameID, privacy: .public): \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    /// Abandon every mesh frame currently in this adapter's hands — queued in
    /// `pendingRawFrames` or submitted to the device in `rawTransmitsInFlight`
    /// — and fail their Rust delivery tickets.
    ///
    /// `BridgeRadio::transmit` awaits each ticket while the MAC coordinator
    /// borrow is held, so a frame dropped without failing its ticket wedges
    /// the entire mesh session: every later send, ping, and identity
    /// discovery queues behind that borrow forever, surviving reconnects.
    /// Any path that walks away from the frames it was carrying —
    /// disconnect, fatal teardown, or a fresh synchronization whose device
    /// session cannot answer for the old one's transactions — must come
    /// through here.
    func abandonOutstandingMeshFrames() {
        // A restarted session issues transaction IDs from the start of the
        // space again, so entries kept here would swallow a genuine protocol
        // violation on the new session.
        abandonedRawTransactions.removeAll()
        guard !pendingRawFrames.isEmpty || !rawTransmitsInFlight.isEmpty else { return }
        Self.logger.notice(
            """
            abandoning mesh frames: queued=\(self.pendingRawFrames.count, privacy: .public) \
            inFlight=\(self.rawTransmitsInFlight.count, privacy: .public)
            """
        )
        pendingRawFrames.removeAll()
        rawTransmitsInFlight.removeAll()
        do {
            try meshSession?.failOutboundTransmissions()
        } catch {
            Self.logger.error(
                "Could not fail abandoned outbound mesh frames: \(error.localizedDescription, privacy: .public)"
            )
        }
    }

    /// A ULCP attachment is intended to provide a usable radio. Preserve
    /// the radio's authoritative profile and enable only the PHY bit after the
    /// initial inspection discovers it disabled.
    func enableAttachedPhy(
        provisioning: UlcpSyncRecord,
        deviceName: String?,
        generation: UInt64
    ) {
        guard linkGeneration == generation,
              link?.linkIsReady == true,
              snapshot.linkState == .attached
        else { return }
        let settings = UlcpRadioSettingsRecord(
            deviceName: provisioning.supportsDeviceName ? deviceName : nil,
            phyEnabled: true,
            frequencyKhz: provisioning.frequencyKhz,
            transmitPowerDbm: provisioning.transmitPowerDbm,
            bandwidthHz: provisioning.bandwidthHz,
            spreadingFactor: provisioning.spreadingFactor,
            codingRateDenom: provisioning.codingRateDenom,
            dutyCycleLimit: provisioning.dutyCycleLimit
        )
        do {
            try applySessionUpdate(
                ulcpSession.configure(settings: settings)
            )
        } catch {
            Self.logger.error("Could not automatically enable the radio PHY")
            snapshot.problemDescription = "The companion radio could not be enabled automatically"
            publish(snapshot)
        }
    }

    func publish(_ newSnapshot: RadioSnapshot) {
        snapshot = newSnapshot
        for continuation in continuations.values {
            continuation.yield(newSnapshot)
        }
    }

    func finishRefresh(throwing error: (any Error)?) {
        refreshInProgress = false
        let waiters = refreshWaiters
        refreshWaiters.removeAll()
        for waiter in waiters {
            if let error {
                waiter.resume(throwing: error)
            } else {
                waiter.resume(returning: snapshot)
            }
        }
    }

    func finishConfiguration(throwing error: (any Error)?) {
        guard let waiter = configurationWaiter else { return }
        configurationWaiter = nil
        if let error {
            waiter.resume(throwing: error)
        } else {
            waiter.resume()
        }
    }

    func finishPendingOperations(throwing error: any Error) {
        if refreshInProgress || !refreshWaiters.isEmpty {
            finishRefresh(throwing: error)
        }
        finishConfiguration(throwing: error)
        finishDevicePeerOperation(throwing: DevicePeerError.radioUnavailable)
        for waiter in pingWaiters.values {
            waiter.resume(throwing: error)
        }
        pingWaiters.removeAll()
        // A management exchange lives in the Rust worker, which the link
        // going down takes with it: nothing will ever report its outcome,
        // so the callers are released here alongside the pings.
        for waiter in managementWaiters.values {
            waiter.continuation.resume(throwing: RemoteManagementError.unavailable)
        }
        managementWaiters.removeAll()
        finishLocalManagement(throwing: RemoteManagementError.unavailable)
        meshPumpGeneration = UUID()
    }


    // ------------------------------------------------------------------
    // Link lifecycle
    // ------------------------------------------------------------------

    /// Adopt the transport. Called by the subclass once, at init, since
    /// the subclass is its own link.
    func adopt(link: any UlcpFrameLink) {
        self.link = link
    }

    /// The transport can carry frames: start the ULCP session over it.
    func linkDidBecomeReady() {
        linkGeneration &+= 1
        beginSynchronization()
    }

    /// One complete ULCP frame arrived.
    ///
    /// Consuming the frame and applying what it produced fail for
    /// unrelated reasons — a frame this session cannot read, against a
    /// value inside a frame it read fine — so they are reported apart
    /// rather than under one message that blames the framing for both.
    func linkDidReceive(frame: Data) {
        let update: UlcpSessionUpdateRecord
        do {
            update = try ulcpSession.consume(frame: frame)
        } catch MobileError.UlcpUnexpectedCommand {
            // A well-formed command this session does not handle — an
            // unsolicited notification from newer firmware, a
            // `CMD_PROP_ARE` — is not a broken link. Ignoring it costs at
            // most one operation that times out; tearing the link down
            // costs the whole session.
            Self.logger.notice(
                """
                ulcp: ignoring unhandled command \
                \(UlcpFrameDiagnostic.structure(frame), privacy: .public)
                """
            )
            return
        } catch {
            terminateConnectionForFatalProtocolError(
                "The radio sent an invalid ULCP frame",
                detail: """
                    cause=\(UlcpFrameDiagnostic.cause(error)) \
                    frame=[\(UlcpFrameDiagnostic.structure(frame))]
                    """,
                bytes: frame,
                name: link?.linkName
            )
            return
        }
        do {
            try applySessionUpdate(update)
        } catch {
            terminateConnectionForFatalProtocolError(
                "The radio sent a value the session could not use",
                detail: """
                    cause=\(UlcpFrameDiagnostic.cause(error)) \
                    frame=[\(UlcpFrameDiagnostic.structure(frame))]
                    """,
                bytes: frame,
                name: link?.linkName
            )
        }
    }

    /// The link is gone: release everything that was waiting on the
    /// device and retire the generation, so delayed work armed against
    /// it cannot act on whatever link comes next.
    ///
    /// The frames the Rust session is holding open matter most — a
    /// dropped completion parks every later send behind it for the life
    /// of the session.
    func sessionDidLoseLink() {
        linkGeneration &+= 1
        // The attach is over however it ended. Leaving the stamp behind
        // would let a fault during the *next* attach's handshake claim
        // credit for how long the previous one held.
        attachedAtUptimeNanoseconds = nil
        finishPendingOperations(throwing: RadioConnectionError.radioNotFound)
        _ = ulcpSession.reset()
        abandonOutstandingMeshFrames()
        autoEnableAttemptedGeneration = nil
        autoClaimAttemptedGeneration = nil
        syncAttempt = UUID()
    }

    /// The transport went away on its own.
    func linkDidClose(problem: String? = "Radio disconnected") {
        sessionDidLoseLink()
        publishDisconnected(name: link?.linkName, problem: problem)
    }

    /// Writes carrying these raw transmits failed while the link itself
    /// stayed up. Their tickets have to be released here: the Rust MAC
    /// awaits each completion holding the coordinator borrow, so one
    /// dropped ticket parks every later send behind it.
    func linkWritesFailed(rawTransactionIDs: Set<UInt8>, message: String) {
        pendingRawFrames.removeAll()
        for transactionID in rawTransactionIDs {
            rawTransmitsInFlight.removeValue(forKey: transactionID)
        }
        _ = ulcpSession.abandonRawTransmits(
            transactionIds: Data(rawTransactionIDs.sorted())
        )
        do {
            try meshSession?.failOutboundTransmissions()
        } catch {
            Self.logger.error(
                "Could not publish ULCP write failure to Rust mesh session"
            )
        }
        reportOperationFailure(message, name: link?.linkName)
    }
}

/// Bridges the Rust session's pending-update announcement onto the
/// session's own queue. Runs on the Rust worker thread; holds the
/// session weakly so a retired one cannot keep it alive.
final class MeshSessionWakeListener: MobileMeshWakeListener, @unchecked Sendable {
    private weak var session: UlcpRadioSession?

    init(session: UlcpRadioSession) {
        self.session = session
    }

    func onUpdatePending() {
        session?.meshSessionDidAnnounceUpdate()
    }
}
