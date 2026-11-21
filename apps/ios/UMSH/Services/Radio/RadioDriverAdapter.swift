import Foundation
import OSLog
import UMSHMobileCore

/// What to say in the log when a ULCP frame is refused.
///
/// A refusal that reaches the log as prose alone is unactionable: the
/// cause the Rust core named, the frame's own structure, and the octets
/// all exist at the point of failure and are worth carrying.
///
/// Cause and structure are logged `.public`—they are what a bug report
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

/// One transport carrying whole ULCP frames, as the radio driver asks of
/// it.
///
/// A transport owns only the physical connection, the framing its medium
/// requires (GATT segmentation, HDLC-Lite on a byte stream), the write
/// pacing it needs, and what it persists. The driver owns the protocol
/// and the radio's published state. Every call arrives on the adapter's
/// queue, in the order the driver made it.
protocol UlcpFrameLink: AnyObject {
    /// The transport's identifier for this radio: the bound peripheral
    /// over BLE, a synthesized one for transports with nothing to
    /// discover. Feeds `RadioSnapshot.localIdentifier`.
    var linkID: UUID? { get }

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
    /// `retrying` says whether the driver would spend a reconnect on
    /// this. When it would and the transport can, the transport takes
    /// its ordinary link-loss path, because that is what this is. When
    /// not, the transport stops trying. Either way it reports the state
    /// it comes to, and the driver decides from that what the user sees.
    func linkInvalidate(retrying: Bool)

    /// The radio attached. Where a transport persists which radio the
    /// app is bound to, this is when it does so.
    func linkDidAttach()

    /// The radio reported its own name, which outranks whatever the
    /// transport had cached.
    func linkDidReportName(_ name: String)

    /// The radio is erasing itself and will reboot. Drop the binding,
    /// but leave the link up: the command still has to reach the wire.
    func linkAbandonBinding()

    /// Stop automatic reconnect after confirmed DFU, retaining the binding.
    func linkDidEnterDfu()
}

/// The radio side of a companion radio, over `MobileRadioDriver`, and the
/// mesh session's events.
///
/// The driver runs the ULCP session, carries the mesh session's frames to
/// and from the radio, and owns the radio's whole state. This class
/// reports the transport's state to it, carries out the link calls it
/// makes, maps what it publishes onto `RadioSnapshot`, and maps its errors
/// onto the ones callers already handle. The mesh session's events—
/// pings, management, advertisements, chat changes—are distributed here
/// from that session's own wake.
///
/// Subclasses are the transports. They supply the link—and, with it,
/// discovery, connection lifecycle, and whatever they persist. This class
/// never names a transport.
class RadioDriverAdapter: NSObject, @unchecked Sendable {
    /// The one queue the transport and this adapter run on. Injected so a
    /// transport whose callbacks already arrive on a queue of its own
    /// (CoreBluetooth's, for one) can hand that same queue over rather
    /// than hop.
    let sessionQueue: DispatchQueue

    /// Owned for the adapter's life and stopped with it.
    let driver: MobileRadioDriver

    /// Carries the driver's link calls to the transport; `nil` when the
    /// link lives in the core.
    private let linkBridge: DriverLinkBridge?

    /// The transport, set by the subclass that is also the link.
    private(set) weak var link: (any UlcpFrameLink)?

    /// What the transport last reported while carrying no frames, for the
    /// transport's own decisions. `nil` while the link carries frames: the
    /// driver's protocol phases apply then.
    ///
    /// The transport's own record rather than the published state, which
    /// is the driver's and reaches this queue a hop later.
    private(set) var transportReport: MobileRadioTransportStateRecord? =
        MobileRadioTransportStateRecord(phase: .idle, name: nil, linkId: nil, problem: nil)

    var transportPhase: MobileRadioTransportPhase? { transportReport?.phase }

    static let logger = Logger(subsystem: "com.voria.umsh.ios", category: "UlcpDevice")

    init(sessionQueue: DispatchQueue) {
        self.sessionQueue = sessionQueue
        let bridge = DriverLinkBridge(queue: sessionQueue)
        linkBridge = bridge
        // Only fails when the system will not start a thread, which leaves
        // nothing to recover with.
        driver = try! MobileRadioDriver(link: bridge)
        super.init()
        driver.setListener(listener: DriverUpdateListener(adapter: self))
    }

    /// Over a driver whose link lives in the core, which reports its own
    /// transport states: the staging air's.
    init(sessionQueue: DispatchQueue, driver: MobileRadioDriver) {
        self.sessionQueue = sessionQueue
        linkBridge = nil
        self.driver = driver
        super.init()
        driver.setListener(listener: DriverUpdateListener(adapter: self))
    }

    deinit {
        // The driver's thread holds the link bridge and the mesh session
        // until it stops; nothing else would end it.
        driver.stop()
    }

    struct ManagementWaiter {
        let waiter: RadioOperationWaiter<MobileMeshManagementEventRecord>
        /// Called for every progress report, and never after the exchange
        /// resolves.
        let progress: (@Sendable (UInt32?) -> Void)?
    }

    /// The radio as last published, mapped for the app.
    private(set) var snapshot = RadioSnapshot.idle
    var continuations: [UUID: AsyncStream<RadioSnapshot>.Continuation] = [:]
    var chatContinuations: [UUID: AsyncStream<MobileChatChangesRecord>.Continuation] = [:]
    var advertisementContinuations:
        [UUID: AsyncStream<RadioAdvertisementEvent>.Continuation] = [:]
    var peerHeardContinuations:
        [UUID: AsyncStream<RadioPeerHeardEvent>.Continuation] = [:]
    var localHintContinuations: [UUID: AsyncStream<[Data]>.Continuation] = [:]
    /// The mesh session's latest report of the addresses it answers to
    /// besides its own. A session starts with none.
    var latestLocalDestinationHints: [Data] = []
    var forwardSecretContinuations: [UUID: AsyncStream<Set<String>>.Continuation] = [:]
    /// The mesh session's latest report of the conversations whose next
    /// message goes under a session with forward secrecy. A session starts
    /// with none.
    var latestForwardSecretConversations: Set<String> = []
    var meetContinuations: [UUID: AsyncStream<MobileMeetStateRecord?>.Continuation] = [:]
    var latestMeetState: MobileMeetStateRecord?
    var hostReleaseContinuations: [UUID: AsyncStream<String>.Continuation] = [:]
    var propertyPushContinuations:
        [UUID: AsyncStream<UlcpPropertyPushRecord>.Continuation] = [:]
    var meshSession: MobileMeshSession?
    var pingWaiters: [UInt64: CheckedContinuation<RadioPingResult, any Error>] = [:]
    /// Callers awaiting a node-management exchange, by operation id.
    ///
    /// Shaped like `pingWaiters` because the operations are shaped alike—
    /// the Rust worker owns the timeout and reports the outcome as an event
    ///—with one addition: a whole-device read reports its progress along
    /// the way, and the handler for that has to outlive each report.
    var managementWaiters: [UInt64: ManagementWaiter] = [:]
    var meshPumpGeneration = UUID()
    var meshPumpScheduled = false
    /// The latest mesh-session change, which the next waits behind.
    private var meshSessionChange: Task<Void, Never>?

    // ------------------------------------------------------------------
    // Streams
    // ------------------------------------------------------------------

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

    func chatChanges() async -> AsyncStream<MobileChatChangesRecord> {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                // Every report counts: each names what changed since the
                // last, so none may be dropped.
                let stream = AsyncStream(bufferingPolicy: .unbounded) { continuation in
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

    func localDestinationHints() async -> AsyncStream<[Data]> {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                // Each value is the whole set, so only the newest matters.
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
                    let id = UUID()
                    localHintContinuations[id] = continuation
                    continuation.yield(latestLocalDestinationHints)
                    continuation.onTermination = { [weak self] _ in
                        self?.sessionQueue.async { [weak self] in
                            self?.localHintContinuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    func meetStates() async -> AsyncStream<MobileMeetStateRecord?> {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                // Each value is the whole state, so only the newest matters.
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
                    let id = UUID()
                    meetContinuations[id] = continuation
                    continuation.yield(latestMeetState)
                    continuation.onTermination = { [weak self] _ in
                        self?.sessionQueue.async { [weak self] in
                            self?.meetContinuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    func hostReleases() async -> AsyncStream<String> {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                let stream = AsyncStream<String> { continuation in
                    let id = UUID()
                    hostReleaseContinuations[id] = continuation
                    continuation.onTermination = { [weak self] _ in
                        self?.sessionQueue.async { [weak self] in
                            self?.hostReleaseContinuations[id] = nil
                        }
                    }
                }
                result.resume(returning: stream)
            }
        }
    }

    func forwardSecretConversations() async -> AsyncStream<Set<String>> {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                // Each value is the whole set, so only the newest matters.
                let stream = AsyncStream(bufferingPolicy: .bufferingNewest(1)) { continuation in
                    let id = UUID()
                    forwardSecretContinuations[id] = continuation
                    continuation.yield(latestForwardSecretConversations)
                    continuation.onTermination = { [weak self] _ in
                        self?.sessionQueue.async { [weak self] in
                            self?.forwardSecretContinuations[id] = nil
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

    /// Values the companion radio announces on its own, verbatim.
    func companionPropertyPushes() async -> AsyncStream<UlcpPropertyPushRecord> {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                // Pushes are sparse—battery, alert, the occasional fix—
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

    func publishMeetState(_ state: MobileMeetStateRecord?) {
        guard state != latestMeetState else { return }
        latestMeetState = state
        for continuation in meetContinuations.values {
            continuation.yield(state)
        }
    }

    func publishLocalDestinationHints(_ hints: [Data]) {
        guard hints != latestLocalDestinationHints else { return }
        latestLocalDestinationHints = hints
        for continuation in localHintContinuations.values {
            continuation.yield(hints)
        }
    }

    /// Record and announce the conversations whose next message goes under
    /// a session with forward secrecy. Runs on `sessionQueue`.
    func publishForwardSecretConversations(_ addresses: Set<String>) {
        guard addresses != latestForwardSecretConversations else { return }
        latestForwardSecretConversations = addresses
        for continuation in forwardSecretContinuations.values {
            continuation.yield(addresses)
        }
    }

    // ------------------------------------------------------------------
    // The transport, reporting to the driver
    // ------------------------------------------------------------------

    /// Adopt the transport. Called by the subclass once, at init, since
    /// the subclass is its own link.
    func adopt(link: any UlcpFrameLink) {
        self.link = link
        linkBridge?.link = link
    }

    /// The transport carries no frames, and stands here. Every state the
    /// transport comes to is reported, the idle it rests at included: a
    /// fault settles on the report that follows it.
    ///
    /// `linkID` defaults to the link's own.
    func reportTransport(
        _ phase: MobileRadioTransportPhase,
        name: String?,
        linkID: UUID? = nil,
        problem: MobileRadioProblem? = nil
    ) {
        dispatchPrecondition(condition: .onQueue(sessionQueue))
        let report = MobileRadioTransportStateRecord(
            phase: phase,
            name: name,
            linkId: (linkID ?? link?.linkID)?.uuidString,
            problem: problem
        )
        transportReport = report
        driver.transportChanged(state: report)
    }

    /// The transport carries frames: the driver starts the ULCP session.
    /// `boundRadio` says whether the radio on the other end is the one the
    /// app is bound to.
    func reportLinkReady(boundRadio: Bool) {
        dispatchPrecondition(condition: .onQueue(sessionQueue))
        transportReport = nil
        driver.linkReady(boundRadio: boundRadio)
    }

    // ------------------------------------------------------------------
    // What the driver publishes
    // ------------------------------------------------------------------

    /// Called by the driver's thread whenever `pollUpdate` has news. Hop
    /// to the queue and drain; the driver coalesces these.
    fileprivate func driverDidAnnounceUpdate() {
        sessionQueue.async { [weak self] in
            self?.drainDriver()
        }
    }

    private func drainDriver() {
        let update = driver.pollUpdate()
        if let state = update.state {
            apply(state)
        }
        for push in update.pushedProperties {
            for continuation in propertyPushContinuations.values {
                continuation.yield(push)
            }
        }
        for key in update.hostReleases {
            guard let address = try? UMSHMobileCore.inspectPublicIdentityBytes(publicKey: key)
                .canonicalAddress
            else { continue }
            for continuation in hostReleaseContinuations.values {
                continuation.yield(address)
            }
        }
    }

    private func apply(_ state: MobileRadioStateRecord) {
        // The driver logs its own transitions.
        let next = RadioSnapshot(state)
        snapshot = next
        for continuation in continuations.values {
            continuation.yield(next)
        }
        // A ping or management exchange travels over this radio. Once the
        // session it went out under is gone, its answer cannot come back.
        if !Self.sessionContinues(next.linkState) {
            failMeshWaiters()
        }
    }

    /// Whether a radio in `state` is still in the session that carried
    /// what was sent: attached, or in a configuration change, which
    /// leaves the session in place.
    private static func sessionContinues(_ state: RadioLinkState) -> Bool {
        state == .attached || state == .configuring
    }

    /// Release every ping and management caller. Their operations are
    /// canceled in the Rust worker, which outlives the link: left
    /// running, each would hold its device's queue and retry a request
    /// whose answer nobody is waiting for.
    private func failMeshWaiters() {
        for waiter in pingWaiters.values {
            waiter.resume(throwing: RadioConnectionError.radioNotFound)
        }
        pingWaiters.removeAll()
        for (operation, waiter) in managementWaiters {
            waiter.waiter.resume(throwing: RemoteManagementError.unavailable)
            try? meshSession?.cancelManagement(operationId: operation)
        }
        managementWaiters.removeAll()
    }

    /// Whether the radio can carry a frame for the mesh session now:
    /// attached, and set up for this phone's identity. Read from the
    /// driver, whose state is current; the snapshot here is a hop behind.
    private var radioCarriesThisPhone: Bool {
        let state = driver.state()
        return state.phase == .attached && state.host == .ours
    }

    // ------------------------------------------------------------------
    // The mesh session
    // ------------------------------------------------------------------

    /// Install `session`, or none. Changes take effect one at a time, in
    /// the order asked for: each spans two hops with the driver between,
    /// and interleaved, the one asked for first could end up installed.
    func useMeshSession(_ session: MobileMeshSession?) async {
        let change = await onQueue { [self] () -> Task<Void, Never> in
            let previous = meshSessionChange
            let change = Task { [self] in
                await previous?.value
                await changeMeshSession(to: session)
            }
            meshSessionChange = change
            return change
        }
        await change.value
    }

    private func changeMeshSession(to session: MobileMeshSession?) async {
        await onQueue { [self] in
            Self.logger.notice(
                "mesh session \(session == nil ? "cleared" : self.meshSession == nil ? "installed" : "replaced", privacy: .public)"
            )
            // The session being replaced is drained no more.
            meshSession?.clearWakeListener()
            meshPumpGeneration = UUID()
            meshPumpScheduled = false
        }
        // The driver before the wake listener: it takes the new session's
        // outbound frames from here on, so none can reach a poll here and
        // be lost. It also replays what it received while there was none.
        try? await driver.useMeshSession(session: session)
        await onQueue { [self] in
            // Operations went out under the session being replaced, and
            // their answers go to it.
            failMeshWaiters()
            meshSession = session
            // Addresses belong to the session that answers to them, and
            // so do an exchange and sessions with forward secrecy.
            publishLocalDestinationHints([])
            publishForwardSecretConversations([])
            publishMeetState(nil)
            // Push, not poll: the Rust worker announces pending updates
            // (ping/advertisement events, chat changes) through this
            // listener, so no polling cadence exists. If data is already
            // pending, the listener fires immediately.
            session?.setWakeListener(listener: MeshSessionWakeListener(adapter: self))
        }
    }

    /// Called by the Rust worker (on its own thread) whenever `pollUpdate`
    /// has new data. Hop to the queue and drain.
    fileprivate func meshSessionDidAnnounceUpdate() {
        sessionQueue.async { [weak self] in
            self?.scheduleMeshPump()
        }
    }

    /// Coalesced immediate drain of the mesh session's events. There is
    /// no polling cadence: pumps are triggered by the session's wake.
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

    /// Distribute what the mesh session reported. Its outbound frames go
    /// to the driver directly and never appear here; nothing else needs
    /// the radio, so nothing waits for it.
    func pumpMeshSession() {
        guard let meshSession else { return }
        let update = meshSession.pollUpdate()
        if let changes = update.chatChanges {
            for continuation in chatContinuations.values {
                continuation.yield(changes)
            }
        }
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
                            traceSignal: event.traceSignal.map {
                                MeshLegSignal(
                                    rssiDBm: $0.rssiDbm,
                                    signalToNoiseCentibels: $0.snrCentibels
                                )
                            },
                            rssiDBm: event.rssiDbm,
                            signalToNoiseCentibels: event.snrCentibels,
                            linkQuality: event.lqi,
                            viaRouteRetry: event.viaRouteRetry
                        )
                    )
                )
            case .timedOut:
                waiter.resume(returning: .timedOut)
            case .canceled:
                waiter.resume(returning: .canceled)
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
                .waiter.resume(returning: event)
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
        if let hints = update.localDestinationHints {
            publishLocalDestinationHints(hints)
        }
        if let addresses = update.forwardSecretConversations {
            publishForwardSecretConversations(Set(addresses))
        }
        if let meet = update.meet {
            publishMeetState(meet)
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

    /// The mesh session, but only while the radio can carry a frame for it:
    /// attached, and set up for this phone's identity. The guard a ping
    /// applies, for callers that await an answer over the air rather than
    /// merely handing a frame off.
    private func readyMeshSession() async throws -> MobileMeshSession {
        try await withCheckedThrowingContinuation { result in
            sessionQueue.async { [self] in
                guard let meshSession, radioCarriesThisPhone else {
                    result.resume(throwing: RemoteManagementError.unavailable)
                    return
                }
                result.resume(returning: meshSession)
            }
        }
    }

    /// Run `body` on the queue and wait for it.
    private func onQueue<T: Sendable>(_ body: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { (result: CheckedContinuation<T, Never>) in
            sessionQueue.async {
                result.resume(returning: body())
            }
        }
    }

    // ------------------------------------------------------------------
    // Mesh operations
    // ------------------------------------------------------------------

    func openMeet(model: UInt16) async throws {
        try await readyMeshSession().openMeet(model: model)
    }

    func closeMeet() async throws {
        // Closing needs no radio: a session key goes back even while the
        // link is down.
        try await currentMeshSession().closeMeet()
    }

    func askToExchange(device: UInt32) async throws -> Bool {
        try await readyMeshSession().askToExchange(device: device)
    }

    func answerExchange(accept: Bool) async throws {
        try await readyMeshSession().answerExchange(accept: accept)
    }

    func confirmCode(same: Bool) async throws {
        try await readyMeshSession().confirmCode(same: same)
    }

    func cancelExchange() async throws {
        try await currentMeshSession().cancelExchange()
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

    func setFloodHops(defaultHops: UInt8, beaconHops: UInt8) async {
        guard let session = try? await currentMeshSession() else { return }
        try? await session.setFloodHops(defaultHops: defaultHops, beaconHops: beaconHops)
    }

    func requestIdentity(peerAddress: String) async throws {
        let session = try await currentMeshSession()
        try await session.requestIdentity(peerAddress: peerAddress)
    }

    func requestPeerRepeaters(
        peerAddress: String,
        cursor: Data?,
        route: [Data]
    ) async throws -> MobileMeshPeerRepeatersPageRecord {
        // Guarded like a ping rather than like an identity request: this
        // waits up to the page deadline for an answer, and a link that
        // cannot carry the ask should say so now rather than after it.
        let session = try await readyMeshSession()
        do {
            return try await session.requestPeerRepeatersPage(
                peerAddress: peerAddress,
                cursor: cursor,
                sourceRoute: route
            )
        } catch MobileMeshError.NoAnswer {
            throw RemoteManagementError.noAnswer
        }
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

    func holdPeerRoute(
        peerAddress: String,
        path: MobileMeshExplicitPath,
        holdMilliseconds: UInt64
    ) async throws -> Bool {
        let session = try await currentMeshSession()
        return try await session.holdPeerRoute(
            peerAddress: peerAddress,
            path: path,
            holdMs: holdMilliseconds
        )
    }

    func adoptLearnedPeerRoute(peerAddress: String) async throws -> Bool {
        let session = try await currentMeshSession()
        return try await session.adoptLearnedPeerRoute(peerAddress: peerAddress)
    }

    func signIdentityBundle(name: String?) async throws -> Data {
        let session = try await currentMeshSession()
        return try await session.signIdentityBundle(
            name: name,
            timestamp: UInt32(clamping: Int(Date.now.timeIntervalSince1970))
        )
    }

    func registerChannels(_ channels: [ChannelRegistration]) async throws {
        guard !channels.isEmpty else { return }
        try await currentMeshSession().registerChannels(channels: channels.map(\.record))
    }

    func removeChannels(_ channelKeys: [Data]) async throws {
        guard !channelKeys.isEmpty else { return }
        try await currentMeshSession().removeChannels(keys: channelKeys)
    }

    func ping(peerAddress: String, path: MobileMeshExplicitPath?) async throws -> RadioPingResult {
        try await withCheckedThrowingContinuation {
            (result: CheckedContinuation<RadioPingResult, any Error>) in
            sessionQueue.async { [self] in
                guard let meshSession, radioCarriesThisPhone else {
                    result.resume(throwing: RadioConnectionError.radioNotFound)
                    return
                }
                do {
                    let operation = try meshSession.ping(
                        peerAddress: peerAddress,
                        path: path
                    )
                    pingWaiters[operation] = result
                } catch {
                    result.resume(throwing: error)
                }
            }
        }
    }

    func nodePublicKey() async -> Data? {
        await withCheckedContinuation { (result: CheckedContinuation<Data?, Never>) in
            sessionQueue.async { [self] in
                result.resume(returning: meshSession?.nodePublicKey())
            }
        }
    }

    // MARK: - Chat

    func prepareChat(
        peers: [MobilePeerRegistrationRecord],
        checkpoints: [MobileChatCheckpointRecord],
        store: MobileAppStore,
        ownerIdentityID: String,
        silentTestsIn: String?
    ) async throws {
        let session = try await currentMeshSession()
        // The store first: what arrives is kept whether or not the peers
        // and streams below can be set up.
        try Self.attachChatStore(
            to: session,
            store: store,
            ownerIdentityID: ownerIdentityID,
            silentTestsIn: silentTestsIn
        )
        try await session.registerPeers(peers: peers)
        try await session.restoreChat(checkpoints: checkpoints)
    }

    /// A session keeps its store for life, and a reattach finds it already
    /// there.
    static func attachChatStore(
        to session: MobileMeshSession,
        store: MobileAppStore,
        ownerIdentityID: String,
        silentTestsIn: String?
    ) throws {
        do {
            try session.attachChatStore(
                store: store,
                ownerIdentityId: ownerIdentityID,
                silentTestsIn: silentTestsIn
            )
        } catch MobileMeshError.OperationInProgress {
        }
    }

    func sendChat(conversationAddress: String, request: MobileChatSendRequest) async throws {
        let session = try await currentMeshSession()
        try await session.sendChat(conversationAddress: conversationAddress, request: request)
    }

    func setChatSilentTestsIn(_ conversationAddress: String?) async throws {
        let session = try await currentMeshSession()
        try session.setChatSilentTestsIn(conversationAddress: conversationAddress)
    }

    func registerChatPeers(_ peers: [MobilePeerRegistrationRecord]) async throws {
        let session = try await currentMeshSession()
        try await session.registerPeers(peers: peers)
    }

    func removeChatPeers(_ peerAddresses: [String]) async throws {
        let session = try await currentMeshSession()
        try await session.removePeers(peerAddresses: peerAddresses)
    }

    func resendChat(
        conversationAddress: String,
        original: MobileChatOriginalRef,
        frames: [MobileChatArchiveRecord],
        forwardSecret: Bool
    ) async throws {
        let session = try await currentMeshSession()
        try await session.resendChat(
            conversationAddress: conversationAddress,
            original: original,
            frames: frames,
            forwardSecret: forwardSecret
        )
    }

    func requestChatRepair(sessionID: UInt64, handle: UInt32) async throws -> Bool {
        let session = try await currentMeshSession()
        return try await session.requestChatRepair(sessionId: sessionID, handle: handle)
    }

    // MARK: - Managing another node over the mesh

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
            // fault—but a reply with nothing in it says the first write
            // alone would not fit, and reissuing it would loop forever.
            guard !event.answers.isEmpty else { throw RemoteManagementError.unreadable }
            answers.append(contentsOf: event.answers)
            remaining.removeFirst(min(event.answers.count, remaining.count))
        }
        return answers
    }

    /// Enter DFU only after receiving the target's status response.
    func enterRemoteDfu(peerAddress: String, mode: UlcpDfuMode) async throws {
        try await DfuEntryError.perform {
            let event = try await self.performManagement { session in
                try session.beginManagementDfu(peerAddress: peerAddress, mode: mode)
            }
            return event.statusCode
        }
    }

    /// Restart or wipe a device across the mesh.
    ///
    /// The reset-class commands are answered by nothing: the device acts and
    /// the MAC acknowledgment is the confirmation, so `.acknowledged` is
    /// success rather than a shortfall and there is no status to require.
    /// The one reply any of them produces is a refusal—a device without
    /// `CAP_REBOOT` saying it cannot restart—and that is worth surfacing.
    func resetRemoteDevice(peerAddress: String, scope: MobileMeshResetScope) async throws {
        let event = try await performManagement { session in
            try session.beginManagementReset(peerAddress: peerAddress, scope: scope)
        }
        try Self.require(refusal: event.refusal)
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

    func announceRemoteDevice(
        peerAddress: String,
        request: MobileAnnouncementRecord
    ) async throws {
        let event = try await performManagement { session in
            try session.beginManagementAnnounce(peerAddress: peerAddress, request: request)
        }
        try Self.require(refusal: event.refusal)
    }

    func saveRemoteDevice(peerAddress: String) async throws {
        let event = try await performManagement { session in
            try session.beginManagementSave(peerAddress: peerAddress)
        }
        try Self.require(refusal: event.refusal)
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

    func setRemoteWifiNetwork(
        peerAddress: String,
        item: Data,
        present: Bool
    ) async throws {
        let property = ulcpManagedPropertyIds().wifiNetworks
        let event = try await performManagement { session in
            present
                ? try session.beginManagementInsert(
                    peerAddress: peerAddress,
                    propertyId: property,
                    item: item
                )
                : try session.beginManagementRemove(
                    peerAddress: peerAddress,
                    propertyId: property,
                    selector: item
                )
        }
        try Self.requireTableEdit(event)
    }

    /// Read the answer to a one-entry table edit: the list as it now
    /// stands, or a status where that list belonged.
    private static func requireTableEdit(_ event: MobileMeshManagementEventRecord) throws {
        try require(refusal: event.answers.first?.refusal ?? event.refusal)
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
            try Self.require(refusal: event.refusal)
            throw RemoteManagementError.unreadable
        }
        try Self.require(refusal: answer.refusal)
        // A write is echoed with what the device is now doing, and that is
        // the answer worth showing: a device may refuse to start an alert
        // it has no way to make, and one already running restarts its own
        // deadline rather than reporting anything new.
        guard let value = answer.value,
              let reported = try? inspectUlcpAlert(value: value)
        else { throw RemoteManagementError.unreadable }
        return RadioAlertState(reported)
    }

    /// Throw the device's refusal, if it refused. The core decides what
    /// counts as one.
    static func require(refusal: UInt32?) throws {
        if let refusal { throw RemoteManagementError.refused(status: refusal) }
    }

    /// Run one node-management exchange to completion.
    ///
    /// Unlike a ULCP operation over the local link, several of these can be
    /// in flight: the Rust worker queues each device's operations behind
    /// one another and runs different devices' side by side, so there is
    /// nothing to serialize here.
    ///
    /// Canceling the calling task cancels the operation in the worker too,
    /// which stops the MAC retrying it and lets the next one for that
    /// device go.
    func performManagement(
        progress: (@Sendable (UInt32?) -> Void)? = nil,
        _ start: @escaping @Sendable (MobileMeshSession) throws -> UInt64
    ) async throws -> MobileMeshManagementEventRecord {
        let waiter = RadioOperationWaiter<MobileMeshManagementEventRecord>()
        let event = try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation {
                (result: CheckedContinuation<MobileMeshManagementEventRecord, any Error>) in
                guard waiter.install(result) else { return }
                sessionQueue.async { [self] in
                    guard !waiter.isCancelled else { return }
                    guard let meshSession, radioCarriesThisPhone else {
                        waiter.resume(throwing: RemoteManagementError.unavailable)
                        return
                    }
                    do {
                        let operation = try start(meshSession)
                        managementWaiters[operation] = ManagementWaiter(
                            waiter: waiter,
                            progress: progress
                        )
                    } catch {
                        waiter.resume(throwing: RemoteManagementError.unavailable)
                    }
                }
            }
        } onCancel: {
            waiter.cancel()
            sessionQueue.async { [weak self] in self?.cancelAbandonedManagement() }
        }
        switch event.outcome {
        case .replied, .acknowledged:
            return event
        case .timedOut:
            throw RemoteManagementError.noAnswer
        case .unreachable:
            throw RemoteManagementError.unreachable
        case .canceled:
            throw CancellationError()
        case .failed:
            throw RemoteManagementError.unreadable
        case .progress:
            // Progress never resolves a waiter; reaching here would mean the
            // pump resumed one with a report rather than an ending.
            throw RemoteManagementError.unreadable
        }
    }

    /// Cancel in the worker every operation whose caller stopped waiting.
    ///
    /// The caller has already been released; this is what stops the
    /// request itself. One whose cancellation landed before it started
    /// never reaches the worker at all.
    private func cancelAbandonedManagement() {
        for (operation, waiter) in managementWaiters where waiter.waiter.isCancelled {
            managementWaiters[operation] = nil
            try? meshSession?.cancelManagement(operationId: operation)
        }
    }
}

// ----------------------------------------------------------------------
// Operations on the radio itself, through the driver
// ----------------------------------------------------------------------

extension RadioDriverAdapter {
    func useHostIdentity(_ identity: MeshPublicIdentity?) throws {
        let hostKey = try identity.map {
            try UMSHMobileCore.publicIdentityBytes(address: $0.canonicalAddress)
        }
        try driver.setHostKey(hostKey: hostKey)
    }

    func claimForCurrentIdentity() async throws {
        try await call(mapping: Self.claimError) { try await driver.claim() }
    }

    /// Hand the radio back before the user disconnects from it, forgets it,
    /// or moves to another: clear this phone's host key, so the radio stops
    /// queueing and acknowledging for a phone that has let it go. A link
    /// that merely drops keeps it—that is what the queue is for.
    ///
    /// Returns once the radio answers, the link goes, or the deadline
    /// passes; the teardown that follows does not depend on which. A radio
    /// holding another host's key, or none, has nothing to release.
    func releaseHost() async {
        await driver.releaseHost()
    }

    /// A deliberate new attempt gets a fresh recovery budget; a failing
    /// automatic reconnect must not refill itself indefinitely.
    func resetRecoveryBudget() {
        driver.resetRecoveryBudget()
    }

    func refresh() async throws -> RadioSnapshot {
        RadioSnapshot(try await call(mapping: Self.connectionError) {
            try await driver.refresh()
        })
    }

    func refreshPositioning() async throws -> RadioSnapshot {
        RadioSnapshot(try await call(mapping: Self.connectionError) {
            try await driver.refreshPositioning()
        })
    }

    func configure(_ settings: RadioSettings) async throws {
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
        try await call(mapping: Self.connectionError) {
            try await driver.configure(settings: record)
        }
    }

    func configurePositioning(
        gnss: UlcpGnssSettingsRecord?,
        timeZoneRule: String?,
        time24h: Bool?
    ) async throws {
        try await call(mapping: Self.connectionError) {
            try await driver.configurePositioning(gnss: gnss, tzRule: timeZoneRule, time24h: time24h)
        }
    }

    func configureAdvertising(_ advert: UlcpAdvertSettingsRecord?) async throws {
        try await call(mapping: Self.connectionError) {
            try await driver.configureAdvertising(advert: advert)
        }
    }

    // MARK: Device tables

    func addDevicePeer(_ publicKey: Data) async throws {
        try await deviceTable { try await $0.insertDevicePeer(publicKey: publicKey) }
    }

    func removeDevicePeer(_ publicKey: Data) async throws {
        try await deviceTable { try await $0.removeDevicePeer(publicKey: publicKey) }
    }

    func addDeviceAdmin(_ publicKey: Data) async throws {
        try await deviceTable { try await $0.insertDeviceAdmin(publicKey: publicKey) }
    }

    func removeDeviceAdmin(_ publicKey: Data) async throws {
        try await deviceTable { try await $0.removeDeviceAdmin(publicKey: publicKey) }
    }

    func addDeviceChannel(_ channelKey: Data) async throws {
        try await deviceTable { try await $0.insertDeviceChannelKey(channelKey: channelKey) }
    }

    func removeDeviceChannel(_ channelKey: Data) async throws {
        try await deviceTable { try await $0.removeDeviceChannelKey(channelKey: channelKey) }
    }

    func reconcileHostChannels(_ channelKeys: [Data]) async throws {
        try await deviceTable { try await $0.reconcileHostChannelKeys(keys: channelKeys) }
    }

    func reconcileHostPeerKeys(_ entries: [HostPeerKeyEntryRecord]) async throws {
        try await deviceTable { try await $0.reconcileHostPeerKeys(entries: entries) }
    }

    func reconcileHostDestinationHints(_ hints: [Data]) async throws {
        try await deviceTable { try await $0.reconcileHostDestinationHints(hints: hints) }
    }

    func reconcileHostMutes(channelIdentifiers: [Data], peerKeys: [Data]) async throws {
        try await deviceTable {
            try await $0.reconcileHostMutes(
                channelIdentifiers: channelIdentifiers,
                peerKeys: peerKeys
            )
        }
    }

    func setHostAutoAcknowledgement(_ enabled: Bool) async throws {
        try await deviceTable { try await $0.setHostAutoAck(enabled: enabled) }
    }

    func drainOfflineQueue() async throws {
        try await deviceTable { try await $0.drainQueue() }
    }

    /// A table edit, resolved by the update that carries its outcome. The
    /// driver queues it behind other exchanges and mesh traffic, and
    /// reports `operationInProgress` only when its queue is full.
    private func deviceTable(
        _ edit: (MobileRadioDriver) async throws -> Void
    ) async throws {
        try await call(mapping: Self.devicePeerError, cancellable: true) {
            try await edit(driver)
        }
    }

    // MARK: Commands the radio acts on at once

    func setAlert(_ state: RadioAlertState) async throws {
        Self.logger.notice("action: user set locate alert to \(state.rawValue)")
        try await call(mapping: Self.immediateError) {
            try await driver.setAlert(state: state.wire)
        }
    }

    func setTime(epochSeconds: UInt32?) async throws {
        Self.logger.notice(
            "action: user \(epochSeconds == nil ? "cleared" : "set") the radio clock"
        )
        try await call(mapping: Self.immediateError) {
            try await driver.setTime(epochSeconds: epochSeconds)
        }
    }

    /// The radio erases all state and reboots, dropping the link itself.
    /// The driver abandons the binding so the app does not reconnect to
    /// the now-blank radio, and leaves the link up so the command's write
    /// flushes before the radio's own reboot disconnects.
    func factoryReset() async throws {
        Self.logger.notice("action: user pressed Factory Reset")
        try await call(mapping: Self.immediateError) { try await driver.factoryReset() }
    }

    /// The link drops when the radio restarts, and the binding is
    /// deliberately kept: the radio coming back is the same radio, with the
    /// same bond and host key, and reconnecting to it is the point.
    func reboot() async throws {
        Self.logger.notice("action: user pressed Restart Radio")
        try await call(mapping: Self.immediateError) { try await driver.reboot() }
    }

    // MARK: Managing the companion radio itself

    func announce(_ request: MobileAnnouncementRecord) async throws {
        Self.logger.notice(
            "action: user asked the radio to announce itself (\(String(describing: request.kind)))"
        )
        // Answered, so it runs as a management exchange: what the radio
        // says—busy, a channel it does not hold—reaches the screen that
        // asked, the way it does over the mesh.
        let event = try await localManagement { try await $0.announce(request: request) }
        try Self.require(refusal: event.refusal)
    }

    func enterDfu(mode: UlcpDfuMode) async throws {
        try await DfuEntryError.perform {
            try await self.localManagement { try await $0.enterDfu(mode: mode) }.statusCode
        }
    }

    /// Read named properties from the companion radio over the local link.
    ///
    /// The local counterpart of `fetchRemoteProperties`: same answers,
    /// same refusal semantics, no mesh in between.
    func fetchCompanionProperties(
        _ propertyIDs: [UInt32]
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        guard !propertyIDs.isEmpty else { return [] }
        return try await localManagement { try await $0.fetchProperties(propertyIds: propertyIDs) }
            .answers
    }

    /// Write properties to the companion radio, in the given order.
    func writeCompanionProperties(
        _ writes: [MobileMeshPropertyWriteRecord]
    ) async throws -> [MobileMeshManagementAnswerRecord] {
        guard !writes.isEmpty else { return [] }
        return try await localManagement { try await $0.writeProperties(writes: writes) }.answers
    }

    func addDeviceWifiNetwork(_ item: Data) async throws {
        try await mutateWifiNetworks(.insert, value: item)
    }

    func removeDeviceWifiNetwork(ssid: Data) async throws {
        try await mutateWifiNetworks(.remove, value: ssid)
    }

    /// Run one edit of the radio's own network table and read its answer:
    /// the item it changed, or a status where that item belonged.
    private func mutateWifiNetworks(
        _ mutation: UlcpItemMutation,
        value: Data
    ) async throws {
        let event = try await localManagement {
            try await $0.editPropertyItems(
                propertyId: ulcpManagedPropertyIds().wifiNetworks,
                mutations: [UlcpItemMutationRecord(mutation: mutation, value: value)]
            )
        }
        try Self.require(refusal: event.answers.first?.refusal ?? event.refusal)
    }

    /// Persist the companion radio's live configuration.
    func saveCompanionDevice() async throws {
        let event = try await localManagement { try await $0.save() }
        try Self.require(refusal: event.refusal)
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

    /// Run one local management exchange to completion.
    ///
    /// Errors wear `RemoteManagementError` so the management screens read
    /// this path and the mesh path with the same copy.
    private func localManagement(
        _ exchange: (MobileRadioDriver) async throws -> UlcpLocalManagementEventRecord
    ) async throws -> UlcpLocalManagementEventRecord {
        try await call(mapping: Self.managementError, cancellable: true) {
            try await exchange(driver)
        }
    }

    // MARK: Errors

    /// Make a driver call, and give its caller the error it has always
    /// handled.
    ///
    /// A call cannot be canceled once it reaches the driver: the radio
    /// may already be acting on it. A `cancellable` caller that stopped
    /// waiting learns so when it returns, the radio's answer or the
    /// driver's deadline whichever comes first.
    private func call<Value>(
        mapping: (MobileRadioError) -> any Error,
        cancellable: Bool = false,
        _ body: () async throws -> Value
    ) async throws -> Value {
        let outcome: Result<Value, any Error>
        do {
            outcome = .success(try await body())
        } catch {
            outcome = .failure(error)
        }
        if cancellable {
            try Task.checkCancellation()
        }
        switch outcome {
        case let .success(value):
            return value
        case let .failure(error as MobileRadioError):
            throw mapping(error)
        case let .failure(error):
            throw error
        }
    }

    /// For a refresh or a configuration change. A call the ULCP session
    /// refused throws the session's own cause, as it always has.
    static func connectionError(_ error: MobileRadioError) -> any Error {
        switch error {
        case .RadioUnavailable, .Stopped, .LinkFailed:
            RadioConnectionError.radioNotFound
        case .OperationInProgress:
            RadioConnectionError.operationInProgress
        case .IdentityUnavailable:
            RadioConnectionError.identityUnavailable
        case .TakeoverNotAllowed:
            RadioConnectionError.takeoverNotAllowed
        case let .OperationRejected(operation, statusCode, statusName):
            RadioConnectionError.operationRejected(
                MobileRadioProblem.operationRejected(
                    operation: operation,
                    statusCode: statusCode,
                    statusName: statusName
                ).text
            )
        case .UnrecognizedAnswer:
            RadioConnectionError.unrecognizedAnswer
        case .TimedOut:
            RadioConnectionError.operationTimedOut
        case let .Refused(cause):
            cause
        case .IncompatibleProtocol, .Unsupported, .DeviceFull, .InvalidArgument:
            RadioConnectionError.incompatibleProtocol
        }
    }

    /// For an edit of the radio's own tables, shaped for the inline copy
    /// those screens show.
    static func devicePeerError(_ error: MobileRadioError) -> any Error {
        switch error {
        case .RadioUnavailable, .Stopped, .LinkFailed:
            DevicePeerError.radioUnavailable
        case .Unsupported:
            DevicePeerError.unsupported
        case .DeviceFull:
            DevicePeerError.deviceFull
        case let .OperationRejected(_, _, statusName):
            DevicePeerError.failed(statusName)
        case .UnrecognizedAnswer:
            DevicePeerError.unrecognizedAnswer
        case .TimedOut:
            DevicePeerError.failed(String(localized: "The radio did not answer"))
        case .OperationInProgress, .Refused, .IncompatibleProtocol, .IdentityUnavailable,
             .TakeoverNotAllowed, .InvalidArgument:
            RadioConnectionError.operationInProgress
        }
    }

    /// For a command the radio acts on at once.
    static func immediateError(_ error: MobileRadioError) -> any Error {
        switch error {
        case .RadioUnavailable, .Stopped, .LinkFailed: RadioConnectionError.radioNotFound
        default: RadioConnectionError.incompatibleProtocol
        }
    }

    /// For a claim. The driver has already put the failure on the banner.
    static func claimError(_ error: MobileRadioError) -> any Error {
        switch error {
        case .IdentityUnavailable: RadioConnectionError.identityUnavailable
        case .TakeoverNotAllowed: RadioConnectionError.takeoverNotAllowed
        case .Stopped, .LinkFailed: RadioConnectionError.radioNotFound
        default: RadioConnectionError.incompatibleProtocol
        }
    }

    /// For a management exchange with the companion radio. Timed out is
    /// the radio saying nothing; everything else is the radio not being
    /// there to ask.
    static func managementError(_ error: MobileRadioError) -> any Error {
        switch error {
        case .TimedOut: RemoteManagementError.noAnswer
        default: RemoteManagementError.unavailable
        }
    }
}

// ----------------------------------------------------------------------
// The state, as the app shows it
// ----------------------------------------------------------------------

extension RadioSnapshot {
    init(_ state: MobileRadioStateRecord) {
        let identity = state.deviceKey.flatMap {
            try? UMSHMobileCore.inspectPublicIdentityBytes(publicKey: $0)
        }
        self.init(
            linkState: RadioLinkState(state.phase),
            name: state.name,
            localIdentifier: state.linkId.flatMap(UUID.init(uuidString:)),
            batteryPercentage: state.battery?.percentage.map(Int.init),
            batteryVoltageMillivolts: state.battery?.voltageMv.map(Int.init),
            chargeState: state.battery?.chargeState.map(RadioChargeState.init),
            batteryReadAt: state.batteryReadAtMs.map(Date.init(unixMilliseconds:)),
            deviceIdentity: identity.map {
                MeshPublicIdentity(
                    canonicalAddress: $0.canonicalAddress,
                    hint: MeshNodeHint(bytes: $0.hint.bytes, text: $0.hint.text)
                )
            },
            hostState: RadioHostState(state.host),
            provisioning: state.provisioning.map(RadioProvisioningSummary.init),
            alert: state.alert.map(RadioAlertState.init),
            clock: state.clock.map {
                RadioClock(
                    date: $0.epochSeconds.map { Date(timeIntervalSince1970: TimeInterval($0)) },
                    readAt: Date(unixMilliseconds: $0.readAtMs)
                )
            },
            position: state.position.map(RadioPosition.init),
            problemDescription: state.problem?.text
        )
    }
}

extension Date {
    init(unixMilliseconds: UInt64) {
        self.init(timeIntervalSince1970: TimeInterval(unixMilliseconds) / 1_000)
    }
}

extension RadioLinkState {
    init(_ phase: MobileRadioPhase) {
        self = switch phase {
        case .idle: .idle
        case .unavailable: .unavailable
        case .scanning: .scanning
        case .discovered: .discovered
        case .connecting: .connecting
        case .pairing: .pairing
        case .attaching: .attaching
        case .reconnecting: .reconnecting
        case .waitingForRadio: .waitingForRadio
        case .synchronizing: .synchronizing
        case .awaitingHost: .awaitingHost
        case .provisioning: .provisioning
        case .configuring: .configuring
        case .attached: .attached
        case .disconnecting: .disconnecting
        case .failed: .failed
        }
    }
}

extension RadioHostState {
    init(_ ownership: UlcpHostOwnership) {
        self = switch ownership {
        case .unknown: .unknown
        case .localIdentityUnavailable: .localIdentityUnavailable
        case .unsupported: .unsupported
        case .unclaimed: .unclaimed
        case .ours: .matchesCurrentIdentity
        case .otherHost: .belongsToAnotherIdentity
        }
    }
}

extension RadioProvisioningSummary {
    init(_ sync: UlcpSyncRecord) {
        self.init(
            capabilityCount: Int(sync.capabilityCount),
            hasHostFiltering: sync.hasHostFiltering,
            supportsOfflineQueue: sync.supportsOfflineQueue,
            supportsDelegatedAcknowledgements: sync.supportsDelegatedAck,
            supportsDeviceName: sync.supportsDeviceName,
            supportsLoRa: sync.supportsLora,
            supportsDutyCycleLimit: sync.supportsDutyCycleLimit,
            supportsBattery: sync.supportsBattery,
            phyEnabled: sync.phyEnabled,
            frequencyKHz: sync.frequencyKhz,
            transmitPowerDBm: sync.transmitPowerDbm,
            bandwidthHz: sync.bandwidthHz,
            spreadingFactor: sync.spreadingFactor,
            codingRateDenominator: sync.codingRateDenom,
            dutyCycleNow: sync.dutyCycleNow,
            dutyCycleLimit: sync.dutyCycleLimit,
            saved: sync.saved,
            queuedFrames: sync.queuedFrames.map(Int.init),
            droppedFrames: sync.droppedFrames,
            filterCount: sync.filterCount.map(Int.init),
            hostChannelCount: sync.hostChannelCount.map(Int.init),
            hostPeerCount: sync.hostPeerCount.map(Int.init),
            autoAcknowledgementEnabled: sync.autoAck,
            supportsDeviceIdentity: sync.supportsDeviceIdentity,
            devPeerAddresses: sync.devPeerKeys.map { keys in
                keys.compactMap {
                    try? UMSHMobileCore.inspectPublicIdentityBytes(publicKey: $0)
                        .canonicalAddress
                }
            },
            devChannelIDs: sync.devChannelIds,
            // The host key tables are read exactly when the radio
            // advertises CAP_HOST_KEYS, so a reported count is the
            // capability.
            supportsHostKeys: sync.hostChannelCount != nil,
            supportsTime: sync.supportsTime,
            supportsGnss: sync.supportsGnss,
            supportsAdvert: sync.supportsAdvert,
            supportsReboot: sync.supportsReboot,
            timeZoneRule: sync.tzRule,
            time24h: sync.time24h,
            gnss: sync.gnss,
            advert: sync.advert
        )
    }
}

// ----------------------------------------------------------------------
// Callbacks from Rust threads
// ----------------------------------------------------------------------

/// Carries the driver's link calls onto the transport's queue, in the
/// order the driver made them. Holds the transport weakly: the driver
/// holds this for as long as it runs, and the transport holds the driver.
final class DriverLinkBridge: RadioLink, @unchecked Sendable {
    private let queue: DispatchQueue
    /// Set before the transport reports anything the driver could answer.
    /// Cleared to cut off a driver being retired, so a late call from it
    /// cannot reach the link that replaced it.
    weak var link: (any UlcpFrameLink)?

    init(queue: DispatchQueue) {
        self.queue = queue
    }

    private func perform(_ body: @escaping @Sendable (any UlcpFrameLink) -> Void) {
        queue.async { [weak self] in
            guard let link = self?.link else { return }
            body(link)
        }
    }

    func send(frame: Data, rawTransactionId: UInt8?) {
        perform { $0.linkSend(frame: frame, rawTransactionID: rawTransactionId) }
    }

    func resetFraming() {
        perform { $0.linkResetFraming() }
    }

    func invalidate(retry: Bool) {
        perform { $0.linkInvalidate(retrying: retry) }
    }

    func didAttach() {
        perform { $0.linkDidAttach() }
    }

    func didReportName(name: String) {
        perform { $0.linkDidReportName(name) }
    }

    func abandonBinding() {
        perform { $0.linkAbandonBinding() }
    }

    func didEnterDfu() {
        perform { $0.linkDidEnterDfu() }
    }
}

/// Tells the adapter that the driver has an update. Runs on the driver's
/// thread; holds the adapter weakly so a retired one cannot be kept alive.
private final class DriverUpdateListener: MobileRadioDriverListener, @unchecked Sendable {
    private weak var adapter: RadioDriverAdapter?

    init(adapter: RadioDriverAdapter) {
        self.adapter = adapter
    }

    func onUpdatePending() {
        adapter?.driverDidAnnounceUpdate()
    }
}

/// Bridges the mesh session's pending-update announcement onto the
/// adapter's queue. Runs on the Rust worker thread; holds the adapter
/// weakly so a retired one cannot keep it alive.
final class MeshSessionWakeListener: MobileMeshWakeListener, @unchecked Sendable {
    private weak var adapter: RadioDriverAdapter?

    init(adapter: RadioDriverAdapter) {
        self.adapter = adapter
    }

    func onUpdatePending() {
        adapter?.meshSessionDidAnnounceUpdate()
    }
}
