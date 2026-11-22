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

/// The radio side of a companion radio, over `MobileRadioDriver`.
///
/// The driver runs the ULCP session and owns the radio's whole state; the
/// app core holds it, carries the mesh session over it, and publishes what
/// it says. This class reports the transport's state to the driver,
/// carries out the link calls it makes, and maps the errors of the plain
/// radio commands onto the ones callers already handle.
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
    }

    /// Over a driver whose link lives in the core, which reports its own
    /// transport states: the staging air's.
    init(sessionQueue: DispatchQueue, driver: MobileRadioDriver) {
        self.sessionQueue = sessionQueue
        linkBridge = nil
        self.driver = driver
        super.init()
    }

    deinit {
        // The driver's thread holds the link bridge until it stops;
        // nothing else would end it.
        driver.stop()
    }

    /// The driver, for the app core to hold.
    var radioDriver: MobileRadioDriver? { driver }

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
}

// ----------------------------------------------------------------------
// Operations on the radio itself, through the driver
// ----------------------------------------------------------------------

extension RadioDriverAdapter {
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

    // MARK: Commands the radio acts on at once

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

    // MARK: Errors

    /// Make a driver call, and give its caller the error it has always
    /// handled.
    ///
    /// A call cannot be canceled once it reaches the driver: the radio
    /// may already be acting on it.
    private func call<Value>(
        mapping: (MobileRadioError) -> any Error,
        _ body: () async throws -> Value
    ) async throws -> Value {
        do {
            return try await body()
        } catch let error as MobileRadioError {
            throw mapping(error)
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
            // A past reading's charge state says nothing about now.
            chargeState: state.batteryCached ? nil : state.battery?.chargeState.map(RadioChargeState.init),
            batteryReadAt: state.batteryReadAtMs.map(Date.init(unixMilliseconds:)),
            batteryCached: state.batteryCached,
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
            advert: sync.advert,
            protocolVersion: sync.protocolVersion,
            capabilities: sync.capabilities,
            deviceVersion: sync.deviceVersion,
            deviceModel: sync.deviceModel
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
