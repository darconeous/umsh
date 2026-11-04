import Foundation
import Network
import OSLog
import UMSHMobileCore

/// The LAN virtual radio.
///
/// A companion radio with no hardware: the production device session,
/// running in the mobile core, whose PHY is the LAN's multicast group.
/// The app attaches to it with the same HDLC-Lite frames a serial link
/// carries, so the session above cannot tell it from a T1000-E. Frames
/// it sends reach the mesh through whichever radios on the network
/// forward them. Its group is a setting of its own, managed like any
/// radio's.
///
/// The device runs in one of two places. Hosted in this process, as in
/// the Simulator, it runs only while the app does. Hosted by the network
/// extension, it runs while the phone is on a listed network, whatever
/// the app is doing, and the app reaches it over the extension's local
/// socket: connecting attaches and closing detaches. Either way it keeps
/// running across a detach, acknowledging and queueing.
final class VirtualRadioConnection: UlcpRadioSession, RadioConnection, UlcpFrameLink,
    @unchecked Sendable {
    /// Where the device runs.
    enum Hosting {
        /// In this process, keeping its state in `stateDirectory`.
        case inProcess(stateDirectory: URL)
        /// In the network extension, reached at its local socket.
        case socket(path: String)
    }

    /// How long to wait before trying again when the device cannot be
    /// reached.
    private static let retryDelaySeconds: TimeInterval = 2

    /// The one virtual radio's identifier, fixed so the app remembers it
    /// like any other radio. The same wherever it is hosted: it is one
    /// device.
    private static let identifier = UUID(uuidString: "5B0E7C1A-8D3F-4E62-9A4B-6C1D2E3F4A5B")!

    private static let displayName = "Local network"

    private let hosting: Hosting
    private var identifier: UUID { Self.identifier }
    private let decoder = MobileHdlcDecoder()
    /// The device, when hosted here.
    private var radio: MobileVirtualRadio?
    /// The connection to the extension's socket, while there is one.
    private var socket: NWConnection?
    private var attached = false
    /// Counts attaches to an in-process device, so bytes owed to an
    /// earlier session are recognized and dropped.
    private var generation = 0
    /// False once the user disconnects, so a deliberate teardown does
    /// not immediately start again.
    private var wantsConnection = false

    init(hosting: Hosting = .inProcess(stateDirectory: VirtualRadioPaths.stateDirectory)) {
        self.hosting = hosting
        super.init(sessionQueue: DispatchQueue(
            label: "com.voria.umsh.radio.virtual",
            qos: .userInitiated
        ))
        adopt(link: self)
        snapshot.localIdentifier = Self.identifier
    }

    // ------------------------------------------------------------------
    // Connection lifecycle
    // ------------------------------------------------------------------

    func connect() async throws {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                Self.logger.notice("action: connect to the LAN virtual radio")
                startAttaching()
                result.resume()
            }
        }
    }

    func autoConnect() async {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                startAttaching()
                result.resume()
            }
        }
    }

    func reconnect() async {
        await autoConnect()
    }

    func disconnect() async {
        await releaseHost()
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                Self.logger.notice("action: user pressed Disconnect")
                wantsConnection = false
                detach(problem: nil)
                result.resume()
            }
        }
    }

    /// The virtual radio's state is its own, like a radio's flash, and
    /// stays; forgetting it is disconnecting.
    func forget() async {
        await disconnect()
    }

    // ------------------------------------------------------------------
    // Discovery
    // ------------------------------------------------------------------

    /// One virtual radio. The list is a single entry so the existing
    /// picker works unchanged.
    func discoverRadios() async -> AsyncStream<[DiscoveredRadio]> {
        AsyncStream { continuation in
            continuation.yield([DiscoveredRadio(
                id: identifier,
                name: Self.displayName,
                // The sentinel the rest of the app already reads as
                // "no signal to report".
                rssiDBm: 127,
                isRemembered: true
            )])
            continuation.finish()
        }
    }

    func selectRadio(_ id: UUID) async throws {
        guard id == identifier else {
            throw RadioConnectionError.radioNotFound
        }
        try await connect()
    }

    func stopDiscovery() async {}

    // ------------------------------------------------------------------
    // UlcpFrameLink
    // ------------------------------------------------------------------

    var linkIsReady: Bool { attached }

    var linkID: UUID? { identifier }

    var linkName: String? { snapshot.name ?? Self.displayName }

    var linkIsBoundRadio: Bool { true }

    var linkCanReconnect: Bool { wantsConnection }

    func linkSend(frame: Data, rawTransactionID: UInt8?) {
        guard attached else { return }
        let wire: Data
        do {
            wire = try UMSHMobileCore.ulcpHdlcEncode(frame: frame)
        } catch {
            terminateConnectionForFatalProtocolError(
                "The ULCP session produced an unsendable frame",
                name: linkName
            )
            return
        }
        if let radio {
            radio.receive(bytes: wire)
        } else if let socket {
            socket.send(content: wire, completion: .contentProcessed { [weak self] error in
                guard let self, error != nil else { return }
                // A refused write means the socket is gone.
                self.sessionQueue.async {
                    self.detach(problem: "The local network radio stopped")
                }
            })
        }
    }

    func linkResetFraming() {
        decoder.reset()
    }

    func linkInvalidate(retrying: Bool) {
        if !retrying { wantsConnection = false }
        detach(problem: nil, preservingPublishedFailure: true)
    }

    func linkDidAttach() {}

    func linkDidReportName(_ name: String) {}

    func linkAbandonBinding() {
        wantsConnection = false
    }

    func linkDidEnterDfu() {
        wantsConnection = false
        detach(problem: nil)
    }

    // ------------------------------------------------------------------
    // The device
    // ------------------------------------------------------------------

    private func startAttaching() {
        wantsConnection = true
        guard !attached, socket == nil else { return }
        // Publishes over the standing snapshot, so a failure stays on
        // screen through the retry.
        snapshot.linkState = .connecting
        snapshot.name = Self.displayName
        snapshot.localIdentifier = identifier
        publish(snapshot)
        switch hosting {
        case .inProcess(let stateDirectory):
            attachInProcess(stateDirectory: stateDirectory)
        case .socket(let path):
            connectSocket(path: path)
        }
    }

    private func attachInProcess(stateDirectory: URL) {
        if radio == nil {
            do {
                try FileManager.default.createDirectory(
                    at: stateDirectory,
                    withIntermediateDirectories: true,
                    attributes: [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication]
                )
                // Choosing this radio is choosing the LAN, so it comes up
                // listening whatever it saved.
                radio = try MobileVirtualRadio.start(
                    stateDir: stateDirectory.path,
                    enablePhy: true,
                    listener: VirtualRadioListener()
                )
            } catch {
                snapshot.problemDescription = Self.describe(error)
                publish(snapshot)
                scheduleRetry()
                return
            }
        }
        decoder.reset()
        generation &+= 1
        attached = true
        radio?.attach(sink: VirtualRadioSink(connection: self, generation: generation))
        linkDidBecomeReady()
    }

    private func connectSocket(path: String) {
        let connection = NWConnection(to: .unix(path: path), using: .tcp)
        socket = connection
        connection.stateUpdateHandler = { [weak self] state in
            guard let self, self.socket === connection else { return }
            switch state {
            case .ready:
                self.decoder.reset()
                self.attached = true
                self.receiveNext(on: connection)
                // Connecting is attaching, so the ULCP handshake starts
                // here.
                self.linkDidBecomeReady()
            case .failed, .waiting:
                // No extension listening: try again shortly.
                self.detach(problem: "The local network radio is not running")
            default:
                break
            }
        }
        connection.start(queue: sessionQueue)
    }

    /// A stream hands over arbitrary chunks, so one read can complete
    /// none, one, or several frames.
    private func receiveNext(on connection: NWConnection) {
        connection.receive(
            minimumIncompleteLength: 1,
            maximumLength: 65_536
        ) { [weak self] content, _, isComplete, error in
            guard let self, self.socket === connection else { return }
            if let content, !content.isEmpty {
                for frame in self.decoder.push(bytes: content) {
                    self.linkDidReceive(frame: frame)
                }
            }
            // The extension closing the socket is a detach: it stopped,
            // or another connection replaced this one.
            if error != nil || isComplete {
                self.detach(problem: "The local network radio closed the connection")
                return
            }
            self.receiveNext(on: connection)
        }
    }

    /// Detach from the device, which carries on queueing wherever it is
    /// hosted, then try again if the user still wants this radio.
    private func detach(problem: String?, preservingPublishedFailure: Bool = false) {
        let wasUp = attached || socket != nil
        if attached, radio != nil {
            radio?.detach()
        }
        attached = false
        generation &+= 1
        socket?.stateUpdateHandler = nil
        socket?.cancel()
        socket = nil
        decoder.reset()
        guard wasUp else { return }
        if preservingPublishedFailure {
            sessionDidLoseLink()
        } else if wantsConnection {
            // The retry is part of the same standing attempt, so this
            // publishes one steady state rather than flapping.
            sessionDidLoseLink()
            snapshot.linkState = .connecting
            snapshot.name = Self.displayName
            snapshot.localIdentifier = identifier
            if let problem { snapshot.problemDescription = problem }
            publish(snapshot)
        } else {
            linkDidClose(problem: problem)
        }
        if wantsConnection { scheduleRetry() }
    }

    private func scheduleRetry() {
        sessionQueue.asyncAfter(deadline: .now() + Self.retryDelaySeconds) { [weak self] in
            guard let self, self.wantsConnection, !self.attached, self.socket == nil else { return }
            self.startAttaching()
        }
    }

    private static func describe(_ error: Error) -> String {
        switch error as? MobileVirtualRadioError {
        case .StateInUse:
            "The local network radio is in use elsewhere"
        default:
            "The local network radio could not start"
        }
    }

    /// Bytes from an in-process device, on its worker thread.
    fileprivate func deviceDidSend(_ bytes: Data, generation: Int) {
        sessionQueue.async { [self] in
            guard attached, generation == self.generation else { return }
            for frame in decoder.push(bytes: bytes) {
                linkDidReceive(frame: frame)
            }
        }
    }
}

/// Carries one attach's replies onto the connection's queue. Holds the
/// connection weakly so a released one cannot be kept alive by its
/// device.
private final class VirtualRadioSink: MobileWireSink, @unchecked Sendable {
    private weak var connection: VirtualRadioConnection?
    private let generation: Int

    init(connection: VirtualRadioConnection, generation: Int) {
        self.connection = connection
        self.generation = generation
    }

    func onWire(bytes: Data) {
        connection?.deviceDidSend(bytes, generation: generation)
    }
}

/// In-process, the device queues only while the app is running and
/// detached, and the app notices its own messages when it drains.
private final class VirtualRadioListener: MobileVirtualRadioListener, @unchecked Sendable {
    func onQueued(notice: MobileQueuedNoticeRecord) {}
}
