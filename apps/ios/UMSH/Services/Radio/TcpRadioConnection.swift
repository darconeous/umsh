import CryptoKit
import Foundation
import Network
import OSLog
import UMSHMobileCore

/// Where a bridged radio lives, as the user typed it.
struct TcpEndpoint: Equatable {
    var host: String
    var port: UInt16

    /// Parse `host:port`, accepting a bracketed IPv6 literal. The port
    /// is required — there is no registered one to assume.
    init?(_ text: String) {
        let text = text.trimmingCharacters(in: .whitespaces)
        let host: Substring
        let port: Substring
        if text.hasPrefix("["), let close = text.firstIndex(of: "]") {
            host = text[text.index(after: text.startIndex)..<close]
            let rest = text[text.index(after: close)...]
            guard rest.hasPrefix(":") else { return nil }
            port = rest.dropFirst()
        } else {
            guard let colon = text.lastIndex(of: ":") else { return nil }
            host = text[text.startIndex..<colon]
            port = text[text.index(after: colon)...]
        }
        guard !host.isEmpty, let number = UInt16(port), number != 0 else { return nil }
        self.host = String(host)
        self.port = number
    }

    var text: String {
        host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
    }

    /// A stable identity for this endpoint, so the snapshot's radio id
    /// and anything keyed on it survive a relaunch.
    var identifier: UUID {
        var digest = Array(SHA256.hash(data: Data("umsh-tcp-radio:\(text)".utf8)).prefix(16))
        digest[6] = (digest[6] & 0x0F) | 0x50  // version 5
        digest[8] = (digest[8] & 0x3F) | 0x80  // RFC 4122 variant
        return UUID(uuid: (
            digest[0], digest[1], digest[2], digest[3],
            digest[4], digest[5], digest[6], digest[7],
            digest[8], digest[9], digest[10], digest[11],
            digest[12], digest[13], digest[14], digest[15]
        ))
    }
}

/// A companion radio reached over TCP, framed exactly as a serial one.
///
/// This exists because the simulator has no Bluetooth. Bridging a real
/// radio's port to a socket — `socat TCP-LISTEN:9000 /dev/cu.usbmodem…`
/// — puts a real device in front of a simulator build, and because the
/// bytes are the same HDLC-Lite frames a UART carries, the device
/// cannot tell the difference.
///
/// There is nothing to discover: the endpoint the user typed *is* the
/// radio. Attach is the connection opening and detach is it closing,
/// which is the transport binding the spec gives for TCP.
final class TcpRadioConnection: UlcpRadioSession, RadioConnection, UlcpFrameLink, @unchecked
    Sendable {
    /// How long to wait before dialing again after the socket drops.
    /// Short, because the usual cause is the bridge being restarted by
    /// hand while the app is watching.
    private static let retryDelaySeconds: TimeInterval = 2

    private let endpoint: TcpEndpoint
    private let decoder = MobileHdlcDecoder()
    private var connection: NWConnection?
    /// False once the user disconnects, so a deliberate teardown does
    /// not immediately dial again.
    private var wantsConnection = false

    init(endpoint: TcpEndpoint) {
        self.endpoint = endpoint
        super.init(sessionQueue: DispatchQueue(
            label: "com.umsh.radio.tcp",
            qos: .userInitiated
        ))
        adopt(link: self)
        snapshot.localIdentifier = endpoint.identifier
    }

    // ------------------------------------------------------------------
    // Connection lifecycle
    // ------------------------------------------------------------------

    func connect() async throws {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                Self.logger.notice("action: connect to bridged radio")
                startConnecting()
                result.resume()
            }
        }
    }

    func autoConnect() async {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                startConnecting()
                result.resume()
            }
        }
    }

    func reconnect() async {
        await autoConnect()
    }

    func disconnect() async {
        await withCheckedContinuation { result in
            sessionQueue.async { [self] in
                Self.logger.notice("action: user pressed Disconnect")
                wantsConnection = false
                teardown(problem: nil)
                result.resume()
            }
        }
    }

    /// Nothing is persisted for a bridged radio — the endpoint is the
    /// binding, and it lives in Settings — so forgetting is just
    /// disconnecting.
    func forget() async {
        await disconnect()
    }

    // ------------------------------------------------------------------
    // Discovery
    // ------------------------------------------------------------------

    /// One endpoint, one radio. The list is a single entry so the
    /// existing picker works unchanged.
    func discoverRadios() async -> AsyncStream<[DiscoveredRadio]> {
        AsyncStream { continuation in
            continuation.yield([DiscoveredRadio(
                id: endpoint.identifier,
                name: endpoint.text,
                // The sentinel the rest of the app already reads as
                // "no signal to report".
                rssiDBm: 127,
                isRemembered: true
            )])
            continuation.finish()
        }
    }

    func selectRadio(_ id: UUID) async throws {
        guard id == endpoint.identifier else {
            throw RadioConnectionError.radioNotFound
        }
        try await connect()
    }

    func stopDiscovery() async {}

    // ------------------------------------------------------------------
    // UlcpFrameLink
    // ------------------------------------------------------------------

    var linkIsReady: Bool { connection?.state == .ready }

    var linkID: UUID? { endpoint.identifier }

    var linkName: String? { snapshot.name ?? endpoint.text }

    /// The endpoint names exactly one radio, so whatever answers on it
    /// is the radio this connection is bound to.
    var linkIsBoundRadio: Bool { true }

    func linkSend(frame: Data, rawTransactionID: UInt8?) {
        guard let connection, connection.state == .ready else { return }
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
        connection.send(content: wire, completion: .contentProcessed { [weak self] error in
            guard let self, let error else { return }
            // A stream has no per-write recovery worth modeling: if the
            // socket refused a frame, the link is gone. `teardown` fails
            // every outstanding ticket, this frame's included.
            self.sessionQueue.async {
                self.teardown(problem: "The connection to the radio failed: \(error)")
            }
        })
    }

    func linkResetFraming() {
        decoder.reset()
    }

    func linkInvalidate() {
        teardown(problem: nil, preservingPublishedFailure: true)
    }

    /// Nothing to remember: the endpoint is the binding.
    func linkDidAttach() {}

    func linkDidReportName(_ name: String) {}

    func linkAbandonBinding() {
        wantsConnection = false
    }

    // ------------------------------------------------------------------
    // The socket
    // ------------------------------------------------------------------

    private func startConnecting() {
        wantsConnection = true
        guard connection == nil else { return }

        let options = NWProtocolTCP.Options()
        // ULCP frames are small and each one is a turn in a
        // request/response exchange; coalescing only adds latency.
        options.noDelay = true
        let connection = NWConnection(
            host: NWEndpoint.Host(endpoint.host),
            port: NWEndpoint.Port(rawValue: endpoint.port) ?? .any,
            using: NWParameters(tls: nil, tcp: options)
        )
        self.connection = connection
        // Publishes over the standing snapshot rather than a fresh one, so a
        // failure stays on screen through the retry. Clearing it for the dial
        // and re-publishing it on the failure two seconds later made the
        // whole interface pulse with the banner. The message stands until a
        // session update — which only a live connection produces — clears it,
        // or a new failure replaces it.
        snapshot.linkState = .connecting
        snapshot.name = endpoint.text
        snapshot.localIdentifier = endpoint.identifier
        publish(snapshot)

        connection.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                Self.logger.notice("bridged radio connected")
                self.decoder.reset()
                self.receiveNext(on: connection)
                // Connection established is attach, so the ULCP
                // handshake starts here.
                self.linkDidBecomeReady()
            case .failed(let error):
                self.teardown(problem: "The radio bridge is unreachable: \(error)")
            case .cancelled:
                break
            case .waiting(let error):
                // Network.framework parks here and re-dials only when
                // the network path changes — which never happens for a
                // refused connection to the loopback, so it would wait
                // forever. Since the usual cause is a bridge that has
                // not been started yet (or was restarted by hand), take
                // the connection down and dial again ourselves.
                self.teardown(problem: "Waiting for the radio bridge: \(error)")
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
            guard let self, self.connection === connection else { return }
            if let content, !content.isEmpty {
                for frame in self.decoder.push(bytes: content) {
                    self.linkDidReceive(frame: frame)
                }
            }
            if let error {
                self.teardown(problem: "The connection to the radio failed: \(error)")
                return
            }
            // The bridge closing the socket is a detach.
            guard !isComplete else {
                self.teardown(problem: "The radio bridge closed the connection")
                return
            }
            self.receiveNext(on: connection)
        }
    }

    /// Drop the socket and release everything waiting on it, then dial
    /// again if the user has not asked to be disconnected.
    private func teardown(problem: String?, preservingPublishedFailure: Bool = false) {
        let hadConnection = connection != nil
        connection?.stateUpdateHandler = nil
        connection?.cancel()
        connection = nil
        decoder.reset()

        if preservingPublishedFailure {
            // The session has already published why it gave up; an
            // ordinary disconnect notice would overwrite it.
            sessionDidLoseLink()
        } else if hadConnection {
            if wantsConnection {
                // The dial two seconds out is part of the same standing
                // attempt, so this publishes one steady state — connecting,
                // and here is why it has not worked — rather than flapping
                // through disconnected and back on every retry. With the
                // message unchanged the snapshot is unchanged, and the
                // interface holds perfectly still.
                sessionDidLoseLink()
                snapshot.linkState = .connecting
                snapshot.name = endpoint.text
                snapshot.localIdentifier = endpoint.identifier
                if let problem {
                    snapshot.problemDescription = problem
                }
                publish(snapshot)
            } else {
                linkDidClose(problem: problem)
            }
        }

        guard wantsConnection else { return }
        sessionQueue.asyncAfter(deadline: .now() + Self.retryDelaySeconds) { [weak self] in
            guard let self, self.wantsConnection, self.connection == nil else { return }
            self.startConnecting()
        }
    }
}
