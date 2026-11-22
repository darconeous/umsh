#if DEBUG
import Foundation
import UMSHMobileCore

/// The staged radio: a radio driver over the core's staging air.
///
/// The air runs a soft device for the radio and a real mesh session for
/// every staged node, so the phone attaches, chats, pings, and manages a
/// remote device through the same code it uses over RF. The air owns the
/// radio's link and reports its transport states itself; this class
/// connects it, lists it, and carries the staging controls. Another
/// identity taking the radio starts the staged mesh over by itself.
final class StagingRadioConnection: RadioDriverAdapter, RadioConnection, @unchecked Sendable {
    private let air: MobileStagingAir

    /// The air's link identifier, which the snapshot reports as the radio's.
    private let identifier: UUID

    private let displayName: String

    /// The staged devices beside the phone, for device setup.
    let administeredDevices: StagedAdministeredDevices

    init(stateDirectory: URL, wifiScanOnly: Bool) throws {
        try FileManager.default.createDirectory(
            at: stateDirectory,
            withIntermediateDirectories: true
        )
        air = try MobileStagingAir.start(
            stateDir: stateDirectory.path,
            wifiScanOnly: wifiScanOnly
        )
        // The core's own constant, so a malformed one is a build mistake.
        identifier = UUID(uuidString: air.radioLinkId())!
        displayName = air.radioName()
        administeredDevices = StagedAdministeredDevices(air: air)
        super.init(
            sessionQueue: DispatchQueue(label: "com.voria.umsh.radio.staging", qos: .userInitiated),
            driver: air.radio()
        )
    }

    deinit {
        air.stop()
    }

    /// Where the staged nodes keep their frame counters, which must
    /// survive relaunches for replay protection to hold between them and
    /// the phone.
    static var stateDirectory: URL {
        URL.applicationSupportDirectory
            .appending(path: "UMSH", directoryHint: .isDirectory)
            .appending(path: "StagingAir", directoryHint: .isDirectory)
    }

    // ------------------------------------------------------------------
    // Connection lifecycle
    // ------------------------------------------------------------------

    func connect() async throws {
        Self.logger.notice("action: connect to the staged radio")
        air.connect()
    }

    func autoConnect() async {
        air.connect()
    }

    func reconnect() async {
        air.connect()
    }

    func disconnect() async {
        await releaseHost()
        Self.logger.notice("action: user pressed Disconnect")
        air.disconnect()
    }

    /// The staged radio's state is the air's, and stays; forgetting it is
    /// disconnecting.
    func forget() async {
        await disconnect()
    }

    // ------------------------------------------------------------------
    // Discovery
    // ------------------------------------------------------------------

    /// One staged radio, so the picker works unchanged.
    func discoverRadios() async -> AsyncStream<[DiscoveredRadio]> {
        AsyncStream { continuation in
            continuation.yield([DiscoveredRadio(
                id: identifier,
                name: displayName,
                // The sentinel the rest of the app reads as "no signal to
                // report".
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
    // Staging controls
    // ------------------------------------------------------------------

    /// A staged peer says `body` to the phone, or with `onChannel` to the
    /// staged named channel.
    func stagedPeerSendsMessage(body: String, onChannel: Bool) async {
        await control { try await $0.peerSays(body: body, onChannel: onChannel) }
    }

    /// A staged peer says three things on the staged channel, the second
    /// lost on the air.
    func stagedPeerLosesChannelMessage(bodies: (String, String, String)) async {
        await control {
            try await $0.peerSaysLosingOne(first: bodies.0, lost: bodies.1, last: bodies.2)
        }
    }

    /// A staged peer reacts to the phone's last message to it.
    func stagedPeerReacts(body: String) async {
        await control { try await $0.peerReacts(body: body) }
    }

    /// A staged peer replies to the phone's last message to it.
    func stagedPeerReplies(body: String) async {
        await control { try await $0.peerReplies(body: body) }
    }

    /// A staged peer opens Add Peer, and with `asking`, asks the phone to
    /// exchange once it lists it.
    func stagedPeerMeets(asking: Bool) async {
        await control { try await $0.peerOpensAddPeer(asking: asking) }
    }

    /// Fail every transmission the staged radio makes, as a dead link would.
    func setTransmissionsFailing(_ failing: Bool) {
        air.setTransmissionsFailing(failing: failing)
    }

    /// Take the managed remote device off the air, or put it back.
    func setRemoteDeviceReachable(_ reachable: Bool) {
        air.setRemoteDeviceReachable(reachable: reachable)
    }

    private func control(_ body: (MobileStagingAir) async throws -> Void) async {
        do {
            try await body(air)
        } catch {
            Self.logger.warning(
                "staging control failed: \(String(describing: error), privacy: .public)"
            )
        }
    }
}

/// The staged devices beside the phone: one that forwards and one that
/// does not. Device setup lists them with the devices it finds over
/// Bluetooth and attaches to them through the staging air instead.
struct StagedAdministeredDevices: Sendable {
    private let air: MobileStagingAir
    /// The link identifier each row's id stands for.
    private let linkIds: [UUID: String]

    /// One row for each, in the core's order.
    let radios: [DiscoveredRadio]

    init(air: MobileStagingAir) {
        self.air = air
        let devices = air.administeredDevices()
        radios = devices.map { device in
            DiscoveredRadio(
                // The core's own constant, so a malformed one is a build
                // mistake.
                id: UUID(uuidString: device.linkId)!,
                name: device.name,
                // No signal to report.
                rssiDBm: 127,
                isRemembered: false
            )
        }
        linkIds = Dictionary(uniqueKeysWithValues: devices.map {
            (UUID(uuidString: $0.linkId)!, $0.linkId)
        })
    }

    func offers(_ id: UUID) -> Bool {
        linkIds[id] != nil
    }

    /// A driver for a fresh copy of the device `id` names, holding
    /// `hostKey` and attaching as it returns.
    func driver(for id: UUID, hostKey: Data?, lazyInspection: Bool) throws -> MobileRadioDriver {
        guard let linkId = linkIds[id] else {
            throw RadioConnectionError.radioNotFound
        }
        return try air.administeredDevice(
            linkId: linkId,
            hostKey: hostKey,
            lazyInspection: lazyInspection
        )
    }
}
#endif
