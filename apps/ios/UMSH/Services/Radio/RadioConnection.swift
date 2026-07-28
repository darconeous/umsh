import Foundation
import UMSHMobileCore

protocol RadioConnection: AnyObject, Sendable {
    func snapshots() async -> AsyncStream<RadioSnapshot>
    func receivedFrames() async -> AsyncStream<RadioReceivedFrame>
    func chatUpdates() async -> AsyncStream<RadioChatUpdate>
    func advertisementEvents() async -> AsyncStream<RadioAdvertisementEvent>
    func advertiseIdentity(name: String?) async throws
    func signIdentityBundle(name: String?) async throws -> Data
    func useHostIdentity(_ identity: MeshPublicIdentity?) async throws
    func useMeshSession(_ session: MobileMeshSession?) async
    func autoConnect() async
    func reconnect() async
    func connect() async throws
    /// Begin an explicit discovery scan and stream the live list of nearby
    /// companion radios. The scan runs until `stopDiscovery()` or `selectRadio`
    /// is called; it never auto-connects. Each element is the full current
    /// list, sorted for display.
    func discoverRadios() async -> AsyncStream<[DiscoveredRadio]>
    /// Attach to a specific radio surfaced by `discoverRadios()`. Ends
    /// discovery and drives the normal connect/attach path.
    func selectRadio(_ id: UUID) async throws
    /// Cancel an in-progress discovery scan without connecting.
    func stopDiscovery() async
    func claimForCurrentIdentity() async throws
    /// Erase ALL mutable state on the radio (saved provisioning, device
    /// identity, BLE bonds, pairing PIN) and reboot it to a blank factory
    /// state. Requires a live connection; the radio drops the link on reset.
    /// The app also abandons its binding to the radio.
    func factoryReset() async throws
    func refresh() async throws -> RadioSnapshot
    func configure(_ settings: RadioSettings) async throws
    func ping(peerAddress: String) async throws -> RadioPingResult
    /// Solicit a peer's current node identity by sending a targeted MAC
    /// Identity Request. Resolves once the request is handed to the radio;
    /// the peer's response arrives asynchronously on `advertisementEvents()`.
    func requestIdentity(peerAddress: String) async throws
    /// The route the phone's MAC will use for the next frame to this peer.
    /// Read-only: inspecting a peer never registers it.
    func peerRoute(peerAddress: String) async throws -> RadioPeerRoute
    /// Discard this peer's learned route, returning whether one was held.
    /// Keys and counters are untouched.
    func clearPeerRoute(peerAddress: String) async throws -> Bool
    func prepareChat(
        peerAddresses: [String],
        checkpoints: [MobileChatCheckpointRecord]
    ) async throws
    func registerChatPeers(_ peerAddresses: [String]) async throws
    func composeText(
        peerAddress: String,
        clientToken: UInt32,
        body: String
    ) async throws -> MobileChatComposeBatchRecord
    func composeEdit(
        peerAddress: String,
        clientToken: UInt32,
        original: MobileChatOriginalRef,
        body: String
    ) async throws -> MobileChatComposeBatchRecord
    func composeDelete(
        peerAddress: String,
        clientToken: UInt32,
        original: MobileChatOriginalRef
    ) async throws -> MobileChatComposeBatchRecord
    func commitChatBatch(_ batchID: UInt64) async throws
    func rejectChatBatch(
        _ batchID: UInt64,
        checkpoints: [MobileChatCheckpointRecord]
    ) async throws
    func applyChatArchiveResult(
        requestID: UInt32,
        kind: MobileChatArchiveResultKind,
        payload: Data
    ) async throws
    func acknowledgeChatBatch(_ batchID: UInt64) async throws
    func disconnect() async
    /// Unbind from the remembered radio entirely: revoke any standing connect
    /// and clear the persisted `connectedUUID`. The app stops offering
    /// Reconnect and will not auto-connect on launch until a radio is chosen
    /// again via `selectRadio`.
    func forget() async
}

/// A node-identity advertisement received over the mesh. The payload is the
/// raw bundle; consumers verify its signature before trusting any claim.
struct RadioAdvertisementEvent: Equatable, Sendable {
    let peerAddress: String
    let payload: Data
    /// Whether the MAC authenticated the sender of the frame that carried
    /// this bundle.
    ///
    /// An Identity Request reply arrives as a unicast authenticated by its
    /// MIC, so it carries no detached signature; a broadcast advertisement
    /// has no MIC and must carry one. See `isTrustworthy(given:)`.
    let sourceAuthenticated: Bool

    /// Whether these claims may be attributed to the peer.
    ///
    /// A bundle is trustworthy when *something* authenticated it: either its
    /// embedded signature verifies against the claimed key, or the MAC
    /// authenticated the frame that delivered it. A broadcast advertisement
    /// has no MIC, so it must be signed — anything else could be spoofed by
    /// any nearby transmitter. An Identity Request reply is a unicast
    /// authenticated by its MIC and deliberately carries no signature, so it
    /// is trusted without one.
    ///
    /// A signature that is present and fails to verify is never trusted,
    /// however the bundle arrived.
    func isTrustworthy(given signature: MeshIdentitySignatureState) -> Bool {
        switch signature {
        case .valid: true
        case .unsigned: sourceAuthenticated
        case .invalid: false
        }
    }
}

struct RadioChatUpdate: Sendable {
    let batchID: UInt64
    let mutations: [MobileChatMutationRecord]
    let deliveries: [MobileChatDeliveryRecord]
    let archiveLookups: [MobileChatArchiveLookupRecord]
    let diagnostics: [String]
}

struct RadioPingReply: Equatable, Sendable {
    let roundTripMilliseconds: UInt64
    let hopCount: UInt8?
    let routeHints: [Data]
    let rssiDBm: Int16?
    let signalToNoiseCentibels: Int16?
    let linkQuality: UInt8?
}

enum RadioPingResult: Equatable, Sendable {
    case reply(RadioPingReply)
    case timedOut
}

/// The route the phone's MAC currently holds for one peer, as raw wire values.
struct RadioPeerRoute: Equatable, Sendable {
    let kind: MobileMeshRouteKind
    /// Routers named by a source route, in send order.
    let hints: [Data]
    let floodHops: UInt8?
    /// Two-octet region codes learned with a flood route.
    let floodRegions: [Data]

    static let unknown = RadioPeerRoute(kind: .unknown, hints: [], floodHops: nil, floodRegions: [])

    init(kind: MobileMeshRouteKind, hints: [Data], floodHops: UInt8?, floodRegions: [Data]) {
        self.kind = kind
        self.hints = hints
        self.floodHops = floodHops
        self.floodRegions = floodRegions
    }

    init(_ record: MobileMeshRouteRecord) {
        self.init(
            kind: record.kind,
            hints: record.hints,
            floodHops: record.floodHops,
            floodRegions: record.floodRegions
        )
    }
}

struct RadioReceivedFrame: Equatable, Sendable {
    let data: Data
    let rssiDBm: Int?
    let linkQuality: UInt8?
    let signalToNoiseCentibels: Int?
    let wasBuffered: Bool
    let wasAcknowledgedByRadio: Bool
    let ageSeconds: UInt32
}

enum RadioConnectionError: Error, Equatable, Sendable {
    case bluetoothUnavailable
    case radioNotFound
    case incompatibleProtocol
    /// The device refused an encrypted characteristic because it and this
    /// phone have no usable pairing. Distinct from `incompatibleProtocol`:
    /// the device is fine, the pairing is missing.
    case pairingRequired
    case identityUnavailable
    case takeoverNotAllowed
    case operationInProgress
    case operationRejected(String)
}
