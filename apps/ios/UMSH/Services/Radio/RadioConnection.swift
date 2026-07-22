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
    func refresh() async throws -> RadioSnapshot
    func configure(_ settings: RadioSettings) async throws
    func ping(peerAddress: String) async throws -> RadioPingResult
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
    case companionNotFound
    case incompatibleProtocol
    case identityUnavailable
    case takeoverNotAllowed
    case operationInProgress
    case operationRejected(String)
}
