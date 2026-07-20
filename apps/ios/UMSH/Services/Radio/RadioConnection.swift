import Foundation
import UMSHMobileCore

protocol RadioConnection: AnyObject, Sendable {
    func snapshots() async -> AsyncStream<RadioSnapshot>
    func receivedFrames() async -> AsyncStream<RadioReceivedFrame>
    func chatUpdates() async -> AsyncStream<RadioChatUpdate>
    func useHostIdentity(_ identity: MeshPublicIdentity?) async throws
    func useMeshSession(_ session: MobileMeshSession?) async
    func autoConnect() async
    func connect() async throws
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
}
