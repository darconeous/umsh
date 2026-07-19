import Foundation

protocol RadioConnection: AnyObject, Sendable {
    func snapshots() async -> AsyncStream<RadioSnapshot>
    func receivedFrames() async -> AsyncStream<RadioReceivedFrame>
    func useHostIdentity(_ identity: MeshPublicIdentity?) async throws
    func autoConnect() async
    func connect() async throws
    func claimForCurrentIdentity() async throws
    func disconnect() async
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
}
