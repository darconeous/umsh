import Foundation

protocol RadioConnection: AnyObject, Sendable {
    func snapshots() async -> AsyncStream<RadioSnapshot>
    func useHostIdentity(_ identity: MeshPublicIdentity?) async throws
    func autoConnect() async
    func connect() async throws
    func claimForCurrentIdentity() async throws
    func disconnect() async
}

enum RadioConnectionError: Error, Equatable, Sendable {
    case bluetoothUnavailable
    case companionNotFound
    case incompatibleProtocol
    case identityUnavailable
    case takeoverNotAllowed
}
