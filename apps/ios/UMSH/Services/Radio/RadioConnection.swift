import Foundation

@MainActor
protocol RadioConnection: AnyObject {
    func snapshots() -> AsyncStream<RadioSnapshot>
    func useHostIdentity(_ identity: MeshPublicIdentity?) async
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
