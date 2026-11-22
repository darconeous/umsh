import Foundation
import UMSHMobileCore

/// A connection with no radio behind it: for the test host, previews, and a
/// staged radio whose air would not start.
///
/// It lists no radios and has no driver to hand the app core, and every
/// command it is given fails as a radio that is not there. It fabricates
/// nothing.
final class NoRadioConnection: RadioConnection, Sendable {
    var radioDriver: MobileRadioDriver? { nil }

    func autoConnect() async {}
    func reconnect() async {}
    func connect() async throws { throw RadioConnectionError.radioNotFound }

    func discoverRadios() async -> AsyncStream<[DiscoveredRadio]> {
        AsyncStream { continuation in
            continuation.yield([])
            continuation.finish()
        }
    }

    func selectRadio(_ id: UUID) async throws { throw RadioConnectionError.radioNotFound }
    func stopDiscovery() async {}
    func claimForCurrentIdentity() async throws { throw RadioConnectionError.radioNotFound }
    func factoryReset() async throws { throw RadioConnectionError.radioNotFound }
    func reboot() async throws { throw RadioConnectionError.radioNotFound }
    func refresh() async throws -> RadioSnapshot { throw RadioConnectionError.radioNotFound }
    func refreshPositioning() async throws -> RadioSnapshot {
        throw RadioConnectionError.radioNotFound
    }
    func disconnect() async {}
    func forget() async {}
}
