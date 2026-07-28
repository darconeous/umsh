import Foundation

/// The peripherals currently held by administrative sessions.
///
/// The companion connection revokes standing connects by sweeping every
/// peripheral advertising the ULCP service
/// (`cancelAllServiceConnections`). That sweep is right for stray companion
/// connections and fatal for an administrative link, which is deliberately
/// concurrent with the companion and connected to a *different* device.
///
/// This is the only thing the two paths have to agree on, so it is kept as
/// small as it can be: a set of identifiers that are spoken for, and no
/// opinion about what anyone does with them. Registration is the
/// administrative session's responsibility and is released on disconnect —
/// a leaked entry does not break the companion, it only spares one
/// peripheral from a sweep that would have been a no-op anyway.
final class AdminSessionRegistry: @unchecked Sendable {
    static let shared = AdminSessionRegistry()

    private let lock = NSLock()
    private var held: Set<UUID> = []

    /// Claim `identifier` on behalf of an administrative session.
    func register(_ identifier: UUID) {
        lock.lock()
        defer { lock.unlock() }
        held.insert(identifier)
    }

    /// Release `identifier`. Safe to call for one never registered.
    func deregister(_ identifier: UUID) {
        lock.lock()
        defer { lock.unlock() }
        held.remove(identifier)
    }

    /// Whether an administrative session is currently using this peripheral.
    func contains(_ identifier: UUID) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return held.contains(identifier)
    }
}
