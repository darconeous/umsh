import Foundation
import UMSHMobileCore

enum FrameCounterStoreError: Error, Equatable, Sendable {
    case applicationSupportUnavailable
    case invalidIdentity
    case corruptState
    case persistenceFailure
}

/// Identity-scoped durable boundaries for the Rust MAC reservation-block
/// algorithm. A caller must not release authenticated frames until
/// `commitBoundary` returns successfully.
actor FrameCounterReservationStore {
    private let core: MobileCounterStore

    init(fileManager: FileManager = .default) throws {
        guard let applicationSupport = fileManager.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            throw FrameCounterStoreError.applicationSupportUnavailable
        }
        let root = applicationSupport
            .appendingPathComponent("UMSH", isDirectory: true)
            .appendingPathComponent("CounterReservations", isDirectory: true)
        do {
            core = try MobileCounterStore(rootDirectory: root.path)
        } catch {
            throw FrameCounterStoreError.persistenceFailure
        }
    }

    func loadBoundary(for identity: LocalIdentitySnapshot) throws -> UInt32 {
        do {
            return try core.loadBoundary(context: context(for: identity))
        } catch CounterStoreError.InvalidContext {
            throw FrameCounterStoreError.invalidIdentity
        } catch CounterStoreError.CorruptRecord {
            throw FrameCounterStoreError.corruptState
        } catch {
            throw FrameCounterStoreError.persistenceFailure
        }
    }

    func commitBoundary(_ boundary: UInt32, for identity: LocalIdentitySnapshot) throws {
        do {
            try core.commitBoundary(context: context(for: identity), boundary: boundary)
        } catch CounterStoreError.InvalidContext {
            throw FrameCounterStoreError.invalidIdentity
        } catch CounterStoreError.CorruptRecord {
            throw FrameCounterStoreError.corruptState
        } catch {
            throw FrameCounterStoreError.persistenceFailure
        }
    }

    private func context(for identity: LocalIdentitySnapshot) -> Data {
        Data(identity.id.utf8)
    }
}
