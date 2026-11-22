import Foundation
import OSLog
import UIKit
import UMSHMobileCore

/// Opens the stores and makes the app core over them, one core at a time.
///
/// One per process. The core and the Swift store share one connection to
/// the database, so a store is opened once per kind and kept; the core is
/// made over whichever store the current radio mode reads.
@MainActor
final class AppCoreHost {
    private static let logger = Logger(subsystem: "com.voria.umsh.ios", category: "AppRoot")

    enum StoreKind: Hashable {
        case live
        #if DEBUG
        /// Fabricated content, in a database of its own.
        case staging
        #endif
    }

    /// A core over the store it reads, with the channel-key vault it was
    /// made with.
    struct Opened {
        let store: SQLiteApplicationStore
        let core: MobileAppCore
        let vault: any SecretVault
    }

    /// The one channel-key vault: its legacy-move flag is per instance, so
    /// every core and runtime shares this one.
    let channelKeyVault = KeychainChannelKeyVault()

    private var stores: [StoreKind: SQLiteApplicationStore] = [:]
    private var current: (kind: StoreKind, opened: Opened)?

    /// The first core, at launch, before any other is open.
    func openFirst(_ kind: StoreKind) -> Result<Opened, any Error> {
        precondition(current == nil, "a core is already open")
        return make(kind)
    }

    /// The core over `kind`'s store, made on first use. Moving to another
    /// store first waits for the core over the last one to stop, so two
    /// cores never hold the radio at once. Callers serialize their switches.
    /// Fails when the store will not open.
    func open(_ kind: StoreKind) async -> Result<Opened, any Error> {
        if let current, current.kind == kind { return .success(current.opened) }
        if let previous = current {
            current = nil
            await previous.opened.core.stop()
        }
        return make(kind)
    }

    /// Hand the open core `connection`'s driver, so the core holds that
    /// radio and no other. A connection with no radio leaves it holding
    /// none.
    func useRadio(_ connection: any RadioConnection) async {
        guard let core = current?.opened.core else { return }
        do {
            try await core.useRadio(driver: connection.radioDriver)
        } catch {
            Self.logger.error("The core did not take the radio: \(String(describing: error), privacy: .public)")
        }
    }

    private func make(_ kind: StoreKind) -> Result<Opened, any Error> {
        do {
            let store = try store(kind)
            let core = try MobileAppCore(
                store: store.coreStore,
                vault: channelKeyVault,
                config: MobileAppConfigRecord(
                    counterDirectory: try Self.counterDirectory(kind).path,
                    platformModel: Self.platformModel
                )
            )
            let opened = Opened(store: store, core: core, vault: channelKeyVault)
            current = (kind, opened)
            return .success(opened)
        } catch {
            Self.logger.error(
                "Could not open the application store: \(String(describing: error), privacy: .public)"
            )
            return .failure(error)
        }
    }

    private func store(_ kind: StoreKind) throws -> SQLiteApplicationStore {
        if let store = stores[kind] { return store }
        let store: SQLiteApplicationStore
        switch kind {
        case .live:
            store = try SQLiteApplicationStore.applicationStore()
        #if DEBUG
        case .staging:
            store = try SQLiteApplicationStore.stagingStore()
        #endif
        }
        stores[kind] = store
        return store
    }

    /// Where a core keeps its message counters. The live directory is the
    /// one the phone has always used: any other restarts this identity's
    /// counters, and peers drop its frames as replays.
    private static func counterDirectory(_ kind: StoreKind) throws -> URL {
        guard let applicationSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            throw ApplicationStoreError.applicationSupportUnavailable
        }
        let name = switch kind {
        case .live: "CounterReservations"
        #if DEBUG
        case .staging: "StagingCounterReservations"
        #endif
        }
        return applicationSupport
            .appendingPathComponent("UMSH", isDirectory: true)
            .appendingPathComponent(name, isDirectory: true)
    }

    #if DEBUG
    /// The staging store is in use by the open core.
    struct StagingStoreInUse: Error {}

    /// Throw away the staged set, by emptying the staging database. Refused
    /// while the staging core is open: the caller switches away from staging
    /// first, so the stopped core is not writing as it empties.
    ///
    /// Content and not the file: the store stays open here, shared with the
    /// next staging core, and SQLite treats a file unlinked under an open
    /// connection as a corrupted database rather than a missing one.
    func eraseStagedContent() async throws {
        guard current?.kind != .staging else { throw StagingStoreInUse() }
        try await store(.staging).eraseAllContent()
    }

    /// Remove the counter directory of the store kind not in use. The
    /// identity is shared between the two, so erasing it in either erases
    /// both: the core removes its own directory, and this the other's.
    static func removeOtherCounterDirectory(inUse kind: StoreKind) {
        let other: StoreKind = kind == .live ? .staging : .live
        guard let directory = try? counterDirectory(other) else { return }
        try? FileManager.default.removeItem(at: directory)
    }
    #endif

    /// This device's platform id (`platforms.json`), which its Hellos carry.
    static var platformModel: UInt16 {
        UIDevice.current.userInterfaceIdiom == .pad ? 0xFE01 : 0xFE00
    }

    /// A core that is never started and never given a radio, over `store`,
    /// with counters in a directory of its own: for the test host, tests and
    /// previews, which read through it and nothing more.
    static func radioLess(
        over store: SQLiteApplicationStore,
        vault: any SecretVault = KeychainChannelKeyVault()
    ) throws -> Opened {
        let counters = FileManager.default.temporaryDirectory
            .appendingPathComponent("counters-\(UUID().uuidString)", isDirectory: true)
        let core = try MobileAppCore(
            store: store.coreStore,
            vault: vault,
            config: MobileAppConfigRecord(counterDirectory: counters.path, platformModel: platformModel)
        )
        return Opened(store: store, core: core, vault: vault)
    }
}
