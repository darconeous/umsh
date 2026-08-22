import CoreLocation
import Foundation
import SwiftUI
import UMSHMobileCore

/// The region database this app answers "which regions cover here?" from.
///
/// One database, opened once and held for the life of the process: the file
/// is read-only and a worst-case lookup is about a millisecond, so there is
/// nothing to manage past getting it open. Opening is a blocking file read
/// plus an in-memory region table, which is why it happens off the main
/// actor and publishes its result rather than being awaited on the way into
/// a screen.
///
/// Nothing here decides anything geographic. What a position's uncertainty
/// means, which configured regions already match a suggestion, and what each
/// accept mode produces are all answered in Rust, so this app, the CLI and
/// the site cannot drift apart on any of it. This is a way to ask.
@MainActor
@Observable
final class RegionService {
    enum State {
        /// Not opened yet. A reader shows nothing rather than a failure.
        case loading
        case ready(MobileRegionDatabase)
        /// Why there are no answers, in a sentence.
        case unavailable(String)
    }

    private(set) var state: State = .loading

    private var database: MobileRegionDatabase? {
        guard case let .ready(database) = state else { return nil }
        return database
    }

    /// The data release the answers come from, such as `2026.34.1`.
    var datasetVersion: String? { database?.datasetVersion() }
    var formatVersion: UInt32? { database?.formatVersion() }
    var regionCount: UInt32? { database?.regionCount() }
    /// Whether proposals can be made at all, for a control that should not
    /// be offered when they cannot.
    var isReady: Bool { database != nil }

    var unavailableMessage: String? {
        guard case let .unavailable(message) = state else { return nil }
        return message
    }

    /// Open the database, once. Later calls are no-ops, so every screen may
    /// ask without coordinating.
    func load() async {
        guard case .loading = state else { return }
        guard let url = Self.databaseURL() else {
            state = .unavailable("This build carries no region database.")
            return
        }
        let path = url.path
        do {
            state = .ready(
                try await Task.detached(priority: .utility) {
                    try MobileRegionDatabase.open(path: path)
                }.value
            )
        } catch {
            state = .unavailable(Self.text(for: error))
        }
    }

    /// Where the database is.
    ///
    /// One method because it will grow a second candidate: the update path
    /// is deferred until the site publishes a manifest, and when it lands a
    /// downloaded copy is compared against this one here rather than at
    /// every call site.
    private static func databaseURL() -> URL? {
        Bundle.main.url(forResource: "world", withExtension: "regiondb")
    }

    /// Every region covering one exact position.
    func lookup(latitude: Double, longitude: Double) async throws -> MobileRegionLookupRecord {
        let database = try requireDatabase()
        return try await Task.detached(priority: .userInitiated) {
            try database.lookup(latitude: latitude, longitude: longitude)
        }.value
    }

    /// Propose a region configuration for a position, against what the
    /// device currently holds.
    ///
    /// Five lookups at worst, so a few milliseconds — well inside an
    /// interaction budget even hopped off the main actor.
    func propose(
        position: MobileRegionPositionRecord,
        currentRegions: [String],
        currentDefaultRegion: Data?
    ) async throws -> MobileRegionProposalRecord {
        let database = try requireDatabase()
        return try await Task.detached(priority: .userInitiated) {
            try database.propose(
                position: position,
                currentRegions: currentRegions,
                currentDefaultRegion: currentDefaultRegion
            )
        }.value
    }

    private func requireDatabase() throws -> MobileRegionDatabase {
        guard let database else { throw MobileRegionError.DatabaseUnavailable }
        return database
    }

    /// What went wrong, in a sentence an operator can act on.
    ///
    /// The Rust side names each of these with a `summary_key` rather than
    /// prose, so this is the catalog those keys point at — one entry per
    /// case, and nothing from Rust is ever shown directly.
    static func text(for error: any Error) -> String {
        switch error as? MobileRegionError {
        case .NotARegionDatabase:
            "The bundled region file is not a region database."
        case .UnsupportedFormat:
            """
            The region database was built for a newer version of this app. \
            Update UMSH to use it.
            """
        case .MissingSpatialIndex:
            """
            This build cannot search the region database — its copy of SQLite \
            has no spatial index.
            """
        case .Corrupt:
            "The region database opened but could not be read."
        case .InvalidPosition:
            "That is not a position this app can look anything up for."
        case .PositionTooCoarse:
            """
            That position covers too much ground to suggest regions from. \
            Choose a more precise source.
            """
        case .InvalidRegionCode:
            "One of the regions already configured could not be read as a region."
        // `DatabaseUnavailable` and anything unrecognized are the same
        // thing to a reader: the database is not answering.
        case .DatabaseUnavailable, nil:
            "The region database could not be opened."
        }
    }
}

extension EnvironmentValues {
    /// The opened region database, for any screen that proposes regions.
    /// Nil in previews and in any tree that never registered one, where the
    /// suggestion controls are simply not offered.
    @Entry var regionService: RegionService? = nil
    /// One reading of where this phone is, for a screen looking regions up.
    /// Nil where there is no location seam to ask, which is the same
    /// non-offer as above.
    @Entry var readPhonePosition: (@MainActor () async -> CLLocation?)? = nil
}
