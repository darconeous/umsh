import Foundation
import SQLite3
import XCTest
@testable import UMSHMobileCore

final class UMSHMobileCoreTests: XCTestCase {
    func testReferenceNodeHintRoundTripsThroughRust() throws {
        let hint = try renderNodeHint(bytes: Data([0xA1, 0xB2, 0x03]))
        XCTAssertEqual(hint.bytes, Data([0xA1, 0xB2, 0x03]))
        XCTAssertEqual(hint.text, "BtC5")
    }

    func testStructuredRustErrorBecomesSwiftError() {
        XCTAssertThrowsError(try inspectPublicIdentity(address: "not-an-address")) { error in
            guard case MobileError.InvalidAddressLength = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }

    func testSecretDerivationReturnsPublicMaterial() throws {
        let identity = try MobileIdentity.unlock(
            secretKey: Data(repeating: 7, count: 32)
        ).publicIdentity()
        XCTAssertEqual(identity.canonicalAddress.count, 44)
        XCTAssertEqual(try inspectPublicIdentity(address: identity.canonicalAddress), identity)
    }

    func testRadioPresetsSurfaceTheVettedTable() throws {
        let presets = ulcpRadioPresets()
        XCTAssertEqual(presets.count, 22)
        XCTAssertEqual(Set(presets.map(\.id)).count, presets.count)

        let usCanada = try XCTUnwrap(presets.first)
        XCTAssertEqual(usCanada.id, "umsh-us-ca")
        XCTAssertEqual(usCanada.frequencyKhz, 917_500)
        XCTAssertEqual(usCanada.bandwidthHz, 500_000)
        XCTAssertEqual(usCanada.spreadingFactor, 10)
        XCTAssertEqual(usCanada.codingRateDenom, 5)
        XCTAssertEqual(usCanada.transmitPowerDbm, 30)
        XCTAssertEqual(usCanada.dutyCycleLimit, UInt16.max)

        XCTAssertEqual(ulcpSupportedBandwidthsHz().count, 10)
        XCTAssertTrue(ulcpSupportedBandwidthsHz().contains(usCanada.bandwidthHz))
    }

    private func fixtureDatabase() throws -> MobileRegionDatabase {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "fixture", withExtension: "regiondb")
        )
        return try MobileRegionDatabase.open(path: url.path)
    }

    // San Carlos, the regression the fixture exists for: a real IATA
    // location that must never be reported as a commercial airport. The
    // expectations mirror regions/tests/known-points.yaml, proving the
    // iOS lookup path agrees with the Rust and Python references.
    func testRegionLookupMatchesTheFixtureReference() throws {
        let db = try fixtureDatabase()
        XCTAssertEqual(db.datasetVersion(), "fixture-1")
        let lookup = try db.lookup(latitude: 37.5119, longitude: -122.2495)
        let keys = lookup.matches.map(\.regionKey)
        XCTAssertTrue(keys.contains("iata-location:SQL"))
        XCTAssertTrue(keys.contains("iata-airport:SFO"))
        XCTAssertFalse(keys.contains("iata-airport:SQL"))
        XCTAssertEqual(lookup.suggestedDefaultRegion?.name, "XSF")
    }

    func testRegionProposalComparesByDerivedCode() throws {
        // "sfo" and the hex spelling of XSF already name two of the
        // suggestions, however they are written; add-missing keeps the
        // operator's spellings and appends only what is absent.
        let proposal = try fixtureDatabase().propose(
            position: MobileRegionPositionRecord(
                latitude: 37.6189,
                longitude: -122.3750,
                locationBytes: nil,
                accuracyM: nil
            ),
            currentRegions: ["sfo", "0x98FE"],
            currentDefaultRegion: nil
        )
        XCTAssertEqual(proposal.alreadyPresent, ["SFO", "XSF"])
        XCTAssertEqual(Array(proposal.addMissing.regions.prefix(2)), ["sfo", "0x98FE"])
        XCTAssertTrue(proposal.addMissing.regions.contains("US"))
        XCTAssertEqual(proposal.addMissing.defaultRegion, Data([0x98, 0xFE]))
        XCTAssertTrue(proposal.addMissing.changesAnything)
    }

    /// The shipped world database has no lookup cache, so every lookup on
    /// a real build goes through SQLite's R-tree — a module Apple's SQLite
    /// is not contractually required to carry, and whose absence surfaces
    /// only as a failed lookup. The fixture *does* have a cache, so a test
    /// against it as-built proves nothing about that path; this one empties
    /// the cache to take it.
    func testLookupsWorkWithoutTheCache() throws {
        let source = try XCTUnwrap(
            Bundle.module.url(forResource: "fixture", withExtension: "regiondb")
        )
        let uncached = FileManager.default.temporaryDirectory
            .appendingPathComponent("uncached-\(UUID().uuidString).regiondb")
        try FileManager.default.copyItem(at: source, to: uncached)
        defer { try? FileManager.default.removeItem(at: uncached) }

        var handle: OpaquePointer?
        XCTAssertEqual(sqlite3_open(uncached.path, &handle), SQLITE_OK)
        defer { sqlite3_close(handle) }
        XCTAssertEqual(
            sqlite3_exec(handle, "DELETE FROM lookup_ranges", nil, nil, nil),
            SQLITE_OK
        )
        sqlite3_close(handle)
        handle = nil

        let db = try MobileRegionDatabase.open(path: uncached.path)
        let lookup = try db.lookup(latitude: 37.5119, longitude: -122.2495)
        XCTAssertTrue(lookup.matches.map(\.regionKey).contains("iata-location:SQL"))
    }

    func testCoarsePositionsAreRefused() throws {
        XCTAssertThrowsError(
            try fixtureDatabase().propose(
                position: MobileRegionPositionRecord(
                    latitude: 37.5119,
                    longitude: -122.2495,
                    locationBytes: nil,
                    accuracyM: 30_000
                ),
                currentRegions: [],
                currentDefaultRegion: nil
            )
        ) { error in
            guard case MobileRegionError.PositionTooCoarse = error else {
                return XCTFail("Unexpected error: \(error)")
            }
        }
    }
}
