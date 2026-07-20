import Foundation
import XCTest
@testable import UMSHMobileCore

final class UMSHMobileCoreTests: XCTestCase {
    func testReferenceNodeHintRoundTripsThroughRust() throws {
        XCTAssertEqual(mobileApiVersion(), 17)

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
}
