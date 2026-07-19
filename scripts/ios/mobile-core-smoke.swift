import Foundation

@main
struct MobileCoreSmokeTest {
    static func main() throws {
        precondition(mobileApiVersion() == 9)

        let hint = try renderNodeHint(bytes: Data([0xA1, 0xB2, 0x03]))
        precondition(hint.bytes == Data([0xA1, 0xB2, 0x03]))
        precondition(hint.text == "BtC5")

        let identity = try MobileIdentity.unlock(
            secretKey: Data(repeating: 7, count: 32)
        ).publicIdentity()
        precondition(identity.canonicalAddress.count == 44)
        let inspectedIdentity = try inspectPublicIdentity(address: identity.canonicalAddress)
        precondition(inspectedIdentity == identity)
        let rawIdentity = try inspectPublicIdentityBytes(
            publicKey: Data((0..<32).map(UInt8.init))
        )
        precondition(rawIdentity.canonicalAddress.count == 44)
        let decodedIdentity = try publicIdentityBytes(address: rawIdentity.canonicalAddress)
        precondition(decodedIdentity == Data((0..<32).map(UInt8.init)))
        let nodePreview = try inspectNodeUri(uri: "umsh:n:\(rawIdentity.canonicalAddress)")
        precondition(nodePreview.canonicalAddress == rawIdentity.canonicalAddress)
        precondition(!nodePreview.hasIdentityData)

        let propertyGet = try companionPropGet(transactionId: 3, propertyId: 4_864)
        let propertySet = try companionPropSet(
            transactionId: 6,
            propertyId: 96,
            value: Data(repeating: 7, count: 32)
        )
        precondition(propertySet.count > 32)
        let segments = try companionGattSegments(frame: propertyGet, maximumValueLength: 4)
        precondition(segments.count > 1)
        let reassembler = MobileGattReassembler()
        var reassembled: Data?
        for segment in segments {
            if let frame = try reassembler.push(segment: segment.value) {
                reassembled = frame
            }
        }
        precondition(reassembled == propertyGet)

        let battery = try inspectCompanionBattery(value: Data([0b110, 82, 1]))
        precondition(battery.percentage == 82)
        precondition(battery.isExternallyPowered == true)

        let inspectionProperties = try companionInspectionProperties(
            capabilities: Data([8])
        )
        precondition(inspectionProperties == [3, 32, 35])
        let frequency = withUnsafeBytes(of: UInt32(915_000).littleEndian) { Data($0) }
        let sync = try inspectCompanionSync(responses: [
            CompanionPropertyFrameRecord(
                transactionId: 1,
                command: 6,
                propertyId: 5,
                value: Data([8])
            ),
            CompanionPropertyFrameRecord(
                transactionId: 2,
                command: 6,
                propertyId: 3,
                value: Data([8])
            ),
            CompanionPropertyFrameRecord(
                transactionId: 3,
                command: 6,
                propertyId: 32,
                value: Data([1])
            ),
            CompanionPropertyFrameRecord(
                transactionId: 4,
                command: 6,
                propertyId: 35,
                value: frequency
            ),
        ])
        precondition(sync.phyEnabled)
        precondition(sync.frequencyKhz == 915_000)
        precondition(sync.queuedFrames == nil)

        let counterRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("umsh-mobile-counter-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: counterRoot) }
        let counters = try MobileCounterStore(rootDirectory: counterRoot.path)
        let context = Data("primary".utf8)
        let initialBoundary = try counters.loadBoundary(context: context)
        precondition(initialBoundary == 0)
        try counters.commitBoundary(context: context, boundary: 128)
        let committedBoundary = try counters.loadBoundary(context: context)
        precondition(committedBoundary == 128)
        let reopenedCounters = try MobileCounterStore(rootDirectory: counterRoot.path)
        let reopenedBoundary = try reopenedCounters.loadBoundary(context: context)
        precondition(reopenedBoundary == 128)

        do {
            _ = try inspectPublicIdentity(address: "not-an-address")
            preconditionFailure("Invalid address unexpectedly succeeded")
        } catch MobileError.InvalidAddressLength {
            // Expected structured Rust error.
        }

        print("Swift successfully called umsh-mobile-core")
    }
}
