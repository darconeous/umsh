import Foundation

@main
struct MobileCoreSmokeTest {
    static func main() throws {
        precondition(mobileApiVersion() == 37)
        precondition(ulcpMaxDevPeers() == 8)

        let hint = try renderNodeHint(bytes: Data([0xA1, 0xB2, 0x03]))
        precondition(hint.bytes == Data([0xA1, 0xB2, 0x03]))
        precondition(hint.text == "BtC5")

        let routerHint = try renderRouterHint(bytes: Data([0xA1, 0xB2]))
        precondition(routerHint.bytes == Data([0xA1, 0xB2]))
        precondition(routerHint.text == "BtC")

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

        let propertyGet = try ulcpPropGet(transactionId: 3, propertyId: 4_864)
        let propertySet = try ulcpPropSet(
            transactionId: 6,
            propertyId: 96,
            value: Data(repeating: 7, count: 32)
        )
        precondition(propertySet.count > 32)
        let segments = try ulcpGattSegments(frame: propertyGet, maximumValueLength: 4)
        precondition(segments.count > 1)
        let reassembler = MobileGattReassembler()
        var reassembled: Data?
        for segment in segments {
            if let frame = try reassembler.push(segment: segment.value) {
                reassembled = frame
            }
        }
        precondition(reassembled == propertyGet)

        let battery = try inspectUlcpBattery(value: Data([0b111, 0xEC, 0x0E, 82, 1]))
        precondition(battery.percentage == 82)
        precondition(battery.voltageMv == 3820)
        precondition(battery.chargeState == .charging)

        let inspectionProperties = try ulcpInspectionProperties(
            capabilities: Data([8])
        )
        precondition(inspectionProperties == [3, 32, 35, 37])
        let frequency = withUnsafeBytes(of: UInt32(915_000).littleEndian) { Data($0) }
        let sync = try inspectUlcpSync(responses: [
            UlcpPropertyFrameRecord(
                transactionId: 1,
                command: 6,
                propertyId: 5,
                value: Data([8])
            ),
            UlcpPropertyFrameRecord(
                transactionId: 2,
                command: 6,
                propertyId: 3,
                value: Data([8])
            ),
            UlcpPropertyFrameRecord(
                transactionId: 3,
                command: 6,
                propertyId: 32,
                value: Data([1])
            ),
            UlcpPropertyFrameRecord(
                transactionId: 4,
                command: 6,
                propertyId: 35,
                value: frequency
            ),
            UlcpPropertyFrameRecord(
                transactionId: 5,
                command: 6,
                propertyId: 37,
                value: Data([14])
            ),
        ])
        precondition(sync.phyEnabled)
        precondition(sync.frequencyKhz == 915_000)
        precondition(sync.queuedFrames == nil)
        precondition(sync.unreadableProperties.isEmpty)

        precondition(!sync.supportsRepeater)
        precondition(sync.repeater == nil)
        precondition(!sync.supportsTime)
        precondition(!sync.supportsGnss)
        precondition(sync.tzOffsetMin == nil)
        precondition(sync.gnss == nil)

        // The default identity precision, and what it discloses: a ~38 m
        // cell at the equator.
        precondition((38.0...39.0).contains(ulcpLocationCellMeters(precisionBytes: 5)!))
        precondition(ulcpLocationCellMeters(precisionBytes: 0) == nil)

        let sjc = try regionCodeFromString(text: "SJC")
        precondition(sjc == Data([0x78, 0x53]))
        precondition(try! regionCodeDescription(code: sjc) == "SJC")
        let named = try regionCodeFromString(text: "Rogue Valley")
        precondition(try! regionCodeDescription(code: named) == "0xDF6F")

        let administrative = MobileUlcpSession.administrative()
        precondition(administrative.attachMode() == .administrative)
        _ = try administrative.begin(selectedHostKey: Data(repeating: 0xAA, count: 32))
        do {
            _ = try administrative.claim(hostKey: Data(repeating: 0xAA, count: 32))
            preconditionFailure("Administrative session unexpectedly claimed a radio")
        } catch MobileError.AdministrativeSession {
            // Commissioning never writes a host key.
        }
        do {
            _ = try administrative.configureDevice(
                configuration: UlcpDeviceConfigRecord(
                    radio: UlcpRadioSettingsRecord(
                        deviceName: nil,
                        phyEnabled: true,
                        frequencyKhz: 915_000,
                        transmitPowerDbm: 14,
                        bandwidthHz: nil,
                        spreadingFactor: nil,
                        codingRateDenom: nil,
                        dutyCycleLimit: nil
                    ),
                    identRole: nil,
                    identMobile: nil,
                    devDiscoverable: nil,
                    repeater: UlcpRepeaterSettingsRecord(
                        enabled: true,
                        regions: [sjc],
                        defaultRegion: sjc,
                        minRssiDbm: -115,
                        minSnrDb: -7
                    ),
                    tzOffsetMin: nil,
                    gnss: nil
                )
            )
            preconditionFailure("Configuration unexpectedly succeeded before attaching")
        } catch MobileError.InvalidUlcpFrame {
            // Configuration requires an attached session.
        }

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
