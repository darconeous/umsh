#if DEBUG
import Foundation
import UMSHMobileCore

/// A fabricated mesh, for marketing screenshots taken in the simulator.
///
/// The core's `seedStaging` writes the mesh into the staging store: its
/// nodes, conversations and channels. What stays here is what the staged
/// air needs to speak as those nodes, until it moves into the core too, so
/// the nodes and channels below must match the core's.
enum StagingScenario {
    /// Where the staged crew is working: around Desolation Wilderness, west
    /// of Lake Tahoe. The staged radio sits here.
    static let centerLatitude = 38.8985
    static let centerLongitude = -120.1020

    /// The crew's named public channel.
    static let channelName = "Trail Crew"

    /// The key of the crew leads' private channel. Fabricated; nothing real
    /// is ever encrypted under it.
    static let privateChannelKey = Data([
        0x3B, 0x7A, 0xF1, 0x0C, 0x92, 0x4E, 0xD8, 0x65,
        0x11, 0xA3, 0x5F, 0xC7, 0x2D, 0x88, 0xB0, 0x49,
        0xE6, 0x14, 0x7C, 0xA2, 0x53, 0xDF, 0x96, 0x38,
        0x0B, 0xE1, 0x6D, 0x74, 0xCA, 0x2F, 0x85, 0x1E,
    ])

    /// Every node in the staged mesh.
    static let nodes: [StagingNode] = [
        StagingNode(seed: 0x11, name: "Maya Ortiz", role: .chat),
        StagingNode(seed: 0x22, name: "Tallac Ridge", role: .repeater),
        StagingNode(seed: 0x33, name: "Dev Raman", role: .tracker),
        StagingNode(seed: 0x44, name: "Jules Whitaker", role: .chat),
        StagingNode(seed: 0x55, name: "Echo Basecamp", role: .chat),
        StagingNode(seed: 0x66, name: "Sam Ihara", role: .tracker),
        StagingNode(seed: 0x77, name: "Glen Alpine Relay", role: .repeater),
    ]

    /// The radio the staged phone is attached to: a T-Echo sitting at the
    /// center of the staged mesh, so the map's "this radio" marker lands among
    /// the nodes rather than an ocean away.
    static var radioSnapshot: RadioSnapshot {
        var snapshot = RadioSnapshot.previewReady
        snapshot.name = "T-Echo"
        snapshot.batteryPercentage = 76
        snapshot.batteryVoltageMillivolts = 3_780
        snapshot.chargeState = .discharging
        snapshot.batteryReadAt = .now
        snapshot.clock = RadioClock(date: .now, readAt: .now)
        snapshot.position = RadioPosition(
            UlcpGnssRecord(
                fix: .threeD,
                location: Data([0xB2, 0x59, 0x15, 0x00, 0x00]),
                latitudeDeg: centerLatitude,
                longitudeDeg: centerLongitude,
                locationCellMeters: 38.2,
                altitudeM: 2_164,
                accuracyDm: 48,
                satellitesUsed: 11,
                satellitesInView: 17
            )
        )
        return snapshot
    }
}

/// One node in the staged mesh.
struct StagingNode {
    /// Fills all 32 secret-key bytes, so a node keeps its address across
    /// reseeds.
    let seed: UInt8
    let name: String
    let role: PeerRole

    var secretKey: Data { Data(repeating: seed, count: 32) }
}
#endif
