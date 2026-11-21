#if DEBUG
import Foundation
import UMSHMobileCore

/// Where the staged mesh stands, for the views that draw it without a
/// radio. The mesh itself is the core's: `seedStaging` writes it into the
/// staging store, and the staging air runs its nodes.
enum StagingScenario {
    /// Where the staged crew is working: around Desolation Wilderness, west
    /// of Lake Tahoe. The staged radio sits here.
    static let centerLatitude = 38.8985
    static let centerLongitude = -120.1020

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

#endif
