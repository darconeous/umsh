import UMSHMobileCore

/// The core's bounds and starting values for this phone's settings, channels
/// and manual paths. Constants, so they are read once.
enum CoreLimits {
    static let current = mobileLimits()

    /// The phone's reach for messages and requests as stored, or the reach
    /// a phone starts with when nothing usable is stored.
    static func floodHops(stored: Int?) -> UInt8 {
        stored.flatMap(UInt8.init(exactly:)) ?? current.recommendedFloodHops
    }

    /// The phone's beacon reach as stored, or its starting value.
    static func beaconFloodHops(stored: Int?) -> UInt8 {
        stored.flatMap(UInt8.init(exactly:)) ?? current.recommendedBeaconFloodHops
    }

    /// The precision the phone shares its location at as stored, or its
    /// starting value.
    static func locationPrecision(stored: Int?) -> UInt8 {
        stored.flatMap(UInt8.init(exactly:)) ?? current.defaultLocationPrecision
    }
}
