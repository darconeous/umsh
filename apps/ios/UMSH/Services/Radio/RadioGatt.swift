@preconcurrency import CoreBluetooth

/// The UMSH ULCP GATT service.
///
/// Every transport in the app that speaks ULCP over BLE — the companion
/// connection and any administrative session — discovers the same service
/// with the same characteristics on the same devices. There is exactly one
/// definition of what that service is.
enum RadioGatt {
    static let service = CBUUID(string: "21EB6B15-0001-4CCF-92E4-A079171BEC97")
    /// Host-to-device: ULCP frames, GATT-segmented, written with response.
    static let frameIn = CBUUID(string: "21EB6B15-0002-4CCF-92E4-A079171BEC97")
    /// Device-to-host: ULCP frames delivered as notifications.
    static let frameOut = CBUUID(string: "21EB6B15-0003-4CCF-92E4-A079171BEC97")
}
