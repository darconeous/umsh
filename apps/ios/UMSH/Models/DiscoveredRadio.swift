import Foundation

/// A saved accessory record or a radio sighting. Pickers display only recent
/// connectable sightings; the authorization inventory also retains offline radios.
struct DiscoveredRadio: Identifiable, Equatable, Sendable {
    /// The CoreBluetooth peripheral identifier, stable for this device.
    let id: UUID
    /// System accessory name, or the fallback scanner's advertised/cached name.
    let name: String?
    /// Advertised signal strength. CoreBluetooth reports `127` when the value
    /// is unavailable; `hasSignal` reflects that.
    let rssiDBm: Int
    /// True for a saved accessory or the fallback scanner's saved companion.
    let isRemembered: Bool
    var requiresMigration: Bool = false

    /// CoreBluetooth uses `127` as the "RSSI unavailable" sentinel.
    var hasSignal: Bool { rssiDBm != 127 }

    /// A coarse 0–3 bar level derived from RSSI, for a signal-strength glyph.
    var signalBars: Int {
        guard hasSignal else { return 0 }
        switch rssiDBm {
        case ..<(-90): return 1
        case ..<(-75): return 2
        default: return 3
        }
    }
}
