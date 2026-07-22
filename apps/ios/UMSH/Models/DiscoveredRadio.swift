import Foundation

/// A companion radio seen during an explicit discovery scan, before the user
/// has chosen one to attach. Unlike the auto-connect path, discovery never
/// picks a radio on its own — every advertising radio in range is surfaced so
/// the user can select the intended one (essential when several radios are on
/// the bench at once).
struct DiscoveredRadio: Identifiable, Equatable, Sendable {
    /// The CoreBluetooth peripheral identifier, stable for this device.
    let id: UUID
    /// Advertised local name, falling back to the cached peripheral name.
    let name: String?
    /// Advertised signal strength. CoreBluetooth reports `127` when the value
    /// is unavailable; `hasSignal` reflects that.
    let rssiDBm: Int
    /// True when this is the currently saved companion radio.
    let isRemembered: Bool

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
