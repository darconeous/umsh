import Foundation
import UMSHMobileCore

/// A vetted PHY configuration a whole mesh can agree on, as a picker row.
///
/// The list comes from the shared table the firmware ships its own
/// defaults from. What a preset sets is the core's business; the app only
/// names it.
struct RadioPreset: Identifiable {
    let id: String
    let name: String

    static let vetted: [RadioPreset] = ulcpRadioPresets().map { preset in
        RadioPreset(id: preset.id, name: preset.name)
    }
}
