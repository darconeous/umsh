import Foundation
import UMSHMobileCore

/// A vetted PHY configuration a whole mesh can agree on.
///
/// The list comes from the shared table the firmware ships its own
/// defaults from, so a device commissioned here and the phone's own radio
/// cannot end up describing the same profile differently.
struct RadioPreset: Identifiable {
    let id: String
    let name: String
    let frequencyKHz: UInt32
    /// Nil where the profile has no vetted power, in which case adopting
    /// it leaves whatever the device is set to alone.
    let transmitPowerDBm: Int8?
    let bandwidthHz: UInt32
    let spreadingFactor: UInt8
    let codingRate: UInt8
    let dutyCycleLimit: UInt16

    /// Whether a node on this preset and one on `profile` can hear each
    /// other—the same exclusion of power and the transmit limit that
    /// ``RadioProfile/interoperates(with:)`` makes.
    func interoperates(with profile: RadioProfile) -> Bool {
        profile.frequencyKHz == frequencyKHz
            && profile.bandwidthHz == bandwidthHz
            && profile.spreadingFactor == spreadingFactor
            && profile.codingRateDenominator == codingRate
    }

    static let vetted: [RadioPreset] = ulcpRadioPresets().map { preset in
        RadioPreset(
            id: preset.id,
            name: preset.name,
            frequencyKHz: preset.frequencyKhz,
            transmitPowerDBm: preset.transmitPowerDbm,
            bandwidthHz: preset.bandwidthHz,
            spreadingFactor: preset.spreadingFactor,
            codingRate: preset.codingRateDenom,
            dutyCycleLimit: preset.dutyCycleLimit
        )
    }
}
