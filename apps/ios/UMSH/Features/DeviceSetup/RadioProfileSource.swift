import Foundation
import UMSHMobileCore

/// A complete PHY profile: what two nodes must agree on to hear each other,
/// plus the two local settings that travel alongside it.
struct RadioProfile: Equatable, Sendable {
    var frequencyKHz: UInt32
    var transmitPowerDBm: Int8
    /// The modem triple, present together or not at all — on a radio with
    /// `CAP_PHY_LORA` that reported all three.
    var bandwidthHz: UInt32?
    var spreadingFactor: UInt8?
    var codingRateDenominator: UInt8?
    /// Present on a radio with `CAP_PHY_DUTY_LIMIT`. The *limit*, never the
    /// current duty figure, which is a measurement rather than a setting.
    var dutyCycleLimit: UInt16?

    /// Whether a node on this profile and one on `other` can hear each other.
    ///
    /// Transmit power and the duty-cycle limit are deliberately excluded.
    /// Neither changes what a receiver can decode, and a radio reports power
    /// clamped to what it can actually reach — so comparing power would call
    /// two radios on the same mesh profile "custom" merely because one of them
    /// cannot transmit as hard as the other.
    func interoperates(with other: RadioProfile) -> Bool {
        frequencyKHz == other.frequencyKHz
            && bandwidthHz == other.bandwidthHz
            && spreadingFactor == other.spreadingFactor
            && codingRateDenominator == other.codingRateDenominator
    }
}

extension RadioPreset {
    var profile: RadioProfile {
        RadioProfile(
            frequencyKHz: frequencyKHz,
            transmitPowerDBm: transmitPowerDBm,
            bandwidthHz: bandwidthHz,
            spreadingFactor: spreadingFactor,
            codingRateDenominator: codingRate,
            dutyCycleLimit: dutyCycleLimit
        )
    }
}

/// Where a setup sheet gets a PHY profile it does not ask about.
///
/// Putting a node on a mesh means putting it on the mesh's profile, and the
/// one profile this phone can be sure of is the one its own radio is using.
/// What travels is the companion's live report rather than a preset
/// identifier: the phone's radio may not be on a vetted preset at all.
struct CompanionRadioProfile: Equatable, Sendable {
    let name: String?
    let profile: RadioProfile

    /// Nil when no companion radio is attached, or when it has not reported
    /// its PHY — `provisioning` is populated only once a session attaches.
    init?(_ provisioning: RadioProvisioningSummary?, name: String?) {
        guard let provisioning else { return nil }
        self.name = name
        self.profile = RadioProfile(
            frequencyKHz: provisioning.frequencyKHz,
            transmitPowerDBm: provisioning.transmitPowerDBm,
            bandwidthHz: provisioning.bandwidthHz,
            spreadingFactor: provisioning.spreadingFactor,
            codingRateDenominator: provisioning.codingRateDenominator,
            dutyCycleLimit: provisioning.dutyCycleLimit
        )
    }
}

/// The PHY a setup sheet starts on, and what to say about how it got there.
///
/// Resolved once, when the device attaches and its capabilities are known.
/// All three cases render as the same single row — the operator finds the
/// radio profile in the same place every time, and only the value and the
/// explanation differ.
enum ResolvedRadioProfile: Equatable {
    /// Copied from the phone's radio, reduced to what this device accepts.
    /// `preset` is set when the result is one of the vetted profiles, so the
    /// row can name it instead of reciting six numbers.
    case copied(RadioProfile, source: String?, preset: RadioPreset.ID?)
    /// Nothing could be copied, and this device reported enough about itself
    /// that the operator can be asked. This is the sheet's one required field.
    case mustChoose(MissingReason)
    /// Nothing could be copied and there is nothing safe to offer either,
    /// because the device would not report the modem settings a profile has to
    /// set. Its own profile stands.
    case leftAsFound(MissingReason)

    enum MissingReason: Equatable {
        case noCompanion
        case companionHasNoModemProfile
    }

    var copiedProfile: RadioProfile? {
        if case let .copied(profile, _, _) = self { return profile }
        return nil
    }

    /// Whether the operator has to set the profile before the sheet can apply.
    var requiresChoice: Bool {
        if case .mustChoose = self { return true }
        return false
    }

    static func resolve(
        companion: CompanionRadioProfile?,
        target sync: UlcpSyncRecord
    ) -> Self {
        // Whether this device told us enough about its modem for a profile to
        // be meaningfully chosen. Same condition as the editor's preset
        // picker, and for the same reason: a profile sets every radio
        // parameter, so offering one for a device that would not report them
        // shows a value that is not the device's and edits that go nowhere.
        let modemReadable = !sync.supportsLora
            || (sync.bandwidthHz != nil
                && sync.spreadingFactor != nil
                && sync.codingRateDenom != nil)
        let dutyReadable = !sync.supportsDutyCycleLimit || sync.dutyCycleLimit != nil
        let canChoose = modemReadable && dutyReadable

        guard let companion else {
            return canChoose ? .mustChoose(.noCompanion) : .leftAsFound(.noCompanion)
        }

        // The modem triple travels only to a device that has a modem, and only
        // whole: Rust requires all three present exactly when `CAP_PHY_LORA`
        // is, so a partial triple is not a profile.
        if sync.supportsLora {
            guard companion.profile.bandwidthHz != nil,
                  companion.profile.spreadingFactor != nil,
                  companion.profile.codingRateDenominator != nil
            else {
                return canChoose
                    ? .mustChoose(.companionHasNoModemProfile)
                    : .leftAsFound(.companionHasNoModemProfile)
            }
        }

        let copied = RadioProfile(
            frequencyKHz: companion.profile.frequencyKHz,
            transmitPowerDBm: companion.profile.transmitPowerDBm,
            bandwidthHz: sync.supportsLora ? companion.profile.bandwidthHz : nil,
            spreadingFactor: sync.supportsLora ? companion.profile.spreadingFactor : nil,
            codingRateDenominator: sync.supportsLora
                ? companion.profile.codingRateDenominator
                : nil,
            // A duty-cycle limit is a local regulatory setting rather than an
            // interop parameter, so a companion without one falls back to what
            // this device already holds instead of failing the copy.
            dutyCycleLimit: sync.supportsDutyCycleLimit
                ? (companion.profile.dutyCycleLimit ?? sync.dutyCycleLimit ?? UInt16.max)
                : nil
        )
        let preset = RadioPreset.vetted
            .first { $0.profile.interoperates(with: copied) }?
            .id
        return .copied(copied, source: companion.name, preset: preset)
    }
}
