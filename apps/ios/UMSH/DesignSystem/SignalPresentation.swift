import Foundation

/// How a radio reading is put into words: "−97 dBm · SNR 6.5 dB".
///
/// dBm and dB have no Foundation unit, so this is the one place that writes
/// them. Every figure is formatted for the reader's locale and every unit is
/// a localized format string around it.
enum SignalPresentation {
    /// Received signal strength: "−97 dBm".
    static func rssiText(_ dBm: Int16, locale: Locale = .current) -> String {
        let number = Int(dBm).formatted(.number.locale(locale))
        return String(
            localized: "\(number) dBm",
            locale: locale,
            comment: "Received signal strength, in decibel-milliwatts. The placeholder is a number."
        )
    }

    /// A signal-to-noise ratio as a bare value: "6.5 dB".
    static func decibelsText(_ decibels: Double, locale: Locale = .current) -> String {
        let number = decibels.formatted(.number.precision(.fractionLength(1)).locale(locale))
        return String(
            localized: "\(number) dB",
            locale: locale,
            comment: "A signal-to-noise ratio, in decibels. The placeholder is a number."
        )
    }

    /// A signal-to-noise ratio beside a strength reading: "SNR 6.5 dB".
    static func snrText(_ decibels: Double, locale: Locale = .current) -> String {
        let number = decibels.formatted(.number.precision(.fractionLength(1)).locale(locale))
        return String(
            localized: "SNR \(number) dB",
            locale: locale,
            comment: "A signal-to-noise ratio, in decibels. SNR is the usual abbreviation. The placeholder is a number."
        )
    }

    /// Strength and signal-to-noise together, whichever of them is known.
    /// `nil` when neither is.
    static func readingText(
        rssiDBm: Int16?,
        snrDecibels: Double?,
        locale: Locale = .current
    ) -> String? {
        switch (rssiDBm, snrDecibels) {
        case let (rssi?, snr?):
            let strength = rssiText(rssi, locale: locale)
            let noise = snrText(snr, locale: locale)
            return String(
                localized: "\(strength) · \(noise)",
                locale: locale,
                comment: "A radio reading: signal strength, then signal-to-noise ratio."
            )
        case let (rssi?, nil):
            return rssiText(rssi, locale: locale)
        case let (nil, snr?):
            return snrText(snr, locale: locale)
        case (nil, nil):
            return nil
        }
    }

    /// The same, for a reading whose signal-to-noise ratio is in centibels,
    /// as a ping reply carries it.
    static func readingText(
        rssiDBm: Int16?,
        snrCentibels: Int16?,
        locale: Locale = .current
    ) -> String? {
        readingText(rssiDBm: rssiDBm, snrDecibels: snrCentibels.map(decibels(centibels:)), locale: locale)
    }

    static func decibels(centibels: Int16) -> Double {
        Double(centibels) / 10
    }

    /// The reading as zero to four bars.
    ///
    /// Signal-to-noise decides when it is known: at LoRa's spreading factors
    /// a link decodes well below the noise floor, so strength alone says
    /// little about whether the next frame will arrive.
    static func bars(rssiDBm: Int16?, snrDecibels: Double?) -> Int? {
        if let snr = snrDecibels {
            return switch snr {
            case 10...: 4
            case 5..<10: 3
            case 0..<5: 2
            case -7.5..<0: 1
            default: 0
            }
        }
        guard let rssi = rssiDBm else { return nil }
        return switch rssi {
        case (-90)...: 4
        case -100 ..< -90: 3
        case -110 ..< -100: 2
        case -120 ..< -110: 1
        default: 0
        }
    }
}
