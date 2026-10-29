import CoreLocation
import Foundation
import UMSHMobileCore

/// How a reported location is put into words.
///
/// A location names a grid cell, not a point, and everything shown about one
///—the size of the area, how many coordinate digits are real—follows from
/// the cell rather than from the coordinate pair. The core owns the
/// conversion; this is the one place that asks it, so the peer sheet, the
/// radio's own readout, and the map cannot drift apart.
enum LocationPresentation {
    /// Cell width at the equator. Map bodies re-derive per render, so the
    /// crossing is made once—and the whole byte is probed rather than the
    /// seven values the wire allows today, so the core stays the only place
    /// that knows the range.
    private static let cellMetersByPrecision: [UInt8: Double] = Dictionary(
        uniqueKeysWithValues: (UInt8.min...UInt8.max).compactMap { precision in
            ulcpLocationCellMeters(precisionBytes: precision).map { (precision, $0) }
        }
    )

    static func cellMeters(precisionBytes: UInt8) -> Double? {
        cellMetersByPrecision[precisionBytes]
    }

    /// Every precision the encoding accepts, coarsest first. Whatever the
    /// core answers a cell size for, and nothing written out here.
    static let precisions: [UInt8] = cellMetersByPrecision.keys.sorted()

    /// A precision named by the area it discloses, which is the only thing
    /// about it a person can weigh. Bare sizes, so a picker row reads as a
    /// measurement rather than a sentence.
    static func precisionLabel(precisionBytes: UInt8) -> String {
        guard let meters = cellMeters(precisionBytes: precisionBytes) else {
            return String(
                localized: "\(Int(precisionBytes)) bytes",
                comment: "A location precision this app cannot size, by its encoded length. Has plural variants."
            )
        }
        return cellSizeText(meters: meters)
    }

    /// How large the cell is, stated plainly: "about 611 m".
    static func cellLabel(precisionBytes: UInt8) -> String? {
        cellMeters(precisionBytes: precisionBytes).map { cellLabel(meters: $0) }
    }

    static func cellLabel(meters: Double, locale: Locale = .current) -> String {
        let size = cellSizeText(meters: meters, locale: locale)
        return String(
            localized: "about \(size)",
            locale: locale,
            comment: "The approximate width of a location cell. The placeholder is a length, such as 611 m."
        )
    }

    /// The bare measurement, in whichever unit keeps it readable.
    static func cellSizeText(meters: Double, locale: Locale = .current) -> String {
        let (value, unit, digits): (Double, UnitLength, Int) =
            if meters >= 1_000 {
                (meters / 1_000, .kilometers, 0)
            } else if meters >= 1 {
                (meters, .meters, meters < 10 ? 1 : 0)
            } else {
                (meters * 100, .centimeters, 0)
            }
        return Measurement(value: value, unit: unit).formatted(
            .measurement(
                width: .abbreviated,
                usage: .asProvided,
                numberFormatStyle: .number.precision(.fractionLength(digits))
            )
            .locale(locale)
        )
    }

    /// Decimal places worth showing for a cell of this size. Digits finer
    /// than the grid code resolves would be invented.
    static func coordinateDecimals(cellMeters: Double?) -> Int {
        guard let cellMeters else { return 5 }
        let degreeMeters = 111_320.0
        return max(0, min(7, Int(log10(degreeMeters / max(cellMeters, 0.01)).rounded(.up))))
    }

    static func coordinateText(
        latitude: Double,
        longitude: Double,
        cellMeters: Double?
    ) -> String {
        let format = FloatingPointFormatStyle<Double>.number
            .precision(.fractionLength(coordinateDecimals(cellMeters: cellMeters)))
        return "\(latitude.formatted(format))°, \(longitude.formatted(format))°"
    }

    /// Great-circle distance between two cell centers, in meters.
    static func distanceMeters(
        fromLatitude: Double,
        longitude fromLongitude: Double,
        toLatitude: Double,
        longitude toLongitude: Double
    ) -> Double {
        CLLocation(latitude: fromLatitude, longitude: fromLongitude)
            .distance(from: CLLocation(latitude: toLatitude, longitude: toLongitude))
    }

    /// How far apart two located nodes are, honest about the cells.
    ///
    /// Each node is somewhere in its cell, so the distance between the two
    /// centers is off by up to half a cell at either end. When the centers
    /// are closer than that slack, the real figure is unknown beyond an upper
    /// bound, and the text says so: "<1.2 km" rather than a number the grid
    /// cannot support. Farther apart, the center distance stands.
    static func separationText(
        centerMeters: Double,
        cellMeters: Double?,
        otherCellMeters: Double?
    ) -> String {
        let slack = (cellMeters ?? 0) / 2 + (otherCellMeters ?? 0) / 2
        if centerMeters < slack {
            return "<\(distanceText(meters: centerMeters + slack))"
        }
        return distanceText(meters: centerMeters)
    }

    /// A distance between nodes: "0.3 mi", "3.6 km", "60 mi".
    ///
    /// Always in the locale's road unit, never meters or feet: a short
    /// distance in meters reads as an altitude next to the other figures on
    /// a node row. Tenths below five, whole units from there. One style for
    /// every place the app states how far apart two nodes are.
    static func distanceText(meters: Double, locale: Locale = .current) -> String {
        let unit: UnitLength = switch locale.measurementSystem {
        case .us, .uk: .miles
        default: .kilometers
        }
        let distance = Measurement(value: meters, unit: UnitLength.meters).converted(to: unit)
        let digits = distance.value < 5 ? 1 : 0
        return distance.formatted(
            .measurement(
                width: .abbreviated,
                usage: .asProvided,
                numberFormatStyle: .number.precision(.fractionLength(digits))
            )
            .locale(locale)
        )
    }

    /// The initial great-circle bearing from one point to another, in
    /// degrees clockwise from true north, 0 up to 360.
    static func bearingDegrees(
        fromLatitude: Double,
        longitude fromLongitude: Double,
        toLatitude: Double,
        longitude toLongitude: Double
    ) -> Double {
        let φ1 = fromLatitude * .pi / 180
        let φ2 = toLatitude * .pi / 180
        let Δλ = (toLongitude - fromLongitude) * .pi / 180
        let y = sin(Δλ) * cos(φ2)
        let x = cos(φ1) * sin(φ2) - sin(φ1) * cos(φ2) * cos(Δλ)
        let degrees = atan2(y, x) * 180 / .pi
        return (degrees + 360).truncatingRemainder(dividingBy: 360)
    }

    /// A bearing as the nearest of eight compass points, for VoiceOver to
    /// read beside a distance: "northeast".
    static func compassText(degrees: Double, locale: Locale = .current) -> String {
        let point = Int(((degrees.truncatingRemainder(dividingBy: 360) + 360) / 45).rounded()) % 8
        return switch point {
        case 0: String(localized: "north", locale: locale, comment: "Compass direction, read by VoiceOver after a distance.")
        case 1: String(localized: "northeast", locale: locale, comment: "Compass direction, read by VoiceOver after a distance.")
        case 2: String(localized: "east", locale: locale, comment: "Compass direction, read by VoiceOver after a distance.")
        case 3: String(localized: "southeast", locale: locale, comment: "Compass direction, read by VoiceOver after a distance.")
        case 4: String(localized: "south", locale: locale, comment: "Compass direction, read by VoiceOver after a distance.")
        case 5: String(localized: "southwest", locale: locale, comment: "Compass direction, read by VoiceOver after a distance.")
        case 6: String(localized: "west", locale: locale, comment: "Compass direction, read by VoiceOver after a distance.")
        default: String(localized: "northwest", locale: locale, comment: "Compass direction, read by VoiceOver after a distance.")
        }
    }
}
