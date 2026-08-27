import Foundation
import UMSHMobileCore

/// How a reported location is put into words.
///
/// A location names a grid cell, not a point, and everything shown about one
/// — the size of the area, how many coordinate digits are real — follows from
/// the cell rather than from the coordinate pair. The core owns the
/// conversion; this is the one place that asks it, so the peer sheet, the
/// radio's own readout, and the map cannot drift apart.
enum LocationPresentation {
    /// Cell width at the equator. Map bodies re-derive per render, so the
    /// crossing is made once — and the whole byte is probed rather than the
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
            return "\(precisionBytes) bytes"
        }
        return cellSizeText(meters: meters)
    }

    /// How large the cell is, stated plainly: "about 611 m".
    static func cellLabel(precisionBytes: UInt8) -> String? {
        cellMeters(precisionBytes: precisionBytes).map(cellLabel(meters:))
    }

    static func cellLabel(meters: Double) -> String {
        "about \(cellSizeText(meters: meters))"
    }

    /// The bare measurement, in whichever unit keeps it readable.
    static func cellSizeText(meters: Double) -> String {
        if meters >= 1_000 {
            return "\((meters / 1_000).formatted(.number.precision(.fractionLength(0)))) km"
        }
        if meters >= 1 {
            let digits = meters < 10 ? 1 : 0
            return "\(meters.formatted(.number.precision(.fractionLength(digits)))) m"
        }
        return "\((meters * 100).formatted(.number.precision(.fractionLength(0)))) cm"
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
}
