import Foundation
import UMSHMobileCore

/// The property numbers the management screens name, read once.
let ulcpProperties = ulcpManagedPropertyIds()

extension UlcpDevicePropertiesRecord {
    /// A device nothing has been read from.
    ///
    /// Built by decoding nothing rather than written out field by field, so
    /// a property added to the record needs no second place to be told
    /// about it.
    static let empty = inspectUlcpProperties(responses: [])
}

/// One category's reading as the screens look it up: the core's record,
/// with its lists turned into the dictionaries a view indexes by property.
///
/// Built once per published reading. Everything here is the core's; this
/// only changes its shape.
struct RemoteCategoryReading {
    let record: MobileCategoryReadingRecord
    /// What each property last came back as, verbatim.
    let values: [UInt32: Data]
    /// Each sample's own instant: a setting's echo does not redate an older
    /// clock or uptime reading.
    let receivedAt: [UInt32: Date]
    /// Each property's read state, by property.
    let states: [UInt32: MobilePropertyState]

    init(_ record: MobileCategoryReadingRecord) {
        self.record = record
        values = Dictionary(
            record.values.map { ($0.propertyId, $0.value) },
            uniquingKeysWith: { _, last in last }
        )
        receivedAt = Dictionary(
            record.values.map { ($0.propertyId, Self.instant($0.receivedAtMs)) },
            uniquingKeysWith: { _, last in last }
        )
        states = Dictionary(
            record.states.map { ($0.propertyId, $0.state) },
            uniquingKeysWith: { _, last in last }
        )
    }

    /// What those octets mean.
    var properties: UlcpDevicePropertiesRecord { record.properties }
    /// The properties this category covers on this device, in ask order.
    var propertyIDs: [UInt32] { record.propertyIds }
    /// When the values on screen were learned. `nil` means nothing has been
    /// read, so the fields have nothing to prefill from.
    var asOf: Date? { record.asOfMs.map(Self.instant) }
    /// Whether any of it came off the air this session, as opposed to out
    /// of the cache.
    var isFresh: Bool { record.isFresh }
    /// Raised whenever the reading changes.
    var revision: UInt64 { record.revision }
    var batteryDiagnosticsAsOf: Date? { record.batteryDiagnosticsAsOfMs.map(Self.instant) }
    var temperatures: MobileTemperatureSummaryRecord? { record.temperatures }

    /// Whether the device actually answered for this property: covered by
    /// the category and not refused on the last read.
    func answered(_ property: UInt32) -> Bool {
        record.answered.contains(property)
    }

    /// The property's read state; `notRead` for one the category does not
    /// cover.
    func state(_ property: UInt32) -> MobilePropertyState {
        states[property] ?? .notRead
    }

    private static func instant(_ milliseconds: Int64) -> Date {
        Date(timeIntervalSince1970: TimeInterval(milliseconds) / 1_000)
    }
}

/// Why a property shows no value, for a read-only row. `nil` when it has
/// one to show.
enum PropertyStateText {
    static func text(_ state: MobilePropertyState) -> String? {
        switch state {
        case .present:
            nil
        case .notRead:
            notRead
        case .empty:
            unavailable
        case .invalid:
            invalid
        case let .refused(refusal):
            failed(status: refusal.status)
        case .noResponse, .failed:
            failed(status: nil)
        }
    }

    static func failed(status: UInt32?) -> String {
        if let status {
            String(
                localized: "Read failed (\(ulcpStatusName(status: status)))",
                comment: "Managing a node: a value could not be read. The placeholder is a protocol status name, not translated."
            )
        } else {
            String(localized: "Read failed", comment: "Managing a node: a value could not be read.")
        }
    }

    static var notRead: String {
        String(localized: "Not read", comment: "Managing a node: a value nobody has asked the device for yet.")
    }

    static var invalid: String {
        String(localized: "Invalid reading", comment: "Managing a node: a value it reported could not be decoded.")
    }

    static var unavailable: String {
        String(localized: "Unavailable", comment: "Managing a node: the device holds no value for this sensor right now.")
    }
}

struct RemoteTemperatureRow: Identifiable {
    let id: Int
    let name: String
    let value: String
}

/// The temperature section's rows and notes, worded from the core's
/// summary.
struct RemoteTemperaturePresentation {
    let rows: [RemoteTemperatureRow]
    let problem: String?
    let state: String?
    let sampledAt: Date?

    init(reading: RemoteCategoryReading?, locale: Locale = .autoupdatingCurrent) {
        let summary = reading?.temperatures
        sampledAt = summary?.sampledAtMs.map {
            Date(timeIntervalSince1970: TimeInterval($0) / 1_000)
        }
        problem = switch summary?.names {
        case .unreadable?:
            String(localized: "Sensor names could not be read.", comment: "Managing a node: its temperature sensor names were refused or not answered.")
        case .incomplete?:
            String(localized: "Sensor names are invalid or incomplete.", comment: "Managing a node: its temperature sensor names did not decode, or name fewer sensors than it measures.")
        case .known?, nil:
            nil
        }
        let failure = summary?.failure.flatMap(PropertyStateText.text)
        rows = (summary?.rows ?? []).map { row in
            let value: String
            if let failure {
                value = failure
            } else {
                switch row.value {
                case let .reading(tenthsKelvin):
                    value = Self.format(tenthsKelvin, locale: locale)
                case .unavailable:
                    value = PropertyStateText.unavailable
                case .notRead:
                    value = PropertyStateText.notRead
                }
            }
            return RemoteTemperatureRow(
                id: Int(row.index),
                name: row.name ?? String(
                    localized: "Temperature \(Int(row.index) + 1)",
                    comment: "Managing a node: a temperature sensor the device gave no name. The placeholder is its position in the list."
                ),
                value: value
            )
        }
        if rows.isEmpty {
            state = failure ?? (reading?.properties.temperatures != nil
                ? String(localized: "No temperature sensors", comment: "Managing a node: it reported an empty list of temperature sensors.")
                : PropertyStateText.notRead)
        } else {
            state = nil
        }
    }

    static func format(_ tenthsKelvin: UInt16, locale: Locale = .autoupdatingCurrent) -> String {
        let kelvin = Measurement(value: Double(tenthsKelvin) / 10, unit: UnitTemperature.kelvin)
        let unit = UnitTemperature(forLocale: locale)
        func formatted(_ unit: UnitTemperature) -> String {
            kelvin.converted(to: unit).formatted(
                .measurement(width: .abbreviated, usage: .asProvided,
                             numberFormatStyle: .number.precision(.fractionLength(1)))
                    .locale(locale)
            )
        }
        let preferred = formatted(unit)
        guard unit != .celsius else { return preferred }
        let celsius = formatted(.celsius)
        return String(
            localized: "\(preferred) (\(celsius))",
            comment: "A temperature in the locale's unit, then in degrees Celsius. Both placeholders are formatted temperatures."
        )
    }
}
