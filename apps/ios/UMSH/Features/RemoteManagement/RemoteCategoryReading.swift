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

/// The properties one management screen is about, and what is known of them.
///
/// Held per category rather than per device because that is the unit that
/// goes on the air: a screen asks for its own handful and nothing else.
///
/// The octets are the truth here and the decoded record is derived from
/// them, so a write's echoes fold in as a dictionary merge—no field of
/// the record needs its own rule for what a partial update means.
struct RemoteCategoryReading {
    /// What each property last came back as, verbatim.
    private(set) var values: [UInt32: Data] = [:]
    /// Each sample keeps its own date: a setting echo must not restart an
    /// older clock or uptime reading at the echo's arrival time.
    private(set) var receivedAt: [UInt32: Date] = [:]
    /// What those octets mean.
    private(set) var properties = UlcpDevicePropertiesRecord.empty
    /// The properties this category covers on this device, in ask order.
    var propertyIDs: [UInt32] = []
    /// Properties the device refused, which is how it says it does not
    /// implement one its capabilities implied.
    var refused: Set<UInt32> = []
    /// Keep individual error codes: an acquisition failure is not an
    /// unsupported diagnostic and must remain visible and retryable.
    var statuses: [UInt32: UInt32] = [:]
    /// Transport failures are distinct from property refusals and malformed values.
    var failures: [UInt32: String] = [:]
    /// A failed metadata replacement must not discard usable labels.
    private(set) var invalidTemperatureNames = false
    /// Battery pushes update the summary independently of explicit reads
    /// of the diagnostics, so they must not make old diagnostics look fresh.
    private(set) var batteryDiagnosticsAsOf: Date?
    /// When the values on screen were learned. `nil` means nothing has been
    /// read, so the fields have nothing to prefill from.
    private(set) var asOf: Date?
    /// Whether any of it came off the air this session, as opposed to out of
    /// the cache. A refreshed screen stops dating what it shows.
    private(set) var isFresh = false

    /// Whether the device actually answered for this property.
    ///
    /// The three outcomes a screen has to tell apart: answered, refused,
    /// and never asked. Absence in ``properties`` covers the last two
    /// together, which is not enough—a refusal is the device saying it
    /// does not have the property, and that is the signal for leaving its
    /// controls out rather than showing them empty.
    func answered(_ property: UInt32) -> Bool {
        propertyIDs.contains(property) && !refused.contains(property)
    }

    /// Keep names within this management session while acquiring new readings.
    static func sensorRefresh(previous: Self?, properties: [UInt32]) -> Self {
        var reading = Self()
        reading.propertyIDs = properties
        let names = ulcpProperties.temperatureNames
        if properties.contains(names), previous?.properties.temperatureNames != nil,
           let bytes = previous?.values[names], let date = previous?.receivedAt[names] {
            reading.absorb([names: bytes], at: date, fromAir: false)
        }
        return reading
    }

    var needsTemperatureNames: Bool {
        (properties.temperatures?.count ?? 0) > (properties.temperatureNames?.count ?? 0)
    }

    /// Bootstrap readings and labels in one request. Once names are known,
    /// the names-only group is conditional on the preceding measurement count.
    var sensorRefreshRequests: [[UInt32]] {
        let id = ulcpProperties
        var requests: [[UInt32]] = []
        if propertyIDs.contains(id.temperatures) {
            if propertyIDs.contains(id.temperatureNames) {
                if properties.temperatureNames == nil {
                    requests.append([id.temperatures, id.temperatureNames])
                } else {
                    requests.append([id.temperatures])
                    requests.append([id.temperatureNames])
                }
            } else {
                requests.append([id.temperatures])
            }
        }
        if propertyIDs.contains(id.illuminance) {
            requests.append([id.illuminance])
        }
        return requests
    }

    /// Publish a valid replacement atomically. An incomplete reply cannot erase
    /// labels already known; a growing partial inventory can still add labels.
    mutating func absorbTemperatureNames(_ bytes: Data, at date: Date) {
        let decoded = inspectUlcpProperties(responses: [
            ulcpPropertyRecord(propertyId: ulcpProperties.temperatureNames, value: bytes)
        ]).temperatureNames
        guard let decoded, decoded.count >= (properties.temperatureNames?.count ?? 0) else {
            invalidTemperatureNames = true
            return
        }
        invalidTemperatureNames = false
        absorb([ulcpProperties.temperatureNames: bytes], at: date, fromAir: true)
    }

    /// Take in values the device reported, from a read or from a write's
    /// echoes, and redecode around them.
    mutating func absorb(
        _ reported: [UInt32: Data], at instant: Date, fromAir: Bool,
        sampleDates: [UInt32: Date] = [:]
    ) {
        if reported.keys.contains(where: {
            (ulcpProperties.batteryCurrent...ulcpProperties.batteryGaugeOperationStatus)
                .contains($0)
        }) {
            batteryDiagnosticsAsOf = instant
        }
        for property in reported.keys {
            receivedAt[property] = sampleDates[property] ?? instant
        }
        values.merge(reported) { _, reported in reported }
        properties = inspectUlcpProperties(
            responses: values.map { ulcpPropertyRecord(propertyId: $0.key, value: $0.value) }
        )
        asOf = instant
        isFresh = isFresh || fromAir
    }
}

/// Sensor inventories are connection-local, and measurements are always read fresh.
func isPersistentManagedProperty(_ property: UInt32) -> Bool {
    ![ulcpProperties.illuminance, ulcpProperties.temperatures,
      ulcpProperties.temperatureNames, ulcpProperties.wifiScanResults,
      ulcpProperties.wifiRssi].contains(property)
}

struct RemoteTemperatureRow: Identifiable {
    let id: Int
    let name: String
    let value: String
}

struct RemoteTemperaturePresentation {
    let rows: [RemoteTemperatureRow]
    let problem: String?
    let state: String?
    let sampledAt: Date?

    init(reading: RemoteCategoryReading?, locale: Locale = .autoupdatingCurrent) {
        let id = ulcpProperties
        let readings = reading?.properties.temperatures
        let names = reading?.properties.temperatureNames
        sampledAt = reading?.receivedAt[id.temperatures]
        let metadataFailed = reading?.failures[id.temperatureNames] != nil
            || reading?.refused.contains(id.temperatureNames) == true
        let malformedNames = reading?.invalidTemperatureNames == true
            || (reading?.values[id.temperatureNames] != nil && names == nil)
        let shortNames = readings.map { names == nil || (names?.count ?? 0) < $0.count } ?? false
        if metadataFailed {
            problem = "Sensor names could not be read."
        } else if malformedNames || shortNames {
            problem = "Sensor names are invalid or incomplete."
        } else {
            problem = nil
        }
        let labels = names
        let failure: String?
        if let status = reading?.statuses[id.temperatures] {
            failure = "Read failed (\(ulcpStatusName(status: status)))"
        } else if reading?.failures[id.temperatures] != nil
                    || reading?.refused.contains(id.temperatures) == true {
            failure = "Read failed"
        } else if reading?.values[id.temperatures] != nil && readings == nil {
            failure = "Invalid reading"
        } else {
            failure = nil
        }
        let count = max(readings?.count ?? 0, labels?.count ?? 0)
        rows = (0..<count).map { index in
            let value: String
            if let failure {
                value = failure
            } else if let readings, index < readings.count {
                value = readings[index].map { Self.format($0, locale: locale) } ?? "Unavailable"
            } else {
                value = "Not read"
            }
            return RemoteTemperatureRow(
                id: index,
                name: labels.flatMap { index < $0.count ? $0[index] : nil } ?? "Temperature \(index + 1)",
                value: value
            )
        }
        state = count == 0 ? (failure ?? (readings != nil ? "No temperature sensors" : "Not read")) : nil
    }

    static func format(_ tenthsKelvin: UInt16, locale: Locale = .autoupdatingCurrent) -> String {
        guard tenthsKelvin != .max else { return "Unavailable" }
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
        return unit == .celsius ? preferred : "\(preferred) (\(formatted(.celsius)))"
    }
}
