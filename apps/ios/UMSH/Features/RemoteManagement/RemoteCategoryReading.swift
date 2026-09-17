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
