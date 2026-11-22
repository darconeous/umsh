import Foundation
import UMSHMobileCore

/// What is left of device management in Swift once the core holds the
/// engine: the reading's lookups and the temperature words over the core's
/// summary. The rules behind them are the core's, and tested there.
@main
struct DeviceManagementSmokeTest {
    static func main() throws {
        try temperatureTests()
        let id = ulcpProperties
        let absentSensors = try ulcpCategoryProperties(category: .sensors, capabilities: Data())
        let presentSensors = try ulcpCategoryProperties(
            category: .sensors, capabilities: Data([0x2F])
        )
        precondition(absentSensors.isEmpty)
        precondition(presentSensors == [id.illuminance])

        // The reading's lookups keep each sample's own instant.
        let start: Int64 = 1_800_000_000_000
        let values = [
            MobilePropertyValueRecord(propertyId: id.time, value: bytes(UInt32(1_800_000_000)), receivedAtMs: start),
            MobilePropertyValueRecord(propertyId: id.uptime, value: bytes(UInt32(600)), receivedAtMs: start),
            MobilePropertyValueRecord(propertyId: id.tzRule, value: Data("UTC0".utf8), receivedAtMs: start + 60_000),
        ]
        let decoded = inspectUlcpProperties(
            responses: values.map { ulcpPropertyRecord(propertyId: $0.propertyId, value: $0.value) }
        )
        let reading = RemoteCategoryReading(record(
            category: .time,
            ids: [id.time, id.uptime, id.tzRule, id.time24h],
            answered: [id.time, id.uptime, id.tzRule],
            values: values,
            properties: decoded,
            states: [
                MobilePropertyStateRecord(propertyId: id.time24h, state: .refused(
                    refusal: MobileRefusal(reason: .noSuchProperty, status: 13)
                )),
            ],
            asOfMs: start + 60_000
        ))
        let epoch = Date(timeIntervalSince1970: 1_800_000_000)
        precondition(reading.receivedAt[id.time] == epoch)
        precondition(reading.receivedAt[id.uptime] == epoch)
        precondition(reading.receivedAt[id.tzRule] == epoch.addingTimeInterval(60))
        precondition(reading.asOf == epoch.addingTimeInterval(60))
        precondition(reading.values[id.tzRule] == Data("UTC0".utf8))
        precondition(reading.answered(id.time) && !reading.answered(id.time24h))
        precondition(reading.properties.uptimeSeconds == 600)
        if case .refused = reading.state(id.time24h) {} else { preconditionFailure("refused state") }
        if case .notRead = reading.state(id.statTxPackets) {} else { preconditionFailure("not read") }
        precondition(PropertyStateText.text(.present) == nil)
        precondition(PropertyStateText.text(.empty) == "Unavailable")
        precondition(PropertyStateText.text(.refused(
            refusal: MobileRefusal(reason: .other, status: 3)
        )) == "Read failed (\(ulcpStatusName(status: 3)))")
        precondition(PropertyStateText.text(.noResponse) == "Read failed")

        // Applying settings with a cached time present never sends PROP_TIME.
        let settings = try ulcpDirtyWrites(
            desired: reading.properties,
            dirtyPropertyIds: [id.tzRule]
        )
        precondition(Set(settings.map(\.propertyId)) == [id.tzRule])

        // Clear Position sends empty values, including removal of altitude.
        var desired = UlcpDevicePropertiesRecord.empty
        desired.identLocation = Data()
        desired.identAltitudeM = nil
        let cleared = try ulcpDirtyWrites(
            desired: desired, dirtyPropertyIds: [id.identLocation, id.identAltitude]
        )
        precondition(cleared.count == 2 && cleared.allSatisfy { $0.value.isEmpty })
        print("Device management smoke tests passed")
    }

    static func temperatureTests() throws {
        let id = ulcpProperties
        let celsius = Locale(identifier: "en-US-u-mu-celsius")
        let fahrenheit = Locale(identifier: "en-GB-u-mu-fahrenhe")
        precondition(RemoteTemperaturePresentation.format(2981, locale: celsius) == "25.0°C")
        precondition(RemoteTemperaturePresentation.format(2981, locale: fahrenheit) == "76.9°F (25.0°C)")
        precondition(RemoteTemperaturePresentation.format(2631, locale: celsius) == "-10.0°C")
        precondition(RemoteTemperaturePresentation.format(2631, locale: fahrenheit) == "13.9°F (-10.0°C)")

        let sampled: Int64 = 1_800_000_000_000
        func sensors(
            _ summary: MobileTemperatureSummaryRecord?, decoded temperatures: [UInt16?]? = nil
        ) -> RemoteCategoryReading {
            var properties = UlcpDevicePropertiesRecord.empty
            properties.temperatures = temperatures
            return RemoteCategoryReading(record(
                category: .sensors,
                ids: [id.temperatures, id.temperatureNames],
                answered: [id.temperatures, id.temperatureNames],
                values: [], properties: properties, states: [],
                asOfMs: sampled, temperatures: summary
            ))
        }

        // Rows in order: a reading, an unavailable sensor, one not read.
        let grown = RemoteTemperaturePresentation(reading: sensors(MobileTemperatureSummaryRecord(
            rows: [
                MobileTemperatureRowRecord(index: 0, name: "Die", value: .reading(tenthsKelvin: 2981)),
                MobileTemperatureRowRecord(index: 1, name: "Die", value: .unavailable),
                MobileTemperatureRowRecord(index: 2, name: "電池", value: .notRead),
            ],
            failure: nil, names: .known, sampledAtMs: sampled
        ), decoded: [2981, nil]), locale: celsius)
        precondition(grown.sampledAt == Date(timeIntervalSince1970: 1_800_000_000))
        precondition(grown.rows.map(\.id) == [0, 1, 2])
        precondition(grown.rows.map(\.name) == ["Die", "Die", "電池"])
        precondition(grown.rows.map(\.value) == ["25.0°C", "Unavailable", "Not read"])
        precondition(grown.problem == nil)
        precondition(grown.state == nil)

        // Nameless sensors are numbered; names the core could not use are said.
        for names in [MobileTemperatureNames.incomplete, .unreadable] {
            let partial = RemoteTemperaturePresentation(reading: sensors(MobileTemperatureSummaryRecord(
                rows: [
                    MobileTemperatureRowRecord(index: 0, name: "Die", value: .reading(tenthsKelvin: 2981)),
                    MobileTemperatureRowRecord(index: 1, name: nil, value: .unavailable),
                ],
                failure: nil, names: names, sampledAtMs: sampled
            ), decoded: [2981, nil]), locale: celsius)
            precondition(partial.rows.map(\.name) == ["Die", "Temperature 2"])
            precondition(partial.problem != nil)
        }

        // A failed read puts its words on every row, or in the state line.
        let failedRow = RemoteTemperaturePresentation(reading: sensors(MobileTemperatureSummaryRecord(
            rows: [MobileTemperatureRowRecord(index: 0, name: "Die", value: .notRead)],
            failure: .failed(problem: .noAnswer), names: .known, sampledAtMs: nil
        )))
        precondition(failedRow.rows.map(\.value) == ["Read failed"])
        let failed = RemoteTemperaturePresentation(reading: sensors(MobileTemperatureSummaryRecord(
            rows: [], failure: .noResponse, names: .known, sampledAtMs: nil
        )))
        precondition(failed.state == "Read failed")
        let invalid = RemoteTemperaturePresentation(reading: sensors(MobileTemperatureSummaryRecord(
            rows: [], failure: .invalid, names: .known, sampledAtMs: nil
        )))
        precondition(invalid.state == "Invalid reading")
        let none = RemoteTemperaturePresentation(reading: sensors(MobileTemperatureSummaryRecord(
            rows: [], failure: nil, names: .known, sampledAtMs: sampled
        ), decoded: []))
        precondition(none.state == "No temperature sensors")
        precondition(RemoteTemperaturePresentation(reading: nil).state == "Not read")
    }

    static func record(
        category: UlcpManageCategory,
        ids: [UInt32],
        answered: [UInt32],
        values: [MobilePropertyValueRecord],
        properties: UlcpDevicePropertiesRecord,
        states: [MobilePropertyStateRecord],
        asOfMs: Int64?,
        temperatures: MobileTemperatureSummaryRecord? = nil
    ) -> MobileCategoryReadingRecord {
        MobileCategoryReadingRecord(
            category: category,
            propertyIds: ids,
            answered: answered,
            values: values,
            properties: properties,
            states: states,
            refusals: [],
            temperatures: temperatures,
            canResetCounters: false,
            batteryDiagnosticsAsOfMs: nil,
            asOfMs: asOfMs,
            isFresh: true,
            revision: 1
        )
    }

    static func bytes<T: FixedWidthInteger>(_ value: T) -> Data {
        withUnsafeBytes(of: value.littleEndian) { Data($0) }
    }
}
