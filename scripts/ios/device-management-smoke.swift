import Foundation
import UMSHMobileCore

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
        precondition(inspectUlcpProperties(responses: [
            ulcpPropertyRecord(propertyId: id.illuminance, value: bytes(UInt32(320_000)))
        ]).illuminanceMillilux == 320_000)
        precondition(inspectUlcpProperties(responses: [
            ulcpPropertyRecord(propertyId: id.illuminance, value: Data())
        ]).illuminanceMillilux == nil)
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        var reading = RemoteCategoryReading()
        reading.absorb([
            id.time: bytes(UInt32(1_800_000_000)),
            id.uptime: bytes(UInt32(600)),
            id.tzOffset: bytes(Int16(0)),
        ], at: start, fromAir: true)

        // Apply's setting echoes and periodic pushes must not rewind either
        // extrapolated clock, even when they arrive repeatedly.
        for seconds in 1...60 {
            reading.absorb([
                id.tzOffset: bytes(Int16(-420)),
                id.gnssTimeTrust: Data([1]),
            ], at: start.addingTimeInterval(Double(seconds)), fromAir: true)
        }
        precondition(reading.receivedAt[id.time] == start)
        precondition(reading.receivedAt[id.uptime] == start)
        precondition(reading.asOf == start.addingTimeInterval(60))
        let uptime = Double(reading.properties.uptimeSeconds!)
            + start.addingTimeInterval(60).timeIntervalSince(reading.receivedAt[id.uptime]!)
        precondition(uptime == 660)

        // The same merge is used by Statistics after a counter reset.
        reading.absorb([id.statTxPackets: bytes(UInt32(0))],
                       at: start.addingTimeInterval(70), fromAir: true)
        precondition(reading.receivedAt[id.uptime] == start)

        // A fresh clock sample replaces its own date without moving uptime.
        let later = start.addingTimeInterval(80)
        reading.absorb([id.time: bytes(UInt32(1_800_000_080))], at: later, fromAir: true)
        precondition(reading.receivedAt[id.time] == later)
        precondition(reading.receivedAt[id.uptime] == start)

        // Cached samples retain individual dates instead of borrowing the
        // category's oldest date.
        var cached = RemoteCategoryReading()
        cached.absorb([
            id.tzOffset: bytes(Int16(-420)), id.uptime: bytes(UInt32(600)),
        ], at: start, fromAir: false, sampleDates: [id.tzOffset: later, id.uptime: start])
        precondition(cached.receivedAt[id.uptime] == start)
        precondition(cached.receivedAt[id.tzOffset] == later)
        precondition(!cached.isFresh)

        // Applying settings with a cached time present never sends PROP_TIME.
        let settings = try ulcpDirtyWrites(
            desired: reading.properties, dirtyPropertyIds: [id.tzOffset, id.gnssTimeTrust]
        )
        precondition(Set(settings.map(\.propertyId)) == [id.tzOffset, id.gnssTimeTrust])
        let clock = try ulcpDirtyWrites(desired: reading.properties, dirtyPropertyIds: [id.time])
        precondition(clock.count == 1 && clock[0].propertyId == id.time)
        precondition(clock[0].value == bytes(UInt32(1_800_000_080)))

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
        precondition(RemoteTemperaturePresentation.format(.max, locale: celsius) == "Unavailable")
        let temperatureOnly = try ulcpCategoryProperties(category: .sensors, capabilities: Data([61]))
        precondition(temperatureOnly == [id.temperatures, id.temperatureNames])
        precondition(!isPersistentManagedProperty(id.temperatures))
        precondition(!isPersistentManagedProperty(id.temperatureNames))
        precondition(!isPersistentManagedProperty(id.illuminance))
        precondition(isPersistentManagedProperty(id.deviceName))
        let date = Date(timeIntervalSince1970: 1_800_000_000)
        func names(_ values: [String]) -> Data {
            values.reduce(into: Data()) { $0.append(UInt8($1.utf8.count)); $0.append(Data($1.utf8)) }
        }
        var reading = RemoteCategoryReading()
        reading.absorb([id.temperatures: Data([0xA5,0x0B,0xFF,0xFF])], at: date, fromAir: true)
        // Appended labels arrive later than the sampled inventory.
        reading.absorb([id.temperatureNames: names(["Die", "Die", "電池"])], at: date.addingTimeInterval(5), fromAir: true)
        let grown = RemoteTemperaturePresentation(reading: reading, locale: celsius)
        precondition(grown.sampledAt == date)
        precondition(grown.rows.map(\.id) == [0,1,2])
        precondition(grown.rows.map(\.name) == ["Die","Die","電池"])
        precondition(grown.rows.map(\.value) == ["25.0°C","Unavailable","Not read"])
        precondition(grown.problem == nil)
        for labels in [names(["Die"]), Data([3,65]), Data([0])] {
            reading.absorb([id.temperatureNames: labels], at: date, fromAir: true)
            let presentation = RemoteTemperaturePresentation(reading: reading, locale: celsius)
            precondition(presentation.rows.map(\.name) == ["Temperature 1","Temperature 2"])
            precondition(presentation.rows.map(\.value) == ["25.0°C","Unavailable"])
            precondition(presentation.problem != nil)
        }
        var missing = RemoteCategoryReading()
        missing.absorb([id.temperatures: Data([0,0])], at: date, fromAir: true)
        missing.refused.insert(id.temperatureNames)
        precondition(RemoteTemperaturePresentation(reading: missing).rows[0].name == "Temperature 1")
        precondition(RemoteTemperaturePresentation(reading: missing).problem != nil)
        var failed = RemoteCategoryReading()
        failed.failures[id.temperatures] = "Timeout"
        precondition(RemoteTemperaturePresentation(reading: failed).state == "Read failed")
        failed.failures = [:]
        failed.absorb([id.temperatures: Data([0])], at: date, fromAir: true)
        precondition(RemoteTemperaturePresentation(reading: failed).state == "Invalid reading")
        failed.absorb([id.temperatures: Data(), id.temperatureNames: Data()], at: date, fromAir: true)
        precondition(RemoteTemperaturePresentation(reading: failed).state == "No temperature sensors")
        precondition(RemoteTemperaturePresentation(reading: nil).state == "Not read")
    }

    static func bytes<T: FixedWidthInteger>(_ value: T) -> Data {
        withUnsafeBytes(of: value.littleEndian) { Data($0) }
    }
}
