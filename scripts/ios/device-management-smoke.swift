import Foundation
import UMSHMobileCore

@main
struct DeviceManagementSmokeTest {
    static func main() throws {
        let id = ulcpProperties
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

    static func bytes<T: FixedWidthInteger>(_ value: T) -> Data {
        withUnsafeBytes(of: value.littleEndian) { Data($0) }
    }
}
