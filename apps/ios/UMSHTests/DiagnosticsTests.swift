import Foundation
import OSLog
import Testing
import UMSHMobileCore
@testable import UMSH

private func utc(_ text: String) throws -> Date {
    try Date(text, strategy: Date.ISO8601FormatStyle(includingFractionalSeconds: true, timeZone: .gmt))
}

private func logLine(
    _ id: Int,
    _ date: Date,
    _ message: String,
    level: DiagnosticsEntry.Level = .notice,
    category: String = "UlcpDevice"
) -> DiagnosticsEntry {
    DiagnosticsEntry(
        id: id,
        date: date,
        level: level,
        subsystem: "com.voria.umsh.ios",
        category: category,
        message: message
    )
}

private func fullHeader() throws -> DiagnosticsHeader {
    DiagnosticsHeader(
        app: "0.1 (1)",
        os: "26.1.0 (23B74)",
        device: "iPhone17,1",
        coreAPI: 92,
        launched: try utc("2026-11-21T22:04:31.123Z"),
        exported: try utc("2026-11-21T22:31:02.004Z"),
        radioLink: "ready",
        radioFirmware: "fw-2026.11.02",
        radioModel: "T-Echo",
        ulcp: UlcpProtocolVersionRecord(major: 6, minor: 1),
        capabilities: [9, 1, 5, 2],
        phy: .init(
            frequencyKHz: 906_875,
            bandwidthHz: 250_000,
            spreadingFactor: 11,
            codingRateDenominator: 5,
            transmitPowerDBm: 22
        )
    )
}

struct DiagnosticsTests {
    @Test func theExportIsTheHeaderThenOneLinePerEntry() throws {
        let entries = [
            logLine(0, try utc("2026-11-21T22:04:31.123Z"), "attached"),
            logLine(1, try utc("2026-11-21T22:05:00.000Z"), "the link dropped: <private>", level: .error, category: "umsh_mobile_core::radio_driver"),
        ]
        let text = DiagnosticsLog.export(header: try fullHeader(), entries: entries)
        #expect(text == """
        UMSH diagnostics
        app: 0.1 (1)
        ios: 26.1.0 (23B74)
        device: iPhone17,1
        core-api: 92
        launched: 2026-11-21T22:04:31.123Z
        exported: 2026-11-21T22:31:02.004Z
        radio-link: ready
        radio-firmware: fw-2026.11.02
        radio-model: T-Echo
        ulcp: 6.1
        capabilities: 1,2,5,9
        phy: freq=906875kHz bw=250000Hz sf=11 cr=4/5 tx=22dBm
        entries: 2

        2026-11-21T22:04:31.123Z notice com.voria.umsh.ios/UlcpDevice attached
        2026-11-21T22:05:00.000Z error com.voria.umsh.ios/umsh_mobile_core::radio_driver the link dropped: <private>

        """)
    }

    @Test func unknownRadioFactsAreLeftOut() throws {
        var header = try fullHeader()
        header.radioLink = "idle"
        header.radioFirmware = nil
        header.radioModel = nil
        header.ulcp = nil
        header.capabilities = nil
        header.phy = nil
        let text = DiagnosticsLog.export(header: header, entries: [])
        #expect(text == """
        UMSH diagnostics
        app: 0.1 (1)
        ios: 26.1.0 (23B74)
        device: iPhone17,1
        core-api: 92
        launched: 2026-11-21T22:04:31.123Z
        exported: 2026-11-21T22:31:02.004Z
        radio-link: idle
        entries: 0


        """)
    }

    @Test func aPartlyKnownPhyAndNoCapabilitiesReadAsSuch() throws {
        var header = try fullHeader()
        header.capabilities = []
        header.phy = .init(
            frequencyKHz: 915_000,
            bandwidthHz: nil,
            spreadingFactor: nil,
            codingRateDenominator: nil,
            transmitPowerDBm: -4
        )
        let text = DiagnosticsLog.export(header: header, entries: [])
        #expect(text.contains("\ncapabilities: none\n"))
        #expect(text.contains("\nphy: freq=915000kHz tx=-4dBm\n"))
    }

    @Test func eachEntryStaysOnOneLine() throws {
        let date = try utc("2026-11-21T22:04:31.123Z")
        let text = DiagnosticsLog.export(
            header: try fullHeader(),
            entries: [logLine(0, date, "first\nsecond\r\nthird \\n literal")]
        )
        let last = try #require(text.split(separator: "\n").last)
        #expect(last == #"2026-11-21T22:04:31.123Z notice com.voria.umsh.ios/UlcpDevice first\nsecond\r\nthird \\n literal"#)
    }

    @Test func theCapKeepsTheNewest() throws {
        let start = try utc("2026-11-21T22:00:00.000Z")
        let entries = (0..<10).map { logLine($0, start.addingTimeInterval(Double($0)), "line \($0)") }
        #expect(DiagnosticsLog.newest(entries, limit: 3).map(\.id) == [7, 8, 9])
        #expect(DiagnosticsLog.newest(entries, limit: 20).map(\.id) == Array(0..<10))
        #expect(DiagnosticsLog.newest(entries, limit: 0).isEmpty)
        #expect(DiagnosticsLog.entryLimit == 2_000)
    }

    @Test func onlyErrorsAndFaultsAreErrors() {
        #expect(DiagnosticsEntry.Level.error.isError)
        #expect(DiagnosticsEntry.Level.fault.isError)
        #expect(!DiagnosticsEntry.Level.notice.isError)
        #expect(!DiagnosticsEntry.Level.info.isError)
        #expect(!DiagnosticsEntry.Level.debug.isError)
        #expect(!DiagnosticsEntry.Level.undefined.isError)
    }

    @Test func theFileNameCarriesTheLocalDateAndMinute() throws {
        let date = try utc("2026-11-21T22:04:31.123Z")
        let name = DiagnosticsLog.fileName(
            at: date,
            timeZone: try #require(TimeZone(identifier: "America/Los_Angeles")),
            locale: Locale(identifier: "en_US")
        )
        #expect(name == "UMSH Diagnostics 2026-11-21 1404")
    }

    @Test func theHeaderTakesTheRadiosFactsButNotItsName() throws {
        var radio = RadioSnapshot.previewReady
        radio.name = "Kitchen Radio"
        radio.provisioning?.deviceVersion = "fw-2026.11.02"
        radio.provisioning?.deviceModel = "T-Echo"
        radio.provisioning?.protocolVersion = UlcpProtocolVersionRecord(major: 6, minor: 1)
        radio.provisioning?.capabilities = [3, 1]
        let launched = try utc("2026-11-21T22:04:31.123Z")
        let exported = try utc("2026-11-21T22:31:02.004Z")
        let header = DiagnosticsHeader(radio: radio, launched: launched, exported: exported)
        #expect(header.coreAPI == mobileApiVersion())
        #expect(header.radioLink == "ready")
        #expect(header.radioFirmware == "fw-2026.11.02")
        #expect(header.ulcp == UlcpProtocolVersionRecord(major: 6, minor: 1))
        #expect(header.capabilities == [3, 1])
        #expect(header.phy?.frequencyKHz == 915_000)
        let text = DiagnosticsLog.export(header: header, entries: [])
        #expect(text.contains("\ncapabilities: 1,3\n"))
        #expect(!text.contains("Kitchen Radio"))
        #expect(!text.contains("F2A1073A"))

        let noRadio = DiagnosticsHeader(radio: .idle, launched: launched, exported: exported)
        #expect(noRadio.radioLink == "idle")
        #expect(noRadio.os.hasPrefix("\(ProcessInfo.processInfo.operatingSystemVersion.majorVersion)."))
        #expect(noRadio.radioFirmware == nil)
        #expect(noRadio.capabilities == nil)
        #expect(noRadio.phy == nil)
    }

    @Test func aWriteLeavesOnlyTheNewestExport() throws {
        let folder = URL.temporaryDirectory
            .appending(path: "DiagnosticsTests-\(UUID().uuidString)", directoryHint: .isDirectory)
        defer { try? FileManager.default.removeItem(at: folder) }
        var header = try fullHeader()
        let entries = [logLine(0, try utc("2026-11-21T22:04:31.123Z"), "attached")]
        let first = try DiagnosticsLog.write(header: header, entries: entries, into: folder)
        header.exported = try utc("2026-11-21T23:15:00.000Z")
        let second = try DiagnosticsLog.write(header: header, entries: entries, into: folder)

        #expect(second.pathExtension == "txt")
        #expect(second.deletingPathExtension().lastPathComponent == DiagnosticsLog.fileName(at: header.exported))
        #expect(first != second)
        let left = try FileManager.default.contentsOfDirectory(atPath: folder.path(percentEncoded: false))
        #expect(left == [second.lastPathComponent])
        let text = try String(contentsOf: second, encoding: .utf8)
        #expect(text == DiagnosticsLog.export(header: header, entries: entries))
        #expect(text.contains("\nexported: 2026-11-21T23:15:00.000Z\n"))
    }

    @Test func theReaderSeesThisProcesssLines() async throws {
        let since = Date.now.addingTimeInterval(-1)
        let marker = UUID().uuidString
        Logger(subsystem: "com.voria.umsh.ios", category: "DiagnosticsTests")
            .notice("diagnostics marker \(marker, privacy: .public)")
        Logger(subsystem: "com.example.elsewhere", category: "DiagnosticsTests")
            .notice("diagnostics marker \(marker, privacy: .public)")
        let entries = try await DiagnosticsLog.read(since: since)
        let found = entries.filter { $0.message.contains(marker) }
        #expect(found.count == 1)
        #expect(found.first?.subsystem == "com.voria.umsh.ios")
        #expect(found.first?.category == "DiagnosticsTests")
        #expect(found.first?.level == .notice)
        #expect(entries.map(\.id) == Array(entries.indices))
    }
}
