import Foundation
import OSLog
import UMSHMobileCore

/// One line this process logged, as the system log store returns it.
/// Private values arrive as `<private>`.
struct DiagnosticsEntry: Identifiable, Equatable, Sendable {
    enum Level: String, Sendable {
        case undefined, debug, info, notice, error, fault

        init(_ level: OSLogEntryLog.Level) {
            self = switch level {
            case .debug: .debug
            case .info: .info
            case .notice: .notice
            case .error: .error
            case .fault: .fault
            case .undefined: .undefined
            @unknown default: .undefined
            }
        }

        var isError: Bool { self == .error || self == .fault }
    }

    /// Its place in the read, oldest first.
    let id: Int
    let date: Date
    let level: Level
    let subsystem: String
    let category: String
    let message: String
}

/// What an export says about the app and its radio above the log lines.
/// Every field is a fact for support, in fixed English, never display text.
struct DiagnosticsHeader: Equatable, Sendable {
    var app: String
    var os: String
    var device: String
    var coreAPI: UInt16
    var launched: Date
    var exported: Date
    /// The radio link's state name; `idle` with no radio.
    var radioLink: String
    var radioFirmware: String?
    var radioModel: String?
    var ulcp: UlcpProtocolVersionRecord?
    /// Capability codes, or `nil` when the radio has not been read.
    var capabilities: [UInt32]?
    var phy: Phy?

    struct Phy: Equatable, Sendable {
        var frequencyKHz: UInt32
        var bandwidthHz: UInt32?
        var spreadingFactor: UInt8?
        var codingRateDenominator: UInt8?
        var transmitPowerDBm: Int8
    }
}

extension DiagnosticsHeader {
    /// The header for this app, process and radio, exported now.
    init(radio: RadioSnapshot, launched: Date, exported: Date) {
        let provisioning = radio.provisioning
        self.init(
            app: Self.appVersion,
            os: Self.osVersion,
            device: Self.deviceModel,
            coreAPI: mobileApiVersion(),
            launched: launched,
            exported: exported,
            radioLink: radio.linkState.rawValue,
            radioFirmware: provisioning?.deviceVersion,
            radioModel: provisioning?.deviceModel,
            ulcp: provisioning?.protocolVersion,
            capabilities: provisioning?.capabilities,
            phy: provisioning.map {
                Phy(
                    frequencyKHz: $0.frequencyKHz,
                    bandwidthHz: $0.bandwidthHz,
                    spreadingFactor: $0.spreadingFactor,
                    codingRateDenominator: $0.codingRateDenominator,
                    transmitPowerDBm: $0.transmitPowerDBm
                )
            }
        )
    }

    /// The app's version and build, such as `0.1 (1)`.
    static var appVersion: String {
        let info = Bundle.main.infoDictionary ?? [:]
        let version = info["CFBundleShortVersionString"] as? String ?? "?"
        let build = info["CFBundleVersion"] as? String ?? "?"
        return "\(version) (\(build))"
    }

    /// The system's version and build, such as `26.1.0 (23B74)`; on the
    /// simulator, the simulated runtime's build.
    static var osVersion: String {
        let version = ProcessInfo.processInfo.operatingSystemVersion
        let number = "\(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
        if let simulated = ProcessInfo.processInfo.environment["SIMULATOR_RUNTIME_BUILD_VERSION"] {
            return "\(number) (\(simulated))"
        }
        var size = 0
        guard sysctlbyname("kern.osversion", nil, &size, nil, 0) == 0, size > 0 else { return number }
        var build = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.osversion", &build, &size, nil, 0) == 0 else { return number }
        let octets = build.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return "\(number) (\(String(decoding: octets, as: UTF8.self)))"
    }

    /// The hardware model identifier, such as `iPhone17,1`; on the
    /// simulator, the model it simulates.
    static var deviceModel: String {
        if let simulated = ProcessInfo.processInfo.environment["SIMULATOR_MODEL_IDENTIFIER"] {
            return simulated
        }
        var system = utsname()
        uname(&system)
        return withUnsafeBytes(of: &system.machine) { bytes in
            String(decoding: bytes.prefix { $0 != 0 }, as: UTF8.self)
        }
    }
}

/// Reads this process's log lines and writes them out for support.
enum DiagnosticsLog {
    /// The most lines held, newest kept.
    static let entryLimit = 2_000

    /// When this process started its app delegate. Touched first thing in
    /// `AppDelegate.init`, so it is set before anything logs.
    static let launchDate = Date()

    /// Every subsystem the app and its core log under.
    static let subsystemPrefix = "com.voria.umsh"

    /// Reads this process's lines since `launch`, oldest first, keeping
    /// the newest `limit`. Runs off the caller's actor: a read can take a
    /// second or more.
    static func read(since launch: Date, limit: Int = entryLimit) async throws -> [DiagnosticsEntry] {
        try await Task.detached(priority: .userInitiated) {
            let store = try OSLogStore(scope: .currentProcessIdentifier)
            let lines = try store.getEntries(
                at: store.position(date: launch),
                matching: NSPredicate(format: "subsystem BEGINSWITH %@", subsystemPrefix)
            )
            var entries: [DiagnosticsEntry] = []
            for case let line as OSLogEntryLog in lines {
                entries.append(
                    DiagnosticsEntry(
                        id: entries.count,
                        date: line.date,
                        level: .init(line.level),
                        subsystem: line.subsystem,
                        category: line.category,
                        message: line.composedMessage
                    )
                )
            }
            return newest(entries, limit: limit)
        }.value
    }

    /// The last `limit` of `entries`, in their order.
    static func newest(_ entries: [DiagnosticsEntry], limit: Int) -> [DiagnosticsEntry] {
        Array(entries.suffix(max(limit, 0)))
    }

    /// The export's text: the header, a blank line, then one line per
    /// entry in the order given.
    static func export(header: DiagnosticsHeader, entries: [DiagnosticsEntry]) -> String {
        var lines = [
            "UMSH diagnostics",
            "app: \(header.app)",
            "ios: \(header.os)",
            "device: \(header.device)",
            "core-api: \(header.coreAPI)",
            "launched: \(timestamp(header.launched))",
            "exported: \(timestamp(header.exported))",
            "radio-link: \(header.radioLink)",
        ]
        if let firmware = header.radioFirmware {
            lines.append("radio-firmware: \(escaped(firmware))")
        }
        if let model = header.radioModel {
            lines.append("radio-model: \(escaped(model))")
        }
        if let ulcp = header.ulcp {
            lines.append("ulcp: \(ulcp.major).\(ulcp.minor)")
        }
        if let capabilities = header.capabilities {
            let codes = capabilities.sorted().map(String.init).joined(separator: ",")
            lines.append("capabilities: \(codes.isEmpty ? "none" : codes)")
        }
        if let phy = header.phy {
            var fields = ["freq=\(phy.frequencyKHz)kHz"]
            if let bandwidth = phy.bandwidthHz { fields.append("bw=\(bandwidth)Hz") }
            if let factor = phy.spreadingFactor { fields.append("sf=\(factor)") }
            if let rate = phy.codingRateDenominator { fields.append("cr=4/\(rate)") }
            fields.append("tx=\(phy.transmitPowerDBm)dBm")
            lines.append("phy: \(fields.joined(separator: " "))")
        }
        lines.append("entries: \(entries.count)")
        lines.append("")
        for entry in entries {
            lines.append(
                "\(timestamp(entry.date)) \(entry.level.rawValue) \(entry.subsystem)/\(entry.category) \(escaped(entry.message))"
            )
        }
        return lines.joined(separator: "\n") + "\n"
    }

    /// Writes the export as `<file name>.txt` into `folder`, emptied
    /// first, so at most one export stays on disk.
    static func write(header: DiagnosticsHeader, entries: [DiagnosticsEntry], into folder: URL) throws -> URL {
        let manager = FileManager.default
        if manager.fileExists(atPath: folder.path(percentEncoded: false)) {
            try manager.removeItem(at: folder)
        }
        try manager.createDirectory(at: folder, withIntermediateDirectories: true)
        let file = folder.appending(path: "\(fileName(at: header.exported)).txt", directoryHint: .notDirectory)
        try Data(export(header: header, entries: entries).utf8).write(to: file, options: .atomic)
        return file
    }

    /// The export's file name, without extension, for an export made at
    /// `date` in `timeZone`.
    static func fileName(at date: Date, timeZone: TimeZone = .current, locale: Locale = .current) -> String {
        let style = Date.VerbatimFormatStyle(
            format: "\(year: .defaultDigits)-\(month: .twoDigits)-\(day: .twoDigits) \(hour: .twoDigits(clock: .twentyFourHour, hourCycle: .zeroBased))\(minute: .twoDigits)",
            locale: Locale(identifier: "en_US_POSIX"),
            timeZone: timeZone,
            calendar: Calendar(identifier: .gregorian)
        )
        let stamp = date.formatted(style)
        return String(localized: "UMSH Diagnostics \(stamp)", locale: locale, comment: "File name of an exported diagnostics log, without extension. The placeholder is a date and time, such as 2026-11-21 2204.")
    }

    /// ISO 8601 in UTC, to the nearest millisecond. The style truncates,
    /// and a time read back from text can sit a hair below its millisecond.
    static func timestamp(_ date: Date) -> String {
        date.addingTimeInterval(0.000_5)
            .formatted(Date.ISO8601FormatStyle(includingFractionalSeconds: true, timeZone: .gmt))
    }

    /// One line per entry: backslashes, newlines and carriage returns are
    /// written as escapes.
    static func escaped(_ text: String) -> String {
        text.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r")
    }
}
