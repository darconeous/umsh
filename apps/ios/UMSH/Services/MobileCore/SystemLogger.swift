import Foundation
import OSLog
import UMSHMobileCore

/// Sends the Rust core's log records to the unified logging system.
///
/// Each record's message is public; its fields hold addresses, locations,
/// or message text, and are logged private.
final class SystemLogger: MobileLogger {
    /// Installed once, at launch, before anything in the core can log.
    static func install() {
        #if DEBUG
        setLogger(logger: SystemLogger(), level: .debug)
        #else
        setLogger(logger: SystemLogger(), level: .info)
        #endif
    }

    func log(record: MobileLogRecord) {
        let logger = Logger(subsystem: "com.voria.umsh.core", category: record.target)
        let type = Self.type(record.level)
        if record.privateFields.isEmpty {
            logger.log(level: type, "\(record.message, privacy: .public)")
        } else {
            let fields = record.privateFields
                .map { "\($0.key)=\($0.value)" }
                .joined(separator: " ")
            logger.log(
                level: type,
                "\(record.message, privacy: .public) \(fields, privacy: .private)"
            )
        }
    }

    private static func type(_ level: MobileLogLevel) -> OSLogType {
        switch level {
        case .error, .warn: .error
        case .info: .default
        case .debug, .trace: .debug
        }
    }
}
