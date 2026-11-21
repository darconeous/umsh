import Foundation

/// Failures at application boundaries. Cancellation is control flow; it must
/// not be presented as a device or storage failure.
enum AppOperationError: Error, Equatable, Sendable, LocalizedError {
    case cancelled
    case unavailable(String)
    case validation(String)
    case persistence(String)
    case operation(String)

    var errorDescription: String? {
        switch self {
        case .cancelled: String(localized: "The operation was canceled.", comment: "A request the person stopped.")
        case let .unavailable(message), let .validation(message),
             let .persistence(message), let .operation(message): message
        }
    }

    static func storage(_ error: any Error) -> Self {
        if error is CancellationError { return .cancelled }
        if let error = error as? Self { return error }
        return .persistence(String(
            localized: "Changes could not be saved.",
            comment: "A write to the phone's database failed."
        ))
    }
}

typealias AppOperationResult = Result<Void, AppOperationError>
