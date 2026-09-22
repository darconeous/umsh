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
        case .cancelled: "The operation was canceled."
        case let .unavailable(message), let .validation(message),
             let .persistence(message), let .operation(message): message
        }
    }

    static func storage(_ error: any Error) -> Self {
        if error is CancellationError { return .cancelled }
        if let error = error as? Self { return error }
        return .persistence("Changes could not be saved. Please try again.")
    }
}

typealias AppOperationResult = Result<Void, AppOperationError>
