import Foundation
import UMSHMobileCore

/// A send, then the draft. The core keeps the message before releasing it
/// to the radio and finishes the send even if the view leaves, so all that
/// is left here is the draft: cleared only once the message is submitted.
/// A cleanup failure after that is a submitted message with a warning,
/// never a failed send that invites the caller to send it twice.
@MainActor
struct ChatSubmissionCoordinator {
    enum Outcome: Equatable {
        case submitted(warning: AppOperationError? = nil)
        case failed(AppOperationError)
    }

    func submit(
        send: () async throws -> Void,
        didChange: () async -> Void,
        clearDraft: () async throws -> Void
    ) async -> Outcome {
        do {
            try Task.checkCancellation()
            try await send()
        } catch is CancellationError {
            return .failed(.cancelled)
        } catch let error as MobileChatSendError {
            // Some failures leave a stored message behind, marked failed.
            await didChange()
            return .failed(Self.sendError(error))
        } catch {
            return .failed(.operation("The message could not be sent: \(error)"))
        }
        await didChange()
        do { try await clearDraft() }
        catch {
            return .submitted(warning: .persistence("The message was submitted, but the draft could not be cleared. Do not resend it."))
        }
        return .submitted()
    }

    nonisolated static func sendError(_ error: MobileChatSendError) -> AppOperationError {
        switch error {
        case let .NotComposed(error):
            composeError(error)
        case .NotSaved:
            .persistence("Changes could not be saved. Please try again.")
        case .NotSavedOrReset:
            .operation("The message was not sent. Its pending radio operation could not be reset. Reconnect before retrying.")
        case let .NotQueued(error):
            .operation("The message could not be queued for transmission: \(error)")
        case .NotQueuedOrRecorded:
            .persistence("The message could not be queued, and its failure could not be saved. Reconnect and check the transcript before retrying.")
        case .NoStore:
            .unavailable("Connect a companion radio configured for this phone before sending.")
        }
    }

    nonisolated static func composeError(_ error: MobileMeshError) -> AppOperationError {
        switch error {
        case .InvalidPeer, .InvalidChannelKey, .UnknownConversation, .InvalidLocation, .InvalidRequest,
             .InvalidRoute:
            .validation("The message's recipient or request is invalid. Check the conversation before retrying.")
        case .SessionUnavailable:
            .unavailable("Connect a companion radio configured for this phone before sending.")
        case .OperationInProgress:
            .unavailable("The radio is busy. Try again when its current operation finishes.")
        case .CounterPersistenceFailed:
            .persistence("The message could not be prepared safely because its counter could not be saved.")
        case .SendFailed, .ChatComposeFailed, .ChatBatchMissing, .ChannelCapacity, .NoAnswer,
             .ChatResendNotInPlace:
            .operation("The message could not be prepared by the radio session. Check the connection and try again.")
        }
    }
}
