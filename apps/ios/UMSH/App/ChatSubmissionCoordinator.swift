import Foundation
import UMSHMobileCore

/// The compose transaction: persist before releasing frames to the radio.
/// Once released, a cleanup failure is a submitted message with a warning,
/// never a failed send that invites the caller to send it twice.
@MainActor
struct ChatSubmissionCoordinator {
    enum Outcome: Equatable {
        case submitted(warning: AppOperationError? = nil)
        case failed(AppOperationError)
    }

    let persist: (MobileChatComposeBatchRecord) async throws -> Void
    let reject: (UInt64) async throws -> Void
    let release: (UInt64) async throws -> Void
    let markFailed: (MobileChatComposeBatchRecord) async throws -> Void

    func submit(
        compose: () async throws -> MobileChatComposeBatchRecord,
        didChange: () async -> Void,
        clearDraft: () async throws -> Void
    ) async -> Outcome {
        let batch: MobileChatComposeBatchRecord
        do {
            try Task.checkCancellation()
            batch = try await compose()
        } catch is CancellationError { return .failed(.cancelled) }
        catch let error as MobileMeshError { return .failed(Self.composeError(error)) }
        catch { return .failed(.operation("The message could not be composed: \(error)")) }

        do {
            try Task.checkCancellation()
            try await persist(batch)
        } catch {
            // Cleanup remains necessary even when the caller was canceled.
            do { try await reject(batch.batchId) }
            catch {
                return .failed(.operation("The message was not sent. Its pending radio operation could not be reset. Reconnect before retrying."))
            }
            return .failed(AppOperationError.storage(error))
        }
        await didChange()
        // After persistence, finish the transaction even if the view leaves.
        // No cancellation check may strand a durable compose batch here.
        do { try await release(batch.batchId) }
        catch {
            do { try await markFailed(batch) }
            catch {
                await didChange()
                return .failed(.persistence("The message could not be queued, and its failure could not be saved. Reconnect and check the transcript before retrying."))
            }
            await didChange()
            return .failed(.operation("The message could not be queued for transmission: \(error)"))
        }
        do { try await clearDraft() }
        catch {
            return .submitted(warning: .persistence("The message was submitted, but the draft could not be cleared. Do not resend it."))
        }
        return .submitted()
    }

    nonisolated static func composeError(_ error: MobileMeshError) -> AppOperationError {
        switch error {
        case .InvalidPeer, .InvalidChannelKey, .UnknownConversation, .InvalidLocation, .InvalidRequest:
            .validation("The message's recipient or request is invalid. Check the conversation before retrying.")
        case .SessionUnavailable:
            .unavailable("Connect a companion radio configured for this phone before sending.")
        case .OperationInProgress:
            .unavailable("The radio is busy. Try again when its current operation finishes.")
        case .CounterPersistenceFailed:
            .persistence("The message could not be prepared safely because its counter could not be saved.")
        case .SendFailed, .ChatComposeFailed, .ChatBatchMissing, .ChannelCapacity, .NoAnswer:
            .operation("The message could not be prepared by the radio session. Check the connection and try again.")
        }
    }
}
