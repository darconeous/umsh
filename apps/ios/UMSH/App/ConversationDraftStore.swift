import Foundation

struct ConversationDraftKey: Hashable, Sendable {
    enum Kind: Sendable { case direct, channel }
    let owner: String
    let kind: Kind
    let id: Int64
}

/// Serializes writes per conversation and keeps unsaved text available across
/// screen changes. The runtime owns these tasks and cancels them on stop.
@MainActor
final class ConversationDraftStore {
    private struct Entry {
        let revision: UUID
        let text: String
        let task: Task<AppOperationResult, Never>
    }
    private let write: @Sendable (ConversationDraftKey, String) async throws -> Void
    private var entries: [ConversationDraftKey: Entry] = [:]
    private var latest: [ConversationDraftKey: String] = [:]
    private var isStopped = false

    init(write: @escaping @Sendable (ConversationDraftKey, String) async throws -> Void) {
        self.write = write
    }

    func pendingText(for key: ConversationDraftKey) -> String? { entries[key]?.text }
    func latestText(for key: ConversationDraftKey) -> String? { latest[key] }

    func save(_ text: String, for key: ConversationDraftKey) async -> AppOperationResult {
        guard !Task.isCancelled else { return .failure(.cancelled) }
        return await write(text, for: key, restoringOnFailure: nil)
    }

    private func write(
        _ text: String, for key: ConversationDraftKey, restoringOnFailure: String?
    ) async -> AppOperationResult {
        guard !isStopped else { return .failure(.cancelled) }
        latest[key] = text
        let previous = entries[key]?.task
        let revision = UUID()
        let task = Task { [write] in
            _ = await previous?.value
            do {
                try Task.checkCancellation()
                try await write(key, text)
                return AppOperationResult.success(())
            } catch { return .failure(AppOperationError.storage(error)) }
        }
        entries[key] = Entry(revision: revision, text: text, task: task)
        let result = await task.value
        if entries[key]?.revision == revision {
            switch result {
            case .success:
                entries[key] = nil
            case .failure:
                if let restoringOnFailure {
                    entries[key] = Entry(revision: revision, text: restoringOnFailure, task: task)
                    latest[key] = restoringOnFailure
                }
            }
        }
        return result
    }

    /// Cleanup after a durable submission: a canceled caller is not a reason
    /// to leave a sent message behind as its own draft, so only runtime
    /// shutdown refuses the write.
    func clear(for key: ConversationDraftKey, preserving text: String) async throws {
        // Sending an older draft must not erase words entered while it was
        // being submitted. The view applies the same rule to its text field.
        if let current = latest[key], current != text { return }
        let result = await write("", for: key, restoringOnFailure: text)
        try result.get()
    }

    func stop() {
        isStopped = true
        for entry in entries.values { entry.task.cancel() }
    }
}
