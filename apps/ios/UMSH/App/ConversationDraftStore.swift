import Foundation

/// A conversation's draft, under the identity that wrote it.
struct ConversationDraftKey: Hashable, Sendable {
    let owner: String
    /// The conversation's address, direct or channel.
    let address: String
}

/// Serializes writes per conversation and keeps unsaved text available across
/// screen changes. The runtime owns these tasks and cancels them on stop.
@MainActor
final class ConversationDraftStore {
    private struct Entry {
        let revision: UUID
        let text: String
        let task: Task<AppOperationResult, Never>
        /// The write finished and failed: nothing waits on it any more.
        var failed = false
    }
    private let write: @Sendable (ConversationDraftKey, String) async throws -> Void
    private var entries: [ConversationDraftKey: Entry] = [:]
    /// The text last handed to the core to send, per key. The core writes it
    /// as the draft and clears it once the message is kept; a save of the
    /// same text after the tap (a debounce already under way, the flush on
    /// leaving) would land after that clear and bring the sent words back.
    private var submitted: [ConversationDraftKey: String] = [:]
    private var isStopped = false

    /// The identity the core writes for. A write queued under another is
    /// dropped when its turn comes rather than handed to the core, which
    /// would keep it as this one's draft; what is held for another is let go.
    var owner: String? {
        didSet {
            guard owner != oldValue else { return }
            entries = entries.filter { $0.key.owner == owner }
            submitted = submitted.filter { $0.key.owner == owner }
        }
    }

    init(write: @escaping @Sendable (ConversationDraftKey, String) async throws -> Void) {
        self.write = write
    }

    /// Text handed in for `key` that is not known to be stored: a write
    /// under way, or one that failed.
    func pendingText(for key: ConversationDraftKey) -> String? { entries[key]?.text }

    /// Wait until every write already handed in for `key` has landed or
    /// failed, so a write made after this cannot be overtaken by one of them.
    func settle(_ key: ConversationDraftKey) async {
        _ = await entries[key]?.task.value
    }

    /// Text handed to the core to send, and the write held for its key at
    /// that moment.
    struct Submission {
        let key: ConversationDraftKey
        let text: String
        fileprivate let held: UUID?
    }

    /// Hand `text` to the core to send: from now on a save of exactly `text`
    /// for `key` is dropped, until a save of other text or ``withdraw(_:)``.
    /// Then wait for the writes already handed in, as ``settle(_:)`` does.
    @discardableResult
    func submit(_ text: String, for key: ConversationDraftKey) async -> Submission {
        submitted[key] = text
        let held = entries[key]?.revision
        await settle(key)
        return Submission(key: key, text: text, held: held)
    }

    /// The send was refused with nothing kept: the words are the draft
    /// again, and saving them is no longer dropped.
    func withdraw(_ submission: Submission) {
        if submitted[submission.key] == submission.text { submitted[submission.key] = nil }
    }

    /// Whether a save of `text` for `key` would be dropped as the words of a
    /// send under way or done.
    func isSubmitted(_ text: String, for key: ConversationDraftKey) -> Bool {
        submitted[key] == text
    }

    /// The core kept the message and cleared its draft. The write held when
    /// the text was handed in has finished, and if it failed, its words,
    /// whatever they were, are older than the core's write of the sent text:
    /// they must not come back as a draft. A write made since is the
    /// composer's newer text and stays, so later writes stay behind it.
    func forget(_ submission: Submission) {
        guard let held = submission.held, entries[submission.key]?.revision == held else { return }
        entries[submission.key] = nil
    }

    func save(_ text: String, for key: ConversationDraftKey) async -> AppOperationResult {
        guard !Task.isCancelled else { return .failure(.cancelled) }
        if let sent = submitted[key] {
            // The core holds these words; storing them again could undo its clear.
            if sent == text { return .success(()) }
            submitted[key] = nil
        }
        guard !isStopped, key.owner == owner else { return .failure(.cancelled) }
        let previous = entries[key]?.task
        let revision = UUID()
        let task = Task { [write] in
            _ = await previous?.value
            do {
                try Task.checkCancellation()
                // Checked here, on the main actor that changes the owner, so
                // the core takes the write for the identity it was made under.
                guard key.owner == self.owner else { throw CancellationError() }
                try await write(key, text)
                return AppOperationResult.success(())
            } catch is CancellationError {
                return .failure(.cancelled)
            } catch { return .failure(AppOperationError.storage(error)) }
        }
        entries[key] = Entry(revision: revision, text: text, task: task)
        let result = await task.value
        if entries[key]?.revision == revision {
            switch result {
            case .success: entries[key] = nil
            // A failed write stays, so the words stay on screen until one lands.
            case .failure: entries[key]?.failed = true
            }
        }
        return result
    }

    func stop() {
        isStopped = true
        for entry in entries.values { entry.task.cancel() }
    }
}
