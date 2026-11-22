import Foundation
import OSLog
import UMSHMobileCore

extension AppRuntime {
    /// Reload every peer and transcript from storage.
    ///
    /// A full read takes the peers and neighbor reports too. Chat submission
    /// and read cursors only reload conversation summaries; neither
    /// operation changes peer identity or map metadata.
    /// Callers arriving before a queued reload has begun join it instead of
    /// adding another; a caller arriving mid-reload gets a fresh one chained
    /// behind it. Either way `await` still returns only once state observed
    /// after the call has been published, which senders rely on.
    func reloadApplicationState() async {
        await reloadApplicationState(includingPeers: true)
    }

    func reloadConversationState() async {
        await reloadApplicationState(includingPeers: false)
    }

    private func reloadApplicationState(includingPeers: Bool) async {
        coordinator.pendingReloadIncludesPeers = coordinator.pendingReloadIncludesPeers || includingPeers
        if let pending = coordinator.pendingReload {
            await pending.value
            return
        }
        let running = coordinator.runningReload
        let task = Task { @MainActor in
            await running?.value
            let includingPeers = coordinator.pendingReloadIncludesPeers
            coordinator.pendingReloadIncludesPeers = false
            coordinator.pendingReload = nil
            await performApplicationStateReload(includingPeers: includingPeers)
        }
        coordinator.pendingReload = task
        coordinator.runningReload = task
        await task.value
    }

    /// Run `body` in turn with the reloads: after every reload queued before
    /// it, and before any queued after it, so no reload publishes the lists
    /// between its steps.
    func inReloadOrder<Result: Sendable>(
        _ body: @escaping @MainActor () async -> Result
    ) async -> Result {
        let running = coordinator.runningReload
        let work = Task { @MainActor in
            await running?.value
            return await body()
        }
        coordinator.runningReload = Task { _ = await work.value }
        return await work.value
    }

    func performApplicationStateReload(includingPeers: Bool) async {
        guard core != nil, let owner = localIdentity?.id, !Task.isCancelled else { return }
        do {
            var full = includingPeers
            let conversationsOnly = !full
            let nameRevision = advertisedNameRevision
            var record = try await read { try $0.state(conversationsOnly: conversationsOnly) }
            // A structural change while the request waited requires a full
            // read, rather than silently dropping a conversation.
            let knownIDs = Set(peers.map(\.id))
            if !full, record.directConversations.contains(where: { !knownIDs.contains($0.peer.stored.id) }) {
                full = true
                record = try await read { try $0.state(conversationsOnly: false) }
            }
            var loaded = MappedApplicationState(record, chatRevisions: coordinator.chatRevisions)
            guard localIdentity?.id == owner, !Task.isCancelled else { return }
            for index in loaded.conversations.indices {
                let key = ConversationDraftKey(owner: owner, address: loaded.conversations[index].conversationAddress)
                if let text = drafts.pendingText(for: key) { loaded.conversations[index].draftText = text }
            }
            for index in loaded.channelConversations.indices {
                let key = ConversationDraftKey(owner: owner, address: loaded.channelConversations[index].conversationAddress)
                if let text = drafts.pendingText(for: key) { loaded.channelConversations[index].draftText = text }
            }
            // Assign only on a real change: most reloads are triggered by
            // radio or chat activity that leaves the displayed state
            // identical, and an equal-value write to an observed property
            // still invalidates everything that reads it.
            if let read = loaded.peers, peers != read { peers = read }
            if channels != loaded.channels { channels = loaded.channels }
            if let read = loaded.neighborReports, neighborReports != read { neighborReports = read }
            if conversations != loaded.conversations { conversations = loaded.conversations }
            if channelConversations != loaded.channelConversations { channelConversations = loaded.channelConversations }
            // A name saved while the read ran is newer than the one it read.
            let name = loaded.advertisedName ?? ""
            if advertisedNameRevision == nameRevision, advertisedName != name {
                advertisedName = name
            }
            if full, failedReadAddress == nil { stateLoadError = nil }
        } catch is CancellationError {
            return
        } catch MobileAppError.Store(let error) {
            Self.logger.error("Could not reload application state: \(String(describing: error), privacy: .public)")
            stateLoadError = .persistence("Stored information could not be refreshed. Your last loaded information is still shown.")
        } catch {
            // No owner yet, or the core busy or stopped: the lists stand
            // until a read can be made.
            Self.logger.debug("State not read: \(String(describing: error), privacy: .public)")
        }
    }

    /// Run one of the core's synchronous queries off the main actor.
    func read<T: Sendable>(
        _ body: @escaping @Sendable (MobileAppCore) throws -> T
    ) async throws -> T {
        guard let core else { throw MobileAppError.Stopped }
        return try await Task.detached(priority: .userInitiated) { try body(core) }.value
    }
}
