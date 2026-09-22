import Foundation
import SQLite3
import Testing
import UMSHMobileCore
@testable import UMSH

private enum TestFailure: Error { case unavailable }

private actor TestVault: IdentityVault {
    let stored: StoredIdentity
    var creations = 0
    var adoptions = 0
    init(_ stored: StoredIdentity) { self.stored = stored }
    func storedIdentity() -> StoredIdentity { stored }
    func createIdentity() throws -> LocalIdentitySnapshot {
        creations += 1
        return testIdentity
    }
    func adoptStoredIdentity() throws -> LocalIdentitySnapshot {
        adoptions += 1
        return testIdentity
    }
    func eraseIdentity() {}
}

private let testIdentity = LocalIdentitySnapshot(id: "test", publicIdentity: .init(
    canonicalAddress: "test", hint: .init(bytes: Data([1, 2, 3]), text: "Test")))

@Suite @MainActor
struct IdentityTests {
    @Test func unreadableStoreDoesNotAdoptOrReplaceIdentity() async throws {
        let vault = TestVault(.orphaned(testIdentity))
        let operations = IdentityOperations(vault: vault,
            knowsIdentity: { _ in throw TestFailure.unavailable }, persistName: { _, _ in })
        await #expect(throws: TestFailure.self) { try await operations.load() }
        #expect(await vault.adoptions == 0)
        #expect(await vault.creations == 0)
    }

    @Test func existingRecordsAuthorizeAdoption() async throws {
        let vault = TestVault(.orphaned(testIdentity))
        let operations = IdentityOperations(vault: vault, knowsIdentity: { _ in true }, persistName: { _, _ in })
        #expect(try await operations.load() == .ready(testIdentity, minted: false))
        #expect(await vault.adoptions == 1)
    }

    @Test func emptyStoreRequiresUserDecision() async throws {
        let vault = TestVault(.orphaned(testIdentity))
        let operations = IdentityOperations(vault: vault, knowsIdentity: { _ in false }, persistName: { _, _ in })
        #expect(try await operations.load() == .needsAdoption(testIdentity))
        #expect(await vault.adoptions == 0)
    }
}

private actor DraftWriter {
    var fails = true
    var saved: [String] = []
    func write(_ text: String) throws {
        if fails { throw TestFailure.unavailable }
        saved.append(text)
    }
    func allowWrites() { fails = false }
}

@Suite @MainActor
struct DraftTests {
    @Test func sendCleanupDoesNotEraseNewerInput() async throws {
        let writer = DraftWriter()
        await writer.allowWrites()
        let drafts = ConversationDraftStore { _, text in try await writer.write(text) }
        let key = ConversationDraftKey(owner: "alice", kind: .direct, id: 1)
        try await drafts.save("Old draft", for: key).get()
        try await drafts.save("New words", for: key).get()
        try await drafts.clear(for: key, preserving: "Old draft")
        #expect(await writer.saved == ["Old draft", "New words"])
    }
    @Test func failedClearRetainsSubmittedDraftForRecovery() async {
        let drafts = ConversationDraftStore { _, _ in throw TestFailure.unavailable }
        let key = ConversationDraftKey(owner: "alice", kind: .direct, id: 2)
        await #expect(throws: AppOperationError.self) {
            try await drafts.clear(for: key, preserving: "Original draft")
        }
        #expect(drafts.pendingText(for: key) == "Original draft")
    }
    @Test func failedWriteRetainsTextAndRetryPersistsIt() async throws {
        let writer = DraftWriter()
        let drafts = ConversationDraftStore { _, text in try await writer.write(text) }
        let key = ConversationDraftKey(owner: "alice", kind: .direct, id: 1)
        let failed = await drafts.save("Do not lose this", for: key)
        if case .success = failed { Issue.record("Failed storage reported success") }
        #expect(drafts.pendingText(for: key) == "Do not lose this")
        await writer.allowWrites()
        try await drafts.save("Do not lose this", for: key).get()
        #expect(drafts.pendingText(for: key) == nil)
        #expect(await writer.saved == ["Do not lose this"])
    }

    @Test func cancelledCallerDoesNotStartWrite() async {
        let writer = DraftWriter()
        await writer.allowWrites()
        let drafts = ConversationDraftStore { _, text in try await writer.write(text) }
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return await drafts.save("canceled", for: .init(owner: "alice", kind: .channel, id: 1))
        }
        if case .failure(.cancelled) = await task.value {} else { Issue.record("Expected cancellation") }
        #expect(await writer.saved.isEmpty)
    }

    @Test func cancelledCallerStillClearsSubmittedDraft() async throws {
        let writer = DraftWriter()
        await writer.allowWrites()
        let drafts = ConversationDraftStore { _, text in try await writer.write(text) }
        let key = ConversationDraftKey(owner: "alice", kind: .direct, id: 3)
        try await drafts.save("Sent text", for: key).get()
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try await drafts.clear(for: key, preserving: "Sent text")
        }
        try await task.value
        #expect(drafts.pendingText(for: key) == nil)
        #expect(await writer.saved == ["Sent text", ""])
    }
}

@Suite
struct BoundaryTests {
    @Test func deviceOutcomeUsesTypedKindInsteadOfDiagnosticText() {
        let session = UlcpRadioSession(sessionQueue: DispatchQueue(label: "test.outcomes"))
        let full = UlcpOperationErrorRecord(kind: .capacity, operation: "renamed",
            statusCode: 0, statusName: "renamed diagnostic")
        #expect(session.devicePeerOutcome(full) as? DevicePeerError == .deviceFull)
        for kind in [UlcpOperationFailureKind.saveFailed, .alreadyApplied, .itemMissing] {
            let applied = UlcpOperationErrorRecord(kind: kind, operation: "renamed",
                statusCode: 0, statusName: "renamed diagnostic")
            #expect(session.devicePeerOutcome(applied) == nil)
        }
    }

    @Test func composeValidationAndAvailabilityRemainDistinct() {
        if case .validation = ChatSubmissionCoordinator.composeError(.UnknownConversation) {}
        else { Issue.record("Expected validation failure") }
        if case .unavailable = ChatSubmissionCoordinator.composeError(.SessionUnavailable) {}
        else { Issue.record("Expected unavailable service") }
        if case .persistence = ChatSubmissionCoordinator.composeError(.CounterPersistenceFailed) {}
        else { Issue.record("Expected persistence failure") }
    }
    @Test func coreErrorsAreNotAllInvalidAddresses() {
        #expect(RustMeshEngine.inputError(.InvalidSecretKeyLength) == .coreFailure)
        #expect(RustMeshEngine.inputError(.InvalidIdentityData) == .invalidIdentityData)
        #expect(RustMeshEngine.inputError(.InvalidUri, invalidURI: .invalidChannelURI) == .invalidChannelURI)
        #expect(RustMeshEngine.inputError(.AddressOverflow) == .invalidAddress)
    }

    @Test func reusedControlIDGetsANewDeadline() {
        var deadlines = RadioControlDeadlines()
        deadlines.update(pending: [1], now: 10)
        deadlines.update(pending: [1], now: 15)
        #expect(deadlines.next == 18)
        deadlines.update(pending: [1], completed: 1, now: 17)
        #expect(deadlines.next == 25)
        deadlines.reset()
        #expect(deadlines.next == nil)
    }

    @Test func cancellationBeforeRegistrationResumesExactlyOnce() async {
        let waiter = RadioOperationWaiter<Int>()
        waiter.cancel()
        await #expect(throws: CancellationError.self) {
            try await withCheckedThrowingContinuation { continuation in
                #expect(!waiter.install(continuation))
                waiter.resume(returning: 42)
            } as Int
        }
    }

    @Test func localOperationCancellationRetainsSlotUntilDisconnect() async throws {
        let queue = DispatchQueue(label: "test.local-management")
        let session = UlcpRadioSession(sessionQueue: queue)
        let link = TestRadioLink()
        let (events, started) = AsyncStream<Void>.makeStream()
        queue.sync {
            session.adopt(link: link)
            session.snapshot.linkState = .attached
            session.snapshot.hostState = .matchesCurrentIdentity
        }
        let operation = Task {
            try await session.performLocalManagement { core in
                started.yield(())
                started.finish()
                return try core.begin(selectedHostKey: nil)
            }
        }
        for await _ in events { break }
        operation.cancel()
        await #expect(throws: CancellationError.self) { try await operation.value }
        queue.sync {
            #expect(session.localManagementWaiter != nil)
            session.sessionDidLoseLink()
            #expect(session.localManagementWaiter == nil)
            #expect(session.ulcpSession.reset().pendingControlTransactions.isEmpty)
        }
    }
}

private final class TestRadioLink: UlcpFrameLink {
    var linkIsReady = true
    let linkID: UUID? = UUID()
    let linkName: String? = "Test"
    var linkIsBoundRadio: Bool { true }
    var linkCanReconnect: Bool { true }
    func linkSend(frame: Data, rawTransactionID: UInt8?) {}
    func linkResetFraming() {}
    func linkInvalidate(retrying: Bool) { linkIsReady = false }
    func linkDidAttach() {}
    func linkDidReportName(_ name: String) {}
    func linkAbandonBinding() {}
}

@Suite @MainActor
struct ChatSubmissionTests {
    private let batch = MobileChatComposeBatchRecord(batchId: 1,
        checkpoint: .init(conversationAddress: "peer", nextId: 1, epoch: 0),
        archiveDeletes: [], archives: [], mutations: [])

    @Test func failedPersistenceRejectsWithoutSendingOrClearingDraft() async {
        var calls: [String] = []
        let coordinator = ChatSubmissionCoordinator(
            persist: { _ in calls.append("persist"); throw TestFailure.unavailable },
            reject: { _ in calls.append("reject") }, release: { _ in calls.append("send") },
            markFailed: { _ in calls.append("markFailed") })
        let result = await coordinator.submit(compose: { batch }, didChange: {}, clearDraft: { calls.append("clear") })
        #expect(calls == ["persist", "reject"])
        if case .failed(.persistence) = result {} else { Issue.record("Expected persistence failure") }
    }

    @Test func failedReleaseKeepsDraftAndMarksMessageFailed() async {
        var calls: [String] = []
        let coordinator = ChatSubmissionCoordinator(persist: { _ in calls.append("persist") },
            reject: { _ in calls.append("reject") },
            release: { _ in calls.append("send"); throw TestFailure.unavailable },
            markFailed: { _ in calls.append("markFailed") })
        let result = await coordinator.submit(compose: { batch }, didChange: {}, clearDraft: { calls.append("clear") })
        #expect(calls == ["persist", "send", "markFailed"])
        if case .failed(.operation) = result {} else { Issue.record("Expected release failure") }
    }

    @Test func cleanupFailureDoesNotReportSubmittedMessageAsFailed() async {
        let coordinator = ChatSubmissionCoordinator(persist: { _ in }, reject: { _ in },
            release: { _ in }, markFailed: { _ in })
        let result = await coordinator.submit(compose: { batch }, didChange: {}, clearDraft: { throw TestFailure.unavailable })
        if case .submitted(warning: .persistence) = result {} else { Issue.record("Expected submitted with warning") }
    }
}

@Suite @MainActor
struct RuntimePersistenceTests {
    @Test func conversationRefreshDoesNotReadNeighborReports() async throws {
        let fixture = try await StoreFixture()
        defer { fixture.remove() }
        let runtime = AppRuntime(radioConnection: FakeRadioConnection(), openStore: { fixture.store })
        runtime.localIdentity = fixture.identity
        try await fixture.store.upsertPeer(ownerIdentityID: fixture.identity.id,
            publicAddress: fixture.identity.publicIdentity.canonicalAddress, alias: "Peer", isSaved: true)
        _ = try await fixture.store.ensureDirectConversation(ownerIdentityID: fixture.identity.id,
            peerAddress: fixture.identity.publicIdentity.canonicalAddress)
        await runtime.reloadApplicationState()
        #expect(runtime.conversations.count == 1)
        // A query against this unrelated table would now fail. Marking a
        // conversation read must refresh only its summary, not the map.
        try fixture.execute("ALTER TABLE node_peer_repeater_entry RENAME TO test_hidden_reports;")
        await runtime.markConversationRead(fixture.identity.publicIdentity.canonicalAddress)
        #expect(runtime.stateLoadError == nil)
        #expect(runtime.conversations.count == 1)
        #expect(runtime.peers.count == 1)
    }

    @Test func writingMissingDraftIsNotSuccess() async throws {
        let store = try SQLiteApplicationStore(path: ":memory:")
        await #expect(throws: ApplicationStoreError.recordNotFound) {
            try await store.updateDraft(ownerIdentityID: "absent", conversationID: 1, text: "unsaved")
        }
    }
    @Test func failedNameSaveKeepsPublishedName() async throws {
        let fixture = try await StoreFixture()
        defer { fixture.remove() }
        let runtime = AppRuntime(radioConnection: FakeRadioConnection(), openStore: { fixture.store })
        runtime.localIdentity = fixture.identity
        runtime.advertisedName = "Original"
        try fixture.execute("CREATE TRIGGER fail_name BEFORE UPDATE ON local_identity BEGIN SELECT RAISE(FAIL, 'test'); END;")
        let result = await runtime.saveAdvertisedName("New")
        if case .success = result { Issue.record("Failed save reported success") }
        #expect(runtime.advertisedName == "Original")
    }

    @Test func failedReloadRetainsLastSnapshotAndRetryRecovers() async throws {
        let fixture = try await StoreFixture()
        defer { fixture.remove() }
        let runtime = AppRuntime(radioConnection: FakeRadioConnection(), openStore: { fixture.store })
        runtime.localIdentity = fixture.identity
        try await fixture.store.upsertPeer(ownerIdentityID: fixture.identity.id,
            publicAddress: fixture.identity.publicIdentity.canonicalAddress, alias: "Peer", isSaved: true)
        await runtime.reloadApplicationState()
        #expect(runtime.peers.count == 1)
        try fixture.execute("ALTER TABLE node_peer_repeater_entry RENAME TO test_hidden_reports;")
        await runtime.reloadApplicationState()
        #expect(runtime.peers.count == 1)
        #expect(runtime.stateLoadError != nil)
        try fixture.execute("ALTER TABLE test_hidden_reports RENAME TO node_peer_repeater_entry;")
        await runtime.reloadApplicationState()
        #expect(runtime.stateLoadError == nil)
        #expect(runtime.peers.count == 1)
    }
}

private struct StoreFixture {
    let url: URL
    let store: SQLiteApplicationStore
    let identity: LocalIdentitySnapshot
    init() async throws {
        url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".sqlite")
        store = try SQLiteApplicationStore(path: url.path)
        let publicIdentity = try await RustMeshEngine().unlockIdentity(secretKey: Data(repeating: 7, count: 32))
        identity = .init(id: publicIdentity.canonicalAddress, publicIdentity: publicIdentity)
        try await store.insertIdentity(id: identity.id, publicAddress: publicIdentity.canonicalAddress)
    }
    func execute(_ sql: String) throws {
        var db: OpaquePointer?
        guard sqlite3_open(url.path, &db) == SQLITE_OK else { throw TestFailure.unavailable }
        defer { sqlite3_close(db) }
        guard sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else { throw TestFailure.unavailable }
    }
    func remove() { try? FileManager.default.removeItem(at: url) }
}
