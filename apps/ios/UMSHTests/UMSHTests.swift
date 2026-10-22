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
    func linkDidEnterDfu() {}
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

@Suite @MainActor
struct ContactExchangeTests {
    private func contact(secret: Data, name: String) async throws -> MobileMeetContactRecord {
        let theirs = try MobileIdentity.unlock(secretKey: secret).publicIdentity()
        let bundle = try await signNodeIdentityBundle(secretKey: secret,
            profile: NodeIdentityProfileRecord(roleCode: 0, capabilityBits: 0, name: name,
                latitude: nil, longitude: nil, locationPrecision: nil, altitudeM: nil, timestamp: nil))
        return MobileMeetContactRecord(peerAddress: theirs.canonicalAddress,
            identityBundle: bundle, signed: true)
    }

    @Test func exchangedContactIsRecordedUnsaved() async throws {
        let fixture = try await StoreFixture()
        defer { fixture.remove() }
        let runtime = AppRuntime(radioConnection: FakeRadioConnection(), openStore: { fixture.store })
        runtime.localIdentity = fixture.identity
        await runtime.reloadApplicationState()
        let theirs = try await contact(secret: Data(repeating: 9, count: 32), name: "Maya")
        await runtime.recordExchanged(theirs)
        let peer = try #require(runtime.exchangedPeer)
        #expect(peer.identity.canonicalAddress == theirs.peerAddress)
        #expect(peer.advertisedName == "Maya")
        #expect(!peer.isSaved)
        // The bundle came from the exchange's session key, not the peer's.
        #expect(!peer.advertisedIdentityAuthenticated)
    }

    @Test func exchangingWithASavedPeerKeepsItSaved() async throws {
        let fixture = try await StoreFixture()
        defer { fixture.remove() }
        let runtime = AppRuntime(radioConnection: FakeRadioConnection(), openStore: { fixture.store })
        runtime.localIdentity = fixture.identity
        let theirs = try await contact(secret: Data(repeating: 9, count: 32), name: "Maya")
        try await fixture.store.upsertPeer(ownerIdentityID: fixture.identity.id,
            publicAddress: theirs.peerAddress, alias: "Peer", isSaved: true)
        await runtime.reloadApplicationState()
        await runtime.recordExchanged(theirs)
        let peer = try #require(runtime.exchangedPeer)
        #expect(peer.isSaved)
        #expect(peer.alias == "Peer")
    }

    @Test func ownContactIsNotRecorded() async throws {
        let fixture = try await StoreFixture()
        defer { fixture.remove() }
        let runtime = AppRuntime(radioConnection: FakeRadioConnection(), openStore: { fixture.store })
        runtime.localIdentity = fixture.identity
        await runtime.reloadApplicationState()
        await runtime.recordExchanged(try await contact(secret: Data(repeating: 7, count: 32), name: "Me"))
        #expect(runtime.exchangedPeer == nil)
        #expect(runtime.peers.isEmpty)
    }
}

@Suite @MainActor
struct ManualPathTests {
    @Test func savedPathRoundTripsUntilItsHoldEnds() async throws {
        let fixture = try await StoreFixture()
        defer { fixture.remove() }
        let owner = fixture.identity.id
        let address = fixture.identity.publicIdentity.canonicalAddress
        try await fixture.store.upsertPeer(ownerIdentityID: owner, publicAddress: address,
            alias: "Peer", isSaved: true)
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let hints = [Data([0x5E, 0xBD]), Data([0xED, 0xBC])]
        try await fixture.store.saveManualRoute(ownerIdentityID: owner, publicAddress: address,
            hints: hints, floodHops: 3, holdUntil: now.addingTimeInterval(3600),
            latitude: 44.05, longitude: -123.09, accuracy: 12)
        try await fixture.store.settleManualRoutePrompt(ownerIdentityID: owner, publicAddress: address)

        let stored = try #require(try await fixture.store.manualRoute(
            ownerIdentityID: owner, publicAddress: address, now: now))
        #expect(stored.hints == hints)
        #expect(stored.floodHops == 3)
        #expect(stored.promptSettled)
        #expect(stored.savedLatitude == 44.05)
        #expect(try await fixture.store.manualRoutes(ownerIdentityID: owner, now: now).count == 1)

        // Saving again is a new choice: the declined offer does not carry over.
        try await fixture.store.saveManualRoute(ownerIdentityID: owner, publicAddress: address,
            hints: [], floodHops: 0, holdUntil: now.addingTimeInterval(3600),
            latitude: nil, longitude: nil, accuracy: nil)
        let direct = try #require(try await fixture.store.manualRoute(
            ownerIdentityID: owner, publicAddress: address, now: now))
        #expect(direct.promptSettled == false)
        #expect(direct.hints.isEmpty)
        #expect(direct.floodHops == 0)

        let later = now.addingTimeInterval(3601)
        #expect(try await fixture.store.manualRoutes(ownerIdentityID: owner, now: later).isEmpty)
        #expect(try await fixture.store.manualRoute(
            ownerIdentityID: owner, publicAddress: address, now: now) == nil)
    }

    @Test func clearingForgetsThePath() async throws {
        let fixture = try await StoreFixture()
        defer { fixture.remove() }
        let owner = fixture.identity.id
        let address = fixture.identity.publicIdentity.canonicalAddress
        try await fixture.store.upsertPeer(ownerIdentityID: owner, publicAddress: address,
            alias: "Peer", isSaved: true)
        try await fixture.store.saveManualRoute(ownerIdentityID: owner, publicAddress: address,
            hints: [Data([1, 2])], floodHops: 1, holdUntil: .now.addingTimeInterval(60),
            latitude: nil, longitude: nil, accuracy: nil)
        try await fixture.store.clearManualRoute(ownerIdentityID: owner, publicAddress: address)
        #expect(try await fixture.store.manualRoute(ownerIdentityID: owner, publicAddress: address) == nil)
    }

    private func record(accuracy: Double? = 10, settled: Bool = false) -> ManualPathRecord {
        ManualPathRecord(holdUntil: .now.addingTimeInterval(3600), savedLatitude: 44.0,
            savedLongitude: -123.0, savedAccuracy: accuracy, promptSettled: settled)
    }

    /// About 222 m north of the saved fix, and about 111 m.
    private let farLatitude = 44.002
    private let nearLatitude = 44.001

    @Test func movingTwoHundredMetersCounts() {
        #expect(record().hasMoved(latitude: farLatitude, longitude: -123.0, accuracy: 10))
        #expect(!record().hasMoved(latitude: nearLatitude, longitude: -123.0, accuracy: 10))
    }

    @Test func vagueOrMissingFixesNeverCountAsMoving() {
        #expect(!record().hasMoved(latitude: farLatitude, longitude: -123.0, accuracy: 150))
        #expect(!record(accuracy: 150).hasMoved(latitude: farLatitude, longitude: -123.0, accuracy: 10))
        #expect(!record(accuracy: nil).hasMoved(latitude: farLatitude, longitude: -123.0, accuracy: 10))
    }

    @Test func offerNeedsTwoFloodedAcksOrOneAfterMoving() {
        let candidate = PeerRoute.Candidate(kind: .source, hints: [], hopCount: 1)
        func route(acks: UInt8, candidate: PeerRoute.Candidate? = candidate) -> PeerRoute {
            PeerRoute(kind: .source, hints: [], hopCount: 2, floodHops: nil, floodRegions: [],
                holdUntil: .now.addingTimeInterval(60), fallbackAcks: acks, candidate: candidate)
        }
        #expect(!record().shouldOfferLearnedPath(route: route(acks: 1), moved: false))
        #expect(record().shouldOfferLearnedPath(route: route(acks: 1), moved: true))
        #expect(record().shouldOfferLearnedPath(route: route(acks: 2), moved: false))
        #expect(!record().shouldOfferLearnedPath(route: route(acks: 0), moved: true))
        #expect(!record().shouldOfferLearnedPath(route: route(acks: 3, candidate: nil), moved: true))
        #expect(!record(settled: true).shouldOfferLearnedPath(route: route(acks: 3), moved: true))
    }
}

@Suite @MainActor
struct AdvertisementArrivalTests {
    @Test func arrivalMovesWithTheBundleItDates() async throws {
        let fixture = try await StoreFixture()
        defer { fixture.remove() }
        let owner = fixture.identity.id
        let address = fixture.identity.publicIdentity.canonicalAddress
        let heard = Date(timeIntervalSince1970: 1_800_000_000)
        func stored() async throws -> StoredNode? {
            try await fixture.store.listNodes(ownerIdentityID: owner).first
        }

        try await fixture.store.upsertPeer(ownerIdentityID: owner, publicAddress: address,
            alias: nil, advertisement: Data([1]), advertisementReceivedAt: heard)
        #expect(try await stored()?.advertisementReceivedAt == heard)

        // A write that carries no bundle says nothing about the one held.
        try await fixture.store.upsertPeer(ownerIdentityID: owner, publicAddress: address,
            alias: "Renamed")
        #expect(try await stored()?.advertisementReceivedAt == heard)

        // An imported bundle replaces it, and has no arrival to date it by.
        try await fixture.store.upsertPeer(ownerIdentityID: owner, publicAddress: address,
            alias: nil, advertisement: Data([2]))
        #expect(try await stored()?.advertisementReceivedAt == nil)
    }

    /// The conversation columns are read after the node's; a node column
    /// added in the middle must not shift them.
    @Test func conversationColumnsFollowTheNodeColumns() async throws {
        let fixture = try await StoreFixture()
        defer { fixture.remove() }
        let owner = fixture.identity.id
        let address = fixture.identity.publicIdentity.canonicalAddress
        try await fixture.store.upsertPeer(ownerIdentityID: owner, publicAddress: address,
            alias: "Peer", isSaved: true, advertisement: Data([1]),
            advertisementReceivedAt: Date(timeIntervalSince1970: 1_800_000_000))
        let id = try await fixture.store.ensureDirectConversation(ownerIdentityID: owner,
            peerAddress: address)
        try await fixture.store.updateDraft(ownerIdentityID: owner, conversationID: id, text: "Draft")
        let conversation = try #require(
            try await fixture.store.listDirectConversations(ownerIdentityID: owner).first)
        #expect(conversation.node.alias == "Peer")
        #expect(conversation.node.advertisementReceivedAt != nil)
        #expect(conversation.draftText == "Draft")
        #expect(conversation.notificationsEnabled)
    }
}

@Suite
struct MapNodeTests {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let hint = Data([0xA1, 0xB2, 0xC3])

    private func peer(id: Int64, ownAdvertisementAt: Date? = nil, heard: Date? = nil) -> PeerSummary {
        PeerSummary(
            id: id,
            identity: MeshPublicIdentity(
                canonicalAddress: "node-\(id)",
                hint: MeshNodeHint(bytes: id == 1 ? hint : Data([0, 0, UInt8(id)]), text: "N\(id)")
            ),
            alias: nil, advertisedName: nil, systemRole: nil, storedRole: .repeater,
            advertisedIdentityReceivedAt: ownAdvertisementAt,
            lastHeard: heard
        )
    }

    private func report(
        by reporter: PeerSummary,
        at reportedAt: Date,
        minutesAgo: UInt16? = 5,
        placed: Bool = true
    ) -> PeerRepeaterNeighborReport {
        PeerRepeaterNeighborReport(
            reporter: reporter,
            neighbor: PeerRepeaterNeighbor(
                hint: hint, hintText: "A1B2C3", name: "Ridge", rssiDBm: -90, snrQuarterDB: 20,
                lastHeardMinutes: minutesAgo,
                latitude: placed ? 38.9 : nil, longitude: placed ? -120.1 : nil,
                locationPrecision: nil, regionCodes: [], reportedAt: reportedAt
            )
        )
    }

    @Test func recencyWindowsAdmitWhatWasHeardWithinThem() {
        let twoDaysAgo = now.addingTimeInterval(-2 * 86_400)
        #expect(MapRecencyFilter.day.admits(now.addingTimeInterval(-3_600), now: now))
        #expect(!MapRecencyFilter.day.admits(twoDaysAgo, now: now))
        #expect(MapRecencyFilter.week.admits(twoDaysAgo, now: now))
        #expect(MapRecencyFilter.any.admits(twoDaysAgo, now: now))
        // Never heard counts only when any age does.
        #expect(!MapRecencyFilter.week.admits(nil, now: now))
        #expect(MapRecencyFilter.any.admits(nil, now: now))
    }

    @Test func aRouterPlacesANodeThatHasNotSpokenSinceItAnswered() {
        let router = peer(id: 2)
        let neighbor = peer(id: 1, ownAdvertisementAt: now.addingTimeInterval(-7_200))
        let nodes = MapNode.nodes(
            peers: [neighbor, router],
            neighborReports: [report(by: router, at: now.addingTimeInterval(-3_600))]
        )
        #expect(nodes.map(\.id) == [.neighbor(hint: hint)])
        #expect(nodes.first?.peer?.id == 1)
    }

    /// The node advertised after the router answered, and named no position:
    /// the router's older copy does not put one back.
    @Test func theNodesOwnLaterAdvertisementOverrulesTheRouter() {
        let router = peer(id: 2)
        let neighbor = peer(id: 1, ownAdvertisementAt: now.addingTimeInterval(-60))
        let nodes = MapNode.nodes(
            peers: [neighbor, router],
            neighborReports: [report(by: router, at: now.addingTimeInterval(-3_600))]
        )
        #expect(nodes.isEmpty)
    }

    @Test func theFreshestReportDecidesEvenWhenItNamesNoPosition() {
        let first = peer(id: 2)
        let second = peer(id: 3)
        let nodes = MapNode.nodes(
            peers: [first, second],
            neighborReports: [
                report(by: first, at: now.addingTimeInterval(-7_200)),
                report(by: second, at: now.addingTimeInterval(-60), placed: false),
            ]
        )
        #expect(nodes.isEmpty)
    }

    @Test func aReportAgesByWhenTheRouterLastHeardTheNode() throws {
        let router = peer(id: 2)
        func reported(minutesAgo: UInt16?) throws -> MapNode {
            try #require(MapNode.nodes(
                peers: [router],
                neighborReports: [report(by: router, at: now, minutesAgo: minutesAgo)]
            ).first)
        }
        // Two days before the router answered.
        let quiet = try reported(minutesAgo: 2_880)
        #expect(!quiet.passes(tier: .all, capabilities: [], recency: .day, now: now))
        #expect(quiet.passes(tier: .all, capabilities: [], recency: .week, now: now))
        // No figure: the router still had it when it answered.
        let unknown = try reported(minutesAgo: nil)
        #expect(unknown.passes(tier: .all, capabilities: [], recency: .hour, now: now))
        // The saturated figure is "long ago", older than any window.
        let longAgo = try reported(minutesAgo: .max)
        #expect(!longAgo.passes(tier: .all, capabilities: [], recency: .week, now: now))
        #expect(longAgo.passes(tier: .all, capabilities: [], recency: .any, now: now))
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

@Suite
struct PeerAvatarTests {
    private func textIsWhite(_ bytes: [UInt8]) -> Bool {
        AvatarStyle.peer(hint: MeshNodeHint(bytes: Data(bytes), text: "test")).text == .white
    }

    /// The vectors in docs/ux/src/apps/peer-identity-and-sessions.md.
    @Test func guidelineVectorsChooseTheDocumentedTextColor() {
        #expect(!textIsWhite([0xA1, 0xB2, 0x03]))
        #expect(textIsWhite([0x84, 0x81, 0x1B]))
        #expect(textIsWhite([0x5E, 0xA1, 0xB2]))
        #expect(textIsWhite([0x8B, 0x60, 0xF5]))
    }

    @Test func textColorFollowsPerceivedContrast() {
        #expect(!textIsWhite([0xFF, 0xFF, 0xFF]))
        #expect(!textIsWhite([0x80, 0xFF, 0x00]))
        #expect(!textIsWhite([0xFF, 0xFF, 0x00]))
        #expect(textIsWhite([0x00, 0x00, 0xFF]))
        #expect(textIsWhite([0xFF, 0x00, 0x00]))
        #expect(textIsWhite([0x00, 0x00, 0x00]))
    }

    @Test func shapeRulesApplyInOrder() {
        #expect(PeerAvatarShape(role: .repeater, capabilities: .textMessages) == .circle)
        #expect(PeerAvatarShape(role: .chat, capabilities: []) == .circle)
        #expect(PeerAvatarShape(role: .bridge, capabilities: []) == .triangle)
        #expect(PeerAvatarShape(role: .repeater, capabilities: nil) == .triangle)
        #expect(PeerAvatarShape(role: .tracker, capabilities: .repeater) == .hexagon)
        #expect(PeerAvatarShape(role: .unknown, capabilities: nil) == .hexagon)
    }

    @Test func storedChatRoleWithoutAdvertisementIsACircle() {
        let identity = MeshPublicIdentity(
            canonicalAddress: "test",
            hint: MeshNodeHint(bytes: Data([1, 2, 3]), text: "Test")
        )
        let chat = PeerSummary(
            id: 1, identity: identity, alias: nil, advertisedName: nil, systemRole: nil, storedRole: .chat
        )
        let unknown = PeerSummary(
            id: 2, identity: identity, alias: nil, advertisedName: nil, systemRole: nil, storedRole: .unknown
        )
        #expect(chat.avatarShape == .circle)
        #expect(chat.roleLabel == "Chat")
        #expect(unknown.avatarShape == .hexagon)
        #expect(unknown.roleLabel == nil)
    }
}
