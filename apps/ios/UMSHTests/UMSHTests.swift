import CoreBluetooth
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
    @Test func aCommandsFailureSaysItsOwnCause() {
        let locked = MobileAppError.message(for: MobileAppError.Vault(error: .Unavailable))
        let unreadable = MobileAppError.message(for: MobileAppError.Vault(error: .Failed))
        let gone = MobileAppError.message(for: MobileAppError.NotFound)
        let full = MobileAppError.message(for: MobileAppError.ChannelTableFull)
        let messages = [locked, unreadable, gone, full, MobileAppError.NoRadio.message]
        #expect(Set(messages).count == messages.count)
        #expect(!messages.contains { $0.isEmpty })
        // Anything that is not the core's own code still says something.
        #expect(!MobileAppError.message(for: CancellationError()).isEmpty)
        #expect(FailureNotice("Title", MobileAppError.NotFound).message == gone)
    }

    @Test func theProtocolsOwnChannelsFollowTheCoresRule() {
        func channel(_ kind: StoredChannelKind, _ canonicalName: String?) -> ChannelSummary {
            ChannelSummary(
                id: UUID(), kind: kind, canonicalName: canonicalName, name: nil, alias: nil,
                channelIDHex: "0000", tint: Data([0, 0, 0]), regionCode: nil, maxFloodHops: nil,
                joinedPhone: true, notificationsEnabled: false, joinedAt: nil
            )
        }
        let publicChannel = channel(.builtin, "public")
        let emergency = channel(.builtin, "emergency")
        let named = channel(.named, "trail crew")
        let secret = channel(.privateKey, nil)
        #expect(publicChannel.protocolMaxFloodHops != nil && !publicChannel.isEmergency)
        #expect(emergency.protocolMaxFloodHops != nil && emergency.isEmergency)
        #expect(named.protocolMaxFloodHops == nil && !named.isEmergency && named.protocolBehavior.isEmpty)
        #expect(!publicChannel.protocolBehavior.isEmpty && !emergency.protocolBehavior.isEmpty)
        // Joining `public` by hand reaches the same channel, with the same rules.
        #expect(channel(.named, "public").protocolMaxFloodHops == publicChannel.protocolMaxFloodHops)
        // A named channel can be joined again by its name; a private one
        // needs a new invitation.
        #expect(secret.leaveMessage != named.leaveMessage)
        #expect(named.leaveMessage == publicChannel.leaveMessage)
    }

    @Test func driverErrorsReachTableEditsAsTheirOwnCopy() {
        func mapped(_ error: MobileRadioError) -> DevicePeerError? {
            RadioDriverAdapter.devicePeerError(error) as? DevicePeerError
        }
        #expect(mapped(.DeviceFull) == .deviceFull)
        #expect(mapped(.Unsupported) == .unsupported)
        #expect(mapped(.RadioUnavailable) == .radioUnavailable)
        #expect(mapped(.UnrecognizedAnswer) == .unrecognizedAnswer)
        #expect(mapped(.OperationRejected(operation: "renamed", statusCode: 5,
            statusName: "STATUS_NAME")) == .failed("STATUS_NAME"))
        #expect(RadioDriverAdapter.devicePeerError(.OperationInProgress)
            as? RadioConnectionError == .operationInProgress)
    }

    @Test func aRefusedConfigurationThrowsTheSessionsOwnCause() {
        let refused = RadioDriverAdapter.connectionError(.Refused(error: .UlcpUnexpectedFrame))
        #expect(refused as? MobileError == .UlcpUnexpectedFrame)
        #expect(RadioDriverAdapter.connectionError(.TimedOut)
            as? RadioConnectionError == .operationTimedOut)
        #expect(RadioDriverAdapter.managementError(.TimedOut)
            as? RemoteManagementError == .noAnswer)
        #expect(RadioDriverAdapter.managementError(.Refused(error: .UlcpUnexpectedFrame))
            as? RemoteManagementError == .unavailable)
    }

    @Test func transportProblemsKeepTheirCodes() {
        for problem in RadioTransportProblem.allCases {
            guard case let .transport(domain, code) = problem.problem else {
                Issue.record("Expected a transport problem")
                continue
            }
            #expect(domain == RadioTransportProblem.domain)
            #expect(RadioTransportProblem(rawValue: code) == problem)
            #expect(problem.problem.text == problem.text)
        }
    }

    @Test func anAdministeredLinkFailsWithTheErrorItsSetupStepNeeds() {
        func failure(_ problem: MobileRadioProblem?) -> RadioConnectionError {
            AdministrativeDeviceSession.connectionFailure(problem)
        }
        let unpaired = MobileRadioProblem.transport(
            domain: CBATTErrorDomain,
            code: Int64(CBATTError.insufficientEncryption.rawValue)
        )
        if case .pairingRequired = failure(unpaired) {} else {
            Issue.record("A missing pairing is a setup step")
        }
        if case .pairingRequired = failure(RadioTransportProblem.accessRemoved.problem) {} else {
            Issue.record("Access removed in Settings is a setup step")
        }
        if case .bluetoothUnavailable = failure(RadioTransportProblem.bluetoothOff.problem) {} else {
            Issue.record("Expected Bluetooth unavailable")
        }
        for gone in [nil, RadioTransportProblem.linkLost.problem,
                     RadioTransportProblem.connectionIncomplete.problem,
                     MobileRadioProblem.synchronizationStalled] {
            if case .radioNotFound = failure(gone) {} else {
                Issue.record("Expected radio not found for \(String(describing: gone))")
            }
        }
        for broken in [MobileRadioProblem.invalidFrame,
                       RadioTransportProblem.serviceMissing.problem] {
            if case .incompatibleProtocol = failure(broken) {} else {
                Issue.record("Expected an incompatible protocol for \(broken)")
            }
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
}

@Suite @MainActor
struct ChatSubmissionTests {
    @Test func unsavedMessageKeepsDraft() async {
        var calls: [String] = []
        let result = await ChatSubmissionCoordinator().submit(
            send: { calls.append("send"); throw MobileChatSendError.NotSaved(error: .RecordNotFound) },
            didChange: {}, clearDraft: { calls.append("clear") })
        #expect(calls == ["send"])
        if case .failed(.persistence) = result {} else { Issue.record("Expected persistence failure") }
    }

    @Test func unqueuedMessageKeepsDraftAndRedraws() async {
        var calls: [String] = []
        let result = await ChatSubmissionCoordinator().submit(
            send: { calls.append("send"); throw MobileChatSendError.NotQueued(error: .SendFailed) },
            didChange: { calls.append("redraw") }, clearDraft: { calls.append("clear") })
        #expect(calls == ["send", "redraw"])
        if case .failed(.operation) = result {} else { Issue.record("Expected release failure") }
    }

    @Test func sentMessageRedrawsThenClearsDraft() async {
        var calls: [String] = []
        let result = await ChatSubmissionCoordinator().submit(
            send: { calls.append("send") },
            didChange: { calls.append("redraw") }, clearDraft: { calls.append("clear") })
        #expect(calls == ["send", "redraw", "clear"])
        #expect(result == .submitted())
    }

    @Test func cleanupFailureDoesNotReportSubmittedMessageAsFailed() async {
        let result = await ChatSubmissionCoordinator().submit(
            send: {}, didChange: {}, clearDraft: { throw TestFailure.unavailable })
        if case .submitted(warning: .persistence) = result {} else { Issue.record("Expected submitted with warning") }
    }
}

@Suite @MainActor
struct RuntimePersistenceTests {
    @Test func writingMissingDraftIsNotSuccess() async throws {
        let store = try SQLiteApplicationStore(path: ":memory:")
        await #expect(throws: ApplicationStoreError.recordNotFound) {
            try await store.updateDraft(ownerIdentityID: "absent", conversationID: 1, text: "unsaved")
        }
    }
    @Test func failedReloadRetainsLastSnapshotAndRetryRecovers() async throws {
        let fixture = try await StoreFixture()
        defer { fixture.remove() }
        let runtime = try radioLessRuntime(store: fixture.store)
        runtime.localIdentity = fixture.identity
        try fixture.store.coreStore.upsertPeer(
            ownerIdentityId: fixture.identity.id,
            publicAddress: fixture.identity.publicIdentity.canonicalAddress,
            peer: MobilePeerUpsertRecord(alias: "Peer", isSaved: true)
        )
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
                locationPrecision: nil, regionCodes: [], reportedAt: reportedAt,
                peerAddress: "node-1"
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

    /// Showing one node on the map widens each filter only as far as it must.
    @Test func filtersWidenJustEnoughToShowANode() {
        let twoDaysAgo = now.addingTimeInterval(-2 * 86_400)
        #expect(MapRecencyFilter.hour.widened(toAdmit: twoDaysAgo, now: now) == .week)
        #expect(MapRecencyFilter.week.widened(toAdmit: now, now: now) == .week)
        #expect(MapRecencyFilter.day.widened(toAdmit: nil, now: now) == .any)

        let repeaters: MeshNodeCapabilities = [.repeater]
        #expect(MapCapabilityFilterOption.widened(repeaters, toAdmit: [.repeater, .mobile]) == repeaters)
        #expect(
            MapCapabilityFilterOption.widened(repeaters, toAdmit: [.textMessages, .mobile])
                == [.repeater, .mobile]
        )
        #expect(MapCapabilityFilterOption.widened(repeaters, toAdmit: []) == [])

        let saved = peer(id: 1)
        #expect(MapTierFilter.favorites.widened(toInclude: saved) == (saved.isSaved ? .saved : .all))
        #expect(MapTierFilter.saved.widened(toInclude: nil) == .all)
        #expect(MapTierFilter.all.widened(toInclude: nil) == .all)
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

/// A runtime over a core that is never started and never given a radio,
/// reading `store`.
@MainActor
func radioLessRuntime(store: SQLiteApplicationStore) throws -> AppRuntime {
    AppRuntime(
        radioConnection: NoRadioConnection(),
        opened: .success(try AppCoreHost.radioLess(over: store))
    )
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

@Suite
struct RepeatCaptionTests {
    @Test func namesTheLeadRepeaterAndCountsTheRest() {
        #expect(RepeatCaption.text(lead: nil, count: 0) == "Sent")
        #expect(RepeatCaption.text(lead: "Tallac Ridge", count: 1) == "Sent via Tallac Ridge")
        #expect(RepeatCaption.text(lead: "Tallac Ridge", count: 2) == "Sent via Tallac Ridge and 1 other")
        #expect(RepeatCaption.text(lead: "Tallac Ridge", count: 3) == "Sent via Tallac Ridge and 2 others")
    }

    @Test func countsRepeatersThatNamedNobody() {
        #expect(RepeatCaption.text(lead: nil, count: 1) == "Heard a repeat")
        #expect(RepeatCaption.text(lead: nil, count: 3) == "Heard 3 repeats")
    }
}
