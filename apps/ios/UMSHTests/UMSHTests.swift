import CoreBluetooth
import Foundation
import SQLite3
import Testing
import UIKit
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

/// A draft store writing for "alice", the owner the tests' keys name.
@MainActor
private func aliceDrafts(
    _ write: @escaping @Sendable (ConversationDraftKey, String) async throws -> Void
) -> ConversationDraftStore {
    let drafts = ConversationDraftStore(write: write)
    drafts.owner = "alice"
    return drafts
}

@Suite @MainActor
struct DraftTests {
    @Test func failedWriteRetainsTextAndRetryPersistsIt() async throws {
        let writer = DraftWriter()
        let drafts = aliceDrafts { _, text in try await writer.write(text) }
        let key = ConversationDraftKey(owner: "alice", address: "umsh:a")
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
        let drafts = aliceDrafts { _, text in try await writer.write(text) }
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return await drafts.save("canceled", for: .init(owner: "alice", address: "umsh:c"))
        }
        if case .failure(.cancelled) = await task.value {} else { Issue.record("Expected cancellation") }
        #expect(await writer.saved.isEmpty)
    }

    @Test func writesReachTheConversationTheyNamed() async throws {
        let written = Written()
        let drafts = aliceDrafts { key, text in await written.append(key.address, text) }
        try await drafts.save("to a", for: .init(owner: "alice", address: "umsh:a")).get()
        try await drafts.save("to b", for: .init(owner: "alice", address: "umsh:b")).get()
        #expect(await written.items == ["umsh:a: to a", "umsh:b: to b"])
    }

    @Test func settleWaitsForTheWriteUnderWay() async {
        let writer = DraftWriter()
        await writer.allowWrites()
        let (gate, open) = AsyncStream<Void>.makeStream()
        let drafts = aliceDrafts { _, text in
            for await _ in gate { break }
            try await writer.write(text)
        }
        let key = ConversationDraftKey(owner: "alice", address: "umsh:d")
        let saving = Task { await drafts.save("hello", for: key) }
        while drafts.pendingText(for: key) == nil { await Task.yield() }
        let settled = Task {
            await drafts.settle(key)
            return await writer.saved
        }
        open.yield()
        #expect(await settled.value == ["hello"])
        _ = await saving.value
    }

    @Test func aFlushAfterTheTapLeavesNoDraft() async throws {
        let writer = DraftWriter()
        await writer.allowWrites()
        let drafts = aliceDrafts { _, text in try await writer.write(text) }
        let key = ConversationDraftKey(owner: "alice", address: "umsh:e")
        await drafts.submit("hello", for: key)
        // The core writes the draft and clears it here; the debounce and the
        // flush on leaving come after.
        try await drafts.save("hello", for: key).get()
        #expect(await writer.saved.isEmpty)
        // Other text ends the rule, so the same words typed again are kept.
        try await drafts.save("hello again", for: key).get()
        try await drafts.save("hello", for: key).get()
        #expect(await writer.saved == ["hello again", "hello"])
    }

    @Test func aRefusedSendsWordsAreSavedAgain() async throws {
        let writer = DraftWriter()
        await writer.allowWrites()
        let drafts = aliceDrafts { _, text in try await writer.write(text) }
        let key = ConversationDraftKey(owner: "alice", address: "umsh:f")
        let submission = await drafts.submit("hello", for: key)
        drafts.withdraw(submission)
        try await drafts.save("hello", for: key).get()
        #expect(await writer.saved == ["hello"])
    }

    @Test func sentWordsHeldAsUnsavedAreForgotten() async {
        let drafts = aliceDrafts { _, _ in throw TestFailure.unavailable }
        let key = ConversationDraftKey(owner: "alice", address: "umsh:g")
        _ = await drafts.save("hello", for: key)
        #expect(drafts.pendingText(for: key) == "hello")
        let submission = await drafts.submit("hello", for: key)
        drafts.forget(submission)
        #expect(drafts.pendingText(for: key) == nil)
    }

    /// A failed write of a prefix of the sent words, the newer words'
    /// debounce dropped by the tap: the core's write of the sent text
    /// replaced it, so it does not come back.
    @Test func olderWordsHeldAsUnsavedAreForgotten() async {
        let (gate, open) = AsyncStream<Void>.makeStream()
        let drafts = aliceDrafts { _, _ in
            for await _ in gate { break }
            throw TestFailure.unavailable
        }
        let key = ConversationDraftKey(owner: "alice", address: "umsh:i")
        let saving = Task { await drafts.save("hel", for: key) }
        while drafts.pendingText(for: key) == nil { await Task.yield() }
        let submitting = Task { await drafts.submit("hello", for: key) }
        open.yield()
        let submission = await submitting.value
        _ = await saving.value
        #expect(drafts.pendingText(for: key) == "hel")
        drafts.forget(submission)
        #expect(drafts.pendingText(for: key) == nil)
    }

    /// Words typed while the send is under way are the composer's, whether
    /// their write is still going or failed.
    @Test func aFailedWriteSinceTheTapIsNotForgotten() async {
        let drafts = aliceDrafts { _, _ in throw TestFailure.unavailable }
        let key = ConversationDraftKey(owner: "alice", address: "umsh:j")
        _ = await drafts.save("hel", for: key)
        let submission = await drafts.submit("hello", for: key)
        _ = await drafts.save("hello!", for: key)
        drafts.forget(submission)
        #expect(drafts.pendingText(for: key) == "hello!")
    }

    /// A write made since the tap is under way: it stays, and the next one
    /// stays behind it.
    @Test func aWriteUnderWayIsNotForgotten() async {
        let writer = DraftWriter()
        await writer.allowWrites()
        let (gate, open) = AsyncStream<Void>.makeStream()
        let drafts = aliceDrafts { _, text in
            if text == "hello!" { for await _ in gate { break } }
            try await writer.write(text)
        }
        let key = ConversationDraftKey(owner: "alice", address: "umsh:h")
        let submission = await drafts.submit("hello", for: key)
        let first = Task { await drafts.save("hello!", for: key) }
        while drafts.pendingText(for: key) == nil { await Task.yield() }
        drafts.forget(submission)
        #expect(drafts.pendingText(for: key) == "hello!")
        let second = Task { await drafts.save("hellox", for: key) }
        while drafts.pendingText(for: key) != "hellox" { await Task.yield() }
        open.yield()
        _ = await (first.value, second.value)
        #expect(await writer.saved == ["hello!", "hellox"])
    }

    /// A write queued under one identity is not handed to the core once
    /// another is current.
    @Test func aWriteQueuedForAnotherOwnerIsDropped() async {
        let written = Written()
        let (gate, open) = AsyncStream<Void>.makeStream()
        let drafts = aliceDrafts { key, text in
            if text == "first" { for await _ in gate { break } }
            await written.append(key.address, text)
        }
        let key = ConversationDraftKey(owner: "alice", address: "umsh:i")
        let first = Task { await drafts.save("first", for: key) }
        while drafts.pendingText(for: key) == nil { await Task.yield() }
        let queued = Task { await drafts.save("queued", for: key) }
        while drafts.pendingText(for: key) != "queued" { await Task.yield() }
        drafts.owner = "bob"
        #expect(drafts.pendingText(for: key) == nil)
        open.yield()
        _ = await first.value
        if case .failure(.cancelled) = await queued.value {} else { Issue.record("Expected the write dropped") }
        #expect(await written.items == ["umsh:i: first"])
        if case .failure(.cancelled) = await drafts.save("late", for: key) {} else {
            Issue.record("Expected a save under the old owner refused")
        }
    }

    /// An open composer adds a kept reply as the core added it to the
    /// stored draft, so the composer's next save writes the same text.
    @Test func anOpenComposerAddsAKeptReplyAsTheCoreDoes() {
        let addition = DraftAddition(sequence: 1, address: "umsh:g", text: "ok")
        #expect(addition.added(to: "") == "ok")
        #expect(addition.added(to: "abc") == "abc\nok")
    }
}

private actor Written {
    private(set) var items: [String] = []
    func append(_ address: String, _ text: String) { items.append("\(address): \(text)") }
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

    @Test func aRefusedConfigurationThrowsTheSessionsOwnCause() {
        let refused = RadioDriverAdapter.connectionError(.Refused(error: .UlcpUnexpectedFrame))
        #expect(refused as? MobileError == .UlcpUnexpectedFrame)
        #expect(RadioDriverAdapter.connectionError(.TimedOut)
            as? RadioConnectionError == .operationTimedOut)
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

    @Test func chatFailuresHaveTheirOwnWords() {
        let generic = MobileAppError.message(for: TestFailure.unavailable)
        let kept = MobileAppError.MessageNotQueued(recorded: true).message
        let unrecorded = MobileAppError.MessageNotQueued(recorded: false).message
        let uncertified = MobileAppError.EmergencyNotCertified.message
        for words in [kept, unrecorded, uncertified] {
            #expect(!words.isEmpty)
            #expect(words != generic)
        }
        #expect(kept != unrecorded)
        #expect(uncertified.contains("EMERGENCY"))
    }

    @Test func reactionKindsAndGlyphsRoundTrip() {
        for entry in ReactionEmoji.palette {
            #expect(ReactionEmoji.glyph(for: entry.kind) == entry.glyph)
            #expect(ReactionEmoji.kind(for: entry.glyph) == entry.kind)
        }
        #expect(ReactionEmoji.glyph(for: .other(cluster: "👋🏽")) == "👋🏽")
        #expect(ReactionEmoji.kind(for: "👋🏽") == .other(cluster: "👋🏽"))
        #expect(ReactionEmoji.glyph(for: nil) == "")
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
struct RuntimePersistenceTests {
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

    /// The pin says whether its claims may be attributed to the node by the
    /// core's flag, not by the advertisement's signature read here.
    @Test func aPinIsAttributableOnlyWhenTheCoreSaysSo() {
        func placed(attributable: Bool) -> PeerSummary {
            var summary = peer(id: 3)
            summary.advertisedIdentity = MeshNodeIdentity(
                roleCode: 3, capabilityBits: [.mobile], forwards: false, name: nil,
                latitude: 38.9, longitude: -120.1, locationPrecision: nil,
                altitudeMeters: nil, timestamp: nil, signature: .valid
            )
            summary.advertisedIdentityIsAttributable = attributable
            return summary
        }
        let unattributed = MapNode.nodes(peers: [placed(attributable: false)], neighborReports: [])
        #expect(unattributed.map(\.isAttributable) == [false])
        let attributed = MapNode.nodes(peers: [placed(attributable: true)], neighborReports: [])
        #expect(attributed.map(\.isAttributable) == [true])
    }

    @Test func aRepeaterPlacesANodeThatHasNotSpokenSinceItAnswered() {
        let repeater = peer(id: 2)
        let neighbor = peer(id: 1, ownAdvertisementAt: now.addingTimeInterval(-7_200))
        let nodes = MapNode.nodes(
            peers: [neighbor, repeater],
            neighborReports: [report(by: repeater, at: now.addingTimeInterval(-3_600))]
        )
        #expect(nodes.map(\.id) == [.neighbor(hint: hint)])
        #expect(nodes.first?.peer?.id == 1)
    }

    /// The node advertised after the repeater answered, and named no position:
    /// the repeater's older copy does not put one back.
    @Test func theNodesOwnLaterAdvertisementOverrulesTheRepeater() {
        let repeater = peer(id: 2)
        let neighbor = peer(id: 1, ownAdvertisementAt: now.addingTimeInterval(-60))
        let nodes = MapNode.nodes(
            peers: [neighbor, repeater],
            neighborReports: [report(by: repeater, at: now.addingTimeInterval(-3_600))]
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

    @Test func aReportAgesByWhenTheRepeaterLastHeardTheNode() throws {
        let repeater = peer(id: 2)
        func reported(minutesAgo: UInt16?) throws -> MapNode {
            try #require(MapNode.nodes(
                peers: [repeater],
                neighborReports: [report(by: repeater, at: now, minutesAgo: minutesAgo)]
            ).first)
        }
        // Two days before the repeater answered.
        let quiet = try reported(minutesAgo: 2_880)
        #expect(!quiet.passes(tier: .all, capabilities: [], recency: .day, now: now))
        #expect(quiet.passes(tier: .all, capabilities: [], recency: .week, now: now))
        // No figure: the repeater still had it when it answered.
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

    /// The goldens Android's `AvatarStyleTest` reads too, so both apps draw a
    /// node and a channel the same.
    @Test func sharedGoldensMatch() throws {
        let url = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .appendingPathComponent("docs/ux/src/apps/avatar-goldens.tsv")
        let rows = try String(contentsOf: url, encoding: .utf8)
            .split(separator: "\n")
            .filter { !$0.hasPrefix("#") && !$0.hasPrefix("kind\t") }
            .map { $0.split(separator: "\t", omittingEmptySubsequences: false).map(String.init) }
        #expect(rows.count > 60)

        func bytes(_ hex: String) -> Data {
            var data = Data()
            var rest = Substring(hex)
            while !rest.isEmpty {
                data.append(UInt8(rest.prefix(2), radix: 16)!)
                rest = rest.dropFirst(2)
            }
            return data
        }
        func octets(_ color: UIColor) -> [Int] {
            var red: CGFloat = 0, green: CGFloat = 0, blue: CGFloat = 0
            color.getRed(&red, green: &green, blue: &blue, alpha: nil)
            return [red, green, blue].map { Int(($0 * 255).rounded()) }
        }

        for row in rows {
            let want = Array(bytes(row[4]))
            switch row[0] {
            case "peer":
                let style = AvatarStyle.peer(hint: MeshNodeHint(bytes: bytes(row[1]), text: row[7]))
                #expect(octets(style.fill) == want.map(Int.init), "fill \(row[1])")
                #expect((style.text == .white) == (row[5] == "white"), "text \(row[1])")
                let capabilities = row[3] == "-" ? nil : MeshNodeCapabilities(rawValue: UInt8(row[3], radix: 16)!)
                let shape = PeerAvatarShape(role: PeerRole(roleCode: UInt8(row[2])!), capabilities: capabilities)
                #expect("\(shape)" == row[6], "shape \(row[1])")
                #expect(style.lines == [String(row[7].prefix(2)), String(row[7].dropFirst(2))])
            case "channel":
                let style = AvatarStyle.channel(canonicalName: nil, title: "X", identifierHex: "00", tint: bytes(row[1]))
                let got = octets(style.fill)
                // UIKit keeps components as floats; the golden rounds them.
                #expect(zip(got, want).allSatisfy { abs($0 - Int($1)) <= 1 }, "fill \(row[1]): \(got)")
                #expect((style.text == .white) == (row[5] == "white"), "text \(row[1])")
            default:
                Issue.record("unknown row kind \(row[0])")
            }
        }
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

@Suite
struct RadioBatteryTests {
    private func record(cached: Bool, phase: MobileRadioPhase) -> MobileRadioStateRecord {
        MobileRadioStateRecord(
            phase: phase, name: "T1000-E", linkId: UUID().uuidString, host: .ours, deviceKey: nil,
            battery: UlcpBatteryRecord(percentage: 78, voltageMv: 3_900, chargeState: .charging),
            batteryReadAtMs: 1_800_000_000_000, batteryCached: cached, alert: nil, clock: nil,
            position: nil, provisioning: nil, problem: nil
        )
    }

    @Test func aReadingFromAnEarlierLinkIsShownWithItsAge() {
        let snapshot = RadioSnapshot(record(cached: true, phase: .reconnecting))
        #expect(snapshot.batteryCached)
        #expect(snapshot.batteryPercentage == 78)
        // A past reading's charge state says nothing about now.
        #expect(snapshot.chargeState == nil)
        let readAt = Date(unixMilliseconds: 1_800_000_000_000)
        let summary = snapshot.accessibleSummary(now: readAt.addingTimeInterval(12 * 60))
        #expect(summary.contains(AgePresentation.text(since: readAt, now: readAt.addingTimeInterval(12 * 60))))
    }

    @Test func aLiveReadingHasNoAge() {
        let snapshot = RadioSnapshot(record(cached: false, phase: .attached))
        #expect(!snapshot.batteryCached)
        #expect(snapshot.chargeState == .charging)
        let readAt = Date(unixMilliseconds: 1_800_000_000_000)
        let later = readAt.addingTimeInterval(12 * 60)
        #expect(!snapshot.accessibleSummary(now: later).contains(AgePresentation.text(since: readAt, now: later)))
    }

    @Test func anAdministeredDeviceShowsOnlyItsLiveReading() {
        #expect(AdministeredDeviceSnapshot(record(cached: true, phase: .reconnecting)).batteryPercentage == nil)
        #expect(AdministeredDeviceSnapshot(record(cached: false, phase: .attached)).batteryPercentage == 78)
    }
}

@Suite
struct TranscriptActionExpiryTests {
    private static func message(
        _ row: Int64,
        reviseUntil: Int64?,
        actions: MessageActions
    ) -> ChatMessageSummary {
        ChatMessageSummary(
            id: "s:\(row)", body: "m\(row)", isOutbound: true, deliveryState: nil,
            isDeleted: false, isEdited: false, sessionID: "s", handle: UInt32(row),
            wireID: nil, epoch: nil,
            cursor: ChatMessageCursor(createdAtMilliseconds: row, rowID: row),
            createdAtMilliseconds: row,
            reviseUntilMilliseconds: reviseUntil,
            actions: actions
        )
    }

    @Test func theWindowIsReadAgainWhenTheFirstOfferLapses() {
        var window = TranscriptWindow()
        window.replace(with: TranscriptPage(messages: [
            // Past its window: it offers nothing timed, so it sets nothing.
            Self.message(1, reviseUntil: 500, actions: MessageActions(delete: true)),
            Self.message(2, reviseUntil: 3_000, actions: MessageActions(edit: true, delete: true)),
            Self.message(3, reviseUntil: 2_000, actions: MessageActions(resend: .inPlace)),
            // Going as new does not lapse.
            Self.message(4, reviseUntil: 1_000, actions: MessageActions(resend: .asNew)),
        ]), revision: 1)
        #expect(window.nextActionExpiry == Date(storeMilliseconds: 2_000))

        window.replace(with: TranscriptPage(messages: [
            Self.message(1, reviseUntil: 500, actions: MessageActions(delete: true)),
        ]), revision: 2)
        #expect(window.nextActionExpiry == nil)
    }
}

/// The Join sheet's alias field (DP3-112): what is filled in for a held
/// channel stays with that channel, and emptying it clears that channel's
/// alias and no other.
@Suite
struct ChannelAliasDraftTests {
    private func held(_ alias: String?) -> ChannelSummary {
        ChannelSummary(
            id: UUID(), kind: .named, canonicalName: "trail crew", name: "trail crew", alias: alias,
            channelIDHex: "0000", tint: Data([0, 0, 0]), regionCode: nil, maxFloodHops: nil,
            joinedPhone: true, notificationsEnabled: true, joinedAt: nil
        )
    }

    @Test func aHeldChannelsAliasIsFilledInAndKeptAsIs() {
        let hikers = held("Hikers")
        var draft = ChannelAliasDraft()
        draft.previewed(hikers)
        #expect(draft.text == "Hikers")
        let outcome = draft.outcome(for: hikers)
        #expect(outcome.alias == "Hikers" && !outcome.clears)
    }

    @Test func emptyingTheFilledInAliasClearsItsChannel() {
        let hikers = held("Hikers")
        var draft = ChannelAliasDraft()
        draft.previewed(hikers)
        draft.type("  ")
        let outcome = draft.outcome(for: hikers)
        #expect(outcome.alias == nil && outcome.clears)
        // Looking the same channel up again keeps the emptied field.
        draft.previewed(hikers)
        #expect(draft.outcome(for: hikers).clears)
    }

    @Test func aFilledInAliasNeverReachesAnotherChannel() {
        let hikers = held("Hikers")
        let bikers = held(nil)
        var draft = ChannelAliasDraft()
        draft.previewed(hikers)
        draft.previewed(bikers)
        #expect(draft.text.isEmpty)
        let outcome = draft.outcome(for: bikers)
        #expect(outcome.alias == nil && !outcome.clears)
        // A channel the phone does not hold starts unnamed too.
        draft.previewed(hikers)
        draft.previewed(nil)
        #expect(draft.text.isEmpty && draft.outcome(for: nil) == (nil, false))
    }

    @Test func anEmptiedFieldShowsTheNextChannelsOwnAlias() {
        let hikers = held("Hikers")
        let bikers = held("Bikers")
        var draft = ChannelAliasDraft()
        draft.previewed(hikers)
        draft.type("")
        draft.previewed(bikers)
        #expect(draft.text == "Bikers" && !draft.outcome(for: bikers).clears)
    }

    @Test func aTypedAliasStaysAcrossLookups() {
        let bikers = held("Bikers")
        var draft = ChannelAliasDraft()
        draft.type("Crew")
        draft.previewed(held("Hikers"))
        draft.previewed(bikers)
        let outcome = draft.outcome(for: bikers)
        #expect(outcome.alias == "Crew" && !outcome.clears)
    }

    @Test func aNewChannelWithAnEmptyFieldJoinsUnnamed() {
        let draft = ChannelAliasDraft()
        #expect(draft.outcome(for: nil) == (nil, false))
    }
}

/// Join through the runtime to a started, radio-less core: emptying a held
/// channel's filled-in alias and joining again clears it in the store.
@Suite @MainActor
struct ChannelJoinAliasRuntimeTests {
    @Test func emptyingAHeldChannelsAliasClearsIt() async throws {
        let fixture = try await StoreFixture()
        defer { fixture.remove() }
        let runtime = AppRuntime(
            radioConnection: NoRadioConnection(),
            opened: .success(try AppCoreHost.radioLess(over: fixture.store, vault: MemorySecretVault()))
        )
        runtime.localIdentity = fixture.identity
        let core = try #require(runtime.core)
        try await core.start(identity: MobileIdentity.unlock(secretKey: Data(repeating: 7, count: 32)))
        do {
            let join = try #require(runtime.channelActions(enterConversation: { _ in }).join)
            var typed = ChannelAliasDraft()
            typed.type("Hikers")
            _ = try await typed.join("Ridge", existing: nil, openConversation: false, through: join)
            let held = try #require(runtime.channels.first { $0.kind != .builtin })
            #expect(held.alias == "Hikers")

            // Joining again with the filled-in alias untouched keeps it.
            var kept = ChannelAliasDraft()
            kept.previewed(held)
            _ = try await kept.join("Ridge", existing: held, openConversation: false, through: join)
            #expect(runtime.channels.first { $0.id == held.id }?.alias == "Hikers")

            var emptied = ChannelAliasDraft()
            emptied.previewed(held)
            emptied.type("")
            _ = try await emptied.join("Ridge", existing: held, openConversation: false, through: join)
            let cleared = try #require(runtime.channels.first { $0.id == held.id })
            #expect(cleared.alias == nil && cleared.joinedPhone)
        } catch {
            await core.stop()
            throw error
        }
        await core.stop()
    }
}
