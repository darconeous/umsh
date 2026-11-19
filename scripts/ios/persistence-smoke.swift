import Foundation
import SQLite3
import UMSHMobileCore

@main
struct PersistenceSmokeTest {
    static func main() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("umsh-persistence-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let databaseURL = root.appendingPathComponent("application.sqlite")

        let store = try SQLiteApplicationStore(path: databaseURL.path)
        let initialSchemaVersion = try await store.schemaVersion()
        precondition(initialSchemaVersion >= 31, "a new store is at or past the baseline")

        try await store.insertIdentity(id: "alice", publicAddress: "alice-public")

        // A user-initiated import is saved.
        try await store.upsertPeer(
            ownerIdentityID: "alice",
            publicAddress: "peer-saved",
            alias: "Ridge Medic",
            isSaved: true
        )
        // An over-the-air advertisement lands in the transient tier.
        try await store.upsertPeer(
            ownerIdentityID: "alice",
            publicAddress: "peer-transient",
            alias: nil,
            advertisedName: "Roaming Node"
        )
        var nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "peer-saved").isSaved)
        precondition(!node(nodes, "peer-transient").isSaved)

        // A background advertisement upsert must never demote a saved peer.
        try await store.upsertPeer(
            ownerIdentityID: "alice",
            publicAddress: "peer-saved",
            alias: nil,
            advertisedName: "Ridge Medic Node"
        )
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "peer-saved").isSaved)

        // Promote a transient; favorite it (favoriting implies saved).
        try await store.promotePeerToSaved(ownerIdentityID: "alice", publicAddress: "peer-transient")
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "peer-transient").isSaved)
        try await store.setPeerFavorite(
            ownerIdentityID: "alice",
            publicAddress: "peer-transient",
            isFavorite: true
        )
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "peer-transient").isFavorite)

        // Demote clears favorite and alias but keeps the row.
        try await store.demotePeerToTransient(ownerIdentityID: "alice", publicAddress: "peer-saved")
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(!node(nodes, "peer-saved").isSaved)
        precondition(node(nodes, "peer-saved").alias == nil)
        try await store.promotePeerToSaved(ownerIdentityID: "alice", publicAddress: "peer-saved")

        // Delete refuses a peer with a conversation; the combined delete works
        // and removes both.
        let conversationID = try await store.ensureDirectConversation(
            ownerIdentityID: "alice",
            peerAddress: "peer-saved"
        )
        try await store.updateDraft(
            ownerIdentityID: "alice",
            conversationID: conversationID,
            text: "Draft survives relaunch"
        )
        let conversations = try await store.listDirectConversations(ownerIdentityID: "alice")
        precondition(conversations.count == 1)
        precondition(conversations[0].draftText == "Draft survives relaunch")
        let refused = try await store.deletePeer(ownerIdentityID: "alice", publicAddress: "peer-saved")
        precondition(!refused)
        let removed = try await store.deletePeerAndConversation(
            ownerIdentityID: "alice",
            publicAddress: "peer-saved"
        )
        precondition(removed)
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(!nodes.contains { $0.publicAddress == "peer-saved" })
        let remainingConversations = try await store.listDirectConversations(ownerIdentityID: "alice")
        precondition(remainingConversations.isEmpty)

        // Plain delete works for a peer without a conversation.
        let deleted = try await store.deletePeer(ownerIdentityID: "alice", publicAddress: "peer-transient")
        precondition(deleted)

        // The companion radio row is protected from delete and demote.
        try await store.upsertUlcpDevicePeer(
            ownerIdentityID: "alice",
            publicAddress: "radio-peer",
            advertisedName: "Tracker",
            radioIdentifier: "AAAA"
        )
        let radioDeleted = try await store.deletePeer(ownerIdentityID: "alice", publicAddress: "radio-peer")
        precondition(!radioDeleted)
        try await store.demotePeerToTransient(ownerIdentityID: "alice", publicAddress: "radio-peer")
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "radio-peer").isSaved)

        // Retention keeps the newest-heard transients up to the cap; rows with
        // a conversation are never evicted. clearTransientPeers drops the rest.
        for index in 0..<5 {
            let address = "flood-\(index)"
            try await store.upsertPeer(
                ownerIdentityID: "alice",
                publicAddress: address,
                alias: nil
            )
            try await store.touchLastHeard(
                ownerIdentityID: "alice",
                publicAddress: address,
                at: Date(timeIntervalSince1970: 1_000 + Double(index))
            )
        }
        _ = try await store.ensureDirectConversation(ownerIdentityID: "alice", peerAddress: "flood-0")
        try await store.enforceTransientRetention(ownerIdentityID: "alice", cap: 2)
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        let survivingTransients = nodes.filter { $0.publicAddress.hasPrefix("flood-") }
        // flood-0 survives via its conversation; flood-4 and flood-3 are the
        // two newest-heard evictable rows.
        precondition(
            Set(survivingTransients.map(\.publicAddress)) == ["flood-0", "flood-3", "flood-4"]
        )
        try await store.clearTransientPeers(ownerIdentityID: "alice")
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(
            Set(nodes.filter { $0.publicAddress.hasPrefix("flood-") }.map(\.publicAddress))
                == ["flood-0"]
        )

        // Device-identity reconcile: the device's read-back is authority.
        // Known keys gain the flag, unknown keys gain a transient row, and
        // keys absent from the list lose the flag (rows survive).
        try await store.reconcileDeviceIdentityPeers(
            ownerIdentityID: "alice",
            addresses: ["flood-0", "device-only-peer"]
        )
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "flood-0").onDeviceIdentity)
        let deviceOnly = node(nodes, "device-only-peer")
        precondition(deviceOnly.onDeviceIdentity && !deviceOnly.isSaved)
        try await store.reconcileDeviceIdentityPeers(ownerIdentityID: "alice", addresses: [])
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(nodes.allSatisfy { !$0.onDeviceIdentity })
        precondition(nodes.contains { $0.publicAddress == "device-only-peer" })
        // The single-flag cache setter round-trips too.
        try await store.setPeerOnDeviceIdentity(
            ownerIdentityID: "alice",
            publicAddress: "flood-0",
            isOnDeviceIdentity: true
        )
        nodes = try await store.listNodes(ownerIdentityID: "alice")
        precondition(node(nodes, "flood-0").onDeviceIdentity)
        try await store.setPeerOnDeviceIdentity(
            ownerIdentityID: "alice",
            publicAddress: "flood-0",
            isOnDeviceIdentity: false
        )
        try await store.deletePeer(ownerIdentityID: "alice", publicAddress: "device-only-peer")

        // A file older than the baseline is refused and left as it was:
        // the Swift migrations that would have upgraded it are gone.
        let historicalURL = root.appendingPathComponent("historical.sqlite")
        try createHistoricalStore(path: historicalURL.path)
        let historicalBytes = try Data(contentsOf: historicalURL)
        do {
            _ = try SQLiteApplicationStore(path: historicalURL.path)
            preconditionFailure("A v12 store must be refused")
        } catch ApplicationStoreError.unsupportedSchema(let version) {
            precondition(version == 12)
        }
        let historicalAfter = try Data(contentsOf: historicalURL)
        precondition(historicalAfter == historicalBytes)

        try await checkReplies(store)
        try await checkRepeats(store)
        try await checkClaimedRadios(store)
        try await checkRemainingCalls(store)
        try await checkReopenAndErase(store, path: databaseURL.path)

        print("SQLite tier, delete/demote, retention, refusal, reply, repeat, claimed-radio, round-trip, and reopen checks passed")

        // Seeding tens of thousands of rows takes long enough that the ordinary
        // smoke run should not pay for it.
        if ProcessInfo.processInfo.environment["UMSH_CHAT_BENCH"] == "1" {
            try await runChatScaleBenchmark()
        }
    }

    /// A radio left holding the identity is remembered until it is cleared
    /// or its record lapses, and an attach refreshes it.
    private static func checkClaimedRadios(_ store: SQLiteApplicationStore) async throws {
        let start = Date(timeIntervalSince1970: 1_800_000_000)
        try await store.recordClaimedRadio(
            ownerIdentityID: "alice", deviceAddress: "radio-a", name: "Ridge", now: start
        )
        try await store.recordClaimedRadio(
            ownerIdentityID: "alice", deviceAddress: "radio-b", name: nil,
            now: start.addingTimeInterval(60)
        )
        var radios = try await store.claimedRadios(ownerIdentityID: "alice", now: start)
        precondition(radios.map(\.deviceAddress) == ["radio-b", "radio-a"])
        precondition(radios[1].name == "Ridge" && radios[0].name == nil)

        // Attaching again moves the lapse out.
        let later = start.addingTimeInterval(StoredClaimedRadio.lapse - 1)
        try await store.recordClaimedRadio(
            ownerIdentityID: "alice", deviceAddress: "radio-a", name: "Ridge", now: later
        )
        radios = try await store.claimedRadios(
            ownerIdentityID: "alice", now: start.addingTimeInterval(StoredClaimedRadio.lapse + 60)
        )
        precondition(radios.map(\.deviceAddress) == ["radio-a"])

        try await store.clearClaimedRadio(ownerIdentityID: "alice", deviceAddress: "radio-a")
        radios = try await store.claimedRadios(ownerIdentityID: "alice", now: later)
        precondition(radios.isEmpty)
    }

    /// The repeaters heard carrying a message fold across its fragments and
    /// across each fragment's transmissions: named ones merged, anonymous
    /// ones counted as the most any fragment heard.
    private static func checkRepeats(_ store: SQLiteApplicationStore) async throws {
        let peer = "repeat-peer"
        _ = try await store.applyChatMutations(ownerIdentityID: "alice", mutations: [
            MobileChatMutationRecord(
                sessionId: 300, handle: 1, revision: 0, kind: .insert,
                conversationAddress: peer, senderAddress: nil, senderHint: nil,
                direction: .outbound, messageType: 0, wireId: 1, epoch: 0,
                clientToken: nil, senderHandle: nil, regardingHandle: nil,
                regardingWireId: nil, regardingDirection: nil,
                regardingSenderHint: nil, regardingUnknown: false, unknownOriginal: false,
                backgroundColor: nil, textColor: nil,
                originalHandle: nil, originalWireId: nil, originalDirection: nil,
                originalSenderHint: nil, body: "Anyone on the ridge?", complete: true,
                presentFragments: 2, fragmentCount: 2, finalized: true, presence: .present,
                receivedLate: false, notify: false, rx: nil, forwardSecret: nil
            ),
        ])
        func stored() async throws -> StoredChatMessage {
            let page = try await store.chatMessagePage(
                ownerIdentityID: "alice", conversationAddress: peer, newest: 10
            )
            return page.messages[0]
        }
        let unsent = try await stored()
        precondition(unsent.repeats == nil, "nothing sent, so no repeats yet")

        try await store.applyChatDeliveries(ownerIdentityID: "alice", deliveries: [
            .init(sessionId: 300, handle: 1, fragmentIndex: 0, state: .sent, viaFlood: false),
        ])
        let sent = try await stored()
        precondition(sent.deliveryState == "sent")
        precondition(sent.repeats?.count == 0, "sending stamps the message's progress")

        let ridge = RouterHintRecord(bytes: Data([0x01, 0x02]), text: "ridge")
        let butte = RouterHintRecord(bytes: Data([0x03, 0x04]), text: "butte")
        let peak = RouterHintRecord(bytes: Data([0x05, 0x06]), text: "peak")
        try await store.applyChatRepeats(ownerIdentityID: "alice", repeats: [
            .init(sessionId: 300, handle: 1, fragmentIndex: 0, repeaters: [ridge],
                  anonymousRepeats: 1),
            .init(sessionId: 300, handle: 1, fragmentIndex: 1, repeaters: [ridge, butte],
                  anonymousRepeats: 0),
            // A resend of the first fragment tallies afresh.
            .init(sessionId: 300, handle: 1, fragmentIndex: 0, repeaters: [peak],
                  anonymousRepeats: 0),
        ])
        let repeats = try await stored().repeats
        precondition(repeats?.repeaters.first == Data([0x01, 0x02]))
        precondition(Set(repeats?.repeaters ?? []) == [
            Data([0x01, 0x02]), Data([0x03, 0x04]), Data([0x05, 0x06]),
        ])
        precondition(repeats?.anonymous == 1)
        precondition(repeats?.count == 4)
    }

    /// A reply quotes its original as that reads now: found by live handle or
    /// by wire coordinates, adopted when it arrives after the reply, shown as
    /// deleted once taken back, and unavailable when it never comes.
    private static func checkReplies(_ store: SQLiteApplicationStore) async throws {
        let peer = "reply-peer"
        func message(
            session: UInt64,
            handle: UInt32,
            revision: UInt32 = 0,
            kind: MobileChatMutationKind = .insert,
            direction: MobileChatDirection = .inbound,
            wireId: UInt8? = nil,
            body: String? = nil,
            regardingHandle: UInt32? = nil,
            regardingWireId: UInt8? = nil,
            originalHandle: UInt32? = nil,
            presence: MobileChatPresence = .present
        ) -> MobileChatMutationRecord {
            MobileChatMutationRecord(
                sessionId: session, handle: handle, revision: revision, kind: kind,
                conversationAddress: peer, senderAddress: nil, senderHint: nil,
                direction: direction, messageType: 0, wireId: wireId, epoch: 0,
                clientToken: nil, senderHandle: nil, regardingHandle: regardingHandle,
                regardingWireId: regardingWireId,
                regardingDirection: regardingWireId == nil ? nil : .inbound,
                regardingSenderHint: nil, regardingUnknown: false, unknownOriginal: false,
                backgroundColor: nil, textColor: nil,
                originalHandle: originalHandle, originalWireId: nil, originalDirection: nil,
                originalSenderHint: nil, body: body, complete: true, presentFragments: 1,
                fragmentCount: 1, finalized: true, presence: presence, receivedLate: false,
                notify: false, rx: nil, forwardSecret: nil
            )
        }
        func page() async throws -> [String: StoredChatMessage] {
            let page = try await store.chatMessagePage(
                ownerIdentityID: "alice",
                conversationAddress: peer,
                newest: 100
            )
            return Dictionary(uniqueKeysWithValues: page.messages.map { ($0.body, $0) })
        }

        _ = try await store.applyChatMutations(ownerIdentityID: "alice", mutations: [
            message(session: 100, handle: 1, wireId: 5, body: "Is the repeater up?"),
            // Same session: named by its live handle.
            message(session: 100, handle: 2, direction: .outbound, wireId: 1,
                    body: "Since this morning.", regardingHandle: 1),
        ])
        _ = try await store.applyChatMutations(ownerIdentityID: "alice", mutations: [
            // A later session: named by wire coordinates.
            message(session: 200, handle: 1, wireId: 6, body: "Three hops?", regardingWireId: 5),
            // Ahead of its original.
            message(session: 200, handle: 2, wireId: 8, body: "Bring the antenna.",
                    regardingWireId: 7),
            // Never answered by anything stored.
            message(session: 200, handle: 3, wireId: 9, body: "Ten minutes late.",
                    regardingWireId: 77),
            // A gap that turns out to be a reply once repaired.
            message(session: 200, handle: 4, wireId: 10, body: "", presence: .gapPending),
        ])
        var rows = try await page()
        precondition(rows["Since this morning."]?.quote?.original?.body == "Is the repeater up?")
        precondition(rows["Three hops?"]?.quote?.original?.ref.id == "100:1")
        precondition(rows["Bring the antenna."]?.isReply == true)
        precondition(rows["Bring the antenna."]?.quote?.original == nil)
        precondition(rows["Ten minutes late."]?.quote == .unavailable)
        precondition(rows["Is the repeater up?"]?.quote == nil, "an original is not a reply")

        _ = try await store.applyChatMutations(ownerIdentityID: "alice", mutations: [
            message(session: 200, handle: 5, wireId: 7, body: "The antenna is in the truck."),
            message(session: 200, handle: 4, revision: 1, wireId: 10, body: "Filled in.",
                    regardingWireId: 7),
            message(session: 100, handle: 6, kind: .delete, originalHandle: 1),
        ])
        rows = try await page()
        precondition(
            rows["Bring the antenna."]?.quote?.original?.body == "The antenna is in the truck.",
            "a reply that outran its original adopts it"
        )
        precondition(rows["Filled in."]?.quote?.original?.ref.id == "200:5")
        precondition(rows["Three hops?"]?.quote?.original?.isDeleted == true)
    }

    /// The calls the checks above leave out, each written with a different
    /// value in every argument and read back, so one the store drops or
    /// crosses with its neighbor shows.
    private static func checkRemainingCalls(_ store: SQLiteApplicationStore) async throws {
        let owner = "dana"
        func at(_ seconds: Double) -> Date { Date(timeIntervalSince1970: 1_780_000_000 + seconds) }
        func peer(_ address: String) async throws -> StoredNode {
            node(try await store.listNodes(ownerIdentityID: owner), address)
        }
        func transcript(_ address: String) async throws -> [StoredChatMessage] {
            try await store.chatMessagePage(
                ownerIdentityID: owner, conversationAddress: address, newest: 100
            ).messages
        }
        func message(
            session: UInt64, handle: UInt32, address: String,
            direction: MobileChatDirection = .inbound, messageType: UInt8 = 0,
            wireId: UInt8, epoch: UInt16 = 0, body: String,
            senderHint: Data? = nil, regardingHandle: UInt32? = nil,
            presence: MobileChatPresence = .present, notify: Bool = false,
            rx: MobileChatRxMetadataRecord? = nil, fragments: UInt8 = 1
        ) -> MobileChatMutationRecord {
            MobileChatMutationRecord(
                sessionId: session, handle: handle, revision: 0, kind: .insert,
                conversationAddress: address, senderAddress: nil, senderHint: senderHint,
                direction: direction, messageType: messageType, wireId: wireId, epoch: epoch,
                clientToken: nil, senderHandle: nil, regardingHandle: regardingHandle,
                regardingWireId: nil, regardingDirection: nil,
                regardingSenderHint: nil, regardingUnknown: false, unknownOriginal: false,
                backgroundColor: nil, textColor: nil,
                originalHandle: nil, originalWireId: nil, originalDirection: nil,
                originalSenderHint: nil, body: body, complete: true,
                presentFragments: UInt16(fragments), fragmentCount: fragments, finalized: true,
                presence: presence, receivedLate: false, notify: notify, rx: rx,
                forwardSecret: nil
            )
        }

        // Identity.
        try await store.upsertIdentity(id: owner, publicAddress: "dana-public", createdAt: at(1))
        try await store.upsertIdentity(id: owner, publicAddress: "dana-public", createdAt: at(2))
        let known = try await store.knowsIdentity(id: owner, publicAddress: "dana-public")
        let unknown = try await store.knowsIdentity(id: "nobody", publicAddress: "nobody-public")
        precondition(known && !unknown)
        var localName = try await store.localAdvertisedName(ownerIdentityID: owner)
        precondition(localName == nil)
        try await store.updateLocalAdvertisedName(ownerIdentityID: owner, name: "Dana")
        localName = try await store.localAdvertisedName(ownerIdentityID: owner)
        precondition(localName == "Dana")
        let otherName = try await store.localAdvertisedName(ownerIdentityID: "alice")
        precondition(otherName == nil, "a name belongs to one identity")

        // Peers.
        try await store.upsertPeer(
            ownerIdentityID: owner, publicAddress: "relay", alias: "Relay",
            advertisedName: "relay-adv", isSaved: true, nodeKind: "repeater",
            advertisement: Data([1, 2, 3]), advertisementAuthenticated: true,
            advertisementReceivedAt: at(10)
        )
        try await store.upsertPeer(
            ownerIdentityID: owner, publicAddress: "friend", alias: "Friend",
            isSaved: true, nodeKind: "chat"
        )
        var relay = try await peer("relay")
        precondition(relay.alias == "Relay" && relay.advertisedName == "relay-adv")
        precondition(relay.nodeKind == "repeater" && relay.advertisement == Data([1, 2, 3]))
        precondition(relay.advertisementAuthenticated && relay.advertisementReceivedAt == at(10))
        try await store.updateNodeAlias(ownerIdentityID: owner, publicAddress: "relay", alias: "Ridge relay")
        try await store.setNotifyWhenHeard(ownerIdentityID: owner, publicAddress: "relay", enabled: true)
        relay = try await peer("relay")
        var friend = try await peer("friend")
        precondition(relay.alias == "Ridge relay" && relay.notifyWhenHeard)
        precondition(friend.alias == "Friend" && !friend.notifyWhenHeard)
        let wasWatched = try await store.touchLastHeard(
            ownerIdentityID: owner, publicAddress: "relay", at: at(20)
        )
        relay = try await peer("relay")
        precondition(wasWatched && !relay.notifyWhenHeard && relay.lastHeardAt == at(20))

        // Channels.
        let named = StoredChannel(
            id: UUID(), ownerIdentityID: owner, kind: .named, canonicalName: "general",
            name: "General", alias: nil, channelIDHex: "a1b2", tint: Data([1, 2, 3]),
            regionCode: Data([0x55, 0x53]), maxFloodHops: 3, joinedPhone: true,
            joinedDevice: false, notificationsEnabled: true, joinedAt: at(30)
        )
        let secret = StoredChannel(
            id: UUID(), ownerIdentityID: owner, kind: .privateKey, canonicalName: nil,
            name: nil, alias: "Secret", channelIDHex: "c3d4", tint: Data([9]),
            regionCode: nil, maxFloodHops: nil, joinedPhone: false,
            joinedDevice: true, notificationsEnabled: false, joinedAt: nil
        )
        func channel(_ id: UUID) async throws -> StoredChannel? {
            try await store.channels(ownerIdentityID: owner).first { $0.id == id }
        }
        try await store.insertChannel(named, keyDigest: "digest-named")
        try await store.insertChannel(secret, keyDigest: "digest-secret")
        var readNamed = try await channel(named.id)
        var readSecret = try await channel(secret.id)
        precondition(readNamed == named && readSecret == secret)
        let byDigest = try await store.channel(ownerIdentityID: owner, keyDigest: "digest-secret")
        let otherOwner = try await store.channel(ownerIdentityID: "alice", keyDigest: "digest-secret")
        precondition(byDigest == secret && otherOwner == nil)
        try await store.updateChannelDetails(
            id: secret.id, alias: "Renamed", regionCode: Data([1, 2]), maxFloodHops: 5,
            notificationsEnabled: true
        )
        try await store.setChannelMembership(id: secret.id, joinedPhone: true, joinedDevice: false)
        readSecret = try await channel(secret.id)
        precondition(readSecret?.alias == "Renamed" && readSecret?.regionCode == Data([1, 2]))
        precondition(readSecret?.maxFloodHops == 5 && readSecret?.notificationsEnabled == true)
        precondition(readSecret?.joinedPhone == true && readSecret?.joinedDevice == false)
        precondition(readSecret?.joinedAt != nil, "the phone's first join is dated")
        readNamed = try await channel(named.id)
        precondition(readNamed == named, "changing one channel leaves the other")

        // Conversations.
        let direct = try await store.ensureDirectConversation(ownerIdentityID: owner, peerAddress: "friend")
        let general = try await store.ensureChannelConversation(
            ownerIdentityID: owner, channelID: named.id, conversationAddress: "general-address"
        )
        let hidden = try await store.ensureChannelConversation(
            ownerIdentityID: owner, channelID: secret.id, conversationAddress: "secret-address"
        )
        try await store.updateChannelDraft(ownerIdentityID: owner, conversationID: general, text: "channel draft")
        try await store.setDirectConversationNotifications(
            ownerIdentityID: owner, conversationID: direct, enabled: false
        )
        var directs = try await store.listDirectConversations(ownerIdentityID: owner)
        precondition(directs.map(\.id) == [direct] && directs[0].node.publicAddress == "friend")
        precondition(!directs[0].notificationsEnabled)
        var channelConversations = try await store.listChannelConversations(ownerIdentityID: owner)
        let readGeneral = channelConversations.first { $0.id == general }
        precondition(Set(channelConversations.map(\.id)) == [general, hidden])
        precondition(readGeneral?.channelID == named.id)
        precondition(readGeneral?.conversationAddress == "general-address")
        precondition(readGeneral?.draftText == "channel draft")

        // Chat: what arrives.
        let reception = StoredMessageReception(
            rssiDbm: -101, snrCentibels: -35, lqi: 200, hopCount: 3,
            routeHints: [Data([1, 2]), Data([3, 4])], sourceAuthenticated: true
        )
        _ = try await store.applyChatMutations(ownerIdentityID: owner, mutations: [
            message(session: 700, handle: 1, address: "friend", wireId: 1, body: "Hello", notify: true,
                    rx: MobileChatRxMetadataRecord(
                        rssiDbm: -101, snrCentibels: -35, lqi: 200, hopCount: 3,
                        routeHints: [Data([1, 2]), Data([3, 4])], sourceAuthenticated: true,
                        bufferedAgeSeconds: 0
                    )),
            message(session: 700, handle: 2, address: "friend", direction: .outbound, wireId: 1,
                    body: "Hi back"),
            message(session: 700, handle: 3, address: "friend", messageType: 1, wireId: 2,
                    body: "+1", regardingHandle: 2, notify: true),
            message(session: 700, handle: 4, address: "friend", wireId: 3, body: "",
                    presence: .gapPending),
            message(session: 710, handle: 1, address: "general-address", wireId: 1,
                    body: "On the channel", senderHint: Data([0xAA, 0xBB, 0xCC]), notify: true),
        ])
        var messages = try await transcript("friend")
        let hello = messages.first { $0.body == "Hello" }
        precondition(hello?.sessionID == "700" && hello?.handle == 1 && hello?.wireID == 1)
        precondition(hello?.reception == reception)
        precondition(messages.first { $0.body == "Hi back" }?.reactions.map(\.body) == ["+1"])
        precondition(messages.contains { $0.isGapPlaceholder })
        let count = try await store.chatMessageCount(ownerIdentityID: owner, conversationAddress: "friend")
        precondition(count == 3, "a reaction is not a message")
        let cursor = try await store.chatMessageCursor(
            ownerIdentityID: owner, conversationAddress: "friend", sessionID: "700", handle: 1
        )
        let strayCursor = try await store.chatMessageCursor(
            ownerIdentityID: owner, conversationAddress: "general-address", sessionID: "700", handle: 1
        )
        precondition(cursor == hello?.cursor && strayCursor == nil)

        let directAddress = try await store.conversationAddressForMessage(
            ownerIdentityID: owner, sessionID: 700, handle: 1
        )
        let channelAddress = try await store.conversationAddressForMessage(
            ownerIdentityID: owner, sessionID: 710, handle: 1
        )
        let noAddress = try await store.conversationAddressForMessage(
            ownerIdentityID: owner, sessionID: 710, handle: 2
        )
        precondition(directAddress == "friend" && channelAddress == "general-address" && noAddress == nil)
        let banner = try await store.chatNotificationTarget(ownerIdentityID: owner, sessionID: 700, handle: 1)
        let reactionAsMessage = try await store.chatNotificationTarget(
            ownerIdentityID: owner, sessionID: 700, handle: 3
        )
        precondition(banner?.conversationAddress == "friend" && banner?.body == "Hello")
        precondition(reactionAsMessage == nil)
        let reacted = try await store.chatReactionNotificationTarget(
            ownerIdentityID: owner, sessionID: 700, handle: 3
        )
        let messageAsReaction = try await store.chatReactionNotificationTarget(
            ownerIdentityID: owner, sessionID: 700, handle: 1
        )
        precondition(reacted?.conversationAddress == "friend" && reacted?.body == "+1")
        precondition(reacted?.targetBody == "Hi back" && messageAsReaction == nil)
        var channelBanner = try await store.chatNotificationTarget(
            ownerIdentityID: owner, sessionID: 710, handle: 1
        )
        precondition(channelBanner?.senderHint == Data([0xAA, 0xBB, 0xCC]))
        precondition(channelBanner?.senderAddress == nil)
        try await store.applySenderResolution(
            ownerIdentityID: owner, conversationAddress: "general-address",
            senderHint: Data([0xAA, 0xBB, 0xCC]), senderAddress: "relay"
        )
        channelBanner = try await store.chatNotificationTarget(ownerIdentityID: owner, sessionID: 710, handle: 1)
        precondition(channelBanner?.senderAddress == "relay")

        try await store.resolveGapsUnavailable(ownerIdentityID: owner, rows: [(sessionID: "700", handle: 4)])
        messages = try await transcript("friend")
        precondition(!messages.contains { $0.isGapPlaceholder })
        precondition(messages.contains { $0.isUnavailable })

        // Chat: what is composed.
        try await store.commitChatComposeBatch(ownerIdentityID: owner, batch: MobileChatComposeBatchRecord(
            batchId: 1, checkpoint: .init(conversationAddress: "friend", nextId: 5, epoch: 2),
            archiveDeletes: [],
            archives: [
                .init(conversationAddress: "friend", messageId: 4, fragmentIndex: 0, payload: Data([1, 2, 3])),
                .init(conversationAddress: "friend", messageId: 4, fragmentIndex: 1, payload: Data([4, 5])),
            ],
            mutations: [message(session: 720, handle: 1, address: "friend", direction: .outbound,
                                wireId: 4, epoch: 2, body: "Composed", fragments: 2)]
        ))
        var checkpoints = try await store.chatCheckpoints(ownerIdentityID: owner)
        precondition(checkpoints.map(\.conversationAddress) == ["friend"])
        precondition(checkpoints[0].nextId == 5 && checkpoints[0].epoch == 2)
        let secondFragment = try await store.chatArchive(ownerIdentityID: owner, lookup: .init(
            requestId: 0, conversationAddress: "friend", messageId: 4, fragmentIndex: 1
        ))
        let notArchived = try await store.chatArchive(ownerIdentityID: owner, lookup: .init(
            requestId: 0, conversationAddress: "friend", messageId: 5, fragmentIndex: 1
        ))
        precondition(secondFragment == Data([4, 5]) && notArchived == nil)
        var frames = try await store.chatResendFrames(
            ownerIdentityID: owner, conversationAddress: "friend", sessionID: "720", handle: 1, wireID: 4
        )
        precondition(frames.map(\.payload) == [Data([1, 2, 3]), Data([4, 5])])
        precondition(frames.map(\.fragmentIndex) == [0, 1])

        // A resend goes out under a new transmission; word of that one
        // reaches the message.
        try await store.applyChatResends(ownerIdentityID: owner, resends: [
            .init(message: .init(sessionId: 720, handle: 1, wireId: 4, epoch: 2),
                  deliverySessionId: 800, deliveryHandle: 9, forwardSecret: true),
        ])
        _ = try await store.applyChatDeliveries(ownerIdentityID: owner, deliveries: [
            .init(sessionId: 800, handle: 9, fragmentIndex: 0, state: .acknowledged, viaFlood: false),
        ])
        frames = try await store.chatResendFrames(
            ownerIdentityID: owner, conversationAddress: "friend", sessionID: "720", handle: 1, wireID: 4
        )
        precondition(frames.map(\.fragmentIndex) == [1], "an acknowledged fragment is not sent again")
        messages = try await transcript("friend")
        precondition(messages.first { $0.body == "Composed" }?.isForwardSecret == true)

        // A compose made durable that the engine could not release is
        // marked, and can be taken back out.
        let unreleasedBatch = MobileChatComposeBatchRecord(
            batchId: 2, checkpoint: .init(conversationAddress: "friend", nextId: 6, epoch: 2),
            archiveDeletes: [], archives: [],
            mutations: [message(session: 720, handle: 2, address: "friend", direction: .outbound,
                                wireId: 5, epoch: 2, body: "Never released")]
        )
        try await store.commitChatComposeBatch(ownerIdentityID: owner, batch: unreleasedBatch)
        try await store.markChatComposeBatchFailed(ownerIdentityID: owner, batch: unreleasedBatch)
        checkpoints = try await store.chatCheckpoints(ownerIdentityID: owner)
        precondition(checkpoints[0].nextId == 6)
        messages = try await transcript("friend")
        let unreleased = messages.first { $0.body == "Never released" }
        precondition(unreleased?.deliveryState == "undelivered")
        precondition(messages.first { $0.body == "Composed" }?.deliveryState != "undelivered")
        try await store.removeFailedMessage(ownerIdentityID: owner, sessionID: "720", handle: 2)
        try await store.removeFailedMessage(ownerIdentityID: owner, sessionID: "700", handle: 1)
        messages = try await transcript("friend")
        precondition(!messages.contains { $0.body == "Never released" })
        precondition(messages.contains { $0.body == "Hello" }, "only a failed message can be removed")

        // What a previous process left pending never went out.
        _ = try await store.applyChatMutations(ownerIdentityID: owner, mutations: [
            message(session: 730, handle: 1, address: "friend", direction: .outbound, wireId: 6,
                    body: "Left pending"),
        ])
        try await store.settleInterruptedDeliveries(ownerIdentityID: owner)
        messages = try await transcript("friend")
        precondition(messages.first { $0.body == "Left pending" }?.deliveryState == "undelivered")

        // Device management cache.
        let card = StoredManagementCard(
            capabilities: Data([1, 2]), deviceVersion: "1.0", deviceModel: "T1000",
            deviceName: "Ridge", fetchedAt: at(40)
        )
        try await store.saveManagementCard(ownerIdentityID: owner, publicAddress: "relay", card: card)
        try await store.saveCachedProperties(
            ownerIdentityID: owner, publicAddress: "relay", values: [1: Data([1]), 70: Data([7, 0])], at: at(41)
        )
        var readCard = try await store.managementCard(ownerIdentityID: owner, publicAddress: "relay")
        let noCard = try await store.managementCard(ownerIdentityID: owner, publicAddress: "friend")
        precondition(readCard == card && noCard == nil)
        var properties = try await store.cachedProperties(
            ownerIdentityID: owner, publicAddress: "relay", propertyIDs: [1, 70, 5]
        )
        precondition(properties == [
            1: StoredCachedProperty(value: Data([1]), fetchedAt: at(41)),
            70: StoredCachedProperty(value: Data([7, 0]), fetchedAt: at(41)),
        ])
        properties = try await store.cachedProperties(
            ownerIdentityID: owner, publicAddress: "relay", propertyIDs: [70]
        )
        precondition(Array(properties.keys) == [70], "only what was asked for")
        // Different firmware may hold different properties.
        try await store.saveManagementCard(ownerIdentityID: owner, publicAddress: "relay", card: StoredManagementCard(
            capabilities: Data([1, 2]), deviceVersion: "1.1", deviceModel: "T1000",
            deviceName: "Ridge", fetchedAt: at(42.0006)
        ))
        properties = try await store.cachedProperties(
            ownerIdentityID: owner, publicAddress: "relay", propertyIDs: [1, 70]
        )
        precondition(properties.isEmpty)
        // This cache's stamps go to the nearest millisecond; a message's
        // (below) drop the fraction. Rows already stored were written so.
        readCard = try await store.managementCard(ownerIdentityID: owner, publicAddress: "relay")
        let fetchedAtMilliseconds = readCard.map { ($0.fetchedAt.timeIntervalSince1970 * 1_000).rounded() }
        precondition(fetchedAtMilliseconds == 1_780_000_042_001)
        try await store.forgetManagementCache(ownerIdentityID: owner, publicAddress: "relay")
        readCard = try await store.managementCard(ownerIdentityID: owner, publicAddress: "relay")
        precondition(readCard == nil)

        // Repeater listings.
        let full = StoredPeerRepeaterEntry(
            hint: Data([1, 2]), name: "North", rssiDBm: -90, snrQuarterDB: -12,
            lastHeardMinutes: 65_535, latitude: 45.125, longitude: -122.25, locationPrecision: 3,
            regionCodes: [Data([0x55, 0x53]), Data([1, 2])], reportedAt: at(50)
        )
        let bare = StoredPeerRepeaterEntry(
            hint: Data([3, 4, 5]), name: nil, rssiDBm: nil, snrQuarterDB: nil,
            lastHeardMinutes: nil, latitude: nil, longitude: nil, locationPrecision: nil,
            regionCodes: [], reportedAt: at(50)
        )
        try await store.savePeerRepeaterPage(
            ownerIdentityID: owner, publicAddress: "relay", entries: [full, bare], total: 5,
            nextCursor: Data([9]), replacing: true, at: at(51)
        )
        var listing = try await store.peerRepeaterListing(ownerIdentityID: owner, publicAddress: "relay")
        precondition(listing?.total == 5 && listing?.nextCursor == Data([9]) && listing?.asOf == at(51))
        precondition(listing?.entries.count == 2)
        precondition(listing?.entries.contains(full) == true && listing?.entries.contains(bare) == true)
        let third = StoredPeerRepeaterEntry(
            hint: Data([7, 8]), name: "South", rssiDBm: -70, snrQuarterDB: 20,
            lastHeardMinutes: 0, latitude: nil, longitude: nil, locationPrecision: nil,
            regionCodes: [], reportedAt: at(52)
        )
        try await store.savePeerRepeaterPage(
            ownerIdentityID: owner, publicAddress: "relay", entries: [third], total: nil,
            nextCursor: nil, replacing: false, at: at(53)
        )
        listing = try await store.peerRepeaterListing(ownerIdentityID: owner, publicAddress: "relay")
        precondition(listing?.entries.count == 3 && listing?.nextCursor == nil && listing?.asOf == at(53))
        let reports = try await store.allPeerRepeaterEntries(ownerIdentityID: owner)
        precondition(reports.count == 3 && reports.allSatisfy { $0.reporterNodeID == relay.id })
        precondition(reports.contains { $0.entry == third })
        let noListing = try await store.peerRepeaterListing(ownerIdentityID: owner, publicAddress: "friend")
        precondition(noListing == nil)

        // Everything at once.
        let records = try await store.applicationRecords(ownerIdentityID: owner)
        precondition(Set(records.peers.map(\.publicAddress)) == ["relay", "friend"])
        precondition(Set(records.channels.map(\.id)) == [named.id, secret.id])
        precondition(records.conversations.map(\.id) == [direct])
        precondition(Set(records.channelConversations.map(\.id)) == [general, hidden])
        precondition(records.reports.count == 3)
        let conversationsOnly = try await store.applicationRecords(
            ownerIdentityID: owner, conversationsOnly: true
        )
        precondition(conversationsOnly.conversations.map(\.id) == [direct])
        precondition(Set(conversationsOnly.channels.map(\.id)) == [named.id, secret.id])
        precondition(conversationsOnly.peers.isEmpty && conversationsOnly.reports.isEmpty)

        // Staged transcripts.
        try await store.seedStagedTranscript(
            ownerIdentityID: owner, conversationAddress: "friend", sessionID: "staging-smoke",
            messages: [
                StagedMessage(
                    handle: 1, body: "Staged inbound", outbound: false, createdAt: at(60.0009),
                    senderAddress: "friend", reception: reception,
                    reactions: [StagedReaction(body: "ha", outbound: true, createdAt: at(61))]
                ),
                StagedMessage(
                    handle: 2, body: "Staged reply", outbound: true, createdAt: at(62),
                    deliveryState: "acknowledged", regarding: .message(1)
                ),
            ]
        )
        messages = try await transcript("friend")
        let stagedInbound = messages.first { $0.body == "Staged inbound" }
        let stagedReply = messages.first { $0.body == "Staged reply" }
        precondition(stagedInbound?.sessionID == "staging-smoke" && stagedInbound?.reception == reception)
        precondition(stagedInbound?.createdAtMilliseconds == 1_780_000_060_000)
        precondition(stagedInbound?.reactions.map(\.body) == ["ha"])
        precondition(stagedReply?.deliveryState == "acknowledged")
        precondition(stagedReply?.quote?.original?.body == "Staged inbound")
        let window = try await store.chatMessageWindow(
            ownerIdentityID: owner, conversationAddress: "friend", around: "staging-smoke",
            handle: 1, radius: 1
        )
        precondition(window?.messages.contains { $0.body == "Staged inbound" } == true)
        let before = try await store.chatMessageCount(ownerIdentityID: owner, conversationAddress: "general-address")
        try await store.seedGeneratedMessages(
            ownerIdentityID: owner, conversationAddress: "general-address", count: 25
        )
        let after = try await store.chatMessageCount(ownerIdentityID: owner, conversationAddress: "general-address")
        precondition(after == before + 25)

        // Clearing keeps the conversation and its checkpoint; deleting takes
        // the conversation.
        try await store.clearConversationMessages(ownerIdentityID: owner, conversationAddress: "friend")
        messages = try await transcript("friend")
        checkpoints = try await store.chatCheckpoints(ownerIdentityID: owner)
        directs = try await store.listDirectConversations(ownerIdentityID: owner)
        precondition(messages.isEmpty && checkpoints.count == 1 && directs.map(\.id) == [direct])
        let clearedArchive = try await store.chatArchive(ownerIdentityID: owner, lookup: .init(
            requestId: 0, conversationAddress: "friend", messageId: 4, fragmentIndex: 1
        ))
        precondition(clearedArchive == nil)
        try await store.deleteDirectConversation(ownerIdentityID: owner, conversationID: direct)
        directs = try await store.listDirectConversations(ownerIdentityID: owner)
        friend = try await peer("friend")
        precondition(directs.isEmpty && friend.isSaved, "deleting a conversation keeps the peer")
        try await store.deleteChannelConversation(ownerIdentityID: owner, conversationID: hidden)
        channelConversations = try await store.listChannelConversations(ownerIdentityID: owner)
        precondition(channelConversations.map(\.id) == [general])
        try await store.deleteChannel(id: secret.id)
        let remaining = try await store.channels(ownerIdentityID: owner)
        precondition(remaining.map(\.id) == [named.id])
    }

    /// A second connection to the same file reads what the first wrote, and
    /// erasing through it empties the store without taking the schema.
    private static func checkReopenAndErase(
        _ store: SQLiteApplicationStore,
        path: String
    ) async throws {
        let reopened = try SQLiteApplicationStore(path: path)
        for owner in ["alice", "dana"] {
            let written = try await store.applicationRecords(ownerIdentityID: owner)
            let read = try await reopened.applicationRecords(ownerIdentityID: owner)
            precondition(!written.peers.isEmpty)
            precondition(read.peers == written.peers && read.channels == written.channels)
            precondition(read.conversations == written.conversations)
            precondition(read.channelConversations == written.channelConversations)
            precondition(read.reports == written.reports)
        }
        let page = try await store.chatMessagePage(
            ownerIdentityID: "alice", conversationAddress: "reply-peer", newest: 100
        )
        let reread = try await reopened.chatMessagePage(
            ownerIdentityID: "alice", conversationAddress: "reply-peer", newest: 100
        )
        precondition(!page.messages.isEmpty && reread == page)

        let version = try await reopened.schemaVersion()
        try await reopened.eraseAllContent()
        let erasedVersion = try await store.schemaVersion()
        let erased = try await store.applicationRecords(ownerIdentityID: "alice")
        let erasedIdentity = try await store.knowsIdentity(id: "alice", publicAddress: "alice-public")
        precondition(erasedVersion == version)
        precondition(erased.peers.isEmpty && erased.conversations.isEmpty && !erasedIdentity)
    }

    private static func node(_ nodes: [StoredNode], _ address: String) -> StoredNode {
        guard let found = nodes.first(where: { $0.publicAddress == address }) else {
            preconditionFailure("Missing expected node \(address)")
        }
        return found
    }

    private static func createHistoricalStore(path: String) throws {
        let fixture = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("fixtures/application-v12.sql")
        let sql = try String(contentsOf: fixture, encoding: .utf8)
        var connection: OpaquePointer?
        precondition(sqlite3_open(path, &connection) == SQLITE_OK)
        defer { sqlite3_close(connection) }
        precondition(
            sqlite3_exec(connection, sql, nil, nil, nil) == SQLITE_OK,
            "Historical fixture failed: \(String(cString: sqlite3_errmsg(connection)))"
        )
    }

}

// MARK: - Chat scale benchmark

/// Times the reads a conversation list and an open transcript depend on, on a
/// database large enough for their complexity to show.
///
/// The numbers that matter are not the absolute times—those track whatever
/// machine ran them—but two shapes: whether a whole-database read grows with
/// stored history, and whether paging into deep history costs more than paging
/// at the head. The second is the one that decides whether the transcript index
/// is really driving the range scan, so every query also prints its plan.
extension PersistenceSmokeTest {
    private static let benchmarkOwner = "bench-owner"
    private static let benchmarkDirectConversations = 50
    /// One conversation deep enough that reading all of it is visibly a choice.
    private static let benchmarkDeepMessages = 5_000
    private static let benchmarkShallowMessages = 20
    private static let benchmarkChannelMessages = 20_000
    private static let benchmarkChannelAddress = "bench-channel-address"

    static func runChatScaleBenchmark() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("umsh-chat-bench-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let databaseURL = root.appendingPathComponent("application.sqlite")

        let store = try SQLiteApplicationStore(path: databaseURL.path)
        try await store.insertIdentity(
            id: benchmarkOwner,
            publicAddress: "\(benchmarkOwner)-public"
        )

        var directAddresses: [String] = []
        for index in 0..<benchmarkDirectConversations {
            let address = String(format: "bench-peer-%03d", index)
            try await store.upsertPeer(
                ownerIdentityID: benchmarkOwner,
                publicAddress: address,
                alias: "Bench Peer \(index)",
                isSaved: true
            )
            _ = try await store.ensureDirectConversation(
                ownerIdentityID: benchmarkOwner,
                peerAddress: address
            )
            directAddresses.append(address)
        }

        let channelID = UUID()
        try await store.insertChannel(
            StoredChannel(
                id: channelID,
                ownerIdentityID: benchmarkOwner,
                kind: .named,
                canonicalName: "bench",
                name: "Bench",
                alias: nil,
                channelIDHex: "beef",
                tint: Data([0xBE, 0xEF, 0x01]),
                regionCode: nil,
                maxFloodHops: nil,
                joinedPhone: true,
                joinedDevice: false,
                notificationsEnabled: true,
                joinedAt: nil
            ),
            keyDigest: "bench-key-digest"
        )
        _ = try await store.ensureChannelConversation(
            ownerIdentityID: benchmarkOwner,
            channelID: channelID,
            conversationAddress: benchmarkChannelAddress
        )

        // Seeding goes through raw SQL rather than `applyChatMutations`, for two
        // reasons that both invalidate the measurement otherwise: that path
        // stamps `created_at_ms` from the clock, so every seeded row would land
        // in the same handful of milliseconds and the keyset sweep would degrade
        // to one timestamp bucket; and with `synchronous = FULL` a transaction
        // per row takes minutes.
        var connection: OpaquePointer?
        precondition(sqlite3_open(databaseURL.path, &connection) == SQLITE_OK, "bench open failed")
        defer { sqlite3_close(connection) }
        sqlite3_busy_timeout(connection, 5_000)

        let seedStart = ContinuousClock.now
        let epoch: Int64 = 1_700_000_000_000
        for (index, address) in directAddresses.enumerated() {
            seedMessages(
                connection,
                address: address,
                sessionID: "\(1_000 + index)",
                count: index == 0 ? benchmarkDeepMessages : benchmarkShallowMessages,
                startingAt: epoch,
                withSenderHints: false
            )
        }
        seedMessages(
            connection,
            address: benchmarkChannelAddress,
            sessionID: "2000",
            count: benchmarkChannelMessages,
            startingAt: epoch,
            withSenderHints: true
        )
        let totalSeeded =
            benchmarkDeepMessages
            + (benchmarkDirectConversations - 1) * benchmarkShallowMessages
            + benchmarkChannelMessages
        print("")
        print("=== chat scale benchmark ===")
        print(
            "seeded \(totalSeeded) messages across "
                + "\(benchmarkDirectConversations) direct + 1 channel conversation "
                + "in \(formatted(ContinuousClock.now - seedStart))"
        )

        let deepAddress = directAddresses[0]

        // Page the whole deep transcript backward. This doubles as the
        // correctness fixture—every later assertion compares against it—and
        // as proof that a full walk in bounded pages reassembles exactly what
        // one unbounded read used to return.
        var start = ContinuousClock.now
        var deepMessages: [StoredChatMessage] = []
        var page = try await store.chatMessagePage(
            ownerIdentityID: benchmarkOwner,
            conversationAddress: deepAddress,
            newest: 150
        )
        var pages = 1
        deepMessages = page.messages
        precondition(!page.hasNewer, "the newest page is at the live edge")
        while page.hasOlder, let oldest = page.messages.first?.cursor {
            page = try await store.chatMessagePage(
                ownerIdentityID: benchmarkOwner,
                conversationAddress: deepAddress,
                before: oldest,
                limit: 150
            )
            precondition(page.hasNewer, "a page read before a cursor always has newer messages")
            deepMessages.insert(contentsOf: page.messages, at: 0)
            pages += 1
        }
        print(
            "full backward walk, \(benchmarkDeepMessages)-message direct: "
                + "\(formatted(ContinuousClock.now - start)) "
                + "(\(deepMessages.count) rows over \(pages) pages)"
        )
        precondition(deepMessages.count == benchmarkDeepMessages, "the walk lost or repeated rows")
        precondition(
            deepMessages.map(\.handle) == (0..<UInt32(benchmarkDeepMessages)).map { $0 },
            "the walk reassembled the transcript out of order"
        )
        precondition(
            zip(deepMessages, deepMessages.dropFirst()).allSatisfy { $0.cursor < $1.cursor },
            "cursors must be strictly increasing in transcript order"
        )

        // Opening a transcript: one bounded page, whatever the history depth.
        start = ContinuousClock.now
        var newestPage = StoredChatMessagePage.empty
        for _ in 0..<20 {
            newestPage = try await store.chatMessagePage(
                ownerIdentityID: benchmarkOwner,
                conversationAddress: benchmarkChannelAddress,
                newest: 150
            )
        }
        print(
            "newest(150) on \(benchmarkChannelMessages)-message channel: "
                + "\(formatted((ContinuousClock.now - start) / 20)) per call "
                + "(\(newestPage.messages.count) rows)"
        )
        precondition(newestPage.messages.count == 150 && newestPage.hasOlder && !newestPage.hasNewer)

        // The newest page really is the tail of the transcript.
        let deepNewest = try await store.chatMessagePage(
            ownerIdentityID: benchmarkOwner,
            conversationAddress: deepAddress,
            newest: 150
        )
        precondition(
            deepNewest.messages.map(\.id) == deepMessages.suffix(150).map(\.id),
            "newest(150) must be the last 150 of the transcript"
        )

        // A window centred on a message, for a search result opening in place.
        let anchor = deepMessages[2_500]
        guard let centred = try await store.chatMessageWindow(
            ownerIdentityID: benchmarkOwner,
            conversationAddress: deepAddress,
            around: anchor.sessionID,
            handle: anchor.handle,
            radius: 75
        ) else { preconditionFailure("the anchor message must be findable") }
        precondition(centred.messages.contains { $0.id == anchor.id }, "the window must hold its anchor")
        precondition(centred.hasOlder && centred.hasNewer, "a mid-history window is bounded both ways")
        precondition(
            centred.messages.map(\.id) == deepMessages[(2_500 - 75)...(2_500 + 75)].map(\.id),
            "the centred window must be the contiguous slice around the anchor"
        )
        // A message that is not in this conversation is a stale hit, not a fault.
        let foreignWindow = try await store.chatMessageWindow(
            ownerIdentityID: benchmarkOwner,
            conversationAddress: directAddresses[1],
            around: anchor.sessionID,
            handle: anchor.handle,
            radius: 75
        )
        precondition(foreignWindow == nil, "a message from another conversation must not resolve")

        // Re-reading the extent a window already holds, which is how an open
        // transcript picks up edits without moving the reading position.
        let extent = try await store.chatMessagePage(
            ownerIdentityID: benchmarkOwner,
            conversationAddress: deepAddress,
            after: deepMessages[1_000].cursor,
            including: true,
            limit: 150
        )
        precondition(
            extent.messages.map(\.id) == deepMessages[1_000..<1_150].map(\.id),
            "an inclusive forward read must start at its own cursor"
        )
        precondition(extent.hasNewer && extent.hasOlder)

        // What one `performApplicationStateReload` now costs in storage time:
        // two statements total, whatever the history depth. This is the number
        // every one of the reload's ~37 triggers used to multiply by the whole
        // database.
        start = ContinuousClock.now
        var directConversations: [StoredDirectConversation] = []
        var channelConversations: [StoredChannelConversation] = []
        for _ in 0..<20 {
            directConversations = try await store.listDirectConversations(
                ownerIdentityID: benchmarkOwner
            )
            channelConversations = try await store.listChannelConversations(
                ownerIdentityID: benchmarkOwner
            )
        }
        print(
            "FULL RELOAD READ (list + tails, \(directConversations.count) direct "
                + "+ \(channelConversations.count) channel): "
                + "\(formatted((ContinuousClock.now - start) / 20)) per call"
        )

        // The tail has to agree with the transcript it summarises, or a list row
        // quietly describes a different conversation than the one it opens.
        guard let deepConversation = directConversations.first(
            where: { $0.node.publicAddress == deepAddress }
        ) else { preconditionFailure("the deep conversation must be listed") }
        guard let deepPreview = deepConversation.lastMessage else {
            preconditionFailure("a conversation with messages must have a preview")
        }
        let deepLast = deepMessages[deepMessages.count - 1]
        precondition(
            deepPreview.createdAtMilliseconds == deepLast.createdAtMilliseconds
                && deepPreview.body == deepLast.body
                && deepPreview.isOutbound == deepLast.outbound
                && deepPreview.isDeleted == deepLast.isDeleted,
            "the preview must be the literal last row, tombstones included"
        )
        // Never opened, so everything inbound and readable is unread.
        let expectedUnread = deepMessages.filter {
            !$0.outbound && !$0.isDeleted && !$0.isGapPlaceholder && !$0.isUnavailable
        }.count
        precondition(
            deepConversation.unreadCount == expectedUnread,
            "unread \(deepConversation.unreadCount) != expected \(expectedUnread)"
        )
        // A conversation with no messages reports no preview and nothing unread,
        // rather than a zero-valued one.
        let emptyAddress = "bench-empty-peer"
        try await store.upsertPeer(
            ownerIdentityID: benchmarkOwner,
            publicAddress: emptyAddress,
            alias: "Empty",
            isSaved: true
        )
        _ = try await store.ensureDirectConversation(
            ownerIdentityID: benchmarkOwner,
            peerAddress: emptyAddress
        )
        guard let empty = (try await store.listDirectConversations(ownerIdentityID: benchmarkOwner))
            .first(where: { $0.node.publicAddress == emptyAddress })
        else { preconditionFailure("the empty conversation must be listed") }
        precondition(empty.lastMessage == nil && empty.unreadCount == 0)

        // Marking read must clear the badge without touching the preview.
        try await store.markConversationRead(
            ownerIdentityID: benchmarkOwner,
            conversationAddress: deepAddress
        )
        guard let afterRead = (try await store.listDirectConversations(ownerIdentityID: benchmarkOwner))
            .first(where: { $0.node.publicAddress == deepAddress })
        else { preconditionFailure("the deep conversation must survive being read") }
        precondition(
            afterRead.unreadCount == 0 && afterRead.lastMessage == deepConversation.lastMessage,
            "marking read clears unread and leaves the preview alone"
        )

        // The channel tail resolves its sender the same way a direct one does.
        guard let channelConversation = channelConversations.first,
              let channelPreview = channelConversation.lastMessage
        else { preconditionFailure("the channel conversation must have a preview") }
        precondition(channelConversation.unreadCount > 0, "an unopened channel has unread messages")
        precondition(
            channelPreview.isOutbound || channelPreview.senderHint != nil,
            "an inbound group preview carries the hint its bubble would show"
        )

        // The reload again, with every conversation read. Unread counting starts
        // at the read cursor, so this is the steady-state cost; the figure above
        // is its worst case, a 20 000-message channel never once opened.
        try await store.markConversationRead(
            ownerIdentityID: benchmarkOwner,
            conversationAddress: benchmarkChannelAddress
        )
        start = ContinuousClock.now
        for _ in 0..<20 {
            _ = try await store.listDirectConversations(ownerIdentityID: benchmarkOwner)
            _ = try await store.listChannelConversations(ownerIdentityID: benchmarkOwner)
        }
        print(
            "FULL RELOAD READ (list + tails, everything read): "
                + "\(formatted((ContinuousClock.now - start) / 20)) per call"
        )

        explainQueryPlan(
            connection,
            label: "listDirectConversations with tails",
            sql: """
                SELECT c.id, c.draft_text, lm.body,
                       (SELECT COUNT(*) FROM chat_message u
                         WHERE u.owner_identity_id = c.owner_identity_id
                           AND u.conversation_address = n.public_address
                           AND u.direction = 0 AND u.deleted = 0 AND u.presence = 0
                           AND u.created_at_ms > c.last_read_at_ms)
                FROM direct_conversation c JOIN node n ON n.id = c.node_id
                LEFT JOIN chat_message lm ON lm.rowid = (
                    SELECT m.rowid FROM chat_message m
                    WHERE m.owner_identity_id = c.owner_identity_id
                      AND m.conversation_address = n.public_address
                    ORDER BY m.created_at_ms DESC, m.rowid DESC
                    LIMIT 1
                )
                WHERE c.owner_identity_id = ? ORDER BY c.created_at_ms DESC, c.id DESC
                """
        )
        explainQueryPlan(
            connection,
            label: "newest page (candidate)",
            sql: """
                SELECT session_id, handle, body, created_at_ms, rowid
                FROM chat_message
                WHERE owner_identity_id = ? AND conversation_address = ?
                ORDER BY created_at_ms DESC, rowid DESC
                LIMIT ?
                """
        )
        explainQueryPlan(
            connection,
            label: "before-cursor page, row value (candidate)",
            sql: """
                SELECT session_id, handle, body, created_at_ms, rowid
                FROM chat_message
                WHERE owner_identity_id = ? AND conversation_address = ?
                  AND (created_at_ms, rowid) < (?, ?)
                ORDER BY created_at_ms DESC, rowid DESC
                LIMIT ?
                """
        )
        explainQueryPlan(
            connection,
            label: "unread count (candidate)",
            sql: """
                SELECT COUNT(*) FROM chat_message
                WHERE owner_identity_id = ? AND conversation_address = ?
                  AND direction = 0 AND deleted = 0 AND presence = 0
                  AND created_at_ms > ?
                """
        )

        // Does paging deep into history cost more than paging at the head? If
        // it does, the index is not driving the range and the cursor form needs
        // rethinking. Measured through the real API, so the row mapping is in
        // the number too.
        for depth in [0, 1_000, 4_900] {
            let cursor = deepMessages[max(0, benchmarkDeepMessages - 1 - depth)].cursor
            start = ContinuousClock.now
            var older = StoredChatMessagePage.empty
            for _ in 0..<20 {
                older = try await store.chatMessagePage(
                    ownerIdentityID: benchmarkOwner,
                    conversationAddress: deepAddress,
                    before: cursor,
                    limit: 150
                )
            }
            print(
                "before-cursor page at depth \(depth): "
                    + "\(formatted((ContinuousClock.now - start) / 20)) per call "
                    + "(\(older.messages.count) rows)"
            )
        }

        // Unread counting, best and worst case, to size the partial index the
        // plan holds in reserve.
        for (label, since) in [("all unread", Int64(0)), ("fully read", Int64.max / 2)] {
            start = ContinuousClock.now
            var unread = 0
            for _ in 0..<20 {
                unread = unreadCount(connection, address: benchmarkChannelAddress, since: since)
            }
            print(
                "unread count on \(benchmarkChannelMessages)-message channel, \(label): "
                    + "\(formatted((ContinuousClock.now - start) / 20)) per call (\(unread))"
            )
        }
        print("=== end chat scale benchmark ===")
        print("")
    }

    /// Insert `count` messages ordered in time, with deliberate same-millisecond
    /// clusters: the store stamps a whole mutation batch from one clock read, so
    /// ties are the normal case and the cursor's rowid tiebreak has to survive
    /// them. Everything here is derived from the row index, so two runs seed
    /// byte-identical fixtures.
    private static func seedMessages(
        _ connection: OpaquePointer?,
        address: String,
        sessionID: String,
        count: Int,
        startingAt epoch: Int64,
        withSenderHints: Bool
    ) {
        precondition(
            sqlite3_exec(connection, "BEGIN IMMEDIATE", nil, nil, nil) == SQLITE_OK,
            "bench begin failed"
        )
        var statement: OpaquePointer?
        let sql = """
            INSERT INTO chat_message (
                owner_identity_id, session_id, handle, conversation_address,
                sender_address, sender_hint, direction, body, deleted,
                created_at_ms, presence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
        precondition(
            sqlite3_prepare_v2(connection, sql, -1, &statement, nil) == SQLITE_OK,
            "bench prepare failed: \(String(cString: sqlite3_errmsg(connection)))"
        )
        defer { sqlite3_finalize(statement) }

        let transient = unsafeBitCast(-1 as Int, to: sqlite3_destructor_type.self)  // SQLITE_TRANSIENT
        var createdAt = epoch
        var clusterRemaining = 0
        for index in 0..<count {
            if clusterRemaining == 0 {
                clusterRemaining = 3 + (index % 6)
                createdAt += 60_000 + Int64((index % 997) * 311)
            }
            clusterRemaining -= 1

            let outbound = index % 3 == 0
            let deleted = index % 97 == 0
            // A gap placeholder and an unavailable marker, at prime-ish strides
            // so they land inside and across page boundaries.
            let presence: Int32 = index % 89 == 0 ? 1 : (index % 211 == 0 ? 2 : 0)
            let body = String(
                repeating: "message \(index) body ",
                count: 1 + (index % 8)
            )

            sqlite3_reset(statement)
            sqlite3_bind_text(statement, 1, benchmarkOwner, -1, transient)
            sqlite3_bind_text(statement, 2, sessionID, -1, transient)
            sqlite3_bind_int64(statement, 3, Int64(index))
            sqlite3_bind_text(statement, 4, address, -1, transient)
            if withSenderHints && !outbound {
                sqlite3_bind_text(statement, 5, "bench-sender-\(index % 7)", -1, transient)
                var hint = [UInt8(index % 7), 0xAB, 0xCD]
                sqlite3_bind_blob(statement, 6, &hint, 3, transient)
            } else {
                sqlite3_bind_null(statement, 5)
                sqlite3_bind_null(statement, 6)
            }
            sqlite3_bind_int(statement, 7, outbound ? 1 : 0)
            sqlite3_bind_text(statement, 8, body, -1, transient)
            sqlite3_bind_int(statement, 9, deleted ? 1 : 0)
            sqlite3_bind_int64(statement, 10, createdAt)
            sqlite3_bind_int(statement, 11, presence)
            precondition(
                sqlite3_step(statement) == SQLITE_DONE,
                "bench insert failed: \(String(cString: sqlite3_errmsg(connection)))"
            )
        }
        precondition(
            sqlite3_exec(connection, "COMMIT", nil, nil, nil) == SQLITE_OK,
            "bench commit failed"
        )
    }

    private static func explainQueryPlan(
        _ connection: OpaquePointer?,
        label: String,
        sql: String
    ) {
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(connection, "EXPLAIN QUERY PLAN \(sql)", -1, &statement, nil)
            == SQLITE_OK
        else {
            print("plan [\(label)]: prepare failed: \(String(cString: sqlite3_errmsg(connection)))")
            return
        }
        defer { sqlite3_finalize(statement) }
        print("plan [\(label)]:")
        while sqlite3_step(statement) == SQLITE_ROW {
            guard let detail = sqlite3_column_text(statement, 3) else { continue }
            print("  \(String(cString: detail))")
        }
    }

    private static func unreadCount(
        _ connection: OpaquePointer?,
        address: String,
        since: Int64
    ) -> Int {
        var statement: OpaquePointer?
        let sql = """
            SELECT COUNT(*) FROM chat_message
            WHERE owner_identity_id = ? AND conversation_address = ?
              AND direction = 0 AND deleted = 0 AND presence = 0
              AND created_at_ms > ?
            """
        precondition(sqlite3_prepare_v2(connection, sql, -1, &statement, nil) == SQLITE_OK)
        defer { sqlite3_finalize(statement) }
        let transient = unsafeBitCast(-1 as Int, to: sqlite3_destructor_type.self)
        sqlite3_bind_text(statement, 1, benchmarkOwner, -1, transient)
        sqlite3_bind_text(statement, 2, address, -1, transient)
        sqlite3_bind_int64(statement, 3, since)
        precondition(sqlite3_step(statement) == SQLITE_ROW)
        return Int(sqlite3_column_int64(statement, 0))
    }

    private static func formatted(_ duration: Duration) -> String {
        let parts = duration.components
        let milliseconds =
            Double(parts.seconds) * 1_000
            + Double(parts.attoseconds) / 1_000_000_000_000_000
        return String(format: "%.2f ms", milliseconds)
    }
}

/// The core stores chat itself as it comes, so the app has no calls for
/// these. The smoke still writes and reads its chat fixtures through them,
/// straight on the core's store.
extension SQLiteApplicationStore {
    private static var nowMilliseconds: Int64 {
        Int64(Date.now.timeIntervalSince1970 * 1_000)
    }

    @discardableResult
    func applyChatMutations(
        ownerIdentityID: String,
        mutations: [MobileChatMutationRecord],
        silentTestsIn: String? = nil
    ) throws -> [MobileChatMutationRecord] {
        try coreStore.applyChatMutations(
            ownerIdentityId: ownerIdentityID,
            mutations: mutations,
            nowMs: Self.nowMilliseconds,
            silentTestsIn: silentTestsIn
        )
    }

    @discardableResult
    func applyChatDeliveries(
        ownerIdentityID: String,
        deliveries: [MobileChatDeliveryRecord]
    ) throws -> [ChatDeliveryFailure] {
        try coreStore.applyChatDeliveries(
            ownerIdentityId: ownerIdentityID,
            deliveries: deliveries,
            nowMs: Self.nowMilliseconds
        )
        .map(ChatDeliveryFailure.init)
    }

    func applyChatRepeats(ownerIdentityID: String, repeats: [MobileChatRepeatRecord]) throws {
        try coreStore.applyChatRepeats(
            ownerIdentityId: ownerIdentityID,
            repeats: repeats,
            nowMs: Self.nowMilliseconds
        )
    }

    func applyChatResends(ownerIdentityID: String, resends: [MobileChatResendRecord]) throws {
        try coreStore.applyChatResends(
            ownerIdentityId: ownerIdentityID,
            resends: resends,
            nowMs: Self.nowMilliseconds
        )
    }

    func applySenderResolution(
        ownerIdentityID: String,
        conversationAddress: String,
        senderHint: Data,
        senderAddress: String
    ) throws {
        try coreStore.applySenderResolution(
            ownerIdentityId: ownerIdentityID,
            resolution: MobileChatSenderResolutionRecord(
                conversationAddress: conversationAddress,
                senderHint: senderHint,
                senderAddress: senderAddress
            )
        )
    }

    func commitChatComposeBatch(ownerIdentityID: String, batch: MobileChatComposeBatchRecord) throws {
        try coreStore.commitChatComposeBatch(
            ownerIdentityId: ownerIdentityID,
            batch: batch,
            nowMs: Self.nowMilliseconds
        )
    }

    func markChatComposeBatchFailed(ownerIdentityID: String, batch: MobileChatComposeBatchRecord) throws {
        try coreStore.markChatComposeBatchFailed(ownerIdentityId: ownerIdentityID, batch: batch)
    }

    func conversationAddressForMessage(
        ownerIdentityID: String,
        sessionID: UInt64,
        handle: UInt32
    ) throws -> String? {
        try coreStore.conversationAddressForMessage(
            ownerIdentityId: ownerIdentityID,
            sessionId: sessionID,
            handle: handle
        )
    }

    func chatNotificationTarget(
        ownerIdentityID: String,
        sessionID: UInt64,
        handle: UInt32
    ) throws -> MobileStoredChatNotificationTargetRecord? {
        try coreStore.chatNotificationTarget(
            ownerIdentityId: ownerIdentityID,
            sessionId: sessionID,
            handle: handle
        )
    }

    func chatReactionNotificationTarget(
        ownerIdentityID: String,
        sessionID: UInt64,
        handle: UInt32
    ) throws -> MobileStoredChatReactionNotificationTargetRecord? {
        try coreStore.chatReactionNotificationTarget(
            ownerIdentityId: ownerIdentityID,
            sessionId: sessionID,
            handle: handle
        )
    }

    func chatArchive(ownerIdentityID: String, lookup: MobileChatArchiveLookupRecord) throws -> Data? {
        try coreStore.chatArchive(ownerIdentityId: ownerIdentityID, lookup: lookup)
    }
}
