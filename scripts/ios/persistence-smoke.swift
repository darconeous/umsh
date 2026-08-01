import Foundation
import SQLite3

@main
struct PersistenceSmokeTest {
    static func main() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("umsh-persistence-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let databaseURL = root.appendingPathComponent("application.sqlite")

        var store = try SQLiteApplicationStore(path: databaseURL.path)
        let initialSchemaVersion = try await store.schemaVersion()
        precondition(initialSchemaVersion == SQLiteApplicationStore.currentSchemaVersion)

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

        // Legacy "primary" identity migration still transfers records intact.
        try await store.insertIdentity(id: "primary", publicAddress: "legacy-public")
        try await store.upsertPeer(
            ownerIdentityID: "primary",
            publicAddress: "legacy-peer",
            alias: "Legacy Peer",
            isSaved: true
        )
        try await store.migrateLegacyPrimaryIdentity(
            to: "legacy-public",
            publicAddress: "legacy-public"
        )
        let migratedNodes = try await store.listNodes(ownerIdentityID: "legacy-public")
        precondition(migratedNodes.map(\.publicAddress) == ["legacy-peer"])

        // v12 → current upgrade on a populated database: restore the v12 shape
        // — v13's columns gone, v14's dropped `is_contact` back — and stamp
        // user_version 12, then reopen. Nothing may vanish, and every
        // pre-existing row must upgrade as saved.
        store = try SQLiteApplicationStore(path: databaseURL.path)
        try await store.demotePeerToTransient(ownerIdentityID: "alice", publicAddress: "flood-0")
        try downgradeToV12(path: databaseURL.path)
        let reopened = try SQLiteApplicationStore(path: databaseURL.path)
        let reopenedSchemaVersion = try await reopened.schemaVersion()
        precondition(reopenedSchemaVersion == SQLiteApplicationStore.currentSchemaVersion)
        let upgraded = try await reopened.listNodes(ownerIdentityID: "alice")
        precondition(upgraded.contains { $0.publicAddress == "flood-0" })
        precondition(upgraded.allSatisfy(\.isSaved))
        precondition(upgraded.allSatisfy { !$0.isFavorite && !$0.onDeviceIdentity })

        print("SQLite tier, delete/demote, retention, migration, and upgrade checks passed")

        // Seeding tens of thousands of rows takes long enough that the ordinary
        // smoke run should not pay for it.
        if ProcessInfo.processInfo.environment["UMSH_CHAT_BENCH"] == "1" {
            try await runChatScaleBenchmark()
        }
    }

    private static func node(_ nodes: [StoredNode], _ address: String) -> StoredNode {
        guard let found = nodes.first(where: { $0.publicAddress == address }) else {
            preconditionFailure("Missing expected node \(address)")
        }
        return found
    }

    /// Rewind a current-schema database to the v12 shape so the migration path
    /// from a populated store is exercised for real.
    ///
    /// Every migration above 12 has to be undone, not just the ones whose data
    /// the assertions look at: replaying a `CREATE TABLE` over a table the
    /// rewind left behind fails, so a partial rewind tests nothing and takes
    /// the whole harness down with it.
    private static func downgradeToV12(path: String) throws {
        var connection: OpaquePointer?
        precondition(sqlite3_open(path, &connection) == SQLITE_OK, "downgrade open failed")
        defer { sqlite3_close(connection) }
        let sql = """
            -- v16: conversation addressing, per-message reception, read cursors.
            DROP TABLE channel_conversation;
            ALTER TABLE direct_conversation DROP COLUMN last_read_at_ms;
            ALTER TABLE chat_message DROP COLUMN rx_source_authenticated;
            ALTER TABLE chat_message DROP COLUMN rx_route_hints;
            ALTER TABLE chat_message DROP COLUMN rx_hop_count;
            ALTER TABLE chat_message DROP COLUMN rx_lqi;
            ALTER TABLE chat_message DROP COLUMN rx_snr_cb;
            ALTER TABLE chat_message DROP COLUMN rx_rssi_dbm;
            ALTER TABLE chat_message DROP COLUMN sender_hint;
            ALTER TABLE chat_outbound_archive
                RENAME COLUMN conversation_address TO peer_address;
            ALTER TABLE chat_stream_checkpoint
                RENAME COLUMN conversation_address TO peer_address;
            ALTER TABLE chat_message RENAME COLUMN conversation_address TO peer_address;

            -- v15: channel membership.
            DROP TABLE channel;

            -- v14 and v13: the node tiering columns.
            DROP INDEX node_owner_transient_heard_idx;
            ALTER TABLE node DROP COLUMN is_saved;
            ALTER TABLE node DROP COLUMN is_favorite;
            ALTER TABLE node DROP COLUMN on_dev_identity;
            ALTER TABLE node ADD COLUMN is_contact INTEGER NOT NULL DEFAULT 0;

            PRAGMA user_version = 12;
            """
        precondition(
            sqlite3_exec(connection, sql, nil, nil, nil) == SQLITE_OK,
            "downgrade DDL failed: \(String(cString: sqlite3_errmsg(connection)))"
        )
    }
}

// MARK: - Chat scale benchmark

/// Times the reads a conversation list and an open transcript depend on, on a
/// database large enough for their complexity to show.
///
/// The numbers that matter are not the absolute times — those track whatever
/// machine ran them — but two shapes: whether a whole-database read grows with
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
        // correctness fixture — every later assertion compares against it — and
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
