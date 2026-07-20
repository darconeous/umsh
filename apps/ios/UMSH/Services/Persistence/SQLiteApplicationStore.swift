import Foundation
import SQLite3
import UMSHMobileCore

enum ApplicationStoreError: Error, Equatable, Sendable {
    case applicationSupportUnavailable
    case openFailed(Int32)
    case sqliteFailure(Int32)
    case unsupportedSchema(Int32)
}

struct StoredNode: Equatable, Sendable {
    let id: Int64
    let ownerIdentityID: String
    let publicAddress: String
    let alias: String?
    let advertisedName: String?
    let isContact: Bool
    let systemRole: String?
    let nodeKind: String?
}

struct NewStoredNode: Equatable, Sendable {
    let publicAddress: String
    let alias: String?
}

struct StoredDirectConversation: Equatable, Sendable {
    let id: Int64
    let node: StoredNode
    let draftText: String
}

struct StoredChatMessage: Equatable, Sendable, Identifiable {
    var id: String { "\(sessionID):\(handle)" }
    let sessionID: String
    let handle: UInt32
    let body: String
    let outbound: Bool
    let deliveryState: String?
    let isDeleted: Bool
    let createdAtMilliseconds: Int64
}

/// Phase 0 direct-SQLite prototype.
///
/// This store contains public application records only. Private identity and
/// channel key bytes are never accepted by this API and remain in Keychain.
actor SQLiteApplicationStore {
    static let currentSchemaVersion: Int32 = 4

    nonisolated(unsafe) private let database: OpaquePointer

    static func applicationStore(fileManager: FileManager = .default) throws -> SQLiteApplicationStore {
        guard let applicationSupport = fileManager.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            throw ApplicationStoreError.applicationSupportUnavailable
        }
        let directory = applicationSupport.appendingPathComponent("UMSH", isDirectory: true)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        return try SQLiteApplicationStore(
            path: directory.appendingPathComponent("Application.sqlite").path
        )
    }

    init(path: String) throws {
        var connection: OpaquePointer?
        let status = sqlite3_open_v2(
            path,
            &connection,
            SQLITE_OPEN_CREATE | SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX,
            nil
        )
        guard status == SQLITE_OK, let connection else {
            if let connection {
                sqlite3_close(connection)
            }
            throw ApplicationStoreError.openFailed(status)
        }
        database = connection

        do {
            try Self.execute(connection, sql: "PRAGMA foreign_keys = ON")
            try Self.execute(connection, sql: "PRAGMA journal_mode = WAL")
            try Self.execute(connection, sql: "PRAGMA synchronous = FULL")
            sqlite3_busy_timeout(connection, 5_000)
            try Self.migrate(connection)
        } catch {
            sqlite3_close(connection)
            throw error
        }
    }

    deinit {
        sqlite3_close(database)
    }

    func schemaVersion() throws -> Int32 {
        try Self.readSchemaVersion(database)
    }

    func insertIdentity(id: String, publicAddress: String, createdAt: Date = .now) throws {
        let statement = try prepare(
            "INSERT INTO local_identity (id, public_address, created_at_ms) VALUES (?, ?, ?)"
        )
        defer { sqlite3_finalize(statement) }
        try bind(id, to: statement, at: 1)
        try bind(publicAddress, to: statement, at: 2)
        try check(sqlite3_bind_int64(statement, 3, Int64(createdAt.timeIntervalSince1970 * 1_000)))
        try stepDone(statement)
    }

    func upsertIdentity(id: String, publicAddress: String, createdAt: Date = .now) throws {
        let statement = try prepare(
            """
            INSERT INTO local_identity (id, public_address, created_at_ms) VALUES (?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET public_address = excluded.public_address
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(id, to: statement, at: 1)
        try bind(publicAddress, to: statement, at: 2)
        try check(sqlite3_bind_int64(statement, 3, Int64(createdAt.timeIntervalSince1970 * 1_000)))
        try stepDone(statement)
    }

    /// Move records created by early builds from the Keychain slot name to the
    /// identity's stable public address. Migration is deliberately refused if
    /// the legacy row belongs to a different public key or the destination
    /// already exists; either case could otherwise transfer records between
    /// identities.
    func migrateLegacyPrimaryIdentity(
        to stableID: String,
        publicAddress: String
    ) throws {
        guard stableID != "primary" else { return }
        try transaction {
            // The parent key and its children must change together. SQLite's
            // immediate foreign keys would reject the transient mismatch, so
            // defer validation until this transaction commits.
            try Self.execute(database, sql: "PRAGMA defer_foreign_keys = ON")

            let legacy = try prepare(
                "SELECT public_address FROM local_identity WHERE id = 'primary'"
            )
            defer { sqlite3_finalize(legacy) }
            guard sqlite3_step(legacy) == SQLITE_ROW,
                  Self.stringColumn(legacy, at: 0) == publicAddress
            else { return }

            let destination = try prepare(
                "SELECT 1 FROM local_identity WHERE id = ? LIMIT 1"
            )
            defer { sqlite3_finalize(destination) }
            try bind(stableID, to: destination, at: 1)
            guard sqlite3_step(destination) == SQLITE_DONE else { return }

            let identity = try prepare(
                "UPDATE local_identity SET id = ? WHERE id = 'primary' AND public_address = ?"
            )
            defer { sqlite3_finalize(identity) }
            try bind(stableID, to: identity, at: 1)
            try bind(publicAddress, to: identity, at: 2)
            try stepDone(identity)

            let nodes = try prepare(
                "UPDATE node SET owner_identity_id = ? WHERE owner_identity_id = 'primary'"
            )
            defer { sqlite3_finalize(nodes) }
            try bind(stableID, to: nodes, at: 1)
            try stepDone(nodes)

            let conversations = try prepare(
                "UPDATE direct_conversation SET owner_identity_id = ? WHERE owner_identity_id = 'primary'"
            )
            defer { sqlite3_finalize(conversations) }
            try bind(stableID, to: conversations, at: 1)
            try stepDone(conversations)

            for table in [
                "chat_stream_checkpoint",
                "chat_outbound_archive",
                "chat_message",
                "chat_applied_mutation",
                "chat_delivery_fragment",
            ] {
                let statement = try prepare(
                    "UPDATE \(table) SET owner_identity_id = ? WHERE owner_identity_id = 'primary'"
                )
                defer { sqlite3_finalize(statement) }
                try bind(stableID, to: statement, at: 1)
                try stepDone(statement)
            }

        }
    }

    func upsertPeer(
        ownerIdentityID: String,
        publicAddress: String,
        alias: String?,
        advertisedName: String? = nil,
        isContact: Bool,
        nodeKind: String? = nil,
        systemRole: String? = nil,
        radioIdentifier: String? = nil
    ) throws {
        let statement = try prepare(
            """
            INSERT INTO node (
                owner_identity_id, public_address, alias, alias_search,
                advertised_name, is_contact, system_role, radio_identifier, node_kind
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_identity_id, public_address) DO UPDATE SET
                alias = COALESCE(excluded.alias, node.alias),
                alias_search = CASE WHEN excluded.alias IS NULL
                    THEN node.alias_search ELSE excluded.alias_search END,
                advertised_name = COALESCE(excluded.advertised_name, node.advertised_name),
                is_contact = MAX(node.is_contact, excluded.is_contact),
                system_role = COALESCE(excluded.system_role, node.system_role),
                radio_identifier = COALESCE(excluded.radio_identifier, node.radio_identifier),
                node_kind = COALESCE(excluded.node_kind, node.node_kind)
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(publicAddress, to: statement, at: 2)
        try bindOptional(alias, to: statement, at: 3)
        try bind(Self.normalizeSearch(alias ?? advertisedName ?? ""), to: statement, at: 4)
        try bindOptional(advertisedName, to: statement, at: 5)
        try check(sqlite3_bind_int(statement, 6, isContact ? 1 : 0))
        try bindOptional(systemRole, to: statement, at: 7)
        try bindOptional(radioIdentifier, to: statement, at: 8)
        try bindOptional(nodeKind, to: statement, at: 9)
        try stepDone(statement)
    }

    func upsertCompanionRadioPeer(
        ownerIdentityID: String,
        publicAddress: String,
        advertisedName: String?,
        radioIdentifier: String
    ) throws {
        try transaction {
            let clear = try prepare(
                """
                UPDATE node SET system_role = NULL, radio_identifier = NULL
                WHERE owner_identity_id = ? AND system_role = 'companion_radio'
                    AND public_address <> ?
                """
            )
            defer { sqlite3_finalize(clear) }
            try bind(ownerIdentityID, to: clear, at: 1)
            try bind(publicAddress, to: clear, at: 2)
            try stepDone(clear)
            try upsertPeer(
                ownerIdentityID: ownerIdentityID,
                publicAddress: publicAddress,
                alias: nil,
                advertisedName: advertisedName,
                isContact: false,
                systemRole: "companion_radio",
                radioIdentifier: radioIdentifier
            )
        }
    }

    func listNodes(ownerIdentityID: String) throws -> [StoredNode] {
        let statement = try prepare(
            """
            SELECT id, owner_identity_id, public_address, alias, advertised_name,
                   is_contact, system_role, node_kind
            FROM node WHERE owner_identity_id = ?
            ORDER BY (system_role IS NOT NULL) DESC, is_contact DESC,
                     alias_search, id
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        return try readNodes(statement)
    }

    func ensureDirectConversation(
        ownerIdentityID: String,
        peerAddress: String
    ) throws -> Int64 {
        let insert = try prepare(
            """
            INSERT OR IGNORE INTO direct_conversation (owner_identity_id, node_id, created_at_ms)
            SELECT ?, id, ? FROM node
            WHERE owner_identity_id = ? AND public_address = ?
            """
        )
        defer { sqlite3_finalize(insert) }
        try bind(ownerIdentityID, to: insert, at: 1)
        try check(sqlite3_bind_int64(insert, 2, Int64(Date.now.timeIntervalSince1970 * 1_000)))
        try bind(ownerIdentityID, to: insert, at: 3)
        try bind(peerAddress, to: insert, at: 4)
        try stepDone(insert)

        let select = try prepare(
            """
            SELECT c.id FROM direct_conversation c JOIN node n ON n.id = c.node_id
            WHERE c.owner_identity_id = ? AND n.public_address = ?
            """
        )
        defer { sqlite3_finalize(select) }
        try bind(ownerIdentityID, to: select, at: 1)
        try bind(peerAddress, to: select, at: 2)
        guard sqlite3_step(select) == SQLITE_ROW else {
            throw ApplicationStoreError.sqliteFailure(sqlite3_errcode(database))
        }
        return sqlite3_column_int64(select, 0)
    }

    func listDirectConversations(ownerIdentityID: String) throws -> [StoredDirectConversation] {
        let statement = try prepare(
            """
            SELECT c.id, n.id, n.owner_identity_id, n.public_address, n.alias,
                   n.advertised_name, n.is_contact, n.system_role, n.node_kind,
                   c.draft_text
            FROM direct_conversation c JOIN node n ON n.id = c.node_id
            WHERE c.owner_identity_id = ? ORDER BY c.created_at_ms DESC, c.id DESC
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        var conversations: [StoredDirectConversation] = []
        while true {
            switch sqlite3_step(statement) {
            case SQLITE_ROW:
                conversations.append(
                    StoredDirectConversation(
                        id: sqlite3_column_int64(statement, 0),
                        node: storedNode(statement, offset: 1),
                        draftText: Self.stringColumn(statement, at: 9)
                    )
                )
            case SQLITE_DONE:
                return conversations
            case let code:
                throw ApplicationStoreError.sqliteFailure(code)
            }
        }
    }

    func updateDraft(ownerIdentityID: String, conversationID: Int64, text: String) throws {
        let statement = try prepare(
            "UPDATE direct_conversation SET draft_text = ? WHERE id = ? AND owner_identity_id = ?"
        )
        defer { sqlite3_finalize(statement) }
        try bind(text, to: statement, at: 1)
        try check(sqlite3_bind_int64(statement, 2, conversationID))
        try bind(ownerIdentityID, to: statement, at: 3)
        try stepDone(statement)
    }

    func chatCheckpoints(ownerIdentityID: String) throws -> [MobileChatCheckpointRecord] {
        let statement = try prepare(
            """
            SELECT peer_address, next_id, epoch FROM chat_stream_checkpoint
            WHERE owner_identity_id = ? ORDER BY updated_at_ms ASC, peer_address ASC
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        var records: [MobileChatCheckpointRecord] = []
        while true {
            switch sqlite3_step(statement) {
            case SQLITE_ROW:
                records.append(
                    MobileChatCheckpointRecord(
                        peerAddress: Self.stringColumn(statement, at: 0),
                        nextId: UInt8(sqlite3_column_int(statement, 1)),
                        epoch: UInt16(sqlite3_column_int(statement, 2))
                    )
                )
            case SQLITE_DONE: return records
            case let code: throw ApplicationStoreError.sqliteFailure(code)
            }
        }
    }

    /// The checkpoint and exact resend material are one durable commit. The
    /// caller may release the corresponding Rust batch only after this returns.
    func commitChatComposeBatch(
        ownerIdentityID: String,
        batch: MobileChatComposeBatchRecord
    ) throws {
        try transaction {
            try upsertChatCheckpoint(ownerIdentityID: ownerIdentityID, batch.checkpoint)
            for archive in batch.archives {
                try upsertChatArchive(ownerIdentityID: ownerIdentityID, archive)
            }
            for mutation in batch.mutations {
                try applyChatMutation(ownerIdentityID: ownerIdentityID, mutation)
            }
        }
    }

    func applyChatMutations(
        ownerIdentityID: String,
        mutations: [MobileChatMutationRecord]
    ) throws {
        try transaction {
            for mutation in mutations {
                try applyChatMutation(ownerIdentityID: ownerIdentityID, mutation)
            }
        }
    }

    func applyChatDeliveries(
        ownerIdentityID: String,
        deliveries: [MobileChatDeliveryRecord]
    ) throws {
        try transaction {
            for delivery in deliveries {
                let fragmentStatement = try prepare(
                    """
                    INSERT INTO chat_delivery_fragment (
                        owner_identity_id, session_id, handle, fragment_index, state
                    ) VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(owner_identity_id, session_id, handle, fragment_index)
                    DO UPDATE SET state = CASE
                        WHEN chat_delivery_fragment.state = 'failed'
                            OR excluded.state = 'failed' THEN 'failed'
                        WHEN chat_delivery_fragment.state = 'acknowledged'
                            OR excluded.state = 'acknowledged' THEN 'acknowledged'
                        ELSE 'sent'
                    END
                    """
                )
                defer { sqlite3_finalize(fragmentStatement) }
                try bind(ownerIdentityID, to: fragmentStatement, at: 1)
                try bind(String(delivery.sessionId), to: fragmentStatement, at: 2)
                try check(sqlite3_bind_int64(fragmentStatement, 3, Int64(delivery.handle)))
                try check(sqlite3_bind_int(
                    fragmentStatement,
                    4,
                    delivery.fragmentIndex.map(Int32.init) ?? -1
                ))
                try bind(
                    String(describing: delivery.state).lowercased(),
                    to: fragmentStatement,
                    at: 5
                )
                try stepDone(fragmentStatement)

                let message = try prepare(
                    """
                    UPDATE chat_message SET delivery_state = CASE
                        WHEN EXISTS (
                            SELECT 1 FROM chat_delivery_fragment f
                            WHERE f.owner_identity_id = chat_message.owner_identity_id
                                AND f.session_id = chat_message.session_id
                                AND f.handle = chat_message.handle AND f.state = 'failed'
                        ) THEN 'failed'
                        WHEN (
                            SELECT COUNT(*) FROM chat_delivery_fragment f
                            WHERE f.owner_identity_id = chat_message.owner_identity_id
                                AND f.session_id = chat_message.session_id
                                AND f.handle = chat_message.handle
                                AND f.state = 'acknowledged'
                        ) >= COALESCE(chat_message.fragment_count, 1) THEN 'acknowledged'
                        WHEN EXISTS (
                            SELECT 1 FROM chat_delivery_fragment f
                            WHERE f.owner_identity_id = chat_message.owner_identity_id
                                AND f.session_id = chat_message.session_id
                                AND f.handle = chat_message.handle
                                AND f.state IN ('sent', 'acknowledged')
                        ) THEN 'sent'
                        ELSE 'pending'
                    END
                    WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                    """
                )
                defer { sqlite3_finalize(message) }
                try bind(ownerIdentityID, to: message, at: 1)
                try bind(String(delivery.sessionId), to: message, at: 2)
                try check(sqlite3_bind_int64(message, 3, Int64(delivery.handle)))
                try stepDone(message)
            }
        }
    }

    /// The compose transaction is already durable at this point, but Rust
    /// could not release its held transmissions (for example because the
    /// fail-closed counter store became unavailable). Keep the optimistic row
    /// honest instead of leaving it pending forever.
    func markChatComposeBatchFailed(
        ownerIdentityID: String,
        batch: MobileChatComposeBatchRecord
    ) throws {
        try transaction {
            for mutation in batch.mutations
            where mutation.kind == .insert && mutation.direction == .outbound {
                let statement = try prepare(
                    """
                    UPDATE chat_message SET delivery_state = 'failed'
                    WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                    """
                )
                defer { sqlite3_finalize(statement) }
                try bind(ownerIdentityID, to: statement, at: 1)
                try bind(String(mutation.sessionId), to: statement, at: 2)
                try check(sqlite3_bind_int64(statement, 3, Int64(mutation.handle)))
                try stepDone(statement)
            }
        }
    }

    func chatArchive(
        ownerIdentityID: String,
        lookup: MobileChatArchiveLookupRecord
    ) throws -> Data? {
        let statement = try prepare(
            """
            SELECT payload FROM chat_outbound_archive
            WHERE owner_identity_id = ? AND peer_address = ?
                AND message_id = ? AND fragment_index = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(lookup.peerAddress, to: statement, at: 2)
        try check(sqlite3_bind_int(statement, 3, Int32(lookup.messageId)))
        try check(sqlite3_bind_int(statement, 4, lookup.fragmentIndex.map(Int32.init) ?? -1))
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return Self.dataColumn(statement, at: 0)
    }

    func chatMessages(ownerIdentityID: String, peerAddress: String) throws -> [StoredChatMessage] {
        let statement = try prepare(
            """
            SELECT session_id, handle, body, direction, delivery_state, deleted, created_at_ms
            FROM chat_message
            WHERE owner_identity_id = ? AND peer_address = ?
            ORDER BY created_at_ms ASC, rowid ASC
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(peerAddress, to: statement, at: 2)
        var messages: [StoredChatMessage] = []
        while true {
            switch sqlite3_step(statement) {
            case SQLITE_ROW:
                messages.append(
                    StoredChatMessage(
                        sessionID: Self.stringColumn(statement, at: 0),
                        handle: UInt32(sqlite3_column_int64(statement, 1)),
                        body: Self.stringColumn(statement, at: 2),
                        outbound: sqlite3_column_int(statement, 3) == 1,
                        deliveryState: Self.optionalStringColumn(statement, at: 4),
                        isDeleted: sqlite3_column_int(statement, 5) != 0,
                        createdAtMilliseconds: sqlite3_column_int64(statement, 6)
                    )
                )
            case SQLITE_DONE: return messages
            case let code: throw ApplicationStoreError.sqliteFailure(code)
            }
        }
    }

    func insertNodesAtomically(
        ownerIdentityID: String,
        nodes: [NewStoredNode]
    ) throws {
        try transaction {
            for node in nodes {
                try insertNode(ownerIdentityID: ownerIdentityID, node: node)
            }
        }
    }

    func searchNodes(ownerIdentityID: String, aliasPrefix: String) throws -> [StoredNode] {
        let normalized = Self.normalizeSearch(aliasPrefix)
        let upperBound = normalized + "\u{10FFFF}"
        let statement = try prepare(
            """
            SELECT id, owner_identity_id, public_address, alias, advertised_name,
                   is_contact, system_role, node_kind
            FROM node
            WHERE owner_identity_id = ? AND alias_search >= ? AND alias_search < ?
            ORDER BY alias_search, id
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(normalized, to: statement, at: 2)
        try bind(upperBound, to: statement, at: 3)

        var nodes: [StoredNode] = []
        while true {
            switch sqlite3_step(statement) {
            case SQLITE_ROW:
                nodes.append(storedNode(statement))
            case SQLITE_DONE:
                return nodes
            case let code:
                throw ApplicationStoreError.sqliteFailure(code)
            }
        }
    }

    func nodeSearchUsesIndex(ownerIdentityID: String, aliasPrefix: String) throws -> Bool {
        let normalized = Self.normalizeSearch(aliasPrefix)
        let statement = try prepare(
            """
            EXPLAIN QUERY PLAN
            SELECT id FROM node
            WHERE owner_identity_id = ? AND alias_search >= ? AND alias_search < ?
            ORDER BY alias_search, id
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(normalized, to: statement, at: 2)
        try bind(normalized + "\u{10FFFF}", to: statement, at: 3)

        while sqlite3_step(statement) == SQLITE_ROW {
            if Self.stringColumn(statement, at: 3).contains("node_owner_alias_search_idx") {
                return true
            }
        }
        return false
    }

    private func insertNode(ownerIdentityID: String, node: NewStoredNode) throws {
        let statement = try prepare(
            """
            INSERT INTO node (owner_identity_id, public_address, alias, alias_search)
            VALUES (?, ?, ?, ?)
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(node.publicAddress, to: statement, at: 2)
        try bindOptional(node.alias, to: statement, at: 3)
        try bind(Self.normalizeSearch(node.alias ?? ""), to: statement, at: 4)
        try stepDone(statement)
    }

    private func readNodes(_ statement: OpaquePointer) throws -> [StoredNode] {
        var nodes: [StoredNode] = []
        while true {
            switch sqlite3_step(statement) {
            case SQLITE_ROW: nodes.append(storedNode(statement))
            case SQLITE_DONE: return nodes
            case let code: throw ApplicationStoreError.sqliteFailure(code)
            }
        }
    }

    private func storedNode(_ statement: OpaquePointer, offset: Int32 = 0) -> StoredNode {
        StoredNode(
            id: sqlite3_column_int64(statement, offset),
            ownerIdentityID: Self.stringColumn(statement, at: offset + 1),
            publicAddress: Self.stringColumn(statement, at: offset + 2),
            alias: Self.optionalStringColumn(statement, at: offset + 3),
            advertisedName: Self.optionalStringColumn(statement, at: offset + 4),
            isContact: sqlite3_column_int(statement, offset + 5) != 0,
            systemRole: Self.optionalStringColumn(statement, at: offset + 6),
            nodeKind: Self.optionalStringColumn(statement, at: offset + 7)
        )
    }

    private func upsertChatCheckpoint(
        ownerIdentityID: String,
        _ checkpoint: MobileChatCheckpointRecord
    ) throws {
        let statement = try prepare(
            """
            INSERT INTO chat_stream_checkpoint (
                owner_identity_id, peer_address, next_id, epoch, updated_at_ms
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(owner_identity_id, peer_address) DO UPDATE SET
                next_id = excluded.next_id,
                epoch = excluded.epoch,
                updated_at_ms = excluded.updated_at_ms
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(checkpoint.peerAddress, to: statement, at: 2)
        try check(sqlite3_bind_int(statement, 3, Int32(checkpoint.nextId)))
        try check(sqlite3_bind_int(statement, 4, Int32(checkpoint.epoch)))
        try check(sqlite3_bind_int64(statement, 5, Self.nowMilliseconds()))
        try stepDone(statement)
    }

    private func upsertChatArchive(
        ownerIdentityID: String,
        _ archive: MobileChatArchiveRecord
    ) throws {
        let statement = try prepare(
            """
            INSERT INTO chat_outbound_archive (
                owner_identity_id, peer_address, message_id, fragment_index, payload
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(owner_identity_id, peer_address, message_id, fragment_index)
            DO UPDATE SET payload = excluded.payload
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(archive.peerAddress, to: statement, at: 2)
        try check(sqlite3_bind_int(statement, 3, Int32(archive.messageId)))
        try check(sqlite3_bind_int(statement, 4, archive.fragmentIndex.map(Int32.init) ?? -1))
        try bind(archive.payload, to: statement, at: 5)
        try stepDone(statement)
    }

    private func applyChatMutation(
        ownerIdentityID: String,
        _ mutation: MobileChatMutationRecord
    ) throws {
        let sessionID = String(mutation.sessionId)
        let ledger = try prepare(
            """
            INSERT INTO chat_applied_mutation (owner_identity_id, session_id, handle, revision)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(owner_identity_id, session_id, handle) DO UPDATE SET
                revision = excluded.revision
            WHERE excluded.revision > chat_applied_mutation.revision
            """
        )
        defer { sqlite3_finalize(ledger) }
        try bind(ownerIdentityID, to: ledger, at: 1)
        try bind(sessionID, to: ledger, at: 2)
        try check(sqlite3_bind_int64(ledger, 3, Int64(mutation.handle)))
        try check(sqlite3_bind_int64(ledger, 4, Int64(mutation.revision)))
        try stepDone(ledger)
        guard sqlite3_changes(database) > 0 else { return }

        switch mutation.kind {
        case .insert:
            guard let peerAddress = mutation.peerAddress,
                  let direction = mutation.direction,
                  let body = mutation.body
            else { return }
            let statement = try prepare(
                """
                INSERT INTO chat_message (
                    owner_identity_id, session_id, handle, peer_address, sender_address,
                    direction, message_type, wire_id, epoch, client_token,
                    sender_handle, regarding_handle, background_color, text_color, body,
                    complete, present_fragments, fragment_count, finalized,
                    delivery_state, deleted, created_at_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(owner_identity_id, session_id, handle) DO UPDATE SET
                    body = excluded.body,
                    complete = excluded.complete,
                    present_fragments = excluded.present_fragments,
                    fragment_count = excluded.fragment_count,
                    finalized = excluded.finalized
                """
            )
            defer { sqlite3_finalize(statement) }
            try bind(ownerIdentityID, to: statement, at: 1)
            try bind(sessionID, to: statement, at: 2)
            try check(sqlite3_bind_int64(statement, 3, Int64(mutation.handle)))
            try bind(peerAddress, to: statement, at: 4)
            try bindOptional(mutation.senderAddress, to: statement, at: 5)
            try check(sqlite3_bind_int(statement, 6, direction == .outbound ? 1 : 0))
            try bindOptionalInt(mutation.messageType.map(Int64.init), to: statement, at: 7)
            try bindOptionalInt(mutation.wireId.map(Int64.init), to: statement, at: 8)
            try bindOptionalInt(mutation.epoch.map(Int64.init), to: statement, at: 9)
            try bindOptionalInt(mutation.clientToken.map(Int64.init), to: statement, at: 10)
            try bindOptional(mutation.senderHandle, to: statement, at: 11)
            try bindOptionalInt(mutation.regardingHandle.map(Int64.init), to: statement, at: 12)
            try bindOptional(mutation.backgroundColor, to: statement, at: 13)
            try bindOptional(mutation.textColor, to: statement, at: 14)
            try bind(body, to: statement, at: 15)
            try bindOptionalBool(mutation.complete, to: statement, at: 16)
            try bindOptionalInt(mutation.presentFragments.map(Int64.init), to: statement, at: 17)
            try bindOptionalInt(mutation.fragmentCount.map(Int64.init), to: statement, at: 18)
            try bindOptionalBool(mutation.finalized, to: statement, at: 19)
            try bindOptional(direction == .outbound ? "pending" : nil, to: statement, at: 20)
            try check(sqlite3_bind_int64(statement, 21, Self.nowMilliseconds()))
            try stepDone(statement)
        case .updateBody:
            guard let body = mutation.body else { return }
            let statement = try prepare(
                """
                UPDATE chat_message SET body = ?, complete = ?, present_fragments = ?,
                    fragment_count = ?, finalized = ?
                WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                """
            )
            defer { sqlite3_finalize(statement) }
            try bind(body, to: statement, at: 1)
            try bindOptionalBool(mutation.complete, to: statement, at: 2)
            try bindOptionalInt(mutation.presentFragments.map(Int64.init), to: statement, at: 3)
            try bindOptionalInt(mutation.fragmentCount.map(Int64.init), to: statement, at: 4)
            try bindOptionalBool(mutation.finalized, to: statement, at: 5)
            try bind(ownerIdentityID, to: statement, at: 6)
            try bind(sessionID, to: statement, at: 7)
            try check(sqlite3_bind_int64(statement, 8, Int64(mutation.handle)))
            try stepDone(statement)
        case .edit, .delete:
            guard let original = mutation.originalHandle else { return }
            let statement = try prepare(
                """
                UPDATE chat_message SET body = ?, deleted = ?
                WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                """
            )
            defer { sqlite3_finalize(statement) }
            try bind(mutation.kind == .delete ? "" : (mutation.body ?? ""), to: statement, at: 1)
            try check(sqlite3_bind_int(statement, 2, mutation.kind == .delete ? 1 : 0))
            try bind(ownerIdentityID, to: statement, at: 3)
            try bind(sessionID, to: statement, at: 4)
            try check(sqlite3_bind_int64(statement, 5, Int64(original)))
            try stepDone(statement)
        }
    }

    private func transaction<T>(_ operation: () throws -> T) throws -> T {
        try Self.execute(database, sql: "BEGIN IMMEDIATE")
        do {
            let value = try operation()
            try Self.execute(database, sql: "COMMIT")
            return value
        } catch {
            try? Self.execute(database, sql: "ROLLBACK")
            throw error
        }
    }

    private func prepare(_ sql: String) throws -> OpaquePointer {
        var statement: OpaquePointer?
        let status = sqlite3_prepare_v2(database, sql, -1, &statement, nil)
        guard status == SQLITE_OK, let statement else {
            throw ApplicationStoreError.sqliteFailure(status)
        }
        return statement
    }

    private func bind(_ value: String, to statement: OpaquePointer, at index: Int32) throws {
        let status = value.withCString { pointer in
            sqlite3_bind_text(statement, index, pointer, -1, Self.sqliteTransient)
        }
        try check(status)
    }

    private func bind(_ value: Data, to statement: OpaquePointer, at index: Int32) throws {
        let status = value.withUnsafeBytes { bytes in
            sqlite3_bind_blob(statement, index, bytes.baseAddress, Int32(bytes.count), Self.sqliteTransient)
        }
        try check(status)
    }

    private func bindOptional(
        _ value: String?,
        to statement: OpaquePointer,
        at index: Int32
    ) throws {
        if let value {
            try bind(value, to: statement, at: index)
        } else {
            try check(sqlite3_bind_null(statement, index))
        }
    }

    private func bindOptional(
        _ value: Data?,
        to statement: OpaquePointer,
        at index: Int32
    ) throws {
        if let value {
            try bind(value, to: statement, at: index)
        } else {
            try check(sqlite3_bind_null(statement, index))
        }
    }

    private func bindOptionalInt(
        _ value: Int64?,
        to statement: OpaquePointer,
        at index: Int32
    ) throws {
        if let value {
            try check(sqlite3_bind_int64(statement, index, value))
        } else {
            try check(sqlite3_bind_null(statement, index))
        }
    }

    private func bindOptionalBool(
        _ value: Bool?,
        to statement: OpaquePointer,
        at index: Int32
    ) throws {
        try bindOptionalInt(value.map { $0 ? 1 : 0 }, to: statement, at: index)
    }

    private func stepDone(_ statement: OpaquePointer) throws {
        let status = sqlite3_step(statement)
        guard status == SQLITE_DONE else {
            throw ApplicationStoreError.sqliteFailure(status)
        }
    }

    private func check(_ status: Int32) throws {
        guard status == SQLITE_OK else {
            throw ApplicationStoreError.sqliteFailure(status)
        }
    }

    private static func migrate(_ database: OpaquePointer) throws {
        let version = try readSchemaVersion(database)
        guard version <= currentSchemaVersion else {
            throw ApplicationStoreError.unsupportedSchema(version)
        }
        if version < 1 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
            try execute(
                database,
                sql: """
                CREATE TABLE local_identity (
                    id TEXT PRIMARY KEY NOT NULL,
                    public_address TEXT NOT NULL UNIQUE,
                    created_at_ms INTEGER NOT NULL
                );

                CREATE TABLE node (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    owner_identity_id TEXT NOT NULL
                        REFERENCES local_identity(id) ON DELETE CASCADE,
                    public_address TEXT NOT NULL,
                    alias TEXT,
                    alias_search TEXT NOT NULL,
                    UNIQUE (owner_identity_id, public_address)
                );

                CREATE INDEX node_owner_alias_search_idx
                    ON node (owner_identity_id, alias_search, id);

                PRAGMA user_version = 1;
                """
            )
            try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 2 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                try execute(
                    database,
                    sql: """
                    ALTER TABLE node ADD COLUMN advertised_name TEXT;
                    ALTER TABLE node ADD COLUMN is_contact INTEGER NOT NULL DEFAULT 0;
                    ALTER TABLE node ADD COLUMN system_role TEXT;
                    ALTER TABLE node ADD COLUMN radio_identifier TEXT;

                    CREATE TABLE direct_conversation (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        node_id INTEGER NOT NULL REFERENCES node(id) ON DELETE RESTRICT,
                        draft_text TEXT NOT NULL DEFAULT '',
                        created_at_ms INTEGER NOT NULL,
                        UNIQUE (owner_identity_id, node_id)
                    );

                    PRAGMA user_version = 2;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }


        if version < 3 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                try execute(
                    database,
                    sql: """
                    ALTER TABLE node ADD COLUMN node_kind TEXT;
                    PRAGMA user_version = 3;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }


        if version < 4 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                try execute(
                    database,
                    sql: """
                    CREATE TABLE chat_stream_checkpoint (
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        peer_address TEXT NOT NULL,
                        next_id INTEGER NOT NULL,
                        epoch INTEGER NOT NULL,
                        updated_at_ms INTEGER NOT NULL,
                        PRIMARY KEY (owner_identity_id, peer_address)
                    );

                    CREATE TABLE chat_outbound_archive (
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        peer_address TEXT NOT NULL,
                        message_id INTEGER NOT NULL,
                        fragment_index INTEGER NOT NULL,
                        payload BLOB NOT NULL,
                        PRIMARY KEY (
                            owner_identity_id, peer_address, message_id, fragment_index
                        )
                    );

                    CREATE TABLE chat_message (
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        session_id TEXT NOT NULL,
                        handle INTEGER NOT NULL,
                        peer_address TEXT NOT NULL,
                        sender_address TEXT,
                        direction INTEGER NOT NULL,
                        message_type INTEGER,
                        wire_id INTEGER,
                        epoch INTEGER,
                        client_token INTEGER,
                        sender_handle TEXT,
                        regarding_handle INTEGER,
                        background_color BLOB,
                        text_color BLOB,
                        body TEXT NOT NULL,
                        complete INTEGER,
                        present_fragments INTEGER,
                        fragment_count INTEGER,
                        finalized INTEGER,
                        delivery_state TEXT,
                        deleted INTEGER NOT NULL DEFAULT 0,
                        created_at_ms INTEGER NOT NULL,
                        PRIMARY KEY (owner_identity_id, session_id, handle)
                    );

                    CREATE INDEX chat_message_conversation_idx
                        ON chat_message (owner_identity_id, peer_address, created_at_ms);

                    CREATE TABLE chat_applied_mutation (
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        session_id TEXT NOT NULL,
                        handle INTEGER NOT NULL,
                        revision INTEGER NOT NULL,
                        PRIMARY KEY (owner_identity_id, session_id, handle)
                    );

                    CREATE TABLE chat_delivery_fragment (
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        session_id TEXT NOT NULL,
                        handle INTEGER NOT NULL,
                        fragment_index INTEGER NOT NULL,
                        state TEXT NOT NULL,
                        PRIMARY KEY (
                            owner_identity_id, session_id, handle, fragment_index
                        )
                    );

                    PRAGMA user_version = 4;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }
    }

    private static func readSchemaVersion(_ database: OpaquePointer) throws -> Int32 {
        var statement: OpaquePointer?
        let status = sqlite3_prepare_v2(database, "PRAGMA user_version", -1, &statement, nil)
        guard status == SQLITE_OK, let statement else {
            throw ApplicationStoreError.sqliteFailure(status)
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw ApplicationStoreError.sqliteFailure(sqlite3_errcode(database))
        }
        return sqlite3_column_int(statement, 0)
    }

    private static func execute(_ database: OpaquePointer, sql: String) throws {
        let status = sqlite3_exec(database, sql, nil, nil, nil)
        guard status == SQLITE_OK else {
            throw ApplicationStoreError.sqliteFailure(status)
        }
    }

    private static func normalizeSearch(_ value: String) -> String {
        value.folding(
            options: [.caseInsensitive, .diacriticInsensitive],
            locale: Locale(identifier: "en_US_POSIX")
        )
    }

    private static func stringColumn(_ statement: OpaquePointer, at index: Int32) -> String {
        guard let pointer = sqlite3_column_text(statement, index) else { return "" }
        return String(cString: pointer)
    }

    private static func dataColumn(_ statement: OpaquePointer, at index: Int32) -> Data {
        guard let bytes = sqlite3_column_blob(statement, index) else { return Data() }
        return Data(bytes: bytes, count: Int(sqlite3_column_bytes(statement, index)))
    }

    private static func nowMilliseconds() -> Int64 {
        Int64(Date.now.timeIntervalSince1970 * 1_000)
    }

    private static func optionalStringColumn(
        _ statement: OpaquePointer,
        at index: Int32
    ) -> String? {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL else { return nil }
        return stringColumn(statement, at: index)
    }

    private static let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
}
