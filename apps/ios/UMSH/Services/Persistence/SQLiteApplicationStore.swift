import Foundation
import SQLite3

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

/// Phase 0 direct-SQLite prototype.
///
/// This store contains public application records only. Private identity and
/// channel key bytes are never accepted by this API and remain in Keychain.
actor SQLiteApplicationStore {
    static let currentSchemaVersion: Int32 = 3

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

    private static func optionalStringColumn(
        _ statement: OpaquePointer,
        at index: Int32
    ) -> String? {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL else { return nil }
        return stringColumn(statement, at: index)
    }

    private static let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
}
