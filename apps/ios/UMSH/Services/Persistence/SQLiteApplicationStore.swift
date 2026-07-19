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
}

struct NewStoredNode: Equatable, Sendable {
    let publicAddress: String
    let alias: String?
}

/// Phase 0 direct-SQLite prototype.
///
/// This store contains public application records only. Private identity and
/// channel key bytes are never accepted by this API and remain in Keychain.
actor SQLiteApplicationStore {
    static let currentSchemaVersion: Int32 = 1

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
            SELECT id, owner_identity_id, public_address, alias
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
                nodes.append(
                    StoredNode(
                        id: sqlite3_column_int64(statement, 0),
                        ownerIdentityID: Self.stringColumn(statement, at: 1),
                        publicAddress: Self.stringColumn(statement, at: 2),
                        alias: Self.optionalStringColumn(statement, at: 3)
                    )
                )
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
        guard version < 1 else { return }

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
