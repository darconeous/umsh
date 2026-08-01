import Foundation
import SQLite3
import UMSHMobileCore

enum ApplicationStoreError: Error, Equatable, Sendable {
    case applicationSupportUnavailable
    case openFailed(Int32)
    case sqliteFailure(Int32)
    case unsupportedSchema(Int32)
    /// Migrations ran but left the database at a version other than
    /// ``SQLiteApplicationStore/currentSchemaVersion`` — a migration block
    /// stamped a `user_version` the constant was never raised to match. Fails
    /// on the first run of the offending build rather than on the second,
    /// where the store would open once and then be rejected forever after.
    case schemaVersionMismatch(applied: Int32, expected: Int32)
}

extension ApplicationStoreError {
    /// Enough detail to act on in a bug report, without leaking record content.
    var diagnosticDescription: String {
        switch self {
        case .applicationSupportUnavailable:
            "The Application Support directory is unavailable."
        case .openFailed(let code):
            "sqlite3_open_v2 failed with code \(code)."
        case .sqliteFailure(let code):
            "SQLite returned code \(code)."
        case .unsupportedSchema(let version):
            """
            The database is at schema version \(version); this build supports \
            up to \(SQLiteApplicationStore.currentSchemaVersion). It was \
            written by a newer build.
            """
        case .schemaVersionMismatch(let applied, let expected):
            """
            Migrations left the database at schema version \(applied) but this \
            build declares \(expected). A migration was added without raising \
            currentSchemaVersion.
            """
        }
    }
}

struct StoredNode: Equatable, Sendable {
    let id: Int64
    let ownerIdentityID: String
    let publicAddress: String
    let alias: String?
    let advertisedName: String?
    let systemRole: String?
    let nodeKind: String?
    /// Raw advertised-identity payload bytes (node-identity.md wire form),
    /// decoded for display through the Rust facade on load.
    let advertisement: Data?
    /// Whether the MAC authenticated the frame that delivered `advertisement`.
    /// A bundle that arrived as a MIC-authenticated unicast reply carries no
    /// signature of its own, so this is the only surviving evidence that it
    /// really came from the peer.
    let advertisementAuthenticated: Bool
    /// Wall-clock instant we last heard from this peer by any means
    /// (advertisement, inbound message, delivery ack, ping reply). `nil`
    /// until the first inbound evidence lands.
    let lastHeardAt: Date?
    /// Whether this node is saved on the local (phone) identity. Rows with
    /// `false` are the transient tier: heard on the air, kept for search and
    /// discovery, hidden from the main Peers list, and subject to retention.
    let isSaved: Bool
    let isFavorite: Bool
    /// Cache of whether this node's public key is stored on the companion
    /// radio's device identity (`PROP_DEV_PEERS`). The device is the
    /// authority; this flag is reconciled from it on attach.
    let onDeviceIdentity: Bool
}

struct StoredDirectConversation: Equatable, Sendable {
    let id: Int64
    let node: StoredNode
    let draftText: String
    /// When this conversation was last read. Messages newer than this are
    /// unread; a conversation the user has never opened reads as all-unread
    /// from its first message.
    let lastReadAtMilliseconds: Int64
    /// When the conversation row was created — the activity time of a
    /// conversation that has no messages yet.
    let createdAtMilliseconds: Int64
}

/// A channel's group conversation. Its other end is a channel rather than a
/// node, which is why it is not a row in `direct_conversation`.
struct StoredChannelConversation: Equatable, Sendable {
    let id: Int64
    let channelID: UUID
    /// The address the facade keys this conversation's records by.
    let conversationAddress: String
    let draftText: String
    let lastReadAtMilliseconds: Int64
    /// When the conversation row was created — the activity time of a
    /// conversation that has no messages yet.
    let createdAtMilliseconds: Int64
}

/// What a notification needs to describe an arrived message, resolved from
/// storage rather than from the mutation that triggered it.
struct ChatNotificationTarget: Equatable, Sendable {
    let conversationAddress: String
    let body: String
    /// The sender's full address, when known. A group message from a member
    /// whose hint has not resolved yet has none.
    let senderAddress: String?
    /// The sender's claimed hint, for a group message.
    let senderHint: Data?
    /// The name the sender attached to the message.
    let senderHandle: String?
}

/// How a channel's key was established, which decides what may be shared.
enum StoredChannelKind: String, Equatable, Sendable {
    /// `public` or `EMERGENCY`: named channels the protocol fixes rules for.
    /// These rows are never deleted — leaving clears the joined flags so the
    /// channel can be offered again.
    case builtin
    /// Key derived from a name anyone may know, so the name is shareable.
    case named
    /// Key distributed out of band; the invitation is a secret.
    case privateKey = "private"
}

/// A channel this identity knows about. Public metadata only: the 32-byte key
/// lives in Keychain under `id`.
struct StoredChannel: Equatable, Sendable {
    let id: UUID
    let ownerIdentityID: String
    let kind: StoredChannelKind
    /// Canonical lowercase name the key is derived from. Key-derivation
    /// machinery, not something to show: `name` is what the channel is called.
    let canonicalName: String?
    /// The channel's own name, written the way it was typed or shared.
    let name: String?
    /// What this user calls the channel. Takes display precedence but never
    /// overwrites `name`, matching how a peer alias works.
    let alias: String?
    /// Two-octet derived identifier, hex. A hint, not an identity: distinct
    /// keys may collide here.
    let channelIDHex: String
    /// Three presentation octets — the identifier extended by one byte — kept
    /// here so a list can colour its rows without unlocking every key.
    let tint: Data
    let regionCode: Data?
    let maxFloodHops: Int?
    /// Whether the phone identity has joined. Drives MAC registration and the
    /// radio's host channel table.
    let joinedPhone: Bool
    /// Whether the companion radio's device identity has joined. A cache: the
    /// device is authoritative and this is reconciled from it on attach.
    let joinedDevice: Bool
    /// Reserved for channel chat; no notification path reads it yet.
    let notificationsEnabled: Bool
    let joinedAt: Date?
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
    /// Durable wire identity for referencing this message (edit/delete)
    /// after the facade session that composed it is gone.
    let wireID: UInt8?
    let epoch: UInt16?
    let isEdited: Bool
    /// Ordered-repair presence: 0 = present, 1 = gap placeholder, 2 = unavailable.
    let presence: Int
    /// The message filled a reserved gap slot out of order.
    let receivedLate: Bool
    /// An outbound message that failed transport but was later acknowledged
    /// via a resend.
    let deliveredLate: Bool
    /// Pre-edit text of the sender's own edited message, kept for review.
    let originalBody: String?
    /// Who sent this, for a group message: the full address once known, the
    /// claimed hint the wire always carries, and the name the sender put in
    /// the message itself.
    let senderAddress: String?
    let senderHint: Data?
    let senderHandle: String?
    /// What the radio observed of the frame this message arrived on. Absent
    /// for outbound messages and for anything that predates the metadata.
    let reception: StoredMessageReception?

    var isGapPlaceholder: Bool { presence == 1 }
    var isUnavailable: Bool { presence == 2 }
}

/// The radio's view of one received message, for the message-details sheet.
struct StoredMessageReception: Hashable, Sendable {
    let rssiDbm: Int?
    let snrCentibels: Int?
    let lqi: Int?
    /// Hops accumulated on the way here. Zero means heard directly.
    let hopCount: Int?
    /// Repeater hints in trace-route order: nearest this phone first, nearest
    /// the sender last.
    let routeHints: [Data]
    let sourceAuthenticated: Bool
}

/// Maps the engine's presence enum to its stored integer code.
private func presenceCode(_ presence: MobileChatPresence) -> Int32 {
    switch presence {
    case .present: return 0
    case .gapPending: return 1
    case .unavailable: return 2
    }
}

/// Phase 0 direct-SQLite prototype.
///
/// This store contains public application records only. Private identity and
/// channel key bytes are never accepted by this API and remain in Keychain.
actor SQLiteApplicationStore {
    /// Must equal the highest `PRAGMA user_version` any migration block in
    /// ``migrate(_:)`` stamps. Raise it in the same commit that adds one:
    /// migrations run when the stored version is *below* their target, but the
    /// store refuses to open any database above this constant, so a stale value
    /// lets the new schema apply once and then locks the user out of their own
    /// data on the next launch. ``migrate(_:)`` checks the two agree.
    static let currentSchemaVersion: Int32 = 16

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
        isSaved: Bool = false,
        nodeKind: String? = nil,
        systemRole: String? = nil,
        radioIdentifier: String? = nil,
        advertisement: Data? = nil,
        advertisementAuthenticated: Bool = false
    ) throws {
        let statement = try prepare(
            """
            INSERT INTO node (
                owner_identity_id, public_address, alias, alias_search,
                advertised_name, is_saved, system_role, radio_identifier,
                node_kind, advertisement, advertisement_authenticated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(owner_identity_id, public_address) DO UPDATE SET
                alias = COALESCE(excluded.alias, node.alias),
                alias_search = CASE WHEN excluded.alias IS NULL
                    THEN node.alias_search ELSE excluded.alias_search END,
                advertised_name = COALESCE(excluded.advertised_name, node.advertised_name),
                -- A background advertisement upsert must never demote a saved
                -- peer to the transient tier; only the explicit demote/delete
                -- setters move a row downward.
                is_saved = MAX(node.is_saved, excluded.is_saved),
                system_role = COALESCE(excluded.system_role, node.system_role),
                radio_identifier = COALESCE(excluded.radio_identifier, node.radio_identifier),
                node_kind = COALESCE(excluded.node_kind, node.node_kind),
                advertisement = COALESCE(excluded.advertisement, node.advertisement),
                -- Provenance belongs to the bundle it describes, so it moves
                -- only when the bundle does. A call that carries no
                -- advertisement leaves both untouched.
                advertisement_authenticated = CASE WHEN excluded.advertisement IS NULL
                    THEN node.advertisement_authenticated
                    ELSE excluded.advertisement_authenticated END
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(publicAddress, to: statement, at: 2)
        try bindOptional(alias, to: statement, at: 3)
        try bind(Self.normalizeSearch(alias ?? advertisedName ?? ""), to: statement, at: 4)
        try bindOptional(advertisedName, to: statement, at: 5)
        try check(sqlite3_bind_int(statement, 6, isSaved ? 1 : 0))
        try bindOptional(systemRole, to: statement, at: 7)
        try bindOptional(radioIdentifier, to: statement, at: 8)
        try bindOptional(nodeKind, to: statement, at: 9)
        try bindOptional(advertisement, to: statement, at: 10)
        try check(sqlite3_bind_int(statement, 11, advertisementAuthenticated ? 1 : 0))
        try stepDone(statement)
    }

    func localAdvertisedName(ownerIdentityID: String) throws -> String? {
        let statement = try prepare(
            "SELECT advertised_name FROM local_identity WHERE id = ?"
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return Self.optionalStringColumn(statement, at: 0)
    }

    func updateLocalAdvertisedName(ownerIdentityID: String, name: String?) throws {
        let statement = try prepare(
            "UPDATE local_identity SET advertised_name = ? WHERE id = ?"
        )
        defer { sqlite3_finalize(statement) }
        try bindOptional(name, to: statement, at: 1)
        try bind(ownerIdentityID, to: statement, at: 2)
        try stepDone(statement)
    }

    // MARK: - Channels

    func channels(ownerIdentityID: String) throws -> [StoredChannel] {
        let statement = try prepare(
            """
            SELECT id, kind, canonical_name, name, alias, channel_id_hex, tint,
                   region_code, max_flood_hops, joined_phone, joined_device,
                   notifications_enabled, joined_at_ms
            FROM channel WHERE owner_identity_id = ?
            ORDER BY created_at_ms, id
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)

        var channels: [StoredChannel] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            guard
                let id = UUID(uuidString: Self.stringColumn(statement, at: 0)),
                let kind = StoredChannelKind(rawValue: Self.stringColumn(statement, at: 1))
            else {
                continue
            }
            channels.append(
                StoredChannel(
                    id: id,
                    ownerIdentityID: ownerIdentityID,
                    kind: kind,
                    canonicalName: Self.optionalStringColumn(statement, at: 2),
                    name: Self.optionalStringColumn(statement, at: 3),
                    alias: Self.optionalStringColumn(statement, at: 4),
                    channelIDHex: Self.stringColumn(statement, at: 5),
                    tint: Self.dataColumn(statement, at: 6),
                    regionCode: Self.optionalDataColumn(statement, at: 7),
                    maxFloodHops: Self.optionalIntColumn(statement, at: 8).map(Int.init),
                    joinedPhone: sqlite3_column_int(statement, 9) != 0,
                    joinedDevice: sqlite3_column_int(statement, 10) != 0,
                    notificationsEnabled: sqlite3_column_int(statement, 11) != 0,
                    joinedAt: Self.optionalIntColumn(statement, at: 12).map {
                        Date(timeIntervalSince1970: Double($0) / 1_000)
                    }
                )
            )
        }
        return channels
    }

    /// The channel this identity already holds under `keyDigest`, if any.
    ///
    /// Import checks this before inserting so a re-scanned invitation updates
    /// the existing channel instead of creating a second one for the same key.
    func channel(ownerIdentityID: String, keyDigest: String) throws -> StoredChannel? {
        let statement = try prepare(
            "SELECT id FROM channel WHERE owner_identity_id = ? AND key_digest = ?"
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(keyDigest, to: statement, at: 2)
        guard sqlite3_step(statement) == SQLITE_ROW,
              let id = UUID(uuidString: Self.stringColumn(statement, at: 0))
        else {
            return nil
        }
        return try channels(ownerIdentityID: ownerIdentityID).first { $0.id == id }
    }

    func insertChannel(_ channel: StoredChannel, keyDigest: String) throws {
        let statement = try prepare(
            """
            INSERT INTO channel (
                id, owner_identity_id, kind, canonical_name, name, alias,
                channel_id_hex, tint, key_digest, region_code, max_flood_hops,
                joined_phone, joined_device, notifications_enabled,
                created_at_ms, joined_at_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
        )
        defer { sqlite3_finalize(statement) }
        let now = Self.nowMilliseconds()
        try bind(channel.id.uuidString, to: statement, at: 1)
        try bind(channel.ownerIdentityID, to: statement, at: 2)
        try bind(channel.kind.rawValue, to: statement, at: 3)
        try bindOptional(channel.canonicalName, to: statement, at: 4)
        try bindOptional(channel.name, to: statement, at: 5)
        try bindOptional(channel.alias, to: statement, at: 6)
        try bind(channel.channelIDHex, to: statement, at: 7)
        try bind(channel.tint, to: statement, at: 8)
        try bind(keyDigest, to: statement, at: 9)
        try bindOptional(channel.regionCode, to: statement, at: 10)
        try bindOptionalInt(channel.maxFloodHops.map(Int64.init), to: statement, at: 11)
        try check(sqlite3_bind_int(statement, 12, channel.joinedPhone ? 1 : 0))
        try check(sqlite3_bind_int(statement, 13, channel.joinedDevice ? 1 : 0))
        try check(sqlite3_bind_int(statement, 14, channel.notificationsEnabled ? 1 : 0))
        try check(sqlite3_bind_int64(statement, 15, now))
        try bindOptionalInt(
            channel.joinedAt.map { Int64($0.timeIntervalSince1970 * 1_000) },
            to: statement,
            at: 16
        )
        try stepDone(statement)
    }

    /// Update the parts of a channel the user controls, leaving membership and
    /// key-derived columns alone.
    func updateChannelDetails(
        id: UUID,
        alias: String?,
        regionCode: Data?,
        maxFloodHops: Int?,
        notificationsEnabled: Bool
    ) throws {
        let statement = try prepare(
            """
            UPDATE channel
            SET alias = ?, region_code = ?, max_flood_hops = ?,
                notifications_enabled = ?
            WHERE id = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try bindOptional(alias, to: statement, at: 1)
        try bindOptional(regionCode, to: statement, at: 2)
        try bindOptionalInt(maxFloodHops.map(Int64.init), to: statement, at: 3)
        try check(sqlite3_bind_int(statement, 4, notificationsEnabled ? 1 : 0))
        try bind(id.uuidString, to: statement, at: 5)
        try stepDone(statement)
    }

    /// Record which identities have joined. `joinedAt` is stamped the first
    /// time the phone joins and left alone after.
    func setChannelMembership(id: UUID, joinedPhone: Bool, joinedDevice: Bool) throws {
        let statement = try prepare(
            """
            UPDATE channel
            SET joined_phone = ?, joined_device = ?,
                joined_at_ms = CASE
                    WHEN ? = 1 AND joined_at_ms IS NULL THEN ? ELSE joined_at_ms
                END
            WHERE id = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try check(sqlite3_bind_int(statement, 1, joinedPhone ? 1 : 0))
        try check(sqlite3_bind_int(statement, 2, joinedDevice ? 1 : 0))
        try check(sqlite3_bind_int(statement, 3, joinedPhone ? 1 : 0))
        try check(sqlite3_bind_int64(statement, 4, Self.nowMilliseconds()))
        try bind(id.uuidString, to: statement, at: 5)
        try stepDone(statement)
    }

    func deleteChannel(id: UUID) throws {
        let statement = try prepare("DELETE FROM channel WHERE id = ?")
        defer { sqlite3_finalize(statement) }
        try bind(id.uuidString, to: statement, at: 1)
        try stepDone(statement)
    }

    func updateNodeAlias(
        ownerIdentityID: String,
        publicAddress: String,
        alias: String?
    ) throws {
        try transaction {
            // The prefix-search key falls back to the advertised name when
            // the alias is cleared, matching upsertPeer's initial insert.
            let select = try prepare(
                """
                SELECT advertised_name FROM node
                WHERE owner_identity_id = ? AND public_address = ?
                """
            )
            defer { sqlite3_finalize(select) }
            try bind(ownerIdentityID, to: select, at: 1)
            try bind(publicAddress, to: select, at: 2)
            guard sqlite3_step(select) == SQLITE_ROW else { return }
            let advertisedName = Self.optionalStringColumn(select, at: 0)

            let update = try prepare(
                """
                UPDATE node SET alias = ?, alias_search = ?
                WHERE owner_identity_id = ? AND public_address = ?
                """
            )
            defer { sqlite3_finalize(update) }
            try bindOptional(alias, to: update, at: 1)
            try bind(Self.normalizeSearch(alias ?? advertisedName ?? ""), to: update, at: 2)
            try bind(ownerIdentityID, to: update, at: 3)
            try bind(publicAddress, to: update, at: 4)
            try stepDone(update)
        }
    }

    func setPeerFavorite(
        ownerIdentityID: String,
        publicAddress: String,
        isFavorite: Bool
    ) throws {
        // Favoriting implies saving: the star lives in the main list, so a
        // favorite hidden in the transient tier would be unreachable.
        let statement = try prepare(
            """
            UPDATE node SET is_favorite = ?,
                is_saved = CASE WHEN ? = 1 THEN 1 ELSE is_saved END
            WHERE owner_identity_id = ? AND public_address = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try check(sqlite3_bind_int(statement, 1, isFavorite ? 1 : 0))
        try check(sqlite3_bind_int(statement, 2, isFavorite ? 1 : 0))
        try bind(ownerIdentityID, to: statement, at: 3)
        try bind(publicAddress, to: statement, at: 4)
        try stepDone(statement)
    }

    /// Record a transient node on the local identity, making it visible in
    /// the main Peers list.
    func promotePeerToSaved(ownerIdentityID: String, publicAddress: String) throws {
        let statement = try prepare(
            """
            UPDATE node SET is_saved = 1
            WHERE owner_identity_id = ? AND public_address = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(publicAddress, to: statement, at: 2)
        try stepDone(statement)
    }

    /// Remove a node from the local identity without touching its history:
    /// the row stays as a transient (searchable, discoverable) and any
    /// conversation keeps working. Favorite and alias are local statements
    /// about a saved peer, so they clear with it. Refuses the
    /// companion radio, whose row is system-managed.
    func demotePeerToTransient(ownerIdentityID: String, publicAddress: String) throws {
        try transaction {
            let select = try prepare(
                """
                SELECT advertised_name FROM node
                WHERE owner_identity_id = ? AND public_address = ?
                    AND (system_role IS NULL OR system_role <> 'companion_radio')
                """
            )
            defer { sqlite3_finalize(select) }
            try bind(ownerIdentityID, to: select, at: 1)
            try bind(publicAddress, to: select, at: 2)
            guard sqlite3_step(select) == SQLITE_ROW else { return }
            let advertisedName = Self.optionalStringColumn(select, at: 0)

            let update = try prepare(
                """
                UPDATE node SET is_saved = 0, is_favorite = 0,
                    alias = NULL, alias_search = ?
                WHERE owner_identity_id = ? AND public_address = ?
                """
            )
            defer { sqlite3_finalize(update) }
            try bind(Self.normalizeSearch(advertisedName ?? ""), to: update, at: 1)
            try bind(ownerIdentityID, to: update, at: 2)
            try bind(publicAddress, to: update, at: 3)
            try stepDone(update)
        }
    }

    /// Delete a peer row outright. Refused — returning `false` — when a
    /// conversation references it (demote instead, or use
    /// ``deletePeerAndConversation``) or when the row is the system-managed
    /// companion radio. Stream checkpoints and counter state survive by
    /// design: sequence continuity and replay protection outlive the row.
    @discardableResult
    func deletePeer(ownerIdentityID: String, publicAddress: String) throws -> Bool {
        let statement = try prepare(
            """
            DELETE FROM node
            WHERE owner_identity_id = ?1 AND public_address = ?2
                AND (system_role IS NULL OR system_role <> 'companion_radio')
                AND id NOT IN (
                    SELECT node_id FROM direct_conversation WHERE owner_identity_id = ?1
                )
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(publicAddress, to: statement, at: 2)
        try stepDone(statement)
        return sqlite3_changes(database) > 0
    }

    /// Delete a peer together with its conversation and local history, in one
    /// transaction. Stream checkpoints are retained (see
    /// ``deleteDirectConversation``); the companion radio is refused.
    @discardableResult
    func deletePeerAndConversation(
        ownerIdentityID: String,
        publicAddress: String
    ) throws -> Bool {
        try transaction {
            let select = try prepare(
                """
                SELECT id FROM node
                WHERE owner_identity_id = ? AND public_address = ?
                    AND (system_role IS NULL OR system_role <> 'companion_radio')
                """
            )
            defer { sqlite3_finalize(select) }
            try bind(ownerIdentityID, to: select, at: 1)
            try bind(publicAddress, to: select, at: 2)
            guard sqlite3_step(select) == SQLITE_ROW else { return false }
            let nodeID = sqlite3_column_int64(select, 0)

            try purgeConversationHistory(
                ownerIdentityID: ownerIdentityID,
                conversationAddress: publicAddress
            )

            let conversation = try prepare(
                "DELETE FROM direct_conversation WHERE owner_identity_id = ? AND node_id = ?"
            )
            defer { sqlite3_finalize(conversation) }
            try bind(ownerIdentityID, to: conversation, at: 1)
            try check(sqlite3_bind_int64(conversation, 2, nodeID))
            try stepDone(conversation)

            let node = try prepare("DELETE FROM node WHERE id = ?")
            defer { sqlite3_finalize(node) }
            try check(sqlite3_bind_int64(node, 1, nodeID))
            try stepDone(node)
            return true
        }
    }

    /// Drop every transient row that nothing else depends on: saved peers,
    /// the companion radio, rows on the device identity, and rows with a
    /// conversation all stay.
    func clearTransientPeers(ownerIdentityID: String) throws {
        let statement = try prepare(
            """
            DELETE FROM node
            WHERE owner_identity_id = ?1 AND is_saved = 0 AND on_dev_identity = 0
                AND system_role IS NULL
                AND id NOT IN (
                    SELECT node_id FROM direct_conversation WHERE owner_identity_id = ?1
                )
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try stepDone(statement)
    }

    /// Keep the transient tier bounded: beyond `cap` rows, the oldest-heard
    /// evictable transients are dropped. Rows with a conversation, on the
    /// device identity, or with a system role are never evicted.
    func enforceTransientRetention(ownerIdentityID: String, cap: Int = 256) throws {
        let statement = try prepare(
            """
            DELETE FROM node WHERE id IN (
                SELECT id FROM node
                WHERE owner_identity_id = ?1 AND is_saved = 0 AND on_dev_identity = 0
                    AND system_role IS NULL
                    AND id NOT IN (
                        SELECT node_id FROM direct_conversation WHERE owner_identity_id = ?1
                    )
                ORDER BY last_heard_at DESC, id DESC
                LIMIT -1 OFFSET ?2
            )
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try check(sqlite3_bind_int64(statement, 2, Int64(cap)))
        try stepDone(statement)
    }

    /// Make the local cache of the radio's device-identity peer list match
    /// the device's read-back. The device is the authority: flags clear
    /// where it no longer holds a key, set where it does, and unknown keys
    /// gain a transient row carrying the flag so lists can show them.
    func reconcileDeviceIdentityPeers(ownerIdentityID: String, addresses: [String]) throws {
        try transaction {
            let clear = try prepare(
                """
                UPDATE node SET on_dev_identity = 0
                WHERE owner_identity_id = ? AND on_dev_identity = 1
                """
            )
            defer { sqlite3_finalize(clear) }
            try bind(ownerIdentityID, to: clear, at: 1)
            try stepDone(clear)
            for address in addresses {
                try markOnDeviceIdentity(ownerIdentityID: ownerIdentityID, publicAddress: address)
            }
        }
    }

    /// Cache one device-identity membership change after a confirmed radio
    /// mutation, without waiting for the next attach-edge reconcile.
    func setPeerOnDeviceIdentity(
        ownerIdentityID: String,
        publicAddress: String,
        isOnDeviceIdentity: Bool
    ) throws {
        if isOnDeviceIdentity {
            try markOnDeviceIdentity(ownerIdentityID: ownerIdentityID, publicAddress: publicAddress)
        } else {
            let statement = try prepare(
                """
                UPDATE node SET on_dev_identity = 0
                WHERE owner_identity_id = ? AND public_address = ?
                """
            )
            defer { sqlite3_finalize(statement) }
            try bind(ownerIdentityID, to: statement, at: 1)
            try bind(publicAddress, to: statement, at: 2)
            try stepDone(statement)
        }
    }

    /// Set the device-identity flag, creating a transient row when the key
    /// is not otherwise recorded on this phone.
    private func markOnDeviceIdentity(ownerIdentityID: String, publicAddress: String) throws {
        let statement = try prepare(
            """
            INSERT INTO node (owner_identity_id, public_address, alias_search, on_dev_identity)
            VALUES (?, ?, '', 1)
            ON CONFLICT(owner_identity_id, public_address) DO UPDATE SET on_dev_identity = 1
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(publicAddress, to: statement, at: 2)
        try stepDone(statement)
    }

    /// Record that we just heard from a peer by any means. No-ops when the
    /// peer is not yet saved locally — an unknown peer has no row to touch and
    /// needs no last-heard until it is added.
    func touchLastHeard(
        ownerIdentityID: String,
        publicAddress: String,
        at instant: Date
    ) throws {
        let statement = try prepare(
            """
            UPDATE node SET last_heard_at = ?
            WHERE owner_identity_id = ? AND public_address = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try check(sqlite3_bind_double(statement, 1, instant.timeIntervalSince1970))
        try bind(ownerIdentityID, to: statement, at: 2)
        try bind(publicAddress, to: statement, at: 3)
        try stepDone(statement)
    }

    /// Resolve the peer a locally-stored message belongs to, keyed by its
    /// durable `(sessionID, handle)`. Used to attribute delivery acks — which
    /// carry no address of their own — back to a conversation for last-heard
    /// bookkeeping.
    func conversationAddressForMessage(
        ownerIdentityID: String,
        sessionID: UInt64,
        handle: UInt32
    ) throws -> String? {
        let statement = try prepare(
            """
            SELECT conversation_address FROM chat_message
            WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        // session_id is stored as TEXT (the decimal UInt64), matching how
        // delivery fragments and message rows are written.
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(String(sessionID), to: statement, at: 2)
        try check(sqlite3_bind_int64(statement, 3, Int64(handle)))
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return Self.optionalStringColumn(statement, at: 0)
    }

    /// The persisted conversation address, sender, and body of an inbound,
    /// displayable message, for raising a notification. Returns `nil` for
    /// outbound rows, tombstones, gap placeholders, unavailable markers, or
    /// empty bodies — nothing worth alerting the user about. Resolves every
    /// field from storage so a notify carried on an `UpdateBody` (which omits
    /// them) still works.
    func chatNotificationTarget(
        ownerIdentityID: String,
        sessionID: UInt64,
        handle: UInt32
    ) throws -> ChatNotificationTarget? {
        let statement = try prepare(
            """
            SELECT conversation_address, body, sender_address, sender_hint, sender_handle
            FROM chat_message
            WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                AND direction = 0 AND deleted = 0 AND presence = 0 AND body <> ''
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(String(sessionID), to: statement, at: 2)
        try check(sqlite3_bind_int64(statement, 3, Int64(handle)))
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return ChatNotificationTarget(
            conversationAddress: Self.stringColumn(statement, at: 0),
            body: Self.stringColumn(statement, at: 1),
            senderAddress: Self.optionalStringColumn(statement, at: 2),
            senderHint: Self.optionalDataColumn(statement, at: 3),
            senderHandle: Self.optionalStringColumn(statement, at: 4)
        )
    }

    func upsertUlcpDevicePeer(
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
                isSaved: true,
                systemRole: "companion_radio",
                radioIdentifier: radioIdentifier
            )
        }
    }

    func listNodes(ownerIdentityID: String) throws -> [StoredNode] {
        let statement = try prepare(
            """
            SELECT id, owner_identity_id, public_address, alias, advertised_name,
                   system_role, node_kind, advertisement,
                   advertisement_authenticated, last_heard_at,
                   is_saved, is_favorite, on_dev_identity
            FROM node WHERE owner_identity_id = ?
            ORDER BY (system_role IS NOT NULL) DESC, alias_search, id
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
                   n.advertised_name, n.system_role, n.node_kind,
                   n.advertisement, n.advertisement_authenticated, n.last_heard_at,
                   n.is_saved, n.is_favorite, n.on_dev_identity,
                   c.draft_text, c.last_read_at_ms, c.created_at_ms
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
                        draftText: Self.stringColumn(statement, at: 14),
                        lastReadAtMilliseconds: sqlite3_column_int64(statement, 15),
                        createdAtMilliseconds: sqlite3_column_int64(statement, 16)
                    )
                )
            case SQLITE_DONE:
                return conversations
            case let code:
                throw ApplicationStoreError.sqliteFailure(code)
            }
        }
    }

    /// The channel conversation for a channel, created if this is the first
    /// time the user has entered it. Channels are joined without a chat; the
    /// conversation appears when someone asks for one, or when a message
    /// arrives.
    func ensureChannelConversation(
        ownerIdentityID: String,
        channelID: UUID,
        conversationAddress: String
    ) throws -> Int64 {
        let insert = try prepare(
            """
            INSERT OR IGNORE INTO channel_conversation (
                owner_identity_id, channel_id, conversation_address, created_at_ms
            ) VALUES (?, ?, ?, ?)
            """
        )
        defer { sqlite3_finalize(insert) }
        try bind(ownerIdentityID, to: insert, at: 1)
        try bind(channelID.uuidString, to: insert, at: 2)
        try bind(conversationAddress, to: insert, at: 3)
        try check(sqlite3_bind_int64(insert, 4, Self.nowMilliseconds()))
        try stepDone(insert)

        let select = try prepare(
            "SELECT id FROM channel_conversation WHERE owner_identity_id = ? AND channel_id = ?"
        )
        defer { sqlite3_finalize(select) }
        try bind(ownerIdentityID, to: select, at: 1)
        try bind(channelID.uuidString, to: select, at: 2)
        guard sqlite3_step(select) == SQLITE_ROW else {
            throw ApplicationStoreError.sqliteFailure(sqlite3_errcode(database))
        }
        return sqlite3_column_int64(select, 0)
    }

    func listChannelConversations(
        ownerIdentityID: String
    ) throws -> [StoredChannelConversation] {
        let statement = try prepare(
            """
            SELECT id, channel_id, conversation_address, draft_text, last_read_at_ms,
                   created_at_ms
            FROM channel_conversation WHERE owner_identity_id = ?
            ORDER BY created_at_ms DESC, id DESC
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        var conversations: [StoredChannelConversation] = []
        while true {
            switch sqlite3_step(statement) {
            case SQLITE_ROW:
                guard let channelID = UUID(uuidString: Self.stringColumn(statement, at: 1)) else {
                    continue
                }
                conversations.append(
                    StoredChannelConversation(
                        id: sqlite3_column_int64(statement, 0),
                        channelID: channelID,
                        conversationAddress: Self.stringColumn(statement, at: 2),
                        draftText: Self.stringColumn(statement, at: 3),
                        lastReadAtMilliseconds: sqlite3_column_int64(statement, 4),
                        createdAtMilliseconds: sqlite3_column_int64(statement, 5)
                    )
                )
            case SQLITE_DONE:
                return conversations
            case let code:
                throw ApplicationStoreError.sqliteFailure(code)
            }
        }
    }

    /// Remove a channel conversation and its local transcript. Leaving a group
    /// chat is not leaving the channel: the key stays, so traffic still
    /// arrives and a later message opens the conversation again.
    func deleteChannelConversation(ownerIdentityID: String, conversationID: Int64) throws {
        try transaction {
            let select = try prepare(
                """
                SELECT conversation_address FROM channel_conversation
                WHERE id = ? AND owner_identity_id = ?
                """
            )
            defer { sqlite3_finalize(select) }
            try check(sqlite3_bind_int64(select, 1, conversationID))
            try bind(ownerIdentityID, to: select, at: 2)
            guard sqlite3_step(select) == SQLITE_ROW else { return }
            let address = Self.stringColumn(select, at: 0)

            try purgeConversationHistory(
                ownerIdentityID: ownerIdentityID,
                conversationAddress: address
            )

            let delete = try prepare(
                "DELETE FROM channel_conversation WHERE id = ? AND owner_identity_id = ?"
            )
            defer { sqlite3_finalize(delete) }
            try check(sqlite3_bind_int64(delete, 1, conversationID))
            try bind(ownerIdentityID, to: delete, at: 2)
            try stepDone(delete)
        }
    }

    func updateChannelDraft(
        ownerIdentityID: String,
        conversationID: Int64,
        text: String
    ) throws {
        let statement = try prepare(
            "UPDATE channel_conversation SET draft_text = ? WHERE id = ? AND owner_identity_id = ?"
        )
        defer { sqlite3_finalize(statement) }
        try bind(text, to: statement, at: 1)
        try check(sqlite3_bind_int64(statement, 2, conversationID))
        try bind(ownerIdentityID, to: statement, at: 3)
        try stepDone(statement)
    }

    /// Mark everything in a conversation read as of now. Addressed rather than
    /// keyed by row so one call serves both kinds of conversation.
    func markConversationRead(ownerIdentityID: String, conversationAddress: String) throws {
        let now = Self.nowMilliseconds()
        let direct = try prepare(
            """
            UPDATE direct_conversation SET last_read_at_ms = ?
            WHERE owner_identity_id = ? AND node_id IN (
                SELECT id FROM node
                WHERE owner_identity_id = ? AND public_address = ?
            )
            """
        )
        defer { sqlite3_finalize(direct) }
        try check(sqlite3_bind_int64(direct, 1, now))
        try bind(ownerIdentityID, to: direct, at: 2)
        try bind(ownerIdentityID, to: direct, at: 3)
        try bind(conversationAddress, to: direct, at: 4)
        try stepDone(direct)

        let channel = try prepare(
            """
            UPDATE channel_conversation SET last_read_at_ms = ?
            WHERE owner_identity_id = ? AND conversation_address = ?
            """
        )
        defer { sqlite3_finalize(channel) }
        try check(sqlite3_bind_int64(channel, 1, now))
        try bind(ownerIdentityID, to: channel, at: 2)
        try bind(conversationAddress, to: channel, at: 3)
        try stepDone(channel)
    }

    /// Fill in the sender of group messages stored before that member's hint
    /// resolved to a real address. Rows that already name a sender are left
    /// alone — the first attribution seen for a hint is the one kept.
    func applySenderResolution(
        ownerIdentityID: String,
        conversationAddress: String,
        senderHint: Data,
        senderAddress: String
    ) throws {
        let statement = try prepare(
            """
            UPDATE chat_message SET sender_address = ?
            WHERE owner_identity_id = ? AND conversation_address = ?
                AND sender_hint = ? AND sender_address IS NULL
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(senderAddress, to: statement, at: 1)
        try bind(ownerIdentityID, to: statement, at: 2)
        try bind(conversationAddress, to: statement, at: 3)
        try bind(senderHint, to: statement, at: 4)
        try stepDone(statement)
    }

    /// Remove a conversation and its local history. Outbound stream
    /// checkpoints are deliberately retained: sequence continuity with the
    /// peer must survive the transcript, or the next message would announce
    /// a Sequence Reset. Archived outbound payloads go with the history, so
    /// a late resend request for them is answered Unavailable — the protocol
    /// handles that; keeping deleted content on disk would not be acceptable.
    func deleteDirectConversation(ownerIdentityID: String, conversationID: Int64) throws {
        try transaction {
            let peerSelect = """
                SELECT n.public_address FROM direct_conversation c
                JOIN node n ON n.id = c.node_id
                WHERE c.id = ? AND c.owner_identity_id = ?
                """
            let peer = try prepare(peerSelect)
            defer { sqlite3_finalize(peer) }
            try check(sqlite3_bind_int64(peer, 1, conversationID))
            try bind(ownerIdentityID, to: peer, at: 2)
            guard sqlite3_step(peer) == SQLITE_ROW else { return }
            let peerAddress = Self.stringColumn(peer, at: 0)

            try purgeConversationHistory(
                ownerIdentityID: ownerIdentityID,
                conversationAddress: peerAddress
            )

            let conversation = try prepare(
                "DELETE FROM direct_conversation WHERE id = ? AND owner_identity_id = ?"
            )
            defer { sqlite3_finalize(conversation) }
            try check(sqlite3_bind_int64(conversation, 1, conversationID))
            try bind(ownerIdentityID, to: conversation, at: 2)
            try stepDone(conversation)
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
            SELECT conversation_address, next_id, epoch FROM chat_stream_checkpoint
            WHERE owner_identity_id = ? ORDER BY updated_at_ms ASC, conversation_address ASC
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
                        conversationAddress: Self.stringColumn(statement, at: 0),
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
            // Retirements first: an edit's replacement payloads must land on a
            // clean slate so no stale fragment of the superseded content can
            // ever be served to a resend request.
            for delete in batch.archiveDeletes {
                try deleteChatArchive(ownerIdentityID: ownerIdentityID, delete)
            }
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
                        -- A positive ack is definitive proof the frame landed;
                        -- it supersedes an earlier transport failure so a
                        -- resent-and-acked fragment can recover from 'failed'.
                        WHEN chat_delivery_fragment.state = 'acknowledged'
                            OR excluded.state = 'acknowledged' THEN 'acknowledged'
                        WHEN chat_delivery_fragment.state = 'failed'
                            OR excluded.state = 'failed' THEN 'failed'
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

                // Every fragment acknowledged wins over any earlier failure, so
                // a resent-and-acked message recovers to 'acknowledged'. When
                // that recovery crosses from a previously 'failed' row, flag it
                // "delivered late". SQLite evaluates every SET right-hand side
                // against the pre-update row, so `delivery_state` below reads
                // the old value while the counts read the just-updated fragments.
                let message = try prepare(
                    """
                    UPDATE chat_message SET
                        delivered_late = CASE
                            WHEN chat_message.delivery_state = 'failed'
                                AND (
                                    SELECT COUNT(*) FROM chat_delivery_fragment f
                                    WHERE f.owner_identity_id = chat_message.owner_identity_id
                                        AND f.session_id = chat_message.session_id
                                        AND f.handle = chat_message.handle
                                        AND f.state = 'acknowledged'
                                ) >= COALESCE(chat_message.fragment_count, 1) THEN 1
                            ELSE chat_message.delivered_late
                        END,
                        delivery_state = CASE
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
                                AND f.handle = chat_message.handle AND f.state = 'failed'
                        ) THEN 'failed'
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

    /// Outbound messages still marked 'pending' at launch were composed by a
    /// previous process. Their in-flight transmissions died with that process
    /// and the replacement Rust session issues new session IDs, so no delivery
    /// evidence can ever arrive for them. Resolve them to 'failed' instead of
    /// promising a send that is no longer happening. Messages that reached
    /// 'sent' keep that state: they went on the air and may well have arrived.
    func failStalePendingMessages(ownerIdentityID: String) throws {
        let statement = try prepare(
            """
            UPDATE chat_message SET delivery_state = 'failed'
            WHERE owner_identity_id = ? AND direction = 1
                AND delivery_state = 'pending'
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try stepDone(statement)
    }

    func chatArchive(
        ownerIdentityID: String,
        lookup: MobileChatArchiveLookupRecord
    ) throws -> Data? {
        let statement = try prepare(
            """
            SELECT payload FROM chat_outbound_archive
            WHERE owner_identity_id = ? AND conversation_address = ?
                AND message_id = ? AND fragment_index = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(lookup.conversationAddress, to: statement, at: 2)
        try check(sqlite3_bind_int(statement, 3, Int32(lookup.messageId)))
        try check(sqlite3_bind_int(statement, 4, lookup.fragmentIndex.map(Int32.init) ?? -1))
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return Self.dataColumn(statement, at: 0)
    }

    func chatMessages(
        ownerIdentityID: String,
        conversationAddress: String
    ) throws -> [StoredChatMessage] {
        let statement = try prepare(
            """
            SELECT session_id, handle, body, direction, delivery_state, deleted, created_at_ms,
                   wire_id, epoch, edited, presence, received_late, delivered_late, original_body,
                   sender_address, sender_hint, sender_handle,
                   rx_rssi_dbm, rx_snr_cb, rx_lqi, rx_hop_count,
                   rx_route_hints, rx_source_authenticated
            FROM chat_message
            WHERE owner_identity_id = ? AND conversation_address = ?
            ORDER BY created_at_ms ASC, rowid ASC
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(conversationAddress, to: statement, at: 2)
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
                        createdAtMilliseconds: sqlite3_column_int64(statement, 6),
                        wireID: sqlite3_column_type(statement, 7) == SQLITE_NULL
                            ? nil : UInt8(truncatingIfNeeded: sqlite3_column_int64(statement, 7)),
                        epoch: sqlite3_column_type(statement, 8) == SQLITE_NULL
                            ? nil : UInt16(truncatingIfNeeded: sqlite3_column_int64(statement, 8)),
                        isEdited: sqlite3_column_int(statement, 9) != 0,
                        presence: Int(sqlite3_column_int64(statement, 10)),
                        receivedLate: sqlite3_column_int(statement, 11) != 0,
                        deliveredLate: sqlite3_column_int(statement, 12) != 0,
                        originalBody: Self.optionalStringColumn(statement, at: 13),
                        senderAddress: Self.optionalStringColumn(statement, at: 14),
                        senderHint: Self.optionalDataColumn(statement, at: 15),
                        senderHandle: Self.optionalStringColumn(statement, at: 16),
                        reception: Self.reception(statement, at: 17)
                    )
                )
            case SQLITE_DONE: return messages
            case let code: throw ApplicationStoreError.sqliteFailure(code)
            }
        }
    }

    /// Remove a conversation's message history, outbound archive, and
    /// delivery fragments. Runs inside a caller-held transaction; the
    /// conversation row itself is the caller's to delete.
    private func purgeConversationHistory(
        ownerIdentityID: String,
        conversationAddress: String
    ) throws {
        let fragments = try prepare(
            """
            DELETE FROM chat_delivery_fragment
            WHERE owner_identity_id = ? AND (session_id, handle) IN (
                SELECT session_id, handle FROM chat_message
                WHERE owner_identity_id = ? AND conversation_address = ?
            )
            """
        )
        defer { sqlite3_finalize(fragments) }
        try bind(ownerIdentityID, to: fragments, at: 1)
        try bind(ownerIdentityID, to: fragments, at: 2)
        try bind(conversationAddress, to: fragments, at: 3)
        try stepDone(fragments)

        for table in ["chat_message", "chat_outbound_archive"] {
            let statement = try prepare(
                "DELETE FROM \(table) WHERE owner_identity_id = ? AND conversation_address = ?"
            )
            defer { sqlite3_finalize(statement) }
            try bind(ownerIdentityID, to: statement, at: 1)
            try bind(conversationAddress, to: statement, at: 2)
            try stepDone(statement)
        }
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
            systemRole: Self.optionalStringColumn(statement, at: offset + 5),
            nodeKind: Self.optionalStringColumn(statement, at: offset + 6),
            advertisement: Self.optionalDataColumn(statement, at: offset + 7),
            advertisementAuthenticated: sqlite3_column_int(statement, offset + 8) != 0,
            lastHeardAt: Self.optionalDateColumn(statement, at: offset + 9),
            isSaved: sqlite3_column_int(statement, offset + 10) != 0,
            isFavorite: sqlite3_column_int(statement, offset + 11) != 0,
            onDeviceIdentity: sqlite3_column_int(statement, offset + 12) != 0
        )
    }

    private func upsertChatCheckpoint(
        ownerIdentityID: String,
        _ checkpoint: MobileChatCheckpointRecord
    ) throws {
        let statement = try prepare(
            """
            INSERT INTO chat_stream_checkpoint (
                owner_identity_id, conversation_address, next_id, epoch, updated_at_ms
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(owner_identity_id, conversation_address) DO UPDATE SET
                next_id = excluded.next_id,
                epoch = excluded.epoch,
                updated_at_ms = excluded.updated_at_ms
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(checkpoint.conversationAddress, to: statement, at: 2)
        try check(sqlite3_bind_int(statement, 3, Int32(checkpoint.nextId)))
        try check(sqlite3_bind_int(statement, 4, Int32(checkpoint.epoch)))
        try check(sqlite3_bind_int64(statement, 5, Self.nowMilliseconds()))
        try stepDone(statement)
    }

    /// Remove every archived fragment stored under one message ID (the
    /// unfragmented entry included): its content was superseded by an edit or
    /// retracted by a delete and must never be resent.
    private func deleteChatArchive(
        ownerIdentityID: String,
        _ delete: MobileChatArchiveDeleteRecord
    ) throws {
        let statement = try prepare(
            """
            DELETE FROM chat_outbound_archive
            WHERE owner_identity_id = ? AND conversation_address = ? AND message_id = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(delete.conversationAddress, to: statement, at: 2)
        try check(sqlite3_bind_int(statement, 3, Int32(delete.messageId)))
        try stepDone(statement)
    }

    private func upsertChatArchive(
        ownerIdentityID: String,
        _ archive: MobileChatArchiveRecord
    ) throws {
        let statement = try prepare(
            """
            INSERT INTO chat_outbound_archive (
                owner_identity_id, conversation_address, message_id, fragment_index, payload
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(owner_identity_id, conversation_address, message_id, fragment_index)
            DO UPDATE SET payload = excluded.payload
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(archive.conversationAddress, to: statement, at: 2)
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
            guard let peerAddress = mutation.conversationAddress,
                  let direction = mutation.direction,
                  let body = mutation.body
            else { return }
            let statement = try prepare(
                """
                INSERT INTO chat_message (
                    owner_identity_id, session_id, handle, conversation_address, sender_address,
                    direction, message_type, wire_id, epoch, client_token,
                    sender_handle, regarding_handle, background_color, text_color, body,
                    complete, present_fragments, fragment_count, finalized,
                    delivery_state, deleted, created_at_ms, presence, received_late,
                    sender_hint, rx_rssi_dbm, rx_snr_cb, rx_lqi, rx_hop_count,
                    rx_route_hints, rx_source_authenticated
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(owner_identity_id, session_id, handle) DO UPDATE SET
                    body = excluded.body,
                    complete = excluded.complete,
                    present_fragments = excluded.present_fragments,
                    fragment_count = excluded.fragment_count,
                    finalized = excluded.finalized,
                    message_type = excluded.message_type,
                    sender_handle = excluded.sender_handle,
                    background_color = excluded.background_color,
                    text_color = excluded.text_color,
                    presence = excluded.presence,
                    received_late = MAX(chat_message.received_late, excluded.received_late),
                    -- A placeholder filled in later carries the metadata of
                    -- the frame that filled it; keep whichever row has any.
                    sender_hint = COALESCE(excluded.sender_hint, chat_message.sender_hint),
                    rx_rssi_dbm = COALESCE(excluded.rx_rssi_dbm, chat_message.rx_rssi_dbm),
                    rx_snr_cb = COALESCE(excluded.rx_snr_cb, chat_message.rx_snr_cb),
                    rx_lqi = COALESCE(excluded.rx_lqi, chat_message.rx_lqi),
                    rx_hop_count = COALESCE(excluded.rx_hop_count, chat_message.rx_hop_count),
                    rx_route_hints =
                        COALESCE(excluded.rx_route_hints, chat_message.rx_route_hints),
                    rx_source_authenticated = COALESCE(
                        excluded.rx_source_authenticated, chat_message.rx_source_authenticated
                    )
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
            try check(sqlite3_bind_int(statement, 22, presenceCode(mutation.presence)))
            try check(sqlite3_bind_int(statement, 23, mutation.receivedLate ? 1 : 0))
            try bindOptional(mutation.senderHint.map { Data($0) }, to: statement, at: 24)
            try bindOptionalInt(mutation.rx?.rssiDbm.map(Int64.init), to: statement, at: 25)
            try bindOptionalInt(mutation.rx?.snrCentibels.map(Int64.init), to: statement, at: 26)
            try bindOptionalInt(mutation.rx?.lqi.map(Int64.init), to: statement, at: 27)
            try bindOptionalInt(mutation.rx?.hopCount.map(Int64.init), to: statement, at: 28)
            try bindOptional(mutation.rx.map { Self.packRouteHints($0.routeHints) },
                             to: statement, at: 29)
            try bindOptionalInt(
                mutation.rx.map { Int64($0.sourceAuthenticated ? 1 : 0) },
                to: statement,
                at: 30
            )
            try stepDone(statement)
        case .updateBody:
            guard let body = mutation.body else { return }
            // A fragment-completion or notify-deadline update can carry a late
            // flag; never clear an existing one, and leave presence untouched.
            let statement = try prepare(
                """
                UPDATE chat_message SET body = ?, complete = ?, present_fragments = ?,
                    fragment_count = ?, finalized = ?,
                    received_late = MAX(received_late, ?),
                    rx_rssi_dbm = COALESCE(?, rx_rssi_dbm),
                    rx_snr_cb = COALESCE(?, rx_snr_cb),
                    rx_lqi = COALESCE(?, rx_lqi),
                    rx_hop_count = COALESCE(?, rx_hop_count),
                    rx_route_hints = COALESCE(?, rx_route_hints),
                    rx_source_authenticated = COALESCE(?, rx_source_authenticated)
                WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                """
            )
            defer { sqlite3_finalize(statement) }
            try bind(body, to: statement, at: 1)
            try bindOptionalBool(mutation.complete, to: statement, at: 2)
            try bindOptionalInt(mutation.presentFragments.map(Int64.init), to: statement, at: 3)
            try bindOptionalInt(mutation.fragmentCount.map(Int64.init), to: statement, at: 4)
            try bindOptionalBool(mutation.finalized, to: statement, at: 5)
            try check(sqlite3_bind_int(statement, 6, mutation.receivedLate ? 1 : 0))
            try bindOptionalInt(mutation.rx?.rssiDbm.map(Int64.init), to: statement, at: 7)
            try bindOptionalInt(mutation.rx?.snrCentibels.map(Int64.init), to: statement, at: 8)
            try bindOptionalInt(mutation.rx?.lqi.map(Int64.init), to: statement, at: 9)
            try bindOptionalInt(mutation.rx?.hopCount.map(Int64.init), to: statement, at: 10)
            try bindOptional(mutation.rx.map { Self.packRouteHints($0.routeHints) },
                             to: statement, at: 11)
            try bindOptionalInt(
                mutation.rx.map { Int64($0.sourceAuthenticated ? 1 : 0) },
                to: statement,
                at: 12
            )
            try bind(ownerIdentityID, to: statement, at: 13)
            try bind(sessionID, to: statement, at: 14)
            try check(sqlite3_bind_int64(statement, 15, Int64(mutation.handle)))
            try stepDone(statement)
        case .edit, .delete:
            let body = mutation.kind == .delete ? "" : (mutation.body ?? "")
            let deleted: Int32 = mutation.kind == .delete ? 1 : 0
            let markEdited: Int32 = mutation.kind == .edit ? 1 : 0
            if let original = mutation.originalHandle {
                // The first edit of the sender's own message captures its
                // pre-edit text (`body` on the right-hand side reads the
                // pre-update row) so the sender can still review it; the
                // resend archive only ever holds the edited content.
                let statement = try prepare(
                    """
                    UPDATE chat_message SET
                        original_body = CASE WHEN ? = 1 AND direction = 1
                            THEN COALESCE(original_body, body)
                            ELSE original_body END,
                        body = ?, deleted = ?,
                        edited = MAX(edited, ?)
                    WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                    """
                )
                defer { sqlite3_finalize(statement) }
                try check(sqlite3_bind_int(statement, 1, markEdited))
                try bind(body, to: statement, at: 2)
                try check(sqlite3_bind_int(statement, 3, deleted))
                try check(sqlite3_bind_int(statement, 4, markEdited))
                try bind(ownerIdentityID, to: statement, at: 5)
                try bind(sessionID, to: statement, at: 6)
                try check(sqlite3_bind_int64(statement, 7, Int64(original)))
                try stepDone(statement)
            } else if let wireID = mutation.originalWireId,
                      let direction = mutation.originalDirection,
                      let peerAddress = mutation.conversationAddress {
                // The original predates the current facade session, so the
                // engine exported its wire reference instead of a handle.
                // Wire IDs recycle serially within a stream; the newest
                // epoch/row with that ID is the one still referenceable.
                let statement = try prepare(
                    """
                    UPDATE chat_message SET
                        original_body = CASE WHEN ? = 1 AND direction = 1
                            THEN COALESCE(original_body, body)
                            ELSE original_body END,
                        body = ?, deleted = ?,
                        edited = MAX(edited, ?)
                    WHERE rowid = (
                        SELECT rowid FROM chat_message
                        WHERE owner_identity_id = ? AND conversation_address = ?
                            AND direction = ? AND wire_id = ?
                        ORDER BY epoch DESC, created_at_ms DESC, rowid DESC
                        LIMIT 1
                    )
                    """
                )
                defer { sqlite3_finalize(statement) }
                try check(sqlite3_bind_int(statement, 1, markEdited))
                try bind(body, to: statement, at: 2)
                try check(sqlite3_bind_int(statement, 3, deleted))
                try check(sqlite3_bind_int(statement, 4, markEdited))
                try bind(ownerIdentityID, to: statement, at: 5)
                try bind(peerAddress, to: statement, at: 6)
                try check(sqlite3_bind_int(statement, 7, direction == .outbound ? 1 : 0))
                try check(sqlite3_bind_int(statement, 8, Int32(wireID)))
                try stepDone(statement)
            }
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

        if version < 5 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                try execute(
                    database,
                    sql: """
                    ALTER TABLE chat_message ADD COLUMN edited INTEGER NOT NULL DEFAULT 0;
                    PRAGMA user_version = 5;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 6 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                try execute(
                    database,
                    sql: """
                    ALTER TABLE node ADD COLUMN advertisement BLOB;
                    PRAGMA user_version = 6;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 7 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                try execute(
                    database,
                    sql: """
                    ALTER TABLE local_identity ADD COLUMN advertised_name TEXT;
                    PRAGMA user_version = 7;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 8 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                try execute(
                    database,
                    sql: """
                    ALTER TABLE node ADD COLUMN last_heard_at REAL;
                    PRAGMA user_version = 8;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 9 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                // Ordered-repair transcript metadata: `presence` marks a row as
                // a real message (0), a reserved gap placeholder (1), or a
                // permanent loss marker (2); `received_late` flags a backfill
                // that filled its slot out of order.
                try execute(
                    database,
                    sql: """
                    ALTER TABLE chat_message ADD COLUMN presence INTEGER NOT NULL DEFAULT 0;
                    ALTER TABLE chat_message ADD COLUMN received_late INTEGER NOT NULL DEFAULT 0;
                    PRAGMA user_version = 9;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 10 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                // An outbound message that failed transport but was later
                // acknowledged via a resend is "Delivered Late".
                try execute(
                    database,
                    sql: """
                    ALTER TABLE chat_message ADD COLUMN delivered_late INTEGER NOT NULL DEFAULT 0;
                    PRAGMA user_version = 10;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 11 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                // An edited outbound message keeps its pre-edit text here so
                // the sender can still review what the original said. Only the
                // first edit captures it; the wire archive holds edited
                // content only and can never serve the original again.
                try execute(
                    database,
                    sql: """
                    ALTER TABLE chat_message ADD COLUMN original_body TEXT;
                    PRAGMA user_version = 11;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 12 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                // Whether the MAC authenticated the frame that delivered the
                // stored advertisement. A bundle's own signature is recoverable
                // from the payload at any time; how it *arrived* is not, and an
                // Identity Request reply is a MIC-authenticated unicast that
                // deliberately carries no signature. Without this, such a reply
                // is indistinguishable on reload from an unsigned broadcast
                // anyone could have sent. Existing rows default to 0: we have
                // no record either way, which is what the old display assumed.
                try execute(
                    database,
                    sql: """
                    ALTER TABLE node
                        ADD COLUMN advertisement_authenticated INTEGER NOT NULL DEFAULT 0;
                    PRAGMA user_version = 12;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 13 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                // The peer tier model: `is_saved` marks a node stored on the
                // local (phone) identity; rows with 0 are the transient tier —
                // heard on the air, kept for search/discovery, hidden from the
                // main list, and evicted by retention. `on_dev_identity` caches
                // whether the node's key is on the companion radio's device
                // identity (PROP_DEV_PEERS); the device is the authority.
                // Every pre-existing row was visible in Peers, so all of
                // them upgrade as saved — nothing may vanish from the list.
                try execute(
                    database,
                    sql: """
                    ALTER TABLE node ADD COLUMN is_saved INTEGER NOT NULL DEFAULT 0;
                    ALTER TABLE node ADD COLUMN is_favorite INTEGER NOT NULL DEFAULT 0;
                    ALTER TABLE node ADD COLUMN on_dev_identity INTEGER NOT NULL DEFAULT 0;
                    UPDATE node SET is_saved = 1;
                    CREATE INDEX node_owner_transient_heard_idx
                        ON node (owner_identity_id, is_saved, last_heard_at);
                    PRAGMA user_version = 13;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 14 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                // `is_contact` distinguished two kinds of saved node and did
                // nothing else: same storage, same messaging, same retention,
                // one section header apart. Favorites says "peers I care
                // about" and can be changed at any time, which is what the
                // flag was reaching for. Contacts stay saved nodes; the flag
                // is not promoted to a favorite, because it defaulted on at
                // import and would star nearly everything.
                try execute(
                    database,
                    sql: """
                    ALTER TABLE node DROP COLUMN is_contact;
                    PRAGMA user_version = 14;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 15 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                // Channel membership. The row is public metadata; the 32-byte
                // key it describes lives in Keychain under `id`.
                //
                // `channel_id_hex` is the two-octet derived identifier, which
                // is a routing hint and NOT unique — distinct keys may collide
                // and receivers resolve that by trial decryption — so it
                // cannot key the table. `key_digest` can: it is a one-way
                // commitment to the key that makes "already joined" and "same
                // name, different key" answerable in SQL, without which an
                // import would have to unlock every stored key to compare.
                try execute(
                    database,
                    sql: """
                    CREATE TABLE channel (
                        id TEXT PRIMARY KEY NOT NULL,
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        kind TEXT NOT NULL,
                        canonical_name TEXT,
                        name TEXT,
                        alias TEXT,
                        channel_id_hex TEXT NOT NULL,
                        tint BLOB NOT NULL,
                        key_digest TEXT NOT NULL,
                        region_code BLOB,
                        max_flood_hops INTEGER,
                        joined_phone INTEGER NOT NULL DEFAULT 0,
                        joined_device INTEGER NOT NULL DEFAULT 0,
                        notifications_enabled INTEGER NOT NULL DEFAULT 0,
                        created_at_ms INTEGER NOT NULL,
                        joined_at_ms INTEGER,
                        UNIQUE (owner_identity_id, key_digest)
                    );

                    CREATE INDEX channel_owner_idx ON channel (owner_identity_id, id);

                    PRAGMA user_version = 15;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 16 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                // Chat is no longer only between two peers, so the column that
                // identified a transcript's other end is renamed to what it
                // actually holds: a conversation address, which is a peer's
                // address for a direct chat and a channel tag for a group.
                // The facade emits exactly this string, so the rename keeps
                // one vocabulary from the engine to the table.
                //
                // Channel messages also carry what a multicast frame carries
                // and a unicast does not — a claimed sender hint — plus the
                // radio metadata of the frame each message arrived on, which
                // the transcript can now show per message.
                try execute(
                    database,
                    sql: """
                    ALTER TABLE chat_message RENAME COLUMN peer_address TO conversation_address;
                    ALTER TABLE chat_stream_checkpoint
                        RENAME COLUMN peer_address TO conversation_address;
                    ALTER TABLE chat_outbound_archive
                        RENAME COLUMN peer_address TO conversation_address;

                    ALTER TABLE chat_message ADD COLUMN sender_hint BLOB;
                    ALTER TABLE chat_message ADD COLUMN rx_rssi_dbm INTEGER;
                    ALTER TABLE chat_message ADD COLUMN rx_snr_cb INTEGER;
                    ALTER TABLE chat_message ADD COLUMN rx_lqi INTEGER;
                    ALTER TABLE chat_message ADD COLUMN rx_hop_count INTEGER;
                    ALTER TABLE chat_message ADD COLUMN rx_route_hints BLOB;
                    ALTER TABLE chat_message ADD COLUMN rx_source_authenticated INTEGER;

                    -- Read cursors. Everything created before this migration
                    -- counts as read: an install that predates unread counts
                    -- should not open to a wall of unread badges.
                    ALTER TABLE direct_conversation
                        ADD COLUMN last_read_at_ms INTEGER NOT NULL DEFAULT 0;
                    UPDATE direct_conversation
                        SET last_read_at_ms = (
                            SELECT COALESCE(MAX(m.created_at_ms), 0) FROM chat_message m
                            JOIN node n ON n.public_address = m.conversation_address
                            WHERE m.owner_identity_id = direct_conversation.owner_identity_id
                              AND n.id = direct_conversation.node_id
                        );

                    -- A channel's group conversation. Separate from
                    -- `direct_conversation` because its other end is a channel
                    -- rather than a node, and `node_id` there is a hard
                    -- reference that cannot be made to mean both.
                    CREATE TABLE channel_conversation (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        owner_identity_id TEXT NOT NULL
                            REFERENCES local_identity(id) ON DELETE CASCADE,
                        channel_id TEXT NOT NULL REFERENCES channel(id) ON DELETE CASCADE,
                        conversation_address TEXT NOT NULL,
                        draft_text TEXT NOT NULL DEFAULT '',
                        created_at_ms INTEGER NOT NULL,
                        last_read_at_ms INTEGER NOT NULL DEFAULT 0,
                        UNIQUE (owner_identity_id, channel_id)
                    );

                    CREATE INDEX channel_conversation_address_idx
                        ON channel_conversation (owner_identity_id, conversation_address);

                    PRAGMA user_version = 16;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        // Every migration above has run, so the database must now sit exactly
        // at the version this build claims to support. A mismatch means a
        // migration stamped a `user_version` the constant was not raised to
        // match, which is invisible on the run that applies it and fatal on
        // every run after. Fail here, while the mistake is still one commit old.
        let applied = try readSchemaVersion(database)
        guard applied == currentSchemaVersion else {
            throw ApplicationStoreError.schemaVersionMismatch(
                applied: applied,
                expected: currentSchemaVersion
            )
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

    /// The radio metadata columns, when the row has any. Presence of the
    /// authentication flag is what distinguishes "no frame recorded" from a
    /// frame that simply reported no signal figures.
    private static func reception(
        _ statement: OpaquePointer,
        at offset: Int32
    ) -> StoredMessageReception? {
        guard sqlite3_column_type(statement, offset + 5) != SQLITE_NULL else { return nil }
        return StoredMessageReception(
            rssiDbm: optionalIntColumn(statement, at: offset).map(Int.init),
            snrCentibels: optionalIntColumn(statement, at: offset + 1).map(Int.init),
            lqi: optionalIntColumn(statement, at: offset + 2).map(Int.init),
            hopCount: optionalIntColumn(statement, at: offset + 3).map(Int.init),
            routeHints: unpackRouteHints(optionalDataColumn(statement, at: offset + 4)),
            sourceAuthenticated: sqlite3_column_int(statement, offset + 5) != 0
        )
    }

    /// Route hints are fixed-width and ordered, so they store as one blob
    /// rather than a table of their own.
    private static func packRouteHints(_ hints: [Data]) -> Data {
        hints.reduce(into: Data()) { packed, hint in packed.append(hint) }
    }

    static func unpackRouteHints(_ packed: Data?) -> [Data] {
        guard let packed, !packed.isEmpty else { return [] }
        return stride(from: 0, to: packed.count - packed.count % 2, by: 2).map { offset in
            packed.subdata(in: offset..<(offset + 2))
        }
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

    private static func optionalDataColumn(
        _ statement: OpaquePointer,
        at index: Int32
    ) -> Data? {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL else { return nil }
        return dataColumn(statement, at: index)
    }

    private static func optionalIntColumn(
        _ statement: OpaquePointer,
        at index: Int32
    ) -> Int64? {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL else { return nil }
        return sqlite3_column_int64(statement, index)
    }

    /// Read a REAL column holding a Unix-epoch-seconds instant.
    private static func optionalDateColumn(
        _ statement: OpaquePointer,
        at index: Int32
    ) -> Date? {
        guard sqlite3_column_type(statement, index) != SQLITE_NULL else { return nil }
        return Date(timeIntervalSince1970: sqlite3_column_double(statement, index))
    }

    private static let sqliteTransient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
}
