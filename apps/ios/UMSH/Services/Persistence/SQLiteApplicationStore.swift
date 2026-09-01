import Foundation
import SQLite3
import UMSHMobileCore

enum ApplicationStoreError: Error, Equatable, Sendable {
    case applicationSupportUnavailable
    case openFailed(Int32)
    /// A result code plus SQLite's own account of it. The code alone says only
    /// that something was refused; the message names the column, table or
    /// constraint, which is the difference between a usable report and a guess.
    case sqliteFailure(Int32, message: String)
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
        case .sqliteFailure(let code, let message):
            "SQLite returned code \(code): \(message)."
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
    /// Whether a one-shot watch is armed on this node: tell the user the
    /// next time anything is heard from it, then disarm. Cleared by the same
    /// write that records the hearing, so the notice fires exactly once.
    let notifyWhenHeard: Bool
}

/// What a remote device said it is, kept between openings of its settings.
///
/// The four things worth learning once: a device's capabilities and firmware
/// version change only when it is reflashed, its hardware never, and its name
/// rarely. Holding them means the second and every later open of a device's
/// settings puts nothing on the air at all — which over five flood hops is
/// the difference between instant and half a minute of everyone's airtime.
struct StoredManagementCard: Equatable, Sendable {
    /// `PROP_CAPS` verbatim, planned against without asking the device
    /// again.
    let capabilities: Data
    /// `PROP_DEV_VERSION`. The key the cached values hang from: different
    /// firmware may hold different properties, so a change here discards
    /// them.
    let deviceVersion: String?
    let deviceModel: String?
    let deviceName: String?
    let fetchedAt: Date
}

/// One property as a device last reported it, and when.
///
/// Stored as the octets that came off the air: what they mean is settled by
/// the ULCP decoders rather than here, so a value cached by one build reads
/// the same in the next. The instant is what lets a screen date a reading
/// rather than present it as current.
struct StoredCachedProperty: Equatable, Sendable {
    let value: Data
    let fetchedAt: Date
}

/// The newest message in a conversation, reduced to what a list row draws.
///
/// This is the literal last row in transcript order, tombstones and gap
/// placeholders included: a list preview says what the bottom of the transcript
/// is, and a deleted last message reads as "Message deleted" rather than
/// silently promoting the one before it.
struct StoredConversationPreview: Equatable, Sendable {
    let createdAtMilliseconds: Int64
    let body: String
    let isOutbound: Bool
    let isDeleted: Bool
    /// Who sent it, for a group conversation: the resolved address once known,
    /// and the hint the wire always carries.
    let senderAddress: String?
    let senderHint: Data?
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
    /// Whether this conversation may raise a notification. Defaults on,
    /// unlike a channel's, which defaults off.
    let notificationsEnabled: Bool
    let lastMessage: StoredConversationPreview?
    let unreadCount: Int
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
    let lastMessage: StoredConversationPreview?
    let unreadCount: Int
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

/// An inbound reaction worth telling the user about: who put what on which
/// message of theirs.
struct ChatReactionNotificationTarget: Equatable, Sendable {
    let conversationAddress: String
    /// The reaction body as it arrived — a wire token like `<3`, rendered to
    /// a glyph for display.
    let body: String
    /// What the reaction is on, so the notice can quote it the way a chat app
    /// quotes the message a tapback landed on.
    let targetBody: String
    let senderAddress: String?
    let senderHint: Data?
    let senderHandle: String?
}

/// An outbound message whose delivery has just been given up on.
struct ChatDeliveryFailure: Equatable, Sendable {
    let conversationAddress: String
    let body: String
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
    /// here so a list can color its rows without unlocking every key.
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
    /// The row's SQLite rowid, which with `createdAtMilliseconds` forms this
    /// message's keyset cursor. Ordering key only — `(sessionID, handle)`
    /// remains the durable identity.
    let rowID: Int64
    /// Reactions about this message, at most one per sender, oldest first.
    /// Folded at read time from the emote rows that name it — they are
    /// messages in their own right, but never transcript rows.
    var reactions: [StoredMessageReaction] = []

    var isGapPlaceholder: Bool { presence == 1 }
    var isUnavailable: Bool { presence == 2 }

    var cursor: ChatMessageCursor {
        ChatMessageCursor(createdAtMilliseconds: createdAtMilliseconds, rowID: rowID)
    }
}

/// Where one message sits in its conversation's storage order.
///
/// `(created_at_ms, rowid)` is exactly the transcript's ORDER BY, so a cursor
/// names a row rather than an offset: a page boundary stays put when older
/// messages are repaired in behind it. The rowid half is load-bearing rather
/// than defensive — a mutation batch is stamped from one clock read, so several
/// messages sharing a millisecond is the normal case, not an edge one.
///
/// Rowids are reused after a transcript is cleared, so two messages in the same
/// conversation and the same millisecond straddling a clear could in principle
/// compare in storage order rather than arrival order. The transcript's ORDER BY
/// has always been ambiguous in exactly that case; the cursor inherits it rather
/// than introducing it.
struct ChatMessageCursor: Hashable, Sendable, Comparable {
    let createdAtMilliseconds: Int64
    let rowID: Int64

    static func < (lhs: ChatMessageCursor, rhs: ChatMessageCursor) -> Bool {
        lhs.createdAtMilliseconds == rhs.createdAtMilliseconds
            ? lhs.rowID < rhs.rowID
            : lhs.createdAtMilliseconds < rhs.createdAtMilliseconds
    }
}

/// One loaded slice of a transcript, oldest first — the order it renders in.
/// The flags describe what storage holds beyond the slice, so a reader knows
/// whether there is more to page toward in either direction.
struct StoredChatMessagePage: Equatable, Sendable {
    let messages: [StoredChatMessage]
    let hasOlder: Bool
    let hasNewer: Bool

    static let empty = StoredChatMessagePage(messages: [], hasOlder: false, hasNewer: false)
}

/// One person's reaction to one message.
///
/// Carries its own durable identity because it is a message: the sender may
/// replace it, and an outbound one is delivered and acknowledged like
/// anything else, which is what lets the transcript show a reaction that has
/// not reached anyone yet.
struct StoredMessageReaction: Hashable, Sendable {
    /// The emote body as it arrived — a short token, not necessarily an
    /// emoji. Presentation normalizes it.
    let body: String
    let outbound: Bool
    let senderAddress: String?
    let senderHint: Data?
    let sessionID: String
    let handle: UInt32
    let wireID: UInt8?
    let epoch: UInt16?
    let createdAtMilliseconds: Int64
    let deliveryState: String?
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

#if DEBUG
/// One message a staged transcript is to contain, stated outright.
///
/// Everything a real message derives from the wire is dictated here instead,
/// because the point of a staged transcript is that it reads a particular way:
/// who said what, when, and what it looked like arriving.
struct StagedMessage {
    let handle: UInt32
    let body: String
    let outbound: Bool
    let createdAt: Date
    /// Who sent it, for a channel message. Nil in a direct conversation,
    /// where the conversation address already answers it.
    var senderAddress: String? = nil
    var senderHint: Data? = nil
    /// The name the sender put in the message itself, as a group message
    /// carries it.
    var senderHandle: String? = nil
    /// `acknowledged`, `sent`, `failed`, or nil. Outbound messages only.
    var deliveryState: String? = nil
    var reception: StoredMessageReception? = nil
    var reactions: [StagedReaction] = []
}

/// One reaction about a ``StagedMessage``. Its handle is allocated by the
/// writer, since nothing outside refers to a reaction by name.
struct StagedReaction {
    let body: String
    let outbound: Bool
    let createdAt: Date
    var senderAddress: String? = nil
    var senderHint: Data? = nil
}
#endif

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
    static let currentSchemaVersion: Int32 = 21

    nonisolated(unsafe) private let database: OpaquePointer

    static func applicationStore(fileManager: FileManager = .default) throws -> SQLiteApplicationStore {
        try SQLiteApplicationStore(
            path: storeURL(named: "Application", fileManager: fileManager).path
        )
    }

    /// Where a named store file lives. One statement of the directory, so the
    /// staging store below cannot drift away from the real one's location.
    static func storeURL(
        named name: String,
        fileManager: FileManager = .default
    ) throws -> URL {
        guard let applicationSupport = fileManager.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            throw ApplicationStoreError.applicationSupportUnavailable
        }
        let directory = applicationSupport.appendingPathComponent("UMSH", isDirectory: true)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory.appendingPathComponent("\(name).sqlite")
    }

    #if DEBUG
    /// The store staging mode fills, kept in its own file.
    ///
    /// A separate database is the whole safety argument for staging: seeding
    /// writes fabricated peers and transcripts, and pointing that at
    /// `Application.sqlite` would mix invented history into a real account with
    /// no way to tell the two apart afterwards. Switching staging off is then
    /// just a matter of opening the other file, and discarding a staged set is
    /// deleting this one.
    static func stagingStore(fileManager: FileManager = .default) throws -> SQLiteApplicationStore {
        try SQLiteApplicationStore(
            path: storeURL(named: "Staging", fileManager: fileManager).path
        )
    }

    /// Throw away the staged set, by emptying the staging database rather than
    /// deleting it. Nothing here can touch the real store: the name is fixed.
    ///
    /// Content and not the file, because nothing can know how many connections
    /// a running app holds on that file: the app opens one per root and closes
    /// them when ARC gets to it, so unlinking races them by construction, and
    /// SQLite treats a file unlinked under an open connection as a corrupted
    /// database rather than a missing one. Rows are the level SQLite is happy
    /// to have several connections agree about.
    static func eraseStagingStore(fileManager: FileManager = .default) async throws {
        try await stagingStore(fileManager: fileManager).eraseAllContent()
    }
    #endif

    /// Delete every row in every table, leaving the schema and its stamped
    /// version in place so the next open has nothing to migrate.
    ///
    /// Not staging tooling, though staging discards go through it too: this
    /// is what identity erasure uses to take the real store down with the
    /// key, so it must exist in every configuration.
    func eraseAllContent() throws {
        let tables = try tableNames()
        try transaction {
            // Which order the tables empty in is not something this has to
            // know: deferring the checks to the commit means the only state
            // foreign keys are tested against is the final one, where every
            // table is empty and nothing can dangle.
            try Self.execute(database, sql: "PRAGMA defer_foreign_keys = ON")
            for table in tables {
                try Self.execute(database, sql: "DELETE FROM \"\(table)\"")
            }
        }
    }

    /// The database's own tables, read from the schema rather than listed here
    /// so a migration that adds one cannot leave a reset quietly incomplete.
    private func tableNames() throws -> [String] {
        let statement = try prepare(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        )
        defer { sqlite3_finalize(statement) }
        var names: [String] = []
        while sqlite3_step(statement) == SQLITE_ROW {
            names.append(Self.stringColumn(statement, at: 0))
        }
        return names
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

    /// Whether this store already holds records for the given identity.
    ///
    /// Asked when a Keychain identity turns up with no anchor beside it: a
    /// container that still has this identity's row is that identity's
    /// container, anchor or no anchor, and there is nothing to ask about.
    /// The legacy `'primary'` slot counts, since a store written before the
    /// address became the key is still this identity's store.
    func knowsIdentity(id: String, publicAddress: String) throws -> Bool {
        let statement = try prepare(
            """
            SELECT 1 FROM local_identity
            WHERE id = ? OR (id = 'primary' AND public_address = ?)
            LIMIT 1
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(id, to: statement, at: 1)
        try bind(publicAddress, to: statement, at: 2)
        return sqlite3_step(statement) == SQLITE_ROW
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
    /// the companion radio, rows on the device identity, rows with a
    /// conversation, and rows carrying a pending watch all stay.
    func clearTransientPeers(ownerIdentityID: String) throws {
        let statement = try prepare(
            """
            DELETE FROM node
            WHERE owner_identity_id = ?1 AND is_saved = 0 AND on_dev_identity = 0
                AND system_role IS NULL AND notify_when_heard = 0
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
    /// device identity, with a system role, or carrying a pending watch are
    /// never evicted — a watch that the cap quietly deleted would be a
    /// promise the app stopped keeping without saying so.
    func enforceTransientRetention(ownerIdentityID: String, cap: Int = 256) throws {
        let statement = try prepare(
            """
            DELETE FROM node WHERE id IN (
                SELECT id FROM node
                WHERE owner_identity_id = ?1 AND is_saved = 0 AND on_dev_identity = 0
                    AND system_role IS NULL AND notify_when_heard = 0
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

    /// Arm or disarm the one-shot "tell me the next time this node is heard"
    /// watch. Unlike favoriting, this does not save a transient node: the
    /// retention queries exempt armed rows instead, so asking to be told
    /// about a node is not the same as deciding to keep it.
    func setNotifyWhenHeard(
        ownerIdentityID: String,
        publicAddress: String,
        enabled: Bool
    ) throws {
        let statement = try prepare(
            """
            UPDATE node SET notify_when_heard = ?
            WHERE owner_identity_id = ? AND public_address = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try check(sqlite3_bind_int(statement, 1, enabled ? 1 : 0))
        try bind(ownerIdentityID, to: statement, at: 2)
        try bind(publicAddress, to: statement, at: 3)
        try stepDone(statement)
    }

    /// Record that we just heard from a peer by any means. No-ops when the
    /// peer is not yet saved locally — an unknown peer has no row to touch and
    /// needs no last-heard until it is added.
    ///
    /// Returns whether this call is the one that disarmed a pending watch,
    /// which is the caller's cue to post the notice. The disarm is its own
    /// conditional write, so two hearings racing through the store cannot
    /// both come away believing they were first.
    @discardableResult
    func touchLastHeard(
        ownerIdentityID: String,
        publicAddress: String,
        at instant: Date
    ) throws -> Bool {
        let disarm = try prepare(
            """
            UPDATE node SET notify_when_heard = 0
            WHERE owner_identity_id = ? AND public_address = ? AND notify_when_heard = 1
            """
        )
        defer { sqlite3_finalize(disarm) }
        try bind(ownerIdentityID, to: disarm, at: 1)
        try bind(publicAddress, to: disarm, at: 2)
        try stepDone(disarm)
        let firedWatch = sqlite3_changes(database) > 0

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
        return firedWatch
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
                AND is_reaction = 0
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

    /// The reaction behind a notifying mutation, when it is one and when it
    /// lands on a message this phone sent.
    ///
    /// Reactions to someone else's message are somebody else's business: in a
    /// channel they would ping every member for every tapback. A withdrawal
    /// carries an empty body and is not an event to announce.
    func chatReactionNotificationTarget(
        ownerIdentityID: String,
        sessionID: UInt64,
        handle: UInt32
    ) throws -> ChatReactionNotificationTarget? {
        let statement = try prepare(
            """
            SELECT r.conversation_address, r.body, target.body,
                r.sender_address, r.sender_hint, r.sender_handle
            FROM chat_message r
            JOIN chat_message target
                ON target.owner_identity_id = r.owner_identity_id
                AND target.session_id = r.reaction_target_session_id
                AND target.handle = r.reaction_target_handle
            WHERE r.owner_identity_id = ? AND r.session_id = ? AND r.handle = ?
                AND r.direction = 0 AND r.deleted = 0 AND r.is_reaction = 1
                AND r.body <> ''
                AND target.direction = 1 AND target.deleted = 0
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(String(sessionID), to: statement, at: 2)
        try check(sqlite3_bind_int64(statement, 3, Int64(handle)))
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return ChatReactionNotificationTarget(
            conversationAddress: Self.stringColumn(statement, at: 0),
            body: Self.stringColumn(statement, at: 1),
            targetBody: Self.stringColumn(statement, at: 2),
            senderAddress: Self.optionalStringColumn(statement, at: 3),
            senderHint: Self.optionalDataColumn(statement, at: 4),
            senderHandle: Self.optionalStringColumn(statement, at: 5)
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

    // MARK: - Remote management cache

    /// What a device last said it is, if this phone has ever asked.
    func managementCard(
        ownerIdentityID: String,
        publicAddress: String
    ) throws -> StoredManagementCard? {
        let statement = try prepare(
            """
            SELECT c.capabilities, c.device_version, c.device_model, c.device_name,
                   c.fetched_at_ms
            FROM node_mgmt_card c JOIN node n ON n.id = c.node_id
            WHERE n.owner_identity_id = ? AND n.public_address = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(publicAddress, to: statement, at: 2)
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return StoredManagementCard(
            capabilities: Self.dataColumn(statement, at: 0),
            deviceVersion: Self.optionalStringColumn(statement, at: 1),
            deviceModel: Self.optionalStringColumn(statement, at: 2),
            deviceName: Self.optionalStringColumn(statement, at: 3),
            fetchedAt: Date(timeIntervalSince1970: Double(sqlite3_column_int64(statement, 4)) / 1000)
        )
    }

    /// Record what a card read found.
    ///
    /// A device running different firmware is a device whose capabilities,
    /// property set, and defaults may all have moved, so everything cached
    /// about the old firmware is dropped in the same transaction. Nothing
    /// about a cached value says which firmware produced it, and a value
    /// that outlives its firmware is worse than no value: it prefills a
    /// form with a plausible reading nobody can date.
    func saveManagementCard(
        ownerIdentityID: String,
        publicAddress: String,
        card: StoredManagementCard
    ) throws {
        try transaction {
            guard let nodeID = try nodeIdentifier(
                ownerIdentityID: ownerIdentityID,
                publicAddress: publicAddress
            ) else { return }

            let known = try prepare("SELECT device_version FROM node_mgmt_card WHERE node_id = ?")
            defer { sqlite3_finalize(known) }
            try check(sqlite3_bind_int64(known, 1, nodeID))
            var superseded = false
            if sqlite3_step(known) == SQLITE_ROW {
                superseded = Self.optionalStringColumn(known, at: 0) != card.deviceVersion
            }
            if superseded {
                let stale = try prepare("DELETE FROM node_prop_cache WHERE node_id = ?")
                defer { sqlite3_finalize(stale) }
                try check(sqlite3_bind_int64(stale, 1, nodeID))
                try stepDone(stale)
            }

            let statement = try prepare(
                """
                INSERT INTO node_mgmt_card (
                    node_id, capabilities, device_version, device_model, device_name,
                    fetched_at_ms
                )
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    capabilities = excluded.capabilities,
                    device_version = excluded.device_version,
                    device_model = excluded.device_model,
                    device_name = excluded.device_name,
                    fetched_at_ms = excluded.fetched_at_ms
                """
            )
            defer { sqlite3_finalize(statement) }
            try check(sqlite3_bind_int64(statement, 1, nodeID))
            try bind(card.capabilities, to: statement, at: 2)
            try bindOptional(card.deviceVersion, to: statement, at: 3)
            try bindOptional(card.deviceModel, to: statement, at: 4)
            try bindOptional(card.deviceName, to: statement, at: 5)
            try check(sqlite3_bind_int64(statement, 6, Self.milliseconds(card.fetchedAt)))
            try stepDone(statement)
        }
    }

    /// Forget everything cached about a device, so the next open asks it
    /// afresh. The card goes too: a refresh that cannot be trusted to be
    /// about the same firmware is not a refresh.
    func forgetManagementCache(ownerIdentityID: String, publicAddress: String) throws {
        try transaction {
            guard let nodeID = try nodeIdentifier(
                ownerIdentityID: ownerIdentityID,
                publicAddress: publicAddress
            ) else { return }
            for table in ["node_prop_cache", "node_mgmt_card"] {
                let statement = try prepare("DELETE FROM \(table) WHERE node_id = ?")
                defer { sqlite3_finalize(statement) }
                try check(sqlite3_bind_int64(statement, 1, nodeID))
                try stepDone(statement)
            }
        }
    }

    /// What a device was last seen configured as, for the properties asked
    /// for. Absent properties are simply not in the result: never fetched
    /// and refused read the same from here, and the screen shows both as a
    /// field it has nothing to prefill.
    func cachedProperties(
        ownerIdentityID: String,
        publicAddress: String,
        propertyIDs: [UInt32]
    ) throws -> [UInt32: StoredCachedProperty] {
        guard !propertyIDs.isEmpty else { return [:] }
        let placeholders = Array(repeating: "?", count: propertyIDs.count).joined(separator: ", ")
        let statement = try prepare(
            """
            SELECT p.property_id, p.value, p.fetched_at_ms
            FROM node_prop_cache p JOIN node n ON n.id = p.node_id
            WHERE n.owner_identity_id = ? AND n.public_address = ?
                AND p.property_id IN (\(placeholders))
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(publicAddress, to: statement, at: 2)
        for (offset, property) in propertyIDs.enumerated() {
            try check(sqlite3_bind_int64(statement, Int32(3 + offset), Int64(property)))
        }
        var cached: [UInt32: StoredCachedProperty] = [:]
        while sqlite3_step(statement) == SQLITE_ROW {
            let property = UInt32(sqlite3_column_int64(statement, 0))
            cached[property] = StoredCachedProperty(
                value: Self.dataColumn(statement, at: 1),
                fetchedAt: Date(
                    timeIntervalSince1970: Double(sqlite3_column_int64(statement, 2)) / 1000
                )
            )
        }
        return cached
    }

    /// Record values a device reported — from a read, or from the echo a
    /// write comes back with, which is the freshest statement of what the
    /// device is actually holding.
    func saveCachedProperties(
        ownerIdentityID: String,
        publicAddress: String,
        values: [UInt32: Data],
        at instant: Date
    ) throws {
        guard !values.isEmpty else { return }
        try transaction {
            guard let nodeID = try nodeIdentifier(
                ownerIdentityID: ownerIdentityID,
                publicAddress: publicAddress
            ) else { return }
            let statement = try prepare(
                """
                INSERT INTO node_prop_cache (node_id, property_id, value, fetched_at_ms)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(node_id, property_id) DO UPDATE SET
                    value = excluded.value,
                    fetched_at_ms = excluded.fetched_at_ms
                """
            )
            defer { sqlite3_finalize(statement) }
            let stamp = Self.milliseconds(instant)
            for (property, value) in values {
                try check(sqlite3_reset(statement))
                try check(sqlite3_bind_int64(statement, 1, nodeID))
                try check(sqlite3_bind_int64(statement, 2, Int64(property)))
                try bind(value, to: statement, at: 3)
                try check(sqlite3_bind_int64(statement, 4, stamp))
                try stepDone(statement)
            }
        }
    }

    /// This phone's row for a peer, or `nil` for one it does not store. A
    /// peer with no row has nowhere to hang a cache, which is ordinary
    /// rather than an error: nothing is cached about a stranger.
    private func nodeIdentifier(ownerIdentityID: String, publicAddress: String) throws -> Int64? {
        let statement = try prepare(
            "SELECT id FROM node WHERE owner_identity_id = ? AND public_address = ?"
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(publicAddress, to: statement, at: 2)
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return sqlite3_column_int64(statement, 0)
    }

    private static func milliseconds(_ instant: Date) -> Int64 {
        Int64((instant.timeIntervalSince1970 * 1000).rounded())
    }

    func listNodes(ownerIdentityID: String) throws -> [StoredNode] {
        let statement = try prepare(
            """
            SELECT id, owner_identity_id, public_address, alias, advertised_name,
                   system_role, node_kind, advertisement,
                   advertisement_authenticated, last_heard_at,
                   is_saved, is_favorite, on_dev_identity, notify_when_heard
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
            throw Self.sqliteFailure(database, sqlite3_errcode(database))
        }
        return sqlite3_column_int64(select, 0)
    }

    /// The last message and unread count a list row needs, as SQL expressions
    /// against an already-joined conversation.
    ///
    /// Both are per-conversation index seeks rather than scans: the last message
    /// resolves a rowid at the end of one index range and then fetches that one
    /// row, and the unread count starts at the read cursor instead of the
    /// beginning of history. Deliberately absent is a total message count — it
    /// is the one aggregate that must walk the whole range, and nothing in a
    /// list row asks for it.
    ///
    /// `owner` and `address` are the outer query's own column references, so
    /// this reads the same for a direct chat keyed by peer address and a
    /// channel chat keyed by channel tag.
    private static func conversationTailColumns(owner: String, address: String) -> String {
        """
        lm.created_at_ms, lm.body, lm.direction, lm.deleted,
        lm.sender_address, lm.sender_hint,
        (SELECT COUNT(*) FROM chat_message u
          WHERE u.owner_identity_id = \(owner)
            AND u.conversation_address = \(address)
            AND u.direction = 0 AND u.deleted = 0 AND u.presence = 0
            AND u.is_reaction = 0
            AND u.created_at_ms > c.last_read_at_ms)
        """
    }

    private static func conversationTailJoin(owner: String, address: String) -> String {
        """
        LEFT JOIN chat_message lm ON lm.rowid = (
            SELECT m.rowid FROM chat_message m
            WHERE m.owner_identity_id = \(owner) AND m.conversation_address = \(address)
                AND m.is_reaction = 0
            ORDER BY m.created_at_ms DESC, m.rowid DESC
            LIMIT 1
        )
        """
    }

    /// Reads the six preview columns and the unread count a tail block selects,
    /// starting at `offset`. A conversation with no messages has a NULL
    /// timestamp and no preview.
    private static func conversationTail(
        _ statement: OpaquePointer,
        at offset: Int32
    ) -> (lastMessage: StoredConversationPreview?, unreadCount: Int) {
        let unread = Int(sqlite3_column_int64(statement, offset + 6))
        guard sqlite3_column_type(statement, offset) != SQLITE_NULL else {
            return (nil, unread)
        }
        return (
            StoredConversationPreview(
                createdAtMilliseconds: sqlite3_column_int64(statement, offset),
                body: stringColumn(statement, at: offset + 1),
                isOutbound: sqlite3_column_int(statement, offset + 2) == 1,
                isDeleted: sqlite3_column_int(statement, offset + 3) != 0,
                senderAddress: optionalStringColumn(statement, at: offset + 4),
                senderHint: optionalDataColumn(statement, at: offset + 5)
            ),
            unread
        )
    }

    func listDirectConversations(ownerIdentityID: String) throws -> [StoredDirectConversation] {
        let statement = try prepare(
            """
            SELECT c.id, n.id, n.owner_identity_id, n.public_address, n.alias,
                   n.advertised_name, n.system_role, n.node_kind,
                   n.advertisement, n.advertisement_authenticated, n.last_heard_at,
                   n.is_saved, n.is_favorite, n.on_dev_identity,
                   n.notify_when_heard,
                   c.draft_text, c.last_read_at_ms, c.created_at_ms,
                   c.notifications_enabled,
                   \(Self.conversationTailColumns(
                        owner: "c.owner_identity_id",
                        address: "n.public_address"
                   ))
            FROM direct_conversation c JOIN node n ON n.id = c.node_id
            \(Self.conversationTailJoin(
                 owner: "c.owner_identity_id",
                 address: "n.public_address"
            ))
            WHERE c.owner_identity_id = ? ORDER BY c.created_at_ms DESC, c.id DESC
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        var conversations: [StoredDirectConversation] = []
        while true {
            switch sqlite3_step(statement) {
            case SQLITE_ROW:
                let tail = Self.conversationTail(statement, at: 19)
                conversations.append(
                    StoredDirectConversation(
                        id: sqlite3_column_int64(statement, 0),
                        node: storedNode(statement, offset: 1),
                        draftText: Self.stringColumn(statement, at: 15),
                        lastReadAtMilliseconds: sqlite3_column_int64(statement, 16),
                        createdAtMilliseconds: sqlite3_column_int64(statement, 17),
                        notificationsEnabled: sqlite3_column_int(statement, 18) != 0,
                        lastMessage: tail.lastMessage,
                        unreadCount: tail.unreadCount
                    )
                )
            case SQLITE_DONE:
                return conversations
            case let code:
                throw Self.sqliteFailure(database, code)
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
            throw Self.sqliteFailure(database, sqlite3_errcode(database))
        }
        return sqlite3_column_int64(select, 0)
    }

    func listChannelConversations(
        ownerIdentityID: String
    ) throws -> [StoredChannelConversation] {
        let statement = try prepare(
            """
            SELECT c.id, c.channel_id, c.conversation_address, c.draft_text,
                   c.last_read_at_ms, c.created_at_ms,
                   \(Self.conversationTailColumns(
                        owner: "c.owner_identity_id",
                        address: "c.conversation_address"
                   ))
            FROM channel_conversation c
            \(Self.conversationTailJoin(
                 owner: "c.owner_identity_id",
                 address: "c.conversation_address"
            ))
            WHERE c.owner_identity_id = ?
            ORDER BY c.created_at_ms DESC, c.id DESC
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
                let tail = Self.conversationTail(statement, at: 6)
                conversations.append(
                    StoredChannelConversation(
                        id: sqlite3_column_int64(statement, 0),
                        channelID: channelID,
                        conversationAddress: Self.stringColumn(statement, at: 2),
                        draftText: Self.stringColumn(statement, at: 3),
                        lastReadAtMilliseconds: sqlite3_column_int64(statement, 4),
                        createdAtMilliseconds: sqlite3_column_int64(statement, 5),
                        lastMessage: tail.lastMessage,
                        unreadCount: tail.unreadCount
                    )
                )
            case SQLITE_DONE:
                return conversations
            case let code:
                throw Self.sqliteFailure(database, code)
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

    /// Erase a conversation's messages while keeping the conversation itself.
    /// Addressed rather than keyed by row so one call serves both kinds.
    ///
    /// Outbound stream checkpoints are kept, for the same reason deleting a
    /// conversation keeps them: sequence continuity with the far end has to
    /// outlive the transcript, or the next message would announce a Sequence
    /// Reset. Archived outbound payloads do go, so a later resend request for
    /// a cleared message is answered Unavailable — the protocol handles that,
    /// and keeping erased content on disk would not be acceptable.
    func clearConversationMessages(
        ownerIdentityID: String,
        conversationAddress: String
    ) throws {
        try transaction {
            try purgeConversationHistory(
                ownerIdentityID: ownerIdentityID,
                conversationAddress: conversationAddress
            )
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

    /// Turn notifications for one direct conversation on or off.
    func setDirectConversationNotifications(
        ownerIdentityID: String,
        conversationID: Int64,
        enabled: Bool
    ) throws {
        let statement = try prepare(
            """
            UPDATE direct_conversation SET notifications_enabled = ?
            WHERE id = ? AND owner_identity_id = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try check(sqlite3_bind_int(statement, 1, enabled ? 1 : 0))
        try check(sqlite3_bind_int64(statement, 2, conversationID))
        try bind(ownerIdentityID, to: statement, at: 3)
        try stepDone(statement)
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
            case let code: throw Self.sqliteFailure(database, code)
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

    /// Returns the mutations that materialized a new message row — an edit
    /// whose original this phone never stored arrives as content, not a
    /// revision (see ``materializeOrphanEdit``). The engine could not flag
    /// those `notify`, since only the platform knows the original was
    /// missing; the caller treats them as the message arrivals they are.
    @discardableResult
    func applyChatMutations(
        ownerIdentityID: String,
        mutations: [MobileChatMutationRecord]
    ) throws -> [MobileChatMutationRecord] {
        var materialized: [MobileChatMutationRecord] = []
        try transaction {
            for mutation in mutations {
                if try applyChatMutation(ownerIdentityID: ownerIdentityID, mutation) {
                    materialized.append(mutation)
                }
            }
        }
        return materialized
    }

    /// Apply delivery evidence, and report which messages this evidence just
    /// gave up on.
    ///
    /// Only a crossing counts. `delivery_state` is recomputed from the whole
    /// fragment table on every record, so a message already resolved to
    /// 'failed' recomputes to 'failed' again on the next fragment, and a
    /// redelivered batch replays the same records; announcing the state rather
    /// than the transition would announce one failure many times.
    @discardableResult
    func applyChatDeliveries(
        ownerIdentityID: String,
        deliveries: [MobileChatDeliveryRecord]
    ) throws -> [ChatDeliveryFailure] {
        var failures: [ChatDeliveryFailure] = []
        try transaction {
            for delivery in deliveries {
                let before = try deliveryState(
                    ownerIdentityID: ownerIdentityID,
                    sessionID: delivery.sessionId,
                    handle: delivery.handle
                )
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

                try recomputeDeliveryState(
                    ownerIdentityID: ownerIdentityID,
                    deliverySessionID: String(delivery.sessionId),
                    deliveryHandle: delivery.handle
                )

                guard before != "failed",
                      try deliveryState(
                          ownerIdentityID: ownerIdentityID,
                          sessionID: delivery.sessionId,
                          handle: delivery.handle
                      ) == "failed",
                      let failure = try failedMessage(
                          ownerIdentityID: ownerIdentityID,
                          sessionID: delivery.sessionId,
                          handle: delivery.handle
                      )
                else { continue }
                failures.append(failure)
            }
        }
        return failures
    }

    /// Resolve one message's delivery state from the fragment evidence
    /// currently recorded against the transmission it reports —
    /// `delivery_session_id`/`delivery_handle`, the row's own compose until an
    /// edit re-aims it at the edit's frames. The keys given here are always
    /// transmission keys, never assumed to be a row's primary key.
    ///
    /// Every fragment acknowledged wins over any earlier failure, so a
    /// resent-and-acked message recovers to 'acknowledged'. When that recovery
    /// crosses from a previously 'failed' row, flag it "delivered late".
    /// SQLite evaluates every SET right-hand side against the pre-update row,
    /// so `delivery_state` below reads the old value while the counts read the
    /// fragments as they now stand.
    private func recomputeDeliveryState(
        ownerIdentityID: String,
        deliverySessionID: String,
        deliveryHandle: UInt32
    ) throws {
        let message = try prepare(
            """
            UPDATE chat_message SET
                delivered_late = CASE
                    WHEN chat_message.delivery_state = 'failed'
                        AND (
                            SELECT COUNT(*) FROM chat_delivery_fragment f
                            WHERE f.owner_identity_id = chat_message.owner_identity_id
                                AND f.session_id = chat_message.delivery_session_id
                                AND f.handle = chat_message.delivery_handle
                                AND f.state = 'acknowledged'
                        ) >= COALESCE(chat_message.fragment_count, 1) THEN 1
                    ELSE chat_message.delivered_late
                END,
                delivery_state = CASE
                WHEN (
                    SELECT COUNT(*) FROM chat_delivery_fragment f
                    WHERE f.owner_identity_id = chat_message.owner_identity_id
                        AND f.session_id = chat_message.delivery_session_id
                        AND f.handle = chat_message.delivery_handle
                        AND f.state = 'acknowledged'
                ) >= COALESCE(chat_message.fragment_count, 1) THEN 'acknowledged'
                WHEN EXISTS (
                    SELECT 1 FROM chat_delivery_fragment f
                    WHERE f.owner_identity_id = chat_message.owner_identity_id
                        AND f.session_id = chat_message.delivery_session_id
                        AND f.handle = chat_message.delivery_handle
                        AND f.state = 'failed'
                ) THEN 'failed'
                WHEN EXISTS (
                    SELECT 1 FROM chat_delivery_fragment f
                    WHERE f.owner_identity_id = chat_message.owner_identity_id
                        AND f.session_id = chat_message.delivery_session_id
                        AND f.handle = chat_message.delivery_handle
                        AND f.state IN ('sent', 'acknowledged')
                ) THEN 'sent'
                ELSE 'pending'
            END
            WHERE owner_identity_id = ? AND delivery_session_id = ? AND delivery_handle = ?
            """
        )
        defer { sqlite3_finalize(message) }
        try bind(ownerIdentityID, to: message, at: 1)
        try bind(deliverySessionID, to: message, at: 2)
        try check(sqlite3_bind_int64(message, 3, Int64(deliveryHandle)))
        try stepDone(message)
    }

    /// The delivery state of whichever row is currently reporting this
    /// transmission — matched through the delivery pointer, since evidence
    /// always arrives keyed by the transmission that earned it.
    private func deliveryState(
        ownerIdentityID: String,
        sessionID: UInt64,
        handle: UInt32
    ) throws -> String? {
        let statement = try prepare(
            """
            SELECT delivery_state FROM chat_message
            WHERE owner_identity_id = ? AND delivery_session_id = ? AND delivery_handle = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(String(sessionID), to: statement, at: 2)
        try check(sqlite3_bind_int64(statement, 3, Int64(handle)))
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return Self.optionalStringColumn(statement, at: 0)
    }

    /// What a just-failed message was, when it is one worth a notice. A
    /// reaction that never landed is not: the user did not write it as a
    /// message and cannot usefully resend it.
    private func failedMessage(
        ownerIdentityID: String,
        sessionID: UInt64,
        handle: UInt32
    ) throws -> ChatDeliveryFailure? {
        let statement = try prepare(
            """
            SELECT conversation_address, body FROM chat_message
            WHERE owner_identity_id = ? AND delivery_session_id = ? AND delivery_handle = ?
                AND direction = 1 AND deleted = 0 AND is_reaction = 0 AND body <> ''
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(String(sessionID), to: statement, at: 2)
        try check(sqlite3_bind_int64(statement, 3, Int64(handle)))
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return ChatDeliveryFailure(
            conversationAddress: Self.stringColumn(statement, at: 0),
            body: Self.stringColumn(statement, at: 1)
        )
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
            for mutation in batch.mutations {
                // A new outbound message is keyed by its own compose; an edit
                // never inserted a row, but the row it revised now points its
                // delivery tracking at the edit's transmissions — the ones
                // that just failed to launch. Either way the row the failure
                // belongs to is the one whose pointer names this mutation.
                switch mutation.kind {
                case .insert where mutation.direction == .outbound, .edit:
                    break
                default:
                    continue
                }
                let statement = try prepare(
                    """
                    UPDATE chat_message SET delivery_state = 'failed'
                    WHERE owner_identity_id = ? AND delivery_session_id = ?
                        AND delivery_handle = ? AND direction = 1
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

    /// Remove a failed outbound message outright, because its text just went
    /// back on the air as a genuinely new message: keeping the dead row would
    /// show the same words twice, once red and once delivered.
    ///
    /// Local only, and deliberately narrow — the guards make this a no-op on
    /// anything but a failed outbound row, so a stale caller can never take
    /// down a message the mesh knows about. Reactions pointing at the row go
    /// with it (nobody ever received the message they decorate), as does the
    /// delivery evidence recorded under the row's pointer.
    func removeFailedMessage(
        ownerIdentityID: String,
        sessionID: String,
        handle: UInt32
    ) throws {
        try transaction {
            let fragments = try prepare(
                """
                DELETE FROM chat_delivery_fragment
                WHERE owner_identity_id = ? AND (session_id, handle) = (
                    SELECT delivery_session_id, delivery_handle FROM chat_message
                    WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                        AND direction = 1 AND delivery_state = 'failed'
                )
                """
            )
            defer { sqlite3_finalize(fragments) }
            try bind(ownerIdentityID, to: fragments, at: 1)
            try bind(ownerIdentityID, to: fragments, at: 2)
            try bind(sessionID, to: fragments, at: 3)
            try check(sqlite3_bind_int64(fragments, 4, Int64(handle)))
            try stepDone(fragments)

            let reactions = try prepare(
                """
                DELETE FROM chat_message
                WHERE owner_identity_id = ? AND reaction_target_session_id = ?
                    AND reaction_target_handle = ?
                    AND EXISTS (
                        SELECT 1 FROM chat_message target
                        WHERE target.owner_identity_id = ?
                            AND target.session_id = ? AND target.handle = ?
                            AND target.direction = 1
                            AND target.delivery_state = 'failed'
                    )
                """
            )
            defer { sqlite3_finalize(reactions) }
            try bind(ownerIdentityID, to: reactions, at: 1)
            try bind(sessionID, to: reactions, at: 2)
            try check(sqlite3_bind_int64(reactions, 3, Int64(handle)))
            try bind(ownerIdentityID, to: reactions, at: 4)
            try bind(sessionID, to: reactions, at: 5)
            try check(sqlite3_bind_int64(reactions, 6, Int64(handle)))
            try stepDone(reactions)

            let message = try prepare(
                """
                DELETE FROM chat_message
                WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                    AND direction = 1 AND delivery_state = 'failed'
                """
            )
            defer { sqlite3_finalize(message) }
            try bind(ownerIdentityID, to: message, at: 1)
            try bind(sessionID, to: message, at: 2)
            try check(sqlite3_bind_int64(message, 3, Int64(handle)))
            try stepDone(message)
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

    /// The columns every transcript read selects, in the order
    /// ``storedChatMessage(_:)`` expects them. `rowid` is last so the reception
    /// block keeps its offsets.
    private static let chatMessageColumns = """
        session_id, handle, body, direction, delivery_state, deleted, created_at_ms,
        wire_id, epoch, edited, presence, received_late, delivered_late, original_body,
        sender_address, sender_hint, sender_handle,
        rx_rssi_dbm, rx_snr_cb, rx_lqi, rx_hop_count,
        rx_route_hints, rx_source_authenticated, rowid
        """

    /// How many messages a transcript read will accept in one page, whatever
    /// the caller asks for. A page becomes a live `UITextView` per row on the
    /// way to the screen, so an unbounded request is a mistake the store can
    /// see and the caller usually cannot.
    static let chatMessagePageLimit = 500

    /// The newest `limit` messages in a conversation.
    func chatMessagePage(
        ownerIdentityID: String,
        conversationAddress: String,
        newest limit: Int
    ) throws -> StoredChatMessagePage {
        // Read newest-first so the LIMIT lands at the end of the index range,
        // then flip: the transcript wants oldest-first.
        try descendingPage(
            ownerIdentityID: ownerIdentityID,
            conversationAddress: conversationAddress,
            cursorClause: nil,
            cursor: nil,
            limit: limit,
            hasNewer: false
        )
    }

    /// The `limit` messages immediately older than `cursor`.
    func chatMessagePage(
        ownerIdentityID: String,
        conversationAddress: String,
        before cursor: ChatMessageCursor,
        limit: Int
    ) throws -> StoredChatMessagePage {
        try descendingPage(
            ownerIdentityID: ownerIdentityID,
            conversationAddress: conversationAddress,
            cursorClause: "AND (created_at_ms, rowid) < (?, ?)",
            cursor: cursor,
            limit: limit,
            // Everything the cursor came from is newer than this page.
            hasNewer: true
        )
    }

    /// The `limit` messages immediately newer than `cursor` — or starting at
    /// it, when `including` is set, which is how a window re-reads the extent
    /// it already holds.
    func chatMessagePage(
        ownerIdentityID: String,
        conversationAddress: String,
        after cursor: ChatMessageCursor,
        including: Bool = false,
        limit: Int
    ) throws -> StoredChatMessagePage {
        let bounded = min(max(limit, 1), Self.chatMessagePageLimit)
        let statement = try prepare(
            """
            SELECT \(Self.chatMessageColumns)
            FROM chat_message
            WHERE owner_identity_id = ? AND conversation_address = ?
              AND is_reaction = 0
              AND (created_at_ms, rowid) \(including ? ">=" : ">") (?, ?)
            ORDER BY created_at_ms ASC, rowid ASC
            LIMIT ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(conversationAddress, to: statement, at: 2)
        try check(sqlite3_bind_int64(statement, 3, cursor.createdAtMilliseconds))
        try check(sqlite3_bind_int64(statement, 4, cursor.rowID))
        // One past the page answers "is there more" without a second statement.
        try check(sqlite3_bind_int64(statement, 5, Int64(bounded) + 1))
        var messages = try readChatMessages(statement)
        let hasNewer = messages.count > bounded
        if hasNewer { messages.removeLast(messages.count - bounded) }
        // A forward read sees nothing behind where it started, so ask. Reporting
        // "no older messages" on a hunch is the one wrong answer with teeth: it
        // tells the transcript its history is complete and retires the only
        // affordance that would have proved otherwise.
        let hasOlder = try messages.first.map {
            try hasMessages(
                ownerIdentityID: ownerIdentityID,
                conversationAddress: conversationAddress,
                before: $0.cursor
            )
        } ?? false
        return try withReactions(
            ownerIdentityID: ownerIdentityID,
            StoredChatMessagePage(
                messages: messages,
                hasOlder: hasOlder,
                hasNewer: hasNewer
            )
        )
    }

    #if DEBUG
    /// Write one staged transcript exactly as described, reactions included.
    ///
    /// Separate from ``seedGeneratedMessages`` because the two answer different
    /// questions: that one wants volume and does not care what it says, this
    /// one wants a specific conversation to read plausibly in a screenshot, so
    /// every body, sender and instant is dictated by the caller. Like that one
    /// it writes straight to the table, since `applyChatMutations` stamps
    /// `created_at_ms` from the clock and a staged transcript needs its own
    /// timeline.
    ///
    /// Reaction handles are allocated above ``stagedReactionHandleBase`` so they
    /// cannot collide with the message handles the caller chose.
    func seedStagedTranscript(
        ownerIdentityID: String,
        conversationAddress: String,
        sessionID: String,
        messages: [StagedMessage]
    ) throws {
        try transaction {
            let statement = try prepare(
                """
                INSERT OR REPLACE INTO chat_message (
                    owner_identity_id, session_id, handle, conversation_address,
                    sender_address, sender_hint, sender_handle,
                    direction, body, deleted, created_at_ms, presence, delivery_state,
                    rx_rssi_dbm, rx_snr_cb, rx_hop_count, rx_source_authenticated,
                    is_reaction, reaction_target_session_id, reaction_target_handle
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)
                """
            )
            defer { sqlite3_finalize(statement) }

            var reactionHandle = Self.stagedReactionHandleBase
            for message in messages {
                try writeStagedRow(
                    statement,
                    ownerIdentityID: ownerIdentityID,
                    conversationAddress: conversationAddress,
                    sessionID: sessionID,
                    handle: message.handle,
                    body: message.body,
                    outbound: message.outbound,
                    createdAt: message.createdAt,
                    senderAddress: message.senderAddress,
                    senderHint: message.senderHint,
                    senderHandle: message.senderHandle,
                    deliveryState: message.deliveryState,
                    reception: message.reception,
                    reactionTarget: nil
                )
                for reaction in message.reactions {
                    try writeStagedRow(
                        statement,
                        ownerIdentityID: ownerIdentityID,
                        conversationAddress: conversationAddress,
                        sessionID: sessionID,
                        handle: reactionHandle,
                        body: reaction.body,
                        outbound: reaction.outbound,
                        createdAt: reaction.createdAt,
                        senderAddress: reaction.senderAddress,
                        senderHint: reaction.senderHint,
                        senderHandle: nil,
                        deliveryState: reaction.outbound ? "acknowledged" : nil,
                        reception: nil,
                        reactionTarget: message.handle
                    )
                    reactionHandle += 1
                }
            }
        }
    }

    /// Handles at or above this belong to staged reaction rows. Far above any
    /// handle a staged transcript assigns its messages, so the two ranges
    /// cannot meet however long a staged conversation grows.
    private static let stagedReactionHandleBase: UInt32 = 1_000_000

    private func writeStagedRow(
        _ statement: OpaquePointer,
        ownerIdentityID: String,
        conversationAddress: String,
        sessionID: String,
        handle: UInt32,
        body: String,
        outbound: Bool,
        createdAt: Date,
        senderAddress: String?,
        senderHint: Data?,
        senderHandle: String?,
        deliveryState: String?,
        reception: StoredMessageReception?,
        reactionTarget: UInt32?
    ) throws {
        sqlite3_reset(statement)
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(sessionID, to: statement, at: 2)
        try check(sqlite3_bind_int64(statement, 3, Int64(handle)))
        try bind(conversationAddress, to: statement, at: 4)
        try bindOptional(senderAddress, to: statement, at: 5)
        try bindOptional(senderHint, to: statement, at: 6)
        try bindOptional(senderHandle, to: statement, at: 7)
        try check(sqlite3_bind_int(statement, 8, outbound ? 1 : 0))
        try bind(body, to: statement, at: 9)
        try check(
            sqlite3_bind_int64(statement, 10, Int64(createdAt.timeIntervalSince1970 * 1_000))
        )
        try bindOptional(deliveryState, to: statement, at: 11)
        try bindOptionalInt(reception?.rssiDbm.map(Int64.init), to: statement, at: 12)
        try bindOptionalInt(reception?.snrCentibels.map(Int64.init), to: statement, at: 13)
        try bindOptionalInt(reception?.hopCount.map(Int64.init), to: statement, at: 14)
        try bindOptionalInt(
            reception.map { Int64($0.sourceAuthenticated ? 1 : 0) },
            to: statement,
            at: 15
        )
        try check(sqlite3_bind_int(statement, 16, reactionTarget == nil ? 0 : 1))
        try bindOptional(reactionTarget == nil ? nil : sessionID, to: statement, at: 17)
        try bindOptionalInt(reactionTarget.map(Int64.init), to: statement, at: 18)
        try stepDone(statement)
    }

    /// Fill a conversation with generated messages, for exercising a transcript
    /// at a size no test account reaches by hand.
    ///
    /// Written straight to the table in one transaction rather than through
    /// `applyChatMutations`: that path stamps `created_at_ms` from the clock, so
    /// every seeded row would share a timestamp and the transcript would have no
    /// spread to page through. Timestamps here run backward from now in
    /// one-minute steps, in occasional same-millisecond clusters, which is what
    /// a real batch produces — with a lull of several hours every so often, so
    /// the seeded transcript spans days and carries the date separators a real
    /// one does.
    func seedGeneratedMessages(
        ownerIdentityID: String,
        conversationAddress: String,
        count: Int
    ) throws {
        try transaction {
            let statement = try prepare(
                """
                INSERT OR REPLACE INTO chat_message (
                    owner_identity_id, session_id, handle, conversation_address,
                    direction, body, deleted, created_at_ms, presence, delivery_state
                ) VALUES (?, ?, ?, ?, ?, ?, 0, ?, 0, ?)
                """
            )
            defer { sqlite3_finalize(statement) }
            let sessionID = "9\(Self.nowMilliseconds() % 1_000_000)"
            // The timeline is laid out first so the newest message still lands
            // on now: the lulls make the total span depend on the pattern, not
            // on the count alone.
            var offsets: [Int64] = []
            offsets.reserveCapacity(count)
            var offset: Int64 = 0
            var clusterRemaining = 0
            var clusters = 0
            for index in 0..<count {
                if clusterRemaining == 0 {
                    clusterRemaining = 3 + (index % 5)
                    if index > 0 {
                        // Counted in clusters rather than messages: cluster
                        // lengths vary, so a condition on the message index
                        // lands on a cluster boundary only by coincidence.
                        offset += clusters % 9 == 0 ? 5 * 3_600_000 : 60_000
                    }
                    clusters += 1
                }
                clusterRemaining -= 1
                offsets.append(offset)
            }
            let start = Self.nowMilliseconds() - (offsets.last ?? 0)
            for index in 0..<count {
                let createdAt = start + offsets[index]
                let outbound = index % 3 == 0
                sqlite3_reset(statement)
                try bind(ownerIdentityID, to: statement, at: 1)
                try bind(sessionID, to: statement, at: 2)
                try check(sqlite3_bind_int64(statement, 3, Int64(index)))
                try bind(conversationAddress, to: statement, at: 4)
                try check(sqlite3_bind_int(statement, 5, outbound ? 1 : 0))
                try bind(
                    "Seeded message \(index + 1) of \(count). "
                        + String(repeating: "Filler text. ", count: 1 + (index % 6)),
                    to: statement,
                    at: 6
                )
                try check(sqlite3_bind_int64(statement, 7, createdAt))
                // "acknowledged" is the app's word for delivered; an unknown
                // state would caption every seeded bubble "Sending…".
                try bindOptional(outbound ? "acknowledged" : nil, to: statement, at: 8)
                try stepDone(statement)
            }
        }
    }
    #endif

    /// Whether anything sits behind `cursor` in this conversation. One index
    /// seek, so a forward read can answer for the side it did not look at.
    private func hasMessages(
        ownerIdentityID: String,
        conversationAddress: String,
        before cursor: ChatMessageCursor
    ) throws -> Bool {
        let statement = try prepare(
            """
            SELECT 1 FROM chat_message
            WHERE owner_identity_id = ? AND conversation_address = ?
              AND is_reaction = 0
              AND (created_at_ms, rowid) < (?, ?)
            LIMIT 1
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(conversationAddress, to: statement, at: 2)
        try check(sqlite3_bind_int64(statement, 3, cursor.createdAtMilliseconds))
        try check(sqlite3_bind_int64(statement, 4, cursor.rowID))
        switch sqlite3_step(statement) {
        case SQLITE_ROW: return true
        case SQLITE_DONE: return false
        case let code: throw Self.sqliteFailure(database, code)
        }
    }

    /// The transcript around one message, for opening a search result in
    /// context. `nil` when that message is not in this conversation — a stale
    /// hit against a cleared transcript, which is not an error.
    func chatMessageWindow(
        ownerIdentityID: String,
        conversationAddress: String,
        around sessionID: String,
        handle: UInt32,
        radius: Int
    ) throws -> StoredChatMessagePage? {
        guard let anchor = try chatMessageCursor(
            ownerIdentityID: ownerIdentityID,
            conversationAddress: conversationAddress,
            sessionID: sessionID,
            handle: handle
        ) else { return nil }
        let older = try chatMessagePage(
            ownerIdentityID: ownerIdentityID,
            conversationAddress: conversationAddress,
            before: anchor,
            limit: radius
        )
        // Including the anchor keeps the centered message in the window even
        // when nothing follows it.
        let newer = try chatMessagePage(
            ownerIdentityID: ownerIdentityID,
            conversationAddress: conversationAddress,
            after: anchor,
            including: true,
            limit: radius + 1
        )
        return StoredChatMessagePage(
            messages: older.messages + newer.messages,
            hasOlder: older.hasOlder,
            hasNewer: newer.hasNewer
        )
    }

    /// Where a message sits in its conversation's order, by the durable
    /// identity the transcript knows it as.
    func chatMessageCursor(
        ownerIdentityID: String,
        conversationAddress: String,
        sessionID: String,
        handle: UInt32
    ) throws -> ChatMessageCursor? {
        let statement = try prepare(
            """
            SELECT created_at_ms, rowid FROM chat_message
            WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
              AND conversation_address = ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(sessionID, to: statement, at: 2)
        try check(sqlite3_bind_int64(statement, 3, Int64(handle)))
        try bind(conversationAddress, to: statement, at: 4)
        switch sqlite3_step(statement) {
        case SQLITE_ROW:
            return ChatMessageCursor(
                createdAtMilliseconds: sqlite3_column_int64(statement, 0),
                rowID: sqlite3_column_int64(statement, 1)
            )
        case SQLITE_DONE: return nil
        case let code: throw Self.sqliteFailure(database, code)
        }
    }

    /// How many messages a conversation holds. Deliberately its own call: this
    /// is the one aggregate that has to walk the whole range, so it belongs
    /// where something asked for it rather than on the conversation list.
    func chatMessageCount(
        ownerIdentityID: String,
        conversationAddress: String
    ) throws -> Int {
        let statement = try prepare(
            """
            SELECT COUNT(*) FROM chat_message
            WHERE owner_identity_id = ? AND conversation_address = ? AND is_reaction = 0
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(conversationAddress, to: statement, at: 2)
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw Self.sqliteFailure(database, sqlite3_errcode(database))
        }
        return Int(sqlite3_column_int64(statement, 0))
    }

    /// Both newest-first reads: take the page off the end of the index range,
    /// then reverse into the transcript's own order.
    private func descendingPage(
        ownerIdentityID: String,
        conversationAddress: String,
        cursorClause: String?,
        cursor: ChatMessageCursor?,
        limit: Int,
        hasNewer: Bool
    ) throws -> StoredChatMessagePage {
        let bounded = min(max(limit, 1), Self.chatMessagePageLimit)
        let statement = try prepare(
            """
            SELECT \(Self.chatMessageColumns)
            FROM chat_message
            WHERE owner_identity_id = ? AND conversation_address = ?
              AND is_reaction = 0
              \(cursorClause ?? "")
            ORDER BY created_at_ms DESC, rowid DESC
            LIMIT ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(conversationAddress, to: statement, at: 2)
        var index: Int32 = 3
        if let cursor {
            try check(sqlite3_bind_int64(statement, index, cursor.createdAtMilliseconds))
            try check(sqlite3_bind_int64(statement, index + 1, cursor.rowID))
            index += 2
        }
        try check(sqlite3_bind_int64(statement, index, Int64(bounded) + 1))
        var messages = try readChatMessages(statement)
        let hasOlder = messages.count > bounded
        if hasOlder { messages.removeLast(messages.count - bounded) }
        return try withReactions(
            ownerIdentityID: ownerIdentityID,
            StoredChatMessagePage(
                messages: messages.reversed(),
                hasOlder: hasOlder,
                hasNewer: hasNewer
            )
        )
    }

    private func readChatMessages(_ statement: OpaquePointer) throws -> [StoredChatMessage] {
        var messages: [StoredChatMessage] = []
        while true {
            switch sqlite3_step(statement) {
            case SQLITE_ROW: messages.append(Self.storedChatMessage(statement))
            case SQLITE_DONE: return messages
            case let code: throw Self.sqliteFailure(database, code)
            }
        }
    }

    /// Attach each message's reactions.
    ///
    /// Reactions are not transcript rows, and the messages they are about may
    /// sit anywhere in history, so this is a second read keyed by the page's
    /// own identities rather than anything the page query could join.
    private func withReactions(
        ownerIdentityID: String,
        _ page: StoredChatMessagePage
    ) throws -> StoredChatMessagePage {
        guard !page.messages.isEmpty else { return page }
        let grouped = try reactions(
            ownerIdentityID: ownerIdentityID,
            targets: page.messages.map { ($0.sessionID, $0.handle) }
        )
        guard !grouped.isEmpty else { return page }
        return StoredChatMessagePage(
            messages: page.messages.map { message in
                var message = message
                message.reactions = grouped[message.id] ?? []
                return message
            },
            hasOlder: page.hasOlder,
            hasNewer: page.hasNewer
        )
    }

    /// Live reactions for the given messages, keyed by `StoredChatMessage.id`.
    ///
    /// A sender has one reaction per message: the newest emote they sent about
    /// it wins, and if that one has no body it is a withdrawal and they have
    /// none. Both rules are settled here rather than on the wire, where every
    /// emote is just another message.
    private func reactions(
        ownerIdentityID: String,
        targets: [(sessionID: String, handle: UInt32)]
    ) throws -> [String: [StoredMessageReaction]] {
        // Newest-per-sender needs arrival order, and a withdrawal has to be
        // able to erase what came before it, so fold rather than aggregate.
        var newest: [String: [String: StoredMessageReaction]] = [:]
        var order: [String: [String]] = [:]
        // Two bound parameters per target, well inside SQLite's limit while
        // keeping the number of statements small.
        for chunk in stride(from: 0, to: targets.count, by: 200).map({ start in
            targets[start..<min(start + 200, targets.count)]
        }) {
            let tuples = Array(repeating: "(?, ?)", count: chunk.count).joined(separator: ", ")
            let statement = try prepare(
                """
                SELECT reaction_target_session_id, reaction_target_handle,
                    body, direction, sender_address, sender_hint,
                    session_id, handle, wire_id, epoch, created_at_ms, delivery_state
                FROM chat_message
                WHERE owner_identity_id = ? AND is_reaction = 1 AND deleted = 0
                    AND (reaction_target_session_id, reaction_target_handle) IN (\(tuples))
                ORDER BY created_at_ms ASC, rowid ASC
                """
            )
            defer { sqlite3_finalize(statement) }
            try bind(ownerIdentityID, to: statement, at: 1)
            var index: Int32 = 2
            for target in chunk {
                try bind(target.sessionID, to: statement, at: index)
                try check(sqlite3_bind_int64(statement, index + 1, Int64(target.handle)))
                index += 2
            }
            rows: while true {
                switch sqlite3_step(statement) {
                case SQLITE_ROW:
                    let key = "\(Self.stringColumn(statement, at: 0))"
                        + ":\(sqlite3_column_int64(statement, 1))"
                    let outbound = sqlite3_column_int(statement, 3) == 1
                    let senderAddress = Self.optionalStringColumn(statement, at: 4)
                    let senderHint = Self.optionalDataColumn(statement, at: 5)
                    // Whoever sent it, however little we know about them: our
                    // own reactions collapse to one sender, and a member we
                    // cannot name yet is still distinct by hint.
                    let sender = outbound
                        ? "me"
                        : (senderAddress ?? senderHint.map { $0.map { String(format: "%02x", $0) }
                            .joined() } ?? "peer")
                    let reaction = StoredMessageReaction(
                        body: Self.stringColumn(statement, at: 2),
                        outbound: outbound,
                        senderAddress: senderAddress,
                        senderHint: senderHint,
                        sessionID: Self.stringColumn(statement, at: 6),
                        handle: UInt32(sqlite3_column_int64(statement, 7)),
                        wireID: Self.optionalIntColumn(statement, at: 8).map { UInt8($0) },
                        epoch: Self.optionalIntColumn(statement, at: 9).map { UInt16($0) },
                        createdAtMilliseconds: sqlite3_column_int64(statement, 10),
                        deliveryState: Self.optionalStringColumn(statement, at: 11)
                    )
                    if newest[key]?[sender] == nil {
                        order[key, default: []].append(sender)
                    }
                    newest[key, default: [:]][sender] = reaction
                case SQLITE_DONE:
                    break rows
                case let code:
                    throw Self.sqliteFailure(database, code)
                }
            }
        }
        return newest.reduce(into: [:]) { result, entry in
            let live = (order[entry.key] ?? []).compactMap { sender -> StoredMessageReaction? in
                guard let reaction = entry.value[sender], !reaction.body.isEmpty else { return nil }
                return reaction
            }
            if !live.isEmpty { result[entry.key] = live }
        }
    }

    private static func storedChatMessage(_ statement: OpaquePointer) -> StoredChatMessage {
        StoredChatMessage(
            sessionID: stringColumn(statement, at: 0),
            handle: UInt32(sqlite3_column_int64(statement, 1)),
            body: stringColumn(statement, at: 2),
            outbound: sqlite3_column_int(statement, 3) == 1,
            deliveryState: optionalStringColumn(statement, at: 4),
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
            originalBody: optionalStringColumn(statement, at: 13),
            senderAddress: optionalStringColumn(statement, at: 14),
            senderHint: optionalDataColumn(statement, at: 15),
            senderHandle: optionalStringColumn(statement, at: 16),
            reception: reception(statement, at: 17),
            rowID: sqlite3_column_int64(statement, 23)
        )
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
                SELECT delivery_session_id, delivery_handle FROM chat_message
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
            case let code: throw Self.sqliteFailure(database, code)
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
            onDeviceIdentity: sqlite3_column_int(statement, offset + 12) != 0,
            notifyWhenHeard: sqlite3_column_int(statement, offset + 13) != 0
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

    /// Returns whether the mutation materialized a new message row instead of
    /// revising one — see ``materializeOrphanEdit``.
    @discardableResult
    private func applyChatMutation(
        ownerIdentityID: String,
        _ mutation: MobileChatMutationRecord
    ) throws -> Bool {
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
        guard sqlite3_changes(database) > 0 else { return false }

        switch mutation.kind {
        case .insert:
            guard let peerAddress = mutation.conversationAddress,
                  let direction = mutation.direction,
                  let body = mutation.body
            else { return false }
            // An emote — status text about another message — is a reaction
            // rather than a transcript row of its own. Resolve what it is
            // about now, while the reference is in hand: the target may be
            // named by a live handle or, far more often, by the wire
            // coordinates of a row stored in some earlier session.
            let isReaction = mutation.messageType == 1
                && (mutation.regardingHandle != nil || mutation.regardingWireId != nil)
            let reactionTarget = isReaction
                ? try resolveReactionTarget(
                    ownerIdentityID: ownerIdentityID,
                    sessionID: sessionID,
                    conversationAddress: peerAddress,
                    mutation: mutation
                )
                : nil
            let statement = try prepare(
                """
                INSERT INTO chat_message (
                    owner_identity_id, session_id, handle, conversation_address, sender_address,
                    direction, message_type, wire_id, epoch, client_token,
                    sender_handle, regarding_handle, background_color, text_color, body,
                    complete, present_fragments, fragment_count, finalized,
                    delivery_state, deleted, created_at_ms, presence, received_late,
                    sender_hint, rx_rssi_dbm, rx_snr_cb, rx_lqi, rx_hop_count,
                    rx_route_hints, rx_source_authenticated,
                    is_reaction, regarding_wire_id, regarding_direction, regarding_sender_hint,
                    reaction_target_session_id, reaction_target_handle,
                    delivery_session_id, delivery_handle
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?,
                          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            // A message replayed from the radio's offline queue is stamped
            // when it was received off the air, not when the drain landed it
            // here, so a drained backlog sorts and reads correctly.
            let bufferedAgeMs = Int64(mutation.rx?.bufferedAgeSeconds ?? 0) * 1000
            try check(sqlite3_bind_int64(statement, 21, Self.nowMilliseconds() - bufferedAgeMs))
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
            try check(sqlite3_bind_int(statement, 31, isReaction ? 1 : 0))
            try bindOptionalInt(mutation.regardingWireId.map(Int64.init), to: statement, at: 32)
            try bindOptionalInt(
                mutation.regardingDirection.map { Int64($0 == .outbound ? 1 : 0) },
                to: statement,
                at: 33
            )
            try bindOptional(mutation.regardingSenderHint.map { Data($0) }, to: statement, at: 34)
            try bindOptional(reactionTarget?.sessionID, to: statement, at: 35)
            try bindOptionalInt(reactionTarget.map { Int64($0.handle) }, to: statement, at: 36)
            // A fresh row reports its own transmission until an edit re-aims it.
            try bind(sessionID, to: statement, at: 37)
            try check(sqlite3_bind_int64(statement, 38, Int64(mutation.handle)))
            try stepDone(statement)
            // A reaction can outrun the message it is about — repaired gaps
            // and channel-group reordering both do it. Whenever a real message
            // lands, adopt whatever was already waiting on it.
            if !isReaction, let wireID = mutation.wireId {
                try bindPendingReactions(
                    ownerIdentityID: ownerIdentityID,
                    sessionID: sessionID,
                    handle: mutation.handle,
                    conversationAddress: peerAddress,
                    wireID: wireID,
                    outbound: direction == .outbound,
                    senderHint: mutation.senderHint.map { Data($0) }
                )
            }
        case .updateBody:
            guard let body = mutation.body else { return false }
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
            guard let target = try editTargetRowid(
                ownerIdentityID: ownerIdentityID,
                sessionID: sessionID,
                mutation: mutation
            ) else {
                // The edit names a message this phone never stored. That is
                // not stray metadata: it is how a resend arrives when both
                // the original AND the engine's chance to open a gap for it
                // are gone (a new conversation, or any app relaunch — inbound
                // stream state is engine RAM). The edit carries the message's
                // whole current content, so materialize it as the message
                // rather than throwing the words away. An unresolved delete
                // stays a no-op: there is nothing to remove.
                return try materializeOrphanEdit(
                    ownerIdentityID: ownerIdentityID,
                    sessionID: sessionID,
                    mutation: mutation
                )
            }
            // The first edit of the sender's own message captures its
            // pre-edit text (`body` on the right-hand side reads the
            // pre-update row) so the sender can still review it; the
            // resend archive only ever holds the edited content.
            //
            // An edit that leaves the text exactly as it stands changed
            // nothing, and is not annotated as an edit: that is the shape
            // a resend takes on the wire, and there is no earlier version
            // of the message for anyone to go back to.
            let statement = try prepare(
                """
                UPDATE chat_message SET
                    original_body = CASE WHEN ? = 1 AND direction = 1 AND body <> ?
                        THEN COALESCE(original_body, body)
                        ELSE original_body END,
                    body = ?, deleted = ?,
                    edited = MAX(edited, CASE WHEN ? = 1 AND body <> ? THEN 1 ELSE 0 END)
                WHERE rowid = ?
                """
            )
            defer { sqlite3_finalize(statement) }
            try check(sqlite3_bind_int(statement, 1, markEdited))
            try bind(body, to: statement, at: 2)
            try bind(body, to: statement, at: 3)
            try check(sqlite3_bind_int(statement, 4, deleted))
            try check(sqlite3_bind_int(statement, 5, markEdited))
            try bind(body, to: statement, at: 6)
            try check(sqlite3_bind_int64(statement, 7, target))
            try stepDone(statement)
            if mutation.kind == .edit {
                try adoptEditDelivery(
                    ownerIdentityID: ownerIdentityID,
                    targetRowid: target,
                    editSessionID: sessionID,
                    editHandle: mutation.handle,
                    fragmentCount: mutation.fragmentCount
                )
            }
        }
        return false
    }

    /// Store an inbound edit whose original this phone never had, as the
    /// message itself.
    ///
    /// A resend goes on the air as an edit of the failed message carrying its
    /// same text, and the receiver may hold nothing for it to revise — the
    /// original never arrived, and no gap placeholder was reserved when the
    /// edit's own sequence advance established a fresh baseline. The row is
    /// keyed by the edit mutation's session and handle (its only durable
    /// identity here) but carries the *original's* wire ID, so later edits,
    /// deletes, and reactions referencing that ID resolve to it; reactions
    /// already waiting on it are adopted the way any late-arriving message
    /// adopts them. Marked received-late — it is one, in the plainest sense.
    ///
    /// Inbound originals only: an unresolved edit of one of our own outbound
    /// messages describes a message this identity never sent, and stays
    /// dropped.
    private func materializeOrphanEdit(
        ownerIdentityID: String,
        sessionID: String,
        mutation: MobileChatMutationRecord
    ) throws -> Bool {
        guard mutation.kind == .edit,
              let body = mutation.body, !body.isEmpty,
              mutation.originalDirection == .inbound,
              let wireID = mutation.originalWireId,
              let peerAddress = mutation.conversationAddress
        else { return false }
        let statement = try prepare(
            """
            INSERT OR IGNORE INTO chat_message (
                owner_identity_id, session_id, handle, conversation_address,
                direction, wire_id, sender_hint, body, complete,
                deleted, created_at_ms, presence, received_late, is_reaction,
                delivery_session_id, delivery_handle
            ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, 1, 0, ?, 0, 1, 0, ?, ?)
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(sessionID, to: statement, at: 2)
        try check(sqlite3_bind_int64(statement, 3, Int64(mutation.handle)))
        try bind(peerAddress, to: statement, at: 4)
        try check(sqlite3_bind_int(statement, 5, Int32(wireID)))
        try bindOptional(mutation.originalSenderHint.map { Data($0) }, to: statement, at: 6)
        try bind(body, to: statement, at: 7)
        try check(sqlite3_bind_int64(statement, 8, Self.nowMilliseconds()))
        try bind(sessionID, to: statement, at: 9)
        try check(sqlite3_bind_int64(statement, 10, Int64(mutation.handle)))
        try stepDone(statement)
        guard sqlite3_changes(database) > 0 else { return false }
        try bindPendingReactions(
            ownerIdentityID: ownerIdentityID,
            sessionID: sessionID,
            handle: mutation.handle,
            conversationAddress: peerAddress,
            wireID: wireID,
            outbound: false,
            senderHint: mutation.originalSenderHint.map { Data($0) }
        )
        return true
    }

    /// Which stored row an edit or delete revises.
    ///
    /// A live handle names a row this facade session wrote. Otherwise the
    /// engine exported the original's wire reference, and the row it names is
    /// the newest with that ID on that stream — wire IDs recycle serially
    /// within a stream, so the newest epoch/row is the one still
    /// referenceable.
    private func editTargetRowid(
        ownerIdentityID: String,
        sessionID: String,
        mutation: MobileChatMutationRecord
    ) throws -> Int64? {
        if let original = mutation.originalHandle {
            let statement = try prepare(
                """
                SELECT rowid FROM chat_message
                WHERE owner_identity_id = ? AND session_id = ? AND handle = ?
                """
            )
            defer { sqlite3_finalize(statement) }
            try bind(ownerIdentityID, to: statement, at: 1)
            try bind(sessionID, to: statement, at: 2)
            try check(sqlite3_bind_int64(statement, 3, Int64(original)))
            guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
            return sqlite3_column_int64(statement, 0)
        }
        guard let wireID = mutation.originalWireId,
              let direction = mutation.originalDirection,
              let peerAddress = mutation.conversationAddress
        else { return nil }
        let statement = try prepare(
            """
            SELECT rowid FROM chat_message
            WHERE owner_identity_id = ? AND conversation_address = ?
                AND direction = ? AND wire_id = ?
            ORDER BY epoch DESC, created_at_ms DESC, rowid DESC
            LIMIT 1
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(peerAddress, to: statement, at: 2)
        try check(sqlite3_bind_int(statement, 3, direction == .outbound ? 1 : 0))
        try check(sqlite3_bind_int(statement, 4, Int32(wireID)))
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        return sqlite3_column_int64(statement, 0)
    }

    /// Aim an edited outbound message's delivery pointer at the edit's own
    /// transmission — the frames now carrying the row's content.
    ///
    /// An edit inserts no row: its mutation revises the original's stored
    /// body. Its frames, though, are tracked under the edit's own engine
    /// handle, so without this the row would keep waiting on evidence for a
    /// transmission nobody is making any more — an edit that failed could
    /// never say so, and a resent message (a resend airs as an edit of
    /// itself) would stay "Not Delivered" however well the resend went. Only
    /// the pointer moves: the row's primary key is its compose identity,
    /// which further edits and reactions still reference. The fragments of
    /// the superseded attempt go with it.
    ///
    /// Scoped to outbound rows in SQL rather than checked here: an inbound
    /// edit only ever revises its own sender's inbound rows, which carry no
    /// delivery state, and this keeps that invariant local to one statement.
    ///
    /// `fragmentCount` is how many frames the edit put in flight — its
    /// content fragments under its own encoding overhead, so the count the
    /// original compose stamped no longer describes what is on the air.
    private func adoptEditDelivery(
        ownerIdentityID: String,
        targetRowid: Int64,
        editSessionID: String,
        editHandle: UInt32,
        fragmentCount: UInt8?
    ) throws {
        let stale = try prepare(
            """
            DELETE FROM chat_delivery_fragment
            WHERE owner_identity_id = ? AND (session_id, handle) = (
                SELECT delivery_session_id, delivery_handle FROM chat_message
                WHERE rowid = ? AND direction = 1
            )
            """
        )
        defer { sqlite3_finalize(stale) }
        try bind(ownerIdentityID, to: stale, at: 1)
        try check(sqlite3_bind_int64(stale, 2, targetRowid))
        try stepDone(stale)

        let message = try prepare(
            """
            UPDATE chat_message
            SET delivery_session_id = ?, delivery_handle = ?,
                delivery_state = 'pending', delivered_late = 0,
                fragment_count = COALESCE(?, fragment_count)
            WHERE rowid = ? AND direction = 1
            """
        )
        defer { sqlite3_finalize(message) }
        try bind(editSessionID, to: message, at: 1)
        try check(sqlite3_bind_int64(message, 2, Int64(editHandle)))
        try bindOptionalInt(fragmentCount.map(Int64.init), to: message, at: 3)
        try check(sqlite3_bind_int64(message, 4, targetRowid))
        try stepDone(message)
    }

    /// Which stored row a reaction is about.
    ///
    /// A live handle names a row this session wrote. Otherwise the reference
    /// arrives as wire coordinates, and the row it names is the newest
    /// non-reaction message holding that ID on that stream — wire IDs recycle
    /// serially, so the newest is the only one still referenceable. `nil`
    /// when the target has not been stored yet; ``bindPendingReactions``
    /// adopts those once it is.
    private func resolveReactionTarget(
        ownerIdentityID: String,
        sessionID: String,
        conversationAddress: String,
        mutation: MobileChatMutationRecord
    ) throws -> (sessionID: String, handle: UInt32)? {
        if let handle = mutation.regardingHandle {
            return (sessionID, handle)
        }
        guard let wireID = mutation.regardingWireId,
              let direction = mutation.regardingDirection
        else { return nil }
        // `IS` rather than `=` so a conversation without hints — every direct
        // one, and our own side of a group — matches null against null.
        let statement = try prepare(
            """
            SELECT session_id, handle FROM chat_message
            WHERE owner_identity_id = ? AND conversation_address = ?
                AND direction = ? AND wire_id = ? AND is_reaction = 0
                AND sender_hint IS ?
            ORDER BY epoch DESC, created_at_ms DESC, rowid DESC
            LIMIT 1
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(ownerIdentityID, to: statement, at: 1)
        try bind(conversationAddress, to: statement, at: 2)
        try check(sqlite3_bind_int(statement, 3, direction == .outbound ? 1 : 0))
        try check(sqlite3_bind_int(statement, 4, Int32(wireID)))
        try bindOptional(mutation.regardingSenderHint.map { Data($0) }, to: statement, at: 5)
        guard sqlite3_step(statement) == SQLITE_ROW else { return nil }
        guard let session = sqlite3_column_text(statement, 0) else { return nil }
        return (String(cString: session), UInt32(sqlite3_column_int64(statement, 1)))
    }

    /// Adopt reactions that arrived before the message they are about.
    private func bindPendingReactions(
        ownerIdentityID: String,
        sessionID: String,
        handle: UInt32,
        conversationAddress: String,
        wireID: UInt8,
        outbound: Bool,
        senderHint: Data?
    ) throws {
        let statement = try prepare(
            """
            UPDATE chat_message
            SET reaction_target_session_id = ?, reaction_target_handle = ?
            WHERE owner_identity_id = ? AND conversation_address = ?
                AND is_reaction = 1 AND reaction_target_session_id IS NULL
                AND regarding_wire_id = ? AND regarding_direction = ?
                AND regarding_sender_hint IS ?
            """
        )
        defer { sqlite3_finalize(statement) }
        try bind(sessionID, to: statement, at: 1)
        try check(sqlite3_bind_int64(statement, 2, Int64(handle)))
        try bind(ownerIdentityID, to: statement, at: 3)
        try bind(conversationAddress, to: statement, at: 4)
        try check(sqlite3_bind_int(statement, 5, Int32(wireID)))
        try check(sqlite3_bind_int(statement, 6, outbound ? 1 : 0))
        try bindOptional(senderHint, to: statement, at: 7)
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
            throw Self.sqliteFailure(database, status)
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
            throw Self.sqliteFailure(database, status)
        }
    }

    private func check(_ status: Int32) throws {
        guard status == SQLITE_OK else {
            throw Self.sqliteFailure(database, status)
        }
    }

    /// Pair a result code with SQLite's own description of it, taken while the
    /// connection still holds it — `sqlite3_errmsg` reports the most recent
    /// failure, so it has to be read at the throw and not later.
    private static func sqliteFailure(
        _ database: OpaquePointer?,
        _ status: Int32
    ) -> ApplicationStoreError {
        let message = database.map { String(cString: sqlite3_errmsg($0)) } ?? "no connection"
        return .sqliteFailure(status, message: message)
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

        if version < 17 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                // Reactions are emotes: ordinary messages carrying a Regarding
                // reference, which is why they live in `chat_message` rather
                // than a table of their own — they are sent, delivered,
                // acknowledged, and repaired like anything else. What they need
                // is somewhere to record who they are about, resolved once on
                // arrival: the wire columns say what the frame claimed, and the
                // `reaction_target_*` pair says which stored row that turned out
                // to be. Reactions whose target has not arrived yet keep the
                // pair null until it does.
                try execute(
                    database,
                    sql: """
                    ALTER TABLE chat_message ADD COLUMN is_reaction INTEGER NOT NULL DEFAULT 0;
                    ALTER TABLE chat_message ADD COLUMN regarding_wire_id INTEGER;
                    ALTER TABLE chat_message ADD COLUMN regarding_direction INTEGER;
                    ALTER TABLE chat_message ADD COLUMN regarding_sender_hint BLOB;
                    ALTER TABLE chat_message ADD COLUMN reaction_target_session_id TEXT;
                    ALTER TABLE chat_message ADD COLUMN reaction_target_handle INTEGER;

                    CREATE INDEX chat_message_reaction_target_idx
                        ON chat_message (
                            owner_identity_id,
                            reaction_target_session_id,
                            reaction_target_handle
                        )
                        WHERE is_reaction = 1;

                    PRAGMA user_version = 17;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 18 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                // What a device said about itself, kept so that opening its
                // settings does not have to ask again. A node several flood
                // hops away answers slowly and at the cost of everyone's
                // airtime, so the phone asks once and remembers.
                //
                // `node_mgmt_card` is what a device *is*: capabilities, the
                // firmware they belong to, the hardware, the name. Firmware
                // version is the key the rest hangs from — capabilities
                // cannot change without it changing too — so a card arriving
                // with a different version invalidates every cached value
                // alongside it.
                //
                // `node_prop_cache` is what a device was last seen configured
                // as, verbatim: the bytes the device sent, decoded in Rust
                // where the wire formats already live. `fetched_at_ms` is
                // what lets a screen admit its age rather than present a
                // stale reading as current.
                try execute(
                    database,
                    sql: """
                    CREATE TABLE node_mgmt_card (
                        node_id INTEGER PRIMARY KEY REFERENCES node(id) ON DELETE CASCADE,
                        capabilities BLOB NOT NULL,
                        device_version TEXT,
                        device_model TEXT,
                        device_name TEXT,
                        fetched_at_ms INTEGER NOT NULL
                    );

                    CREATE TABLE node_prop_cache (
                        node_id INTEGER NOT NULL REFERENCES node(id) ON DELETE CASCADE,
                        property_id INTEGER NOT NULL,
                        value BLOB NOT NULL,
                        fetched_at_ms INTEGER NOT NULL,
                        PRIMARY KEY (node_id, property_id)
                    ) WITHOUT ROWID;

                    PRAGMA user_version = 18;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 19 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                // A one-shot watch: tell me the next time this node is heard
                // from. Armed by hand, disarmed by the hearing itself, so it
                // is state rather than a preference and belongs on the row it
                // is about — a watch that did not survive relaunch would be
                // useless for the thing it is for, which is a node that has
                // gone quiet and may come back at any hour.
                try execute(
                    database,
                    sql: """
                    ALTER TABLE node ADD COLUMN notify_when_heard INTEGER NOT NULL DEFAULT 0;
                    PRAGMA user_version = 19;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 20 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                // Which transmission a message row reports delivery for. A
                // row's primary key is its compose identity and never moves —
                // edits and reactions reference it — but the transmission
                // carrying its content changes whenever an edit (or a resend,
                // which airs as one) supersedes the original frames under the
                // edit's own engine handle. These columns are the pointer the
                // delivery-evidence machinery follows; they start equal to
                // the row's own key and are re-aimed at each edit.
                //
                // Backfilled for every existing row rather than outbound only:
                // handles are unique within a facade session regardless of
                // direction, so an inbound row can never match outbound
                // evidence, and one uniform rule beats a nullable special case.
                try execute(
                    database,
                    sql: """
                    ALTER TABLE chat_message ADD COLUMN delivery_session_id TEXT;
                    ALTER TABLE chat_message ADD COLUMN delivery_handle INTEGER;

                    UPDATE chat_message
                    SET delivery_session_id = session_id, delivery_handle = handle;

                    CREATE INDEX chat_message_delivery_idx ON chat_message (
                        owner_identity_id, delivery_session_id, delivery_handle
                    );

                    PRAGMA user_version = 20;
                    """
                )
                try execute(database, sql: "COMMIT")
            } catch {
                try? execute(database, sql: "ROLLBACK")
                throw error
            }
        }

        if version < 21 {
            try execute(database, sql: "BEGIN IMMEDIATE")
            do {
                // Whether a direct conversation may notify. Defaults on,
                // which is what direct messages did before there was a
                // switch. Channels have carried the same setting since they
                // arrived, defaulting off — the asymmetry is deliberate: a
                // message addressed to you is worth interrupting for, and a
                // channel's traffic is not until its owner says so.
                try execute(
                    database,
                    sql: """
                    ALTER TABLE direct_conversation
                        ADD COLUMN notifications_enabled INTEGER NOT NULL DEFAULT 1;

                    PRAGMA user_version = 21;
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
            throw Self.sqliteFailure(database, status)
        }
        defer { sqlite3_finalize(statement) }
        guard sqlite3_step(statement) == SQLITE_ROW else {
            throw Self.sqliteFailure(database, sqlite3_errcode(database))
        }
        return sqlite3_column_int(statement, 0)
    }

    private static func execute(_ database: OpaquePointer, sql: String) throws {
        let status = sqlite3_exec(database, sql, nil, nil, nil)
        guard status == SQLITE_OK else {
            throw Self.sqliteFailure(database, status)
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
