import Foundation
import UMSHMobileCore

enum ApplicationStoreError: Error, Equatable, Sendable {
    case applicationSupportUnavailable
    case openFailed(Int32)
    case recordNotFound
    /// A channel ID that is not a UUID, or a router hint that is not two
    /// octets.
    case invalidArgument
    /// SQLite's extended result code plus its own account of it. The code
    /// alone says only that something was refused; the message names the
    /// column, table or constraint, which is the difference between a usable
    /// report and a guess.
    /// Code 0 is a row the store could not read back.
    case sqliteFailure(Int32, message: String)
    case unsupportedSchema(Int32)
}

extension ApplicationStoreError {
    init(_ error: MobileStoreError) {
        switch error {
        case .OpenFailed(let code): self = .openFailed(code)
        case .UnsupportedSchema(let version): self = .unsupportedSchema(Int32(clamping: version))
        case .RecordNotFound: self = .recordNotFound
        case .InvalidArgument: self = .invalidArgument
        case .Failed(let code, let detail): self = .sqliteFailure(code, message: detail)
        }
    }

    /// Enough detail to act on in a bug report, without leaking record content.
    var diagnosticDescription: String {
        switch self {
        case .applicationSupportUnavailable:
            "The Application Support directory is unavailable."
        case .openFailed(let code):
            "Opening the database failed with code \(code)."
        case .recordNotFound:
            "The record being updated no longer exists."
        case .invalidArgument:
            "A value passed to the store is malformed."
        case .sqliteFailure(let code, let message):
            "SQLite returned code \(code): \(message)."
        case .unsupportedSchema(let version):
            "The database is at schema version \(version), which this build cannot open."
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
    /// When `advertisement` was heard off the air. `nil` for a bundle that
    /// was imported: nothing about how it arrived dates what it says.
    let advertisementReceivedAt: Date?
}

/// What a remote device said it is, kept between openings of its settings.
///
/// The four things worth learning once: a device's capabilities and firmware
/// version change only when it is reflashed, its hardware never, and its name
/// rarely. Holding them means the second and every later open of a device's
/// settings puts nothing on the air at all—which over five flood hops is
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

/// One neighbor a router reported, as the page carried it.
///
/// Stored decoded rather than as the wire entry: the fields are few and
/// fixed, the map reads them without a decoder in the loop, and the location
/// arrives from the core already reduced to a center and a precision.
struct StoredPeerRepeaterEntry: Equatable, Sendable {
    /// Two or three bytes; the row's key within the router's listing.
    let hint: Data
    let name: String?
    let rssiDBm: Int16?
    let snrQuarterDB: Int16?
    let lastHeardMinutes: UInt16?
    let latitude: Double?
    let longitude: Double?
    let locationPrecision: UInt8?
    let regionCodes: [Data]
    /// When the page naming this neighbor was answered.
    let reportedAt: Date
}

/// What a router last said about its neighbors, as far as this phone asked.
///
/// The cursor is kept so the next open can carry on where the last page
/// stopped rather than starting the listing over—the ask is the operator's
/// to make, and the cache should make it cheap to make the right one.
struct StoredPeerRepeaterListing: Equatable, Sendable {
    let entries: [StoredPeerRepeaterEntry]
    let total: Int?
    let nextCursor: Data?
    let asOf: Date
}

/// A path the person chose for one node, held until `holdUntil`.
struct StoredManualRoute: Equatable, Sendable {
    let publicAddress: String
    /// Two-byte router hints, in send order. None is a direct path.
    let hints: [Data]
    /// How far the path floods past its last repeater.
    let floodHops: UInt8
    let holdUntil: Date
    /// Where the phone stood when the path was saved, if it knew.
    let savedLatitude: Double?
    let savedLongitude: Double?
    /// Horizontal accuracy of that fix, in meters.
    let savedAccuracy: Double?
    /// The offer to switch to a learned path was declined.
    let promptSettled: Bool
}

/// A radio that took this phone's identity as its host and has not been
/// seen to let it go.
struct StoredClaimedRadio: Equatable, Sendable {
    /// After this long the radio has stood down on its own, so the record
    /// lapses: the device lease runs this long from detach. The core's
    /// figure, which its own lapse check uses.
    static let lapse = TimeInterval(claimedRadioLapseMs()) / 1_000

    /// The radio's device address.
    let deviceAddress: String
    let name: String?
    /// The last time this phone was attached to it.
    let attachedAt: Date
}

/// A neighbor entry with the row of the router that reported it.
struct StoredPeerRepeaterReport: Equatable, Sendable {
    let reporterNodeID: Int64
    let entry: StoredPeerRepeaterEntry
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
    /// Status text, which reads as its sender's name followed by its body.
    let isStatus: Bool
}

struct StoredDirectConversation: Equatable, Sendable {
    let id: Int64
    let node: StoredNode
    let draftText: String
    /// When this conversation was last read. Messages newer than this are
    /// unread; a conversation the user has never opened reads as all-unread
    /// from its first message.
    let lastReadAtMilliseconds: Int64
    /// When the conversation row was created—the activity time of a
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
    /// When the conversation row was created—the activity time of a
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
    /// Status text, which reads as its sender's name followed by its body.
    let isStatus: Bool
}

/// An inbound reaction worth telling the user about: who put what on which
/// message of theirs.
struct ChatReactionNotificationTarget: Equatable, Sendable {
    let conversationAddress: String
    /// The reaction body as it arrived—a wire token like `<3`, rendered to
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
    /// It never went out where the peer could read it, rather than going
    /// out and drawing no acknowledgment.
    let undelivered: Bool
}

/// How a channel's key was established, which decides what may be shared.
enum StoredChannelKind: String, Equatable, Sendable {
    /// `public` or `EMERGENCY`: named channels the protocol fixes rules for.
    /// These rows are never deleted—leaving clears the joined flags so the
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
    /// Three presentation octets—the identifier extended by one byte—kept
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
    /// Ordered-repair presence: 0 = present, 1 = gap under repair, 2 =
    /// unavailable, 3 = gap waiting for the user.
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
    /// message's keyset cursor. Ordering key only—`(sessionID, handle)`
    /// remains the durable identity.
    let rowID: Int64
    /// An outbound message whose acknowledgment came back through the flood
    /// that followed a missed route.
    var deliveredFlooded: Bool = false
    /// Reactions about this message, at most one per sender, oldest first.
    /// Folded at read time from the emote rows that name it—they are
    /// messages in their own right, but never transcript rows.
    var reactions: [StoredMessageReaction] = []
    /// Whether this message replies to another.
    var isReply = false
    /// Came as an edit of a message this phone does not hold.
    var isEditOfUnknown = false
    /// Status text, which reads as its sender's name followed by its body,
    /// with no bubble.
    var isStatus = false
    /// Mine, and what it reads went under a session with forward secrecy.
    var isForwardSecret = false
    /// The stored row it replies to, once that has been found.
    var replyTarget: StoredMessageRef?
    /// What it replies to, as it reads now: read with the page, so an edit
    /// or a deletion of the original shows in every quote of it.
    var quote: StoredMessageQuote?
    /// The repeaters heard carrying an outbound message, once any of it has
    /// been sent.
    var repeats: StoredMessageRepeats?

    var isGapPlaceholder: Bool { presence == 1 || presence == 3 }
    /// A gap no repair is under way for, which waits for the user to ask.
    var isGapIdle: Bool { presence == 3 }
    var isUnavailable: Bool { presence == 2 }

    var cursor: ChatMessageCursor {
        ChatMessageCursor(createdAtMilliseconds: createdAtMilliseconds, rowID: rowID)
    }

    /// Whether a stored delivery state is a failure: 'undelivered' (it did
    /// not arrive) or 'failed' (it went out unacknowledged and may have).
    static func isDeliveryFailure(_ state: String?) -> Bool {
        switch state?.lowercased() {
        case "failed", "undelivered": true
        default: false
        }
    }
}

/// Where one message sits in its conversation's storage order.
///
/// `(created_at_ms, rowid)` is exactly the transcript's ORDER BY, so a cursor
/// names a row rather than an offset: a page boundary stays put when older
/// messages are repaired in behind it. The rowid half is load-bearing rather
/// than defensive—a mutation batch is stamped from one clock read, so several
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

/// One loaded slice of a transcript, oldest first—the order it renders in.
/// The flags describe what storage holds beyond the slice, so a reader knows
/// whether there is more to page toward in either direction.
struct StoredChatMessagePage: Equatable, Sendable {
    let messages: [StoredChatMessage]
    let hasOlder: Bool
    let hasNewer: Bool

    static let empty = StoredChatMessagePage(messages: [], hasOlder: false, hasNewer: false)
}

/// The repeaters overheard carrying an outbound message.
struct StoredMessageRepeats: Hashable, Sendable {
    /// Two-byte hints of the repeaters that named themselves, first heard
    /// first.
    let repeaters: [Data]
    /// Repeaters heard that did not.
    let anonymous: Int
    /// When the message's delivery last moved: its first frame going out, or
    /// a repeater being heard.
    let progressAt: Date

    var count: Int { repeaters.count + anonymous }
}

/// A stored message's durable identity.
struct StoredMessageRef: Hashable, Sendable {
    let sessionID: String
    let handle: UInt32

    var id: String { "\(sessionID):\(handle)" }
}

/// What a reply quotes of the message it answers.
struct StoredMessageQuote: Hashable, Sendable {
    /// The original, while it is stored and present; `nil` when it never
    /// arrived, is no longer kept, or was lost to a gap.
    let original: Original?

    struct Original: Hashable, Sendable {
        let ref: StoredMessageRef
        let body: String
        let outbound: Bool
        let isDeleted: Bool
        let senderAddress: String?
        let senderHint: Data?
        let senderHandle: String?
    }

    static let unavailable = StoredMessageQuote(original: nil)
}

/// One person's reaction to one message.
///
/// Carries its own durable identity because it is a message: the sender may
/// replace it, and an outbound one is delivered and acknowledged like
/// anything else, which is what lets the transcript show a reaction that has
/// not reached anyone yet.
struct StoredMessageReaction: Hashable, Sendable {
    /// The emote body as it arrived—a short token, not necessarily an
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
    /// Mine, and it went under a session with forward secrecy.
    var forwardSecret = false
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
    /// What it replies to, when it is a reply.
    var regarding: StagedRegarding? = nil
    /// Taken back by its sender: a tombstone, with nothing left to say.
    var isDeleted = false
}

/// What a staged reply answers.
enum StagedRegarding {
    /// Another message of the same staged transcript, by handle.
    case message(UInt32)
    /// One this phone never stored.
    case missing
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

/// Everything the interface lists, read together so a concurrent writer
/// cannot produce a mixture of old and new lists.
///
/// This store contains public application records only. Private identity and
/// channel key bytes are never accepted by this API and remain in Keychain.
struct ApplicationRecords: Sendable {
    let peers: [StoredNode]
    let channels: [StoredChannel]
    let conversations: [StoredDirectConversation]
    let channelConversations: [StoredChannelConversation]
    let reports: [StoredPeerRepeaterReport]
}

/// The application database, kept by the shared Rust store
/// (`MobileAppStore` in `umsh-mobile-core`), which Android uses too.
///
/// This actor only adapts: Swift types and `Date`s on this side, the core's
/// records and millisecond instants on the other. Writes that need the time
/// are stamped here, from the clock, as the Swift store stamped them.
actor SQLiteApplicationStore {
    private let store: MobileAppStore

    init(path: String) throws {
        store = try Self.mapped { try MobileAppStore.open(path: path) }
    }

    /// One read transaction in the core.
    func applicationRecords(ownerIdentityID: String, conversationsOnly: Bool = false) throws -> ApplicationRecords {
        let records = try run {
            try $0.applicationRecords(ownerIdentityId: ownerIdentityID, conversationsOnly: conversationsOnly)
        }
        return ApplicationRecords(
            peers: records.peers.map(StoredNode.init),
            channels: records.channels.compactMap(StoredChannel.init),
            conversations: records.conversations.map(StoredDirectConversation.init),
            channelConversations: records.channelConversations.compactMap(StoredChannelConversation.init),
            reports: records.reports.map(StoredPeerRepeaterReport.init)
        )
    }

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
        try run { try $0.eraseAllContent() }
    }

    func schemaVersion() throws -> Int32 {
        Int32(clamping: try run { try $0.schemaVersion() })
    }

    // MARK: Identity and peers

    func insertIdentity(id: String, publicAddress: String, createdAt: Date = .now) throws {
        try run {
            try $0.insertIdentity(id: id, publicAddress: publicAddress, createdAtMs: createdAt.storeMilliseconds)
        }
    }

    func upsertIdentity(id: String, publicAddress: String, createdAt: Date = .now) throws {
        try run {
            try $0.upsertIdentity(id: id, publicAddress: publicAddress, createdAtMs: createdAt.storeMilliseconds)
        }
    }

    /// Whether this store already holds records for the given identity.
    ///
    /// Asked when a Keychain identity turns up with no anchor beside it: a
    /// container that still has this identity's row is that identity's
    /// container, anchor or no anchor, and there is nothing to ask about.
    /// The legacy `'primary'` slot counts, since a store written before the
    /// address became the key is still this identity's store.
    func knowsIdentity(id: String, publicAddress: String) throws -> Bool {
        try run { try $0.knowsIdentity(id: id, publicAddress: publicAddress) }
    }

    /// `nodeKind` is a ``PeerRole`` raw value and `systemRole` is
    /// `companion_radio`; anything else is stored as absent.
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
        advertisementAuthenticated: Bool = false,
        advertisementReceivedAt: Date? = nil
    ) throws {
        let peer = MobilePeerUpsertRecord(
            alias: alias,
            advertisedName: advertisedName,
            isSaved: isSaved,
            nodeKind: nodeKind.flatMap(MobileStoredNodeKind.init(storedText:)),
            systemRole: systemRole.flatMap(MobileStoredSystemRole.init(storedText:)),
            radioIdentifier: radioIdentifier,
            advertisement: advertisement,
            advertisementAuthenticated: advertisementAuthenticated,
            advertisementReceivedAtMs: advertisementReceivedAt?.storeMilliseconds
        )
        try run { try $0.upsertPeer(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress, peer: peer) }
    }

    func localAdvertisedName(ownerIdentityID: String) throws -> String? {
        try run { try $0.localAdvertisedName(ownerIdentityId: ownerIdentityID) }
    }

    func updateLocalAdvertisedName(ownerIdentityID: String, name: String?) throws {
        try run { try $0.updateLocalAdvertisedName(ownerIdentityId: ownerIdentityID, name: name) }
    }

    func updateNodeAlias(
        ownerIdentityID: String,
        publicAddress: String,
        alias: String?
    ) throws {
        try run { try $0.updateNodeAlias(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress, alias: alias) }
    }

    func setPeerFavorite(
        ownerIdentityID: String,
        publicAddress: String,
        isFavorite: Bool
    ) throws {
        try run {
            try $0.setPeerFavorite(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress, isFavorite: isFavorite)
        }
    }

    /// Record a transient node on the local identity, making it visible in
    /// the main Peers list.
    func promotePeerToSaved(ownerIdentityID: String, publicAddress: String) throws {
        try run { try $0.promotePeerToSaved(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress) }
    }

    /// Remove a node from the local identity without touching its history:
    /// the row stays as a transient (searchable, discoverable) and any
    /// conversation keeps working. Favorite and alias are local statements
    /// about a saved peer, so they clear with it. Refuses the
    /// companion radio, whose row is system-managed.
    func demotePeerToTransient(ownerIdentityID: String, publicAddress: String) throws {
        try run { try $0.demotePeerToTransient(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress) }
    }

    @discardableResult
    func deletePeer(ownerIdentityID: String, publicAddress: String) throws -> Bool {
        try run { try $0.deletePeer(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress) }
    }

    @discardableResult
    func deletePeerAndConversation(
        ownerIdentityID: String,
        publicAddress: String
    ) throws -> Bool {
        try run { try $0.deletePeerAndConversation(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress) }
    }

    /// Drop every transient row that nothing else depends on: saved peers,
    /// the companion radio, rows on the device identity, rows with a
    /// conversation, and rows carrying a pending watch all stay.
    func clearTransientPeers(ownerIdentityID: String) throws {
        try run { try $0.clearTransientPeers(ownerIdentityId: ownerIdentityID) }
    }

    /// Keep the transient tier bounded: beyond `cap` rows, the oldest-heard
    /// evictable transients are dropped. Rows with a conversation, on the
    /// device identity, with a system role, or carrying a pending watch are
    /// never evicted—a watch that the cap quietly deleted would be a
    /// promise the app stopped keeping without saying so.
    func enforceTransientRetention(ownerIdentityID: String, cap: Int = 256) throws {
        try run { try $0.enforceTransientRetention(ownerIdentityId: ownerIdentityID, cap: UInt32(clamping: cap)) }
    }

    /// Make the local cache of the radio's device-identity peer list match
    /// the device's read-back. The device is the authority: flags clear
    /// where it no longer holds a key, set where it does, and unknown keys
    /// gain a transient row carrying the flag so lists can show them.
    func reconcileDeviceIdentityPeers(ownerIdentityID: String, addresses: [String]) throws {
        try run { try $0.reconcileDeviceIdentityPeers(ownerIdentityId: ownerIdentityID, addresses: addresses) }
    }

    /// Cache one device-identity membership change after a confirmed radio
    /// mutation, without waiting for the next attach-edge reconcile.
    func setPeerOnDeviceIdentity(
        ownerIdentityID: String,
        publicAddress: String,
        isOnDeviceIdentity: Bool
    ) throws {
        try run {
            try $0.setPeerOnDeviceIdentity(
                ownerIdentityId: ownerIdentityID,
                publicAddress: publicAddress,
                isOnDeviceIdentity: isOnDeviceIdentity
            )
        }
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
        try run { try $0.setNotifyWhenHeard(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress, enabled: enabled) }
    }

    /// Record that the node was heard at `instant`. Returns whether that
    /// fired its one-shot watch.
    @discardableResult
    func touchLastHeard(
        ownerIdentityID: String,
        publicAddress: String,
        at instant: Date
    ) throws -> Bool {
        try run {
            try $0.touchLastHeard(
                ownerIdentityId: ownerIdentityID,
                publicAddress: publicAddress,
                atMs: instant.storeMilliseconds
            )
        }
    }

    func upsertUlcpDevicePeer(
        ownerIdentityID: String,
        publicAddress: String,
        advertisedName: String?,
        radioIdentifier: String
    ) throws {
        try run {
            try $0.upsertUlcpDevicePeer(
                ownerIdentityId: ownerIdentityID,
                publicAddress: publicAddress,
                advertisedName: advertisedName,
                radioIdentifier: radioIdentifier
            )
        }
    }

    func listNodes(ownerIdentityID: String) throws -> [StoredNode] {
        try run { try $0.listNodes(ownerIdentityId: ownerIdentityID) }.map(StoredNode.init)
    }

    // MARK: Channels

    func channels(ownerIdentityID: String) throws -> [StoredChannel] {
        try run { try $0.channels(ownerIdentityId: ownerIdentityID) }.compactMap(StoredChannel.init)
    }

    /// The channel this identity already holds under `keyDigest`, if any.
    ///
    /// Import checks this before inserting so a re-scanned invitation updates
    /// the existing channel instead of creating a second one for the same key.
    func channel(ownerIdentityID: String, keyDigest: String) throws -> StoredChannel? {
        try run { try $0.channel(ownerIdentityId: ownerIdentityID, keyDigest: keyDigest) }
            .flatMap(StoredChannel.init)
    }

    func insertChannel(_ channel: StoredChannel, keyDigest: String) throws {
        try run {
            try $0.insertChannel(
                channel: MobileStoredChannelRecord(channel),
                keyDigest: keyDigest,
                createdAtMs: Date.now.storeMilliseconds
            )
        }
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
        try run {
            try $0.updateChannelDetails(
                id: id.uuidString,
                alias: alias,
                regionCode: regionCode,
                maxFloodHops: maxFloodHops.map { UInt8(clamping: $0) },
                notificationsEnabled: notificationsEnabled
            )
        }
    }

    /// Record which identities have joined. `joinedAt` is stamped the first
    /// time the phone joins and left alone after.
    func setChannelMembership(id: UUID, joinedPhone: Bool, joinedDevice: Bool) throws {
        try run {
            try $0.setChannelMembership(
                id: id.uuidString,
                joinedPhone: joinedPhone,
                joinedDevice: joinedDevice,
                nowMs: Date.now.storeMilliseconds
            )
        }
    }

    /// Forget a channel. Its transcript stays: delete the conversation first
    /// with ``deleteChannelConversation(ownerIdentityID:conversationID:)``.
    func deleteChannel(id: UUID) throws {
        try run { try $0.deleteChannel(id: id.uuidString) }
    }

    // MARK: Conversations

    func ensureDirectConversation(
        ownerIdentityID: String,
        peerAddress: String
    ) throws -> Int64 {
        try run {
            try $0.ensureDirectConversation(
                ownerIdentityId: ownerIdentityID,
                peerAddress: peerAddress,
                createdAtMs: Date.now.storeMilliseconds
            )
        }
    }

    func listDirectConversations(ownerIdentityID: String) throws -> [StoredDirectConversation] {
        try run { try $0.listDirectConversations(ownerIdentityId: ownerIdentityID) }
            .map(StoredDirectConversation.init)
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
        try run {
            try $0.ensureChannelConversation(
                ownerIdentityId: ownerIdentityID,
                channelId: channelID.uuidString,
                conversationAddress: conversationAddress,
                createdAtMs: Date.now.storeMilliseconds
            )
        }
    }

    func listChannelConversations(
        ownerIdentityID: String
    ) throws -> [StoredChannelConversation] {
        try run { try $0.listChannelConversations(ownerIdentityId: ownerIdentityID) }
            .compactMap(StoredChannelConversation.init)
    }

    /// Remove a channel conversation and its local transcript. Leaving a group
    /// chat is not leaving the channel: the key stays, so traffic still
    /// arrives and a later message opens the conversation again.
    func deleteChannelConversation(ownerIdentityID: String, conversationID: Int64) throws {
        try run { try $0.deleteChannelConversation(ownerIdentityId: ownerIdentityID, conversationId: conversationID) }
    }

    /// Erase a conversation's messages while keeping the conversation itself.
    /// Addressed rather than keyed by row so one call serves both kinds.
    ///
    /// Outbound stream checkpoints are kept, for the same reason deleting a
    /// conversation keeps them: sequence continuity with the far end has to
    /// outlive the transcript, or the next message would announce a Sequence
    /// Reset. Archived outbound payloads do go, so a later resend request for
    /// a cleared message is answered Unavailable—the protocol handles that,
    /// and keeping erased content on disk would not be acceptable.
    func clearConversationMessages(
        ownerIdentityID: String,
        conversationAddress: String
    ) throws {
        try run {
            try $0.clearConversationMessages(ownerIdentityId: ownerIdentityID, conversationAddress: conversationAddress)
        }
    }

    func updateChannelDraft(
        ownerIdentityID: String,
        conversationID: Int64,
        text: String
    ) throws {
        try run { try $0.updateChannelDraft(ownerIdentityId: ownerIdentityID, conversationId: conversationID, text: text) }
    }

    /// Mark everything in a conversation read as of now. Addressed rather than
    /// keyed by row so one call serves both kinds of conversation.
    func markConversationRead(ownerIdentityID: String, conversationAddress: String) throws {
        try run {
            try $0.markConversationRead(
                ownerIdentityId: ownerIdentityID,
                conversationAddress: conversationAddress,
                readAtMs: Date.now.storeMilliseconds
            )
        }
    }

    /// Fill in the sender of group messages stored before that member's hint
    /// resolved to a real address. Rows that already name a sender are left
    /// alone—the first attribution seen for a hint is the one kept.
    func applySenderResolution(
        ownerIdentityID: String,
        conversationAddress: String,
        senderHint: Data,
        senderAddress: String
    ) throws {
        let resolution = MobileChatSenderResolutionRecord(
            conversationAddress: conversationAddress,
            senderHint: senderHint,
            senderAddress: senderAddress
        )
        try run { try $0.applySenderResolution(ownerIdentityId: ownerIdentityID, resolution: resolution) }
    }

    /// Remove a conversation and its local history. Outbound stream
    /// checkpoints are deliberately retained: sequence continuity with the
    /// peer must survive the transcript, or the next message would announce
    /// a Sequence Reset. Archived outbound payloads go with the history, so
    /// a late resend request for them is answered Unavailable—the protocol
    /// handles that; keeping deleted content on disk would not be acceptable.
    func deleteDirectConversation(ownerIdentityID: String, conversationID: Int64) throws {
        try run { try $0.deleteDirectConversation(ownerIdentityId: ownerIdentityID, conversationId: conversationID) }
    }

    /// Turn notifications for one direct conversation on or off.
    func setDirectConversationNotifications(
        ownerIdentityID: String,
        conversationID: Int64,
        enabled: Bool
    ) throws {
        try run {
            try $0.setDirectConversationNotifications(
                ownerIdentityId: ownerIdentityID,
                conversationId: conversationID,
                enabled: enabled
            )
        }
    }

    func updateDraft(ownerIdentityID: String, conversationID: Int64, text: String) throws {
        try run { try $0.updateDraft(ownerIdentityId: ownerIdentityID, conversationId: conversationID, text: text) }
    }

    // MARK: Device management cache

    /// What a device last said it is, if this phone has ever asked.
    func managementCard(
        ownerIdentityID: String,
        publicAddress: String
    ) throws -> StoredManagementCard? {
        try run { try $0.managementCard(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress) }
            .map(StoredManagementCard.init)
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
        try run {
            try $0.saveManagementCard(
                ownerIdentityId: ownerIdentityID,
                publicAddress: publicAddress,
                card: MobileStoredManagementCardRecord(card)
            )
        }
    }

    /// Forget everything cached about a device, so the next open asks it
    /// afresh. The card goes too: a refresh that cannot be trusted to be
    /// about the same firmware is not a refresh.
    func forgetManagementCache(ownerIdentityID: String, publicAddress: String) throws {
        try run { try $0.forgetManagementCache(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress) }
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
        try run {
            try $0.cachedProperties(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress, propertyIds: propertyIDs)
        }
        .mapValues(StoredCachedProperty.init)
    }

    /// Record values a device reported—from a read, or from the echo a
    /// write comes back with, which is the freshest statement of what the
    /// device is actually holding.
    func saveCachedProperties(
        ownerIdentityID: String,
        publicAddress: String,
        values: [UInt32: Data],
        at instant: Date
    ) throws {
        try run {
            try $0.saveCachedProperties(
                ownerIdentityId: ownerIdentityID,
                publicAddress: publicAddress,
                values: values,
                atMs: instant.roundedStoreMilliseconds
            )
        }
    }

    // MARK: Manual routes

    /// The path held for one node, or `nil` when none is held at `now`.
    func manualRoute(
        ownerIdentityID: String,
        publicAddress: String,
        now: Date = Date()
    ) throws -> StoredManualRoute? {
        try run {
            try $0.manualRoute(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress, nowMs: now.roundedStoreMilliseconds)
        }
        .map(StoredManualRoute.init)
    }

    /// Every path still held at `now`, forgetting those whose hold has ended.
    func manualRoutes(ownerIdentityID: String, now: Date = Date()) throws -> [StoredManualRoute] {
        try run { try $0.manualRoutes(ownerIdentityId: ownerIdentityID, nowMs: now.roundedStoreMilliseconds) }
            .map(StoredManualRoute.init)
    }

    /// Hold `hints` for one node until `holdUntil`, replacing any path held
    /// for it. A new path is a new choice, so a declined offer to switch
    /// away from the old one does not carry over. A node with no row has
    /// nowhere to keep it. Every hint must be two octets.
    func saveManualRoute(
        ownerIdentityID: String,
        publicAddress: String,
        hints: [Data],
        floodHops: UInt8,
        holdUntil: Date,
        latitude: Double?,
        longitude: Double?,
        accuracy: Double?
    ) throws {
        try run {
            try $0.saveManualRoute(
                ownerIdentityId: ownerIdentityID,
                publicAddress: publicAddress,
                hints: hints,
                floodHops: floodHops,
                holdUntilMs: holdUntil.roundedStoreMilliseconds,
                latitude: latitude,
                longitude: longitude,
                accuracy: accuracy
            )
        }
    }

    func clearManualRoute(ownerIdentityID: String, publicAddress: String) throws {
        try run { try $0.clearManualRoute(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress) }
    }

    /// Remember that the offer to switch away from this node's path was
    /// declined, so it is not made again for the same path.
    func settleManualRoutePrompt(ownerIdentityID: String, publicAddress: String) throws {
        try run { try $0.settleManualRoutePrompt(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress) }
    }

    // MARK: Claimed radios

    /// Note that this phone is attached to the radio at `deviceAddress` as
    /// its host, as of `now`.
    func recordClaimedRadio(
        ownerIdentityID: String,
        deviceAddress: String,
        name: String?,
        now: Date = Date()
    ) throws {
        try run {
            try $0.recordClaimedRadio(
                ownerIdentityId: ownerIdentityID,
                deviceAddress: deviceAddress,
                name: name,
                nowMs: now.roundedStoreMilliseconds
            )
        }
    }

    /// Every radio still recorded as holding this identity, forgetting
    /// those whose record has lapsed by `now`. Most recent first.
    func claimedRadios(ownerIdentityID: String, now: Date = Date()) throws -> [StoredClaimedRadio] {
        try run { try $0.claimedRadios(ownerIdentityId: ownerIdentityID, nowMs: now.roundedStoreMilliseconds) }
            .map(StoredClaimedRadio.init)
    }

    /// Forget the record of a radio: it let go of this identity, or is no
    /// longer holding it.
    func clearClaimedRadio(ownerIdentityID: String, deviceAddress: String) throws {
        try run { try $0.clearClaimedRadio(ownerIdentityId: ownerIdentityID, deviceAddress: deviceAddress) }
    }

    // MARK: Repeater listings

    /// What a router last said about its neighbors, or `nil` when it was
    /// never asked. Entries come back in the order the router listed them.
    func peerRepeaterListing(
        ownerIdentityID: String,
        publicAddress: String
    ) throws -> StoredPeerRepeaterListing? {
        try run { try $0.peerRepeaterListing(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress) }
            .map(StoredPeerRepeaterListing.init)
    }

    /// Record one page of a router's neighbor listing.
    ///
    /// A page asked for without a cursor is the top of a fresh listing and
    /// replaces whatever was held. A page that followed a cursor is added to
    /// it: new neighbors take their place at the end, and a neighbor the
    /// router named again—the responder restarts a listing whose table has
    /// moved under a stale cursor—updates in place rather than appearing
    /// twice. Either way the cursor and the instant are the latest page's.
    func savePeerRepeaterPage(
        ownerIdentityID: String,
        publicAddress: String,
        entries: [StoredPeerRepeaterEntry],
        total: Int?,
        nextCursor: Data?,
        replacing: Bool,
        at instant: Date
    ) throws {
        try run {
            try $0.savePeerRepeaterPage(
                ownerIdentityId: ownerIdentityID,
                publicAddress: publicAddress,
                entries: entries.map(MobileStoredPeerRepeaterEntryRecord.init),
                total: total.map(Int64.init),
                nextCursor: nextCursor,
                replacing: replacing,
                atMs: instant.roundedStoreMilliseconds
            )
        }
    }

    /// Every neighbor any router has reported to this phone, with the row of
    /// the router that said so. What the map draws.
    func allPeerRepeaterEntries(ownerIdentityID: String) throws -> [StoredPeerRepeaterReport] {
        try run { try $0.allPeerRepeaterEntries(ownerIdentityId: ownerIdentityID) }
            .map(StoredPeerRepeaterReport.init)
    }

    // MARK: Chat

    /// Resolve the peer a locally-stored message belongs to, keyed by its
    /// durable `(sessionID, handle)`. Used to attribute delivery acks—which
    /// carry no address of their own—back to a conversation for last-heard
    /// bookkeeping.
    func conversationAddressForMessage(
        ownerIdentityID: String,
        sessionID: UInt64,
        handle: UInt32
    ) throws -> String? {
        try run {
            try $0.conversationAddressForMessage(ownerIdentityId: ownerIdentityID, sessionId: sessionID, handle: handle)
        }
    }

    /// The persisted conversation address, sender, and body of an inbound,
    /// displayable message, for raising a notification. Returns `nil` for
    /// outbound rows, tombstones, gap placeholders, unavailable markers, or
    /// empty bodies—nothing worth alerting the user about. Resolves every
    /// field from storage so a notify carried on an `UpdateBody` (which omits
    /// them) still works.
    func chatNotificationTarget(
        ownerIdentityID: String,
        sessionID: UInt64,
        handle: UInt32
    ) throws -> ChatNotificationTarget? {
        try run { try $0.chatNotificationTarget(ownerIdentityId: ownerIdentityID, sessionId: sessionID, handle: handle) }
            .map(ChatNotificationTarget.init)
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
        try run {
            try $0.chatReactionNotificationTarget(ownerIdentityId: ownerIdentityID, sessionId: sessionID, handle: handle)
        }
        .map(ChatReactionNotificationTarget.init)
    }

    func chatCheckpoints(ownerIdentityID: String) throws -> [MobileChatCheckpointRecord] {
        try run { try $0.chatCheckpoints(ownerIdentityId: ownerIdentityID) }
    }

    /// The checkpoint and exact resend material are one durable commit. The
    /// caller may release the corresponding Rust batch only after this returns.
    func commitChatComposeBatch(
        ownerIdentityID: String,
        batch: MobileChatComposeBatchRecord
    ) throws {
        try run {
            try $0.commitChatComposeBatch(ownerIdentityId: ownerIdentityID, batch: batch, nowMs: Date.now.storeMilliseconds)
        }
    }

    /// Apply one batch of the engine's mutations in one transaction, and
    /// return those still worth a notification.
    @discardableResult
    func applyChatMutations(
        ownerIdentityID: String,
        mutations: [MobileChatMutationRecord],
        silentTestsIn: String? = nil
    ) throws -> [MobileChatMutationRecord] {
        try run {
            try $0.applyChatMutations(
                ownerIdentityId: ownerIdentityID,
                mutations: mutations,
                nowMs: Date.now.storeMilliseconds,
                silentTestsIn: silentTestsIn
            )
        }
    }

    /// Apply delivery evidence, and return the messages whose delivery was
    /// just given up on.
    @discardableResult
    func applyChatDeliveries(
        ownerIdentityID: String,
        deliveries: [MobileChatDeliveryRecord]
    ) throws -> [ChatDeliveryFailure] {
        try run {
            try $0.applyChatDeliveries(
                ownerIdentityId: ownerIdentityID,
                deliveries: deliveries,
                nowMs: Date.now.storeMilliseconds
            )
        }
        .map(ChatDeliveryFailure.init)
    }

    /// Record the repeaters overheard carrying our frames.
    ///
    /// Each record is one transmission's whole tally, and a fragment sent
    /// again starts a fresh one, so a fragment keeps the union of the
    /// repeaters every transmission of it named, and the most any of them
    /// heard anonymously. A message's delivery is stamped as having moved
    /// whenever one of its fragments gains a repeater.
    func applyChatRepeats(
        ownerIdentityID: String,
        repeats: [MobileChatRepeatRecord]
    ) throws {
        try run {
            try $0.applyChatRepeats(ownerIdentityId: ownerIdentityID, repeats: repeats, nowMs: Date.now.storeMilliseconds)
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
        try run { try $0.markChatComposeBatchFailed(ownerIdentityId: ownerIdentityID, batch: batch) }
    }

    /// Remove a failed outbound message outright, because its text just went
    /// back on the air as a genuinely new message: keeping the dead row would
    /// show the same words twice, once red and once delivered.
    ///
    /// Local only, and deliberately narrow—the guards make this a no-op on
    /// anything but a failed outbound row, so a stale caller can never take
    /// down a message the mesh knows about. Reactions pointing at the row go
    /// with it (nobody ever received the message they decorate), as does the
    /// delivery evidence recorded under the row's pointer.
    func removeFailedMessage(
        ownerIdentityID: String,
        sessionID: String,
        handle: UInt32
    ) throws {
        try run {
            try $0.removeFailedMessage(
                ownerIdentityId: ownerIdentityID,
                message: MobileStoredChatMessageRefRecord(sessionId: sessionID, handle: handle)
            )
        }
    }

    /// Outbound messages still awaiting word at launch were sent by a previous
    /// process. Their in-flight transmissions died with that process and the
    /// replacement Rust session issues new session IDs, so no delivery
    /// evidence can ever arrive for them. One still 'pending' never went out:
    /// 'undelivered'. A direct one that reached 'sent' went on the air and may
    /// well have arrived, but its acknowledgment can no longer be heard:
    /// 'failed'. A channel message's 'sent' is already its last word.
    func settleInterruptedDeliveries(ownerIdentityID: String) throws {
        try run { try $0.settleInterruptedDeliveries(ownerIdentityId: ownerIdentityID) }
    }

    /// Resolve gap placeholders as unavailable: the named rows, or every gap
    /// when `rows` is nil. A gap belongs to the mesh session that saw it, so
    /// once that session is gone no repair will ever fill it.
    func resolveGapsUnavailable(
        ownerIdentityID: String,
        rows: [(sessionID: String, handle: UInt32)]? = nil
    ) throws {
        let references = rows?.map { MobileStoredChatMessageRefRecord(sessionId: $0.sessionID, handle: $0.handle) }
        try run { try $0.resolveGapsUnavailable(ownerIdentityId: ownerIdentityID, rows: references) }
    }

    func chatArchive(
        ownerIdentityID: String,
        lookup: MobileChatArchiveLookupRecord
    ) throws -> Data? {
        try run { try $0.chatArchive(ownerIdentityId: ownerIdentityID, lookup: lookup) }
    }

    /// What a resend of one of our messages puts back on the air: its
    /// archived fragments, less those already acknowledged under its current
    /// delivery pointer. Empty when nothing is archived under the wire ID the
    /// row carries—an edit's content lives under the edit's own ID, which the
    /// row does not keep—so the caller sends it as a new message instead.
    func chatResendFrames(
        ownerIdentityID: String,
        conversationAddress: String,
        sessionID: String,
        handle: UInt32,
        wireID: UInt8
    ) throws -> [MobileChatArchiveRecord] {
        try run {
            try $0.chatResendFrames(
                ownerIdentityId: ownerIdentityID,
                conversationAddress: conversationAddress,
                message: MobileStoredChatMessageRefRecord(sessionId: sessionID, handle: handle),
                wireId: wireID
            )
        }
    }

    /// Point each resent message's delivery at the transmission its frames
    /// went out under again, ahead of any word of them, and record whether
    /// they go under forward secrecy. What was acknowledged stays so; what
    /// was last said of the rest no longer holds.
    func applyChatResends(
        ownerIdentityID: String,
        resends: [MobileChatResendRecord]
    ) throws {
        try run {
            try $0.applyChatResends(ownerIdentityId: ownerIdentityID, resends: resends, nowMs: Date.now.storeMilliseconds)
        }
    }

    // MARK: Transcripts

    /// The newest `limit` messages in a conversation.
    func chatMessagePage(
        ownerIdentityID: String,
        conversationAddress: String,
        newest limit: Int
    ) throws -> StoredChatMessagePage {
        StoredChatMessagePage(try run {
            try $0.chatMessagePageNewest(
                ownerIdentityId: ownerIdentityID,
                conversationAddress: conversationAddress,
                limit: UInt32(clamping: limit)
            )
        })
    }

    /// The `limit` messages immediately older than `cursor`.
    func chatMessagePage(
        ownerIdentityID: String,
        conversationAddress: String,
        before cursor: ChatMessageCursor,
        limit: Int
    ) throws -> StoredChatMessagePage {
        StoredChatMessagePage(try run {
            try $0.chatMessagePageBefore(
                ownerIdentityId: ownerIdentityID,
                conversationAddress: conversationAddress,
                cursor: MobileStoredChatCursorRecord(cursor),
                limit: UInt32(clamping: limit)
            )
        })
    }

    /// The `limit` messages immediately newer than `cursor`—or starting at
    /// it, when `including` is set, which is how a window re-reads the extent
    /// it already holds.
    func chatMessagePage(
        ownerIdentityID: String,
        conversationAddress: String,
        after cursor: ChatMessageCursor,
        including: Bool = false,
        limit: Int
    ) throws -> StoredChatMessagePage {
        StoredChatMessagePage(try run {
            try $0.chatMessagePageAfter(
                ownerIdentityId: ownerIdentityID,
                conversationAddress: conversationAddress,
                cursor: MobileStoredChatCursorRecord(cursor),
                limit: UInt32(clamping: limit),
                including: including
            )
        })
    }

    /// The transcript around one message, for opening a search result in
    /// context. `nil` when that message is not in this conversation—a stale
    /// hit against a cleared transcript, which is not an error.
    func chatMessageWindow(
        ownerIdentityID: String,
        conversationAddress: String,
        around sessionID: String,
        handle: UInt32,
        radius: Int
    ) throws -> StoredChatMessagePage? {
        try run {
            try $0.chatMessageWindow(
                ownerIdentityId: ownerIdentityID,
                conversationAddress: conversationAddress,
                message: MobileStoredChatMessageRefRecord(sessionId: sessionID, handle: handle),
                radius: UInt32(clamping: radius)
            )
        }
        .map(StoredChatMessagePage.init)
    }

    /// Where a message sits in its conversation's order, by the durable
    /// identity the transcript knows it as.
    func chatMessageCursor(
        ownerIdentityID: String,
        conversationAddress: String,
        sessionID: String,
        handle: UInt32
    ) throws -> ChatMessageCursor? {
        try run {
            try $0.chatMessageCursor(
                ownerIdentityId: ownerIdentityID,
                conversationAddress: conversationAddress,
                message: MobileStoredChatMessageRefRecord(sessionId: sessionID, handle: handle)
            )
        }
        .map(ChatMessageCursor.init)
    }

    /// How many messages a conversation holds. Deliberately its own call: this
    /// is the one aggregate that has to walk the whole range, so it belongs
    /// where something asked for it rather than on the conversation list.
    func chatMessageCount(
        ownerIdentityID: String,
        conversationAddress: String
    ) throws -> Int {
        Int(try run { try $0.chatMessageCount(ownerIdentityId: ownerIdentityID, conversationAddress: conversationAddress) })
    }

    #if DEBUG
    /// Write one staged transcript exactly as described, reactions included.
    ///
    /// Separate from ``seedGeneratedMessages`` because the two answer different
    /// questions: that one wants volume and does not care what it says, this
    /// one wants a specific conversation to read plausibly in a screenshot, so
    /// every body, sender and instant is dictated by the caller.
    func seedStagedTranscript(
        ownerIdentityID: String,
        conversationAddress: String,
        sessionID: String,
        messages: [StagedMessage]
    ) throws {
        try run {
            try $0.seedStagedTranscript(
                ownerIdentityId: ownerIdentityID,
                conversationAddress: conversationAddress,
                sessionId: sessionID,
                messages: messages.map(MobileStagedChatMessageRecord.init)
            )
        }
    }

    /// Fill a conversation with generated messages, for exercising a transcript
    /// at a size no test account reaches by hand. Instants run back from now,
    /// with lulls of several hours, so the transcript spans days and carries
    /// the date separators a real one does.
    func seedGeneratedMessages(
        ownerIdentityID: String,
        conversationAddress: String,
        count: Int
    ) throws {
        try run {
            try $0.seedGeneratedMessages(
                ownerIdentityId: ownerIdentityID,
                conversationAddress: conversationAddress,
                count: UInt32(clamping: count),
                nowMs: Date.now.storeMilliseconds
            )
        }
    }
    #endif

    // MARK: Calling the core

    private func run<T>(_ work: (MobileAppStore) throws -> T) throws -> T {
        try Self.mapped { try work(store) }
    }

    private static func mapped<T>(_ work: () throws -> T) throws -> T {
        do {
            return try work()
        } catch let error as MobileStoreError {
            throw ApplicationStoreError(error)
        }
    }
}

// MARK: - Conversions

fileprivate extension Date {
    /// The core's instants are whole milliseconds since the Unix epoch.
    init(storeMilliseconds milliseconds: Int64) {
        self.init(timeIntervalSince1970: Double(milliseconds) / 1_000)
    }

    /// This instant with its fraction of a millisecond cut off. What every
    /// stamp uses except those below.
    var storeMilliseconds: Int64 {
        Int64(timeIntervalSince1970 * 1_000)
    }

    /// This instant to the nearest millisecond. The management cache,
    /// manual routes, claimed radios and repeater listings have always been
    /// stamped and compared this way, so their rows keep meaning the same.
    var roundedStoreMilliseconds: Int64 {
        Int64((timeIntervalSince1970 * 1_000).rounded())
    }
}

/// Stored as Swift's ``PeerRole`` raw values.
fileprivate extension MobileStoredNodeKind {
    init?(storedText: String) {
        switch storedText {
        case "repeater": self = .repeater
        case "chat": self = .chat
        case "tracker": self = .tracker
        case "sensor": self = .sensor
        case "bridge": self = .bridge
        case "chatRoom": self = .chatRoom
        case "temporarySession": self = .temporarySession
        case "unknown": self = .unknown
        default: return nil
        }
    }

    var storedText: String {
        switch self {
        case .repeater: "repeater"
        case .chat: "chat"
        case .tracker: "tracker"
        case .sensor: "sensor"
        case .bridge: "bridge"
        case .chatRoom: "chatRoom"
        case .temporarySession: "temporarySession"
        case .unknown: "unknown"
        }
    }
}

fileprivate extension MobileStoredSystemRole {
    init?(storedText: String) {
        switch storedText {
        case "companion_radio": self = .companionRadio
        default: return nil
        }
    }

    var storedText: String {
        switch self {
        case .companionRadio: "companion_radio"
        }
    }
}

fileprivate extension MobileStoredChatDeliveryState {
    init?(storedText: String) {
        switch storedText.lowercased() {
        case "pending": self = .pending
        case "sent": self = .sent
        case "acknowledged": self = .acknowledged
        case "failed": self = .failed
        case "undelivered": self = .undelivered
        default: return nil
        }
    }

    var storedText: String {
        switch self {
        case .pending: "pending"
        case .sent: "sent"
        case .acknowledged: "acknowledged"
        case .failed: "failed"
        case .undelivered: "undelivered"
        }
    }
}

extension StoredNode {
    fileprivate init(_ record: MobileStoredNodeRecord) {
        self.init(
            id: record.id,
            ownerIdentityID: record.ownerIdentityId,
            publicAddress: record.publicAddress,
            alias: record.alias,
            advertisedName: record.advertisedName,
            systemRole: record.systemRole?.storedText,
            nodeKind: record.nodeKind?.storedText,
            advertisement: record.advertisement,
            advertisementAuthenticated: record.advertisementAuthenticated,
            lastHeardAt: record.lastHeardAtMs.map(Date.init(storeMilliseconds:)),
            isSaved: record.isSaved,
            isFavorite: record.isFavorite,
            onDeviceIdentity: record.onDeviceIdentity,
            notifyWhenHeard: record.notifyWhenHeard,
            advertisementReceivedAt: record.advertisementReceivedAtMs.map(Date.init(storeMilliseconds:))
        )
    }
}

extension StoredManagementCard {
    fileprivate init(_ record: MobileStoredManagementCardRecord) {
        self.init(
            capabilities: record.capabilities,
            deviceVersion: record.deviceVersion,
            deviceModel: record.deviceModel,
            deviceName: record.deviceName,
            fetchedAt: Date(storeMilliseconds: record.fetchedAtMs)
        )
    }
}

extension MobileStoredManagementCardRecord {
    fileprivate init(_ card: StoredManagementCard) {
        self.init(
            capabilities: card.capabilities,
            deviceVersion: card.deviceVersion,
            deviceModel: card.deviceModel,
            deviceName: card.deviceName,
            fetchedAtMs: card.fetchedAt.roundedStoreMilliseconds
        )
    }
}

extension StoredCachedProperty {
    fileprivate init(_ record: MobileStoredCachedPropertyRecord) {
        self.init(value: record.value, fetchedAt: Date(storeMilliseconds: record.fetchedAtMs))
    }
}

extension StoredPeerRepeaterEntry {
    fileprivate init(_ record: MobileStoredPeerRepeaterEntryRecord) {
        self.init(
            hint: record.hint,
            name: record.name,
            rssiDBm: record.rssiDbm,
            snrQuarterDB: record.snrQuarterDb,
            lastHeardMinutes: record.lastHeardMinutes,
            latitude: record.latitude,
            longitude: record.longitude,
            locationPrecision: record.locationPrecision,
            regionCodes: record.regionCodes,
            reportedAt: Date(storeMilliseconds: record.reportedAtMs)
        )
    }
}

extension MobileStoredPeerRepeaterEntryRecord {
    fileprivate init(_ entry: StoredPeerRepeaterEntry) {
        self.init(
            hint: entry.hint,
            name: entry.name,
            rssiDbm: entry.rssiDBm,
            snrQuarterDb: entry.snrQuarterDB,
            lastHeardMinutes: entry.lastHeardMinutes,
            latitude: entry.latitude,
            longitude: entry.longitude,
            locationPrecision: entry.locationPrecision,
            regionCodes: entry.regionCodes,
            reportedAtMs: entry.reportedAt.roundedStoreMilliseconds
        )
    }
}

extension StoredPeerRepeaterListing {
    fileprivate init(_ record: MobileStoredPeerRepeaterListingRecord) {
        self.init(
            entries: record.entries.map(StoredPeerRepeaterEntry.init),
            total: record.total.map { Int($0) },
            nextCursor: record.nextCursor,
            asOf: Date(storeMilliseconds: record.asOfMs)
        )
    }
}

extension StoredPeerRepeaterReport {
    fileprivate init(_ record: MobileStoredPeerRepeaterReportRecord) {
        self.init(reporterNodeID: record.reporterNodeId, entry: StoredPeerRepeaterEntry(record.entry))
    }
}

extension StoredManualRoute {
    fileprivate init(_ record: MobileStoredManualRouteRecord) {
        self.init(
            publicAddress: record.publicAddress,
            hints: record.hints,
            floodHops: record.floodHops,
            holdUntil: Date(storeMilliseconds: record.holdUntilMs),
            savedLatitude: record.savedLatitude,
            savedLongitude: record.savedLongitude,
            savedAccuracy: record.savedAccuracy,
            promptSettled: record.promptSettled
        )
    }
}

extension StoredClaimedRadio {
    fileprivate init(_ record: MobileStoredClaimedRadioRecord) {
        self.init(
            deviceAddress: record.deviceAddress,
            name: record.name,
            attachedAt: Date(storeMilliseconds: record.attachedAtMs)
        )
    }
}

extension StoredConversationPreview {
    fileprivate init(_ record: MobileStoredConversationPreviewRecord) {
        self.init(
            createdAtMilliseconds: record.createdAtMs,
            body: record.body,
            isOutbound: record.isOutbound,
            isDeleted: record.isDeleted,
            senderAddress: record.senderAddress,
            senderHint: record.senderHint,
            isStatus: record.isStatus
        )
    }
}

extension StoredDirectConversation {
    fileprivate init(_ record: MobileStoredDirectConversationRecord) {
        self.init(
            id: record.id,
            node: StoredNode(record.node),
            draftText: record.draftText,
            lastReadAtMilliseconds: record.lastReadAtMs,
            createdAtMilliseconds: record.createdAtMs,
            notificationsEnabled: record.notificationsEnabled,
            lastMessage: record.lastMessage.map(StoredConversationPreview.init),
            unreadCount: Int(record.unreadCount)
        )
    }
}

extension StoredChannelConversation {
    /// `nil` when the channel's stored ID is not a UUID.
    fileprivate init?(_ record: MobileStoredChannelConversationRecord) {
        guard let channelID = UUID(uuidString: record.channelId) else { return nil }
        self.init(
            id: record.id,
            channelID: channelID,
            conversationAddress: record.conversationAddress,
            draftText: record.draftText,
            lastReadAtMilliseconds: record.lastReadAtMs,
            createdAtMilliseconds: record.createdAtMs,
            lastMessage: record.lastMessage.map(StoredConversationPreview.init),
            unreadCount: Int(record.unreadCount)
        )
    }
}

extension ChatNotificationTarget {
    fileprivate init(_ record: MobileStoredChatNotificationTargetRecord) {
        self.init(
            conversationAddress: record.conversationAddress,
            body: record.body,
            senderAddress: record.senderAddress,
            senderHint: record.senderHint,
            senderHandle: record.senderHandle,
            isStatus: record.isStatus
        )
    }
}

extension ChatReactionNotificationTarget {
    fileprivate init(_ record: MobileStoredChatReactionNotificationTargetRecord) {
        self.init(
            conversationAddress: record.conversationAddress,
            body: record.body,
            targetBody: record.targetBody,
            senderAddress: record.senderAddress,
            senderHint: record.senderHint,
            senderHandle: record.senderHandle
        )
    }
}

extension ChatDeliveryFailure {
    fileprivate init(_ record: MobileStoredChatDeliveryFailureRecord) {
        self.init(conversationAddress: record.conversationAddress, body: record.body, undelivered: record.undelivered)
    }
}

extension StoredChannelKind {
    fileprivate init(_ kind: MobileStoredChannelKind) {
        switch kind {
        case .builtin: self = .builtin
        case .named: self = .named
        case .privateKey: self = .privateKey
        }
    }
}

extension MobileStoredChannelKind {
    fileprivate init(_ kind: StoredChannelKind) {
        switch kind {
        case .builtin: self = .builtin
        case .named: self = .named
        case .privateKey: self = .privateKey
        }
    }
}

extension StoredChannel {
    /// `nil` when the stored ID is not a UUID.
    fileprivate init?(_ record: MobileStoredChannelRecord) {
        guard let id = UUID(uuidString: record.id) else { return nil }
        self.init(
            id: id,
            ownerIdentityID: record.ownerIdentityId,
            kind: StoredChannelKind(record.kind),
            canonicalName: record.canonicalName,
            name: record.name,
            alias: record.alias,
            channelIDHex: record.channelIdHex,
            tint: record.tint,
            regionCode: record.regionCode,
            maxFloodHops: record.maxFloodHops.map { Int($0) },
            joinedPhone: record.joinedPhone,
            joinedDevice: record.joinedDevice,
            notificationsEnabled: record.notificationsEnabled,
            joinedAt: record.joinedAtMs.map(Date.init(storeMilliseconds:))
        )
    }
}

extension MobileStoredChannelRecord {
    fileprivate init(_ channel: StoredChannel) {
        self.init(
            id: channel.id.uuidString,
            ownerIdentityId: channel.ownerIdentityID,
            kind: MobileStoredChannelKind(channel.kind),
            canonicalName: channel.canonicalName,
            name: channel.name,
            alias: channel.alias,
            channelIdHex: channel.channelIDHex,
            tint: channel.tint,
            regionCode: channel.regionCode,
            maxFloodHops: channel.maxFloodHops.map { UInt8(clamping: $0) },
            joinedPhone: channel.joinedPhone,
            joinedDevice: channel.joinedDevice,
            notificationsEnabled: channel.notificationsEnabled,
            joinedAtMs: channel.joinedAt?.storeMilliseconds
        )
    }
}

extension StoredMessageRef {
    fileprivate init(_ record: MobileStoredChatMessageRefRecord) {
        self.init(sessionID: record.sessionId, handle: record.handle)
    }
}

extension ChatMessageCursor {
    fileprivate init(_ record: MobileStoredChatCursorRecord) {
        self.init(createdAtMilliseconds: record.createdAtMs, rowID: record.rowId)
    }
}

extension MobileStoredChatCursorRecord {
    fileprivate init(_ cursor: ChatMessageCursor) {
        self.init(createdAtMs: cursor.createdAtMilliseconds, rowId: cursor.rowID)
    }
}

extension StoredMessageReception {
    fileprivate init(_ record: MobileStoredChatReceptionRecord) {
        self.init(
            rssiDbm: record.rssiDbm.map { Int($0) },
            snrCentibels: record.snrCentibels.map { Int($0) },
            lqi: record.lqi.map { Int($0) },
            hopCount: record.hopCount.map { Int($0) },
            routeHints: record.routeHints,
            sourceAuthenticated: record.sourceAuthenticated
        )
    }
}

extension MobileStoredChatReceptionRecord {
    fileprivate init(_ reception: StoredMessageReception) {
        self.init(
            rssiDbm: reception.rssiDbm.map { Int16(clamping: $0) },
            snrCentibels: reception.snrCentibels.map { Int16(clamping: $0) },
            lqi: reception.lqi.map { UInt8(clamping: $0) },
            hopCount: reception.hopCount.map { UInt8(clamping: $0) },
            routeHints: reception.routeHints,
            sourceAuthenticated: reception.sourceAuthenticated
        )
    }
}

extension StoredMessageRepeats {
    fileprivate init(_ record: MobileStoredChatRepeatsRecord) {
        self.init(
            repeaters: record.repeaters,
            anonymous: Int(record.anonymous),
            progressAt: Date(storeMilliseconds: record.progressAtMs)
        )
    }
}

extension StoredMessageQuote {
    fileprivate init(_ record: MobileStoredChatQuoteRecord) {
        self.init(original: record.original.map { original in
            Original(
                ref: StoredMessageRef(original.reference),
                body: original.body,
                outbound: original.outbound,
                isDeleted: original.isDeleted,
                senderAddress: original.senderAddress,
                senderHint: original.senderHint,
                senderHandle: original.senderHandle
            )
        })
    }
}

extension StoredMessageReaction {
    fileprivate init(_ record: MobileStoredChatReactionRecord) {
        self.init(
            body: record.body,
            outbound: record.outbound,
            senderAddress: record.senderAddress,
            senderHint: record.senderHint,
            sessionID: record.reference.sessionId,
            handle: record.reference.handle,
            wireID: record.wireId,
            epoch: record.epoch,
            createdAtMilliseconds: record.createdAtMs,
            deliveryState: record.deliveryState?.storedText,
            forwardSecret: record.forwardSecret
        )
    }
}

extension StoredChatMessage {
    fileprivate init(_ record: MobileStoredChatMessageRecord) {
        self.init(
            sessionID: record.reference.sessionId,
            handle: record.reference.handle,
            body: record.body,
            outbound: record.outbound,
            deliveryState: record.deliveryState?.storedText,
            isDeleted: record.isDeleted,
            createdAtMilliseconds: record.createdAtMs,
            wireID: record.wireId,
            epoch: record.epoch,
            isEdited: record.isEdited,
            presence: Self.presenceCode(record.presence),
            receivedLate: record.receivedLate,
            deliveredLate: record.deliveredLate,
            originalBody: record.originalBody,
            senderAddress: record.senderAddress,
            senderHint: record.senderHint,
            senderHandle: record.senderHandle,
            reception: record.reception.map(StoredMessageReception.init),
            rowID: record.rowId,
            deliveredFlooded: record.deliveredFlooded,
            reactions: record.reactions.map(StoredMessageReaction.init),
            isReply: record.isReply,
            isEditOfUnknown: record.isEditOfUnknown,
            isStatus: record.isStatus,
            isForwardSecret: record.isForwardSecret,
            replyTarget: record.replyTarget.map(StoredMessageRef.init),
            quote: record.quote.map(StoredMessageQuote.init),
            repeats: record.repeats.map(StoredMessageRepeats.init)
        )
    }

    /// The stored presence code: 0 present, 1 gap under repair, 2
    /// unavailable, 3 gap waiting for the user.
    private static func presenceCode(_ presence: MobileChatPresence) -> Int {
        switch presence {
        case .present: 0
        case .gapPending: 1
        case .unavailable: 2
        case .gapIdle: 3
        }
    }
}

extension StoredChatMessagePage {
    fileprivate init(_ record: MobileStoredChatMessagePageRecord) {
        self.init(
            messages: record.messages.map(StoredChatMessage.init),
            hasOlder: record.hasOlder,
            hasNewer: record.hasNewer
        )
    }
}

#if DEBUG
extension MobileStagedChatMessageRecord {
    fileprivate init(_ message: StagedMessage) {
        self.init(
            handle: message.handle,
            body: message.body,
            outbound: message.outbound,
            createdAtMs: message.createdAt.storeMilliseconds,
            senderAddress: message.senderAddress,
            senderHint: message.senderHint,
            senderHandle: message.senderHandle,
            deliveryState: message.deliveryState.flatMap(MobileStoredChatDeliveryState.init(storedText:)),
            reception: message.reception.map(MobileStoredChatReceptionRecord.init),
            reactions: message.reactions.map { reaction in
                MobileStagedChatReactionRecord(
                    body: reaction.body,
                    outbound: reaction.outbound,
                    createdAtMs: reaction.createdAt.storeMilliseconds,
                    senderAddress: reaction.senderAddress,
                    senderHint: reaction.senderHint
                )
            },
            regarding: message.regarding.map { regarding in
                switch regarding {
                case .message(let handle): .message(handle: handle)
                case .missing: .missing
                }
            },
            isDeleted: message.isDeleted
        )
    }
}
#endif
