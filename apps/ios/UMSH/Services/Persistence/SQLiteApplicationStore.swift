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
    let systemRole: MobileStoredSystemRole?
    let nodeKind: MobileStoredNodeKind?
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

/// A radio that took this phone's identity as its host and has not been
/// seen to let it go.
struct StoredClaimedRadio: Equatable, Sendable {
    /// The radio's device address.
    let deviceAddress: String
    let name: String?
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
    let deliveryState: MobileStoredChatDeliveryState?
    let isDeleted: Bool
    let createdAtMilliseconds: Int64
    /// Durable wire identity for referencing this message (edit/delete)
    /// after the facade session that composed it is gone.
    let wireID: UInt8?
    let epoch: UInt16?
    let isEdited: Bool
    /// Whether the message is here, or a gap in its place.
    let presence: MobileChatPresence
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

    var isGapPlaceholder: Bool { presence == .gapPending || presence == .gapIdle }
    /// A gap no repair is under way for, which waits for the user to ask.
    var isGapIdle: Bool { presence == .gapIdle }
    var isUnavailable: Bool { presence == .unavailable }

    var cursor: ChatMessageCursor {
        ChatMessageCursor(createdAtMilliseconds: createdAtMilliseconds, rowID: rowID)
    }

    /// Whether a delivery state is a failure: undelivered (it did not
    /// arrive) or failed (it went out unacknowledged and may have).
    static func isDeliveryFailure(_ state: MobileStoredChatDeliveryState?) -> Bool {
        state == .failed || state == .undelivered
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
    let deliveryState: MobileStoredChatDeliveryState?
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

/// The application database, kept by the shared Rust store
/// (`MobileAppStore` in `umsh-mobile-core`), which Android uses too.
///
/// It holds public application records only. Private identity and channel
/// key bytes are never accepted by this API and remain in Keychain.
///
/// This actor only adapts: Swift types and `Date`s on this side, the core's
/// records and millisecond instants on the other. Writes that need the time
/// are stamped here, from the clock, as the Swift store stamped them.
actor SQLiteApplicationStore {
    private let store: MobileAppStore

    /// The core's store itself, for a mesh session to keep its chat in.
    nonisolated var coreStore: MobileAppStore { store }

    init(path: String) throws {
        store = try Self.mapped { try MobileAppStore.open(path: path) }
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

    func upsertPeer(
        ownerIdentityID: String,
        publicAddress: String,
        alias: String?,
        advertisedName: String? = nil,
        isSaved: Bool = false,
        nodeKind: MobileStoredNodeKind? = nil,
        systemRole: MobileStoredSystemRole? = nil,
        radioIdentifier: String? = nil,
        advertisement: Data? = nil,
        advertisementAuthenticated: Bool = false,
        advertisementReceivedAt: Date? = nil
    ) throws {
        let peer = MobilePeerUpsertRecord(
            alias: alias,
            advertisedName: advertisedName,
            isSaved: isSaved,
            nodeKind: nodeKind,
            systemRole: systemRole,
            radioIdentifier: radioIdentifier,
            advertisement: advertisement,
            advertisementAuthenticated: advertisementAuthenticated,
            advertisementReceivedAtMs: advertisementReceivedAt?.storeMilliseconds
        )
        try run { try $0.upsertPeer(ownerIdentityId: ownerIdentityID, publicAddress: publicAddress, peer: peer) }
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

    // MARK: Chat

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

extension Date {
    /// This instant as the core takes one: whole milliseconds since the Unix
    /// epoch, with any fraction cut off. What every stamp uses except those
    /// below.
    var storeMilliseconds: Int64 {
        Int64(timeIntervalSince1970 * 1_000)
    }
}

extension Date {
    /// An instant the core stamped, in milliseconds since the Unix epoch.
    init(storeMilliseconds milliseconds: Int64) {
        self.init(timeIntervalSince1970: Double(milliseconds) / 1_000)
    }
}

fileprivate extension Date {
    /// This instant to the nearest millisecond, which is how the management
    /// cache has always stamped its card, so stored rows keep meaning the same.
    var roundedStoreMilliseconds: Int64 {
        Int64((timeIntervalSince1970 * 1_000).rounded())
    }
}

extension StoredNode {
    init(_ record: MobileStoredNodeRecord) {
        self.init(
            id: record.id,
            ownerIdentityID: record.ownerIdentityId,
            publicAddress: record.publicAddress,
            alias: record.alias,
            advertisedName: record.advertisedName,
            systemRole: record.systemRole,
            nodeKind: record.nodeKind,
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
    init(_ record: MobileStoredManagementCardRecord) {
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
    init(_ card: StoredManagementCard) {
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
    init(_ record: MobileStoredCachedPropertyRecord) {
        self.init(value: record.value, fetchedAt: Date(storeMilliseconds: record.fetchedAtMs))
    }
}

extension StoredPeerRepeaterEntry {
    init(_ record: MobileStoredPeerRepeaterEntryRecord) {
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

extension StoredClaimedRadio {
    init(_ record: MobileStoredClaimedRadioRecord) {
        self.init(
            deviceAddress: record.deviceAddress,
            name: record.name
        )
    }
}

extension StoredConversationPreview {
    init(_ record: MobileStoredConversationPreviewRecord) {
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
    init?(_ record: MobileStoredChannelRecord) {
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
    init(_ record: MobileStoredChatCursorRecord) {
        self.init(createdAtMilliseconds: record.createdAtMs, rowID: record.rowId)
    }
}

extension MobileStoredChatCursorRecord {
    init(_ cursor: ChatMessageCursor) {
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
            deliveryState: record.deliveryState,
            forwardSecret: record.forwardSecret
        )
    }
}

extension StoredChatMessage {
    init(_ record: MobileStoredChatMessageRecord) {
        self.init(
            sessionID: record.reference.sessionId,
            handle: record.reference.handle,
            body: record.body,
            outbound: record.outbound,
            deliveryState: record.deliveryState,
            isDeleted: record.isDeleted,
            createdAtMilliseconds: record.createdAtMs,
            wireID: record.wireId,
            epoch: record.epoch,
            isEdited: record.isEdited,
            presence: record.presence,
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

