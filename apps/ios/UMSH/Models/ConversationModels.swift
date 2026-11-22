import Foundation
import UMSHMobileCore

struct PeerSummary: Identifiable, Hashable, Sendable {
    let id: Int64
    let identity: MeshPublicIdentity
    let alias: String?
    let advertisedName: String?
    let systemRole: MobileStoredSystemRole?
    /// The role last recorded for this node, so the answer survives a restart
    /// and so a device configured through this phone reads correctly before it
    /// has ever been heard on the air. Superseded by a live advertisement.
    let storedRole: PeerRole
    /// Decoded advertised identity, when a bundle has been imported or
    /// received for this peer.
    var advertisedIdentity: MeshNodeIdentity? = nil
    /// Whether the MAC authenticated the frame that delivered
    /// `advertisedIdentity`, as stored.
    var advertisedIdentityAuthenticated: Bool = false
    /// When this phone heard `advertisedIdentity` off the air. `nil` for an
    /// imported bundle, whose arrival says nothing about how current it is.
    var advertisedIdentityReceivedAt: Date? = nil
    /// When we last heard from this peer by any means—beacon, advertisement,
    /// inbound message, delivery ack, or ping reply. `nil` until the first
    /// evidence.
    var lastHeard: Date? = nil
    /// Whether this node is saved on the local (phone) identity. `false` is
    /// the transient tier: hidden from the main Peers list, surfaced only
    /// through search and discovery.
    var isSaved: Bool = true
    var isFavorite: Bool = false
    /// Whether this node's public key is stored on the companion radio's
    /// device identity (PROP_DEV_PEERS). A cache; the device is the authority.
    var isOnDeviceIdentity: Bool = false
    /// Whether a one-shot watch is armed: the next thing that moves
    /// `lastHeard` also raises a notification and clears this.
    var notifyWhenHeard: Bool = false
    /// Whether this node plausibly forwards other nodes' traffic, by the
    /// core's rule. An advertisement is the node's own claim, not proof.
    /// `false` for a summary built here rather than read from the core.
    var isLikelyRepeater: Bool = false
    /// Whether the advertised claims may be attributed to this peer at all:
    /// signed and valid, or unsigned in a frame the MAC authenticated. A
    /// claim nothing authenticated may be anyone's.
    var advertisedIdentityIsAttributable: Bool = false
    /// What this phone actually knows about whether the node repeats, which
    /// tells a node known not to forward from one never heard at all.
    var repeaterEvidence: MobileRepeaterEvidence = .unknown
    /// This node's own two-byte router hint, rendered by the core: what a
    /// repeater carrying its traffic would put on the wire. `nil` for a
    /// summary built here rather than read from the core.
    var routerHint: MeshRouterHint? = nil

    var displayName: String {
        alias ?? advertisedName ?? (isUlcpDevice ? "Companion radio" : identity.hint.text)
    }

    var isUlcpDevice: Bool { systemRole == .companionRadio }

    /// What this node says it is. A live advertisement wins over the stored
    /// role, so the answer tracks the node rather than whatever was true when
    /// the row was created.
    var role: PeerRole {
        guard let advertisedIdentity else { return storedRole }
        return PeerRole(roleCode: advertisedIdentity.roleCode)
    }

    /// Whether this node says it exchanges text messages: the chat role, or
    /// the text-messages capability alongside some other role. A node that
    /// has never advertised anything answers `false`—nothing has claimed
    /// otherwise.
    var offersTextMessages: Bool {
        role == .chat
            || advertisedIdentity?.capabilityBits.contains(.textMessages) == true
    }

    /// The capabilities the node's advertisement names, or `nil` when there
    /// is no advertisement. Every advertisement carries the bitmap, so an
    /// empty set means the node can do none of them. A node's verbs follow
    /// these, not its role: a chat device can repeat too.
    var advertisedCapabilities: MeshNodeCapabilities? {
        advertisedIdentity?.capabilityBits
    }

    /// The role as a peer row's second line, or `nil` when it is unknown and
    /// the row should have no second line.
    var roleLabel: String? {
        role == .unknown ? nil : role.label
    }

    /// The outline this node's avatar is drawn in.
    var avatarShape: PeerAvatarShape {
        PeerAvatarShape(role: role, capabilities: advertisedIdentity?.capabilityBits)
    }

    /// Whether this node answers to a search query, across the names a user
    /// would type and the identifiers they would paste. An empty query
    /// matches everything, so a caller can filter unconditionally.
    ///
    /// Addresses match on a prefix only. They are exact base58, so a hit in
    /// the middle of one carries no meaning and would only add noise.
    func matches(searchQuery: String) -> Bool {
        let query = searchQuery.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else { return true }
        let textOptions: String.CompareOptions = [.caseInsensitive, .diacriticInsensitive]
        if let alias, alias.range(of: query, options: textOptions) != nil { return true }
        if let advertisedName, advertisedName.range(of: query, options: textOptions) != nil {
            return true
        }
        if identity.canonicalAddress.hasPrefix(query) { return true }
        return identity.hint.text.range(of: query, options: .caseInsensitive) != nil
    }
}

/// What a node says it is, named from the wire role byte in its advertised
/// identity.
///
/// Deliberately not a local filing category the operator picks. The role is
/// the node's own claim and arrives with its identity, so it updates on its
/// own as fresher advertisements land and can never drift out of date against
/// what the node is actually doing.
enum PeerRole: String, CaseIterable, Hashable, Sendable, Identifiable {
    case repeater
    case chat
    case tracker
    case sensor
    case bridge
    case chatRoom
    case temporarySession
    /// No identity has been heard for this node yet, or the role byte it
    /// claimed is one this app has no name for. An unrecognized byte still
    /// round-trips on the wire; it just cannot be described here.
    case unknown

    var id: Self { self }

    /// The roles a device can be configured to advertise. `unknown` is not
    /// among them: it describes an absence, not a choice.
    static let selectable: [PeerRole] = [.repeater, .chat, .tracker, .sensor, .bridge]

    /// The role's name, in the reader's language.
    var label: String {
        switch self {
        case .repeater: String(localized: "Repeater", comment: "Node role: forwards other nodes' traffic.")
        case .chat: String(localized: "Chat", comment: "Node role: a person's messaging device.")
        case .tracker: String(localized: "Tracker", comment: "Node role: reports its position.")
        case .sensor: String(localized: "Sensor", comment: "Node role: reports measurements.")
        case .bridge: String(localized: "Bridge", comment: "Node role: links the mesh to another network.")
        case .chatRoom: String(localized: "Chat room", comment: "Node role: hosts a shared conversation.")
        case .temporarySession: String(localized: "Temporary session", comment: "Node role: a short-lived identity.")
        case .unknown: String(localized: "Unknown", comment: "Node role: none advertised, or one this app cannot name.")
        }
    }

    /// The wire role byte, for the roles that name one.
    var roleCode: UInt8? {
        switch self {
        case .repeater: 1
        case .chat: 2
        case .tracker: 3
        case .sensor: 4
        case .bridge: 5
        case .chatRoom: 6
        case .temporarySession: 7
        case .unknown: nil
        }
    }

    init(roleCode: UInt8) {
        self = PeerRole.allCases.first { $0.roleCode == roleCode } ?? .unknown
    }

    /// How a role byte is described, keeping an unrecognized one visible as a
    /// number rather than flattening it to "Unknown"—the node did claim
    /// something.
    static func label(forCode code: UInt8) -> String {
        let role = PeerRole(roleCode: code)
        return role == .unknown
            ? String(localized: "Role \(code)", comment: "A node role this app has no name for, by its number.")
            : role.label
    }
}

extension PeerRole {
    /// The role as the store keeps it.
    init(_ kind: MobileStoredNodeKind) {
        self = switch kind {
        case .repeater: .repeater
        case .chat: .chat
        case .tracker: .tracker
        case .sensor: .sensor
        case .bridge: .bridge
        case .chatRoom: .chatRoom
        case .temporarySession: .temporarySession
        case .unknown: .unknown
        }
    }

    var storedKind: MobileStoredNodeKind {
        switch self {
        case .repeater: .repeater
        case .chat: .chat
        case .tracker: .tracker
        case .sensor: .sensor
        case .bridge: .bridge
        case .chatRoom: .chatRoom
        case .temporarySession: .temporarySession
        case .unknown: .unknown
        }
    }
}

extension MeshNodeCapabilities {
    /// Each capability this app has a name for, in wire bit order.
    static let named: [(MeshNodeCapabilities, LocalizedStringResource)] = [
        (.repeater, LocalizedStringResource("Repeater", comment: "Node capability: forwards other nodes' traffic.")),
        (.mobile, LocalizedStringResource("Mobile", comment: "Node capability: moves around.")),
        (.textMessages, LocalizedStringResource("Text messages", comment: "Node capability: sends and receives text messages.")),
        (.telemetry, LocalizedStringResource("Telemetry", comment: "Node capability: reports measurements.")),
        (.chatRoom, LocalizedStringResource("Chat room", comment: "Node capability: hosts a shared conversation.")),
        (.coap, LocalizedStringResource("CoAP", comment: "Node capability: answers CoAP requests. A protocol name; usually left untranslated.")),
    ]

    /// The names of the capabilities set here, as one list in the reader's
    /// language ("Mobile and Text messages"). Bits with no name are left out.
    var listText: String {
        Self.named
            .filter { contains($0.0) }
            .map { String(localized: $0.1) }
            .formatted(.list(type: .and))
    }
}

struct PeerImportDetails: Sendable {
    let alias: String?
}

/// The newest message in a conversation, reduced to what a list row draws.
///
/// A summary carries this rather than the transcript. The conversations list
/// asks only when a chat last spoke, who spoke, and what they said; answering
/// that by holding every message meant a refresh cost the whole history of
/// every conversation, on a cadence set by radio traffic.
/// Status text as a line of text: who, then what.
func statusLine(name: String, body: String) -> String {
    String(
        localized: "\(name) \(body)",
        comment: "Status text, like an IRC /me: a person's name, then what they say they did."
    )
}

struct ConversationPreviewMessage: Hashable, Sendable {
    let createdAtMilliseconds: Int64
    let body: String
    let isOutbound: Bool
    let isDeleted: Bool
    /// Who sent this, in a group conversation: the resolved address once known,
    /// and the hint the wire always carries.
    let senderAddress: String?
    let senderHint: Data?
    /// Status text, which reads as its sender's name followed by its body.
    var isStatus: Bool = false
    /// The sender's hint as the core renders it, resolved when the list is
    /// loaded.
    var senderNodeHint: MeshNodeHint? = nil

    /// A short label for a member known only by their hint. Mirrors
    /// ``ChatMessageSummary/senderHintLabel`` so a list row and a bubble name
    /// the same member the same way.
    var senderHintLabel: String? { senderNodeHint?.text }
}

struct DirectConversationSummary: Identifiable, Hashable, Sendable {
    let id: Int64
    let peer: PeerSummary
    var draftText: String
    /// The bottom of the transcript, for the list row. The transcript itself is
    /// loaded a window at a time by whichever thread view is open.
    var lastMessage: ConversationPreviewMessage?
    /// Messages received since the user last opened this conversation.
    var unreadCount: Int = 0
    /// When the conversation was created, which stands in for activity until
    /// the first message.
    var createdAtMilliseconds: Int64 = 0
    /// Whether this conversation may raise a notification—on the phone, and
    /// on a companion radio holding its messages while the phone is away.
    ///
    /// Defaults on, where a channel's defaults off: a message addressed to you
    /// is worth interrupting for before you have said so.
    var notificationsEnabled: Bool = true
    /// Bumped whenever this conversation's stored messages change, so an open
    /// transcript knows to re-read its window.
    ///
    /// Stored rather than derived, and part of the synthesized equality on
    /// purpose: a delivery-state change or an edit to an older message moves no
    /// other field here, so this is the only thing that makes a reload publish
    /// the summary at all.
    var messageRevision: Int = 0

    /// The address the mesh facade keys this conversation's records by.
    var conversationAddress: String { peer.identity.canonicalAddress }
}

/// A channel's group conversation. Everyone holding the key is a participant,
/// so there is no peer on the other end—only members, who are known by the
/// hint their messages claim until their full address is learned.
struct ChannelConversationSummary: Identifiable, Hashable, Sendable {
    let id: Int64
    let channel: ChannelSummary
    let conversationAddress: String
    var draftText: String
    var lastMessage: ConversationPreviewMessage?
    var unreadCount: Int = 0
    /// When the conversation was created, which stands in for activity until
    /// the first message.
    var createdAtMilliseconds: Int64 = 0
    /// See ``DirectConversationSummary/messageRevision``.
    var messageRevision: Int = 0
    /// Nothing may go out here until the user agrees to `EMERGENCY`'s
    /// warning.
    var needsEmergencyAgreement = false
}

/// One row of the conversations list, whichever kind it is. The list mixes
/// both and orders them together: a channel with newer traffic belongs above
/// a quiet direct chat.
enum ConversationListItem: Identifiable, Hashable, Sendable {
    case direct(DirectConversationSummary)
    case channel(ChannelConversationSummary)

    var id: String {
        switch self {
        case let .direct(conversation): "direct:\(conversation.id)"
        case let .channel(conversation): "channel:\(conversation.id)"
        }
    }

    var title: String {
        switch self {
        case let .direct(conversation): conversation.peer.displayName
        case let .channel(conversation): conversation.channel.title
        }
    }

    var lastMessage: ConversationPreviewMessage? {
        switch self {
        case let .direct(conversation): conversation.lastMessage
        case let .channel(conversation): conversation.lastMessage
        }
    }

    var messageRevision: Int {
        switch self {
        case let .direct(conversation): conversation.messageRevision
        case let .channel(conversation): conversation.messageRevision
        }
    }

    var draftText: String {
        switch self {
        case let .direct(conversation): conversation.draftText
        case let .channel(conversation): conversation.draftText
        }
    }

    var unreadCount: Int {
        switch self {
        case let .direct(conversation): conversation.unreadCount
        case let .channel(conversation): conversation.unreadCount
        }
    }

    var conversationAddress: String {
        switch self {
        case let .direct(conversation): conversation.conversationAddress
        case let .channel(conversation): conversation.conversationAddress
        }
    }

    /// When this conversation last saw traffic, for ordering. A conversation
    /// with no messages yet is as recent as its creation: a chat just opened
    /// belongs at the top, where the user who opened it will look for it.
    var lastActivityMilliseconds: Int64 {
        let created = switch self {
        case let .direct(conversation): conversation.createdAtMilliseconds
        case let .channel(conversation): conversation.createdAtMilliseconds
        }
        return max(lastMessage?.createdAtMilliseconds ?? 0, created)
    }
}

/// The repeaters overheard carrying an outbound message.
struct MessageRepeats: Hashable, Sendable {
    /// A repeater whose forward said who it was.
    struct Repeater: Hashable, Sendable {
        /// Its router hint, as the core renders it.
        let hint: MeshRouterHint
        /// The node the hint most plausibly names, when one does: a guess,
        /// since a two-byte hint cannot prove which node forwarded a frame.
        let name: String?

        var label: String { name ?? hint.text }
    }

    /// The repeaters that named themselves, first heard first.
    let repeaters: [Repeater]
    /// Repeaters heard that did not.
    let anonymous: Int
    /// When the message's delivery last moved.
    let progressAt: Date

    /// What to call the first repeater that named itself, or `nil` when
    /// none has.
    var lead: String? { repeaters.first?.label }
    /// Repeaters heard in all, named or not.
    var count: Int { repeaters.count + anonymous }
}

struct ChatMessageSummary: Identifiable, Hashable, Sendable {
    let id: String
    let body: String
    let isOutbound: Bool
    let deliveryState: MobileStoredChatDeliveryState?
    let isDeleted: Bool
    let isEdited: Bool
    /// Facade session that recorded the message plus its engine handle;
    /// paired with the durable wire identity below they let the Rust engine
    /// target this message for an edit/delete even after an app restart.
    let sessionID: String
    let handle: UInt32
    let wireID: UInt8?
    let epoch: UInt16?
    /// Where this message sits in its conversation's storage order, so a
    /// transcript can page from the edges of what it holds.
    ///
    /// Safe to compare alongside the rest of the message—`ChatMessageBubble`
    /// is `Equatable` to avoid re-measuring its `UITextView`—because a row's
    /// ordering key is fixed for its lifetime. Two summaries of the same
    /// message always agree on it.
    let cursor: ChatMessageCursor
    /// A reserved gap slot awaiting repair—rendered as a spinner placeholder,
    /// not a real bubble.
    var isGapPlaceholder: Bool = false
    /// A gap no repair is under way for: the user can ask for it.
    var isGapIdle: Bool = false
    /// A gap whose repair failed—rendered as a subtle "message unavailable"
    /// marker.
    var isUnavailable: Bool = false
    /// Filled its ordered slot out of order—annotated "Received late".
    var isReceivedLate: Bool = false
    /// Came as an edit of a message this phone does not hold.
    var isEditOfUnknown: Bool = false
    /// Status text: its sender's name followed by its body, with no bubble.
    var isStatus: Bool = false
    /// Outbound, and what it reads went under a session with forward secrecy.
    var isForwardSecret: Bool = false
    /// Outbound message delivered on a resend after a transport failure—
    /// annotated "Delivered Late".
    var isDeliveredLate: Bool = false
    /// Outbound message whose acknowledgment came back through the flood
    /// that followed a missed route—annotated "Delivered · Flooded".
    var isDeliveredFlooded: Bool = false
    /// Pre-edit text of the sender's own edited message, available for review
    /// via the bubble's context menu. The wire archive never resends it.
    var originalBody: String? = nil
    /// When the message was recorded locally. Drives the Peers list's
    /// "Latest message" sort; transcripts order by storage, not this.
    var createdAtMilliseconds: Int64 = 0
    /// Who sent this, in a group conversation. The address is present once
    /// that member's hint has been resolved; the hint is always there; the
    /// handle is the name the sender chose to attach to the message.
    var senderAddress: String? = nil
    var senderHint: Data? = nil
    var senderHandle: String? = nil
    /// The sender's hint rendered for display, so a group bubble can show the
    /// same deterministic avatar a peer gets. Resolved when the transcript is
    /// loaded rather than per bubble.
    var senderNodeHint: MeshNodeHint? = nil
    /// What the radio observed of the frame this message arrived on.
    var reception: StoredMessageReception? = nil
    /// Reactions to this message, at most one per person, oldest first.
    var reactions: [MessageReaction] = []
    /// What this message replies to, when it is a reply.
    var reply: MessageQuote? = nil
    /// The repeaters heard carrying an outbound message, once it is sent.
    var repeats: MessageRepeats? = nil

    /// The reaction this user has on this message, if any: what the picker
    /// shows as chosen. Whether a tap withdraws it is the core's to decide
    /// when it sends.
    var myReaction: MessageReaction? { reactions.first(where: \.isMine) }

    /// A short label for a member known only by their hint.
    var senderHintLabel: String? { senderNodeHint?.text }

    /// When this was written, or nil for a record carrying no usable time—
    /// a gap placeholder standing in for a message nobody has seen yet.
    var sentDate: Date? {
        guard createdAtMilliseconds > 0 else { return nil }
        return Date(timeIntervalSince1970: Double(createdAtMilliseconds) / 1000)
    }

    /// Until when this message, one of ours not deleted, may be edited or
    /// resent as itself, as the core reports it; nil for any other. Past
    /// it, ``actions`` is out of date and the row is read again.
    var reviseUntilMilliseconds: Int64? = nil
    /// What the row offers, as the core decided when it was read.
    var actions = MessageActions()

    /// How the core names this message in a command.
    var reference: MobileStoredChatMessageRefRecord {
        MobileStoredChatMessageRefRecord(sessionId: sessionID, handle: handle)
    }

    /// One of ours that delivery gave up on, either way
    /// (``StoredChatMessage/isDeliveryFailure(_:)``). It may be sent again or
    /// deleted, and nothing can be said about it.
    var isDeliveryFailed: Bool {
        isOutbound && StoredChatMessage.isDeliveryFailure(deliveryState)
    }

    /// One of ours that never went out where its peer could read it, as
    /// opposed to one that went out and drew no acknowledgment.
    var isUndelivered: Bool { isOutbound && deliveryState == .undelivered }
}

/// What may be done to one message, as the core would take it when the
/// message was read. Copying, details and the original text are always
/// offered and are not here.
struct MessageActions: Hashable, Sendable {
    var edit = false
    var delete = false
    /// How a resend would first go; nil when it cannot be resent. One
    /// offered in place may still go as new: the resend's answer says which.
    var resend: MobileAppResent?
    var react = false
    var reply = false
    /// A gap the session may be asked to fill.
    var requestMissing = false
}

/// A reply's quote of the message it answers, as that message reads now.
struct MessageQuote: Hashable, Sendable {
    enum State: Hashable, Sendable {
        case present
        /// Its sender took it back.
        case deleted
        /// It never arrived here, or is no longer kept.
        case unavailable
    }

    let state: State
    /// The original's transcript id, while it can be scrolled to.
    var targetID: String? = nil
    var body: String = ""
    var isOutbound: Bool = false
    var senderAddress: String? = nil
    var senderHandle: String? = nil
    var senderNodeHint: MeshNodeHint? = nil

    static let unavailable = MessageQuote(state: .unavailable)
}

/// One person's reaction to one message.
struct MessageReaction: Identifiable, Hashable, Sendable {
    var id: String { "\(sessionID):\(handle)" }
    /// The emote body as it arrived, before normalization.
    let body: String
    /// What the body reads as, as the core reads it; nil for a body with
    /// nothing in it.
    let kind: MobileReaction?
    let isMine: Bool
    let senderAddress: String?
    let senderHint: Data?
    let sessionID: String
    let handle: UInt32
    let wireID: UInt8?
    let epoch: UInt16?
    /// One of ours the radio could not deliver. Drawn faded; everything else
    ///—including a reaction still in flight—looks normal, because being
    /// in flight is the ordinary case and not worth alarming anyone about.
    let isFailed: Bool
    /// Ours, and it went under a session with forward secrecy.
    var isForwardSecret = false

    /// The single glyph this reaction renders as.
    var glyph: String { ReactionEmoji.glyph(for: kind) }

    /// Spoken description, so a reaction is never conveyed by color or
    /// glyph alone.
    var accessibilityDescription: String {
        let name = ReactionEmoji.name(for: glyph)
        let who = isMine ? "you" : (senderAddress.map { String($0.prefix(8)) } ?? "someone")
        return isFailed ? "\(name) from \(who), not delivered" : "\(name) from \(who)"
    }
}

/// The reaction palette: what the picker offers and what each kind looks
/// like. What goes on the wire, and what an arriving body reads as, is the
/// core's.
enum ReactionEmoji {
    /// The picker's palette, in the order it is offered.
    static let palette: [(glyph: String, kind: MobileReaction)] = [
        ("🩷", .heart),
        ("👍", .thumbsUp),
        ("👎", .thumbsDown),
        ("🤣", .laugh),
        ("‼️", .exclaim),
        ("❓", .question),
    ]

    private static let names: [String: String] = [
        "🩷": "heart", "👍": "thumbs up", "👎": "thumbs down",
        "🤣": "laughing", "‼️": "exclamation", "❓": "question",
    ]

    /// What a reaction renders as: its palette glyph, or the one character
    /// it is when it is none of them. Only ever one glyph—a peer that sends
    /// a sentence still gets a chip.
    static func glyph(for kind: MobileReaction?) -> String {
        switch kind {
        case nil: ""
        case let .other(cluster)?: cluster
        case let kind?: palette.first { $0.kind == kind }?.glyph ?? ""
        }
    }

    /// The reaction a picked glyph stands for.
    static func kind(for glyph: String) -> MobileReaction {
        palette.first { $0.glyph == glyph }?.kind ?? .other(cluster: glyph)
    }

    static func name(for glyph: String) -> String {
        names[glyph] ?? glyph
    }
}

/// Words added to a conversation's stored draft from outside its composer:
/// a notification reply that did not go out. A composer open on the
/// conversation holds the draft as it stood when the composer opened, and
/// its next save would write over them, so it adds them to what it holds.
struct DraftAddition: Equatable, Sendable {
    /// Rises with each addition, so a composer knows which it has seen.
    let sequence: Int
    let address: String
    let text: String

    /// `draft` with these words added, as the core adds them to a stored
    /// draft: on a line of their own, unless the draft is empty.
    func added(to draft: String) -> String {
        draft.isEmpty ? text : draft + "\n" + text
    }
}

/// Message-level operations on an open transcript. Bundled so intermediate
/// views do not grow a parameter per operation.
///
/// Each throws the core's reason when nothing was kept, except
/// `MobileAppError.MessageNotQueued`, which means the message is in the
/// transcript as not delivered.
struct ChatMessageActions: Sendable {
    /// Keep the composer's text, untrimmed, as the draft of the conversation
    /// at this address.
    var saveDraft: @Sendable (String, String) async -> AppOperationResult = { _, _ in
        .failure(.unavailable(String(
            localized: "Saving is unavailable.",
            comment: "Error when a draft cannot be stored."
        )))
    }
    /// The conversation at this address is on screen: what it holds has been
    /// seen.
    var markRead: @Sendable (String) async -> Void = { _ in }
    /// Send the composer's text, untrimmed as it stood when Send was
    /// pressed, under forward secrecy as the flag says the composer showed
    /// it.
    var send: @Sendable (ConversationListItem, String, Bool) async throws -> Void = { _, _, _ in
        throw MobileAppError.NotRunning
    }
    /// Send the composer's text in reply to a message, quoting it, as `send`
    /// does.
    var reply: @Sendable (ConversationListItem, ChatMessageSummary, String, Bool) async throws -> Void = { _, _, _, _ in
        throw MobileAppError.NotRunning
    }
    var edit: @Sendable (ConversationListItem, ChatMessageSummary, String) async throws -> Void = { _, _, _ in
        throw MobileAppError.NotRunning
    }
    var delete: @Sendable (ConversationListItem, ChatMessageSummary) async throws -> Void = { _, _ in
        throw MobileAppError.NotRunning
    }
    /// React to a message with this reaction, or withdraw it if it is
    /// already this phone's, as the core finds the message when it sends.
    var toggleReaction: @Sendable (ConversationListItem, ChatMessageSummary, MobileReaction) async throws -> Void = { _, _, _ in
        throw MobileAppError.NotRunning
    }
    /// Put a failed message back on the air, under forward secrecy or not,
    /// as the flag says: as itself while it can still land, so a peer who
    /// already has it never sees it twice, otherwise as a new message that
    /// replaces it. Says which.
    var resend: @Sendable (ConversationListItem, ChatMessageSummary, Bool) async throws -> MobileAppResent = { _, _, _ in
        throw MobileAppError.NotRunning
    }
    /// Ask for a run of missing messages no repair is under way for
    /// (``ChatMessageSummary/isGapIdle``).
    var requestMissing: @Sendable (ConversationListItem, [ChatMessageSummary]) async throws -> Void = { _, _ in
        throw MobileAppError.NotRunning
    }
    /// Erase every message in the conversation at this address. Local only:
    /// nothing is sent, and everyone else keeps their copy. The conversation
    /// itself survives, as does its place in the wire stream.
    var clearMessages: @Sendable (String) async throws -> Void = { _ in
        throw MobileAppError.NotRunning
    }
    /// How many messages the conversation at this address holds. Asked for on
    /// demand rather than carried on the summary: it is the one figure that has
    /// to walk a whole transcript, and only the info sheet wants it.
    var countMessages: @Sendable (String) async -> Int = { _ in 0 }

    static let unavailable = ChatMessageActions()

    /// The title of the dialog that says why ``clearMessages`` did not
    /// happen, wherever it was asked from.
    static var messagesNotClearedTitle: String {
        String(
            localized: "Messages Not Cleared",
            comment: "Alert title: a conversation's messages were not erased. The message says why."
        )
    }
}

/// Operations on a channel's group conversation, beyond sending. Bundled the
/// same way the channel-management actions are.
struct ChannelConversationActions: Sendable {
    /// Open a channel's conversation, creating it if this is the first time.
    let start: @Sendable (ChannelSummary) async throws -> ChannelConversationSummary
    /// The channel conversation at `address`, as a join that opened it
    /// returned it.
    let conversation: @Sendable (String) async throws -> ChannelConversationSummary
    /// Leave the group chat: the transcript goes, channel membership stays.
    let delete: @Sendable (ChannelConversationSummary) async throws -> Void
    /// Ask a member known only by their hint to identify themselves.
    let requestMemberIdentity: @Sendable (ChannelConversationSummary, Data) async throws -> Void
    /// Turn this channel's banners on or off. The same setting the Channels
    /// tab carries, reachable from the conversation it actually affects.
    /// Unread counts are unaffected—muting silences banners, not the channel.
    let setNotifications: @Sendable (ChannelSummary, Bool) async throws -> Void
    /// Agree to the warning before sending on `EMERGENCY`. The core keeps the
    /// agreement until the identity changes or the app next launches. Throws
    /// when the core does not take it.
    let certifyEmergency: @MainActor @Sendable () throws -> Void

    static let unavailable = ChannelConversationActions(
        start: { _ in throw MobileAppError.NotRunning },
        conversation: { _ in throw MobileAppError.NotRunning },
        delete: { _ in },
        requestMemberIdentity: { _, _ in },
        setNotifications: { _, _ in },
        certifyEmergency: { throw MobileAppError.NotRunning }
    )
}

struct PeerPingReply: Equatable, Sendable {
    /// `nil` when the core could not time the reply.
    let roundTripMilliseconds: UInt64?
    /// Radio links the reply crossed, counting the final one into this
    /// phone's radio: a direct reply is one hop. `nil` when the reply came
    /// source-routed without a trace route—hops it took went unrecorded.
    let hopCount: UInt8?
    /// The repeaters the reply crossed, the one nearest this phone first,
    /// already rendered by the Rust core. The two endpoints are not included.
    let routeHints: [MeshRouterHint]
    /// How each repeater in `routeHints` heard the node one step farther
    /// out, entry for entry. Empty when the reply carried no such readings.
    let traceSignal: [MeshLegSignal]
    /// How this phone's radio heard the last hop.
    let rssiDBm: Int16?
    let signalToNoiseCentibels: Int16?
    let linkQuality: UInt8?
    /// The reply answered the ping's Route Retry: the first attempt, or
    /// its acknowledgment, was lost along the route it took.
    let viaRouteRetry: Bool
    /// Repeaters the reply crossed that `routeHints` does not name, as the
    /// core counts them; `nil` when the hop count is unknown.
    let unnamedHops: UInt8?
}

/// What this phone's MAC has learned about how to reach a peer. It is the
/// path the next frame will take, not a record of the last one.
struct PeerRoute: Equatable, Sendable {
    enum Kind: Equatable, Sendable {
        /// There is no mesh session to ask—no radio attached, or one that
        /// is not set up for this phone. Distinct from `unknown`, which is a
        /// real answer from a live MAC.
        case unavailable
        /// Nothing is cached, so the next send floods.
        case unknown
        case direct
        case source
        case flood
    }

    let kind: Kind
    /// Repeaters named by a source route, in send order.
    let hints: [MeshRouterHint]
    /// Distance to the peer in hops, the same number a ping reply's hop
    /// count reports: one for a direct peer, repeaters plus one for a source
    /// route, flood hops plus one for a flood route.
    let hopCount: UInt8?
    /// Flood hops a flood route was learned at, the raw `FHOPS_ACC`; one
    /// less than `hopCount`.
    let floodHops: UInt8?
    /// Two-octet region codes learned alongside a flood route.
    let floodRegions: [Data]
    /// Flood hops a held route spends past its last repeater, or from the
    /// start for a direct one; `nil` when the route is not held.
    var heldFloodHops: UInt8? = nil
    /// When the hold on a manual route ends; `nil` when the route is not
    /// held. While held, nothing the mesh teaches replaces it.
    var holdUntil: Date? = nil
    /// Consecutive sends on the held route that missed and were then
    /// acknowledged through the flood fallback.
    var fallbackAcks: UInt8 = 0
    /// When an acknowledgment last came back for a send on this route.
    var lastAcknowledged: Date? = nil
    /// The best path learned while the route was held.
    var candidate: Candidate? = nil
    /// Where an ask for identities near the peer can be steered, as the core
    /// decides it; `nil` when there is no honest way.
    var discoveryVantage: DiscoveryVantage? = nil

    /// A path learned while a manual route was held.
    struct Candidate: Equatable, Sendable {
        let kind: Kind
        /// Repeaters it names, in send order.
        let hints: [MeshRouterHint]
        let hopCount: UInt8?
    }

    /// Where an ask for identities can be steered to reach the peer's
    /// neighborhood.
    struct DiscoveryVantage: Equatable, Sendable {
        /// Router hints to steer through, in send order. Never empty.
        let repeaters: [MeshRouterHint]
        /// The ask ends at the peer; otherwise at the last of `repeaters`.
        let landsAtPeer: Bool
        /// What the peer's own advertisement said, so the copy can hedge as
        /// much as the routing did.
        let evidence: MobileRepeaterEvidence
    }

    var isHeld: Bool { holdUntil != nil }

    /// How far a held route that names no repeaters floods from the start;
    /// `nil` when it names repeaters, floods nothing, or is not held.
    var heldFloodFromStart: UInt8? {
        guard hints.isEmpty, let hops = heldFloodHops, hops > 0 else { return nil }
        return hops
    }

    static let unknown = PeerRoute(
        kind: .unknown, hints: [], hopCount: nil, floodHops: nil, floodRegions: []
    )
    static let unavailable = PeerRoute(
        kind: .unavailable, hints: [], hopCount: nil, floodHops: nil, floodRegions: []
    )

    /// A source route naming no repeaters *is* a direct path: the MAC caches the
    /// empty trace a direct reply carried rather than a separate marker.
    var isDirect: Bool {
        kind == .direct || (kind == .source && hints.isEmpty)
    }
}

/// A path chosen by hand: the repeaters in send order, then how far the
/// frame may flood past the last of them. No repeaters is a direct path.
struct ManualPath: Equatable, Sendable {
    var hops: [MeshRouterHint]
    var floodHops: UInt8
}

/// How long a manual path is held before a learned path may replace it.
enum ManualPathHold: CaseIterable, Identifiable, Hashable, Sendable {
    case thirtyMinutes
    case oneHour
    case fourHours
    case twelveHours
    case oneDay

    static let standard = ManualPathHold.oneHour

    var id: Self { self }

    var duration: TimeInterval {
        switch self {
        case .thirtyMinutes: 30 * 60
        case .oneHour: 60 * 60
        case .fourHours: 4 * 60 * 60
        case .twelveHours: 12 * 60 * 60
        case .oneDay: 24 * 60 * 60
        }
    }

    /// The hold's length, in the reader's language: "30 min", "4 hr".
    var title: String {
        Duration.seconds(duration).formatted(.units(allowed: [.days, .hours, .minutes], width: .wide))
    }
}

/// Where an Identity Request is asked from.
///
/// `nil`—no vantage—is this phone's own neighborhood: the zero-hop
/// broadcast only direct neighbors hear. A vantage steers the same ask down a
/// route instead, so the nodes that answer are the ones in radio range of
/// wherever it lands, which is the only way to discover nodes this phone
/// cannot hear. Where it may be steered is the core's to decide
/// (`PeerRoute.discoveryVantage`); this carries that choice, with the peer it
/// was made for, to the Discover sheet.
struct SolicitVantage: Hashable, Sendable {
    let peerName: String
    let peerAddress: String
    /// Two-byte router hints to steer through, in send order. Never empty.
    ///
    /// Snapshotted when the vantage was chosen: the learned route may move
    /// while the sheet is open, and the ask should go where the user aimed it.
    let repeaters: [Data]
    /// The last repeater the ask passes through, when that is *not* the peer
    /// itself. `nil` means the ask is aimed at the peer, which is what lets the
    /// copy say "at" rather than "near" without overclaiming.
    let landingRepeater: MeshRouterHint?
    /// What was known about the peer when the vantage was built. Carried so the
    /// copy can hedge exactly as much as the routing did: aiming at a peer whose
    /// role was never heard is a guess, and reads as one.
    let evidence: MobileRepeaterEvidence

    var landsAtPeer: Bool { landingRepeater == nil }

    /// The vantage for asking near `peer`, or `nil` when the core found no
    /// honest way to steer an ask there.
    init?(peer: PeerSummary, vantage: PeerRoute.DiscoveryVantage?) {
        guard let vantage, let last = vantage.repeaters.last else { return nil }
        repeaters = vantage.repeaters.map(\.bytes)
        landingRepeater = vantage.landsAtPeer ? nil : last
        evidence = vantage.evidence
        peerName = peer.displayName
        peerAddress = peer.identity.canonicalAddress
    }
}

/// Put what name we can to a two-byte router hint.
///
/// A hint is 16 bits of a public key, so it narrows the field rather than
/// identifying a node: a single match is named, several matches are counted,
/// and a match among repeater-capable nodes is preferred over a bare one.
/// Any name it yields is a guess and must be shown as one.
enum RouterHintNaming {
    /// The one node a hint most plausibly names, or `nil` when the hint is
    /// ambiguous or matches nothing known.
    static func match(_ hint: MeshRouterHint, among peers: [PeerSummary]) -> PeerSummary? {
        let candidates = peers.filter { hint.matches($0.identity) }
        let repeaters = candidates.filter(\.isLikelyRepeater)
        if repeaters.count == 1 { return repeaters.first }
        return candidates.count == 1 ? candidates.first : nil
    }

    /// A hint rendered for prose: a matched node's name, else the hint text.
    static func label(_ hint: MeshRouterHint, among peers: [PeerSummary]) -> String {
        match(hint, among: peers)?.displayName ?? hint.text
    }

    /// The sentence to append wherever a name came from `match`, since a
    /// two-byte hint can never prove which node forwarded a frame.
    static var ambiguityNote: String {
        String(
            localized: "Repeater names are matched by a two-byte hint and may not be the node shown.",
            comment: "Footer under a path whose repeaters were named by guessing from their short hints."
        )
    }
}

/// One repeater a peer reported as its neighbor, from a Peer Repeaters
/// Response.
///
/// Everything past the hint is optional because the reporting node holds only
/// so much: an identity it heard supplies the name, position, and regions; a
/// reception supplies the signal; neither supplies the other.
struct PeerRepeaterNeighbor: Hashable, Sendable {
    /// Three bytes when the reporting node's identity table named the node, two
    /// when only a reception did—all a trace reveals about a transmitter.
    let hint: Data
    /// The hint as the core renders it, so it reads the same as a hint
    /// anywhere else in the app.
    let hintText: String
    let name: String?
    let rssiDBm: Int16?
    /// Quarter-decibel steps, as the wire carries it.
    let snrQuarterDB: Int16?
    /// Minutes before `reportedAt` that the router last heard the node.
    /// Saturates at 65535—about 45 days—which the wire uses to say "long
    /// ago" rather than a measurement.
    let lastHeardMinutes: UInt16?
    let latitude: Double?
    let longitude: Double?
    /// The disclosed cell's precision in encoded bytes.
    let locationPrecision: UInt8?
    let regionCodes: [Data]
    /// When the router answered. The ages above are relative to this.
    let reportedAt: Date
    /// The node the core matched this neighbor to, by address; `nil` when
    /// it names none of this phone's peers.
    var peerAddress: String? = nil

    /// The hint drawn as an avatar. A two-byte hint has no third octet to
    /// color by and draws gray, which is the honest rendering of a node
    /// known only by its trace.
    var avatarHint: MeshNodeHint { MeshNodeHint(bytes: hint, text: hintText) }

    var hasLocation: Bool { latitude != nil && longitude != nil }

    /// Whether the router's last-heard figure is a measurement rather than
    /// the saturated "long ago".
    var lastHeardIsMeasured: Bool {
        guard let lastHeardMinutes else { return false }
        return lastHeardMinutes < UInt16.max
    }

    /// When the router last heard the node, on this phone's clock. `nil`
    /// when the router gave no figure or only the saturated one.
    var lastHeardAt: Date? {
        guard let lastHeardMinutes, lastHeardIsMeasured else { return nil }
        return reportedAt.addingTimeInterval(-Double(lastHeardMinutes) * 60)
    }

    /// Whether the router's last hearing of the node is older than `age`.
    /// The saturated figure is older than any age worth asking about; no
    /// figure at all is not old, merely unknown.
    func lastHeard(isOlderThan age: TimeInterval, now: Date = .now) -> Bool {
        guard lastHeardMinutes != nil else { return false }
        guard let lastHeardAt else { return true }
        return now.timeIntervalSince(lastHeardAt) > age
    }

    /// The one node this neighbor most plausibly is, among those this phone
    /// knows, as the core matched it. A two-byte hint is the same guess a
    /// route hop makes, and reads as one.
    func resolve(among peers: [PeerSummary]) -> PeerSummary? {
        guard let peerAddress else { return nil }
        return peers.first { $0.identity.canonicalAddress == peerAddress }
    }

    /// What to call the neighbor: the known node's name, else the name the
    /// router relayed, else the hint.
    func title(among peers: [PeerSummary]) -> String {
        resolve(among: peers)?.displayName ?? name ?? hintText
    }
}

/// What one router has said about its neighborhood, as far as this phone
/// has asked.
struct PeerRepeaterListing: Hashable, Sendable {
    let entries: [PeerRepeaterNeighbor]
    /// How many neighbors the router holds in all, when it said.
    let total: Int?
    /// Where the next page starts. `nil` when the pages in hand are the
    /// whole listing.
    let nextCursor: Data?
    /// When the most recent page was answered.
    let asOf: Date

    var isComplete: Bool { nextCursor == nil }
}

enum PeerRepeatersPageResult: Equatable, Sendable {
    /// The listing as it now stands, this page folded in.
    case page(PeerRepeaterListing)
    /// The router did not answer within the page deadline.
    case noAnswer
    /// The request could not be handed to the radio.
    case failed
    case unavailable(reason: String)
}

/// A neighbor together with the router that reported it, which is how the
/// map draws a node this phone has never heard itself.
struct PeerRepeaterNeighborReport: Hashable, Sendable {
    let reporter: PeerSummary
    let neighbor: PeerRepeaterNeighbor
}

/// Everything the peer sheet can do with the node it is showing.
///
/// Bundled because `PeerDetailView` is opened from many places—the Peers
/// list, a conversation's header, the map, a link, Settings' radio identity,
/// device setup, and other peers' pages—and passing these one parameter at
/// a time made the same page offer different things depending on where it
/// was opened. One value threaded through means one page with one set of
/// capabilities.
/// Deliberately not `Sendable`: these are main-actor operations owned by the
/// app root, handed to views that also live on the main actor.
struct PeerActions {
    /// Nodes recorded on this phone, used to put names to router hints.
    var knownPeers: [PeerSummary] = []
    /// Open the conversation with the node, creating it the first time.
    var startConversation: ((PeerSummary) async throws -> DirectConversationSummary)? = nil
    var ping: ((PeerSummary) async -> PeerPingResult)? = nil
    var fetchIdentity: ((PeerSummary) async throws -> Void)? = nil
    var updateAlias: ((PeerSummary, String?) async throws -> Void)? = nil
    /// Read the route this phone would use for the next frame to the node.
    var loadRoute: ((PeerSummary) async -> PeerRoute)? = nil
    /// Discard that route, reporting whether one was held.
    var resetRoute: ((PeerSummary) async -> Bool)? = nil
    /// Ask the node behind a hint to identify itself, given the hint and the
    /// two-byte router hints of the repeaters ahead of it in send order.
    ///
    /// A route names its hops by two bytes and nothing else, so the answer is
    /// the only way to know who is actually carrying the traffic.
    var identifyRepeater: ((Data, [Data]) async throws -> Void)? = nil
    /// What a repeater last said about its neighbors, from this phone's cache.
    /// Nothing goes on the air.
    var cachedPeerRepeaters: ((PeerSummary) async -> PeerRepeaterListing?)? = nil
    /// Ask a repeater for one page of its neighbor listing—the first page
    /// without a cursor, the page after a held one with it. Never follows a
    /// cursor on its own: every page is a tap, because every page costs the
    /// mesh airtime.
    var loadPeerRepeaters: ((PeerSummary, Data?) async -> PeerRepeatersPageResult)? = nil
    /// The same ask, sent down an explicit path in send order rather than
    /// along whatever route this phone holds for the repeater.
    var loadPeerRepeatersAlong: ((PeerSummary, Data?, [MeshRouterHint]) async -> PeerRepeatersPageResult)? = nil
    /// The companion radio's own node, which answers for the repeaters this
    /// phone can reach first. `nil` when no radio has a node identity.
    var radioIdentityPeer: PeerSummary? = nil
    /// Hold a path for the node until the hold ends, reporting whether the
    /// phone's routing took it.
    var setManualPath: ((PeerSummary, ManualPath, ManualPathHold) async -> Bool)? = nil
    /// Drop a held path. The node goes back to what the mesh teaches.
    var clearManualPath: ((PeerSummary) async -> Bool)? = nil
    /// Replace a held path with the one learned while it was held.
    var adoptLearnedPath: ((PeerSummary) async -> Bool)? = nil
    /// Decline the offer to replace a held path; it is not made again for the
    /// same path.
    var keepManualPath: ((PeerSummary) async -> Void)? = nil
    /// The held route, when it is time to offer the path learned while it
    /// was held instead. `nil` otherwise.
    var learnedPathOffer: ((PeerSummary) async -> PeerRoute?)? = nil
    /// Ping the node down an explicit path without installing it.
    var pingAlongPath: ((PeerSummary, ManualPath) async -> PeerPingResult)? = nil
    /// Read a router hint typed by a person.
    var parseRouterHint: ((String, RouterHintFormat) async -> RouterHintInput)? = nil
    /// Render two key bytes as a router hint.
    var renderRouterHint: ((Data) async -> MeshRouterHint?)? = nil
    /// Mark or unmark the node as a favorite. Saved nodes only.
    var setFavorite: ((PeerSummary, Bool) async throws -> Void)? = nil
    /// Arm or disarm the one-shot watch on the node: notify once, the next
    /// time anything is heard from it, then disarm itself.
    var setNotifyWhenHeard: ((PeerSummary, Bool) async throws -> Void)? = nil
    /// Turn a direct conversation's notifications on or off—on the phone,
    /// and on a companion radio holding its messages while the phone is away.
    var setConversationNotifications: ((DirectConversationSummary, Bool) async throws -> Void)? = nil
    /// Save a transient node onto the local identity.
    var promoteToSaved: ((PeerSummary) async throws -> Void)? = nil
    /// Take a saved node off the local identity, keeping its history and
    /// searchability. The row survives as a transient.
    var demoteToTransient: ((PeerSummary) async throws -> Void)? = nil
    /// Delete the node's row outright. Refused when a
    /// conversation exists—offer `deletePeerAndConversation` instead.
    var deletePeer: ((PeerSummary) async throws -> Void)? = nil
    /// Delete the node and its conversation history in one transaction.
    var deletePeerAndConversation: ((PeerSummary) async throws -> Void)? = nil
    /// Open this node's settings: the companion radio over its own link,
    /// everything else across the mesh. Nil only where no core could
    /// manage anything at all.
    var manageDevice: (@MainActor (PeerSummary) async throws -> ManageDeviceModel)? = nil
    /// Open the attached companion radio's settings over its own link,
    /// whether or not it has an identity of its own to be a peer under.
    /// Takes what to call it until it says.
    var manageCompanion: (@MainActor (String) async throws -> ManageDeviceModel)? = nil
    /// Open the settings of the bench device an administrative session's
    /// driver is attached to, with this phone's key on that device.
    var manageAdministered: (
        @MainActor (MobileRadioDriver, Data?, PeerSummary) async throws -> ManageDeviceModel
    )? = nil

    /// No app services wired up—used by previews and by any sheet built
    /// before the mesh session exists.
    @MainActor static let unavailable = PeerActions()
}

enum PeerPingResult: Equatable, Sendable {
    case reply(PeerPingReply)
    case timedOut
    /// A newer ping to the same node replaced this one before it was
    /// answered.
    case canceled
    /// The ping never went out. `reason` is already in the reader's
    /// language.
    case unavailable(reason: String)
}
