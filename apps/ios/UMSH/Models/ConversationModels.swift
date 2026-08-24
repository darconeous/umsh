import Foundation

struct PeerSummary: Identifiable, Hashable, Sendable {
    let id: Int64
    let identity: MeshPublicIdentity
    let alias: String?
    let advertisedName: String?
    let systemRole: String?
    /// The role last recorded for this node, so the answer survives a restart
    /// and so a device configured through this phone reads correctly before it
    /// has ever been heard on the air. Superseded by a live advertisement.
    let storedRole: PeerRole
    /// Decoded advertised identity, when a bundle has been imported or
    /// received for this peer.
    var advertisedIdentity: MeshNodeIdentity? = nil
    /// Whether the MAC authenticated the frame that delivered
    /// `advertisedIdentity`. See `advertisedIdentityIsAttributable`.
    var advertisedIdentityAuthenticated: Bool = false
    /// When we last heard from this peer by any means — beacon, advertisement,
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

    var displayName: String {
        alias ?? advertisedName ?? (isUlcpDevice ? "Companion radio" : identity.hint.text)
    }

    var isUlcpDevice: Bool { systemRole == "companion_radio" }

    /// What this node says it is. A live advertisement wins over the stored
    /// role, so the answer tracks the node rather than whatever was true when
    /// the row was created.
    var role: PeerRole {
        guard let advertisedIdentity else { return storedRole }
        return PeerRole(roleCode: advertisedIdentity.roleCode)
    }

    /// Whether this node plausibly forwards other nodes' traffic: advertising
    /// the repeater role, or the repeater capability alongside some other
    /// role. An advertisement is the node's own claim, not proof.
    var isLikelyRepeater: Bool {
        role == .repeater
            || advertisedIdentity?.capabilities
                .contains(MeshNodeIdentity.repeaterCapabilityLabel) == true
    }

    /// What this phone actually knows about whether the node repeats.
    ///
    /// `isLikelyRepeater` answers `false` identically for a node we know to be
    /// a tracker and a node we have only ever seen as a hint in someone else's
    /// trace. Those are different states, and a decision that treats them the
    /// same gets one of them wrong. `role` already falls back to `storedRole`
    /// and `.unknown` already names an absence rather than a choice, so the
    /// third value is there for the asking.
    var repeaterEvidence: RepeaterEvidence {
        if isLikelyRepeater { return .yes }
        return role == .unknown ? .unknown : .no
    }

    /// This node's own two-byte router hint — the leading bytes of its key,
    /// which is what a repeater carrying its traffic would put on the wire.
    /// `nil` only for a hint too short to take one from.
    var routerHintBytes: Data? {
        let bytes = identity.hint.bytes.prefix(2)
        return bytes.count == 2 ? Data(bytes) : nil
    }

    /// Whether the advertised claims may be attributed to this peer at all.
    ///
    /// Something has to have authenticated them: either the bundle's own
    /// signature verifies against the key, or the MAC authenticated the frame
    /// that carried it. A broadcast advertisement has no MIC and must
    /// therefore be signed; an Identity Request reply is a MIC-authenticated
    /// unicast that deliberately carries no signature. A signature that is
    /// present and fails is never trusted, however the bundle arrived.
    var advertisedIdentityIsAttributable: Bool {
        switch advertisedIdentity?.signature {
        case .valid: true
        case .unsigned: advertisedIdentityAuthenticated
        case .invalid, nil: false
        }
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
    /// No identity has been heard for this node yet, or the role byte it
    /// claimed is one this app has no name for. An unrecognized byte still
    /// round-trips on the wire; it just cannot be described here.
    case unknown

    var id: Self { self }

    /// The roles a device can be configured to advertise. `unknown` is not
    /// among them: it describes an absence, not a choice.
    static let selectable: [PeerRole] = [.repeater, .chat, .tracker, .sensor, .bridge]

    var label: String {
        switch self {
        case .repeater: "Repeater"
        case .chat: "Chat"
        case .tracker: "Tracker"
        case .sensor: "Sensor"
        case .bridge: "Bridge"
        case .unknown: "Unknown"
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
        case .unknown: nil
        }
    }

    init(roleCode: UInt8) {
        self = PeerRole.selectable.first { $0.roleCode == roleCode } ?? .unknown
    }

    /// How a role byte is described, keeping an unrecognized one visible as a
    /// number rather than flattening it to "Unknown" — the node did claim
    /// something.
    static func label(forCode code: UInt8) -> String {
        let role = PeerRole(roleCode: code)
        return role == .unknown ? "Role \(code)" : role.label
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
struct ConversationPreviewMessage: Hashable, Sendable {
    let createdAtMilliseconds: Int64
    let body: String
    let isOutbound: Bool
    let isDeleted: Bool
    /// Who sent this, in a group conversation: the resolved address once known,
    /// and the hint the wire always carries.
    let senderAddress: String?
    let senderHint: Data?

    /// A short, stable label for a member known only by their hint. Mirrors
    /// ``ChatMessageSummary/senderHintLabel`` so a list row and a bubble name
    /// the same member the same way.
    var senderHintLabel: String? {
        senderHint.map { hint in hint.map { String(format: "%02x", $0) }.joined() }
    }
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
/// so there is no peer on the other end — only members, who are known by the
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

struct ChatMessageSummary: Identifiable, Hashable, Sendable {
    let id: String
    let body: String
    let isOutbound: Bool
    let deliveryState: String?
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
    /// Safe to compare alongside the rest of the message — `ChatMessageBubble`
    /// is `Equatable` to avoid re-measuring its `UITextView` — because a row's
    /// ordering key is fixed for its lifetime. Two summaries of the same
    /// message always agree on it.
    let cursor: ChatMessageCursor
    /// A reserved gap slot awaiting repair — rendered as a spinner placeholder,
    /// not a real bubble.
    var isGapPlaceholder: Bool = false
    /// A gap whose repair failed — rendered as a subtle "message unavailable"
    /// marker.
    var isUnavailable: Bool = false
    /// Filled its ordered slot out of order — annotated "Received late".
    var isReceivedLate: Bool = false
    /// Outbound message delivered on a resend after a transport failure —
    /// annotated "Delivered Late".
    var isDeliveredLate: Bool = false
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

    /// The reaction this user has on this message, if any. What the picker
    /// shows as chosen, and what tapping the same emoji again withdraws.
    var myReaction: MessageReaction? { reactions.first(where: \.isMine) }

    /// A short, stable label for a member known only by their hint.
    var senderHintLabel: String? {
        senderHint.map { hint in hint.map { String(format: "%02x", $0) }.joined() }
    }

    /// When this was written, or nil for a record carrying no usable time —
    /// a gap placeholder standing in for a message nobody has seen yet.
    var sentDate: Date? {
        guard createdAtMilliseconds > 0 else { return nil }
        return Date(timeIntervalSince1970: Double(createdAtMilliseconds) / 1000)
    }
}

/// One person's reaction to one message.
struct MessageReaction: Identifiable, Hashable, Sendable {
    var id: String { "\(sessionID):\(handle)" }
    /// The emote body as it arrived, before normalization.
    let body: String
    let isMine: Bool
    let senderAddress: String?
    let senderHint: Data?
    let sessionID: String
    let handle: UInt32
    let wireID: UInt8?
    let epoch: UInt16?
    /// One of ours the radio could not deliver. Drawn faded; everything else
    /// — including a reaction still in flight — looks normal, because being
    /// in flight is the ordinary case and not worth alarming anyone about.
    let isFailed: Bool

    /// The single glyph this reaction renders as.
    var glyph: String { ReactionEmoji.displayGlyph(for: body) }

    /// Spoken description, so a reaction is never conveyed by color or
    /// glyph alone.
    var accessibilityDescription: String {
        let name = ReactionEmoji.name(for: glyph)
        let who = isMine ? "you" : (senderAddress.map { String($0.prefix(8)) } ?? "someone")
        return isFailed ? "\(name) from \(who), not delivered" : "\(name) from \(who)"
    }
}

/// The reaction vocabulary: what the picker offers, what goes on the wire,
/// and how an arriving body becomes one glyph.
///
/// Short tokens are what the wire carries — they are what the protocol's own
/// examples use, and two characters of airtime instead of four matters more
/// here than anywhere else in the app. Reading is deliberately looser than
/// writing: anything recognizable maps to the same glyph, and anything else
/// falls back to its own first character rather than being dropped.
enum ReactionEmoji {
    /// The picker's palette, in the order it is offered.
    static let palette: [(glyph: String, token: String)] = [
        ("🩷", "<3"),
        ("👍", "+1"),
        ("👎", "-1"),
        ("🤣", "ha"),
        ("‼️", "!"),
        ("❓", "?"),
    ]

    /// Bodies that stand for a palette glyph, lowercased.
    private static let upgrades: [String: String] = [
        "<3": "🩷", "♥": "🩷", "♥︎": "🩷", "❤": "🩷", "❤️": "🩷",
        "+1": "👍", "👍🏻": "👍", "👍🏼": "👍", "👍🏽": "👍", "👍🏾": "👍", "👍🏿": "👍",
        "-1": "👎", "👎🏻": "👎", "👎🏼": "👎", "👎🏽": "👎", "👎🏾": "👎", "👎🏿": "👎",
        "ha": "🤣", "haha": "🤣", "hahaha": "🤣", "lol": "🤣", "lmao": "🤣",
        "!": "‼️", "!!": "‼️", "❗": "‼️", "❕": "‼️",
        "?": "❓", "??": "❓", "❔": "❓",
    ]

    private static let names: [String: String] = [
        "🩷": "heart", "👍": "thumbs up", "👎": "thumbs down",
        "🤣": "laughing", "‼️": "exclamation", "❓": "question",
    ]

    /// The wire token for a palette glyph, or the glyph itself for anything
    /// outside the palette.
    static func token(for glyph: String) -> String {
        palette.first { $0.glyph == glyph }?.token ?? glyph
    }

    /// What a reaction body renders as: a palette glyph when the body is one
    /// of its spellings, otherwise the body's own first character. Only ever
    /// one glyph — a peer that sends a sentence still gets a chip.
    static func displayGlyph(for body: String) -> String {
        let trimmed = body.trimmingCharacters(in: .whitespacesAndNewlines)
        if let upgraded = upgrades[trimmed.lowercased()] { return upgraded }
        guard let first = trimmed.first else { return "" }
        // A single character may still be a spelling we know — a bare "?"
        // reaches this only if the table above missed it.
        if let upgraded = upgrades[String(first).lowercased()] { return upgraded }
        return String(first)
    }

    static func name(for glyph: String) -> String {
        names[glyph] ?? glyph
    }
}

enum MessageSendResult: Sendable {
    case sent(ConversationListItem)
    case failed(String)
}

/// Message-level operations on an open transcript. Bundled so intermediate
/// views do not grow a parameter per operation.
struct ChatMessageActions: Sendable {
    let edit: @Sendable (ConversationListItem, ChatMessageSummary, String) async -> MessageSendResult
    let delete: @Sendable (ConversationListItem, ChatMessageSummary) async -> MessageSendResult
    /// React with one of the palette glyphs, or withdraw the existing
    /// reaction by passing the one already chosen.
    var react: @Sendable (ConversationListItem, ChatMessageSummary, String) async
        -> MessageSendResult = { _, _, _ in .failed("Messaging is unavailable.") }
    /// Erase every message in the conversation at this address. Local only:
    /// nothing is sent, and everyone else keeps their copy. The conversation
    /// itself survives, as does its place in the wire stream.
    var clearMessages: @Sendable (String) async -> Void = { _ in }
    /// How many messages the conversation at this address holds. Asked for on
    /// demand rather than carried on the summary: it is the one figure that has
    /// to walk a whole transcript, and only the info sheet wants it.
    var countMessages: @Sendable (String) async -> Int = { _ in 0 }

    static let unavailable = ChatMessageActions(
        edit: { _, _, _ in .failed("Messaging is unavailable.") },
        delete: { _, _ in .failed("Messaging is unavailable.") }
    )
}

/// Operations on a channel's group conversation, beyond sending. Bundled the
/// same way the channel-management actions are.
struct ChannelConversationActions: Sendable {
    /// Open a channel's conversation, creating it if this is the first time.
    let start: @Sendable (ChannelSummary) async -> ChannelConversationSummary?
    /// Open the conversation for a channel that was just joined. Joining from
    /// here is a request to talk in the channel, so the chat opens with it —
    /// unlike joining from Settings, which is membership alone.
    let startAfterJoin: @Sendable (MeshChannelPreview) async -> ChannelConversationSummary?
    /// Leave the group chat: the transcript goes, channel membership stays.
    let delete: @Sendable (ChannelConversationSummary) async -> Void
    /// Ask a member known only by their hint to identify themselves.
    let requestMemberIdentity: @Sendable (ChannelConversationSummary, Data) async -> Void
    /// Turn this channel's banners on or off. The same setting the Channels
    /// tab carries, reachable from the conversation it actually affects.
    /// Unread counts are unaffected — muting silences banners, not the channel.
    let setNotifications: @Sendable (ChannelSummary, Bool) async -> Void

    static let unavailable = ChannelConversationActions(
        start: { _ in nil },
        startAfterJoin: { _ in nil },
        delete: { _ in },
        requestMemberIdentity: { _, _ in },
        setNotifications: { _, _ in }
    )
}

struct PeerPingReply: Equatable, Sendable {
    let roundTripMilliseconds: UInt64
    /// Radio links the reply crossed, counting the final one into this
    /// phone's radio: a direct reply is one hop. `nil` when the reply came
    /// source-routed without a trace route — hops it took went unrecorded.
    let hopCount: UInt8?
    /// Intermediate routers in source-to-destination order, already rendered
    /// by the Rust core. The two endpoints are not included.
    let routeHints: [MeshRouterHint]
    let rssiDBm: Int16?
    let signalToNoiseCentibels: Int16?
    let linkQuality: UInt8?
}

/// What this phone's MAC has learned about how to reach a peer. It is the
/// path the next frame will take, not a record of the last one.
struct PeerRoute: Equatable, Sendable {
    enum Kind: Equatable, Sendable {
        /// There is no mesh session to ask — no radio attached, or one that
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
    /// Routers named by a source route, in send order.
    let hints: [MeshRouterHint]
    let floodHops: UInt8?
    /// Two-octet region codes learned alongside a flood route.
    let floodRegions: [Data]

    static let unknown = PeerRoute(kind: .unknown, hints: [], floodHops: nil, floodRegions: [])
    static let unavailable = PeerRoute(kind: .unavailable, hints: [], floodHops: nil, floodRegions: [])

    /// A source route naming no routers *is* a direct path: the MAC caches the
    /// empty trace a direct reply carried rather than a separate marker.
    var isDirect: Bool {
        kind == .direct || (kind == .source && hints.isEmpty)
    }
}

/// How sure this phone is that a node forwards other nodes' traffic.
enum RepeaterEvidence: Equatable, Sendable {
    /// It advertised the repeater role or capability.
    case yes
    /// No identity has been heard for it, so there is nothing to go on.
    case unknown
    /// It advertised something else.
    case no
}

/// Where an Identity Request is asked from.
///
/// `nil` — no vantage — is this phone's own neighborhood: the zero-hop
/// broadcast only direct neighbors hear. A vantage steers the same ask down a
/// route instead, so the nodes that answer are the ones in radio range of
/// wherever it lands, which is the only way to discover nodes this phone
/// cannot hear. A flood-routed ask is not an option: nothing narrows how many
/// nodes would answer it.
struct SolicitVantage: Hashable, Sendable {
    let peerName: String
    let peerAddress: String
    /// Two-byte router hints to steer through, in send order. Never empty.
    ///
    /// Snapshotted when the vantage was chosen: the learned route may move
    /// while the sheet is open, and the ask should go where the user aimed it.
    let routers: [Data]
    /// The last router the ask passes through, when that is *not* the peer
    /// itself. `nil` means the ask is aimed at the peer, which is what lets the
    /// copy say "at" rather than "near" without overclaiming.
    let landingRouter: MeshRouterHint?
    /// What was known about the peer when the vantage was built. Carried so the
    /// copy can hedge exactly as much as the routing did: aiming at a peer whose
    /// role was never heard is a guess, and reads as one.
    let evidence: RepeaterEvidence

    var landsAtPeer: Bool { landingRouter == nil }

    /// Derive the vantage for asking near `peer`, or `nil` when there is no
    /// honest way to steer an ask there.
    ///
    /// A cached route excludes its endpoints, so the route *to* a peer stops
    /// at the last router before it. Landing *at* the peer means appending the
    /// peer's own hint, which is only safe when we have positive evidence it
    /// repeats: the choice is asymmetric. Not appending when the peer does
    /// repeat lands the ask one hop short, which is still useful. Appending
    /// when it does not kills the ask outright — the router before it looks
    /// for a next hop that will never forward. So append only on evidence, and
    /// let the copy carry the uncertainty rather than the route.
    init?(peer: PeerSummary, route: PeerRoute?) {
        guard let route, let peerHint = peer.routerHintBytes else { return nil }
        let evidence = peer.repeaterEvidence
        self.evidence = evidence

        switch route.kind {
        case .source where !route.hints.isEmpty:
            let learned = route.hints
            if evidence == .yes {
                routers = learned.map(\.bytes) + [peerHint]
                landingRouter = nil
            } else {
                routers = learned.map(\.bytes)
                landingRouter = learned.last
            }
        case .direct, .source:
            // Heard directly, so the route names no routers. Asking *through*
            // this node is exactly how to reach what sits behind it — the
            // bench case worth having — but only if it forwards at all. When
            // we know it does not, a plain nearby ask already covers it.
            guard evidence != .no else { return nil }
            routers = [peerHint]
            landingRouter = nil
        case .flood, .unknown, .unavailable:
            // A flood route counts routers, it does not name them, so there is
            // nothing to steer with.
            return nil
        }

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
    static let ambiguityNote =
        "Router names are matched by a two-byte hint and may not be the node shown."
}

/// Everything the peer sheet can do with the node it is showing.
///
/// Bundled because `PeerDetailView` is presented from four places — the
/// Peers list, a conversation's title bar, Settings' radio identity, and
/// device setup — and passing these one parameter at a time made the same
/// sheet offer different things depending on where it was opened. One value
/// threaded through means one sheet with one set of capabilities.
/// Deliberately not `Sendable`: these are main-actor operations owned by the
/// app root, handed to views that also live on the main actor.
struct PeerActions {
    /// Nodes recorded on this phone, used to put names to router hints.
    var knownPeers: [PeerSummary] = []
    var startConversation: ((PeerSummary) async -> DirectConversationSummary?)? = nil
    var ping: ((PeerSummary) async -> PeerPingResult)? = nil
    var fetchIdentity: ((PeerSummary) async -> Bool)? = nil
    var updateAlias: ((PeerSummary, String?) async -> Bool)? = nil
    /// Read the route this phone would use for the next frame to the node.
    var loadRoute: ((PeerSummary) async -> PeerRoute)? = nil
    /// Discard that route, reporting whether one was held.
    var resetRoute: ((PeerSummary) async -> Bool)? = nil
    /// Ask one intermediate router on a route to identify itself, given its
    /// hint and the routers ahead of it in send order.
    ///
    /// A route names its hops by two bytes and nothing else, so the answer is
    /// the only way to know who is actually carrying the traffic.
    var identifyRouter: ((MeshRouterHint, [MeshRouterHint]) async -> Bool)? = nil
    /// Mark or unmark the node as a favorite. Saved nodes only.
    var setFavorite: ((PeerSummary, Bool) async -> Bool)? = nil
    /// Arm or disarm the one-shot watch on the node: notify once, the next
    /// time anything is heard from it, then disarm itself.
    var setNotifyWhenHeard: ((PeerSummary, Bool) async -> Bool)? = nil
    /// Save a transient node onto the local identity.
    var promoteToSaved: ((PeerSummary) async -> Bool)? = nil
    /// Take a saved node off the local identity, keeping its history and
    /// searchability. The row survives as a transient.
    var demoteToTransient: ((PeerSummary) async -> Bool)? = nil
    /// Delete the node's row outright. Refused by the store when a
    /// conversation exists — offer `deletePeerAndConversation` instead.
    var deletePeer: ((PeerSummary) async -> Bool)? = nil
    /// Delete the node and its conversation history in one transaction.
    var deletePeerAndConversation: ((PeerSummary) async -> Bool)? = nil
    /// Store the node's public key on the companion radio's device identity.
    var addToDeviceIdentity: ((PeerSummary) async -> DevicePeerActionOutcome)? = nil
    /// Remove the node's public key from the radio's device identity.
    var removeFromDeviceIdentity: ((PeerSummary) async -> DevicePeerActionOutcome)? = nil
    /// The way to read and change this node's settings, chosen per peer:
    /// the companion radio is managed over its own link, everything else
    /// across the mesh. Nil only where no backend could exist at all.
    var manageDevice: ((PeerSummary) -> DeviceManagementBackend)? = nil

    /// No app services wired up — used by previews and by any sheet built
    /// before the mesh session exists.
    @MainActor static let unavailable = PeerActions()
}

enum PeerPingResult: Equatable, Sendable {
    case reply(PeerPingReply)
    case timedOut
    case unavailable(reason: String)
}

/// Outcome of a device-identity peer mutation, shaped for inline UI copy.
/// `deviceFull` mirrors the radio's own `NOMEM`, which stays authoritative.
enum DevicePeerActionOutcome: Equatable, Sendable {
    case success
    case deviceFull
    case radioUnavailable
    case unsupported
    case failed
}
