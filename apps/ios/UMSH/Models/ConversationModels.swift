import Foundation

struct PeerSummary: Identifiable, Hashable, Sendable {
    let id: Int64
    let identity: MeshPublicIdentity
    let alias: String?
    let advertisedName: String?
    let isContact: Bool
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
    let isContact: Bool
}

struct DirectConversationSummary: Identifiable, Hashable, Sendable {
    let id: Int64
    let peer: PeerSummary
    var draftText: String
    var messages: [ChatMessageSummary]
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
}

enum MessageSendResult: Sendable {
    case sent(DirectConversationSummary)
    case failed(String)
}

/// Message-level operations on an open transcript. Bundled so intermediate
/// views do not grow a parameter per operation.
struct ChatMessageActions: Sendable {
    let edit: @Sendable (DirectConversationSummary, ChatMessageSummary, String) async -> MessageSendResult
    let delete: @Sendable (DirectConversationSummary, ChatMessageSummary) async -> MessageSendResult

    static let unavailable = ChatMessageActions(
        edit: { _, _, _ in .failed("Messaging is unavailable.") },
        delete: { _, _ in .failed("Messaging is unavailable.") }
    )
}

struct PeerPingReply: Equatable, Sendable {
    let roundTripMilliseconds: UInt64
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

/// Everything the peer sheet can do with the node it is showing.
///
/// Bundled because `PeerDetailView` is presented from four places — the
/// Network list, a conversation's title bar, Settings' radio identity, and
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

    /// No app services wired up — used by previews and by any sheet built
    /// before the mesh session exists.
    @MainActor static let unavailable = PeerActions()
}

enum PeerPingResult: Equatable, Sendable {
    case reply(PeerPingReply)
    case timedOut
    case unavailable(reason: String)
}
