import Foundation

/// A channel as the interface presents it.
///
/// Carries no key material: the key lives in the Keychain vault under `id`,
/// and is fetched only when something actually needs it (registering with the
/// MAC, provisioning the radio, building an invitation).
struct ChannelSummary: Identifiable, Hashable, Sendable {
    let id: UUID
    let kind: StoredChannelKind
    /// The folded form the key is derived from. Machinery — it decides which
    /// channel this is, but it is not what the channel is called, and the
    /// interface does not show it.
    let canonicalName: String?
    /// The channel's own name, written the way it was typed or shared.
    let name: String?
    /// What this user calls it. Takes display precedence everywhere but never
    /// overwrites `name`, exactly as a peer alias behaves.
    let alias: String?
    /// Two-octet derived identifier, hex. Shown as a disambiguator, never as
    /// an identity — distinct keys may collide here.
    let channelIDHex: String
    /// Three presentation octets, the identifier extended by one byte. Drives
    /// the channel's color so it looks the same on every device that holds
    /// the key.
    let tint: Data
    let regionCode: Data?
    let maxFloodHops: Int?
    let joinedPhone: Bool
    /// Whether the companion radio's device identity has joined. The device
    /// is authoritative; this is reconciled from it on attach.
    let joinedDevice: Bool
    let notificationsEnabled: Bool
    let joinedAt: Date?

    /// What to call this channel anywhere it is listed or titled. A private
    /// channel that was never named still needs a stable label, so it falls
    /// back to its identifier.
    var title: String {
        if let alias, !alias.isEmpty { return alias }
        if let name, !name.isEmpty { return name }
        return "Channel \(channelIDHex)"
    }

    /// Short label for the channel's type.
    var kindLabel: String {
        switch kind {
        case .builtin: "Built-in"
        case .named: "Public"
        case .privateKey: "Private"
        }
    }

    /// Whether an invitation to this channel discloses the key. Named and
    /// built-in channels share only a name, which is not a secret.
    var invitationIsSecret: Bool {
        kind == .privateKey
    }

    /// The flood-hop ceiling the protocol fixes for this channel, when it
    /// fixes one. `public` and `EMERGENCY` are capped at five hops without a
    /// region code and seven with one, so it is not the user's to choose.
    ///
    /// Keyed on the canonical name rather than the record's kind, because the
    /// name is what derives the key: joining `umsh:cs:public` by hand reaches
    /// the same channel and inherits the same rules.
    var protocolMaxFloodHops: Int? {
        switch canonicalName {
        case "public", "emergency": regionCode == nil ? 5 : 7
        default: nil
        }
    }

    /// The hop ceiling to actually use. A protocol-fixed channel ignores both
    /// the stored value and any `mh=` an invitation carried, so read this
    /// rather than `maxFloodHops` anywhere the number is acted on.
    var effectiveMaxFloodHops: Int? {
        protocolMaxFloodHops ?? maxFloodHops
    }

    /// How this channel behaves, where the protocol decides it.
    ///
    /// Written as statements of fact, not instructions: the app applies these
    /// itself and the user has nothing to comply with.
    var protocolBehavior: [String] {
        switch canonicalName {
        case "public":
            [
                "Every sender is identified. Messages that arrive without a full sender key are ignored.",
                "This channel carries group traffic only — it is never used to conceal a direct message.",
            ]
        case "emergency":
            [
                "All traffic here is unencrypted, so any node in range can read it — including nodes that never joined.",
                "Every message is signed and identifies its sender. Anything unsigned or unattributed is ignored.",
                "Repeaters give this channel priority.",
            ]
        default:
            []
        }
    }

    /// Whether the user may leave without losing the ability to come back.
    /// Built-in channels are always re-joinable by name; a private channel's
    /// key is gone once deleted.
    var canRejoinAfterLeaving: Bool {
        kind != .privateKey
    }

    var isJoined: Bool { joinedPhone || joinedDevice }

    /// Whether this channel answers to a search query, across the names a user
    /// would type and the identifier they might read off someone else's
    /// device. An empty query matches everything, so a caller can filter
    /// unconditionally.
    ///
    /// The channel's own name is matched alongside `title` so an aliased
    /// channel is still found by what it calls itself. The identifier matches
    /// on a prefix: it is four hex digits, and a hit in the middle of one says
    /// nothing.
    func matches(searchQuery: String) -> Bool {
        let query = searchQuery.trimmingCharacters(in: .whitespaces)
        guard !query.isEmpty else { return true }
        let textOptions: String.CompareOptions = [.caseInsensitive, .diacriticInsensitive]
        if title.range(of: query, options: textOptions) != nil { return true }
        if let name, name.range(of: query, options: textOptions) != nil { return true }
        return channelIDHex.hasPrefix(query.lowercased())
    }
}

/// A channel the radio's device identity has joined that this phone cannot
/// name, because the key was never on this phone. The device reports only
/// derived identifiers, so this is all that can be shown.
struct UnknownDeviceChannel: Identifiable, Hashable, Sendable {
    let identifier: Data

    var id: String { identifierHex }
    var identifierHex: String {
        identifier.map { String(format: "%02x", $0) }.joined()
    }
}

/// What a join flow resolved before anything was committed.
struct ChannelPreview: Equatable, Sendable {
    let preview: MeshChannelPreview
    /// The channel this phone already holds for the same key, when there is
    /// one. Its presence turns a join into an update of local details.
    let existing: ChannelSummary?
    /// A different channel already using the resolved name. Two channels may
    /// legitimately share a display name with different keys; the user should
    /// see that before joining.
    let nameConflict: ChannelSummary?
}

/// Local details a user may set on a channel, at join time or later.
struct ChannelDetails: Equatable, Sendable {
    /// What this user calls the channel, overriding its own name.
    var alias: String?
    var regionCode: Data?
    var maxFloodHops: Int?
    var notificationsEnabled: Bool = false
}

/// Why a channel operation could not be completed, in the terms the interface
/// explains it.
enum ChannelActionOutcome: Equatable, Sendable {
    case success
    /// The phone's own channel table is full.
    case phoneFull
    /// The radio's device channel list is full; its `NOMEM` is authoritative.
    case deviceFull
    case radioUnavailable
    /// The radio has no device identity domain to join channels with.
    case unsupported
    case failed
}

/// The channel operations the Channels tab is built from. Assembled where the
/// store, the vault, the radio, and the mesh engine are held together.
struct ChannelActions {
    /// Resolve a pasted URI or a typed public name without committing.
    var preview: ((String) async -> Result<ChannelPreview, MeshEngineError>)? = nil
    /// Join, or update local details when the key is already held.
    var join: ((MeshChannelPreview, ChannelDetails) async -> ChannelActionOutcome)? = nil
    /// Re-join a channel whose row and key this phone still holds — a
    /// built-in the user left. No invitation is involved.
    var rejoin: ((ChannelSummary) async -> ChannelActionOutcome)? = nil
    /// Leave on the phone. A private channel's key is deleted with it.
    var leave: ((ChannelSummary) async -> ChannelActionOutcome)? = nil
    /// Create a private channel with a freshly generated key. The name is the
    /// channel's own — it travels with the invitation — not a local alias.
    var createPrivate: ((String, ChannelDetails) async -> ChannelActionOutcome)? = nil
    var updateDetails: ((ChannelSummary, ChannelDetails) async -> Bool)? = nil
    /// Add or remove the channel on the companion radio's device identity.
    var setDeviceMembership: ((ChannelSummary, Bool) async -> ChannelActionOutcome)? = nil
    /// Build a shareable URI. Returns nil when the key can no longer be read.
    var invitation: ((ChannelSummary) async -> String?)? = nil
    /// Reveal the channel key for display, on explicit user action only.
    var revealKey: ((ChannelSummary) async -> Data?)? = nil
    /// Open this channel's group conversation, creating it the first time.
    /// Joining a channel does not start a chat; this is what does.
    var enterConversation: ((ChannelSummary) async -> Void)? = nil
    /// Read a routing region written as an airport code, an agreed name, or a
    /// raw code. Returns nil when the text names no region.
    var parseRegion: ((String) async -> Data?)? = nil
    /// Render a region code the way it is written and the way it appears in a
    /// capture.
    var describeRegion: ((Data) async -> String?)? = nil

    @MainActor static let unavailable = ChannelActions()
}
