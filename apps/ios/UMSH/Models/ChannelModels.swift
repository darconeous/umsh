import Foundation
import UMSHMobileCore

/// A channel as the interface presents it.
///
/// Carries no key material: the core keeps the key in its vault under `id`,
/// and reads it only when something needs it.
struct ChannelSummary: Identifiable, Hashable, Sendable {
    let id: UUID
    let kind: StoredChannelKind
    /// The folded form the key is derived from. Machinery—it decides which
    /// channel this is, but it is not what the channel is called, and the
    /// interface does not show it.
    let canonicalName: String?
    /// The channel's own name, written the way it was typed or shared.
    let name: String?
    /// What this user calls it. Takes display precedence everywhere but never
    /// overwrites `name`, exactly as a peer alias behaves.
    let alias: String?
    /// Two-octet derived identifier, hex. Shown as a disambiguator, never as
    /// an identity—distinct keys may collide here.
    let channelIDHex: String
    /// Three presentation octets, the identifier extended by one byte. Drives
    /// the channel's color so it looks the same on every device that holds
    /// the key.
    let tint: Data
    let regionCode: Data?
    let maxFloodHops: Int?
    let joinedPhone: Bool
    let notificationsEnabled: Bool
    let joinedAt: Date?
    /// Which channel the protocol fixes rules for this is, if any: the
    /// core's rule, read once from the canonical name.
    let wellKnown: MobileWellKnownChannelRecord?

    init(
        id: UUID,
        kind: StoredChannelKind,
        canonicalName: String?,
        name: String?,
        alias: String?,
        channelIDHex: String,
        tint: Data,
        regionCode: Data?,
        maxFloodHops: Int?,
        joinedPhone: Bool,
        notificationsEnabled: Bool,
        joinedAt: Date?
    ) {
        self.id = id
        self.kind = kind
        self.canonicalName = canonicalName
        self.name = name
        self.alias = alias
        self.channelIDHex = channelIDHex
        self.tint = tint
        self.regionCode = regionCode
        self.maxFloodHops = maxFloodHops
        self.joinedPhone = joinedPhone
        self.notificationsEnabled = notificationsEnabled
        self.joinedAt = joinedAt
        wellKnown = wellKnownChannel(canonicalName: canonicalName)
    }

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
    /// fixes one, so it is not the user's to choose. The mesh session
    /// enforces the same ceiling whatever it is asked to register.
    ///
    /// Keyed on the canonical name rather than the record's kind, because the
    /// name is what derives the key: joining `umsh:cs:public` by hand reaches
    /// the same channel and inherits the same rules.
    var protocolMaxFloodHops: Int? {
        wellKnown.map { Int($0.fixedMaxFloodHops) }
    }

    /// Whether this is `EMERGENCY`, keyed on the canonical name for the same
    /// reason as `protocolMaxFloodHops`.
    var isEmergency: Bool {
        wellKnown?.channel == .emergency
    }

    /// How this channel behaves, where the protocol decides it.
    ///
    /// Written as statements of fact, not instructions: the app applies these
    /// itself and the user has nothing to comply with.
    var protocolBehavior: [String] {
        switch wellKnown?.channel {
        case .public:
            [
                String(
                    localized: "Every sender is identified. Messages that arrive without a full sender key are ignored.",
                    comment: "How the Public channel works."
                ),
                String(
                    localized: "This channel carries group traffic only—it is never used to conceal a direct message.",
                    comment: "How the Public channel works."
                ),
            ]
        case .emergency:
            [
                String(
                    localized: "All traffic here is unencrypted, so any node in range can read it—including nodes that never joined.",
                    comment: "How the EMERGENCY channel works."
                ),
                String(
                    localized: "Every message is signed and identifies its sender. Anything unsigned or unattributed is ignored.",
                    comment: "How the EMERGENCY channel works."
                ),
                String(
                    localized: "Repeaters give this channel priority.",
                    comment: "How the EMERGENCY channel works."
                ),
            ]
        case nil:
            []
        }
    }

    /// Whether the user may leave without losing the ability to come back.
    /// Built-in channels are always re-joinable by name; a private channel's
    /// key is gone once deleted.
    var canRejoinAfterLeaving: Bool {
        kind != .privateKey
    }

    /// The question before leaving this channel.
    var leaveTitle: String {
        String(localized: "Leave “\(title)”?", comment: "Confirmation title before leaving a channel. The placeholder is its name.")
    }

    /// What leaving this channel costs, said before it happens.
    var leaveMessage: String {
        if canRejoinAfterLeaving {
            return String(
                localized: "You can join again with its name. Its messages are removed from this phone.",
                comment: "Confirmation before leaving a channel joined by name."
            )
        }
        return String(
            localized: "The channel key is deleted from this phone. Joining again requires a new invitation from someone still in the channel. Its messages are removed from this phone.",
            comment: "Confirmation before leaving a private channel."
        )
    }

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

/// What a join flow resolved before anything was committed.
struct ChannelPreview: Equatable, Sendable {
    /// The text the preview was read from. Joining hands it back to the
    /// core, which reads it again, so an edit after Look Up cannot join
    /// something else.
    let input: String
    let preview: MeshChannelPreview
    /// The channel this phone already holds for the same key, when there is
    /// one. Its presence turns a join into an update of local details.
    let existing: ChannelSummary?
    /// A different channel already using the resolved name. Two channels may
    /// legitimately share a display name with different keys; the user should
    /// see that before joining.
    let nameConflict: ChannelSummary?
    /// Which channel the protocol fixes rules for this is, if any.
    let wellKnown: MobileWellKnownChannelRecord?
}

/// The channel operations the Channels tab is built from. Each runs a core
/// command and throws the core's reason when it does not happen.
struct ChannelActions {
    /// Resolve a pasted URI or a typed public name without committing.
    var preview: ((String) async -> Result<ChannelPreview, MeshEngineError>)? = nil
    /// Join by the text a preview was read from, or update the alias when
    /// the key is already held. With `openConversation`, the channel's
    /// conversation opens too, and its address is returned.
    var join: ((_ input: String, _ alias: String?, _ openConversation: Bool) async throws -> String?)? = nil
    /// Re-join a channel whose row and key this phone still holds—a
    /// built-in the user left. No invitation is involved.
    var rejoin: ((ChannelSummary) async throws -> Void)? = nil
    /// Leave on the phone. Every channel but a built-in loses its key.
    var leave: ((ChannelSummary) async throws -> Void)? = nil
    /// Create a private channel with a freshly generated key. The name is the
    /// channel's own—it travels with the invitation—not a local alias.
    var createPrivate: ((String) async throws -> Void)? = nil
    /// What this user calls the channel; `nil` clears it.
    var setAlias: ((ChannelSummary, String?) async throws -> Void)? = nil
    /// The channel's region and flood-hop ceiling; `nil` is the default.
    var setRouting: ((ChannelSummary, Data?, Int?) async throws -> Void)? = nil
    var setNotifications: ((ChannelSummary, Bool) async throws -> Void)? = nil
    /// Build a shareable URI.
    var invitation: ((ChannelSummary) async throws -> String)? = nil
    /// Open this channel's group conversation, creating it the first time.
    /// Joining a channel does not start a chat; this is what does.
    var enterConversation: ((ChannelSummary) async throws -> Void)? = nil
    /// Read a routing region written as a short code, an agreed name, or a
    /// raw code. Returns nil when the text names no region.
    var parseRegion: ((String) async -> Data?)? = nil
    /// Render a region code the way it is written and the way it appears in a
    /// capture.
    var describeRegion: ((Data) async -> String?)? = nil

    @MainActor static let unavailable = ChannelActions()
}
