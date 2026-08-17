#if DEBUG
import CryptoKit
import Foundation
import UMSHMobileCore

/// A fabricated mesh, for marketing screenshots taken in the simulator.
///
/// Everything here is invented, but nothing here is faked at the presentation
/// layer: staged nodes hold genuine Ed25519 keys and genuine signed identity
/// bundles, so the map, the peer sheets and the address rendering all run the
/// same decode-and-verify path they run against a real radio. What makes the
/// screenshots possible is that the mesh is written to disk rather than heard
/// over the air — see ``StagingSeeder``.
///
/// The keys are derived from fixed seeds, so reseeding reproduces the same
/// mesh: a screenshot retaken next week has the same nodes at the same
/// addresses with the same avatar colors as the one taken today.
enum StagingScenario {
    /// Where the staged crew is working. Coordinates sit around Desolation
    /// Wilderness, west of Lake Tahoe — real terrain, so the map has contours
    /// and trails under the markers instead of empty tiles.
    static let centerLatitude = 38.8985
    static let centerLongitude = -120.1020

    /// The phone's own display name, which channel messages carry.
    static let operatorName = "Alex Reyes"

    /// The channel the whole crew coordinates on. A named public channel: the
    /// name derives the key, so it is reproducible, and it is the ordinary case
    /// a screenshot should show.
    static let channelName = "Trail Crew"

    /// A private channel alongside it, so the staged mesh shows both kinds of
    /// group chat — this one's key was handed out rather than derived from
    /// anything guessable, which is what its name being a secret means.
    static let privateChannelName = "Crew Leads"

    /// Fixed key material for ``privateChannelName``.
    ///
    /// A literal rather than ``generateChannelKey``: a private channel *is* its
    /// key, so generating a fresh one each reseed would produce a different
    /// channel every time — new identifier, new tint, new conversation address,
    /// and a screenshot that cannot be retaken. Safe to have in the open
    /// precisely because it is fabricated; nothing real is ever encrypted
    /// under it.
    static let privateChannelKey = Data([
        0x3B, 0x7A, 0xF1, 0x0C, 0x92, 0x4E, 0xD8, 0x65,
        0x11, 0xA3, 0x5F, 0xC7, 0x2D, 0x88, 0xB0, 0x49,
        0xE6, 0x14, 0x7C, 0xA2, 0x53, 0xDF, 0x96, 0x38,
        0x0B, 0xE1, 0x6D, 0x74, 0xCA, 0x2F, 0x85, 0x1E,
    ])

    /// Every node in the staged mesh, in the order the roster reads best.
    static let nodes: [StagingNode] = [
        StagingNode(
            seed: 0x11,
            name: "Maya Ortiz",
            role: .chat,
            capabilities: [.mobile, .textMessages],
            latitude: 38.9042,
            longitude: -120.0968,
            altitudeMeters: 2_180,
            isSaved: true,
            isFavorite: true,
            lastHeardMinutesAgo: 4
        ),
        StagingNode(
            seed: 0x22,
            name: "Tallac Ridge",
            role: .repeater,
            capabilities: [.repeater, .textMessages],
            latitude: 38.9061,
            longitude: -120.0983,
            // The high node, which is the point of a ridgeline repeater.
            altitudeMeters: 2_967,
            isSaved: true,
            isFavorite: false,
            lastHeardMinutesAgo: 2
        ),
        StagingNode(
            seed: 0x33,
            name: "Dev Raman",
            role: .tracker,
            capabilities: [.mobile, .textMessages, .telemetry],
            latitude: 38.8931,
            longitude: -120.1104,
            altitudeMeters: 2_243,
            isSaved: true,
            isFavorite: true,
            lastHeardMinutesAgo: 11
        ),
        StagingNode(
            seed: 0x44,
            name: "Jules Whitaker",
            role: .chat,
            capabilities: [.mobile, .textMessages],
            latitude: 38.8877,
            longitude: -120.0891,
            altitudeMeters: 2_055,
            isSaved: true,
            isFavorite: false,
            lastHeardMinutesAgo: 27
        ),
        StagingNode(
            seed: 0x55,
            name: "Echo Basecamp",
            role: .chat,
            capabilities: [.textMessages, .chatRoom, .telemetry],
            latitude: 38.8842,
            longitude: -120.0459,
            altitudeMeters: 2_301,
            isSaved: true,
            isFavorite: false,
            lastHeardMinutesAgo: 8
        ),
        // The last two were heard over the air and never saved, which is the
        // ordinary state of most of a mesh — the map should show that tier.
        StagingNode(
            seed: 0x66,
            name: "Sam Ihara",
            role: .tracker,
            capabilities: [.mobile, .textMessages],
            latitude: 38.9138,
            longitude: -120.1187,
            altitudeMeters: 2_412,
            isSaved: false,
            isFavorite: false,
            lastHeardMinutesAgo: 43
        ),
        StagingNode(
            seed: 0x77,
            name: "Glen Alpine Relay",
            role: .repeater,
            capabilities: [.repeater],
            latitude: 38.8759,
            longitude: -120.0827,
            altitudeMeters: 1_996,
            isSaved: false,
            isFavorite: false,
            lastHeardMinutesAgo: 63
        ),
    ]

    /// The radio the staged phone is attached to: a T-Echo sitting at the
    /// center of the staged mesh, so the map's "this radio" marker lands among
    /// the nodes rather than an ocean away.
    static var radioSnapshot: RadioSnapshot {
        var snapshot = RadioSnapshot.previewReady
        snapshot.name = "T-Echo"
        snapshot.batteryPercentage = 76
        snapshot.batteryVoltageMillivolts = 3_780
        snapshot.chargeState = .discharging
        snapshot.batteryReadAt = .now
        snapshot.clock = RadioClock(date: .now, readAt: .now)
        snapshot.position = RadioPosition(
            UlcpGnssRecord(
                fix: .threeD,
                location: Data([0xB2, 0x59, 0x15, 0x00, 0x00]),
                latitudeDeg: centerLatitude,
                longitudeDeg: centerLongitude,
                locationCellMeters: 38.2,
                altitudeM: 2_164,
                accuracyDm: 48,
                satellitesUsed: 11,
                satellitesInView: 17
            )
        )
        return snapshot
    }
}

/// One node in the staged mesh.
struct StagingNode {
    /// Fills all 32 secret-key bytes. A fixed value rather than a random key,
    /// so a node keeps its address — and therefore its avatar color and its
    /// place in every sorted list — across reseeds.
    let seed: UInt8
    let name: String
    let role: PeerRole
    let capabilities: MeshNodeCapabilities
    let latitude: Double
    let longitude: Double
    let altitudeMeters: Int32
    let isSaved: Bool
    let isFavorite: Bool
    let lastHeardMinutesAgo: Int

    var secretKey: Data { Data(repeating: seed, count: 32) }

    /// The cell size staged nodes disclose. Five bytes is roughly a 38 m cell —
    /// what a tracker sharing a useful position actually reports, and fine
    /// enough that markers separate on the map at trail scale.
    var locationPrecision: UInt8 { 5 }
}

/// Writes a ``StagingScenario`` into a store.
///
/// Deliberately a writer over the ordinary store API rather than a fake data
/// source behind the views: what the screenshots show then comes out of the
/// same queries, the same decoding and the same layout as real data, so a
/// staged screenshot cannot flatter a screen that is broken for real users.
///
/// The store it writes to is expected to be the staging one — a separate file,
/// so nothing here can reach a real account's history.
struct StagingSeeder {
    let store: SQLiteApplicationStore
    let meshEngine: RustMeshEngine
    let channelKeyVault: KeychainChannelKeyVault
    let ownerIdentityID: String
    /// The phone's own address, so it can be named as a channel participant.
    let ownerAddress: String

    /// One staged node, resolved to what the store needs to hold it.
    private struct ResolvedNode {
        let node: StagingNode
        let address: String
        let hint: Data
        let bundle: Data
    }

    func seed() async throws {
        let now = Date()
        let resolved = try await resolveNodes()
        try await writePeers(resolved, now: now)
        try await writeDirectConversations(resolved, now: now)
        try await writeChannelConversations(resolved, now: now)
    }

    /// Give every staged node a real key and a real signed bundle.
    private func resolveNodes() async throws -> [ResolvedNode] {
        var resolved: [ResolvedNode] = []
        for node in StagingScenario.nodes {
            let identity = try MobileIdentity.unlock(secretKey: node.secretKey).publicIdentity()
            // Timestamps are what the bundle says about when the claim was
            // made, and a peer sheet shows them. Match the node's last-heard
            // so the two do not contradict each other.
            let claimedAt = Date().addingTimeInterval(
                -Double(node.lastHeardMinutesAgo) * 60
            )
            let bundle = try await signNodeIdentityBundle(
                secretKey: node.secretKey,
                profile: NodeIdentityProfileRecord(
                    roleCode: node.role.roleCode ?? 0,
                    capabilityBits: node.capabilities.rawValue,
                    name: node.name,
                    latitude: node.latitude,
                    longitude: node.longitude,
                    locationPrecision: node.locationPrecision,
                    altitudeM: node.altitudeMeters,
                    timestamp: UInt32(claimedAt.timeIntervalSince1970)
                )
            )
            resolved.append(
                ResolvedNode(
                    node: node,
                    address: identity.canonicalAddress,
                    hint: identity.hint.bytes,
                    bundle: bundle
                )
            )
        }
        return resolved
    }

    private func writePeers(_ resolved: [ResolvedNode], now: Date) async throws {
        for entry in resolved {
            try await store.upsertPeer(
                ownerIdentityID: ownerIdentityID,
                publicAddress: entry.address,
                alias: nil,
                advertisedName: entry.node.name,
                isSaved: entry.node.isSaved,
                nodeKind: entry.node.role.rawValue,
                advertisement: entry.bundle,
                // The bundle carries a signature that verifies, so this only
                // has to be true for the unsigned case; set it anyway so the
                // row states what a MAC-authenticated arrival would have.
                advertisementAuthenticated: true
            )
            try await store.touchLastHeard(
                ownerIdentityID: ownerIdentityID,
                publicAddress: entry.address,
                at: now.addingTimeInterval(-Double(entry.node.lastHeardMinutesAgo) * 60)
            )
            if entry.node.isFavorite {
                try await store.setPeerFavorite(
                    ownerIdentityID: ownerIdentityID,
                    publicAddress: entry.address,
                    isFavorite: true
                )
            }
        }
    }

    // MARK: - Direct conversations

    private func writeDirectConversations(_ resolved: [ResolvedNode], now: Date) async throws {
        for script in Self.directScripts {
            guard let peer = resolved.first(where: { $0.node.name == script.peerName }) else {
                continue
            }
            _ = try await store.ensureDirectConversation(
                ownerIdentityID: ownerIdentityID,
                peerAddress: peer.address
            )
            // A one-to-one transcript names nobody: which conversation it is
            // already answers who the other voice belongs to. The peer still
            // resolves, so their reactions carry a hint and group as theirs.
            let messages = Self.stagedMessages(
                from: script.lines,
                now: now,
                senderHandleFor: { _ in nil },
                resolve: { $0 == peer.node.name ? peer : nil }
            )
            try await store.seedStagedTranscript(
                ownerIdentityID: ownerIdentityID,
                conversationAddress: peer.address,
                sessionID: "staging-\(peer.node.seed)",
                messages: messages
            )
            if script.markRead {
                try await store.markConversationRead(
                    ownerIdentityID: ownerIdentityID,
                    conversationAddress: peer.address
                )
            }
        }
    }

    // MARK: - Channel conversation

    /// Join both staged group chats and fill them.
    private func writeChannelConversations(_ resolved: [ResolvedNode], now: Date) async throws {
        // The named channel's key comes from its name, exactly as joining it by
        // name would derive it.
        let named = try await meshEngine.inspectChannelName(StagingScenario.channelName)
        try await writeChannel(
            title: StagingScenario.channelName,
            kind: .named,
            canonicalName: named.canonicalName,
            key: named.key,
            channelID: named.channelID,
            tint: named.tint,
            maxFloodHops: named.maxFloodHops.map(Int.init),
            joinedDevice: true,
            joinedDaysAgo: 6,
            sessionID: "staging-channel",
            lines: Self.channelLines,
            resolved: resolved,
            now: now
        )

        // The private one is its key; the identifier and tint are derived from
        // it the same way a pasted invitation's would be.
        let key = StagingScenario.privateChannelKey
        try await writeChannel(
            title: StagingScenario.privateChannelName,
            kind: .privateKey,
            // A private channel has no derived name to canonicalize: nothing
            // about it is guessable from what it is called.
            canonicalName: nil,
            key: key,
            channelID: try await meshEngine.deriveChannelID(key: key),
            tint: try await meshEngine.deriveChannelTint(key: key),
            maxFloodHops: 3,
            // Left off the radio's own identity, so the staged mesh shows the
            // two membership tiers differing somewhere.
            joinedDevice: false,
            joinedDaysAgo: 2,
            sessionID: "staging-private-channel",
            lines: Self.privateChannelLines,
            resolved: resolved,
            now: now
        )
    }

    /// Join one channel and fill it, the way the app's own join does: key to
    /// the Keychain first, row second, so a channel whose key cannot be read is
    /// never left behind in the list.
    private func writeChannel(
        title: String,
        kind: StoredChannelKind,
        canonicalName: String?,
        key: Data,
        channelID: Data,
        tint: Data,
        maxFloodHops: Int?,
        joinedDevice: Bool,
        joinedDaysAgo: Int,
        sessionID: String,
        lines: [Line],
        resolved: [ResolvedNode],
        now: Date
    ) async throws {
        let digest = Self.keyDigest(key)
        let address = try await meshEngine.channelConversationAddress(key: key)

        if try await store.channel(ownerIdentityID: ownerIdentityID, keyDigest: digest) == nil {
            let id = UUID()
            try await channelKeyVault.storeKey(key, channelID: id)
            do {
                try await store.insertChannel(
                    StoredChannel(
                        id: id,
                        ownerIdentityID: ownerIdentityID,
                        kind: kind,
                        canonicalName: canonicalName,
                        name: title,
                        alias: nil,
                        channelIDHex: Self.hex(channelID),
                        tint: tint,
                        regionCode: nil,
                        maxFloodHops: maxFloodHops,
                        joinedPhone: true,
                        joinedDevice: joinedDevice,
                        notificationsEnabled: true,
                        joinedAt: now.addingTimeInterval(-Double(joinedDaysAgo) * 86_400)
                    ),
                    keyDigest: digest
                )
            } catch {
                try? await channelKeyVault.deleteKey(channelID: id)
                throw error
            }
        }

        guard let stored = try await store.channel(
            ownerIdentityID: ownerIdentityID,
            keyDigest: digest
        ) else { return }
        _ = try await store.ensureChannelConversation(
            ownerIdentityID: ownerIdentityID,
            channelID: stored.id,
            conversationAddress: address
        )

        let byName = Dictionary(uniqueKeysWithValues: resolved.map { ($0.node.name, $0) })
        try await store.seedStagedTranscript(
            ownerIdentityID: ownerIdentityID,
            conversationAddress: address,
            sessionID: sessionID,
            messages: Self.stagedMessages(
                from: lines,
                now: now,
                senderHandleFor: { $0 },
                resolve: { byName[$0] }
            )
        )
    }

    // MARK: - Scripts

    /// One line of a staged conversation.
    ///
    /// `minutesAgo` is when it was said, counting back from the moment the
    /// scenario is seeded, so a staged transcript is always freshly plausible
    /// rather than dated to whenever the code was written.
    private struct Line {
        let speaker: String?
        let body: String
        let minutesAgo: Int
        var reactions: [(token: String, from: String?, minutesAgo: Int)] = []

        /// Said by the phone's owner.
        var isOutbound: Bool { speaker == nil }
    }

    private struct DirectScript {
        let peerName: String
        let markRead: Bool
        let lines: [Line]
    }

    private static let directScripts: [DirectScript] = [
        DirectScript(
            peerName: "Maya Ortiz",
            // Left unread, so the conversations list shows a badge.
            markRead: false,
            lines: [
                Line(speaker: "Maya Ortiz", body: "Heading up the north spur now. Should have eyes on the washout in about forty minutes.", minutesAgo: 96),
                Line(speaker: nil, body: "Copy. Dev's already at the lower crossing with the saw.", minutesAgo: 94),
                Line(speaker: "Maya Ortiz", body: "Perfect. Tell him the culvert at mile 3 is completely packed with gravel — we'll need the mattock.", minutesAgo: 91, reactions: [(token: "+1", from: nil, minutesAgo: 90)]),
                Line(speaker: nil, body: "Passing it along. Radio check in an hour?", minutesAgo: 88),
                Line(speaker: "Maya Ortiz", body: "Works. Signal's holding fine off the ridge repeater up here.", minutesAgo: 86),
                Line(speaker: "Maya Ortiz", body: "At the washout. It's worse than the photos — about twelve feet of tread gone and the uphill bank is still moving.", minutesAgo: 12),
                Line(speaker: "Maya Ortiz", body: "Going to flag it and back off. Not something we fix today.", minutesAgo: 11),
                Line(speaker: nil, body: "Agreed, don't push it. Flag both approaches and we'll scope it properly Thursday.", minutesAgo: 9, reactions: [(token: "+1", from: "Maya Ortiz", minutesAgo: 8)]),
                Line(speaker: "Maya Ortiz", body: "On it. Heading back down to meet Dev.", minutesAgo: 4, reactions: [(token: "<3", from: nil, minutesAgo: 3)]),
            ]
        ),
        DirectScript(
            peerName: "Dev Raman",
            markRead: true,
            lines: [
                Line(speaker: nil, body: "How's the lower crossing looking?", minutesAgo: 140),
                Line(speaker: "Dev Raman", body: "Two deadfalls across, both about 18 inches. Working the second one now.", minutesAgo: 137),
                Line(speaker: nil, body: "Nice. Maya says bring the mattock when you head up — culvert at mile 3 is packed solid.", minutesAgo: 133),
                Line(speaker: "Dev Raman", body: "Got it in the pack already. Give me an hour here.", minutesAgo: 131, reactions: [(token: "+1", from: nil, minutesAgo: 130)]),
                Line(speaker: "Dev Raman", body: "Second one's clear. Tread's in better shape than last season through here.", minutesAgo: 18),
                Line(speaker: nil, body: "Good news for once.", minutesAgo: 16, reactions: [(token: "ha", from: "Dev Raman", minutesAgo: 15)]),
            ]
        ),
        DirectScript(
            peerName: "Jules Whitaker",
            markRead: true,
            lines: [
                Line(speaker: "Jules Whitaker", body: "Are we still meeting at the Echo lot at seven Thursday?", minutesAgo: 320),
                Line(speaker: nil, body: "Seven sharp. Bringing the rock bar and both mattocks.", minutesAgo: 316),
                Line(speaker: "Jules Whitaker", body: "I'll have the crosscut and enough water for four.", minutesAgo: 310, reactions: [(token: "+1", from: nil, minutesAgo: 308)]),
                Line(speaker: nil, body: "You're a hero. See you then.", minutesAgo: 305),
            ]
        ),
    ]

    /// The crew channel. Several voices, so the group-chat presentation —
    /// sender names, per-sender avatar colors, reactions from more than one
    /// person — has something to render.
    private static let channelLines: [Line] = [
        Line(speaker: "Echo Basecamp", body: "Morning all. Weather's holding through about four, then a chance of thunder over the crest.", minutesAgo: 210, reactions: [(token: "+1", from: "Maya Ortiz", minutesAgo: 208), (token: "+1", from: "Dev Raman", minutesAgo: 206)]),
        Line(speaker: "Maya Ortiz", body: "Taking the north spur. Dev's on the lower crossing.", minutesAgo: 205),
        Line(speaker: "Dev Raman", body: "Two deadfalls down here, nothing we can't handle.", minutesAgo: 201),
        Line(speaker: nil, body: "I'll stage the tools at the Echo lot for Thursday. Anyone need anything specific?", minutesAgo: 198),
        Line(speaker: "Jules Whitaker", body: "Another rock bar if we have one. The one we've got is bent.", minutesAgo: 194, reactions: [(token: "ha", from: "Dev Raman", minutesAgo: 192)]),
        Line(speaker: "Echo Basecamp", body: "Reminder that the upper loop is still closed to stock until the bridge inspection clears.", minutesAgo: 150),
        Line(speaker: "Maya Ortiz", body: "Washout at the north spur is bigger than reported. Twelve feet of tread gone, bank still active. Flagging both approaches.", minutesAgo: 12, reactions: [(token: "!", from: "Echo Basecamp", minutesAgo: 11), (token: "!", from: "Jules Whitaker", minutesAgo: 10), (token: "!", from: nil, minutesAgo: 9)]),
        Line(speaker: "Echo Basecamp", body: "Noted. I'll get it on the closure list tonight and pull the district engineer in.", minutesAgo: 8),
        Line(speaker: nil, body: "Thanks. Nobody goes past the flags until we've scoped it properly.", minutesAgo: 6, reactions: [(token: "+1", from: "Maya Ortiz", minutesAgo: 5), (token: "+1", from: "Jules Whitaker", minutesAgo: 4)]),
    ]

    /// The private channel: fewer people, and the reason it is private is
    /// legible in what gets said on it rather than only in its badge.
    private static let privateChannelLines: [Line] = [
        Line(speaker: "Echo Basecamp", body: "Leads only — budget came back and it's about 30% short of what we asked for.", minutesAgo: 1_450),
        Line(speaker: nil, body: "That's the bridge decking gone then. Can we phase it?", minutesAgo: 1_446),
        Line(speaker: "Echo Basecamp", body: "Phasing is what I'd propose. Decking next season, abutment repair this one.", minutesAgo: 1_441, reactions: [(token: "+1", from: "Maya Ortiz", minutesAgo: 1_439)]),
        Line(speaker: "Maya Ortiz", body: "Works for me. The abutment is the safety item anyway — the decking is just uncomfortable.", minutesAgo: 1_436),
        Line(speaker: nil, body: "Let's not put the numbers on the open channel until the district signs off.", minutesAgo: 1_430, reactions: [(token: "+1", from: "Echo Basecamp", minutesAgo: 1_428), (token: "+1", from: "Maya Ortiz", minutesAgo: 1_427)]),
        Line(speaker: "Echo Basecamp", body: "Agreed. I'll have a written version for you both by Thursday.", minutesAgo: 1_425),
        Line(speaker: "Maya Ortiz", body: "Given what I saw at the north spur today we should get the washout into the same request.", minutesAgo: 7),
        Line(speaker: nil, body: "Good call. Send me photos and I'll fold it in.", minutesAgo: 5, reactions: [(token: "+1", from: "Maya Ortiz", minutesAgo: 4)]),
    ]

    // MARK: - Script compilation

    /// Turn a script into store rows.
    ///
    /// `resolve` is how a speaker's name becomes an address and a hint, which
    /// only a channel message carries — a direct conversation's sender is
    /// already settled by which conversation it is in.
    private static func stagedMessages(
        from lines: [Line],
        now: Date,
        senderHandleFor: (String) -> String?,
        resolve: (String) -> ResolvedNode?
    ) -> [StagedMessage] {
        lines.enumerated().map { index, line in
            let sender = line.speaker.flatMap(resolve)
            let createdAt = now.addingTimeInterval(-Double(line.minutesAgo) * 60)
            return StagedMessage(
                handle: UInt32(index + 1),
                body: line.body,
                outbound: line.isOutbound,
                createdAt: createdAt,
                senderAddress: sender?.address,
                senderHint: sender?.hint,
                senderHandle: line.speaker.flatMap(senderHandleFor),
                deliveryState: line.isOutbound ? "acknowledged" : nil,
                reception: line.isOutbound ? nil : reception(for: index),
                reactions: line.reactions.map { reaction in
                    let from = reaction.from.flatMap(resolve)
                    return StagedReaction(
                        body: reaction.token,
                        outbound: reaction.from == nil,
                        createdAt: now.addingTimeInterval(-Double(reaction.minutesAgo) * 60),
                        senderAddress: from?.address,
                        senderHint: from?.hint
                    )
                }
            )
        }
    }

    /// Plausible link metrics for the message-details sheet. Varied per
    /// message rather than constant, because a transcript where every frame
    /// arrived at exactly the same RSSI is the one thing that would read as
    /// fabricated.
    private static func reception(for index: Int) -> StoredMessageReception {
        StoredMessageReception(
            rssiDbm: -78 - (index * 7) % 24,
            snrCentibels: 620 - (index * 90) % 380,
            lqi: nil,
            hopCount: index % 3 == 0 ? 2 : 1,
            routeHints: index % 3 == 0 ? [Data([0x2A, 0xE1])] : [],
            sourceAuthenticated: true
        )
    }

    private static func keyDigest(_ key: Data) -> String {
        hex(Data(SHA256.hash(data: key)))
    }

    private static func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}
#endif
