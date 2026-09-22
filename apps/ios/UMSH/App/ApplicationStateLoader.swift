import Foundation

struct ApplicationPresentationSnapshot {
    let peers: [PeerSummary]
    let channels: [ChannelSummary]
    let neighborReports: [PeerRepeaterNeighborReport]
    var conversations: [DirectConversationSummary]
    var channelConversations: [ChannelConversationSummary]
}

/// Builds a complete replacement before the runtime publishes any part of it.
/// Reading or mapping failure leaves the last usable interface intact.
@MainActor
struct ApplicationStateLoader {
    let meshEngine: any MeshEngine

    func load(
        records: ApplicationRecords,
        chatRevisions: [String: Int],
        knownPeers: [PeerSummary]? = nil,
        neighbor: (StoredPeerRepeaterEntry) async -> PeerRepeaterNeighbor
    ) async throws -> ApplicationPresentationSnapshot {
        let storedPeers = records.peers
        var mappedPeers = Dictionary((knownPeers ?? []).map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        for stored in storedPeers where knownPeers == nil {
            guard let identity = try? await meshEngine.inspectPublicIdentity(stored.publicAddress) else {
                continue
            }
            let advertisedIdentity: MeshNodeIdentity? = await {
                guard let payload = stored.advertisement else { return nil }
                return try? await meshEngine.decodeNodeIdentity(
                    address: stored.publicAddress,
                    payload: payload
                )
            }()
            mappedPeers[stored.id] = PeerSummary(
                id: stored.id,
                identity: identity,
                alias: stored.alias,
                advertisedName: stored.advertisedName,
                systemRole: stored.systemRole,
                storedRole: stored.nodeKind.flatMap(PeerRole.init(rawValue:)) ?? .unknown,
                advertisedIdentity: advertisedIdentity,
                advertisedIdentityAuthenticated: stored.advertisementAuthenticated,
                lastHeard: stored.lastHeardAt,
                isSaved: stored.isSaved,
                isFavorite: stored.isFavorite,
                isOnDeviceIdentity: stored.onDeviceIdentity,
                notifyWhenHeard: stored.notifyWhenHeard
            )
        }
        let storedChannels = records.channels
        let mappedChannels = storedChannels.map(Self.summary(from:))
        let storedConversations = records.conversations
        // Assign only on a real change: most reloads are triggered by
        // radio or chat activity that leaves the displayed state
        // identical, and an equal-value write to an observed property
        // still invalidates everything that reads it.
        let mappedPeerList = knownPeers ?? storedPeers.compactMap { mappedPeers[$0.id] }
        let storedReports = records.reports
        var mappedReports: [PeerRepeaterNeighborReport] = []
        mappedReports.reserveCapacity(storedReports.count)
        for report in storedReports {
            guard let reporter = mappedPeers[report.reporterNodeID] else { continue }
            mappedReports.append(
                PeerRepeaterNeighborReport(
                    reporter: reporter,
                    neighbor: await neighbor(report.entry)
                )
            )
        }
        var mappedConversations: [DirectConversationSummary] = []
        for stored in storedConversations {
            guard let peer = mappedPeers[stored.node.id] else { continue }
            mappedConversations.append(
                DirectConversationSummary(
                    id: stored.id,
                    peer: peer,
                    draftText: stored.draftText,
                    lastMessage: Self.previewMessage(from: stored.lastMessage),
                    unreadCount: stored.unreadCount,
                    createdAtMilliseconds: stored.createdAtMilliseconds,
                    notificationsEnabled: stored.notificationsEnabled,
                    messageRevision: chatRevisions[
                        peer.identity.canonicalAddress
                    ] ?? 0
                )
            )
        }

        let storedChannelConversations = records.channelConversations
        let channelsByID = Dictionary(
            mappedChannels.map { ($0.id, $0) },
            uniquingKeysWith: { first, _ in first }
        )
        var mappedChannelConversations: [ChannelConversationSummary] = []
        for stored in storedChannelConversations {
            // A conversation whose channel was left has no key to send
            // with and no name to show, so it is not listed.
            guard let channel = channelsByID[stored.channelID], channel.joinedPhone else {
                continue
            }
            mappedChannelConversations.append(
                ChannelConversationSummary(
                    id: stored.id,
                    channel: channel,
                    conversationAddress: stored.conversationAddress,
                    draftText: stored.draftText,
                    lastMessage: Self.previewMessage(from: stored.lastMessage),
                    unreadCount: stored.unreadCount,
                    createdAtMilliseconds: stored.createdAtMilliseconds,
                    messageRevision: chatRevisions[
                        stored.conversationAddress
                    ] ?? 0
                )
            )
        }

        try Task.checkCancellation()
        return ApplicationPresentationSnapshot(peers: mappedPeerList, channels: mappedChannels,
            neighborReports: mappedReports, conversations: mappedConversations,
            channelConversations: mappedChannelConversations)
    }

    static func summary(from stored: StoredChannel) -> ChannelSummary {
        ChannelSummary(
            id: stored.id,
            kind: stored.kind,
            canonicalName: stored.canonicalName,
            name: stored.name,
            alias: stored.alias,
            channelIDHex: stored.channelIDHex,
            tint: stored.tint,
            regionCode: stored.regionCode,
            maxFloodHops: stored.maxFloodHops,
            joinedPhone: stored.joinedPhone,
            joinedDevice: stored.joinedDevice,
            notificationsEnabled: stored.notificationsEnabled,
            joinedAt: stored.joinedAt
        )
    }

    static func previewMessage(
        from stored: StoredConversationPreview?
    ) -> ConversationPreviewMessage? {
        stored.map { preview in
            ConversationPreviewMessage(
                createdAtMilliseconds: preview.createdAtMilliseconds,
                body: preview.body,
                isOutbound: preview.isOutbound,
                isDeleted: preview.isDeleted,
                senderAddress: preview.senderAddress,
                senderHint: preview.senderHint
            )
        }
    }
}
