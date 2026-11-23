import CoreLocation
import Foundation
import OSLog
import UMSHMobileCore

// The app core's read records, mapped onto the shapes the views draw.
//
// Every initializer here is a pure function of the record and, where a name
// has to be found, the peers already mapped: the core resolves which peer a
// hint names, and this side only looks the address up.

private let logger = Logger(subsystem: "com.voria.umsh.ios", category: "AppRoot")

extension MeshPublicIdentity {
    init(_ record: PublicIdentityRecord) {
        self.init(
            canonicalAddress: record.canonicalAddress,
            hint: MeshNodeHint(bytes: record.hint.bytes, text: record.hint.text)
        )
    }
}

extension PeerSummary {
    init(_ record: MobileAppPeerRecord) {
        let stored = StoredNode(record.stored)
        self.init(
            id: stored.id,
            identity: MeshPublicIdentity(record.identity),
            alias: stored.alias,
            advertisedName: stored.advertisedName,
            systemRole: stored.systemRole,
            storedRole: stored.nodeKind.map(PeerRole.init) ?? .unknown,
            advertisedIdentity: record.advertisedIdentity.map(RustMeshEngine.identity(from:)),
            advertisedIdentityAuthenticated: stored.advertisementAuthenticated,
            advertisedIdentityReceivedAt: stored.advertisementReceivedAt,
            lastHeard: stored.lastHeardAt,
            isSaved: stored.isSaved,
            isFavorite: stored.isFavorite,
            isOnDeviceIdentity: stored.onDeviceIdentity,
            notifyWhenHeard: stored.notifyWhenHeard,
            isLikelyRepeater: record.likelyRepeater,
            advertisedIdentityIsAttributable: record.advertisementAttributable,
            repeaterEvidence: record.repeaterEvidence,
            repeaterHint: MeshRepeaterHint(record.repeaterHint)
        )
    }
}

extension ChannelSummary {
    init(_ stored: StoredChannel) {
        self.init(
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
            notificationsEnabled: stored.notificationsEnabled,
            joinedAt: stored.joinedAt
        )
    }

    /// `nil`, logged, when the stored ID is not a UUID.
    init?(_ record: MobileStoredChannelRecord) {
        guard let stored = StoredChannel(record) else {
            logger.error("A stored channel's ID is not a UUID; it is not listed")
            return nil
        }
        self.init(stored)
    }
}

extension ConversationPreviewMessage {
    init(_ record: MobileAppPreviewRecord) {
        let stored = StoredConversationPreview(record.stored)
        self.init(
            createdAtMilliseconds: stored.createdAtMilliseconds,
            body: stored.body,
            isOutbound: stored.isOutbound,
            isDeleted: stored.isDeleted,
            senderAddress: stored.senderAddress,
            senderHint: stored.senderHint,
            isStatus: stored.isStatus,
            senderNodeHint: MeshNodeHint(bytes: stored.senderHint, text: record.senderNodeHint)
        )
    }
}

extension MeshNodeHint {
    /// A hint with the text the core rendered for it, when there is both.
    init?(bytes: Data?, text: String?) {
        guard let bytes, let text else { return nil }
        self.init(bytes: bytes, text: text)
    }
}

extension DirectConversationSummary {
    init(_ record: MobileAppDirectConversationRecord, peer: PeerSummary, revision: Int) {
        self.init(
            id: record.id,
            peer: peer,
            draftText: record.draftText,
            lastMessage: record.lastMessage.map(ConversationPreviewMessage.init),
            unreadCount: Int(record.unreadCount),
            createdAtMilliseconds: record.createdAtMs,
            notificationsEnabled: record.notificationsEnabled,
            messageRevision: revision
        )
    }
}

extension ChannelConversationSummary {
    init(_ record: MobileAppChannelConversationRecord, channel: ChannelSummary, revision: Int) {
        self.init(
            id: record.id,
            channel: channel,
            conversationAddress: record.conversationAddress,
            draftText: record.draftText,
            lastMessage: record.lastMessage.map(ConversationPreviewMessage.init),
            unreadCount: Int(record.unreadCount),
            createdAtMilliseconds: record.createdAtMs,
            messageRevision: revision,
            needsEmergencyAgreement: record.needsEmergencyAgreement
        )
    }
}

extension PeerRepeaterNeighbor {
    init(_ record: MobileAppRepeaterNeighborRecord) {
        let stored = StoredPeerRepeaterEntry(record.entry)
        self.init(
            hint: stored.hint,
            hintText: record.hintText ?? stored.hint.map { String(format: "%02X", $0) }.joined(),
            name: stored.name,
            rssiDBm: stored.rssiDBm,
            snrQuarterDB: stored.snrQuarterDB,
            lastHeardMinutes: stored.lastHeardMinutes,
            latitude: stored.latitude,
            longitude: stored.longitude,
            locationPrecision: stored.locationPrecision,
            regionCodes: stored.regionCodes,
            reportedAt: stored.reportedAt,
            peerAddress: record.peerAddress
        )
    }
}

extension PeerRepeaterListing {
    init(_ record: MobileAppRepeaterListingRecord) {
        self.init(
            entries: record.entries.map(PeerRepeaterNeighbor.init),
            total: record.total.map { Int($0) },
            nextCursor: record.nextCursor,
            asOf: Date(storeMilliseconds: record.asOfMs)
        )
    }
}

extension ChannelPreview {
    init(_ record: MobileAppChannelPreviewRecord, input: String) {
        self.init(
            input: input,
            preview: RustMeshEngine.channelPreview(from: record.preview),
            existing: record.existing.flatMap(ChannelSummary.init),
            nameConflict: record.nameConflict.flatMap(ChannelSummary.init),
            wellKnown: wellKnownChannel(canonicalName: record.preview.canonicalName)
        )
    }
}

/// The lists one state read produced, mapped, before any is published.
struct MappedApplicationState {
    /// `nil` when the read asked for conversations only.
    var peers: [PeerSummary]?
    var channels: [ChannelSummary]
    var conversations: [DirectConversationSummary]
    var channelConversations: [ChannelConversationSummary]
    /// `nil` when the read asked for conversations only.
    var neighborReports: [PeerRepeaterNeighborReport]?
    var advertisedName: String?

    init(_ record: MobileAppStateRecord, chatRevisions: [String: Int]) {
        let peers = record.peers?.map(PeerSummary.init)
        self.peers = peers
        channels = record.channels.compactMap { ChannelSummary($0.stored) }
        conversations = record.directConversations.map { conversation in
            let peer = PeerSummary(conversation.peer)
            return DirectConversationSummary(
                conversation,
                peer: peer,
                revision: chatRevisions[peer.identity.canonicalAddress] ?? 0
            )
        }
        channelConversations = record.channelConversations.compactMap { conversation in
            guard let channel = ChannelSummary(conversation.channel) else { return nil }
            return ChannelConversationSummary(
                conversation,
                channel: channel,
                revision: chatRevisions[conversation.conversationAddress] ?? 0
            )
        }
        neighborReports = record.neighborReports.map { reports in
            let byAddress = Dictionary(
                (peers ?? []).map { ($0.identity.canonicalAddress, $0) },
                uniquingKeysWith: { first, _ in first }
            )
            // A report whose reporter is not among the peers read with it
            // has nothing to hang from.
            return reports.compactMap { report in
                byAddress[report.reporterAddress].map {
                    PeerRepeaterNeighborReport(reporter: $0, neighbor: PeerRepeaterNeighbor(report.neighbor))
                }
            }
        }
        advertisedName = record.advertisedName
    }
}

// MARK: - Transcripts

extension TranscriptPage {
    init(_ record: MobileAppTranscriptPageRecord, peers: [PeerSummary]) {
        self.init(
            messages: record.messages.map { ChatMessageSummary($0, peers: peers) },
            hasOlder: record.hasOlder,
            hasNewer: record.hasNewer
        )
    }
}

extension ChatMessageSummary {
    /// One stored message, with the hints the core rendered for it and each
    /// repeater named by the peer the core matched it to.
    init(_ record: MobileAppMessageRecord, peers: [PeerSummary]) {
        let stored = StoredChatMessage(record.stored)
        let repeaters = record.repeaters.map { repeater in
            MessageRepeats.Repeater(
                hint: MeshRepeaterHint(
                    bytes: repeater.hint,
                    text: repeater.hintText ?? repeater.hint.map { String(format: "%02x", $0) }.joined()
                ),
                name: repeater.peerAddress.flatMap { address in
                    peers.first { $0.identity.canonicalAddress == address }?.displayName
                }
            )
        }
        self.init(
            id: stored.id,
            body: stored.body,
            isOutbound: stored.outbound,
            deliveryState: stored.deliveryState,
            isDeleted: stored.isDeleted,
            isEdited: stored.isEdited,
            sessionID: stored.sessionID,
            handle: stored.handle,
            wireID: stored.wireID,
            epoch: stored.epoch,
            cursor: stored.cursor,
            isGapPlaceholder: stored.isGapPlaceholder,
            isGapIdle: stored.isGapIdle,
            isUnavailable: stored.isUnavailable,
            isReceivedLate: stored.receivedLate,
            isEditOfUnknown: stored.isEditOfUnknown,
            isStatus: stored.isStatus,
            isForwardSecret: stored.isForwardSecret,
            isDeliveredLate: stored.deliveredLate,
            isDeliveredFlooded: stored.deliveredFlooded,
            originalBody: stored.originalBody,
            createdAtMilliseconds: stored.createdAtMilliseconds,
            senderAddress: stored.senderAddress,
            senderHint: stored.senderHint,
            senderHandle: stored.senderHandle,
            senderNodeHint: MeshNodeHint(bytes: stored.senderHint, text: record.senderNodeHint),
            reception: stored.reception,
            // The core reads each reaction in the order it stored them.
            reactions: zip(stored.reactions, record.reactions).map { MessageReaction($0, kind: $1) },
            reply: stored.quote.map { MessageQuote($0, senderNodeHint: record.quotedSenderNodeHint) },
            repeats: stored.repeats.map { repeats in
                MessageRepeats(
                    repeaters: repeaters,
                    anonymous: repeats.anonymous,
                    progressAt: repeats.progressAt
                )
            },
            reviseUntilMilliseconds: record.reviseUntilMs,
            actions: MessageActions(record.actions)
        )
    }
}

extension MessageActions {
    init(_ record: MobileMessageActionsRecord) {
        self.init(
            edit: record.edit,
            delete: record.delete,
            resend: record.resend,
            react: record.react,
            reply: record.reply,
            requestMissing: record.requestMissing
        )
    }
}

extension MessageQuote {
    init(_ stored: StoredMessageQuote, senderNodeHint: String?) {
        guard let original = stored.original else {
            self = .unavailable
            return
        }
        self.init(
            state: original.isDeleted ? .deleted : .present,
            targetID: original.ref.id,
            body: original.isDeleted ? "" : original.body,
            isOutbound: original.outbound,
            senderAddress: original.senderAddress,
            senderHandle: original.senderHandle,
            senderNodeHint: MeshNodeHint(bytes: original.senderHint, text: senderNodeHint)
        )
    }
}

extension MessageReaction {
    init(_ stored: StoredMessageReaction, kind: MobileReaction?) {
        self.init(
            body: stored.body,
            kind: kind,
            isMine: stored.outbound,
            senderAddress: stored.senderAddress,
            senderHint: stored.senderHint,
            sessionID: stored.sessionID,
            handle: stored.handle,
            wireID: stored.wireID,
            epoch: stored.epoch,
            // Only our own reactions have delivery to report, and only an
            // outright failure is worth showing: in flight looks like any
            // other reaction, the same way an unacknowledged bubble does.
            isFailed: stored.outbound && StoredChatMessage.isDeliveryFailure(stored.deliveryState),
            isForwardSecret: stored.forwardSecret
        )
    }
}

extension MobileStoredChatMessageRefRecord {
    /// A `ChatMessageSummary.id` split back into the durable identity it
    /// was built from: "session:handle".
    init?(messageID: String) {
        guard let separator = messageID.lastIndex(of: ":"),
              let handle = UInt32(messageID[messageID.index(after: separator)...])
        else { return nil }
        self.init(sessionId: String(messageID[..<separator]), handle: handle)
    }
}

// MARK: - Commands

extension MeshRepeaterHint {
    init(_ record: RepeaterHintRecord) {
        self.init(bytes: record.bytes, text: record.text)
    }
}

extension PeerPingReply {
    init(_ record: MobileAppPingReplyRecord) {
        self.init(
            roundTripMilliseconds: record.roundTripMs,
            hopCount: record.hopCount,
            routeHints: record.routeHints.map(MeshRepeaterHint.init),
            traceSignal: record.traceSignal.map {
                MeshLegSignal(rssiDBm: $0.rssiDbm, signalToNoiseCentibels: $0.snrCentibels)
            },
            rssiDBm: record.rssiDbm,
            signalToNoiseCentibels: record.snrCentibels,
            linkQuality: record.lqi,
            viaRouteRetry: record.viaRouteRetry,
            unnamedHops: record.unnamedHops
        )
    }
}

extension PeerRoute.Kind {
    init(_ kind: MobileMeshRouteKind) {
        self = switch kind {
        case .unknown: .unknown
        case .direct: .direct
        case .source: .source
        case .flood: .flood
        }
    }
}

extension PeerRoute {
    /// The route as of `now`, its ages turned into instants.
    init(_ record: MobileAppRouteRecord, now: Date = Date()) {
        self.init(
            kind: Kind(record.kind),
            hints: record.hints.map(MeshRepeaterHint.init),
            hopCount: record.hopCount,
            floodHops: record.floodHops,
            floodRegions: record.floodRegions,
            heldFloodHops: record.holdFloodHops,
            holdUntil: record.holdRemainingMs.map { now.addingTimeInterval(Double($0) / 1000) },
            fallbackAcks: record.fallbackAcks,
            lastAcknowledged: record.confirmedAgeMs.map { now.addingTimeInterval(-Double($0) / 1000) },
            candidate: record.candidate.map {
                Candidate(kind: Kind($0.kind), hints: $0.hints.map(MeshRepeaterHint.init), hopCount: $0.hopCount)
            },
            discoveryVantage: record.discoveryVantage.map {
                DiscoveryVantage(
                    repeaters: $0.repeaters.map(MeshRepeaterHint.init),
                    landsAtPeer: $0.landsAtPeer,
                    evidence: $0.evidence
                )
            }
        )
    }
}

extension MobilePositionRecord {
    /// A CoreLocation fix; an accuracy CoreLocation marks invalid is none.
    init(_ location: CLLocation) {
        self.init(
            latitudeDegrees: location.coordinate.latitude,
            longitudeDegrees: location.coordinate.longitude,
            accuracyMeters: location.horizontalAccuracy < 0 ? nil : location.horizontalAccuracy
        )
    }
}
