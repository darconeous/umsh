package com.voria.umsh.services.mobilecore

import com.voria.umsh.core.ChannelKindRecord
import com.voria.umsh.core.IdentitySignatureState
import com.voria.umsh.core.MobileAppChannelPreviewRecord
import com.voria.umsh.core.MobileAppChannelConversationRecord
import com.voria.umsh.core.MobileAppDirectConversationRecord
import com.voria.umsh.core.MobileAppMessageRecord
import com.voria.umsh.core.MobileAppPeerRecord
import com.voria.umsh.core.MobileAppPingReplyRecord
import com.voria.umsh.core.MobileAppPingResult
import com.voria.umsh.core.MobileAppRouteRecord
import com.voria.umsh.core.MobileMeshExplicitPath
import com.voria.umsh.core.MobileMeshRouteKind
import com.voria.umsh.core.RepeaterHintRecord
import com.voria.umsh.core.MobileAppPreviewRecord
import com.voria.umsh.core.MobileAppRepeaterListingRecord
import com.voria.umsh.core.MobileAppRepeaterNeighborRecord
import com.voria.umsh.core.MobileAppResent
import com.voria.umsh.core.MobileAppStateRecord
import com.voria.umsh.core.MobileAppTranscriptPageRecord
import com.voria.umsh.core.MobileChatPresence
import com.voria.umsh.core.MobileMeetDeviceRecord
import com.voria.umsh.core.MobileMeetEnd
import com.voria.umsh.core.MobileMeetExchange
import com.voria.umsh.core.MobileMeetStateRecord
import com.voria.umsh.core.MobileMessageActionsRecord
import com.voria.umsh.core.MobileReaction
import com.voria.umsh.core.MobileRepeaterEvidence
import com.voria.umsh.core.MobileStoredChannelKind
import com.voria.umsh.core.MobileStoredChannelRecord
import com.voria.umsh.core.MobileStoredChatDeliveryState
import com.voria.umsh.core.MobileStoredChatMessageRefRecord
import com.voria.umsh.core.MobileStoredChatQuoteRecord
import com.voria.umsh.core.MobileStoredChatReactionRecord
import com.voria.umsh.core.MobileStoredNodeKind
import com.voria.umsh.core.MobileStoredSystemRole
import com.voria.umsh.core.NodeIdentityRecord
import com.voria.umsh.core.NodeUriPreviewRecord
import com.voria.umsh.core.PublicIdentityRecord
import com.voria.umsh.models.AdvertisedIdentity
import com.voria.umsh.models.ManualPath
import com.voria.umsh.models.RouteCandidate
import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.ChannelConversationSummary
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChannelPreview
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.ConversationPreview
import com.voria.umsh.models.DeliveryState
import com.voria.umsh.models.ImportPreview
import com.voria.umsh.models.DiscoveryVantage
import com.voria.umsh.models.DirectConversationSummary
import com.voria.umsh.models.MessageActions
import com.voria.umsh.models.MeetDevice
import com.voria.umsh.models.MeetEnd
import com.voria.umsh.models.MeetExchange
import com.voria.umsh.models.MeetState
import com.voria.umsh.models.MessageRef
import com.voria.umsh.models.NeighborReport
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PeerRole
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.Presence
import com.voria.umsh.models.Quote
import com.voria.umsh.models.Reaction
import com.voria.umsh.models.ReactionKind
import com.voria.umsh.models.Reception
import com.voria.umsh.models.RepeaterEvidence
import com.voria.umsh.models.LegSignal
import com.voria.umsh.models.PingOutcome
import com.voria.umsh.models.PingReply
import com.voria.umsh.models.RepeaterHint
import com.voria.umsh.models.RepeaterListing
import com.voria.umsh.models.RepeaterNeighbor
import com.voria.umsh.models.Repeats
import com.voria.umsh.models.ResendMode
import com.voria.umsh.models.RouteKind
import com.voria.umsh.models.RouteSummary
import com.voria.umsh.models.SignatureState
import com.voria.umsh.models.TranscriptCursor
import com.voria.umsh.models.TranscriptPage

/**
 * The core's read records, mapped onto the models the screens draw.
 *
 * Pure functions of the record and, where a name has to be found, the
 * peers already mapped: the core decides which peer a hint names, and this
 * side only looks the address up. No Android APIs, so the JVM tests run it.
 */
object RecordMapping {
    fun hint(record: PublicIdentityRecord): NodeHint =
        NodeHint(Octets(record.hint.bytes), record.hint.text)

    fun peer(record: MobileAppPeerRecord): PeerSummary {
        val stored = record.stored
        return PeerSummary(
            id = stored.id,
            address = record.identity.canonicalAddress,
            hint = hint(record.identity),
            alias = stored.alias,
            advertisedName = stored.advertisedName,
            isCompanionRadio = stored.systemRole == MobileStoredSystemRole.COMPANION_RADIO,
            storedRole = role(stored.nodeKind),
            advertised = record.advertisedIdentity?.let(::advertised),
            advertisementAuthenticated = stored.advertisementAuthenticated,
            advertisementReceivedAtMs = stored.advertisementReceivedAtMs,
            lastHeardAtMs = stored.lastHeardAtMs,
            isSaved = stored.isSaved,
            isFavorite = stored.isFavorite,
            isOnDeviceIdentity = stored.onDeviceIdentity,
            notifyWhenHeard = stored.notifyWhenHeard,
            likelyRepeater = record.likelyRepeater,
            advertisementAttributable = record.advertisementAttributable,
        )
    }

    /** A route as read at [readAtMs] (wall clock): its ages become instants. */
    fun route(record: MobileAppRouteRecord, readAtMs: Long) = RouteSummary(
        kind = routeKind(record.kind),
        hints = record.hints.map(::repeaterHint),
        hopCount = record.hopCount?.toInt(),
        floodHops = record.floodHops?.toInt(),
        holdRemainingMs = record.holdRemainingMs?.toLong(),
        holdFloodHops = record.holdFloodHops?.toInt(),
        confirmedAgeMs = record.confirmedAgeMs?.toLong(),
        floodRegions = record.floodRegions.map(::Octets),
        holdUntilMs = record.holdRemainingMs?.let { readAtMs + it.toLong() },
        confirmedAtMs = record.confirmedAgeMs?.let { readAtMs - it.toLong() },
        discoveryVantage = record.discoveryVantage?.let { vantage ->
            DiscoveryVantage(
                repeaters = vantage.repeaters.map(::repeaterHint),
                landsAtPeer = vantage.landsAtPeer,
                evidence = when (vantage.evidence) {
                    MobileRepeaterEvidence.YES -> RepeaterEvidence.Yes
                    MobileRepeaterEvidence.UNKNOWN -> RepeaterEvidence.Unknown
                    MobileRepeaterEvidence.NO -> RepeaterEvidence.No
                },
            )
        }?.takeIf { it.repeaters.isNotEmpty() },
        fallbackAcks = record.fallbackAcks.toInt(),
        candidate = record.candidate?.let { candidate ->
            RouteCandidate(routeKind(candidate.kind), candidate.hints.map(::repeaterHint), candidate.hopCount?.toInt())
        },
    )

    private fun routeKind(kind: MobileMeshRouteKind) = when (kind) {
        MobileMeshRouteKind.UNKNOWN -> RouteKind.Unknown
        MobileMeshRouteKind.DIRECT -> RouteKind.Direct
        MobileMeshRouteKind.SOURCE -> RouteKind.Source
        MobileMeshRouteKind.FLOOD -> RouteKind.Flood
    }

    /** A path chosen by hand, as the core takes it. */
    fun path(path: ManualPath) = MobileMeshExplicitPath(path.hints.map(Octets::toByteArray), path.floodHops.toUByte())

    /** How a ping ended; [MobileAppPingResult.Canceled] when a newer one replaced it. */
    fun ping(result: MobileAppPingResult): PingOutcome = when (result) {
        is MobileAppPingResult.Reply -> PingOutcome.Reply(pingReply(result.reply))
        MobileAppPingResult.TimedOut -> PingOutcome.TimedOut
        MobileAppPingResult.Canceled -> PingOutcome.Canceled
    }

    fun pingReply(record: MobileAppPingReplyRecord) = PingReply(
        roundTripMs = record.roundTripMs?.toLong(),
        hopCount = record.hopCount?.toInt(),
        routeHints = record.routeHints.map(::repeaterHint),
        traceSignal = record.traceSignal.map { LegSignal(it.rssiDbm?.toInt(), it.snrCentibels?.toInt()) },
        ownSignal = LegSignal(record.rssiDbm?.toInt(), record.snrCentibels?.toInt()),
        viaRouteRetry = record.viaRouteRetry,
        unnamedHops = record.unnamedHops?.toInt(),
    )

    fun repeaterHint(record: RepeaterHintRecord) = RepeaterHint(Octets(record.bytes), record.text)

    private fun role(kind: MobileStoredNodeKind?): PeerRole = when (kind) {
        null, MobileStoredNodeKind.UNKNOWN -> PeerRole.Unknown
        MobileStoredNodeKind.REPEATER -> PeerRole.Repeater
        MobileStoredNodeKind.CHAT -> PeerRole.Chat
        MobileStoredNodeKind.TRACKER -> PeerRole.Tracker
        MobileStoredNodeKind.SENSOR -> PeerRole.Sensor
        MobileStoredNodeKind.BRIDGE -> PeerRole.Bridge
        MobileStoredNodeKind.CHAT_ROOM -> PeerRole.ChatRoom
        MobileStoredNodeKind.TEMPORARY_SESSION -> PeerRole.TemporarySession
    }

    /** What [input] names, as the core read it. */
    fun importPreview(input: String, record: NodeUriPreviewRecord) = ImportPreview(
        input = input,
        address = record.canonicalAddress,
        hint = NodeHint(Octets(record.hint.bytes), record.hint.text),
        hasIdentityData = record.hasIdentityData,
        identity = record.identity?.let(::advertised),
    )

    private fun advertised(record: NodeIdentityRecord) = AdvertisedIdentity(
        roleCode = record.roleCode.toInt(),
        capabilityBits = record.capabilityBits.toInt(),
        forwards = record.forwards,
        name = record.name,
        latitude = record.latitude,
        longitude = record.longitude,
        locationPrecision = record.locationPrecision?.toInt(),
        altitudeMeters = record.altitudeM,
        timestamp = record.timestamp?.toLong(),
        signature = when (record.signature) {
            IdentitySignatureState.UNSIGNED -> SignatureState.Unsigned
            IdentitySignatureState.VALID -> SignatureState.Valid
            IdentitySignatureState.INVALID -> SignatureState.Invalid
        },
    )

    fun channel(record: MobileStoredChannelRecord, conversationAddress: String?) = ChannelSummary(
        id = record.id,
        kind = when (record.kind) {
            MobileStoredChannelKind.BUILTIN -> ChannelKind.Builtin
            MobileStoredChannelKind.NAMED -> ChannelKind.Named
            MobileStoredChannelKind.PRIVATE_KEY -> ChannelKind.PrivateKey
        },
        canonicalName = record.canonicalName,
        name = record.name,
        alias = record.alias,
        channelIdHex = record.channelIdHex,
        tint = Octets(record.tint),
        regionCode = record.regionCode?.let(::Octets),
        maxFloodHops = record.maxFloodHops?.toInt(),
        joinedPhone = record.joinedPhone,
        notificationsEnabled = record.notificationsEnabled,
        joinedAtMs = record.joinedAtMs,
        conversationAddress = conversationAddress,
    )

    /** A channel name or invitation as `preview_channel` read it from [input]. */
    fun channelPreview(input: String, record: MobileAppChannelPreviewRecord) = ChannelPreview(
        input = input,
        isPrivate = record.preview.kind == ChannelKindRecord.PRIVATE_KEY,
        canonicalName = record.preview.canonicalName,
        displayName = record.preview.displayName,
        key = Octets(record.preview.key),
        channelIdHex = Octets(record.preview.channelId).hex(),
        tint = Octets(record.preview.tint),
        existing = record.existing?.let { channel(it, null) },
        nameConflict = record.nameConflict?.let { channel(it, null) },
    )

    fun preview(record: MobileAppPreviewRecord): ConversationPreview {
        val stored = record.stored
        return ConversationPreview(
            createdAtMs = stored.createdAtMs,
            body = stored.body,
            isOutbound = stored.isOutbound,
            isDeleted = stored.isDeleted,
            senderAddress = stored.senderAddress,
            senderHint = stored.senderHint?.let(::Octets),
            isStatus = stored.isStatus,
            senderNodeHint = nodeHint(stored.senderHint, record.senderNodeHint),
        )
    }

    /** A hint with the text the core rendered for it, when there is both. */
    private fun nodeHint(bytes: ByteArray?, text: String?): NodeHint? =
        if (bytes != null && text != null) NodeHint(Octets(bytes), text) else null

    fun direct(record: MobileAppDirectConversationRecord, revision: Long): DirectConversationSummary {
        val peer = peer(record.peer)
        return DirectConversationSummary(
            id = record.id,
            peer = peer,
            draftText = record.draftText,
            lastReadAtMs = record.lastReadAtMs,
            createdAtMs = record.createdAtMs,
            notificationsEnabled = record.notificationsEnabled,
            lastMessage = record.lastMessage?.let(::preview),
            unreadCount = record.unreadCount,
            revision = revision,
        )
    }

    fun channelConversation(record: MobileAppChannelConversationRecord, revision: Long) =
        ChannelConversationSummary(
            id = record.id,
            channel = channel(record.channel, record.conversationAddress),
            address = record.conversationAddress,
            draftText = record.draftText,
            lastReadAtMs = record.lastReadAtMs,
            createdAtMs = record.createdAtMs,
            lastMessage = record.lastMessage?.let(::preview),
            unreadCount = record.unreadCount,
            revision = revision,
            needsEmergencyAgreement = record.needsEmergencyAgreement,
        )

    fun neighbor(record: MobileAppRepeaterNeighborRecord): RepeaterNeighbor {
        val entry = record.entry
        return RepeaterNeighbor(
            hint = Octets(entry.hint),
            hintText = record.hintText ?: entry.hint.joinToString("") { "%02X".format(it.toInt() and 0xFF) },
            name = entry.name,
            rssiDbm = entry.rssiDbm?.toInt(),
            snrQuarterDb = entry.snrQuarterDb?.toInt(),
            lastHeardMinutes = entry.lastHeardMinutes?.toInt(),
            latitude = entry.latitude,
            longitude = entry.longitude,
            locationPrecision = entry.locationPrecision?.toInt(),
            regionCodes = entry.regionCodes.map(::Octets),
            reportedAtMs = entry.reportedAtMs,
            peerAddress = record.peerAddress,
        )
    }

    fun listing(record: MobileAppRepeaterListingRecord) = RepeaterListing(
        entries = record.entries.map(::neighbor),
        total = record.total,
        nextCursor = record.nextCursor?.let(::Octets),
        asOfMs = record.asOfMs,
    )

    /**
     * One state read, mapped. A conversations-only read carries no peers or
     * reports, so [previous]'s stand.
     */
    fun state(
        record: MobileAppStateRecord,
        revisions: Map<String, Long>,
        previous: AppStateSnapshot?,
    ): AppStateSnapshot {
        val peers = record.peers?.map(::peer) ?: previous?.peers.orEmpty()
        val conversationAddresses = record.channels.associate { it.stored.id to it.conversationAddress }
        val reports = record.neighborReports?.let { reports ->
            val byAddress = peers.associateBy { it.address }
            // A report whose reporter is not among the peers read with it
            // has nothing to hang from.
            reports.mapNotNull { report ->
                byAddress[report.reporterAddress]?.let { NeighborReport(it, neighbor(report.neighbor)) }
            }
        } ?: previous?.neighborReports.orEmpty()
        return AppStateSnapshot(
            peers = peers,
            channels = record.channels.map { channel(it.stored, conversationAddresses[it.stored.id]) },
            directConversations = record.directConversations.map {
                direct(it, revisions[it.peer.identity.canonicalAddress] ?: 0)
            },
            channelConversations = record.channelConversations.map {
                channelConversation(it, revisions[it.conversationAddress] ?: 0)
            },
            neighborReports = reports,
            advertisedName = record.advertisedName,
        )
    }

    fun page(record: MobileAppTranscriptPageRecord, peers: List<PeerSummary>) = TranscriptPage(
        messages = record.messages.map { message(it, peers) },
        hasOlder = record.hasOlder,
        hasNewer = record.hasNewer,
    )

    fun ref(record: MobileStoredChatMessageRefRecord) = MessageRef(record.sessionId, record.handle.toLong())

    fun ref(ref: MessageRef) = MobileStoredChatMessageRefRecord(ref.sessionId, ref.handle.toUInt())

    /** One stored message, with the hints the core rendered and each repeater matched to a known peer. */
    fun message(record: MobileAppMessageRecord, peers: List<PeerSummary>): ChatMessage {
        val stored = record.stored
        val known = peers.mapTo(HashSet()) { it.address }
        val repeaters = record.repeaters.map { repeater ->
            Repeats.Repeater(
                hint = Octets(repeater.hint),
                text = repeater.hintText ?: Octets(repeater.hint).hex(),
                peerAddress = repeater.peerAddress?.takeIf { it in known },
            )
        }
        return ChatMessage(
            ref = ref(stored.reference),
            cursor = TranscriptCursor(stored.createdAtMs, stored.rowId),
            body = stored.body,
            isOutbound = stored.outbound,
            delivery = stored.deliveryState?.let(::delivery),
            isDeleted = stored.isDeleted,
            isEdited = stored.isEdited,
            wireId = stored.wireId?.toInt(),
            epoch = stored.epoch?.toInt(),
            presence = when (stored.presence) {
                MobileChatPresence.PRESENT -> Presence.Present
                MobileChatPresence.GAP_PENDING -> Presence.GapPending
                MobileChatPresence.GAP_IDLE -> Presence.GapIdle
                MobileChatPresence.UNAVAILABLE -> Presence.Unavailable
            },
            isReceivedLate = stored.receivedLate,
            isDeliveredLate = stored.deliveredLate,
            isDeliveredFlooded = stored.deliveredFlooded,
            isEditOfUnknown = stored.isEditOfUnknown,
            isStatus = stored.isStatus,
            isForwardSecret = stored.isForwardSecret,
            originalBody = stored.originalBody,
            senderAddress = stored.senderAddress,
            senderHint = stored.senderHint?.let(::Octets),
            senderHandle = stored.senderHandle,
            senderNodeHint = nodeHint(stored.senderHint, record.senderNodeHint),
            reception = stored.reception?.let {
                Reception(
                    rssiDbm = it.rssiDbm?.toInt(),
                    snrCentibels = it.snrCentibels?.toInt(),
                    lqi = it.lqi?.toInt(),
                    hopCount = it.hopCount?.toInt(),
                    routeHints = it.routeHints.map(::Octets),
                    sourceAuthenticated = it.sourceAuthenticated,
                )
            },
            // The core reads each reaction in the order it stored them.
            reactions = stored.reactions.zip(record.reactions) { reaction, kind -> reaction(reaction, kind) },
            quote = stored.quote?.let { quote(it, record.quotedSenderNodeHint) },
            repeats = stored.repeats?.let { Repeats(repeaters, it.anonymous, it.progressAtMs) },
            reviseUntilMs = record.reviseUntilMs,
            actions = actions(record.actions),
        )
    }

    fun actions(record: MobileMessageActionsRecord) = MessageActions(
        edit = record.edit,
        delete = record.delete,
        resend = record.resend?.let(::resendMode),
        react = record.react,
        reply = record.reply,
        requestMissing = record.requestMissing,
    )

    fun resendMode(resent: MobileAppResent): ResendMode = when (resent) {
        MobileAppResent.IN_PLACE -> ResendMode.InPlace
        MobileAppResent.AS_NEW -> ResendMode.AsNew
    }

    /** A reaction as the core sends it. */
    fun reaction(kind: ReactionKind): MobileReaction = when (kind) {
        ReactionKind.Heart -> MobileReaction.Heart
        ReactionKind.ThumbsUp -> MobileReaction.ThumbsUp
        ReactionKind.ThumbsDown -> MobileReaction.ThumbsDown
        ReactionKind.Laugh -> MobileReaction.Laugh
        ReactionKind.Exclaim -> MobileReaction.Exclaim
        ReactionKind.Question -> MobileReaction.Question
        is ReactionKind.Other -> MobileReaction.Other(kind.cluster)
    }

    fun delivery(state: MobileStoredChatDeliveryState): DeliveryState = when (state) {
        MobileStoredChatDeliveryState.PENDING -> DeliveryState.Pending
        MobileStoredChatDeliveryState.SENT -> DeliveryState.Sent
        MobileStoredChatDeliveryState.ACKNOWLEDGED -> DeliveryState.Acknowledged
        MobileStoredChatDeliveryState.FAILED -> DeliveryState.Failed
        MobileStoredChatDeliveryState.UNDELIVERED -> DeliveryState.Undelivered
    }

    private fun isFailure(state: MobileStoredChatDeliveryState?) =
        state == MobileStoredChatDeliveryState.FAILED || state == MobileStoredChatDeliveryState.UNDELIVERED

    private fun reaction(stored: MobileStoredChatReactionRecord, kind: MobileReaction?) = Reaction(
        body = stored.body,
        kind = kind?.let(::reactionKind),
        isMine = stored.outbound,
        senderAddress = stored.senderAddress,
        senderHint = stored.senderHint?.let(::Octets),
        ref = ref(stored.reference),
        wireId = stored.wireId?.toInt(),
        epoch = stored.epoch?.toInt(),
        // Only our own reactions have delivery to report, and only an
        // outright failure is worth showing.
        isFailed = stored.outbound && isFailure(stored.deliveryState),
        isForwardSecret = stored.forwardSecret,
    )

    fun reactionKind(kind: MobileReaction): ReactionKind = when (kind) {
        MobileReaction.Heart -> ReactionKind.Heart
        MobileReaction.ThumbsUp -> ReactionKind.ThumbsUp
        MobileReaction.ThumbsDown -> ReactionKind.ThumbsDown
        MobileReaction.Laugh -> ReactionKind.Laugh
        MobileReaction.Exclaim -> ReactionKind.Exclaim
        MobileReaction.Question -> ReactionKind.Question
        is MobileReaction.Other -> ReactionKind.Other(kind.cluster)
    }

    private fun quote(stored: MobileStoredChatQuoteRecord, senderNodeHint: String?): Quote {
        val original = stored.original ?: return Quote.Unavailable
        return Quote.Original(
            isDeleted = original.isDeleted,
            target = ref(original.reference),
            body = if (original.isDeleted) "" else original.body,
            isOutbound = original.outbound,
            senderAddress = original.senderAddress,
            senderHandle = original.senderHandle,
            senderNodeHint = nodeHint(original.senderHint, senderNodeHint),
        )
    }

    fun meet(record: MobileMeetStateRecord) = MeetState(
        ownColorRgb = record.ownColorRgb?.toInt(),
        devices = record.devices.map(::meetDevice),
        device = record.device?.let(::meetDevice),
        exchange = when (val exchange = record.exchange) {
            MobileMeetExchange.Closed -> MeetExchange.Closed
            MobileMeetExchange.Opening -> MeetExchange.Opening
            MobileMeetExchange.Idle -> MeetExchange.Idle
            is MobileMeetExchange.Asking -> MeetExchange.Asking(meetDevice(exchange.device))
            is MobileMeetExchange.Asked -> MeetExchange.Asked(meetDevice(exchange.device))
            is MobileMeetExchange.Accepted -> MeetExchange.Accepted(meetDevice(exchange.device))
            is MobileMeetExchange.Comparing ->
                MeetExchange.Comparing(meetDevice(exchange.device), exchange.code.toInt(), exchange.sent)
            is MobileMeetExchange.Ended -> MeetExchange.Ended(meetEnd(exchange.reason))
            is MobileMeetExchange.Exchanged ->
                MeetExchange.Exchanged(exchange.contact.peerAddress, exchange.contact.signed)
        },
    )

    private fun meetDevice(record: MobileMeetDeviceRecord) = MeetDevice(
        id = record.id.toLong(),
        model = record.model.toInt(),
        colorRgb = record.colorRgb.toInt(),
        nearness = record.nearness?.toInt(),
    )

    private fun meetEnd(end: MobileMeetEnd): MeetEnd = when (end) {
        MobileMeetEnd.NOT_NOW -> MeetEnd.NotNow
        MobileMeetEnd.BUSY -> MeetEnd.Busy
        MobileMeetEnd.DIFFERENT -> MeetEnd.Different
        MobileMeetEnd.LEFT -> MeetEnd.Left
        MobileMeetEnd.TIMED_OUT -> MeetEnd.TimedOut
        MobileMeetEnd.FAILED -> MeetEnd.Failed
    }
}
