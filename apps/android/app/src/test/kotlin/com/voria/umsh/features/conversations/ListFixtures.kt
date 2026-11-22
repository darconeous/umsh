package com.voria.umsh.features.conversations

import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.ChannelConversationSummary
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.models.ConversationPreview
import com.voria.umsh.models.DirectConversationSummary
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PeerRole
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.services.format.Collation
import java.text.Collator
import java.util.Locale

/** `java.text`'s collator at secondary strength: the JVM stand-in for ICU's. */
class JvmCollation(locale: Locale = Locale.US) : Collation {
    private val collator = Collator.getInstance(locale).apply { strength = Collator.SECONDARY }

    override fun compare(a: String, b: String): Int = synchronized(collator) { collator.compare(a, b) }
}

/** Hand-built models for the list's rules. */
object ListFixtures {
    val names = DisplayNames(
        unnamedNode = "Unnamed node",
        companionRadio = "Companion radio",
        privateChannel = "Private channel",
        publicChannel = "Public",
        emergencyChannel = "EMERGENCY",
    )

    private var nextId = 1L

    fun peer(
        hint: String,
        advertisedName: String? = null,
        alias: String? = null,
        address: String = "${hint}Addr",
        saved: Boolean = true,
        favorite: Boolean = false,
        companion: Boolean = false,
        role: PeerRole = PeerRole.Chat,
    ) = PeerSummary(
        id = nextId++,
        address = address,
        hint = NodeHint(Octets(byteArrayOf(1, 2, 3)), hint),
        alias = alias,
        advertisedName = advertisedName,
        isCompanionRadio = companion,
        storedRole = role,
        advertised = null,
        advertisementAuthenticated = false,
        advertisementReceivedAtMs = null,
        lastHeardAtMs = null,
        isSaved = saved,
        isFavorite = favorite,
        isOnDeviceIdentity = false,
        notifyWhenHeard = false,
    )

    fun channel(
        name: String?,
        id: String = "ID-${name ?: "none"}",
        canonical: String? = null,
        hex: String = "3f9a",
        joined: Boolean = true,
        notifications: Boolean = true,
        kind: ChannelKind = if (canonical != null) ChannelKind.Builtin else ChannelKind.Named,
    ) = ChannelSummary(
        id = id,
        kind = kind,
        canonicalName = canonical,
        name = name,
        alias = null,
        channelIdHex = hex,
        tint = Octets(byteArrayOf(0x3f, 0x9a.toByte(), 0x10)),
        regionCode = null,
        maxFloodHops = null,
        joinedPhone = joined,
        notificationsEnabled = notifications,
        joinedAtMs = null,
        conversationAddress = null,
    )

    fun preview(
        at: Long,
        body: String = "hello",
        outbound: Boolean = false,
        deleted: Boolean = false,
        status: Boolean = false,
        senderAddress: String? = null,
        senderHint: String? = null,
    ) = ConversationPreview(
        createdAtMs = at,
        body = body,
        isOutbound = outbound,
        isDeleted = deleted,
        senderAddress = senderAddress,
        senderHint = senderHint?.let { Octets(byteArrayOf(9, 9, 9)) },
        isStatus = status,
        senderNodeHint = senderHint?.let { NodeHint(Octets(byteArrayOf(9, 9, 9)), it) },
    )

    fun direct(
        peer: PeerSummary,
        last: ConversationPreview? = null,
        created: Long = 0,
        unread: Long = 0,
        draft: String = "",
        notifications: Boolean = true,
    ) = DirectConversationSummary(
        id = nextId++,
        peer = peer,
        draftText = draft,
        lastReadAtMs = 0,
        createdAtMs = created,
        notificationsEnabled = notifications,
        lastMessage = last,
        unreadCount = unread,
        revision = 0,
    )

    fun channelChat(
        channel: ChannelSummary,
        last: ConversationPreview? = null,
        created: Long = 0,
        unread: Long = 0,
        draft: String = "",
    ) = ChannelConversationSummary(
        id = nextId++,
        channel = channel,
        address = "ch:${channel.id}",
        draftText = draft,
        lastReadAtMs = 0,
        createdAtMs = created,
        lastMessage = last,
        unreadCount = unread,
        revision = 0,
    )

    fun state(
        peers: List<PeerSummary> = emptyList(),
        channels: List<ChannelSummary> = emptyList(),
        direct: List<DirectConversationSummary> = emptyList(),
        channelChats: List<ChannelConversationSummary> = emptyList(),
    ) = AppStateSnapshot(
        peers = peers,
        channels = channels,
        directConversations = direct,
        channelConversations = channelChats,
        neighborReports = emptyList(),
        advertisedName = null,
    )
}
