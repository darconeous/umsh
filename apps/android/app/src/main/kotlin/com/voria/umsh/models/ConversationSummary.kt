package com.voria.umsh.models

/** The newest message of a conversation, as its list row previews it. */
data class ConversationPreview(
    val createdAtMs: Long,
    val body: String,
    val isOutbound: Boolean,
    val isDeleted: Boolean,
    val senderAddress: String?,
    val senderHint: Octets?,
    val isStatus: Boolean,
    /** The sender's hint with the text the core rendered, when it has both. */
    val senderNodeHint: NodeHint?,
)

/** A conversation, direct or on a channel. */
sealed interface ConversationSummary {
    val id: Long
    val address: String
    val draftText: String
    val lastReadAtMs: Long
    val createdAtMs: Long
    val lastMessage: ConversationPreview?
    val unreadCount: Long

    /** How many times its stored messages have changed; an open transcript re-reads on a change. */
    val revision: Long

    /** The newer of its last message and its creation. */
    val lastActivityMs: Long get() = maxOf(lastMessage?.createdAtMs ?: Long.MIN_VALUE, createdAtMs)
}

data class DirectConversationSummary(
    override val id: Long,
    val peer: PeerSummary,
    override val draftText: String,
    override val lastReadAtMs: Long,
    override val createdAtMs: Long,
    val notificationsEnabled: Boolean,
    override val lastMessage: ConversationPreview?,
    override val unreadCount: Long,
    override val revision: Long,
) : ConversationSummary {
    override val address: String get() = peer.address
}

data class ChannelConversationSummary(
    override val id: Long,
    val channel: ChannelSummary,
    override val address: String,
    override val draftText: String,
    override val lastReadAtMs: Long,
    override val createdAtMs: Long,
    override val lastMessage: ConversationPreview?,
    override val unreadCount: Long,
    override val revision: Long,
    /**
     * `EMERGENCY`, with its warning not agreed to (or lapsed): the core
     * refuses every transmission here until it is.
     */
    val needsEmergencyAgreement: Boolean = false,
) : ConversationSummary
