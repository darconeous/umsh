package com.voria.umsh.features.conversations

import com.voria.umsh.designsystem.MessageSecurity
import com.voria.umsh.designsystem.PeerAvatarShape
import com.voria.umsh.models.ChannelConversationSummary
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.ConversationSummary
import com.voria.umsh.models.DirectConversationSummary
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.PreviewText.Sender
import com.voria.umsh.models.Quote

/**
 * What a thread's rows need to know about their conversation: who is in it,
 * who can read it, and what to call everyone. Pure, so the naming rules are
 * JVM-tested; the words come from [names] and the screen's resources.
 */
data class ThreadContext(
    val conversation: ConversationSummary,
    val peers: Map<String, PeerSummary>,
    val names: DisplayNames,
    /** This phone's advertised name; empty when it has none. */
    val ownName: String,
    /**
     * The composer writes under forward secrecy: a session is held with this
     * conversation's peer, or the draft was begun under one ([settledSecretDraft]).
     */
    val forwardSecret: Boolean,
) {
    val isChannel: Boolean get() = conversation is ChannelConversationSummary

    /** The conversation's title, as its top bar shows it. */
    val title: String = when (conversation) {
        is DirectConversationSummary -> names.peer(conversation.peer)
        is ChannelConversationSummary -> names.channel(conversation.channel)
    }

    /** Who can read what is written here: the color mine and the composer wear. */
    val security: MessageSecurity = when (conversation) {
        is DirectConversationSummary -> MessageSecurity.Encrypted
        is ChannelConversationSummary -> when (conversation.channel.kind) {
            ChannelKind.PrivateKey -> MessageSecurity.Encrypted
            ChannelKind.Builtin, ChannelKind.Named -> MessageSecurity.Open
        }
    }

    /** The composer's color: violet while a forward-secret session is held, or the draft was begun under one. */
    val composerSecurity: MessageSecurity
        get() = if (forwardSecret && !isChannel) MessageSecurity.ForwardSecret else security

    /** A message of mine wears the color it went under. */
    fun security(message: ChatMessage): MessageSecurity =
        if (message.isForwardSecret) MessageSecurity.ForwardSecret else security

    /**
     * Whoever sent a channel message, in descending order of authority: a
     * name this phone holds for them, then the name the message carried
     * (the sender's own unverified claim, so never above one the phone
     * established), then "Member" and their node hint.
     */
    fun member(address: String?, handle: String?, nodeHint: NodeHint?): Sender {
        val peer = address?.let(peers::get)
        peer?.let(DisplayNames::given)?.let { return Sender.Named(it) }
        handle?.takeIf { it.isNotBlank() }?.let { return Sender.Named(it) }
        val hint = peer?.hint?.text ?: nodeHint?.text
        return if (hint != null) Sender.Hint(hint) else Sender.Unknown
    }

    /** The name above a run in a channel; null in a direct chat, which has one possible sender. */
    fun runLabel(message: ChatMessage): Sender? =
        if (isChannel && !message.isOutbound) member(message.senderAddress, message.senderHandle, message.senderNodeHint) else null

    /** Who a status line ("/me") opens with. */
    fun statusName(message: ChatMessage): Sender = when {
        message.isOutbound -> Sender.Me(ownName.takeIf { it.isNotBlank() })
        isChannel -> member(message.senderAddress, message.senderHandle, message.senderNodeHint)
        else -> Sender.Named(title)
    }

    /** Who a quote names; null for an original this phone never had, which cannot say whose it was. */
    fun quoteName(quote: Quote): Sender? = when (quote) {
        Quote.Unavailable -> null
        is Quote.Original -> when {
            quote.isOutbound -> Sender.Me(null)
            !isChannel -> Sender.Named(title)
            else -> member(quote.senderAddress, quote.senderHandle, quote.senderNodeHint)
        }
    }

    /** Who the reply strip names: me as "You", the peer in a direct chat, the member in a channel. */
    fun replyName(message: ChatMessage): Sender = when {
        message.isOutbound -> Sender.Me(null)
        !isChannel -> Sender.Named(title)
        else -> member(message.senderAddress, message.senderHandle, message.senderNodeHint)
    }

    /** The avatar beside a channel run's last bubble: the known peer's, else the hint's in a circle. */
    fun memberAvatar(message: ChatMessage): Pair<NodeHint, PeerAvatarShape>? {
        if (!isChannel || message.isOutbound) return null
        val peer = message.senderAddress?.let(peers::get)
        if (peer != null) return peer.hint to PeerAvatarShape.of(peer)
        return message.senderNodeHint?.let { it to PeerAvatarShape.Circle }
    }

    /** A repeater's matched peer, by name. */
    fun repeaterName(peerAddress: String): String? = peers[peerAddress]?.let(names::peer)
}

/**
 * Whether the draft keeps forward secrecy (`composer.svg` board 4): one begun,
 * or still being written, while a session is held keeps it until it is
 * erased, even if the session drops; an empty one takes what is held.
 */
internal fun settledSecretDraft(wasSecret: Boolean, draftEmpty: Boolean, sessionHeld: Boolean): Boolean =
    !draftEmpty && (wasSecret || sessionHeld)
