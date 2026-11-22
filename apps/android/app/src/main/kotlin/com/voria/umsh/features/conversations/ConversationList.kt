package com.voria.umsh.features.conversations

import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.ChannelConversationSummary
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.models.ConversationSummary
import com.voria.umsh.models.DirectConversationSummary
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.PreviewText
import com.voria.umsh.services.format.Collation
import com.voria.umsh.services.format.SearchFolding
import com.voria.umsh.services.format.SearchQuery

/** One row of the conversation list, everything it draws already decided. */
data class ConversationRow(
    val address: String,
    val title: String,
    val avatar: RowAvatar,
    val preview: PreviewText,
    /** The last message's time; null with no messages yet. */
    val timeMs: Long?,
    val unreadCount: Long,
    val muted: Boolean,
    /** What removing the row means: deleting a direct conversation, or leaving a channel's chat. */
    val removal: Removal,
    val lastActivityMs: Long,
)

sealed interface RowAvatar {
    data class Peer(val peer: PeerSummary) : RowAvatar
    data class Channel(val channel: ChannelSummary) : RowAvatar
}

sealed interface Removal {
    val address: String

    /** "Delete this conversation?"; the peer, by name, keeps their copy. */
    data class Delete(override val address: String, val peerName: String) : Removal

    /** “Leave “hike-club” chat?”: the phone stays in the channel. */
    data class Leave(override val address: String, val channelTitle: String) : Removal
}

/** What a search found (`conversation-list.svg` boards 4–5), grouped as iOS groups it. */
data class SearchResults(
    /** Conversations that exist, ordered as the list orders itself. */
    val conversations: List<ConversationRow>,
    /** Saved peers with no conversation yet. */
    val peers: List<PeerSummary>,
    /** Joined channels with no conversation yet. */
    val channels: List<ChannelSummary>,
    /** Nodes heard but not saved. */
    val discovered: List<PeerSummary>,
) {
    val isEmpty: Boolean get() = conversations.isEmpty() && peers.isEmpty() && channels.isEmpty() && discovered.isEmpty()
}

/**
 * The conversation list's rules, pure: rows, their order, and search.
 * Names and sorting come in ([DisplayNames], [Collation]) so the JVM tests
 * run them over a real store.
 */
object ConversationList {
    /**
     * Every conversation, direct and channel alike, newest activity first
     * (a channel with newer traffic sits above a quiet direct chat); ties
     * by title.
     */
    fun rows(state: AppStateSnapshot, names: DisplayNames, collation: Collation, ownName: String?): List<ConversationRow> {
        val peers = state.peers.associateBy { it.address }
        return state.conversations
            .map { row(it, peers, names, ownName) }
            .sortedWith(
                compareByDescending<ConversationRow> { it.lastActivityMs }
                    .thenBy(collation) { it.title }
                    .thenBy { it.address },
            )
    }

    fun row(
        conversation: ConversationSummary,
        peers: Map<String, PeerSummary>,
        names: DisplayNames,
        ownName: String?,
    ): ConversationRow {
        val title: String
        val avatar: RowAvatar
        val muted: Boolean
        val removal: Removal
        when (conversation) {
            is DirectConversationSummary -> {
                title = names.peer(conversation.peer)
                avatar = RowAvatar.Peer(conversation.peer)
                muted = !conversation.notificationsEnabled
                removal = Removal.Delete(conversation.address, title)
            }
            is ChannelConversationSummary -> {
                title = names.channel(conversation.channel)
                avatar = RowAvatar.Channel(conversation.channel)
                muted = !conversation.channel.notificationsEnabled
                removal = Removal.Leave(conversation.address, title)
            }
        }
        return ConversationRow(
            address = conversation.address,
            title = title,
            avatar = avatar,
            preview = PreviewText.of(conversation, peers, names, ownName),
            timeMs = conversation.lastMessage?.createdAtMs?.takeIf { it > 0 },
            unreadCount = conversation.unreadCount,
            muted = muted,
            removal = removal,
            lastActivityMs = conversation.lastActivityMs,
        )
    }

    /**
     * What [query] finds, or null when it is blank (the list shows
     * instead). Names, aliases and titles match anywhere, folded for case
     * and accents; addresses on a prefix only (a match inside one means
     * nothing); hints and channel identifiers ignoring case. Messages are
     * not searched. The companion radio is hardware, not a correspondent,
     * and is left out.
     */
    fun search(
        state: AppStateSnapshot,
        rows: List<ConversationRow>,
        query: String,
        names: DisplayNames,
        collation: Collation,
    ): SearchResults? {
        val needle = SearchQuery(query.trim())
        if (needle.text.isEmpty()) return null
        val direct = state.directConversations.associateBy { it.address }
        val channelConversations = state.channelConversations.associateBy { it.address }
        val conversations = rows.filter { row ->
            direct[row.address]?.let { return@filter matches(it.peer, needle) }
            channelConversations[row.address]?.let { return@filter matches(it.channel, needle, names) }
            false
        }
        val withConversation = state.directConversations.mapTo(HashSet()) { it.peer.address }
        val byName = compareBy<PeerSummary, String>(collation) { names.peer(it) }.thenBy { it.id }
        val startable = state.peers
            .filter { !it.isCompanionRadio && it.address !in withConversation && matches(it, needle) }
            .sortedWith(byName)
        val openChannels = state.channelConversations.mapTo(HashSet()) { it.channel.id }
        val channels = state.channels
            .filter { it.joinedPhone && it.id !in openChannels && matches(it, needle, names) }
            .sortedWith(compareBy<ChannelSummary, String>(collation) { names.channel(it) }.thenBy { it.id })
        return SearchResults(
            conversations = conversations,
            peers = startable.filter { it.isSaved },
            channels = channels,
            discovered = startable.filter { !it.isSaved },
        )
    }

    fun matches(peer: PeerSummary, query: SearchQuery): Boolean =
        SearchFolding.contains(peer.alias, query) ||
            SearchFolding.contains(peer.advertisedName, query) ||
            peer.address.startsWith(query.text) ||
            peer.hint.text.contains(query.text, ignoreCase = true)

    fun matches(channel: ChannelSummary, query: SearchQuery, names: DisplayNames): Boolean =
        SearchFolding.contains(names.channel(channel), query) ||
            SearchFolding.contains(channel.alias, query) ||
            SearchFolding.contains(channel.name, query) ||
            channel.channelIdHex.startsWith(query.text, ignoreCase = true)

    /** The kind a channel search row names under its title. */
    enum class KindLabel { Builtin, Named, Private }

    fun kindLabel(channel: ChannelSummary): KindLabel = when (channel.kind) {
        ChannelKind.Builtin -> KindLabel.Builtin
        ChannelKind.Named -> KindLabel.Named
        ChannelKind.PrivateKey -> KindLabel.Private
    }
}
