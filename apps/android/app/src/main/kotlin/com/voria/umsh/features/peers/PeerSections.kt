package com.voria.umsh.features.peers

import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.PeerRole
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.services.format.Collation
import com.voria.umsh.services.format.SearchFolding
import com.voria.umsh.services.format.SearchQuery

/** The Peers list's orders (`peers-list.svg` 2), iOS's three. Remembered by [name]. */
enum class PeerSort {
    Alphabetical,
    RecentlyHeard,
    LatestMessage,
    ;

    companion object {
        /** A stored order, or [Alphabetical] for none or one this build no longer has. */
        fun named(name: String?): PeerSort = entries.firstOrNull { it.name == name } ?: Alphabetical
    }
}

/** The role filters (`peers-list.svg` 1): one at a time, none shows all. Not remembered, as on iOS. */
enum class PeerFilter {
    /** The chat role, or any node there is a conversation with. */
    People,

    /** Sensors and trackers. */
    Sensors,

    /** Whatever the core thinks plausibly forwards. */
    Repeaters,
}

/** What arranges the rows: the order and filter chosen, and the names they sort by. */
data class PeerArrangement(
    val sort: PeerSort,
    val filter: PeerFilter?,
    val names: DisplayNames,
    val collation: Collation,
)

/** The Peers list's sections, as iOS and `peers-list.svg` board 1 order them. */
data class PeerSections(
    val favorites: List<PeerSummary>,
    val saved: List<PeerSummary>,
    /** This phone's own companion radio, the node least often looked for. */
    val radios: List<PeerSummary>,
    /**
     * No node at all is stored, saved or only heard, filter or not: the
     * empty state (`peers-list.svg` 6), as iOS draws it.
     */
    val nothingKnown: Boolean,
    /** Nodes are known but none is saved: a line says where heard ones are, as iOS does. */
    val noneSaved: Boolean,
) {
    val isEmpty: Boolean get() = favorites.isEmpty() && saved.isEmpty() && radios.isEmpty()

    companion object {
        /**
         * Saved nodes, and the companion radio whatever its tier; nodes heard
         * but not saved stay out (search and Discover find them). The radio's
         * row ignores the filter, so it always anchors the list.
         */
        fun of(state: AppStateSnapshot, arrangement: PeerArrangement): PeerSections {
            val shown = state.peers.filter { it.isSaved || it.isCompanionRadio }
            val arranged = PeerArranging(state, arrangement).arranged(shown)
            return PeerSections(
                favorites = arranged.filter { !it.isCompanionRadio && it.isFavorite },
                saved = arranged.filter { !it.isCompanionRadio && !it.isFavorite },
                radios = arranged.filter { it.isCompanionRadio },
                nothingKnown = state.peers.isEmpty(),
                noneSaved = state.peers.isNotEmpty() && state.peers.none { it.isSaved && !it.isCompanionRadio },
            )
        }
    }
}

/** Search's two groups (`peers-list.svg` 3): saved nodes, then nodes heard but not saved. */
data class PeerSearchResults(val saved: List<PeerSummary>, val discovered: List<PeerSummary>) {
    val isEmpty: Boolean get() = saved.isEmpty() && discovered.isEmpty()

    companion object {
        /** Every known node matching [query], through the same chips as the list. */
        fun of(state: AppStateSnapshot, query: String, arrangement: PeerArrangement): PeerSearchResults {
            val matching = state.peers.filter { PeerSearch.matches(it, query) }
            val arranging = PeerArranging(state, arrangement)
            return PeerSearchResults(
                saved = arranging.arranged(matching.filter { it.isSaved || it.isCompanionRadio }),
                discovered = arranging.arranged(matching.filter { !it.isSaved && !it.isCompanionRadio }),
            )
        }
    }
}

/** Whether a node answers to a search, as iOS matches one. */
object PeerSearch {
    /**
     * Its alias or advertised name, without case or accents; its address
     * by prefix only (a hit inside an exact Base58 string means nothing);
     * its hint anywhere, without case. A blank query matches everything.
     */
    fun matches(peer: PeerSummary, query: String): Boolean {
        val trimmed = query.trim()
        if (trimmed.isEmpty()) return true
        val folded = SearchQuery(trimmed)
        return SearchFolding.contains(peer.alias, folded) ||
            SearchFolding.contains(peer.advertisedName, folded) ||
            peer.address.startsWith(trimmed) ||
            peer.hint.text.contains(trimmed, ignoreCase = true)
    }
}

/** Filter, then sort, rows from one state read. */
private class PeerArranging(private val state: AppStateSnapshot, private val arrangement: PeerArrangement) {
    private val withConversation: Set<String> by lazy { state.directConversations.mapTo(HashSet()) { it.peer.address } }

    /** The newest message's time in each direct conversation, by peer. */
    private val latestMessage: Map<String, Long> by lazy {
        state.directConversations.mapNotNull { conversation ->
            conversation.lastMessage?.let { conversation.peer.address to it.createdAtMs }
        }.toMap()
    }

    fun arranged(peers: List<PeerSummary>): List<PeerSummary> =
        peers.filter(::passes).sortedWith(order())

    private fun passes(peer: PeerSummary): Boolean {
        if (peer.isCompanionRadio) return true
        return when (arrangement.filter) {
            null -> true
            PeerFilter.People -> peer.role == PeerRole.Chat || peer.address in withConversation
            PeerFilter.Sensors -> peer.role == PeerRole.Sensor || peer.role == PeerRole.Tracker
            PeerFilter.Repeaters -> peer.likelyRepeater
        }
    }

    private fun order(): Comparator<PeerSummary> = when (arrangement.sort) {
        PeerSort.Alphabetical ->
            compareBy<PeerSummary, String>(arrangement.collation) { arrangement.names.peer(it) }.thenBy { it.id }
        // Never heard last.
        PeerSort.RecentlyHeard ->
            compareByDescending<PeerSummary> { it.lastHeardAtMs ?: Long.MIN_VALUE }.thenBy { it.id }
        PeerSort.LatestMessage ->
            compareByDescending<PeerSummary> { latestMessage[it.address] ?: Long.MIN_VALUE }.thenBy { it.id }
    }
}
