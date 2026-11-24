package com.voria.umsh.features.peers

import com.voria.umsh.models.Capabilities
import com.voria.umsh.models.PeerSummary

/**
 * What removing a node offers (`peers-list.svg` 5), decided by whether
 * there is a conversation with it.
 */
sealed interface RemovalChoice {
    /**
     * A conversation holds it: Delete peer and conversation, and, for a
     * saved node, Remove peer (back to the nodes heard over the air,
     * keeping the conversation).
     */
    data class WithConversation(val offersRemove: Boolean) : RemovalChoice

    /** No conversation: Delete peer alone. Nothing is sent to the node. */
    data object DeleteOnly : RemovalChoice

    companion object {
        /**
         * The list offers removal for any node but the companion radio's own
         * (`peers-list.svg` 4); null for the radio.
         */
        fun forList(peer: PeerSummary, hasConversation: Boolean): RemovalChoice? =
            if (peer.isCompanionRadio) null else of(peer, hasConversation)

        /**
         * The page offers it only for a saved node (`peer-page.svg` 4–5 draw
         * none for one heard but not saved); null otherwise.
         */
        fun forPage(peer: PeerSummary, hasConversation: Boolean): RemovalChoice? =
            if (peer.isCompanionRadio || !peer.isSaved) null else of(peer, hasConversation)

        private fun of(peer: PeerSummary, hasConversation: Boolean): RemovalChoice =
            if (hasConversation) WithConversation(offersRemove = peer.isSaved) else DeleteOnly
    }
}

/** The tiles under a peer page's name (`peer-page.svg`), in their order. */
enum class PeerVerb { Identify, Message, Ping, Neighbors }

/** Which verbs a node gets, as iOS `PeerVerbs.offered`. */
object PeerVerbs {
    /**
     * Chosen by what the node advertises it can do, never by its role: a
     * chat device may also repeat. A node that never advertised keeps every
     * verb and leads with Identify, the one thing that fills the rest in.
     * Message also needs a stored row. The companion radio's own identity is
     * reached over its link: Ping alone. [available] is what this build
     * offers at all; a verb whose page is not built yet is left out.
     */
    fun offered(peer: PeerSummary, available: Set<PeerVerb>, stored: Boolean = true): List<PeerVerb> {
        val verbs = mutableListOf<PeerVerb>()
        if (peer.isCompanionRadio) {
            if (PeerVerb.Ping in available) verbs += PeerVerb.Ping
            return verbs
        }
        val capabilities = peer.capabilities
        if (peer.advertised == null && PeerVerb.Identify in available) verbs += PeerVerb.Identify
        if (PeerVerb.Message in available && stored && capabilities?.contains(Capabilities.TEXT_MESSAGES) != false) {
            verbs += PeerVerb.Message
        }
        if (PeerVerb.Ping in available) verbs += PeerVerb.Ping
        if (PeerVerb.Neighbors in available && capabilities?.contains(Capabilities.REPEATER) != false) {
            verbs += PeerVerb.Neighbors
        }
        return verbs
    }

    /** What this build offers: Manage is Phase 4's, and not a verb here yet. */
    val AVAILABLE: Set<PeerVerb> = PeerVerb.entries.toSet()
}
