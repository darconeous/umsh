package com.voria.umsh.models

/** Where the wrapping key of this phone's secrets is held. */
enum class KeyProtection { StrongBox, TrustedEnvironment, Software, Unknown }

/** This phone's identity, as the screens show it. */
data class LocalIdentity(
    /** The canonical address, which is also the store's owner ID. */
    val address: String,
    val hint: NodeHint,
    /** The stored advertised name; empty when it has none. */
    val advertisedName: String,
    val protection: KeyProtection,
)

/** The lists one state read produced. */
data class AppStateSnapshot(
    val peers: List<PeerSummary>,
    /** Oldest first. */
    val channels: List<ChannelSummary>,
    /** Most recent first. */
    val directConversations: List<DirectConversationSummary>,
    /** Most recent first; joined channels only. */
    val channelConversations: List<ChannelConversationSummary>,
    val neighborReports: List<NeighborReport>,
    val advertisedName: String?,
) {
    val conversations: List<ConversationSummary>
        get() = directConversations + channelConversations
}
