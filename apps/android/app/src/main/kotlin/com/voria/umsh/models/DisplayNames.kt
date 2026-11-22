package com.voria.umsh.models

import com.voria.umsh.designsystem.ChannelNaming
import com.voria.umsh.designsystem.ChannelTitle

/**
 * What peers and channels are called, with the fallback words already in
 * the reader's language. Pure: the screens resolve the words once from
 * resources ([com.voria.umsh.designsystem.rememberDisplayNames]) and pass
 * this to code that sorts and searches by name.
 */
data class DisplayNames(
    val unnamedNode: String,
    val companionRadio: String,
    val privateChannel: String,
    val publicChannel: String,
    val emergencyChannel: String,
) {
    /** A peer's title: the alias the user gave it, else the name it advertised, else a fallback. */
    fun peer(peer: PeerSummary): String =
        given(peer) ?: if (peer.isCompanionRadio) companionRadio else unnamedNode

    /** A channel's title beside its badge (`channel-badges.md`). */
    fun channel(channel: ChannelSummary): String = when (val title = ChannelNaming.title(channel)) {
        is ChannelTitle.Text -> title.text
        ChannelTitle.Public -> publicChannel
        ChannelTitle.Emergency -> emergencyChannel
        ChannelTitle.Private -> privateChannel
    }

    companion object {
        /** The name someone gave a peer, the user or the node itself; null when neither did. */
        fun given(peer: PeerSummary): String? =
            peer.alias?.takeIf { it.isNotBlank() } ?: peer.advertisedName?.takeIf { it.isNotBlank() }
    }
}
