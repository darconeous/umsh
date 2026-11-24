package com.voria.umsh.features.peers

import com.voria.umsh.core.MobileException
import com.voria.umsh.core.MobileLinkKind
import com.voria.umsh.core.classifyUmshLink
import com.voria.umsh.core.inspectPeerIdentity
import com.voria.umsh.models.ImportPreview
import com.voria.umsh.services.mobilecore.RecordMapping

/** What a piece of text in Add peer's field turned out to be. */
sealed interface ImportCheck {
    /** A node: its link, Base58 address or hex key, as the core read it. */
    data class Node(val preview: ImportPreview) : ImportCheck

    /** A `umsh:` channel link, which joins a channel rather than adding a peer. */
    data object ChannelLink : ImportCheck

    /** Not a node link, an address or a key. */
    data object NotPeer : ImportCheck
}

/**
 * Sorting and reading what was typed, pasted or scanned: both rules are
 * the core's (`classify_umsh_link`, `inspect_peer_identity`), so the
 * channel prefixes and the accepted forms live in one place. Pure and
 * local: nothing is stored or sent.
 */
object PeerImport {
    fun check(input: String): ImportCheck {
        val trimmed = input.trim()
        if (classifyUmshLink(trimmed) == MobileLinkKind.CHANNEL) return ImportCheck.ChannelLink
        return try {
            ImportCheck.Node(RecordMapping.importPreview(trimmed, inspectPeerIdentity(trimmed)))
        } catch (_: MobileException) {
            ImportCheck.NotPeer
        }
    }
}
