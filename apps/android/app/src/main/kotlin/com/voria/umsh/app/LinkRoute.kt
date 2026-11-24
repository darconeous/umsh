package com.voria.umsh.app

import com.voria.umsh.features.peers.ImportCheck
import com.voria.umsh.features.peers.PeerImport
import kotlinx.serialization.Serializable

/** Where an opened `umsh:` link came from, which decides what Close and Back on its page do (D7). */
@Serializable
enum class LinkOrigin {
    /** Another app's view intent: Close and Back go back to that app. */
    OtherApp,

    /** A link in one of this app's messages: Close and Back return to the thread. */
    InApp,
}

/** Where a `umsh:` link leads (product-structure, "Deep links"). */
sealed interface LinkTarget {
    /** A channel link: joining a channel, not adding a peer. */
    data class Channel(val uri: String) : LinkTarget

    /** A link that names no node: the import preview, with what is wrong with it. */
    data class Unreadable(val uri: String) : LinkTarget

    /** This phone's own identity: Settings, at Your identity. */
    data object OwnIdentity : LinkTarget

    /** Any other node: its page above whatever was showing. */
    data class Node(val uri: String, val address: String) : LinkTarget
}

/**
 * The one route for `umsh:` links, whether another app opened one or a
 * message holds one. Both rules are the core's (`classify_umsh_link`,
 * `inspect_peer_identity`, through [PeerImport]), so the channel prefixes
 * and the forms a node link takes live in one place.
 */
object LinkRoute {
    /** The scheme the app opens; notification taps carry `umsh-notification`, which is never a link. */
    const val SCHEME = "umsh"

    /**
     * The link a view intent carries: [action] `ACTION_VIEW` and a [scheme]
     * of `umsh`, in any case. Anything else, a notification's tap among
     * them, carries none.
     */
    fun linkOf(action: String?, scheme: String?, data: String?): String? {
        if (action != ACTION_VIEW || data.isNullOrBlank()) return null
        return data.takeIf { scheme.equals(SCHEME, ignoreCase = true) }
    }

    /**
     * Whether an intent may open what the app's own extras ask (a
     * notification's conversation or node, Radio Detail): never one that
     * carries a [link], and never one a browser sent ([fromBrowser]). A web
     * page can put any extras on the link it opens, and the filter that
     * takes `umsh` links is the one way a page reaches the activity.
     */
    fun honorsAppExtras(link: String?, categories: Set<String>?): Boolean = link == null && !fromBrowser(categories)

    /** An intent a browser sent: `CATEGORY_BROWSABLE`, which browsers add to every intent a page opens. */
    fun fromBrowser(categories: Set<String>?): Boolean = categories?.contains(CATEGORY_BROWSABLE) == true

    /** Where [uri] leads for the phone whose address is [ownAddress]. Local: nothing is stored or sent. */
    fun target(uri: String, ownAddress: String): LinkTarget = when (val checked = PeerImport.check(uri)) {
        ImportCheck.ChannelLink -> LinkTarget.Channel(uri)
        ImportCheck.NotPeer -> LinkTarget.Unreadable(uri)
        is ImportCheck.Node -> if (checked.preview.address == ownAddress) {
            LinkTarget.OwnIdentity
        } else {
            LinkTarget.Node(uri, checked.preview.address)
        }
    }

    /** `Intent.ACTION_VIEW`, spelled out so the route stays testable on the JVM. */
    private const val ACTION_VIEW = "android.intent.action.VIEW"

    /** `Intent.CATEGORY_BROWSABLE`, likewise. */
    private const val CATEGORY_BROWSABLE = "android.intent.category.BROWSABLE"
}
