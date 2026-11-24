package com.voria.umsh.app

import androidx.navigation3.runtime.NavKey
import kotlinx.serialization.Serializable

/**
 * Every page the shell's back stacks hold. Serializable, so the stacks
 * survive process death; R8 keeps them (`proguard-rules.pro`).
 */
@Serializable
sealed interface UmshKey : NavKey {
    @Serializable
    data object ConversationsRoot : UmshKey

    /** A conversation, by its address (a peer's, or a channel conversation's). */
    @Serializable
    data class Thread(val address: String) : UmshKey

    /**
     * A channel conversation's Conversation info (`conversation-info.svg`),
     * above its thread, from the thread's title. Closed with the thread
     * once the conversation is gone ([ShellState.closeThreadsNotIn]).
     */
    @Serializable
    data class ConversationInfo(val address: String) : UmshKey

    /** One message's details (`bubbles.svg` 6–7), from its thread. */
    @Serializable
    data class MessageDetails(val address: String, val sessionId: String, val handle: Long) : UmshKey

    @Serializable
    data object PeersRoot : UmshKey

    @Serializable
    data object MapRoot : UmshKey

    @Serializable
    data object SettingsRoot : UmshKey

    @Serializable
    data object YourIdentity : UmshKey

    /**
     * The companion radio's page: above the shell on the app-level stack,
     * or in the Settings stack as Companion radio.
     */
    @Serializable
    data object RadioDetail : UmshKey

    /** Choose a radio (`radio-picker.svg`): above the shell on the app-level stack. */
    @Serializable
    data object RadioPicker : UmshKey

    /**
     * A peer's page (`peer-page.svg`). [destination] is the stack it is on,
     * which picks its pane; null above the shell (from Radio Detail there,
     * and links). [link] is where the link that opened it came from: such
     * a page has Close, which returns there (board 5, D7).
     */
    @Serializable
    data class PeerPage(val address: String, val destination: Destination?, val link: LinkOrigin? = null) : UmshKey, PeerPageKey {
        override val peerAddress: String get() = address
    }

    /**
     * How this phone reaches a peer (`ping-route.svg` 4–5), pushed on the
     * stack of the page that opened it (D12): [destination] as that page's.
     */
    @Serializable
    data class Route(val address: String, val destination: Destination?) : UmshKey, PeerPageKey {
        override val peerAddress: String get() = address
    }

    /**
     * What a repeater reports hearing (`repeaters-discover.svg` 1–2), pushed
     * on the stack of the page that opened it (D12).
     */
    @Serializable
    data class Neighbors(val address: String, val destination: Destination?) : UmshKey, PeerPageKey {
        override val peerAddress: String get() = address
    }

    /**
     * Discover peers (`repeaters-discover.svg` 3–5): from the Peers list, or
     * aimed near [vantagePeer] by its Route page's Ask near this node, on
     * that page's stack (D12). It holds the peer, not the vantage, so a page
     * restored after process death asks where the route goes now.
     */
    @Serializable
    data class Discover(val vantagePeer: String?, val destination: Destination?) : UmshKey, PeerPageKey {
        override val peerAddress: String? get() = vantagePeer
    }

    /**
     * The manual path editor for a peer (`manual-path.svg`): a full-screen
     * dialog above the shell, from the Route page's Edit, wherever that is.
     */
    @Serializable
    data class ManualPath(val address: String) : UmshKey, PeerPageKey {
        override val peerAddress: String get() = address
    }

    /**
     * Add peer (`add-peer.svg`): from the Peers list's button, as the list's
     * detail page, or from Conversations' New message, above that list
     * (D11). [destination] is the stack it is on. Its Nearby keeps the
     * contact exchange open.
     */
    @Serializable
    data class AddPeer(val destination: Destination) : UmshKey, MeetsNearby

    /**
     * A contact exchange under way (`nearby-exchange.svg` 2–5), pushed over
     * the Add peer on [destination]'s stack; the exchange stays open under
     * it. The exchange does not survive process death, so a restored one
     * closes itself ([ShellState.followMeet]).
     */
    @Serializable
    data class Exchange(val destination: Destination) : UmshKey, MeetsNearby

    /**
     * The QR scanner (`qr-scanner.svg`): full screen above the shell, from
     * Scan on [destination]'s root, or the scan button in that stack's Add
     * peer field or Join channel's field ([target]). A recognized code goes back to where the scan
     * began ([ShellState.deliverScan]).
     */
    @Serializable
    data class Scanner(val target: ScanTarget, val destination: Destination) : UmshKey

    /** Settings › Notifications. */
    @Serializable
    data object Notifications : UmshKey

    /** Settings › Channels (`channels.svg` 1–3): the channels this phone joined. */
    @Serializable
    data object Channels : UmshKey

    /**
     * A channel's page (`channels.svg` 10–13), by its ID: above Channels in
     * Settings, or above Conversation info on Conversations ([destination],
     * the stack it is on, which picks its pane). Closed once this phone no
     * longer has it joined ([ShellState.closeChannelPagesNotIn]).
     */
    @Serializable
    data class ChannelPage(val id: String, val destination: Destination = Destination.Settings) : UmshKey

    /**
     * Join channel (`channels.svg` 5–9): a full-screen dialog above the
     * shell, from Channels, a channel link ([input] filled in and looked
     * up), or New channel chat ([forChat]: the join opens the channel's
     * conversation, as joining from Settings does not). An [input] holding
     * a private key is sealed (`ChannelKeyText`): this key is saved state.
     * [opening] tells one link's opening from the next, so the same link
     * opened again starts Join channel over rather than keeping the page
     * it replaces; 0 for every other opening.
     */
    @Serializable
    data class ChannelJoin(val input: String? = null, val forChat: Boolean = false, val opening: Long = 0) : UmshKey

    /** New private channel (`channels.svg` 4): a full-screen dialog above the shell, from Channels. */
    @Serializable
    data object ChannelCreate : UmshKey

    /** The app-level stack's root: the shell itself, with its destinations. */
    @Serializable
    data object Shell : UmshKey
}

/**
 * A page about one stored peer: closed, with whatever is above it, once
 * [peerAddress] is no longer stored ([ShellState.closePeerPagesNotIn]).
 * Null for a page that names no peer.
 */
interface PeerPageKey {
    val peerAddress: String?
}

/**
 * A page that keeps Add peer's contact exchange open while it is the
 * selected destination's top page ([MeetPresence]).
 */
interface MeetsNearby

/** Where a scan began, and so where its code is previewed. */
@Serializable
enum class ScanTarget {
    /** Scan in a root's top app bar: the preview opens as a sheet over the root (`qr-scanner.svg` 3). */
    Root,

    /** The Add peer field's scan button: the field is filled and previewed. */
    AddPeerField,

    /** Join channel's field: the field is filled and looked up (`channels.svg` 5). */
    JoinChannelField,
}

/** A code the scanner recognized, waiting for the page the scan began on. */
data class PendingScan(val target: ScanTarget, val destination: Destination, val text: String)
