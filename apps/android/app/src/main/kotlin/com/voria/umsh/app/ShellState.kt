package com.voria.umsh.app

import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.navigation3.runtime.NavBackStack
import androidx.navigation3.runtime.NavKey
import androidx.navigation3.runtime.rememberNavBackStack
import com.voria.umsh.R

/** The four destinations, in the bar's order (`navigation.svg`). */
enum class Destination(
    val root: UmshKey,
    @StringRes val label: Int,
    /** Outlined, when not selected. */
    @DrawableRes val icon: Int,
    /** Filled, when selected. */
    @DrawableRes val selectedIcon: Int,
    val tag: String,
) {
    Conversations(UmshKey.ConversationsRoot, R.string.nav_conversations, R.drawable.ic_forum_outlined, R.drawable.ic_forum, Tags.NAV_CONVERSATIONS),
    Peers(UmshKey.PeersRoot, R.string.nav_peers, R.drawable.ic_hub_outlined, R.drawable.ic_hub, Tags.NAV_PEERS),
    Map(UmshKey.MapRoot, R.string.nav_map, R.drawable.ic_map_outlined, R.drawable.ic_map, Tags.NAV_MAP),
    Settings(UmshKey.SettingsRoot, R.string.nav_settings, R.drawable.ic_settings_outlined, R.drawable.ic_settings, Tags.NAV_SETTINGS),
}

/**
 * Which destination is shown, and one back stack per destination. The
 * stacks survive destination switches, configuration changes and process
 * death; a mode switch makes a new shell and so new stacks.
 */
@Stable
class ShellState(
    selected: MutableState<Destination>,
    val stacks: Map<Destination, NavBackStack<NavKey>>,
    /**
     * The app-level stack: the shell at its root, and above it the pages
     * that belong to no destination (Radio Detail from the radio control).
     * Opening one never changes the selected destination.
     */
    val appStack: NavBackStack<NavKey>,
) {
    var selected by selected
        private set

    private val reselects = mutableStateMapOf<Destination, Int>()

    val currentStack: NavBackStack<NavKey> get() = stacks.getValue(selected)

    /** The page on top of the shown destination. */
    val top: UmshKey? get() = currentStack.lastOrNull() as? UmshKey

    /** The page on screen: an app-level page over the shell, else [top]. */
    val shownTop: NavKey? get() = if (appStack.size > 1) appStack.last() else top

    /**
     * Bumped each time [destination] is reselected while its root is already
     * shown; the root scrolls to the top once per bump ([ScrollToTopOnReselect]).
     */
    fun reselectCount(destination: Destination): Int = reselects[destination] ?: 0

    /**
     * Tapping a destination: switches to it; when it is shown, pops it to its
     * root, or, already at the root, scrolls the root up.
     */
    fun select(destination: Destination) {
        if (destination != selected) {
            selected = destination
            return
        }
        if (stacks.getValue(destination).size > 1) {
            popToRoot(destination)
        } else {
            reselects[destination] = reselectCount(destination) + 1
        }
    }

    /**
     * Whether [key] is a page shown on [destination] right now: the top of
     * the selected destination, or its root beside it when [twoPane]. A page
     * drawn only behind a back preview is not, so it neither marks read nor
     * takes focus (and the keyboard with it).
     */
    fun isShown(destination: Destination, key: UmshKey, twoPane: Boolean): Boolean {
        if (destination != selected) return false
        val stack = stacks.getValue(destination)
        return stack.lastOrNull() == key || (twoPane && stack.firstOrNull() == key)
    }

    /**
     * Radio Detail above the shell, as the radio control opens it; once,
     * however often it is asked, and not over Settings' Companion radio,
     * which is already the page.
     */
    fun openRadioDetail() {
        if (appStack.lastOrNull() == UmshKey.RadioDetail) return
        if (selected == Destination.Settings && stacks.getValue(Destination.Settings).lastOrNull() == UmshKey.RadioDetail) return
        appStack.add(UmshKey.RadioDetail)
    }

    /**
     * Choose a radio above the shell (and above Radio Detail, when that
     * opened it); once, however often it is asked.
     */
    fun openRadioPicker() {
        if (appStack.lastOrNull() == UmshKey.RadioPicker) return
        appStack.add(UmshKey.RadioPicker)
    }

    /** Choose a radio is done: closed, back to whatever opened it. */
    fun closeRadioPicker() {
        appStack.removeAll { it == UmshKey.RadioPicker }
    }

    /**
     * A notification's or shortcut's tap (product-structure, "Notification
     * taps"): Conversations selected, with that conversation open above its
     * list, and no app-level page over it.
     */
    fun openConversation(address: String) {
        while (appStack.size > 1) appStack.removeAt(appStack.lastIndex)
        selected = Destination.Conversations
        openDetail(Destination.Conversations, UmshKey.Thread(address))
    }

    /**
     * A peer's page pushed on [destination]'s stack, above whatever it shows
     * (a thread, Message details, Radio Detail in Settings); above the shell
     * when [destination] is null (from Radio Detail there). Once: when the
     * page is already on that stack, the stack goes back to it.
     */
    fun openPeer(address: String, destination: Destination?) {
        val key = UmshKey.PeerPage(address, destination)
        pushOnce(destination?.let(stacks::getValue) ?: appStack, key)
    }

    /** Route from [page]: pushed on the stack the page is on (D12), above the shell with it. */
    fun openRoute(page: UmshKey.PeerPage) {
        val key = UmshKey.Route(page.address, page.destination)
        pushOnce(page.destination?.let(stacks::getValue) ?: appStack, key)
    }

    /** The manual path editor for [address]: above the shell, over whatever stack the Route page is on. */
    fun openManualPath(address: String) = pushOnce(appStack, UmshKey.ManualPath(address))

    /** Neighbors from [page]: pushed on the stack the page is on (D12), above the shell with it. */
    fun openNeighbors(page: UmshKey.PeerPage) {
        val key = UmshKey.Neighbors(page.address, page.destination)
        pushOnce(page.destination?.let(stacks::getValue) ?: appStack, key)
    }

    /** Ask near this node on [route]: Discover aimed at its peer, on the stack the Route page is on (D12). */
    fun openDiscover(route: UmshKey.Route) {
        val key = UmshKey.Discover(route.address, route.destination)
        pushOnce(route.destination?.let(stacks::getValue) ?: appStack, key)
    }

    /** The Peers list's Discover peers: as the list's one detail page, asking nearby. */
    fun openDiscoverFromList() = openDetail(Destination.Peers, UmshKey.Discover(null, Destination.Peers))

    /** A Peers row: the node's page as the Peers list's one detail page. */
    fun openPeerFromList(address: String) = openDetail(Destination.Peers, UmshKey.PeerPage(address, Destination.Peers))

    /** Add peer on [destination]'s stack, as its list's one detail page (D11 for Conversations). */
    fun openAddPeer(destination: Destination) = openDetail(destination, UmshKey.AddPeer(destination))

    /**
     * Add peer is done with a node: [address]'s page takes its place on the
     * same stack (`add-peer.svg` 3), so Back from the page returns to the
     * list, not to a preview already used.
     */
    fun leaveAddPeerForPage(addPeer: UmshKey.AddPeer, address: String) {
        val stack = stacks.getValue(addPeer.destination)
        closeFrom(stack, addPeer)
        pushOnce(stack, UmshKey.PeerPage(address, addPeer.destination))
    }

    /** Add peer is done with a conversation: Add peer closes, and the conversation opens on Conversations. */
    fun leaveAddPeerForConversation(addPeer: UmshKey.AddPeer, conversation: String) {
        closeFrom(stacks.getValue(addPeer.destination), addPeer)
        openConversation(conversation)
    }

    /**
     * This phone's own identity was entered in Add peer: Add peer closes and
     * Settings opens at Your identity, as a link to this phone does
     * (product-structure, "Deep links" 2). Beside the Settings list, Your
     * identity is its root's own detail, so the root is enough.
     */
    fun leaveAddPeerForIdentity(addPeer: UmshKey.AddPeer, twoPane: Boolean) {
        closeFrom(stacks.getValue(addPeer.destination), addPeer)
        while (appStack.size > 1) appStack.removeAt(appStack.lastIndex)
        selected = Destination.Settings
        if (twoPane) showRoot(Destination.Settings) else openDetail(Destination.Settings, UmshKey.YourIdentity)
    }

    /**
     * The shown destination's pages follow Add peer's exchange
     * (`nearby-exchange.svg`): an attempt under way pushes the exchange page
     * over Add peer; one that is over (left, declined, closed, or never
     * there, as after process death) closes it; contacts crossed replace
     * Add peer and the exchange with the new peer's page (board 6), so Back
     * leads to the list, not to the code. The exchange is open only while
     * Add peer or the exchange is the shown top page, so other stacks never
     * need following until they are shown, nor this one while an app-level
     * page is over the shell.
     */
    fun followMeet(step: MeetStep) {
        if (appStack.size > 1) return
        val stack = currentStack
        when (val top = stack.lastOrNull()) {
            is UmshKey.AddPeer -> when (step) {
                MeetStep.UnderWay -> pushOnce(stack, UmshKey.Exchange(top.destination))
                is MeetStep.Exchanged -> leaveAddPeerForPage(top, step.peerAddress)
                MeetStep.None -> Unit
            }
            is UmshKey.Exchange -> when (step) {
                MeetStep.UnderWay -> Unit
                is MeetStep.Exchanged -> leaveAddPeerForPage(UmshKey.AddPeer(top.destination), step.peerAddress)
                MeetStep.None -> stack.removeAt(stack.lastIndex)
            }
            else -> Unit
        }
    }

    /** Close [key] and whatever is above it in [stack]; nothing when it is not there or is the root. */
    private fun closeFrom(stack: NavBackStack<NavKey>, key: UmshKey) {
        val index = stack.indexOf(key)
        if (index < 1) return
        while (stack.size > index) stack.removeAt(stack.lastIndex)
    }

    /**
     * A notification about a node that sends no text (product-structure,
     * "Notification taps" 3): Peers selected, with its page open above the
     * list, and no app-level page over it.
     */
    fun showPeer(address: String) {
        while (appStack.size > 1) appStack.removeAt(appStack.lastIndex)
        selected = Destination.Peers
        openPeerFromList(address)
    }

    /**
     * Message on [page]: back to the thread beneath it when that is this
     * conversation (iOS `returnToConversation`), else [conversation] opened
     * on Conversations.
     */
    fun openConversationFrom(page: UmshKey.PeerPage, conversation: String) {
        val stack = page.destination?.let(stacks::getValue) ?: appStack
        val index = stack.lastIndexOf(page)
        if (page.destination == Destination.Conversations && index >= 1 && stack[index - 1] == UmshKey.Thread(conversation)) {
            while (stack.size > index) stack.removeAt(stack.lastIndex)
            selected = Destination.Conversations
            return
        }
        openConversation(conversation)
    }

    /** Close an app-level page: back to the shell as it was left. False with none open. */
    fun popAppPage(): Boolean {
        if (appStack.size <= 1) return false
        appStack.removeAt(appStack.lastIndex)
        return true
    }

    /**
     * Radio Detail is gone (its radio forgotten or erased): closed wherever
     * it is open, above the shell and in the Settings stack.
     */
    fun closeRadioDetail() {
        appStack.removeAll { it == UmshKey.RadioDetail }
        stacks.getValue(Destination.Settings).let { stack ->
            val index = stack.indexOf(UmshKey.RadioDetail)
            if (index >= 1) while (stack.size > index) stack.removeAt(stack.lastIndex)
        }
    }

    /** Back on a page or a root: pops the stack, or at the root of Peers, Map or Settings selects Conversations. */
    fun back(): Boolean = pop() || backAtRoot()

    /** Push [key] on the shown destination's stack. */
    fun push(key: UmshKey) {
        currentStack.add(key)
    }

    /** Push [key] on [destination]'s stack, once: when it is already there, back to it. */
    fun push(destination: Destination, key: UmshKey) = pushOnce(stacks.getValue(destination), key)

    /**
     * [key] on top of [stack], never twice in it: a key names its page's
     * saved state and ViewModels, so two copies would share them. A path
     * that loops back (a hop's page whose route runs through this node)
     * returns to the page already open.
     */
    private fun pushOnce(stack: NavBackStack<NavKey>, key: UmshKey) {
        val index = stack.indexOf(key)
        if (index < 0) {
            stack.add(key)
        } else {
            while (stack.size > index + 1) stack.removeAt(stack.lastIndex)
        }
    }

    /** Close [thread] and whatever is above it, wherever it is in its stack. */
    fun closeThread(thread: UmshKey.Thread) {
        val stack = stacks.getValue(Destination.Conversations)
        val index = stack.indexOf(thread)
        if (index < 1) return
        while (stack.size > index) stack.removeAt(stack.lastIndex)
    }

    /**
     * Open [key] as the destination's one detail page: what a list row
     * does. Beside a list it replaces the page shown, rather than stacking.
     */
    fun openDetail(key: UmshKey) = openDetail(selected, key)

    /** [openDetail] on [destination]'s stack. */
    fun openDetail(destination: Destination, key: UmshKey) {
        popToRoot(destination)
        stacks.getValue(destination).add(key)
    }

    /**
     * Close every thread whose conversation is not among [conversations],
     * with any page above it: what it showed is gone, removed here or
     * anywhere else.
     */
    fun closeThreadsNotIn(conversations: Set<String>) {
        val stack = stacks.getValue(Destination.Conversations)
        val index = stack.indexOfFirst { it is UmshKey.Thread && it.address !in conversations }
        if (index < 1) return
        while (stack.size > index) stack.removeAt(stack.lastIndex)
    }

    /**
     * Close every page about a peer not among [peers] ([PeerPageKey]), with
     * whatever is above it, on every destination's stack and above the
     * shell: the peer was removed here or anywhere else, or erased.
     */
    fun closePeerPagesNotIn(peers: Set<String>) {
        val gone = { key: NavKey -> key is PeerPageKey && key.peerAddress?.let { it !in peers } == true }
        (stacks.values + listOf(appStack)).forEach { stack ->
            val index = stack.indexOfFirst(gone)
            if (index >= 1) while (stack.size > index) stack.removeAt(stack.lastIndex)
        }
    }

    /** [destination] at its root: what its list shows, with its detail placeholder beside it. */
    fun showRoot(destination: Destination) = popToRoot(destination)

    /** Back on a pushed page. False at a root. */
    fun pop(): Boolean {
        val stack = currentStack
        if (stack.size <= 1) return false
        stack.removeAt(stack.lastIndex)
        return true
    }

    /** Back at the root of Peers, Map or Settings selects Conversations; false at Conversations. */
    fun backAtRoot(): Boolean {
        if (selected == Destination.Conversations) return false
        selected = Destination.Conversations
        return true
    }

    private fun popToRoot(destination: Destination) {
        val stack = stacks.getValue(destination)
        while (stack.size > 1) stack.removeAt(stack.lastIndex)
    }
}

@Composable
fun rememberShellState(): ShellState {
    val selected = rememberSaveable { mutableStateOf(Destination.Conversations) }
    val stacks = Destination.entries.associateWith { rememberNavBackStack(it.root) }
    val appStack = rememberNavBackStack(UmshKey.Shell)
    // The stacks are the same instances on every pass.
    return remember { ShellState(selected, stacks, appStack) }
}

/**
 * A root's half of reselect: scroll [list] to the top once for each bump of
 * [reselects]. The last bump handled is saved with the root, so the root
 * coming back (Back from a pushed page, a destination switch, a rotation)
 * does not scroll it again.
 */
@Composable
fun ScrollToTopOnReselect(reselects: Int, list: LazyListState) {
    var handled by rememberSaveable { mutableIntStateOf(reselects) }
    LaunchedEffect(reselects) {
        if (reselects > handled) {
            handled = reselects
            list.animateScrollToItem(0)
        }
    }
}
