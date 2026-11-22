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
) {
    var selected by selected
        private set

    private val reselects = mutableStateMapOf<Destination, Int>()

    val currentStack: NavBackStack<NavKey> get() = stacks.getValue(selected)

    /** The page on top of the shown destination. */
    val top: UmshKey? get() = currentStack.lastOrNull() as? UmshKey

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

    /** Back on a page or a root: pops the stack, or at the root of Peers, Map or Settings selects Conversations. */
    fun back(): Boolean = pop() || backAtRoot()

    /** Push [key] on the shown destination's stack. */
    fun push(key: UmshKey) {
        currentStack.add(key)
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
    // The stacks are the same instances on every pass.
    return remember { ShellState(selected, stacks) }
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
