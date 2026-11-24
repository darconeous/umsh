package com.voria.umsh.features

import android.Manifest
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.compose.material3.adaptive.WindowAdaptiveInfo
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assertHasNoClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.longClick
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.test.performTouchInput
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.Destination
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.ShellState
import com.voria.umsh.app.Tags
import com.voria.umsh.app.TestWindows
import com.voria.umsh.app.UmshKey
import com.voria.umsh.app.UmshShell
import com.voria.umsh.app.rememberShellState
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.designsystem.LocalWindowOverride
import com.voria.umsh.designsystem.RepeaterHintRow
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.conversations.TranscriptWindow
import com.voria.umsh.features.peers.PeerArrangement
import com.voria.umsh.features.peers.PeerFilter
import com.voria.umsh.features.peers.PeerSections
import com.voria.umsh.features.peers.PeerSort
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.services.format.AndroidCollation
import java.util.Locale
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/**
 * The Peers list (`peers-list.svg`) and the peer page (`peer-page.svg`)
 * over the staging core, and the page's ways in: a Peers row, a direct
 * chat's title, Radio Detail's identity row and Message details.
 */
class PeersTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val names: DisplayNames
        get() = DisplayNames(
            context.getString(R.string.unnamed_node),
            context.getString(R.string.companion_radio),
            context.getString(R.string.channel_private),
            context.getString(R.string.channel_public),
            context.getString(R.string.channel_emergency),
        )

    private fun arrangement(sort: PeerSort = PeerSort.Alphabetical, filter: PeerFilter? = null) =
        PeerArrangement(sort, filter, names, AndroidCollation(Locale.getDefault()))

    private fun runtime(): AppRuntime = runBlocking {
        fresh.host.preferences.setFallbackScheme(true)
        fresh.host.ensureRuntime(staging = true)
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        val runtime = ready.runtime
        withTimeout(TIMEOUT) { runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        withTimeout(TIMEOUT) { runtime.radio.first { it?.carriesThisPhone == true } }
        // The staged air's nodes, the unsaved ones among them, have been heard.
        withTimeout(TIMEOUT) {
            runtime.appState.first { state ->
                state != null && state.directConversations.isNotEmpty() && state.peers.any { !it.isSaved && !it.isCompanionRadio }
            }
        }
        runtime
    }

    private fun show(runtime: AppRuntime, window: WindowAdaptiveInfo = TestWindows.Phone) {
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides window,
                ) {
                    val state = rememberShellState()
                    shell = state
                    UmshShell(state)
                }
            }
        }
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed()
    }

    private fun openPeers() {
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitForTag(Tags.PEERS_LIST)
    }

    private fun waitFor(condition: () -> Boolean) = compose.waitUntil(TIMEOUT, condition)

    private fun present(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String) = waitFor { present(tag) }

    private fun waitGone(tag: String) = waitFor { !present(tag) }

    private fun peer(runtime: AppRuntime, name: String): PeerSummary =
        runtime.appState.value!!.peers.first { it.advertisedName == name }

    private fun row(address: String, list: String = Tags.PEERS_LIST): SemanticsNodeInteraction {
        compose.onNodeWithTag(list).performScrollToNode(hasTestTag(Tags.peerRow(address)))
        return compose.onNodeWithTag(Tags.peerRow(address))
    }

    /** The peers shown, top to bottom, by address. */
    private fun shownInOrder(): List<String> = compose
        .onAllNodes(SemanticsMatcher("a peer row") { it.config.getOrNull(SemanticsProperties.TestTag)?.startsWith("peer_row/") == true })
        .fetchSemanticsNodes()
        .sortedBy { it.boundsInRoot.top }
        .map { it.config[SemanticsProperties.TestTag].removePrefix("peer_row/") }

    private fun expected(runtime: AppRuntime, sort: PeerSort = PeerSort.Alphabetical, filter: PeerFilter? = null): List<String> {
        val sections = PeerSections.of(runtime.appState.value!!, arrangement(sort, filter))
        return (sections.favorites + sections.saved + sections.radios).map { it.address }
    }

    /** The rows on screen are a prefix-free run of [all]'s order. */
    private fun assertShownIn(all: List<String>) {
        val onScreen = shownInOrder()
        assertTrue("$onScreen", onScreen.isNotEmpty())
        assertEquals(all.filter { it in onScreen }, onScreen)
    }

    private fun longPress(address: String, list: String = Tags.PEERS_LIST) {
        row(address, list).performTouchInput { longClick() }
        waitForTag(Tags.PEER_MENU)
    }

    private fun openPage(address: String) {
        row(address).performClick()
        waitForTag(Tags.PEER_PAGE)
    }

    /** Whether Clear all messages is enabled; null while it is not on the page. */
    private fun clearEnabled(): Boolean? = compose.onAllNodesWithTag(Tags.PEER_CLEAR_MESSAGES).fetchSemanticsNodes().firstOrNull()
        ?.let { !it.config.contains(SemanticsProperties.Disabled) }

    private fun pageControl(tag: String): SemanticsNodeInteraction =
        compose.onNodeWithTag(tag).performScrollTo()

    // --- The list ---------------------------------------------------------

    /** Board 1: Favorites, Saved, the radio; rows open their page; nodes only heard are left out. */
    @Test
    fun sectionsListSavedNodesAndRowsOpenTheirPage() {
        val runtime = runtime()
        show(runtime)
        openPeers()
        compose.onNodeWithTag(Tags.PEERS_FAVORITES).assertIsDisplayed()
        assertShownIn(expected(runtime))
        for (heard in runtime.appState.value!!.peers.filter { !it.isSaved && !it.isCompanionRadio }) {
            compose.onNodeWithTag(Tags.peerRow(heard.address)).assertDoesNotExist()
        }
        val tallac = peer(runtime, "Tallac Ridge")
        openPage(tallac.address)
        assertEquals(UmshKey.PeerPage(tallac.address, Destination.Peers), shell.stacks.getValue(Destination.Peers).last())
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).performClick()
        waitForTag(Tags.PEERS_LIST)
        assertEquals(listOf(UmshKey.PeersRoot), shell.stacks.getValue(Destination.Peers).toList())
    }

    /**
     * The rows on screen follow [sort] and [filter], re-read as the staged
     * nodes keep being heard (Recently heard moves with them), and none
     * the filter leaves out shows.
     */
    private fun waitForOrder(runtime: AppRuntime, sort: PeerSort, filter: PeerFilter? = null) = waitFor {
        val shown = shownInOrder()
        val all = expected(runtime, sort, filter)
        shown.isNotEmpty() && shown.all { it in all } && all.filter { it in shown } == shown
    }

    /** Board 2: the sort menu reorders; the filters pick roles, one at a time, the radio always shown. */
    @Test
    fun sortAndFilters() {
        val runtime = runtime()
        show(runtime)
        openPeers()
        compose.onNodeWithTag(Tags.PEERS_SORT).performClick()
        compose.onNodeWithTag(Tags.peersSortOption(PeerSort.RecentlyHeard.name)).performClick()
        waitFor { runBlocking { fresh.host.preferences.peersSort.first() } == PeerSort.RecentlyHeard.name }
        waitForOrder(runtime, PeerSort.RecentlyHeard)

        compose.onNodeWithTag(Tags.peersFilter(PeerFilter.Repeaters.name)).performScrollTo().performClick()
        waitForOrder(runtime, PeerSort.RecentlyHeard, PeerFilter.Repeaters)
        val repeaters = expected(runtime, PeerSort.RecentlyHeard, PeerFilter.Repeaters)
        val radio = runtime.appState.value!!.peers.firstOrNull { it.isCompanionRadio }
        if (radio != null) assertTrue(radio.address in repeaters)
        assertTrue(runtime.appState.value!!.peers.filter { it.address in repeaters && !it.isCompanionRadio }.all { it.likelyRepeater })

        // Single choice: People replaces Repeaters.
        compose.onNodeWithTag(Tags.peersFilter(PeerFilter.People.name)).performScrollTo().performClick()
        waitForOrder(runtime, PeerSort.RecentlyHeard, PeerFilter.People)
        // Tapped again, all.
        compose.onNodeWithTag(Tags.peersFilter(PeerFilter.People.name)).performScrollTo().performClick()
        waitForOrder(runtime, PeerSort.RecentlyHeard)
        assertTrue(shownInOrder().any { it !in expected(runtime, PeerSort.RecentlyHeard, PeerFilter.People) })
    }

    /** Board 3: Saved, then Discovered with its add button; one line when nothing matches. */
    @Test
    fun searchGroupsSavedAndDiscovered() {
        val runtime = runtime()
        show(runtime)
        openPeers()
        val glen = peer(runtime, "Glen Alpine Relay")
        val tallac = peer(runtime, "Tallac Ridge")
        compose.onNodeWithTag(Tags.PEERS_SEARCH).performClick()
        compose.onNodeWithTag(Tags.PEERS_SEARCH_FIELD).performTextInput("glen")
        waitForTag(Tags.peerRow(glen.address))
        compose.onNodeWithTag(Tags.PEERS_SEARCH_DISCOVERED).assertIsDisplayed()
        compose.onNodeWithTag(Tags.peerSave(glen.address)).assertIsDisplayed()

        compose.onNodeWithTag(Tags.PEERS_SEARCH_FIELD).performTextReplacement("tallac")
        waitForTag(Tags.peerRow(tallac.address))
        compose.onNodeWithTag(Tags.PEERS_SEARCH_SAVED).assertIsDisplayed()
        compose.onNodeWithTag(Tags.PEERS_SEARCH_DISCOVERED).assertDoesNotExist()

        // The add button saves; the node moves to Saved.
        compose.onNodeWithTag(Tags.PEERS_SEARCH_FIELD).performTextReplacement("glen")
        waitForTag(Tags.peerSave(glen.address))
        compose.onNodeWithTag(Tags.peerSave(glen.address)).performClick()
        waitFor { peer(runtime, "Glen Alpine Relay").isSaved }
        waitForTag(Tags.PEERS_SEARCH_SAVED)
        waitGone(Tags.PEERS_SEARCH_DISCOVERED)

        compose.onNodeWithTag(Tags.PEERS_SEARCH_FIELD).performTextReplacement("zqzqzq")
        waitForTag(Tags.PEERS_SEARCH_NOTHING)
        compose.onNodeWithTag(Tags.PEERS_SEARCH_CLOSE).performClick()
        waitForTag(Tags.PEERS_LIST)
    }

    /** Board 4: a saved row offers Favorite and Remove, a node only heard Save and Remove, the radio nothing. */
    @Test
    fun longPressItemsFollowTheRowKind() {
        val runtime = runtime()
        show(runtime)
        openPeers()
        val maya = peer(runtime, "Maya Ortiz")
        assertTrue(maya.isFavorite)
        longPress(maya.address)
        compose.onNodeWithTag(Tags.PEER_MENU_FAVORITE).assertIsDisplayed()
        assertTrue(hasText(Tags.PEER_MENU_FAVORITE, R.string.peer_unfavorite))
        compose.onNodeWithTag(Tags.PEER_MENU_SAVE).assertDoesNotExist()
        compose.onNodeWithTag(Tags.PEER_MENU_REMOVE).assertIsDisplayed()
        // Unfavorite moves the row out of Favorites.
        compose.onNodeWithTag(Tags.PEER_MENU_FAVORITE).performClick()
        waitFor { !peer(runtime, "Maya Ortiz").isFavorite }
        waitGone(Tags.PEER_MENU)

        val tallac = peer(runtime, "Tallac Ridge")
        longPress(tallac.address)
        assertTrue(hasText(Tags.PEER_MENU_FAVORITE, R.string.peer_favorite))
        compose.onNodeWithTag(Tags.PEER_MENU_FAVORITE).performClick()
        waitFor { peer(runtime, "Tallac Ridge").isFavorite }
        waitGone(Tags.PEER_MENU)

        val radio = runtime.appState.value!!.peers.firstOrNull { it.isCompanionRadio }
        if (radio != null) {
            val node = row(radio.address).fetchSemanticsNode()
            assertNull(node.config.getOrNull(SemanticsActions.OnLongClick))
        }
        // Long press is offered to TalkBack with its label.
        val saved = row(tallac.address).fetchSemanticsNode()
        assertEquals(context.getString(R.string.peer_actions), saved.config[SemanticsActions.OnLongClick].label)

        val glen = peer(runtime, "Glen Alpine Relay")
        compose.onNodeWithTag(Tags.PEERS_SEARCH).performClick()
        compose.onNodeWithTag(Tags.PEERS_SEARCH_FIELD).performTextInput("glen")
        waitForTag(Tags.peerRow(glen.address))
        longPress(glen.address, Tags.PEERS_SEARCH_RESULTS)
        compose.onNodeWithTag(Tags.PEER_MENU_SAVE).assertIsDisplayed()
        compose.onNodeWithTag(Tags.PEER_MENU_FAVORITE).assertDoesNotExist()
        compose.onNodeWithTag(Tags.PEER_MENU_REMOVE).assertIsDisplayed()
        compose.onNodeWithTag(Tags.PEER_MENU_SAVE).performClick()
        waitFor { peer(runtime, "Glen Alpine Relay").isSaved }
    }

    /** The text of the node tagged [tag] and everything under it. */
    private fun nodeText(tag: String): List<String> =
        compose.onAllNodes(hasTestTag(tag) or hasAnyAncestor(hasTestTag(tag)), useUnmergedTree = true).fetchSemanticsNodes().flatMap { node ->
            node.config.getOrNull(SemanticsProperties.Text).orEmpty().map { it.text }
        }

    private fun hasText(tag: String, text: Int): Boolean = context.getString(text) in nodeText(tag)

    /** The removal dialog's buttons (§2.5): [remove] Remove peer offered; [deleteText] Delete's label. */
    private fun assertRemovalDialog(remove: Boolean, deleteText: Int) {
        waitForTag(Tags.REMOVE_PEER_DIALOG)
        if (remove) compose.onNodeWithTag(Tags.REMOVE_PEER_REMOVE).assertIsDisplayed() else compose.onNodeWithTag(Tags.REMOVE_PEER_REMOVE).assertDoesNotExist()
        assertTrue(hasText(Tags.REMOVE_PEER_DELETE, deleteText))
    }

    /** Board 5 on the list: saved or not, with a conversation or without. */
    @Test
    fun theListsRemovalDialogFollowsSavedAndConversation() {
        val runtime = runtime()
        show(runtime)
        openPeers()
        // Saved, with a conversation: Remove peer, or delete it with the conversation.
        val maya = peer(runtime, "Maya Ortiz")
        longPress(maya.address)
        compose.onNodeWithTag(Tags.PEER_MENU_REMOVE).performClick()
        assertRemovalDialog(remove = true, deleteText = R.string.delete_peer_and_conversation)
        compose.onNodeWithTag(Tags.CONFIRM_CANCEL).performClick()
        waitGone(Tags.REMOVE_PEER_DIALOG)
        assertTrue(peer(runtime, "Maya Ortiz").isSaved)

        // Saved, no conversation: Delete peer alone.
        val tallac = peer(runtime, "Tallac Ridge")
        longPress(tallac.address)
        compose.onNodeWithTag(Tags.PEER_MENU_REMOVE).performClick()
        assertRemovalDialog(remove = false, deleteText = R.string.delete_peer)
        compose.onNodeWithTag(Tags.REMOVE_PEER_DELETE).performClick()
        waitFor { runtime.appState.value!!.peers.none { it.address == tallac.address } }
        waitGone(Tags.peerRow(tallac.address))

        // Remove peer keeps the node and its conversation, off the list.
        longPress(maya.address)
        compose.onNodeWithTag(Tags.PEER_MENU_REMOVE).performClick()
        assertRemovalDialog(remove = true, deleteText = R.string.delete_peer_and_conversation)
        compose.onNodeWithTag(Tags.REMOVE_PEER_REMOVE).performClick()
        waitFor { !peer(runtime, "Maya Ortiz").isSaved }
        assertTrue(runtime.appState.value!!.directConversations.any { it.peer.address == maya.address })
        waitGone(Tags.peerRow(maya.address))

        // Not saved, with a conversation: only Delete peer and conversation.
        compose.onNodeWithTag(Tags.PEERS_SEARCH).performClick()
        compose.onNodeWithTag(Tags.PEERS_SEARCH_FIELD).performTextInput("maya")
        waitForTag(Tags.peerRow(maya.address))
        longPress(maya.address, Tags.PEERS_SEARCH_RESULTS)
        compose.onNodeWithTag(Tags.PEER_MENU_REMOVE).performClick()
        assertRemovalDialog(remove = false, deleteText = R.string.delete_peer_and_conversation)
        compose.onNodeWithTag(Tags.CONFIRM_CANCEL).performClick()
        waitGone(Tags.REMOVE_PEER_DIALOG)

        // Not saved, no conversation: Delete peer.
        val glen = peer(runtime, "Glen Alpine Relay")
        compose.onNodeWithTag(Tags.PEERS_SEARCH_FIELD).performTextReplacement("glen")
        waitForTag(Tags.peerRow(glen.address))
        longPress(glen.address, Tags.PEERS_SEARCH_RESULTS)
        compose.onNodeWithTag(Tags.PEER_MENU_REMOVE).performClick()
        assertRemovalDialog(remove = false, deleteText = R.string.delete_peer)
        compose.onNodeWithTag(Tags.REMOVE_PEER_DELETE).performClick()
        waitFor { runtime.appState.value!!.peers.none { it.address == glen.address } }
    }

    // --- The page ---------------------------------------------------------

    /** Board 5 on the page: Remove peer is offered only for a saved node; Add to Peers brings it back. */
    @Test
    fun thePageRemovesOnlySavedNodesAndAddsThemBack() {
        val runtime = runtime()
        show(runtime)
        openPeers()
        val maya = peer(runtime, "Maya Ortiz")
        openPage(maya.address)
        pageControl(Tags.PEER_REMOVE).performClick()
        assertRemovalDialog(remove = true, deleteText = R.string.delete_peer_and_conversation)
        compose.onNodeWithTag(Tags.REMOVE_PEER_REMOVE).performClick()
        waitFor { !peer(runtime, "Maya Ortiz").isSaved }
        // Still open, now as a node not saved: Add to Peers, no Remove peer, no Favorite.
        waitForTag(Tags.PEER_ADD)
        compose.onNodeWithTag(Tags.PEER_REMOVE).assertDoesNotExist()
        compose.onNodeWithTag(Tags.PEER_FAVORITE).assertDoesNotExist()
        compose.onNodeWithTag(Tags.PEER_ADD).performScrollTo().performClick()
        waitFor { peer(runtime, "Maya Ortiz").isSaved }
        waitGone(Tags.PEER_ADD)
        waitForTag(Tags.PEER_FAVORITE)
        pageControl(Tags.PEER_REMOVE).assertIsDisplayed()
    }

    /** Delete on the page deletes the node and pops its page. */
    @Test
    fun deleteOnThePagePopsIt() {
        val runtime = runtime()
        show(runtime)
        openPeers()
        val tallac = peer(runtime, "Tallac Ridge")
        openPage(tallac.address)
        pageControl(Tags.PEER_REMOVE).performClick()
        assertRemovalDialog(remove = false, deleteText = R.string.delete_peer)
        compose.onNodeWithTag(Tags.REMOVE_PEER_DELETE).performClick()
        waitFor { runtime.appState.value!!.peers.none { it.address == tallac.address } }
        waitFor { shell.stacks.getValue(Destination.Peers).toList() == listOf(UmshKey.PeersRoot) }
        waitGone(Tags.PEER_PAGE)
        compose.onNodeWithTag(Tags.PEERS_LIST).assertIsDisplayed()
    }

    /** Board 6: Rename, the advertised name under the alias, back to it; then Clear all messages. */
    @Test
    fun renameAndClearMessages() {
        val runtime = runtime()
        show(runtime)
        openPeers()
        val maya = peer(runtime, "Maya Ortiz")
        openPage(maya.address)
        compose.onNodeWithTag(Tags.PEER_NAME).performClick()
        waitForTag(Tags.RENAME_DIALOG)
        compose.onNodeWithTag(Tags.RENAME_FIELD).performTextReplacement("Maya at camp")
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        waitFor { peer(runtime, "Maya Ortiz").alias == "Maya at camp" }
        waitGone(Tags.RENAME_DIALOG)
        waitFor { nodeText(Tags.PEER_NAME).contains("Maya at camp") }
        // The alias hides the advertised name, so the subtitle carries it.
        waitFor { nodeText(Tags.PEER_SUBTITLE).any { "Maya Ortiz" in it } }

        // Saving the advertised name clears the alias.
        compose.onNodeWithTag(Tags.PEER_NAME).performClick()
        waitForTag(Tags.RENAME_DIALOG)
        compose.onNodeWithTag(Tags.RENAME_FIELD).performTextReplacement("Maya Ortiz")
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        waitFor { peer(runtime, "Maya Ortiz").alias == null }

        val count = runBlocking { runtime.messageCount(maya.address) }
        assertTrue(count > 0)
        // Counted, with messages: enabled.
        waitFor { clearEnabled() == true }
        pageControl(Tags.PEER_CLEAR_MESSAGES).performClick()
        waitForTag(Tags.CONFIRM_DIALOG)
        val confirm = context.resources.getQuantityString(R.plurals.clear_messages_confirm, count.toInt(), count.toInt())
        assertTrue(nodeText(Tags.CONFIRM_ACTION).toString(), confirm in nodeText(Tags.CONFIRM_ACTION))
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        waitFor { runBlocking { runtime.messageCount(maya.address) } == 0L }
        // Nothing left to clear: the row stays, dimmed and not clickable, as on Conversation info.
        waitFor { clearEnabled() == false }
        pageControl(Tags.PEER_CLEAR_MESSAGES).assertIsNotEnabled().performClick()
        compose.waitForIdle()
        compose.onNodeWithTag(Tags.CONFIRM_DIALOG).assertDoesNotExist()
        // The conversation stays.
        assertTrue(runtime.appState.value!!.directConversations.any { it.peer.address == maya.address })
    }

    /** The confirmation closes by itself once the messages are cleared elsewhere: nothing is left to ask about. */
    @Test
    fun clearingElsewhereClosesTheAsk() {
        val runtime = runtime()
        show(runtime)
        openPeers()
        val maya = peer(runtime, "Maya Ortiz")
        openPage(maya.address)
        waitFor { clearEnabled() == true }
        pageControl(Tags.PEER_CLEAR_MESSAGES).performClick()
        waitForTag(Tags.CONFIRM_DIALOG)
        runBlocking { runtime.clearMessages(maya.address).await() }
        waitGone(Tags.CONFIRM_DIALOG)
        waitFor { clearEnabled() == false }
    }

    /** Without a conversation there is nothing to clear: no Clear all messages row at all. */
    @Test
    fun noConversationNoClearRow() {
        val runtime = runtime()
        show(runtime)
        openPeers()
        val tallac = peer(runtime, "Tallac Ridge")
        assertTrue(runtime.appState.value!!.directConversations.none { it.peer.address == tallac.address })
        openPage(tallac.address)
        pageControl(Tags.PEER_REMOVE)
        compose.onNodeWithTag(Tags.PEER_CLEAR_MESSAGES).assertDoesNotExist()
    }

    /**
     * Next time heard arms in the core, and disarms; with notifications
     * allowed nothing is asked. The ask itself, with them refused, is
     * `NotificationAskTest`'s.
     */
    @Test
    fun nextTimeHeardArmsAndDisarms() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            InstrumentationRegistry.getInstrumentation().uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
        val runtime = runtime()
        show(runtime)
        openPeers()
        val tallac = peer(runtime, "Tallac Ridge")
        assertFalse(tallac.notifyWhenHeard)
        openPage(tallac.address)
        pageControl(Tags.PEER_NOTIFY_HEARD).performClick()
        waitFor { peer(runtime, "Tallac Ridge").notifyWhenHeard }
        compose.onNodeWithTag(Tags.PEER_NOTIFY_HEARD).performClick()
        waitFor { !peer(runtime, "Tallac Ridge").notifyWhenHeard }
        // Messages is there only with a conversation.
        compose.onNodeWithTag(Tags.PEER_NOTIFY_MESSAGES).assertDoesNotExist()
    }

    /** Message on a node's page opens its conversation on Conversations. */
    @Test
    fun messageOpensTheConversation() {
        val runtime = runtime()
        show(runtime)
        openPeers()
        val maya = peer(runtime, "Maya Ortiz")
        openPage(maya.address)
        compose.onNodeWithTag(Tags.PEER_VERB_MESSAGE).performClick()
        waitFor { shell.selected == Destination.Conversations }
        waitFor { shell.stacks.getValue(Destination.Conversations).lastOrNull() is UmshKey.Thread }
        val thread = shell.stacks.getValue(Destination.Conversations).last() as UmshKey.Thread
        assertTrue(runtime.appState.value!!.directConversations.any { it.address == thread.address && it.peer.address == maya.address })
    }

    /** Beside the list: deleting the open node from its row closes its page. */
    @Test
    fun deletingFromTheListClosesThePageBesideIt() {
        val runtime = runtime()
        show(runtime, TestWindows.Tablet)
        openPeers()
        waitForTag(Tags.EMPTY_DETAIL)
        val tallac = peer(runtime, "Tallac Ridge")
        row(tallac.address).performClick()
        waitForTag(Tags.PEER_PAGE)
        compose.onNodeWithTag(Tags.PEERS_LIST).assertIsDisplayed()
        // Beside the list the page has no Back, and its row reads selected.
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).assertDoesNotExist()
        assertEquals(true, row(tallac.address).fetchSemanticsNode().config.getOrNull(SemanticsProperties.Selected))
        longPress(tallac.address)
        compose.onNodeWithTag(Tags.PEER_MENU_REMOVE).performClick()
        assertRemovalDialog(remove = false, deleteText = R.string.delete_peer)
        compose.onNodeWithTag(Tags.REMOVE_PEER_DELETE).performClick()
        waitFor { runtime.appState.value!!.peers.none { it.address == tallac.address } }
        waitGone(Tags.PEER_PAGE)
        waitForTag(Tags.EMPTY_DETAIL)
        assertEquals(listOf(UmshKey.PeersRoot), shell.stacks.getValue(Destination.Peers).toList())
    }

    // --- Ways in ----------------------------------------------------------

    /** A direct chat's title opens the node's page above the thread; Back returns to it. */
    @Test
    fun aDirectChatsTitleOpensThePage() {
        val runtime = runtime()
        show(runtime)
        val direct = runtime.appState.value!!.directConversations.first()
        compose.runOnUiThread { shell.openDetail(Destination.Conversations, UmshKey.Thread(direct.address)) }
        waitForTag(Tags.THREAD_TITLE)
        compose.onNodeWithTag(Tags.THREAD_TITLE).performClick()
        waitForTag(Tags.PEER_PAGE)
        assertEquals(UmshKey.PeerPage(direct.peer.address, Destination.Conversations), shell.stacks.getValue(Destination.Conversations).last())
        // Message goes back to the thread under it, not a second one.
        compose.onNodeWithTag(Tags.PEER_VERB_MESSAGE).performClick()
        waitFor { shell.stacks.getValue(Destination.Conversations).last() == UmshKey.Thread(direct.address) }
        assertEquals(1, shell.stacks.getValue(Destination.Conversations).count { it == UmshKey.Thread(direct.address) })
        waitGone(Tags.PEER_PAGE)
        compose.onNodeWithTag(Tags.THREAD_TITLE).performClick()
        waitForTag(Tags.PEER_PAGE)
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).performClick()
        waitGone(Tags.PEER_PAGE)
        compose.onNodeWithTag(Tags.THREAD).assertIsDisplayed()
    }

    /**
     * Message details' way in, beside the list: a repeater's page opens on
     * Conversations above the details, the conversation's row stays
     * selected under it, and system Back returns to the details, then the
     * thread. The page is
     * opened the way the details' `onOpenPeer` does, since the staged air's
     * repeats name no node (the row's own tap is
     * [repeaterRowsOpenANamedNodeOrLookUpAHint]).
     */
    @Test
    fun aPageOpenedFromMessageDetailsSitsAboveThem() {
        val runtime = runtime()
        show(runtime, TestWindows.Tablet)
        val direct = runtime.appState.value!!.directConversations.first()
        val message = runBlocking { runtime.transcriptNewest(direct.address, TranscriptWindow.PAGE_SIZE).messages }.last()
        val thread = UmshKey.Thread(direct.address)
        val details = UmshKey.MessageDetails(direct.address, message.ref.sessionId, message.ref.handle)
        compose.runOnUiThread {
            shell.openDetail(Destination.Conversations, thread)
            shell.push(Destination.Conversations, details)
        }
        waitForTag(Tags.MESSAGE_DETAILS)
        val tallac = peer(runtime, "Tallac Ridge")
        compose.runOnUiThread { shell.openPeer(tallac.address, Destination.Conversations) }
        waitForTag(Tags.PEER_PAGE)
        assertEquals(
            listOf(UmshKey.ConversationsRoot, thread, details, UmshKey.PeerPage(tallac.address, Destination.Conversations)),
            shell.stacks.getValue(Destination.Conversations).toList(),
        )
        val row = compose.onNodeWithTag(Tags.conversationRow(direct.address)).fetchSemanticsNode()
        assertEquals(true, row.config.getOrNull(SemanticsProperties.Selected))
        compose.activityRule.scenario.onActivity { it.onBackPressedDispatcher.onBackPressed() }
        waitGone(Tags.PEER_PAGE)
        waitForTag(Tags.MESSAGE_DETAILS)
        assertEquals(details, shell.stacks.getValue(Destination.Conversations).last())
        // And one page at a time from there: the thread, beside the list.
        compose.activityRule.scenario.onActivity { it.onBackPressedDispatcher.onBackPressed() }
        waitGone(Tags.MESSAGE_DETAILS)
        assertEquals(thread, shell.stacks.getValue(Destination.Conversations).last())
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed()
    }

    /** Radio Detail's Radio identity row opens the radio's own page: no Favorite, Remove or Rename. */
    @Test
    fun radioDetailsIdentityRowOpensTheRadiosPage() {
        val runtime = runtime()
        show(runtime)
        val radio = runtime.appState.value!!.peers.firstOrNull { it.isCompanionRadio }
        assumeTrue("the staged radio has no row", radio != null)
        compose.runOnUiThread { shell.openRadioDetail() }
        waitForTag(Tags.RADIO_DETAIL)
        compose.onNodeWithTag(Tags.RADIO_DETAIL_IDENTITY).performScrollTo().performClick()
        waitForTag(Tags.PEER_PAGE)
        compose.onNodeWithTag(Tags.PEER_FAVORITE).assertDoesNotExist()
        compose.onNodeWithTag(Tags.PEER_REMOVE).assertDoesNotExist()
        compose.onNodeWithTag(Tags.PEER_NOTIFY_HEARD).assertDoesNotExist()
        compose.onNodeWithTag(Tags.PEER_NAME).assertHasNoClickAction()
        assertTrue(nodeText(Tags.PEER_SUBTITLE).contains(context.getString(R.string.companion_radio)))
        // The page is above Radio Detail, on the shell's own stack: the last Back drawn is its.
        val backs = compose.onAllNodesWithTag(Tags.TOP_BAR_BACK)
        backs[backs.fetchSemanticsNodes().size - 1].performClick()
        waitGone(Tags.PEER_PAGE)
        compose.onNodeWithTag(Tags.RADIO_DETAIL).assertIsDisplayed()
    }

    /**
     * Message details' repeater rows (`RepeaterHintRow`): a named node opens
     * its page; a hint naming none offers a lookup, which spins once the
     * radio took it. Drawn alone: the staged air floods untraced, so its
     * repeats name no hint.
     */
    @Test
    fun repeaterRowsOpenANamedNodeOrLookUpAHint() {
        val runtime = runtime()
        val tallac = peer(runtime, "Tallac Ridge")
        val named = tallac.hint.octets.let { Octets(byteArrayOf(it[0], it[1])) }
        val unnamed = Octets(byteArrayOf(0x5e, 0xbd.toByte()))
        var opened: String? = null
        var asked = 0
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                androidx.compose.foundation.layout.Column {
                    RepeaterHintRow(named, named.hex(), tallac, names, onOpen = { opened = it.address }, lookUp = null)
                    RepeaterHintRow(unnamed, unnamed.hex(), null, names, onOpen = null, lookUp = {
                        asked++
                        CompletableDeferred(Unit)
                    })
                }
            }
        }
        compose.onNodeWithTag(Tags.hintLookup(named.hex()), useUnmergedTree = true).assertDoesNotExist()
        compose.onNode(SemanticsMatcher("names Tallac") { node -> node.config.getOrNull(SemanticsProperties.Text).orEmpty().any { it.text == names.peer(tallac) } }).performClick()
        assertEquals(tallac.address, opened)
        compose.onNodeWithTag(Tags.hintLookup(unnamed.hex()), useUnmergedTree = true).performClick()
        compose.waitForIdle()
        assertEquals(1, asked)
        // Waiting: the button gives way to a spinner TalkBack reads as such.
        val waiting = context.getString(R.string.waiting_for_reply)
        compose.onNode(SemanticsMatcher("waiting") { it.config.getOrNull(SemanticsProperties.StateDescription) == waiting }, useUnmergedTree = true).assertExists()
    }

    /**
     * §3.10 in the semantics TalkBack reads (the emulator images ship no
     * TalkBack): each glance cell one node led by its label, filter chips
     * selected, the sort chip's click label, the Ask again spinner's state,
     * and 48 dp targets.
     */
    @Test
    fun whatTalkBackReads() {
        val runtime = runtime()
        show(runtime)
        openPeers()
        val sort = compose.onNodeWithTag(Tags.PEERS_SORT).fetchSemanticsNode()
        assertEquals(context.getString(R.string.peers_sort_change), sort.config[SemanticsActions.OnClick].label)
        // A button that opens a menu, never a checkbox left unchecked.
        assertEquals(Role.Button, sort.config.getOrNull(SemanticsProperties.Role))
        assertNull(sort.config.getOrNull(SemanticsProperties.Selected))
        assertNull(sort.config.getOrNull(SemanticsProperties.ToggleableState))
        compose.onNodeWithTag(Tags.peersFilter(PeerFilter.Sensors.name)).performScrollTo().performClick()
        waitFor { compose.onNodeWithTag(Tags.peersFilter(PeerFilter.Sensors.name)).fetchSemanticsNode().config.getOrNull(SemanticsProperties.Selected) == true }
        assertEquals(false, compose.onNodeWithTag(Tags.peersFilter(PeerFilter.People.name)).fetchSemanticsNode().config.getOrNull(SemanticsProperties.Selected))
        compose.onNodeWithTag(Tags.peersFilter(PeerFilter.Sensors.name)).performClick()

        val maya = peer(runtime, "Maya Ortiz")
        assertTrue(row(maya.address).fetchSemanticsNode().size.height >= minTouch())
        openPage(maya.address)
        for ((tag, label) in listOf(
            Tags.PEER_GLANCE_HEARD to R.string.glance_heard,
            Tags.PEER_GLANCE_ROUTE to R.string.glance_route,
            Tags.PEER_GLANCE_DISTANCE to R.string.glance_distance,
        )) {
            val cell = compose.onNodeWithTag(tag).fetchSemanticsNode()
            val spoken = cell.config[SemanticsProperties.ContentDescription].single()
            assertTrue(spoken, spoken.startsWith(context.getString(label)))
            // One node: nothing under it is read on its own.
            assertTrue(cell.children.isEmpty())
        }
        for (tag in listOf(Tags.PEER_FAVORITE, Tags.PEER_VERB_MESSAGE)) {
            // The touch bounds: an icon button draws 40 dp inside a 48 dp target.
            val size = compose.onNodeWithTag(tag).fetchSemanticsNode().touchBoundsInRoot
            assertTrue("$tag $size", size.width >= minTouch() && size.height >= minTouch())
        }
        compose.onNodeWithTag(Tags.PEER_ASK_AGAIN).performScrollTo()
        val ask = compose.onNodeWithTag(Tags.PEER_ASK_AGAIN).fetchSemanticsNode().touchBoundsInRoot
        assertTrue("$ask", ask.width >= minTouch() && ask.height >= minTouch())

        // Asked of a node that never answers (no device holds the base point's
        // key), so the spinner stays for the whole wait and is always read.
        runBlocking {
            runtime.core.savePeer(NEVER_ANSWERS, null, false)
            runtime.reload(full = true).await()
        }
        compose.runOnUiThread { shell.openPeerFromList(NEVER_ANSWERS) }
        // Its page alone, never advertised, once Maya's has gone.
        val never = context.getString(R.string.peer_advertised_never)
        waitFor {
            compose.onAllNodesWithTag(Tags.PEER_ADVERTISED, useUnmergedTree = true).fetchSemanticsNodes()
                .singleOrNull()?.config?.getOrNull(SemanticsProperties.Text)?.any { it.text == never } == true
        }
        compose.onNodeWithTag(Tags.PEER_ASK_AGAIN).performScrollTo().performClick()
        waitFor { compose.onAllNodesWithTag(Tags.PEER_ASKING, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty() }
        val asking = compose.onNodeWithTag(Tags.PEER_ASKING, useUnmergedTree = true).fetchSemanticsNode()
        assertEquals(context.getString(R.string.waiting_for_reply), asking.config[SemanticsProperties.StateDescription])
    }

    private fun minTouch(): Int = (48 * context.resources.displayMetrics.density).toInt() - 1

    private companion object {
        const val TIMEOUT = 30_000L

        /** The Ed25519 base point's address: a key no device holds, so nothing ever answers it. */
        const val NEVER_ANSWERS = "6x5SYnLroiN7WYq8NQYU9KHcH4YjpBbwpUfVu3EB7ieH"
    }
}
