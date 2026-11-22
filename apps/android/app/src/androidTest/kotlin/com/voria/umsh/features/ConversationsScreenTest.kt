package com.voria.umsh.features

import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsFocused
import androidx.compose.ui.test.assertIsNotFocused
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeLeft
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
import com.voria.umsh.app.UmshKey
import com.voria.umsh.app.UmshShell
import com.voria.umsh.app.rememberShellState
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.conversations.ConversationList
import com.voria.umsh.features.peers.PeerSections
import com.voria.umsh.models.ChannelConversationSummary
import com.voria.umsh.models.DirectConversationSummary
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.services.format.AndroidCollation
import java.util.Locale
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import com.voria.umsh.designsystem.LocalWindowOverride
import com.voria.umsh.app.TestWindows
import androidx.compose.ui.test.onAllNodesWithTag

/** The conversation list (`conversation-list.svg`) and the read-only Peers list (D3), over real cores. */
class ConversationsScreenTest {
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

    private val collation = AndroidCollation(Locale.US)

    private fun runtime(staging: Boolean): AppRuntime = runBlocking {
        fresh.host.ensureRuntime(staging)
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        val runtime = ready.runtime
        withTimeout(TIMEOUT) { runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        // Running: the core has opened Public's chat, and the list has read it.
        withTimeout(TIMEOUT) { runtime.appState.first { state -> state?.channelConversations?.isNotEmpty() == true } }
        runtime
    }

    private fun show(runtime: AppRuntime) {
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                // A phone, whatever the device: these follow the one-page layout.
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides TestWindows.Phone,
                ) {
                    val state = rememberShellState()
                    shell = state
                    UmshShell(state)
                }
            }
        }
        compose.onNodeWithTag(Tags.CONVERSATION_LIST).assertIsDisplayed()
    }

    private fun row(address: String): SemanticsNodeInteraction {
        compose.onNodeWithTag(Tags.CONVERSATION_LIST).performScrollToNode(hasTestTag(Tags.conversationRow(address)))
        return compose.onNodeWithTag(Tags.conversationRow(address), useUnmergedTree = true)
    }

    /** The IDs after [prefix] of the nodes tagged with it, top to bottom. */
    private fun shownInOrder(prefix: String): List<String> = compose
        .onAllNodes(SemanticsMatcher("tag starts with $prefix") { it.config.getOrNull(SemanticsProperties.TestTag)?.startsWith(prefix) == true })
        .fetchSemanticsNodes()
        .sortedBy { it.boundsInRoot.top }
        .map { it.config[SemanticsProperties.TestTag].removePrefix(prefix) }

    private fun waitFor(condition: () -> Boolean) = compose.waitUntil(TIMEOUT, condition)

    /*
     * The list and the search results are computed on Dispatchers.Default,
     * which Compose's idle check does not see: what they show is waited for,
     * never asserted straight after the input that changes it.
     */
    private fun present(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String) = waitFor { present(tag) }

    private fun waitGone(tag: String) = waitFor { !present(tag) }

    /** Board 1: every conversation is a row, newest activity first, with its unread count and mute. */
    @Test
    fun theSeededConversationsAreRowsInOrder() {
        val runtime = runtime(staging = true)
        show(runtime)
        val state = runtime.appState.value!!
        val expected = ConversationList.rows(state, names, collation, runtime.identity.value.advertisedName)
        assertTrue(expected.size > 1)
        // The rows on screen, top to bottom, are the list's order.
        val onScreen = shownInOrder("conversation_row/")
        assertTrue("$onScreen", onScreen.size > 1)
        assertEquals(expected.map { it.address }.filter { it in onScreen }, onScreen)
        for (conversation in state.conversations) {
            row(conversation.address)
            val merged = compose.onNodeWithTag(Tags.conversationRow(conversation.address)).fetchSemanticsNode().config
            val descriptions = merged.getOrNull(SemanticsProperties.ContentDescription).orEmpty()
            val count = conversation.unreadCount.toInt()
            if (count > 0) {
                val spoken = context.resources.getQuantityString(R.plurals.row_unread_messages, count, count)
                assertTrue("$descriptions", spoken in descriptions)
            }
            val muted = when (conversation) {
                is DirectConversationSummary -> !conversation.notificationsEnabled
                is ChannelConversationSummary -> !conversation.channel.notificationsEnabled
            }
            assertEquals(muted, context.getString(R.string.row_muted) in descriptions)
            // Every row offers its removal to TalkBack.
            assertEquals(1, merged.getOrNull(SemanticsActions.CustomActions)?.size)
        }
    }

    /**
     * A first launch: the core opens Public's chat and no other, so the list
     * is Public alone, muted, "No messages yet", as on iOS. EMERGENCY is
     * joined but has no conversation; search offers it under Channels.
     */
    @Test
    fun aFirstLaunchListsPublicAndSearchOffersEmergency() {
        val runtime = runtime(staging = false)
        show(runtime)
        val state = runtime.appState.value!!
        assertEquals(1, state.conversations.size)
        val public = state.channelConversations.single()
        assertEquals("public", public.channel.canonicalName)
        assertFalse(public.channel.notificationsEnabled)
        val emergency = state.channels.single { it.canonicalName == "emergency" }
        assertTrue(emergency.joinedPhone)
        row(public.address).assertIsDisplayed()
        compose.onNodeWithTag(Tags.ROW_MUTED, useUnmergedTree = true).assertIsDisplayed()
        val text = compose.onNodeWithTag(Tags.conversationRow(public.address)).fetchSemanticsNode()
            .config.getOrNull(SemanticsProperties.Text).orEmpty().map { it.text }
        assertTrue("$text", context.getString(R.string.preview_none) in text)

        compose.onNodeWithTag(Tags.CONVERSATIONS_SEARCH).performClick()
        compose.onNodeWithTag(Tags.SEARCH_FIELD).performTextInput("emer")
        waitForTag(Tags.searchChannel(emergency.id))
        compose.onNodeWithTag(Tags.SEARCH_CHANNELS).assertIsDisplayed()
        compose.onNodeWithTag(Tags.searchChannel(emergency.id)).assertIsDisplayed().performClick()
        // Tapping it opens EMERGENCY's chat, started the first time.
        waitFor { (shell.stacks.getValue(Destination.Conversations).lastOrNull() as? UmshKey.Thread) != null }
        val opened = (shell.stacks.getValue(Destination.Conversations).last() as UmshKey.Thread).address
        waitFor { runtime.appState.value!!.channelConversations.any { it.address == opened && it.channel.id == emergency.id } }
        compose.onNodeWithTag(Tags.SEARCH_VIEW).assertDoesNotExist()
    }

    /** Boards 4–5: grouped results, and one line when nothing matches. */
    @Test
    fun searchGroupsResultsAndSaysWhenNothingMatches() {
        val runtime = runtime(staging = true)
        show(runtime)
        val state = runtime.appState.value!!
        val heard = state.peers.first { !it.isSaved && !it.isCompanionRadio }
        val name = heard.advertisedName!!

        compose.onNodeWithTag(Tags.CONVERSATIONS_SEARCH).performClick()
        compose.onNodeWithTag(Tags.SEARCH_VIEW).assertIsDisplayed()
        compose.onNodeWithTag(Tags.SEARCH_FIELD).performTextInput(name.lowercase())
        waitForTag(Tags.searchPeer(heard.address))
        compose.onNodeWithTag(Tags.SEARCH_DISCOVERED).assertIsDisplayed()
        compose.onNodeWithTag(Tags.searchPeer(heard.address)).assertIsDisplayed()

        compose.onNodeWithTag(Tags.SEARCH_FIELD).performTextReplacement("zqzqzq")
        waitForTag(Tags.SEARCH_NOTHING)
        compose.onNodeWithTag(Tags.SEARCH_NOTHING).assertIsDisplayed()

        compose.onNodeWithTag(Tags.SEARCH_CLOSE).performClick()
        compose.onNodeWithTag(Tags.SEARCH_VIEW).assertDoesNotExist()
        compose.onNodeWithTag(Tags.CONVERSATION_LIST).assertIsDisplayed()
    }

    /** A node heard nearby: tapping it starts its conversation and opens it. */
    @Test
    fun searchStartsAConversationWithANodeHeardNearby() {
        val runtime = runtime(staging = true)
        show(runtime)
        val heard = runtime.appState.value!!.peers.first { !it.isSaved && !it.isCompanionRadio }
        compose.onNodeWithTag(Tags.CONVERSATIONS_SEARCH).performClick()
        compose.onNodeWithTag(Tags.SEARCH_FIELD).performTextInput(heard.address.take(6))
        waitForTag(Tags.searchPeer(heard.address))
        compose.onNodeWithTag(Tags.searchPeer(heard.address)).performClick()
        waitFor { shell.stacks.getValue(Destination.Conversations).lastOrNull() == UmshKey.Thread(heard.address) }
        waitFor { runtime.appState.value!!.directConversations.any { it.address == heard.address } }
        compose.onNodeWithTag(Tags.THREAD).assertIsDisplayed()
    }

    /**
     * Search takes focus as it opens, and only then: left open under another
     * destination, it comes back without the keyboard.
     */
    @Test
    fun searchTakesFocusOnlyAsItOpens() {
        val runtime = runtime(staging = true)
        show(runtime)
        compose.onNodeWithTag(Tags.CONVERSATIONS_SEARCH).performClick()
        compose.onNodeWithTag(Tags.SEARCH_FIELD).assertIsFocused()
        compose.runOnUiThread { shell.select(Destination.Settings) }
        compose.onNodeWithTag(Tags.SEARCH_VIEW).assertDoesNotExist()
        compose.runOnUiThread { shell.select(Destination.Conversations) }
        compose.onNodeWithTag(Tags.SEARCH_VIEW).assertIsDisplayed()
        compose.onNodeWithTag(Tags.SEARCH_FIELD).assertIsNotFocused()
    }

    /** Boards 7–8: the swipe only asks; Cancel keeps the row, Delete removes it. */
    @Test
    fun swipingAsksBeforeDeleting() {
        val runtime = runtime(staging = true)
        show(runtime)
        val direct = runtime.appState.value!!.directConversations.first()

        row(direct.address).performTouchInput { swipeLeft() }
        compose.onNodeWithTag(Tags.CONFIRM_DIALOG).assertIsDisplayed()
        compose.onNodeWithTag(Tags.CONFIRM_CANCEL).performClick()
        compose.onNodeWithTag(Tags.CONFIRM_DIALOG).assertDoesNotExist()
        row(direct.address).assertIsDisplayed()
        assertTrue(runtime.appState.value!!.directConversations.any { it.address == direct.address })

        row(direct.address).performTouchInput { swipeLeft() }
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        waitFor { runtime.appState.value!!.directConversations.none { it.address == direct.address } }
        waitGone(Tags.conversationRow(direct.address))
        // The peer stays.
        assertTrue(runtime.appState.value!!.peers.any { it.address == direct.address })
    }

    /** Board 9 through TalkBack's action: leaving a channel's chat keeps the channel joined. */
    @Test
    fun theRowActionLeavesAChannelChatButNotTheChannel() {
        val runtime = runtime(staging = true)
        show(runtime)
        val chat = runtime.appState.value!!.channelConversations.first { it.channel.canonicalName == null }
        row(chat.address)
        val node = compose.onNodeWithTag(Tags.conversationRow(chat.address)).fetchSemanticsNode()
        val action = node.config[SemanticsActions.CustomActions].single()
        assertEquals(context.getString(R.string.action_leave_chat), action.label)
        compose.runOnIdle { action.action() }
        compose.onNodeWithTag(Tags.CONFIRM_DIALOG).assertIsDisplayed()
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        waitFor { runtime.appState.value!!.channelConversations.none { it.address == chat.address } }
        val channel = runtime.appState.value!!.channels.single { it.id == chat.channel.id }
        assertTrue(channel.joinedPhone)
    }

    /** Opening an unread conversation marks it read, and the badge counts one fewer. */
    @Test
    fun openingAConversationMarksItRead() {
        val runtime = runtime(staging = true)
        show(runtime)
        val unread = runtime.appState.value!!.conversations.first { it.unreadCount > 0 }
        val before = runtime.appState.value!!.conversations.count { it.unreadCount > 0 }
        row(unread.address).performClick()
        compose.onNodeWithTag(Tags.THREAD).assertIsDisplayed()
        waitFor { runtime.appState.value!!.conversations.single { it.address == unread.address }.unreadCount == 0L }
        assertEquals(before - 1, runtime.appState.value!!.conversations.count { it.unreadCount > 0 })
        // The bar is hidden under a thread on a phone: the badge is read back at the list.
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).performClick()
        compose.onNodeWithTag(Tags.CONVERSATION_LIST).assertIsDisplayed()
        val badge = compose.onNodeWithTag(Tags.NAV_UNREAD_BADGE, useUnmergedTree = true)
        if (before - 1 == 0) {
            badge.assertDoesNotExist()
        } else {
            val spoken = context.resources.getQuantityString(R.plurals.nav_unread_conversations, before - 1, before - 1)
            waitFor { badge.fetchSemanticsNode().config.getOrNull(SemanticsProperties.ContentDescription) == listOf(spoken) }
        }
    }

    /** A conversation removed from anywhere but its row: the thread showing it closes. */
    @Test
    fun aThreadClosesWhenItsConversationIsRemoved() {
        val runtime = runtime(staging = true)
        show(runtime)
        val direct = runtime.appState.value!!.directConversations.first()
        row(direct.address).performClick()
        compose.onNodeWithTag(Tags.THREAD).assertIsDisplayed()
        runBlocking { runtime.deleteConversation(direct.address).await() }
        waitFor { shell.stacks.getValue(Destination.Conversations).toList() == listOf(UmshKey.ConversationsRoot) }
        compose.onNodeWithTag(Tags.CONVERSATION_LIST).assertIsDisplayed()
    }

    /** With every conversation removed: "No conversations", its body and buttons left out (D5). */
    @Test
    fun noConversationsSaysSo() {
        val runtime = runtime(staging = false)
        show(runtime)
        val public = runtime.appState.value!!.channelConversations.single()
        runBlocking { runtime.deleteConversation(public.address).await() }
        waitForTag(Tags.CONVERSATIONS_EMPTY)
        compose.onNodeWithTag(Tags.CONVERSATIONS_EMPTY).assertIsDisplayed()
        waitGone(Tags.CONVERSATION_LIST)
    }

    /** D3: Favorites, then Saved; nodes heard but not saved are left out, and rows have no action. */
    @Test
    fun peersListsSavedNodesBySection() {
        val runtime = runtime(staging = true)
        show(runtime)
        compose.onNodeWithTag(Tags.NAV_PEERS).performClick()
        compose.onNodeWithTag(Tags.PEERS_LIST).assertIsDisplayed()
        val sections = PeerSections.of(runtime.appState.value!!, names, collation)
        assertTrue(sections.favorites.isNotEmpty())
        compose.onNodeWithTag(Tags.PEERS_FAVORITES).assertIsDisplayed()
        val shown = sections.favorites + sections.saved + sections.radios
        val onScreen = shownInOrder("peer_row/")
        assertTrue("$onScreen", onScreen.size > 1)
        assertEquals(shown.map { it.address }.filter { it in onScreen }, onScreen)
        for (peer in shown) {
            compose.onNodeWithTag(Tags.PEERS_LIST).performScrollToNode(hasTestTag(Tags.peerRow(peer.address)))
            val node = compose.onNodeWithTag(Tags.peerRow(peer.address)).fetchSemanticsNode()
            assertNotNull(node)
            assertFalse(node.config.contains(SemanticsActions.OnClick))
        }
        for (peer in runtime.appState.value!!.peers.filter { !it.isSaved && !it.isCompanionRadio }) {
            compose.onNodeWithTag(Tags.peerRow(peer.address)).assertDoesNotExist()
        }
    }

    private companion object {
        const val TIMEOUT = 20_000L
    }
}
