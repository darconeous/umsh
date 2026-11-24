package com.voria.umsh.features

import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.click
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
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
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.conversations.ChannelMember
import com.voria.umsh.features.conversations.MemberSheet
import com.voria.umsh.features.conversations.TranscriptWindow
import com.voria.umsh.models.ChannelConversationSummary
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PreviewText.Sender
import com.voria.umsh.models.TranscriptRow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Conversation info without Routing (`conversation-info.svg` 1, 2, 5; D6)
 * and the member sheet (board 6), over the staged core. Nothing goes out
 * but over the staged air; nothing is sent on Public or EMERGENCY.
 */
class ConversationInfoTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun start(): AppRuntime {
        val runtime = runBlocking {
            fresh.host.ensureRuntime(staging = true)
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            withTimeout(TIMEOUT) { ready.runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
            withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
            withTimeout(TIMEOUT) {
                ready.runtime.appState.first { state -> state?.channelConversations?.any { it.channel.name == "Trail Crew" } == true }
            }
            ready.runtime
        }
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides TestWindows.Phone,
                ) {
                    shell = rememberShellState()
                    UmshShell(shell)
                }
            }
        }
        waitFor(Tags.CONVERSATIONS_ROOT)
        return runtime
    }

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitFor(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun waitGone(tag: String) = compose.waitUntil(TIMEOUT) { !present(tag) }

    private fun back() = compose.runOnUiThread { shell.back() }

    /** Every text in the node tagged [tag] and under it, in order. */
    private fun texts(tag: String): String = compose.onAllNodes(hasTestTag(tag) or hasAnyAncestor(hasTestTag(tag)), useUnmergedTree = true)
        .fetchSemanticsNodes().joinToString(" ") { node ->
        node.config.getOrNull(SemanticsProperties.Text).orEmpty().joinToString(" ") { it.text }
    }

    /** Every text on screen, merged. */
    private fun screenText(): String = compose.onAllNodes(hasText("", substring = true), useUnmergedTree = true)
        .fetchSemanticsNodes().joinToString(" ") { node -> node.config.getOrNull(SemanticsProperties.Text).orEmpty().joinToString(" ") { it.text } }

    private fun AppRuntime.conversation(name: String): ChannelConversationSummary =
        appState.value!!.channelConversations.first { it.channel.name == name || it.channel.canonicalName == name.lowercase() }

    /** [address]'s thread, then its title: Conversation info. */
    private fun openInfo(address: String) {
        compose.runOnUiThread { shell.openDetail(UmshKey.Thread(address)) }
        waitFor(Tags.THREAD_TITLE)
        compose.onNodeWithTag(Tags.THREAD_TITLE).performClick()
        waitFor(Tags.CONVERSATION_INFO)
        compose.waitUntil(TIMEOUT) { texts(Tags.CONVERSATION_INFO_MESSAGES).any { it.isDigit() } }
    }

    private fun opened(runtime: AppRuntime, canonical: String): String = runBlocking {
        val channel = runtime.appState.value!!.channels.first { it.canonicalName == canonical }
        runtime.openChannelConversation(channel.id).await()
    }

    /** The Routing section is gated (D6): none of its words are drawn. */
    private fun assertNoRouting() {
        val shown = screenText()
        for (word in listOf("Routing", "Regions", "Add region", "Maximum hops")) assertFalse("$word in $shown", word in shown)
    }

    /** Board 1 (as Public): the header to the channel's page, Notifications, the conversation's facts, and how Public works. */
    @Test
    fun aPublicChannelsInfo() {
        val runtime = start()
        val address = opened(runtime, "public")
        val public = runtime.appState.value!!.channels.first { it.canonicalName == "public" }
        openInfo(address)
        assertTrue(texts(Tags.CONVERSATION_INFO_CHANNEL).contains(context.getString(R.string.channel_kind_builtin)))
        assertTrue(texts(Tags.CONVERSATION_INFO_CHANNEL).contains(context.getString(R.string.conversation_info_channel_footer)))
        assertTrue(texts(Tags.CONVERSATION_INFO_IDENTIFIER).contains(public.channelIdHex))
        val count = runBlocking { runtime.messageCount(address) }
        assertTrue(texts(Tags.CONVERSATION_INFO_MESSAGES).contains(count.toString()))
        if (count == 0L) compose.onNodeWithTag(Tags.CONVERSATION_INFO_CLEAR).assertIsNotEnabled()
        compose.onNodeWithTag(Tags.CONVERSATION_INFO_TEST_MESSAGES).assertDoesNotExist()
        compose.onNodeWithTag(Tags.CONVERSATION_INFO_STATEMENTS).performScrollTo()
        assertTrue(texts(Tags.CONVERSATION_INFO_STATEMENTS).contains(context.getString(R.string.channel_public_identified)))
        assertNoRouting()

        // Notifications: the channel's own switch, both ways.
        val before = public.notificationsEnabled
        compose.onNodeWithTag(Tags.CONVERSATION_INFO_NOTIFICATIONS).performScrollTo().performClick()
        compose.waitUntil(TIMEOUT) { runtime.appState.value!!.channels.first { it.id == public.id }.notificationsEnabled != before }
        compose.onNodeWithTag(Tags.CONVERSATION_INFO_NOTIFICATIONS).performClick()
        compose.waitUntil(TIMEOUT) { runtime.appState.value!!.channels.first { it.id == public.id }.notificationsEnabled == before }

        // The header leads to the channel's page on this stack; Back returns here, then to the thread.
        compose.onNodeWithTag(Tags.CONVERSATION_INFO_CHANNEL).performScrollTo().performClick()
        waitFor(Tags.CHANNEL_PAGE)
        assertEquals(UmshKey.ChannelPage(public.id, Destination.Conversations), shell.stacks.getValue(Destination.Conversations).last())
        back()
        waitFor(Tags.CONVERSATION_INFO)
        back()
        waitGone(Tags.CONVERSATION_INFO)
        waitFor(Tags.THREAD)
    }

    /** Board 2: EMERGENCY adds Test messages and its statements; its fixed hop count belongs to Routing and is not drawn. */
    @Test
    fun emergencyHasTestMessagesAndItsStatements() {
        val runtime = start()
        val address = opened(runtime, "emergency")
        openInfo(address)
        assertTrue(texts(Tags.CONVERSATION_INFO_CHANNEL).contains("EMERGENCY"))
        val policy = { runBlocking { runtime.policy.first().testMessageAlerts } }
        assertFalse(policy())
        compose.onNodeWithTag(Tags.CONVERSATION_INFO_TEST_MESSAGES).performScrollTo().performClick()
        compose.waitUntil(TIMEOUT) { policy() }
        compose.onNodeWithTag(Tags.CONVERSATION_INFO_STATEMENTS).performScrollTo()
        val statements = texts(Tags.CONVERSATION_INFO_STATEMENTS)
        for (id in listOf(R.string.channel_emergency_unencrypted, R.string.channel_emergency_signed, R.string.channel_emergency_priority)) {
            assertTrue(statements.contains(context.getString(id)))
        }
        assertNoRouting()
        assertFalse(screenText().contains("10 hops"))
        compose.onNodeWithTag(Tags.CONVERSATION_INFO_TEST_MESSAGES).performScrollTo().performClick()
        compose.waitUntil(TIMEOUT) { !policy() }
    }

    /** Board 5: Clear all messages states the count, erases this phone's copy, and keeps the conversation. */
    @Test
    fun clearAllMessages() {
        val runtime = start()
        val crew = runtime.conversation("Trail Crew")
        val count = runBlocking { runtime.messageCount(crew.address) }.toInt()
        assertTrue(count > 0)
        openInfo(crew.address)
        assertTrue(texts(Tags.CONVERSATION_INFO_MESSAGES).contains(count.toString()))
        // Cancel keeps everything.
        compose.onNodeWithTag(Tags.CONVERSATION_INFO_CLEAR).performScrollTo().performClick()
        waitFor(Tags.CONFIRM_DIALOG)
        assertTrue(texts(Tags.CONFIRM_ACTION).contains(context.resources.getQuantityString(R.plurals.clear_messages_confirm, count, count)))
        assertTrue(screenText().contains(context.getString(R.string.clear_channel_messages_body)))
        compose.onNodeWithTag(Tags.CONFIRM_CANCEL).performClick()
        waitGone(Tags.CONFIRM_DIALOG)
        assertEquals(count.toLong(), runBlocking { runtime.messageCount(crew.address) })

        compose.onNodeWithTag(Tags.CONVERSATION_INFO_CLEAR).performClick()
        waitFor(Tags.CONFIRM_DIALOG)
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        compose.waitUntil(TIMEOUT) { runBlocking { runtime.messageCount(crew.address) } == 0L }
        compose.waitUntil(TIMEOUT) { texts(Tags.CONVERSATION_INFO_MESSAGES).endsWith("0") }
        compose.onNodeWithTag(Tags.CONVERSATION_INFO_CLEAR).assertIsNotEnabled()
        assertTrue(runtime.appState.value!!.channelConversations.any { it.address == crew.address })
    }

    /** The newest row of [sender]'s that carries their avatar (a run's last), in [address]'s thread. */
    private fun avatarRow(runtime: AppRuntime, address: String, sender: String): String = runBlocking {
        val window = TranscriptWindow().replacedBy(runtime.transcriptNewest(address, TranscriptWindow.PAGE_SIZE), 0)
        window.rows.filterIsInstance<TranscriptRow.Message>()
            .last { it.message.senderAddress == sender && it.presentation.isLastInRun && !it.message.isStatus && !it.message.isDeleted }
            .key
    }

    private fun tapAvatar(row: String) {
        compose.onNodeWithTag(Tags.TRANSCRIPT).performScrollToNode(hasTestTag(Tags.message(row)))
        compose.onNode(hasTestTag(Tags.MEMBER_AVATAR) and hasAnyAncestor(hasTestTag(Tags.message(row))), useUnmergedTree = true).performClick()
        waitFor(Tags.MEMBER_SHEET)
    }

    /**
     * The avatar is drawn at 28 dp but takes a 48 dp touch: a tap just above
     * it, or in the gap before the bubble, still opens the sheet.
     */
    @Test
    fun theAvatarTakesTapsAroundIt() {
        aroundTheAvatar { bounds -> Offset(bounds.center.x, bounds.top - 8.dp.toPx()) }
    }

    @Test
    fun theAvatarTakesTapsBeforeTheBubble() {
        aroundTheAvatar { bounds -> Offset(bounds.right + 6.dp.toPx(), bounds.center.y) }
    }

    private fun aroundTheAvatar(at: Density.(Rect) -> Offset) {
        val runtime = start()
        val crew = runtime.conversation("Trail Crew")
        val maya = runtime.appState.value!!.peers.first { it.advertisedName == "Maya Ortiz" }
        compose.runOnUiThread { shell.openDetail(UmshKey.Thread(crew.address)) }
        waitFor(Tags.TRANSCRIPT)
        val row = avatarRow(runtime, crew.address, maya.address)
        compose.onNodeWithTag(Tags.TRANSCRIPT).performScrollToNode(hasTestTag(Tags.message(row)))
        val avatar = compose.onNode(hasTestTag(Tags.MEMBER_AVATAR) and hasAnyAncestor(hasTestTag(Tags.message(row))), useUnmergedTree = true)
        val node = avatar.fetchSemanticsNode()
        val drawn = node.boundsInRoot
        val touch = node.touchBoundsInRoot
        with(compose.density) {
            assertEquals(28.dp.toPx(), drawn.width, 1f)
            assertTrue("touch width ${touch.width}", touch.width >= 48.dp.toPx() - 1f)
            assertTrue("touch height ${touch.height}", touch.height >= 48.dp.toPx() - 1f)
        }
        val tap = with(compose.density) { at(drawn) }
        // The tap lands outside the drawn avatar, inside its touch bounds.
        assertFalse(drawn.contains(tap))
        assertTrue(touch.contains(tap))
        compose.onRoot().performTouchInput { click(tap) }
        waitFor(Tags.MEMBER_SHEET)
        assertEquals("Maya Ortiz", texts(Tags.MEMBER_TITLE))
    }

    /** Board 6, saved: the header leads to the member's page on the Conversations stack. */
    @Test
    fun aSavedMembersSheetLeadsToTheirPage() {
        val runtime = start()
        val crew = runtime.conversation("Trail Crew")
        val maya = runtime.appState.value!!.peers.first { it.advertisedName == "Maya Ortiz" }
        assertTrue(maya.isSaved)
        compose.runOnUiThread { shell.openDetail(UmshKey.Thread(crew.address)) }
        waitFor(Tags.TRANSCRIPT)
        tapAvatar(avatarRow(runtime, crew.address, maya.address))
        assertEquals("Maya Ortiz", texts(Tags.MEMBER_TITLE))
        compose.onNodeWithTag(Tags.MEMBER_REQUEST_IDENTITY).assertDoesNotExist()
        assertTrue(texts(Tags.MEMBER_HINT).contains(maya.hint.text))
        compose.onNodeWithTag(Tags.MEMBER_PEER).performClick()
        waitGone(Tags.MEMBER_SHEET)
        waitFor(Tags.PEER_PAGE)
        assertEquals(
            UmshKey.PeerPage(maya.address, Destination.Conversations),
            shell.stacks.getValue(Destination.Conversations).last(),
        )
    }

    /** Board 6, not saved: Request identity goes over the channel, the staged member answers, and the button says so. */
    @Test
    fun requestIdentityFromAMemberNotSaved() {
        val runtime = start()
        val crew = runtime.conversation("Trail Crew")
        val maya = runtime.appState.value!!.peers.first { it.advertisedName == "Maya Ortiz" }
        runBlocking { runtime.demotePeer(maya.address).await() }
        compose.waitUntil(TIMEOUT) { runtime.appState.value!!.peers.first { it.address == maya.address }.isSaved.not() }
        val heard = runtime.appState.value!!.peers.first { it.address == maya.address }.advertisementReceivedAtMs
        compose.runOnUiThread { shell.openDetail(UmshKey.Thread(crew.address)) }
        waitFor(Tags.TRANSCRIPT)
        val row = avatarRow(runtime, crew.address, maya.address)

        // TalkBack: the avatar is its own button named for the member; every message of theirs offers the sheet too.
        val avatar = compose.onNode(hasTestTag(Tags.MEMBER_AVATAR) and hasAnyAncestor(hasTestTag(Tags.message(row))), useUnmergedTree = true)
        compose.onNodeWithTag(Tags.TRANSCRIPT).performScrollToNode(hasTestTag(Tags.message(row)))
        val node = avatar.fetchSemanticsNode().config
        assertEquals(Role.Button, node[SemanticsProperties.Role])
        assertEquals(context.getString(R.string.member_show), node[SemanticsActions.OnClick].label)
        assertEquals(listOf("Maya Ortiz"), node[SemanticsProperties.ContentDescription])
        val actions = compose.onNodeWithTag(Tags.message(row)).fetchSemanticsNode().config[SemanticsActions.CustomActions]
        assertTrue(actions.any { it.label == context.getString(R.string.member_show) })

        tapAvatar(row)
        compose.onNodeWithTag(Tags.MEMBER_PEER).assertDoesNotExist()
        assertTrue(texts(Tags.MEMBER_NAME).contains("Maya Ortiz"))
        compose.onNodeWithTag(Tags.MEMBER_ADDRESS).assertExists()
        assertTrue(texts(Tags.MEMBER_REQUEST_IDENTITY).contains(context.getString(R.string.member_request_identity)))
        compose.onNodeWithTag(Tags.MEMBER_REQUEST_IDENTITY).performScrollTo().performClick()
        compose.waitUntil(TIMEOUT) { texts(Tags.MEMBER_REQUEST_IDENTITY).contains(context.getString(R.string.member_identity_requested)) }
        compose.onNodeWithTag(Tags.MEMBER_REQUEST_IDENTITY).assertIsNotEnabled()
        compose.waitUntil(TIMEOUT) {
            runtime.appState.value!!.peers.first { it.address == maya.address }.advertisementReceivedAtMs.let { it != null && it != heard }
        }
    }

    /** Board 6 as drawn: an unnamed sender is "Member" and their hint, with no address yet, and Request identity. */
    @Test
    fun anUnnamedMembersSheet() {
        val hint = NodeHint(Octets(byteArrayOf(0x12, 0x34, 0x56)), "BtC5")
        val member = ChannelMember(hint.octets, hint, address = null, handle = null, name = Sender.Hint("BtC5"), peer = null)
        val asked = mutableIntStateOf(0)
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                MemberSheet(member, requested = asked.intValue > 0, onRequestIdentity = { asked.intValue++ }, onOpenPeer = {}, onDismiss = {})
            }
        }
        waitFor(Tags.MEMBER_SHEET)
        val shown = texts(Tags.MEMBER_TITLE)
        assertTrue(shown, shown.contains("BtC5") && shown.contains(context.getString(R.string.member_unknown)))
        assertTrue(texts(Tags.MEMBER_HINT).contains("BtC5"))
        compose.onNodeWithTag(Tags.MEMBER_ADDRESS).assertDoesNotExist()
        compose.onNodeWithTag(Tags.MEMBER_HANDLE).assertDoesNotExist()
        compose.onNodeWithTag(Tags.MEMBER_PEER).assertDoesNotExist()
        assertTrue(screenText().contains(context.getString(R.string.member_request_footer)))
        compose.onNodeWithTag(Tags.MEMBER_REQUEST_IDENTITY).performClick()
        compose.waitUntil(TIMEOUT) { texts(Tags.MEMBER_REQUEST_IDENTITY).contains(context.getString(R.string.member_identity_requested)) }
        assertEquals(1, asked.intValue)
    }

    /** §3.10: the title, the header and the switches read as what they do. */
    @Test
    fun talkBackSemantics() {
        val runtime = start()
        val crew = runtime.conversation("Trail Crew")
        compose.runOnUiThread { shell.openDetail(UmshKey.Thread(crew.address)) }
        waitFor(Tags.THREAD_TITLE)
        val title = compose.onNodeWithTag(Tags.THREAD_TITLE).fetchSemanticsNode().config
        assertEquals(context.getString(R.string.conversation_info_open), title[SemanticsActions.OnClick].label)
        compose.onNodeWithTag(Tags.THREAD_TITLE).performSemanticsAction(SemanticsActions.OnClick)
        waitFor(Tags.CONVERSATION_INFO)
        val header = compose.onNodeWithTag(Tags.CONVERSATION_INFO_CHANNEL).fetchSemanticsNode().config
        assertEquals(context.getString(R.string.conversation_info_open_channel), header[SemanticsActions.OnClick].label)
        assertEquals(Role.Button, header[SemanticsProperties.Role])
        val spoken = header.getOrNull(SemanticsProperties.Text).orEmpty().joinToString(" ") { it.text }
        assertTrue(spoken, "Trail Crew" in spoken && context.getString(R.string.channel_kind_named) in spoken)
        val switch = compose.onNodeWithTag(Tags.CONVERSATION_INFO_NOTIFICATIONS).fetchSemanticsNode().config
        assertEquals(Role.Switch, switch[SemanticsProperties.Role])
        assertTrue(switch.getOrNull(SemanticsProperties.Text).orEmpty().any { it.text == context.getString(R.string.peer_section_notifications) })
        val messages = compose.onNodeWithTag(Tags.CONVERSATION_INFO_MESSAGES).fetchSemanticsNode().config
        val read = messages.getOrNull(SemanticsProperties.Text).orEmpty().joinToString(" ") { it.text }
        assertTrue(read, context.getString(R.string.conversation_info_messages) in read && read.any { it.isDigit() })
    }

    private companion object {
        const val TIMEOUT = 30_000L
    }
}
