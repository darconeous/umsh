package com.voria.umsh.features

import android.Manifest
import android.content.ClipboardManager
import android.content.Intent
import android.os.Build
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.longClick
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.test.performTouchInput
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.Tags
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.designsystem.Copier
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.services.preferences.OnboardingStep
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Settings › Channels and New channel chat in the real activity over the
 * staged air (`channels.svg` 1–13, `new-channel-chat.svg` 1–3,
 * `conversation-list.svg` 6). Staging starts with Public, EMERGENCY,
 * Trail Crew (a named channel) and Crew Leads (private) joined. Nothing
 * here sends; the only air is staged.
 */
class ChannelsTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createEmptyComposeRule()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext

    private var scenario: ActivityScenario<MainActivity>? = null

    @Before
    fun noNotificationAsk() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
        runBlocking { fresh.host.preferences.setNotificationsAsked() }
    }

    @After
    fun close() {
        scenario?.close()
    }

    private fun launch(): AppRuntime {
        scenario = ActivityScenario.launch(Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_STAGING, true))
        return runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime.setOnboarding(OnboardingStep.Done).await()
            withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
            withTimeout(TIMEOUT) { ready.runtime.appState.first { state -> state != null && state.channels.any { it.name == "Crew Leads" } && state.channels.any { it.canonicalName == "public" } } }
            ready.runtime
        }
    }

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitFor(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun waitGone(tag: String) = compose.waitUntil(TIMEOUT) { !present(tag) }

    private fun back() = UiDevice.getInstance(instrumentation).pressBack()

    private fun AppRuntime.channel(name: String): ChannelSummary = appState.value!!.channels.first { it.name == name || it.canonicalName == name.lowercase() }

    private fun texts(tag: String): String = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().joinToString(" ") { node ->
        (node.config.getOrNull(SemanticsProperties.Text).orEmpty().map { it.text } + listOfNotNull(node.config.getOrNull(SemanticsProperties.EditableText)?.text)).joinToString(" ")
    }

    private fun openChannels() {
        waitFor(Tags.NAV_SETTINGS)
        compose.onAllNodesWithTag(Tags.NAV_SETTINGS)[0].performClick()
        waitFor(Tags.SETTINGS_CHANNELS)
        compose.onNodeWithTag(Tags.SETTINGS_CHANNELS).performClick()
        waitFor(Tags.CHANNELS_LIST)
    }

    /** [text] somewhere in the node tagged [tag], merged or not. */
    private fun assertTextUnder(tag: String, text: String) {
        val inside = hasText(text, substring = true) and (hasTestTag(tag) or hasAnyAncestor(hasTestTag(tag)))
        assertTrue("“$text” under $tag", compose.onAllNodes(inside, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty())
    }

    private fun row(id: String): SemanticsNodeInteraction = compose.onNodeWithTag(Tags.channelRow(id))

    private fun openJoin() {
        compose.onNodeWithTag(Tags.CHANNELS_ADD).performClick()
        waitFor(Tags.CHANNELS_MENU_JOIN)
        compose.onNodeWithTag(Tags.CHANNELS_MENU_JOIN).performClick()
        waitFor(Tags.CHANNEL_JOIN_FIELD)
    }

    private fun lookUp(input: String) {
        compose.onNodeWithTag(Tags.CHANNEL_JOIN_FIELD).performTextReplacement(input)
        compose.onNodeWithTag(Tags.CHANNEL_LOOK_UP).performClick()
        waitFor(Tags.CHANNEL_PREVIEW)
    }

    private fun primaryClip(): Pair<String?, Boolean> {
        var text: String? = null
        var sensitive = false
        instrumentation.runOnMainSync {
            val clipboard = context.getSystemService(ClipboardManager::class.java)
            text = clipboard.primaryClip?.getItemAt(0)?.text?.toString()
            sensitive = clipboard.primaryClipDescription?.extras?.getBoolean(Copier.SENSITIVE_EXTRA) == true
        }
        return text to sensitive
    }

    /** Boards 1, 4, 10, 12 (private) and 13: the row count, create, the page, Share's invitation copied as sensitive, and leaving. */
    @Test
    fun createSharePrivatelyAndLeave() {
        val runtime = launch()
        waitFor(Tags.NAV_SETTINGS)
        compose.onAllNodesWithTag(Tags.NAV_SETTINGS)[0].performClick()
        waitFor(Tags.SETTINGS_CHANNELS)
        val joined = runtime.appState.value!!.channels.count { it.joinedPhone }
        val count = context.resources.getQuantityString(R.plurals.settings_channels_joined, joined, joined.toString())
        assertTextUnder(Tags.SETTINGS_CHANNELS, count)
        compose.onNodeWithTag(Tags.SETTINGS_CHANNELS).performClick()
        waitFor(Tags.CHANNELS_LIST)
        // Board 1: the muted bell on Public, none on Trail Crew.
        val public = runtime.channel("Public")
        compose.onNode(hasTestTag(Tags.ROW_MUTED) and hasAnyAncestor(hasTestTag(Tags.channelRow(public.id))), useUnmergedTree = true).assertExists()
        compose.onNode(hasTestTag(Tags.ROW_MUTED) and hasAnyAncestor(hasTestTag(Tags.channelRow(runtime.channel("Trail Crew").id))), useUnmergedTree = true).assertDoesNotExist()

        compose.onNodeWithTag(Tags.CHANNELS_ADD).performClick()
        waitFor(Tags.CHANNELS_MENU_CREATE)
        compose.onNodeWithTag(Tags.CHANNELS_MENU_CREATE).performClick()
        waitFor(Tags.CHANNEL_CREATE_NAME)
        compose.onNodeWithTag(Tags.CHANNEL_CREATE_NAME).performTextReplacement("Ridge SAR")
        compose.onNodeWithTag(Tags.CHANNEL_CREATE_ACTION).performClick()
        waitFor(Tags.CHANNEL_PAGE)
        waitGone(Tags.CHANNEL_CREATE)
        assertEquals("Ridge SAR", texts(Tags.CHANNEL_PAGE_TITLE))
        assertEquals(context.getString(R.string.channel_kind_private), texts(Tags.CHANNEL_PAGE_KIND))
        val ridge = runtime.channel("Ridge SAR")
        assertEquals(ChannelKind.PrivateKey, ridge.kind)
        // A private channel has no "How this channel works".
        compose.onNodeWithTag(Tags.CHANNEL_PAGE_STATEMENTS).assertDoesNotExist()

        // Board 13: the warning, Copy invitation, and a sensitive clip.
        compose.onNodeWithTag(Tags.CHANNEL_VERB_SHARE).performClick()
        waitFor(Tags.CHANNEL_SHARE_WARNING)
        assertTextUnder(Tags.QR_COPY_LINK, context.getString(R.string.copy_invitation))
        compose.onNodeWithTag(Tags.QR_COPY_LINK).performScrollTo().performClick()
        compose.waitForIdle()
        val (invitation, sensitive) = primaryClip()
        android.util.Log.i(TAG, "invitation clip sensitive=$sensitive api=${Build.VERSION.SDK_INT}")
        assertTrue(invitation, invitation?.startsWith("umsh:gk:") == true)
        assertTrue("the invitation is copied as sensitive", sensitive)
        back()
        waitGone(Tags.QR_SHEET)

        // Board 12, private: the key goes, and the page closes.
        compose.onNodeWithTag(Tags.CHANNEL_PAGE_LEAVE).performScrollTo().performClick()
        waitFor(Tags.CONFIRM_DIALOG)
        assertTextUnder(Tags.CONFIRM_DIALOG, context.getString(R.string.leave_channel_private_body))
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        waitFor(Tags.CHANNELS_LIST)
        waitGone(Tags.CHANNEL_PAGE)
        compose.waitUntil(TIMEOUT) { runtime.appState.value!!.channels.none { it.id == ridge.id } }
        row(ridge.id).assertDoesNotExist()
    }

    /** Boards 6, 10 (alias), 11, 12 (named) and 13's variant: join by name with an alias, its page, its link, and leaving. */
    @Test
    fun joinPublicByNameShareItsLinkAndLeave() {
        val runtime = launch()
        openChannels()
        openJoin()
        lookUp("hike-club")
        assertEquals(context.getString(R.string.channel_preview_public), texts(Tags.CHANNEL_PREVIEW_KIND))
        assertEquals(context.getString(R.string.channel_preview_public_line), texts(Tags.CHANNEL_PREVIEW_LINE))
        compose.onNodeWithTag(Tags.CHANNEL_KEY_DOTS).assertDoesNotExist()
        compose.onNodeWithTag(Tags.CHANNEL_ALIAS_FIELD).performTextReplacement("Hikers")
        compose.onNodeWithTag(Tags.CHANNEL_JOIN_ACTION).assertIsEnabled().performClick()
        waitGone(Tags.CHANNEL_JOIN)
        waitFor(Tags.CHANNELS_LIST)
        compose.waitUntil(TIMEOUT) { runtime.appState.value!!.channels.any { it.canonicalName == "hike-club" && it.joinedPhone } }
        val hike = runtime.appState.value!!.channels.first { it.canonicalName == "hike-club" }
        assertEquals("Hikers", hike.alias)
        row(hike.id).performScrollTo().performClick()
        waitFor(Tags.CHANNEL_PAGE)
        assertEquals("Hikers", texts(Tags.CHANNEL_PAGE_TITLE))
        assertEquals("Hikers", texts(Tags.CHANNEL_PAGE_ALIAS))

        // Alias edited in its dialog.
        compose.onNodeWithTag(Tags.CHANNEL_PAGE_ALIAS_ROW).performScrollTo().performClick()
        waitFor(Tags.RENAME_FIELD)
        compose.onNodeWithTag(Tags.RENAME_FIELD).performTextReplacement("Hike Club")
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        compose.waitUntil(TIMEOUT) { texts(Tags.CHANNEL_PAGE_TITLE) == "Hike Club" }

        // Board 13 variant: the name link, no warning, not sensitive.
        compose.onNodeWithTag(Tags.CHANNEL_VERB_SHARE).performClick()
        waitFor(Tags.QR_SHEET)
        compose.onNodeWithTag(Tags.CHANNEL_SHARE_WARNING).assertDoesNotExist()
        assertTextUnder(Tags.QR_COPY_LINK, context.getString(R.string.copy_link))
        compose.onNodeWithTag(Tags.QR_COPY_LINK).performScrollTo().performClick()
        compose.waitForIdle()
        val (link, sensitive) = primaryClip()
        assertTrue(link, link?.startsWith("umsh:") == true && link.contains("hike-club"))
        assertFalse("a name link is not sensitive", sensitive)
        back()
        waitGone(Tags.QR_SHEET)

        // Board 12, named: joined again by name.
        compose.onNodeWithTag(Tags.CHANNEL_PAGE_LEAVE).performScrollTo().performClick()
        waitFor(Tags.CONFIRM_DIALOG)
        assertTextUnder(Tags.CONFIRM_DIALOG, context.getString(R.string.leave_channel_named_body))
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        waitFor(Tags.CHANNELS_LIST)
        compose.waitUntil(TIMEOUT) { runtime.appState.value!!.channels.none { it.id == hike.id && it.joinedPhone } }

        // Board 11: Public's statements.
        row(runtime.channel("Public").id).performClick()
        waitFor(Tags.CHANNEL_PAGE_STATEMENTS)
        assertTextUnder(Tags.CHANNEL_PAGE_STATEMENTS, context.getString(R.string.channel_public_identified))
    }

    /** Boards 7–8: a private invitation, its key behind the eye (not shown again after a recreation), already joined → Update. */
    @Test
    fun joinPrivateInvitationAlreadyJoinedAndTheEye() {
        val runtime = launch()
        val leads = runtime.channel("Crew Leads")
        val invitation = runBlocking { runtime.channelInvitation(leads.id).await() }
        openChannels()
        openJoin()
        lookUp(invitation)
        assertEquals(context.getString(R.string.channel_preview_private), texts(Tags.CHANNEL_PREVIEW_KIND))
        waitFor(Tags.CHANNEL_PREVIEW_JOINED)
        compose.onNodeWithTag(Tags.CHANNEL_PREVIEW_LINE).assertDoesNotExist()
        assertTextUnder(Tags.CHANNEL_JOIN_ACTION, context.getString(R.string.channel_update))
        compose.onNodeWithTag(Tags.CHANNEL_KEY_DOTS).assertExists()
        compose.onNodeWithTag(Tags.CHANNEL_KEY_VALUE).assertDoesNotExist()
        compose.onNodeWithTag(Tags.CHANNEL_KEY_EYE).performClick()
        waitFor(Tags.CHANNEL_KEY_VALUE)
        compose.onNodeWithTag(Tags.CHANNEL_KEY_DOTS).assertDoesNotExist()

        scenario!!.recreate()
        waitFor(Tags.CHANNEL_PREVIEW)
        compose.onNodeWithTag(Tags.CHANNEL_KEY_DOTS).assertExists()
        compose.onNodeWithTag(Tags.CHANNEL_KEY_VALUE).assertDoesNotExist()
        // The invitation comes back within this process, though not in saved state (ChannelKeyTextTest).
        assertEquals(invitation, texts(Tags.CHANNEL_JOIN_FIELD).trim())

        // Update keeps one channel.
        compose.onNodeWithTag(Tags.CHANNEL_JOIN_ACTION).performClick()
        waitGone(Tags.CHANNEL_JOIN)
        waitFor(Tags.CHANNELS_LIST)
        assertEquals(1, runtime.appState.value!!.channels.count { it.name == "Crew Leads" && it.joinedPhone })
    }

    /**
     * The alias a held channel has is filled in for its lookup only: another
     * channel looked up next starts empty, a cleared alias stays cleared
     * across a recreation, and Update then clears it.
     */
    @Test
    fun aFilledInAliasStaysWithItsChannel() {
        val runtime = launch()
        val hike = runBlocking { runtime.joinChannel("hike-club", "Hikers", openConversation = false).await() }.channelId
        openChannels()
        openJoin()
        lookUp("hike-club")
        assertEquals("Hikers", texts(Tags.CHANNEL_ALIAS_FIELD).trim())
        compose.onNodeWithTag(Tags.CHANNEL_JOIN_FIELD).performTextReplacement("ridge-runners")
        compose.onNodeWithTag(Tags.CHANNEL_ALIAS_FIELD).assertDoesNotExist()
        compose.onNodeWithTag(Tags.CHANNEL_LOOK_UP).performClick()
        waitFor(Tags.CHANNEL_PREVIEW)
        compose.waitUntil(TIMEOUT) { texts(Tags.CHANNEL_PREVIEW_NAME).contains("ridge-runners", ignoreCase = true) }
        assertEquals("", texts(Tags.CHANNEL_ALIAS_FIELD).replace(context.getString(R.string.channel_alias), "").trim())

        lookUp("hike-club")
        compose.waitUntil(TIMEOUT) { texts(Tags.CHANNEL_ALIAS_FIELD).contains("Hikers") }
        compose.onNodeWithTag(Tags.CHANNEL_ALIAS_FIELD).performTextReplacement("")
        scenario!!.recreate()
        waitFor(Tags.CHANNEL_PREVIEW)
        assertFalse(texts(Tags.CHANNEL_ALIAS_FIELD).contains("Hikers"))
        compose.onNodeWithTag(Tags.CHANNEL_JOIN_ACTION).performClick()
        waitGone(Tags.CHANNEL_JOIN)
        compose.waitUntil(TIMEOUT) { runtime.appState.value!!.channels.first { it.id == hike }.alias == null }
    }

    /** Board 9: a different channel called the same is a conflict, and joining it keeps both. */
    @Test
    fun aNameConflictJoinsASecondChannel() {
        val runtime = launch()
        val invitation = runBlocking {
            val fire = runtime.createPrivateChannel("Fire").await()
            val text = runtime.channelInvitation(fire).await()
            runtime.leaveChannel(fire).await()
            runtime.createPrivateChannel("Fire").await()
            text
        }
        openChannels()
        openJoin()
        lookUp(invitation)
        waitFor(Tags.CHANNEL_PREVIEW_CONFLICT)
        compose.onNodeWithTag(Tags.CHANNEL_PREVIEW_JOINED).assertDoesNotExist()
        assertTextUnder(Tags.CHANNEL_JOIN_ACTION, context.getString(R.string.channel_join))
        compose.onNodeWithTag(Tags.CHANNEL_ALIAS_FIELD).performTextReplacement("Fire 2")
        compose.onNodeWithTag(Tags.CHANNEL_JOIN_ACTION).performClick()
        waitGone(Tags.CHANNEL_JOIN)
        compose.waitUntil(TIMEOUT) { runtime.appState.value!!.channels.count { it.name == "Fire" && it.joinedPhone } == 2 }
    }

    /** Long press → Leave channel on Public, then Join's suggestion brings it back (board 5). */
    @Test
    fun leavePublicFromTheListAndRejoinFromTheSuggestions() {
        val runtime = launch()
        val public = runtime.channel("Public")
        openChannels()
        row(public.id).performTouchInput { longClick() }
        waitFor(Tags.CHANNEL_MENU_LEAVE)
        compose.onNodeWithTag(Tags.CHANNEL_MENU_LEAVE).performClick()
        waitFor(Tags.CONFIRM_DIALOG)
        assertTextUnder(Tags.CONFIRM_DIALOG, context.getString(R.string.leave_channel_named_body))
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        compose.waitUntil(TIMEOUT) { !present(Tags.channelRow(public.id)) }
        assertTrue(runtime.appState.value!!.channelConversations.none { it.channel.id == public.id })

        openJoin()
        waitFor(Tags.suggestedChannel(public.id))
        compose.onNodeWithTag(Tags.suggestedChannel(public.id)).performClick()
        waitGone(Tags.CHANNEL_JOIN)
        waitFor(Tags.channelRow(public.id))
        assertTrue(runtime.channel("Public").joinedPhone)
    }

    /** A full channel table: the create's failure dialog, and nothing kept. */
    @Test
    fun aFullTableIsAFailureDialog() {
        val runtime = launch()
        runBlocking {
            var made = 0
            while (true) {
                try {
                    runtime.createPrivateChannel("Full $made").await()
                    made++
                } catch (_: MobileAppException.ChannelTableFull) {
                    break
                }
                check(made < 64) { "never full" }
            }
        }
        val before = runtime.appState.value!!.channels.count { it.joinedPhone }
        openChannels()
        compose.onNodeWithTag(Tags.CHANNELS_ADD).performClick()
        waitFor(Tags.CHANNELS_MENU_CREATE)
        compose.onNodeWithTag(Tags.CHANNELS_MENU_CREATE).performClick()
        waitFor(Tags.CHANNEL_CREATE_NAME)
        compose.onNodeWithTag(Tags.CHANNEL_CREATE_NAME).performTextReplacement("One more")
        compose.onNodeWithTag(Tags.CHANNEL_CREATE_ACTION).performClick()
        waitFor(Tags.FAILURE_DIALOG)
        assertTextUnder(Tags.FAILURE_DIALOG, context.getString(R.string.channel_not_created_title))
        compose.onNodeWithTag(Tags.FAILURE_OK).performClick()
        compose.onNodeWithTag(Tags.CHANNEL_CREATE).assertExists()
        runBlocking { runtime.reload(full = false).await() }
        assertEquals(before, runtime.appState.value!!.channels.count { it.joinedPhone })
        assertTrue(runtime.appState.value!!.channels.none { it.name == "One more" })
    }

    /** `new-channel-chat.svg` 1–3: the chooser lists joined channels without a conversation; one opens; Join a channel… opens its conversation; none left says so. */
    @Test
    fun newChannelChat() {
        val runtime = launch()
        val ridge = runBlocking { runtime.createPrivateChannel("Ridge SAR").await() }
        compose.waitUntil(TIMEOUT) { runtime.appState.value!!.channels.any { it.id == ridge } }
        val without = runtime.appState.value!!.channels.filter { it.joinedPhone && it.conversationAddress == null }.map { it.id }

        fun openChooser() {
            waitFor(Tags.CONVERSATIONS_NEW_CHAT)
            compose.onNodeWithTag(Tags.CONVERSATIONS_NEW_CHAT).performClick()
            waitFor(Tags.NEW_CHAT_CHANNEL)
            compose.onNodeWithTag(Tags.NEW_CHAT_CHANNEL).performClick()
            waitFor(Tags.CHANNEL_CHOOSER)
            waitGone(Tags.NEW_CHAT_SHEET)
        }

        openChooser()
        for (id in without) compose.onNodeWithTag(Tags.chooserChannel(id)).assertExists()
        // A chooser row is one button for TalkBack, read with its name, kind and identifier.
        val choice = compose.onNodeWithTag(Tags.chooserChannel(ridge)).fetchSemanticsNode()
        assertEquals(Role.Button, choice.config[SemanticsProperties.Role])
        val ridgeChannel = runtime.appState.value!!.channels.first { it.id == ridge }
        val read = choice.config.getOrNull(SemanticsProperties.Text).orEmpty().joinToString(" ") { it.text }
        assertTrue(read, "Ridge SAR" in read && ridgeChannel.channelIdHex in read)
        for (channel in runtime.appState.value!!.channels.filter { it.conversationAddress != null }) {
            compose.onNodeWithTag(Tags.chooserChannel(channel.id)).assertDoesNotExist()
        }
        compose.onNodeWithTag(Tags.chooserChannel(ridge)).performScrollTo().performClick()
        waitFor(Tags.COMPOSER_FIELD)
        waitGone(Tags.CHANNEL_CHOOSER)
        compose.waitUntil(TIMEOUT) { runtime.appState.value!!.channels.first { it.id == ridge }.conversationAddress != null }
        assertTextUnder(Tags.THREAD_TITLE, "Ridge SAR")
        back()
        waitFor(Tags.CONVERSATIONS_ROOT)

        // Join a channel… joins and opens its conversation; nothing suggested there.
        openChooser()
        compose.onNodeWithTag(Tags.CHANNEL_CHOOSER_JOIN).performClick()
        waitFor(Tags.CHANNEL_JOIN_FIELD)
        compose.onAllNodesWithTag(Tags.suggestedChannel(runtime.channel("Public").id)).fetchSemanticsNodes().let { assertTrue(it.isEmpty()) }
        lookUp("hike-club")
        compose.onNodeWithTag(Tags.CHANNEL_JOIN_ACTION).performClick()
        waitFor(Tags.COMPOSER_FIELD)
        waitGone(Tags.CHANNEL_JOIN)
        val hike = runtime.appState.value!!.channels.first { it.canonicalName == "hike-club" }
        assertNotNull(hike.conversationAddress)
        back()
        waitFor(Tags.CONVERSATIONS_ROOT)

        // Board 3: every joined channel has its conversation.
        runBlocking {
            for (channel in runtime.appState.value!!.channels.filter { it.joinedPhone && it.conversationAddress == null }) {
                runtime.openChannelConversation(channel.id).await()
            }
        }
        compose.waitUntil(TIMEOUT) { runtime.appState.value!!.channels.none { it.joinedPhone && it.conversationAddress == null } }
        openChooser()
        waitFor(Tags.CHANNEL_CHOOSER_NONE)
        compose.onNodeWithTag(Tags.CHANNEL_CHOOSER_JOIN).assertExists()
        back()
        waitGone(Tags.CHANNEL_CHOOSER)
    }

    /** §3.10 through the semantics tree: the long-press label, the key's eye and dots, and the problem line's live region. */
    @Test
    fun talkBackSemantics() {
        val runtime = launch()
        val leads = runtime.channel("Crew Leads")
        val invitation = runBlocking { runtime.channelInvitation(leads.id).await() }
        openChannels()
        val rowNode = row(leads.id).fetchSemanticsNode()
        assertEquals(context.getString(R.string.channel_actions), rowNode.config[SemanticsActions.OnLongClick].label)
        val spoken = rowNode.config.getOrNull(SemanticsProperties.Text).orEmpty().joinToString(" ") { it.text }
        assertTrue(spoken, "Crew Leads" in spoken && context.getString(R.string.channel_kind_private) in spoken && leads.channelIdHex in spoken)

        openJoin()
        compose.onNodeWithTag(Tags.CHANNEL_JOIN_FIELD).performTextReplacement("Café")
        compose.onNodeWithTag(Tags.CHANNEL_LOOK_UP).performClick()
        waitFor(Tags.CHANNEL_JOIN_PROBLEM)
        assertEquals(LiveRegionMode.Polite, compose.onNodeWithTag(Tags.CHANNEL_JOIN_PROBLEM, useUnmergedTree = true).fetchSemanticsNode().config[SemanticsProperties.LiveRegion])
        assertTextUnder(Tags.CHANNEL_JOIN_PROBLEM, context.getString(R.string.channel_input_not_ascii))

        lookUp(invitation)
        val dots = compose.onNodeWithTag(Tags.CHANNEL_KEY_DOTS, useUnmergedTree = true).fetchSemanticsNode()
        assertEquals(listOf(context.getString(R.string.channel_key_hidden)), dots.config[SemanticsProperties.ContentDescription])
        val eye = compose.onNodeWithTag(Tags.CHANNEL_KEY_EYE).fetchSemanticsNode()
        val minimum = 48 * context.resources.displayMetrics.density - 1
        assertTrue("the eye is a 48 dp target", eye.touchBoundsInRoot.width >= minimum && eye.touchBoundsInRoot.height >= minimum)
        assertTextUnderDescription(Tags.CHANNEL_KEY_EYE, context.getString(R.string.channel_key_show))
        compose.onNodeWithTag(Tags.CHANNEL_KEY_EYE).performClick()
        waitFor(Tags.CHANNEL_KEY_VALUE)
        assertTextUnderDescription(Tags.CHANNEL_KEY_EYE, context.getString(R.string.channel_key_hide))
    }

    private fun assertTextUnderDescription(tag: String, description: String) {
        val node = compose.onNodeWithTag(tag).fetchSemanticsNode()
        val all = (listOf(node) + node.children).flatMap { it.config.getOrNull(SemanticsProperties.ContentDescription).orEmpty() }
        assertTrue("$description in $all", description in all)
    }

    private companion object {
        const val TAG = "ChannelsTest"
        const val TIMEOUT = 30_000L
    }
}
