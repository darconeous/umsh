package com.voria.umsh.features

import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toPixelMap
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.longClick
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeDown
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
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
import com.voria.umsh.designsystem.FixedColors
import com.voria.umsh.designsystem.LocalWindowOverride
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.conversations.MenuItem
import com.voria.umsh.features.conversations.TranscriptWindow
import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.DeliveryState
import com.voria.umsh.models.Presence
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import com.voria.umsh.services.radio.StagingRadioConnection
import java.io.File
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Sending (P2c) over real cores: `composer.svg`, `bubbles.svg`,
 * `replies-reactions.svg` and `threads.svg` boards 2 and 5. With
 * `-e shots <light|dark>` each board is also captured into the app's
 * external files, under `shots/`.
 */
class SendingTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val suffix: String? get() = InstrumentationRegistry.getArguments().getString("shots")

    private val air: StagingRadioConnection get() = checkNotNull(fresh.host.stagingRadio.value) { "no staged air" }

    private fun shot(name: String) {
        val suffix = suffix ?: return
        // The boards show no keyboard; the field keeps its focus and cursor.
        compose.runOnUiThread {
            val window = compose.activity.window
            WindowCompat.getInsetsController(window, window.decorView).hide(WindowInsetsCompat.Type.ime())
        }
        compose.waitForIdle()
        Thread.sleep(SETTLE_MS)
        compose.waitForIdle()
        Thread.sleep(SETTLE_MS)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val bitmap = instrumentation.uiAutomation.takeScreenshot() ?: return
        val directory = File(instrumentation.targetContext.getExternalFilesDir(null), "shots").apply { mkdirs() }
        File(directory, "$name-$suffix.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    private fun runtime(staging: Boolean, linkId: String? = null): AppRuntime = runBlocking {
        fresh.host.preferences.setFallbackScheme(true)
        linkId?.let { fresh.host.preferences.radioRegistry.bind(BoundRadio(RadioKind.Tcp, it, name = RADIO_NAME)) }
        fresh.host.ensureRuntime(staging)
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        val runtime = ready.runtime
        withTimeout(TIMEOUT) { runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        withTimeout(TIMEOUT) { runtime.appState.first { state -> state?.channelConversations?.isNotEmpty() == true } }
        if (staging) withTimeout(TIMEOUT) { runtime.radio.first { it?.carriesThisPhone == true } }
        runtime
    }

    private fun show(runtime: AppRuntime) {
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
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
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed()
    }

    private fun open(address: String) {
        compose.runOnUiThread { shell.openDetail(UmshKey.Thread(address)) }
        compose.onNodeWithTag(Tags.THREAD).assertIsDisplayed()
        waitFor { compose.onAllNodesWithTag(Tags.COMPOSER_FIELD).fetchSemanticsNodes().isNotEmpty() }
    }

    private fun waitFor(condition: () -> Boolean) = compose.waitUntil(TIMEOUT, condition)

    private fun shown(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()

    private fun messages(runtime: AppRuntime, address: String): List<ChatMessage> = runBlocking {
        runtime.transcriptNewest(address, TranscriptWindow.PAGE_SIZE).messages
    }

    private fun waitForMessage(runtime: AppRuntime, address: String, predicate: (ChatMessage) -> Boolean): ChatMessage {
        var found: ChatMessage? = null
        waitFor {
            found = messages(runtime, address).lastOrNull(predicate)
            found != null
        }
        return checkNotNull(found)
    }

    private fun direct(runtime: AppRuntime): String =
        runtime.appState.value!!.directConversations.first { it.lastMessage != null }.address

    private fun type(text: String) {
        compose.onNodeWithTag(Tags.COMPOSER_FIELD).performTextReplacement(text)
    }

    private fun send(runtime: AppRuntime, address: String, text: String): ChatMessage {
        type(text)
        compose.onNodeWithTag(Tags.COMPOSER_SEND).performClick()
        return waitForMessage(runtime, address) { it.isOutbound && it.body == text }
    }

    private fun scrollTo(key: String) {
        compose.onNodeWithTag(Tags.TRANSCRIPT).performScrollToNode(hasTestTag(Tags.message(key)))
    }

    private fun captionOf(key: String): List<String> =
        compose.onNodeWithTag(Tags.message(key)).fetchSemanticsNode().config
            .getOrNull(SemanticsProperties.Text).orEmpty().map { it.text }

    private fun longPress(key: String) {
        scrollTo(key)
        // On the bubble: beside a failed one the row's middle is its retry button.
        compose.onNode(hasTestTag(Tags.BUBBLE) and hasAnyAncestor(hasTestTag(Tags.message(key))), useUnmergedTree = true)
            .performTouchInput { longClick() }
        waitFor { shown(Tags.MESSAGE_MENU) }
    }

    /** Swiped down, as a user lets a sheet go. */
    private fun closeMenu() {
        compose.onNodeWithTag(Tags.MESSAGE_MENU).performTouchInput { swipeDown() }
        waitFor { !shown(Tags.MESSAGE_MENU) }
    }

    private fun menuItem(item: MenuItem) {
        compose.onNodeWithTag(Tags.menuItem(item.name)).performClick()
        waitFor { !shown(Tags.MESSAGE_MENU) }
    }

    /**
     * `composer.svg` boards 1, 2, 3, 7 and 8: empty, typing (encrypted and
     * open channel), a long draft, and editing, which sends the edit and
     * leaves the draft alone.
     */
    @Test
    fun theComposerSendsEditsAndKeepsTheDraft() {
        val runtime = runtime(staging = true)
        show(runtime)
        val address = direct(runtime)
        open(address)
        assertTrue(!shown(Tags.COMPOSER_SEND))
        shot("composer-1-empty")
        type("Copy that")
        compose.onNodeWithTag(Tags.COMPOSER_SEND).assertIsDisplayed().assertIsEnabled()
        shot("composer-2-encrypted")
        type((1..9).joinToString("\n") { "Line $it of a long draft about the trail" })
        shot("composer-7-long")

        val mine = send(runtime, address, "South gate.")
        waitFor { (compose.onNodeWithTag(Tags.COMPOSER_FIELD).fetchSemanticsNode().config
            .getOrNull(SemanticsProperties.EditableText)?.text ?: "x").isEmpty() }
        waitFor { messages(runtime, address).last { it.ref == mine.ref }.actions.edit }
        type("half a thought")
        longPress(mine.ref.key)
        menuItem(MenuItem.Edit)
        compose.onNodeWithTag(Tags.COMPOSER_STRIP).assertIsDisplayed()
        compose.onNodeWithTag(Tags.COMPOSER_EDIT_FIELD).performTextReplacement("North gate instead.")
        shot("composer-8-editing")
        compose.onNodeWithTag(Tags.COMPOSER_SEND).performClick()
        waitForMessage(runtime, address) { it.ref == mine.ref && it.body == "North gate instead." && it.isEdited }
        waitFor { !shown(Tags.COMPOSER_STRIP) }
        val draft = compose.onNodeWithTag(Tags.COMPOSER_FIELD).fetchSemanticsNode().config
            .getOrNull(SemanticsProperties.EditableText)?.text
        assertEquals("half a thought", draft)

        // An open channel's Send is green.
        val public = runtime.appState.value!!.channelConversations.firstOrNull { it.channel.canonicalName == "public" }
        if (public != null) {
            compose.runOnUiThread { shell.closeThread(UmshKey.Thread(address)) }
            open(public.address)
            type("See you at 7")
            shot("composer-3-open-channel")
        }
    }

    /** `composer.svg` board 4: Send in violet while a forward-secret session is held. */
    @Test
    fun forwardSecrecyTurnsSendViolet() {
        val runtime = runtime(staging = true)
        show(runtime)
        val address = direct(runtime)
        runBlocking { runtime.send(address, "Gate code is 4471", forwardSecret = true).await() }
        val held = runBlocking {
            withTimeoutOrNull(TIMEOUT) { runtime.forwardSecretConversations.first { address in it } }
        }
        assertNotNull("no forward-secret session was held", held)
        open(address)
        type("Gate code is 4471")
        waitFor { sendColor() == FixedColors.SentForwardSecret }
        shot("composer-4-forward-secret")
    }

    /** Send's fill, read beside its glyph: the button is a 44 dp circle, the glyph 22 dp. */
    private fun sendColor(): Color {
        val image = compose.onNodeWithTag(Tags.COMPOSER_SEND).captureToImage()
        val inset = with(compose.density) { 15.dp.roundToPx() }
        return image.toPixelMap()[image.width / 2 - inset, image.height / 2]
    }

    /** `composer.svg` boards 5 and 9: a connecting radio dims Send; tapping it explains. */
    @Test
    fun aConnectingRadioDimsSendAndExplains() {
        val runtime = runtime(staging = false, linkId = "scripted:connecting")
        show(runtime)
        val address = runtime.appState.value!!.channelConversations.first().address
        open(address)
        type("Ten minutes out.")
        compose.onNodeWithTag(Tags.COMPOSER_SEND).assertIsDisplayed().assertIsEnabled()
        shot("composer-5-connecting")
        compose.onNodeWithTag(Tags.COMPOSER_SEND).performClick()
        waitFor { shown(Tags.THREAD_ALERT) }
        compose.onNode(hasText(context.getString(R.string.message_not_sent_connecting))).assertIsDisplayed()
        shot("composer-9-not-sent")
        compose.onNodeWithTag(Tags.FAILURE_OK).performClick()
        // Nothing was queued; the words stay.
        assertTrue(messages(runtime, address).none { it.body == "Ten minutes out." })
    }

    /** `composer.svg` board 6: with the radio not there, Send is blocked and Connect radio offered. */
    @Test
    fun withNoRadioSendIsBlocked() {
        val runtime = runtime(staging = false, linkId = "scripted:waiting")
        show(runtime)
        open(runtime.appState.value!!.channelConversations.first().address)
        type("Ten minutes out.")
        waitFor { shown(Tags.COMPOSER_BLOCKED) }
        compose.onNodeWithTag(Tags.COMPOSER_SEND).assertIsNotEnabled()
        compose.onNodeWithTag(Tags.COMPOSER_CONNECT_RADIO).assertIsDisplayed()
        shot("composer-6-no-radio")
        compose.onNodeWithTag(Tags.COMPOSER_CONNECT_RADIO).performClick()
        waitFor { shown(Tags.RADIO_DETAIL) }
    }

    /**
     * `bubbles.svg` boards 1, 3, 4 and 5: captions, the long-press menu,
     * the delete confirmation, and a failed message tried again.
     */
    @Test
    fun captionsMenuDeleteAndRetry() {
        val runtime = runtime(staging = true)
        show(runtime)
        val address = direct(runtime)
        open(address)
        val delivered = send(runtime, address, "Ten minutes out.")
        waitFor { context.getString(R.string.caption_delivered) in captionOf(delivered.ref.key) }

        air.setTransmissionsFailing(true)
        val failed = send(runtime, address, "Gate code is 4471")
        val retry = waitForMessage(runtime, address) {
            it.ref == failed.ref && it.actions.resend != null &&
                (it.delivery == DeliveryState.Failed || it.delivery == DeliveryState.Undelivered)
        }
        scrollTo(retry.ref.key)
        waitFor { shown(Tags.RETRY_MESSAGE) }
        shot("bubbles-1-captions")

        // The menu of a delivered message of mine: reactions, and everything it offers.
        longPress(delivered.ref.key)
        compose.onNodeWithTag(Tags.MESSAGE_MENU_REACTIONS).assertExists()
        for (item in listOf(MenuItem.Reply, MenuItem.Copy, MenuItem.Edit, MenuItem.Details, MenuItem.Delete)) {
            compose.onNodeWithTag(Tags.menuItem(item.name)).assertExists()
        }
        shot("bubbles-3-long-press")
        closeMenu()
        // A failed one offers to go again.
        longPress(retry.ref.key)
        assertTrue(shown(Tags.menuItem(MenuItem.TryAgain.name)) || shown(Tags.menuItem(MenuItem.Resend.name)))
        closeMenu()

        // Tried again: the dialog asks first.
        air.setTransmissionsFailing(false)
        compose.onNodeWithTag(Tags.RETRY_MESSAGE).performClick()
        waitFor { shown(Tags.RESEND_DIALOG) }
        shot("bubbles-5-resend")
        compose.onNodeWithTag(Tags.RESEND_CONFIRM).performClick()
        waitFor {
            messages(runtime, address).none {
                it.body == "Gate code is 4471" &&
                    (it.delivery == DeliveryState.Failed || it.delivery == DeliveryState.Undelivered)
            }
        }

        // Delete for everyone, confirmed first.
        longPress(delivered.ref.key)
        menuItem(MenuItem.Delete)
        waitFor { shown(Tags.CONFIRM_DIALOG) }
        compose.onNode(hasText(context.getString(R.string.delete_message_confirm))).assertIsDisplayed()
        shot("bubbles-4-delete")
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        waitForMessage(runtime, address) { it.ref == delivered.ref && it.isDeleted }
    }

    /** `bubbles.svg` boards 2, 6 and 7: the kinds of message, and the details page of each side. */
    @Test
    fun detailsOfSentAndReceived() {
        val runtime = runtime(staging = true)
        show(runtime)
        val address = direct(runtime)
        open(address)
        shot("bubbles-2-kinds")
        val mine = send(runtime, address, "Copy that")
        waitFor { context.getString(R.string.caption_delivered) in captionOf(mine.ref.key) }
        longPress(mine.ref.key)
        menuItem(MenuItem.Details)
        waitFor { shown(Tags.MESSAGE_DETAILS) }
        compose.onNode(hasText(context.getString(R.string.details_section_message))).assertIsDisplayed()
        shot("bubbles-6-details-sent")
        compose.activityRule.scenario.onActivity { it.onBackPressedDispatcher.onBackPressed() }
        waitFor { !shown(Tags.MESSAGE_DETAILS) }

        // Heard now on a channel, so its sender's hint and its reception are recorded.
        val heard = "Saddle in ten ${System.nanoTime().toString().takeLast(4)}"
        runBlocking { air.air.peerSays(heard, true) }
        var channel: String? = null
        waitFor {
            channel = runtime.appState.value?.channelConversations?.firstOrNull { it.lastMessage?.body == heard }?.address
            channel != null
        }
        compose.runOnUiThread { shell.closeThread(UmshKey.Thread(address)) }
        open(checkNotNull(channel))
        val received = waitForMessage(runtime, checkNotNull(channel)) { !it.isOutbound && it.body == heard }
        longPress(received.ref.key)
        assertTrue(!shown(Tags.menuItem(MenuItem.Edit.name)))
        assertTrue(!shown(Tags.menuItem(MenuItem.Delete.name)))
        menuItem(MenuItem.Details)
        waitFor { shown(Tags.MESSAGE_DETAILS) }
        compose.onNode(hasText(context.getString(R.string.details_section_sender))).assertExists()
        // The sender's hint and address copy on a tap.
        compose.onNode(hasText(context.getString(R.string.details_hint)) and hasClickAction()).assertExists()
        shot("bubbles-7-details-received")
    }

    /** `bubbles.svg` board 6 with repeaters: a channel message of mine, heard forwarded by the staged repeaters. */
    @Test
    fun detailsOfARepeatedMessage() {
        val runtime = runtime(staging = true)
        show(runtime)
        val public = runtime.appState.value!!.channelConversations.first { it.channel.canonicalName == "public" }.address
        open(public)
        val mine = send(runtime, public, "Heading up the ridge")
        val repeated = waitForMessage(runtime, public) { message ->
            message.ref == mine.ref && message.repeats.let { it != null && (it.repeaters.isNotEmpty() || it.anonymous > 0) }
        }
        longPress(repeated.ref.key)
        menuItem(MenuItem.Details)
        waitFor { shown(Tags.MESSAGE_DETAILS) }
        compose.onNode(hasText(context.getString(R.string.details_section_repeated_by))).assertIsDisplayed()
        // Let every repeat land before the capture.
        Thread.sleep(REPEATS_SETTLE_MS)
        shot("bubbles-6-details-repeated")
    }

    /**
     * `replies-reactions.svg` boards 1–5: a swipe arms a reply, the strip
     * carries it, quotes, a quote tapped, and reactions written and taken back.
     */
    @Test
    fun repliesAndReactions() {
        val runtime = runtime(staging = true)
        show(runtime)
        val address = direct(runtime)
        open(address)
        shot("replies-3-quotes")
        val theirs = messages(runtime, address).last { !it.isOutbound && !it.isDeleted && it.presence == Presence.Present }
        scrollTo(theirs.ref.key)
        val bubble = compose.onNode(
            hasTestTag(Tags.BUBBLE) and hasAnyAncestor(hasTestTag(Tags.message(theirs.ref.key))),
            useUnmergedTree = true,
        )
        // Toward the middle: a received bubble sits at the start, which is the right in RTL.
        val rtl = bubble.fetchSemanticsNode().layoutInfo.layoutDirection == LayoutDirection.Rtl
        bubble.performTouchInput {
            if (rtl) down(centerRight - Offset(8f, 0f)) else down(centerLeft + Offset(8f, 0f))
            repeat(10) { moveBy(Offset(if (rtl) -20f else 20f, 0f), delayMillis = 16) }
        }
        shot("replies-1-swipe")
        bubble.performTouchInput { up() }
        waitFor { shown(Tags.COMPOSER_STRIP) }
        shot("replies-2-replying")
        type("On my way")
        compose.onNodeWithTag(Tags.COMPOSER_SEND).performClick()
        val reply = waitForMessage(runtime, address) { it.isOutbound && it.body == "On my way" }
        assertTrue(reply.quote != null)
        waitFor { !shown(Tags.COMPOSER_STRIP) }

        // A quote tapped: its original, washed for a moment.
        scrollTo(reply.ref.key)
        compose.onNode(
            hasTestTag(Tags.QUOTE) and hasAnyAncestor(hasTestTag(Tags.message(reply.ref.key))),
            useUnmergedTree = true,
        ).performClick()
        compose.mainClock.advanceTimeBy(150)
        shot("replies-4-quote-tapped")

        // A reaction from the menu, then taken back from its chip.
        longPress(theirs.ref.key)
        compose.onNodeWithTag(Tags.menuReaction("👍")).performClick()
        waitForMessage(runtime, address) { it.ref == theirs.ref && it.reactions.any { r -> r.isMine } }
        scrollTo(theirs.ref.key)
        shot("replies-5-reactions")
        val chip = compose.onNode(
            hasTestTag(Tags.REACTION_CHIPS) and hasAnyAncestor(hasTestTag(Tags.message(theirs.ref.key))),
            useUnmergedTree = true,
        )
        chip.assertExists()
        compose.onNode(
            hasText("👍", substring = true) and hasAnyAncestor(hasTestTag(Tags.REACTION_CHIPS)) and
                hasAnyAncestor(hasTestTag(Tags.message(theirs.ref.key))),
            useUnmergedTree = true,
        ).performClick()
        waitForMessage(runtime, address) { it.ref == theirs.ref && it.reactions.none { r -> r.isMine } }
    }

    /** `threads.svg` board 2: a gap in a channel, asked for and filled. */
    @Test
    fun aGapIsAskedForAndFilled() {
        val runtime = runtime(staging = true)
        show(runtime)
        val tag = System.nanoTime().toString().takeLast(4)
        val (first, lost, last) = listOf("Trailhead $tag", "Saddle $tag", "Summit $tag")
        runBlocking { air.air.peerSaysLosingOne(first, lost, last) }
        var address: String? = null
        waitFor {
            address = runtime.appState.value?.channelConversations?.firstOrNull { it.lastMessage?.body == last }?.address
            address != null
        }
        val channel = checkNotNull(address)
        val gap = waitForMessage(runtime, channel) { it.actions.requestMissing }
        open(channel)
        compose.onNodeWithTag(Tags.TRANSCRIPT).performScrollToNode(hasTestTag(Tags.GAP))
        shot("threads-2-channel-gap")
        assertTrue(gap.actions.requestMissing)
        compose.onNode(hasClickAction() and hasAnyAncestor(hasTestTag(Tags.GAP)), useUnmergedTree = true).performClick()
        waitForMessage(runtime, channel) { it.body == lost }
    }

    /**
     * `threads.svg` board 5: EMERGENCY asks before the first send. Cancel
     * leaves the thread and keeps the draft; Certify and send sends it.
     */
    @Test
    fun emergencyAsksBeforeTheFirstSend() {
        val runtime = runtime(staging = true)
        show(runtime)
        val channel = runtime.appState.value!!.channels.first { it.canonicalName == "emergency" }
        val emergency = runBlocking { runtime.openChannelConversation(channel.id).await() }
        open(emergency)
        type("TEST: radio check")
        compose.onNodeWithTag(Tags.COMPOSER_SEND).performClick()
        waitFor { shown(Tags.EMERGENCY_SHEET) }
        compose.onNode(hasText(context.getString(R.string.emergency_certify_send))).assertIsDisplayed()
        shot("threads-5-emergency")
        compose.onNodeWithTag(Tags.EMERGENCY_CANCEL).performClick()
        waitFor { !shown(Tags.THREAD) }
        waitFor { runtime.appState.value?.conversations?.firstOrNull { it.address == emergency }?.draftText == "TEST: radio check" }

        open(emergency)
        compose.onNodeWithTag(Tags.COMPOSER_SEND).performClick()
        waitFor { shown(Tags.EMERGENCY_SHEET) }
        compose.onNodeWithTag(Tags.EMERGENCY_CERTIFY).performClick()
        waitForMessage(runtime, emergency) { it.isOutbound && it.body == "TEST: radio check" }
        // Certified: the next send goes without asking.
        type("TEST: second check")
        compose.onNodeWithTag(Tags.COMPOSER_SEND).performClick()
        waitForMessage(runtime, emergency) { it.isOutbound && it.body == "TEST: second check" }
        assertTrue(!shown(Tags.EMERGENCY_SHEET))
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 600L
        const val REPEATS_SETTLE_MS = 3_000L
        const val RADIO_NAME = "Pocket Relay"
    }
}
