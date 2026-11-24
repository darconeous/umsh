package com.voria.umsh.features

import android.util.Log
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToIndex
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTextInput
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
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
import com.voria.umsh.features.conversations.TranscriptWindow
import com.voria.umsh.models.ChannelConversationSummary
import com.voria.umsh.models.ConversationSummary
import com.voria.umsh.models.DirectConversationSummary
import com.voria.umsh.models.Quote
import com.voria.umsh.models.TranscriptRow
import com.voria.umsh.services.radio.StagingRadioConnection
import kotlin.math.abs
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import com.voria.umsh.designsystem.LocalWindowOverride
import com.voria.umsh.app.TestWindows
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsNotFocused
import com.voria.umsh.features.conversations.ThreadScreen

/** Threads (`threads.svg`, `bubbles.svg`, `replies-reactions.svg` 3 and 5, `composer.svg`), over real cores. */
class ThreadScreenTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun runtime(staging: Boolean): AppRuntime = runBlocking {
        fresh.host.ensureRuntime(staging)
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        val runtime = ready.runtime
        withTimeout(TIMEOUT) { runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        withTimeout(TIMEOUT) { runtime.appState.first { state -> state?.channelConversations?.isNotEmpty() == true } }
        // Staged traffic needs the staged radio carrying this phone: a peer
        // that transmits before then is heard by no one.
        if (staging) withTimeout(TIMEOUT) { runtime.radio.first { it?.carriesThisPhone == true } }
        runtime
    }

    private val air: StagingRadioConnection get() = checkNotNull(fresh.host.stagingRadio.value) { "no staged air" }

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
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed()
    }

    private fun open(address: String, transcript: Boolean = true) {
        compose.runOnUiThread { shell.openDetail(UmshKey.Thread(address)) }
        compose.onNodeWithTag(Tags.THREAD).assertIsDisplayed()
        if (transcript) waitFor { compose.onAllNodesWithTag(Tags.TRANSCRIPT).fetchSemanticsNodes().isNotEmpty() }
    }

    /** The rows the thread derives from the newest page, as the screen reads it. */
    private fun newestRows(runtime: AppRuntime, address: String): TranscriptWindow = runBlocking {
        val page = runtime.transcriptNewest(address, TranscriptWindow.PAGE_SIZE)
        TranscriptWindow().replacedBy(page, 0)
    }

    private fun scrollTo(tag: String) {
        compose.onNodeWithTag(Tags.TRANSCRIPT).performScrollToNode(hasTestTag(tag))
    }

    private fun tagged(prefix: String) = SemanticsMatcher("tag starts with $prefix") {
        it.config.getOrNull(SemanticsProperties.TestTag)?.startsWith(prefix) == true
    }

    private fun waitFor(condition: () -> Boolean) = compose.waitUntil(TIMEOUT, condition)

    private fun direct(runtime: AppRuntime): DirectConversationSummary =
        runtime.appState.value!!.directConversations.first { it.lastMessage != null }

    /** Boards 1 and 3 of `bubbles.svg`: runs, a date line, the one Delivered, and a quote. */
    @Test
    fun aDirectThreadShowsRunsCaptionsAndQuotes() {
        val runtime = runtime(staging = true)
        show(runtime)
        val conversation = runtime.appState.value!!.directConversations.first { c ->
            newestRows(runtime, c.address).messages.any { message ->
                (message.quote as? Quote.Original)?.let { it.isOutbound && !it.isDeleted } == true
            }
        }
        open(conversation.address)
        val window = newestRows(runtime, conversation.address)
        // The date line opens the transcript; nothing older lies behind the seeded one.
        assertTrue("${window.rows.first()}", window.rows.first() is TranscriptRow.DateLine)
        scrollTo(Tags.DATE_LINE)
        // Every message is on its own row; a direct thread never names a run.
        for (row in window.rows.filterIsInstance<TranscriptRow.Message>()) {
            scrollTo(Tags.message(row.key))
            compose.onNodeWithTag(Tags.message(row.key)).assertIsDisplayed()
        }
        assertEquals(0, compose.onAllNodesWithTag(Tags.RUN_LABEL, useUnmergedTree = true).fetchSemanticsNodes().size)
        // Delivered marks only the newest of mine.
        val delivered = context.getString(R.string.caption_delivered)
        val lastOutbound = checkNotNull(window.lastOutboundKey)
        scrollTo(Tags.message(lastOutbound))
        val merged = compose.onNodeWithTag(Tags.message(lastOutbound)).fetchSemanticsNode().config
        assertTrue(merged.getOrNull(SemanticsProperties.Text).orEmpty().any { it.text == delivered })
        val others = window.messages.filter { it.isOutbound && !it.isDeleted && it.ref.key != lastOutbound }
        for (message in others) {
            scrollTo(Tags.message(message.ref.key))
            val text = compose.onNodeWithTag(Tags.message(message.ref.key)).fetchSemanticsNode().config
                .getOrNull(SemanticsProperties.Text).orEmpty()
            assertTrue("$text", text.none { it.text == delivered })
        }
        // A reply of theirs quoting mine (not deleted) names me.
        val reply = window.messages.first { message ->
            (message.quote as? Quote.Original)?.let { it.isOutbound && !it.isDeleted } == true
        }
        scrollTo(Tags.message(reply.ref.key))
        compose.onNode(
            hasText(context.getString(R.string.quote_you)) and
                hasAnyAncestor(hasTestTag(Tags.QUOTE) and hasAnyAncestor(hasTestTag(Tags.message(reply.ref.key)))),
            useUnmergedTree = true,
        ).assertExists()
    }

    /** `threads.svg` board 2 and `replies-reactions.svg` board 5: runs named above, avatars beside, chips under. */
    @Test
    fun aChannelThreadNamesItsRunsAndShowsReactions() {
        val runtime = runtime(staging = true)
        show(runtime)
        val conversation = runtime.appState.value!!.channelConversations
            .first { c -> newestRows(runtime, c.address).messages.any { !it.isOutbound } }
        open(conversation.address)
        val window = newestRows(runtime, conversation.address)
        val runs = window.rows.filterIsInstance<TranscriptRow.Message>()
            .filter { !it.message.isOutbound && !it.message.isDeleted && !it.message.isStatus && it.presentation.isFirstInRun }
        assertTrue(runs.isNotEmpty())
        // Each run's own first row carries its label.
        for (run in runs) {
            scrollTo(Tags.message(run.key))
            compose.onNode(hasTestTag(Tags.RUN_LABEL) and within(run.key), useUnmergedTree = true).assertExists()
        }
        // Each run's last row carries the member's avatar, and no other row of theirs does.
        val inbound = window.rows.filterIsInstance<TranscriptRow.Message>()
            .filter { !it.message.isOutbound && !it.message.isDeleted && !it.message.isStatus }
        for (row in inbound) {
            scrollTo(Tags.message(row.key))
            val avatars = compose.onAllNodes(hasTestTag(Tags.MEMBER_AVATAR) and within(row.key), useUnmergedTree = true)
                .fetchSemanticsNodes().size
            assertEquals(row.key, if (row.presentation.isLastInRun) 1 else 0, avatars)
        }
        // Each reacted message carries its own chips.
        val reacted = window.messages.filter { message -> message.reactions.any { it.kind != null } }
        assertTrue(reacted.isNotEmpty())
        for (message in reacted) {
            scrollTo(Tags.message(message.ref.key))
            val chips = compose.onAllNodes(tagged("reaction_chip/") and within(message.ref.key), useUnmergedTree = true)
                .fetchSemanticsNodes()
            assertTrue(message.ref.key, chips.isNotEmpty())
        }
    }

    /** A node inside the row of the message keyed [key]. */
    private fun within(key: String) = hasAnyAncestor(hasTestTag(Tags.message(key)))

    /**
     * `composer.svg` boards 1–2: Send arrives with text, ready while the
     * radio carries this phone; the draft reaches the store and comes back
     * with the thread.
     * That leaving saves it, ahead of the typing pause, is
     * `ThreadViewModelTest.leavingTheThreadSavesItsDraft`.
     */
    @Test
    fun theComposerKeepsADraft() {
        val runtime = runtime(staging = true)
        show(runtime)
        val conversation = direct(runtime)
        open(conversation.address)
        assertEquals(0, compose.onAllNodesWithTag(Tags.COMPOSER_SEND).fetchSemanticsNodes().size)
        // Named for the conversation while empty; once typed in, TalkBack reads the draft, not the name.
        fun fieldName() = compose.onNodeWithTag(Tags.COMPOSER_FIELD).fetchSemanticsNode().config
            .getOrNull(SemanticsProperties.ContentDescription).orEmpty()
        assertTrue(fieldName().isNotEmpty())
        compose.onNodeWithTag(Tags.COMPOSER_FIELD).performTextInput("Copy that")
        compose.onNodeWithTag(Tags.COMPOSER_SEND).assertIsDisplayed().assertIsEnabled()
        assertTrue("${fieldName()}", fieldName().isEmpty())
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).performClick()
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed()
        // The store has it, read from the core itself (not the runtime's
        // overlay of what is still waiting to be saved), and the row says so.
        waitFor { storedDraft(runtime, conversation.address) == "Copy that" }
        runBlocking { runtime.reload(full = false).await() }
        assertEquals("Copy that", draftOf(runtime, conversation.address))
        open(conversation.address)
        waitFor {
            compose.onNodeWithTag(Tags.COMPOSER_FIELD).fetchSemanticsNode().config
                .getOrNull(SemanticsProperties.EditableText)?.text == "Copy that"
        }
    }

    /** `composer.svg` boards 5 and 6: the composer follows the staged radio's link. */
    @Test
    fun theComposerFollowsTheRadio() {
        val runtime = runtime(staging = true)
        show(runtime)
        open(direct(runtime).address)
        waitFor { runtime.radio.value?.carriesThisPhone == true }
        assertEquals(0, compose.onAllNodesWithTag(Tags.COMPOSER_BLOCKED).fetchSemanticsNodes().size)
        air.setLinkUp(false)
        waitFor { compose.onAllNodesWithTag(Tags.COMPOSER_BLOCKED).fetchSemanticsNodes().isNotEmpty() }
        // The banner shows in the thread too (`radio-control.svg` board 5). Checked
        // before typing: the test's activity pans for the keyboard, which moves the top bar off screen.
        waitFor { runCatching { compose.onNodeWithTag(Tags.RADIO_BANNER).assertIsDisplayed() }.isSuccess }
        // The field stays usable, and Send arrives blocked.
        compose.onNodeWithTag(Tags.COMPOSER_FIELD).performTextInput("Copy that")
        compose.onNodeWithTag(Tags.COMPOSER_SEND).assertIsNotEnabled()
        air.setLinkUp(true)
        waitFor { compose.onAllNodesWithTag(Tags.COMPOSER_BLOCKED).fetchSemanticsNodes().isEmpty() }
        waitFor { runtime.radio.value?.carriesThisPhone == true }
        compose.onNodeWithTag(Tags.COMPOSER_SEND).assertIsEnabled()
        assertEquals("Copy that", compose.onNodeWithTag(Tags.COMPOSER_FIELD).fetchSemanticsNode().config[SemanticsProperties.EditableText].text)
    }

    /** A message arriving while the thread is open appears at the bottom and is read at once. */
    @Test
    fun aNewMessageArrivesLiveAndIsMarkedRead() {
        val runtime = runtime(staging = true)
        show(runtime)
        val before = runtime.appState.value!!.conversations.associate { it.address to it.revision }
        // Directly, not through the Developer section's `later`, which only
        // logs a failure: one here fails the test where it happens.
        runBlocking { air.air.peerSays("Radio check", false) }
        val target = waitForChange(runtime, before)
        open(target.address)
        waitFor { unread(runtime, target.address) == 0L }
        val marker = "Live ${System.nanoTime()}"
        runBlocking { air.air.peerSays(marker, false) }
        waitFor {
            compose.onAllNodes(hasText(marker, substring = true)).fetchSemanticsNodes().isNotEmpty()
        }
        // The lists know of it (the transcript can draw it before they reload),
        // and the read time reaches it: it was marked read, not merely not yet counted.
        val arrived = waitForConversation(runtime, target.address) { it.lastMessage?.body == marker }
        val sentAt = checkNotNull(arrived.lastMessage).createdAtMs
        waitForConversation(runtime, target.address) { it.unreadCount == 0L && it.lastReadAtMs >= sentAt }
    }

    /**
     * R1-1: a thread drawn while it is not the page shown (behind a back
     * preview) never marks read, and never takes the keyboard; shown, it does.
     */
    @Test
    fun aThreadNotShownMarksNothingRead() {
        val runtime = runtime(staging = true)
        val unread = runtime.appState.value!!.conversations.first { it.unreadCount > 0 }
        val current = mutableStateOf(false)
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides TestWindows.Phone,
                ) {
                    ThreadScreen(
                        UmshKey.Thread(unread.address),
                        current = current.value,
                        onBack = null,
                        onLeave = {},
                        onOpenDetails = {},
                        onOpenPeer = {},
                        onOpenRadio = {},
                        onChooseRadio = {},
                    )
                }
            }
        }
        waitFor { compose.onAllNodesWithTag(Tags.TRANSCRIPT).fetchSemanticsNodes().isNotEmpty() }
        // A few frames' worth, for a mark-read that should not come.
        compose.mainClock.advanceTimeBy(2_000)
        compose.waitForIdle()
        assertEquals(unread.unreadCount, unread(runtime, unread.address))
        compose.onNodeWithTag(Tags.COMPOSER_FIELD).assertIsNotFocused()
        compose.onNodeWithTag(Tags.COMPOSER_FIELD).performClick()
        compose.onNodeWithTag(Tags.COMPOSER_FIELD).assertIsNotFocused()

        compose.runOnUiThread { current.value = true }
        waitFor { unread(runtime, unread.address) == 0L }
    }

    /**
     * `replies-reactions.svg` board 4: tapping a quote shows its original.
     * The staged quotes all answer the message just above them, so the reply
     * is first scrolled to the top, its original out of sight above it.
     */
    @Test
    fun tappingAQuoteShowsItsOriginal() {
        val runtime = runtime(staging = true)
        show(runtime)
        val conversation = runtime.appState.value!!.directConversations.first { c ->
            newestRows(runtime, c.address).messages.dropLast(2).any { it.quote is Quote.Original }
        }
        open(conversation.address)
        val window = newestRows(runtime, conversation.address)
        // One with rows below it, so it can reach the top.
        val reply = window.messages.dropLast(2).first { it.quote is Quote.Original }
        val original = (reply.quote as Quote.Original).target.key
        val quote = compose.onNode(hasTestTag(Tags.QUOTE) and within(reply.ref.key), useUnmergedTree = true)
        scrollTo(Tags.message(reply.ref.key))
        val top = compose.onNodeWithTag(Tags.TRANSCRIPT).fetchSemanticsNode().boundsInRoot.top
        fun replyTop() = compose.onNodeWithTag(Tags.message(reply.ref.key)).fetchSemanticsNode().boundsInRoot.top
        fun scrollBy(dy: Float) {
            compose.onNodeWithTag(Tags.TRANSCRIPT).performSemanticsAction(SemanticsActions.ScrollBy) { it(0f, dy) }
            compose.waitForIdle()
        }
        // Up to the top. The action's sign follows the list's direction, which
        // is reversed here: if the first try moved the reply away, go the other way.
        val distance = replyTop() - top
        scrollBy(distance)
        if (abs(replyTop() - top) > abs(distance)) scrollBy(-2 * distance)
        quote.assertIsDisplayed()
        assertFalse("the original is already in sight", isShown(Tags.message(original)))

        quote.performClick()
        waitFor { isShown(Tags.message(original)) }
    }

    private fun isShown(tag: String) = runCatching { compose.onNodeWithTag(tag).assertIsDisplayed() }.isSuccess

    /** Where the row keyed [key] is in the transcript's list (the newest at 0); -1 when it is not in the window. */
    private fun indexOf(key: String): Int =
        compose.onNodeWithTag(Tags.TRANSCRIPT).fetchSemanticsNode().config[SemanticsProperties.IndexForKey](key)

    /** The key of the lowest message row on screen. */
    private fun bottomMessage(): String =
        compose.onAllNodes(tagged("message/")).fetchSemanticsNodes()
            .filter { isShown(it.config[SemanticsProperties.TestTag]) }
            .maxBy { it.boundsInRoot.bottom }
            .config[SemanticsProperties.TestTag].removePrefix("message/")

    /**
     * `threads.svg` board 3: paging back past the window's capacity gives up
     * the newest messages, Jump to latest shows, and returns to them.
     */
    @Test
    fun jumpToLatestReturnsFromDeepHistory() {
        val runtime = runtime(staging = true)
        show(runtime)
        val before = runtime.appState.value!!.conversations.associate { it.address to it.revision }
        val started = System.currentTimeMillis()
        runBlocking { air.air.peerSays("first", false) }
        val target = waitForChange(runtime, before)
        val fillers = TranscriptWindow.CAPACITY + TranscriptWindow.PAGE_SIZE + 10
        runBlocking { repeat(fillers) { air.air.peerSays("filler $it", false) } }
        val newest = "filler ${fillers - 1}"
        waitFor { newestRows(runtime, target.address).messages.lastOrNull()?.body == newest }
        Log.i("umsh.test", "staged ${fillers + 1} messages in ${System.currentTimeMillis() - started} ms")
        open(target.address)
        val newestKey = newestRows(runtime, target.address).messages.last().ref.key
        compose.onNodeWithTag(Tags.message(newestKey)).assertIsDisplayed()
        assertEquals(0, compose.onAllNodesWithTag(Tags.JUMP_TO_LATEST).fetchSemanticsNodes().size)
        // Up through history, a page at a time, until the window gives up its newest edge.
        waitFor {
            if (compose.onAllNodesWithTag(Tags.JUMP_TO_LATEST).fetchSemanticsNodes().isNotEmpty()) return@waitFor true
            val transcript = compose.onNodeWithTag(Tags.TRANSCRIPT)
            val rows = transcript.fetchSemanticsNode().config[SemanticsProperties.CollectionInfo].rowCount
            transcript.performScrollToIndex(rows - 1)
            false
        }
        compose.onNodeWithTag(Tags.JUMP_TO_LATEST).assertIsDisplayed()
        pauseForScreenshot()
        // On to the oldest, so the window is more than a page short of the newest.
        waitFor {
            val transcript = compose.onNodeWithTag(Tags.TRANSCRIPT)
            val rows = transcript.fetchSemanticsNode().config[SemanticsProperties.CollectionInfo].rowCount
            transcript.performScrollToIndex(rows - 1)
            compose.onAllNodesWithTag(Tags.TRANSCRIPT_EDGE).fetchSemanticsNodes().isEmpty()
        }
        // Down to the window's newer edge: a page of newer messages lands
        // below the row being read, which stays where it is; the reader is
        // not carried page after page on to the newest.
        compose.onNodeWithTag(Tags.TRANSCRIPT).performScrollToIndex(0)
        val reading = bottomMessage()
        waitFor { indexOf(reading) > 0 }
        Thread.sleep(SETTLE_MS)
        compose.waitForIdle()
        assertTrue("$reading left the screen", isShown(Tags.message(reading)))
        compose.onNodeWithTag(Tags.JUMP_TO_LATEST).assertIsDisplayed()
        assertFalse(isShown(Tags.message(newestKey)))
        compose.onNodeWithTag(Tags.JUMP_TO_LATEST).performClick()
        waitFor { compose.onAllNodesWithTag(Tags.JUMP_TO_LATEST).fetchSemanticsNodes().isEmpty() }
        waitFor { compose.onAllNodesWithTag(Tags.message(newestKey)).fetchSemanticsNodes().isNotEmpty() }
    }

    /** `threads.svg` board 4: a conversation with no messages, in live mode. */
    @Test
    fun anEmptyThreadSaysSo() {
        val runtime = runtime(staging = false)
        show(runtime)
        val public = runtime.appState.value!!.channelConversations.first()
        open(public.address, transcript = false)
        compose.onNodeWithTag(Tags.THREAD_EMPTY).assertIsDisplayed()
        val texts = compose.onNodeWithTag(Tags.THREAD_EMPTY).fetchSemanticsNode().children
            .flatMap { it.config.getOrNull(SemanticsProperties.Text).orEmpty() }.map { it.text }
        assertTrue("$texts", context.getString(R.string.thread_empty_channel) in texts)
        // No radio in live mode: the composer says why, and keeps the field.
        compose.onNodeWithTag(Tags.COMPOSER_BLOCKED).assertIsDisplayed()
        compose.onNodeWithTag(Tags.COMPOSER_FIELD).assertIsDisplayed()
    }

    /**
     * Holds the screen still for a screenshot taken from outside, for as many
     * seconds as the `umsh.pause` instrumentation argument says; never otherwise.
     */
    private fun pauseForScreenshot() {
        val seconds = InstrumentationRegistry.getArguments().getString("umsh.pause")?.toLongOrNull() ?: return
        compose.waitForIdle()
        Thread.sleep(seconds * 1_000)
    }

    private fun draftOf(runtime: AppRuntime, address: String): String? =
        runtime.appState.value?.conversations?.firstOrNull { it.address == address }?.draftText

    private fun unread(runtime: AppRuntime, address: String): Long? =
        runtime.appState.value?.conversations?.firstOrNull { it.address == address }?.unreadCount

    /** The draft as the core holds it, without what the runtime has yet to save. */
    private fun storedDraft(runtime: AppRuntime, address: String): String? =
        runtime.core.state(true).directConversations.firstOrNull { it.peer.identity.canonicalAddress == address }?.draftText

    private fun waitForConversation(
        runtime: AppRuntime,
        address: String,
        condition: (ConversationSummary) -> Boolean,
    ): ConversationSummary {
        var found: ConversationSummary? = null
        waitFor {
            found = runtime.appState.value?.conversations?.firstOrNull { it.address == address }?.takeIf(condition)
            found != null
        }
        return checkNotNull(found)
    }

    /** The conversation whose messages changed since [before]. */
    private fun waitForChange(runtime: AppRuntime, before: Map<String, Long>): ConversationSummary {
        var changed: ConversationSummary? = null
        waitFor {
            changed = runtime.appState.value?.conversations?.firstOrNull { (before[it.address] ?: -1) != it.revision }
            changed != null
        }
        return checkNotNull(changed).also { assertTrue(it is DirectConversationSummary || it is ChannelConversationSummary) }
    }

    private companion object {
        const val TIMEOUT = 30_000L
        /** Long enough for a page read; a reader carried page after page would be gone by then. */
        const val SETTLE_MS = 1_000L
    }
}
