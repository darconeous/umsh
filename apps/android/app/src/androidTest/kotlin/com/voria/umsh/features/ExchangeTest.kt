package com.voria.umsh.features

import androidx.activity.ComponentActivity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeDown
import androidx.compose.ui.text.VerbatimTtsAnnotation
import androidx.lifecycle.Lifecycle
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
import com.voria.umsh.app.stagedAir
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileStagingAirException
import com.voria.umsh.designsystem.LocalWindowOverride
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.peers.ExchangeCode
import com.voria.umsh.features.peers.LocalExchangeHost
import com.voria.umsh.models.MeetExchange
import com.voria.umsh.models.MeetState
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Contact exchange (`nearby-exchange.svg` 1–6) over the staged air, whose
 * T-LoRa Pager opens Add peer, asks or agrees, and presses Same a moment
 * after the code shows. Boards 2 and 4 pass in an instant there; the
 * staged-host half of [ExchangeDrawnTest] holds them still.
 */
class ExchangeTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun runtime(): AppRuntime = runBlocking {
        fresh.host.preferences.setFallbackScheme(true)
        fresh.host.ensureRuntime(staging = true)
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        val runtime = ready.runtime
        withTimeout(TIMEOUT) { runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        withTimeout(TIMEOUT) { runtime.radio.first { it?.carriesThisPhone == true } }
        withTimeout(TIMEOUT) { runtime.appState.first { it != null } }
        runtime
    }

    private fun show(runtime: AppRuntime, content: @Composable () -> Unit = {}) {
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
                    content()
                }
            }
        }
        waitForTag(Tags.CONVERSATIONS_ROOT)
    }

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun waitGone(tag: String) = compose.waitUntil(TIMEOUT) { !present(tag) }

    private fun text(tag: String): String = compose.onNodeWithTag(tag, useUnmergedTree = true).fetchSemanticsNode().config
        .getOrNull(SemanticsProperties.Text)?.joinToString("") { it.text }.orEmpty()

    private fun mergedText(tag: String): String = compose.onNodeWithTag(tag).fetchSemanticsNode().config
        .getOrNull(SemanticsProperties.Text)?.joinToString("") { it.text }.orEmpty()

    private fun string(id: Int, vararg args: Any) = context.getString(id, *args)

    private fun stack(destination: Destination) = shell.stacks.getValue(destination).toList()

    private fun openFromPeers() {
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitForTag(Tags.PEERS_ADD)
        compose.onNodeWithTag(Tags.PEERS_ADD).performClick()
        waitForTag(Tags.ADD_PEER)
    }

    private fun openFromConversations() {
        waitForTag(Tags.CONVERSATIONS_NEW_CHAT)
        compose.onNodeWithTag(Tags.CONVERSATIONS_NEW_CHAT).performClick()
        waitForTag(Tags.NEW_CHAT_MESSAGE)
        compose.onNodeWithTag(Tags.NEW_CHAT_MESSAGE).performClick()
        waitForTag(Tags.ADD_PEER)
    }

    private fun meetWhere(runtime: AppRuntime, what: String, predicate: (MeetState?) -> Boolean): MeetState? = runBlocking {
        try {
            withTimeout(TIMEOUT) { runtime.meet.first(predicate) }
        } catch (error: Exception) {
            throw AssertionError("never: $what (last ${runtime.meet.value})", error)
        }
    }

    /** The staged T-LoRa Pager opens Add peer ([asking], it asks), once its session hears this phone's. */
    private fun peerOpensAddPeer(asking: Boolean) = runBlocking {
        withTimeout(TIMEOUT) {
            while (true) {
                try {
                    fresh.stagedAir.air.peerOpensAddPeer(asking)
                    break
                } catch (_: MobileStagingAirException.NoPhone) {
                    delay(POLL_MS)
                }
            }
        }
    }

    /** Nearby lists the pager; its row asks it. */
    private fun askThePager(runtime: AppRuntime) {
        meetWhere(runtime, "open") { it?.exchange == MeetExchange.Idle }
        peerOpensAddPeer(asking = false)
        waitForTag(Tags.NEARBY_DEVICE)
        compose.onNodeWithTag(Tags.NEARBY_DEVICE).performClick()
    }

    // --- Being asked, comparing, exchanged (boards 1, 3, 4, 6) --------------

    @Test
    fun beingAskedThenSameOnBothLandsOnTheNewPeersPage() {
        val runtime = runtime()
        show(runtime)
        openFromPeers()
        // Open: this phone's own glyph beside You; nothing heard yet.
        waitForTag(Tags.NEARBY_YOU)
        meetWhere(runtime, "open") { it?.exchange == MeetExchange.Idle }

        // Board 1: the pager asks; its sheet over Add peer.
        peerOpensAddPeer(asking = true)
        waitForTag(Tags.EXCHANGE_ASKED)
        val asked = runtime.meet.value!!.exchange as MeetExchange.Asked
        assertEquals(9, asked.device.model)
        compose.onNodeWithTag(Tags.EXCHANGE_ACCEPT).performClick()

        // Board 3: the page is pushed over Add peer; the meet stays open under it.
        waitForTag(Tags.EXCHANGE_CODE)
        waitGone(Tags.EXCHANGE_ASKED)
        assertEquals(listOf(UmshKey.PeersRoot, UmshKey.AddPeer(Destination.Peers), UmshKey.Exchange(Destination.Peers)), stack(Destination.Peers))
        val comparing = runtime.meet.value!!.exchange as MeetExchange.Comparing
        assertEquals(ExchangeCode.grouped(comparing.code), text(Tags.EXCHANGE_CODE).filter { it.isDigit() || it == ' ' })
        // Its title: the other device's glyph and model.
        assertEquals("T-LoRa Pager", mergedText(Tags.EXCHANGE_TITLE))

        // Board 4: Same before the pager's, so this side waits with its check.
        compose.onNodeWithTag(Tags.EXCHANGE_SAME).performClick()
        compose.waitUntil(TIMEOUT) { present(Tags.EXCHANGE_SAME_PRESSED) || present(Tags.PEER_PAGE) }

        // Board 6: the new peer's page replaces Add peer and the exchange.
        val exchanged = meetWhere(runtime, "exchanged") { it?.exchange is MeetExchange.Exchanged }!!.exchange as MeetExchange.Exchanged
        waitForTag(Tags.PEER_PAGE)
        compose.waitUntil(TIMEOUT) { stack(Destination.Peers) == listOf(UmshKey.PeersRoot, UmshKey.PeerPage(exchanged.peerAddress, Destination.Peers)) }
        // The page is not a meet page: the meet closes behind it.
        meetWhere(runtime, "closed behind the page") { it == null || it.exchange == MeetExchange.Closed }
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).performClick()
        compose.waitUntil(TIMEOUT) { stack(Destination.Peers) == listOf(UmshKey.PeersRoot) }
    }

    /** D11: from New message, the exchange and the new peer's page stay on Conversations. */
    @Test
    fun fromConversationsTheExchangeStaysThere() {
        val runtime = runtime()
        show(runtime)
        openFromConversations()
        meetWhere(runtime, "open") { it?.exchange == MeetExchange.Idle }
        peerOpensAddPeer(asking = true)
        waitForTag(Tags.EXCHANGE_ASKED)
        compose.onNodeWithTag(Tags.EXCHANGE_ACCEPT).performClick()
        waitForTag(Tags.EXCHANGE_SAME)
        assertEquals(UmshKey.Exchange(Destination.Conversations), stack(Destination.Conversations).last())
        compose.onNodeWithTag(Tags.EXCHANGE_SAME).performClick()
        val exchanged = meetWhere(runtime, "exchanged") { it?.exchange is MeetExchange.Exchanged }!!.exchange as MeetExchange.Exchanged
        compose.waitUntil(TIMEOUT) {
            stack(Destination.Conversations) == listOf(UmshKey.ConversationsRoot, UmshKey.PeerPage(exchanged.peerAddress, Destination.Conversations))
        }
        assertEquals(Destination.Conversations, shell.selected)
    }

    // --- Asking from Nearby; codes that differ (boards 2, 5) ----------------

    @Test
    fun askingFromNearbyThenDifferentEndsItAndTryAgainStartsOver() {
        val runtime = runtime()
        show(runtime)
        openFromPeers()
        val peersBefore = runtime.appState.value!!.peers.map { it.address }.toSet()
        askThePager(runtime)
        // Board 2 passes as soon as the pager agrees; the page is up through it.
        waitForTag(Tags.EXCHANGE)
        waitForTag(Tags.EXCHANGE_DIFFERENT)
        compose.onNodeWithTag(Tags.EXCHANGE_DIFFERENT).performClick()

        // Board 5.
        waitForTag(Tags.EXCHANGE_ENDED)
        assertEquals(string(R.string.exchange_codes_differ), text(Tags.EXCHANGE_ENDED))
        // Nothing saved.
        assertEquals(peersBefore, runtime.appState.value!!.peers.map { it.address }.toSet())

        // Try again: a fresh key, back on Nearby.
        compose.onNodeWithTag(Tags.EXCHANGE_TRY_AGAIN).performClick()
        waitGone(Tags.EXCHANGE)
        assertEquals(UmshKey.AddPeer(Destination.Peers), stack(Destination.Peers).last())
        val after = meetWhere(runtime, "open again") { it != null && !it.exchange.isUnderWay && it.exchange != MeetExchange.Closed }!!
        assertTrue(after.exchange == MeetExchange.Idle || after.exchange == MeetExchange.Opening)

        // Again, ending with Done: back on Add peer.
        askThePager(runtime)
        waitForTag(Tags.EXCHANGE_DIFFERENT)
        compose.onNodeWithTag(Tags.EXCHANGE_DIFFERENT).performClick()
        waitForTag(Tags.EXCHANGE_DONE)
        compose.onNodeWithTag(Tags.EXCHANGE_DONE).performClick()
        waitGone(Tags.EXCHANGE)
        assertEquals(listOf(UmshKey.PeersRoot, UmshKey.AddPeer(Destination.Peers)), stack(Destination.Peers))
        meetWhere(runtime, "open again") { it != null && !it.exchange.isUnderWay && it.exchange != MeetExchange.Closed }
    }

    @Test
    fun backLeavesTheAttemptForBothAndThePageStaysClosed() {
        val runtime = runtime()
        show(runtime)
        openFromPeers()
        askThePager(runtime)
        waitForTag(Tags.EXCHANGE_SAME)
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).performClick()
        waitGone(Tags.EXCHANGE)
        meetWhere(runtime, "backed out") { it != null && !it.exchange.isUnderWay }
        // It does not come back for the attempt it left.
        Thread.sleep(SETTLE_MS)
        compose.waitForIdle()
        assertEquals(listOf(UmshKey.PeersRoot, UmshKey.AddPeer(Destination.Peers)), stack(Destination.Peers))
        assertTrue(!present(Tags.EXCHANGE))
    }

    // --- Swipe, rotate, background -------------------------------------------

    /** Board 1's note: swiping the sheet away declines, and Add peer stays open. The fresh key is ShellMeetTest's. */
    @Test
    fun swipingTheAskAwayDeclines() {
        val runtime = runtime()
        show(runtime)
        openFromPeers()
        meetWhere(runtime, "open") { it?.exchange == MeetExchange.Idle }
        peerOpensAddPeer(asking = true)
        waitForTag(Tags.EXCHANGE_ASKED)
        val asked = runtime.meet.value!!
        compose.onNodeWithTag(Tags.EXCHANGE_ASKED).performTouchInput { swipeDown(startY = top + 8f, endY = bottom) }
        waitGone(Tags.EXCHANGE_ASKED)
        val fresh = meetWhere(runtime, "declined, open again") { it != null && it.exchange !is MeetExchange.Asked && !it.exchange.isUnderWay && it.exchange != MeetExchange.Closed }!!
        assertNotEquals("declined, not exchanged", MeetExchange.Exchanged::class, fresh.exchange::class)
        assertTrue(!present(Tags.EXCHANGE))
        assertEquals(UmshKey.AddPeer(Destination.Peers), stack(Destination.Peers).last())
        assertTrue("the pager was listed before the swipe", asked.devices.isNotEmpty())
    }

    /** Not now does the same as swiping. */
    @Test
    fun notNowDeclines() {
        val runtime = runtime()
        show(runtime)
        openFromPeers()
        meetWhere(runtime, "open") { it?.exchange == MeetExchange.Idle }
        peerOpensAddPeer(asking = true)
        waitForTag(Tags.EXCHANGE_NOT_NOW)
        compose.onNodeWithTag(Tags.EXCHANGE_NOT_NOW).performClick()
        waitGone(Tags.EXCHANGE_ASKED)
        meetWhere(runtime, "declined") { it != null && it.exchange !is MeetExchange.Asked && !it.exchange.isUnderWay }
        assertTrue(!present(Tags.EXCHANGE))
    }

    /** Leaving the app closes the meet (the one deliberate close); coming back opens it afresh, on Add peer. */
    @Test
    fun backgroundClosesTheMeetAndReturningOpensItAgain() {
        val runtime = runtime()
        show(runtime)
        openFromPeers()
        askThePager(runtime)
        waitForTag(Tags.EXCHANGE_SAME)

        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        meetWhere(runtime, "closed in the background") { it == null || it.exchange == MeetExchange.Closed }
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        waitGone(Tags.EXCHANGE)
        assertEquals(listOf(UmshKey.PeersRoot, UmshKey.AddPeer(Destination.Peers)), stack(Destination.Peers))
        meetWhere(runtime, "open again") { it?.exchange == MeetExchange.Idle }
    }

    /** A Nearby with no radio carrying this phone is one line (`add-peer.svg` 2). */
    @Test
    fun withoutTheRadioNearbyIsOneLine() {
        val runtime = runtime()
        show(runtime)
        openFromPeers()
        waitForTag(Tags.NEARBY_EMPTY)
        assertEquals(string(R.string.nearby_empty), text(Tags.NEARBY_EMPTY))
        fresh.stagedAir.setLinkUp(false)
        waitForTag(Tags.NEARBY_NO_RADIO)
        assertEquals(string(R.string.nearby_no_radio), text(Tags.NEARBY_NO_RADIO))
        assertTrue(!present(Tags.NEARBY_YOU))
        fresh.stagedAir.setLinkUp(true)
        waitForTag(Tags.NEARBY_YOU)
    }

    // --- TalkBack (§3.10) ------------------------------------------------------

    @Test
    fun whatTalkBackReads() {
        val runtime = runtime()
        show(runtime)
        openFromPeers()
        meetWhere(runtime, "open") { it?.exchange == MeetExchange.Idle }
        peerOpensAddPeer(asking = false)
        waitForTag(Tags.NEARBY_DEVICE)
        compose.waitUntil(TIMEOUT) { runtime.meet.value?.devices?.firstOrNull()?.nearness != null }
        // The row: model and nearness in words, never color; one button that asks.
        val row = compose.onNodeWithTag(Tags.NEARBY_DEVICE).fetchSemanticsNode().config
        val description = row.getOrNull(SemanticsProperties.ContentDescription)?.joinToString().orEmpty()
        assertTrue(description, description.startsWith("T-LoRa Pager, "))
        val nearness = runtime.meet.value!!.devices.first().nearness!!
        val words = listOf(R.string.meet_nearness_far, R.string.meet_nearness_fairly_far, R.string.meet_nearness_fairly_close, R.string.meet_nearness_close)
        assertEquals(string(R.string.nearby_device_description, "T-LoRa Pager", string(words[nearness])), description)
        assertEquals(string(R.string.nearby_ask_action), row.getOrNull(SemanticsActions.OnClick)?.label)
        // The Nearby header is a heading; You is one stop.
        assertTrue(compose.onAllNodesWithTag(Tags.NEARBY_YOU).fetchSemanticsNodes().single().config.getOrNull(SemanticsProperties.Text)!!.joinToString().contains(string(R.string.nearby_you)))

        compose.onNodeWithTag(Tags.NEARBY_DEVICE).performClick()
        waitForTag(Tags.EXCHANGE_CODE)
        // The code is read digit by digit.
        val code = compose.onNodeWithTag(Tags.EXCHANGE_CODE, useUnmergedTree = true).fetchSemanticsNode().config
            .getOrNull(SemanticsProperties.Text)!!.single()
        val tts = code.getTtsAnnotations(0, code.length).map { it.item }
        assertTrue("verbatim: $tts", tts.any { it is VerbatimTtsAnnotation })
        // Comparing is announced: the question is a polite live region.
        assertEquals(
            androidx.compose.ui.semantics.LiveRegionMode.Polite,
            compose.onNodeWithTag(Tags.EXCHANGE_COMPARE, useUnmergedTree = true).fetchSemanticsNode().config.getOrNull(SemanticsProperties.LiveRegion),
        )
        compose.onNodeWithTag(Tags.EXCHANGE_DIFFERENT).performClick()
        waitForTag(Tags.EXCHANGE_ENDED)
        // The ending is announced once.
        assertEquals(
            androidx.compose.ui.semantics.LiveRegionMode.Polite,
            compose.onNodeWithTag(Tags.EXCHANGE_ENDED, useUnmergedTree = true).fetchSemanticsNode().config.getOrNull(SemanticsProperties.LiveRegion),
        )
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val POLL_MS = 50L
        const val SETTLE_MS = 2_000L
    }
}
