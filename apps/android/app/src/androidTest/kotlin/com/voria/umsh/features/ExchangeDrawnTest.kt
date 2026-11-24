package com.voria.umsh.features

import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
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
import com.voria.umsh.features.peers.LocalExchangeHost
import com.voria.umsh.models.MeetEnd
import com.voria.umsh.models.MeetExchange
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Every state of `nearby-exchange.svg` 1–5 drawn from an exchange moved by
 * hand ([FakeExchangeHost]), each held still: the ones the staged air
 * passes in an instant (board 2's Waiting, board 4's After Same) and the
 * endings it cannot reach (Not exchanged), and what each tap asks.
 */
class ExchangeDrawnTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState
    private val exchange = FakeExchangeHost()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun runtime(): AppRuntime = runBlocking {
        fresh.host.preferences.setFallbackScheme(true)
        fresh.host.ensureRuntime(staging = true)
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        withTimeout(TIMEOUT) { ready.runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        withTimeout(TIMEOUT) { ready.runtime.appState.first { it != null } }
        ready.runtime
    }

    private fun show() {
        val runtime = runtime()
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides TestWindows.Phone,
                    LocalExchangeHost provides exchange,
                ) {
                    val state = rememberShellState()
                    shell = state
                    UmshShell(state)
                }
            }
        }
        compose.waitUntil(TIMEOUT) { present(Tags.CONVERSATIONS_ROOT) }
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitForTag(Tags.PEERS_ADD)
        compose.onNodeWithTag(Tags.PEERS_ADD).performClick()
        waitForTag(Tags.ADD_PEER)
    }

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun waitGone(tag: String) = compose.waitUntil(TIMEOUT) { !present(tag) }

    private fun text(tag: String): String = compose.onNodeWithTag(tag, useUnmergedTree = true).fetchSemanticsNode().config
        .getOrNull(SemanticsProperties.Text)?.joinToString("") { it.text }.orEmpty()

    private fun string(id: Int, vararg args: Any) = context.getString(id, *args)

    private fun stack() = shell.stacks.getValue(Destination.Peers).toList()

    @Test
    fun everyStateInTurn() {
        show()
        // Add peer on top wants the exchange open.
        compose.waitUntil(TIMEOUT) { "wanted true" in exchange.calls }

        // Opening: nothing heard yet.
        exchange.meet.value = FakeExchangeHost.open(devices = emptyList())
        waitForTag(Tags.NEARBY_EMPTY)
        assertEquals(string(R.string.nearby_empty), text(Tags.NEARBY_EMPTY))
        waitForTag(Tags.NEARBY_YOU)

        // Board 1's Nearby: four rows, each asking its device.
        exchange.meet.value = FakeExchangeHost.open()
        compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(Tags.NEARBY_DEVICE).fetchSemanticsNodes().size == 4 }
        compose.onAllNodesWithTag(Tags.NEARBY_DEVICE)[1].performClick()
        compose.waitUntil(TIMEOUT) { "ask 2" in exchange.calls }

        // Board 1: asked.
        exchange.move(MeetExchange.Asked(FakeExchangeHost.pager), FakeExchangeHost.pager)
        waitForTag(Tags.EXCHANGE_ASKED)
        assertEquals(listOf(UmshKey.PeersRoot, UmshKey.AddPeer(Destination.Peers)), stack())
        compose.onNodeWithTag(Tags.EXCHANGE_ACCEPT).performClick()
        compose.waitUntil(TIMEOUT) { "answer true" in exchange.calls }

        // Board 2: waiting, the page pushed over Add peer.
        exchange.move(MeetExchange.Accepted(FakeExchangeHost.pager))
        waitForTag(Tags.EXCHANGE_WAITING)
        waitGone(Tags.EXCHANGE_ASKED)
        assertEquals(string(R.string.exchange_waiting, "T-LoRa Pager"), text(Tags.EXCHANGE_WAITING).filterNot { it in ISOLATES })
        compose.onNodeWithTag(Tags.EXCHANGE_WAITING_SPINNER).assertExists()
        assertEquals(UmshKey.Exchange(Destination.Peers), stack().last())
        exchange.move(MeetExchange.Asking(FakeExchangeHost.pager))
        waitForTag(Tags.EXCHANGE_WAITING)

        // Board 3: comparing.
        exchange.move(MeetExchange.Comparing(FakeExchangeHost.pager, 123_456, sent = false))
        waitForTag(Tags.EXCHANGE_SAME)
        assertEquals("123 456", text(Tags.EXCHANGE_CODE).filterNot { it in ISOLATES })
        assertEquals(string(R.string.exchange_same), compose.onNodeWithTag(Tags.EXCHANGE_SAME).fetchSemanticsNode().config.getOrNull(SemanticsProperties.Text)!!.joinToString())
        compose.onNodeWithTag(Tags.EXCHANGE_SAME).performClick()
        compose.waitUntil(TIMEOUT) { "confirm true" in exchange.calls }
        compose.onNodeWithTag(Tags.EXCHANGE_DIFFERENT).performClick()
        compose.waitUntil(TIMEOUT) { "confirm false" in exchange.calls }

        // Board 4: after Same, this side's check and the wait for the other.
        exchange.move(MeetExchange.Comparing(FakeExchangeHost.pager, 123_456, sent = true))
        waitForTag(Tags.EXCHANGE_SAME_PRESSED)
        waitGone(Tags.EXCHANGE_SAME)
        assertEquals(string(R.string.exchange_waiting, "T-LoRa Pager"), text(Tags.EXCHANGE_WAITING).filterNot { it in ISOLATES })
        compose.onNodeWithTag(Tags.EXCHANGE_WAITING_SPINNER).assertExists()

        // Board 5 and its other ending.
        exchange.move(MeetExchange.Ended(MeetEnd.Different))
        waitForTag(Tags.EXCHANGE_ENDED)
        assertEquals(string(R.string.exchange_codes_differ), text(Tags.EXCHANGE_ENDED))
        for (end in MeetEnd.entries - MeetEnd.Different) {
            exchange.move(MeetExchange.Ended(end))
            compose.waitUntil(TIMEOUT) { text(Tags.EXCHANGE_ENDED) == string(R.string.exchange_not_exchanged) }
        }
        compose.onNodeWithTag(Tags.EXCHANGE_TRY_AGAIN).performClick()
        compose.waitUntil(TIMEOUT) { "back out" in exchange.calls }
        // Starting over: the page goes as the fresh attempt opens.
        exchange.meet.value = FakeExchangeHost.open()
        waitGone(Tags.EXCHANGE)
        assertEquals(UmshKey.AddPeer(Destination.Peers), stack().last())
    }

    @Test
    fun doneAndBackLeaveForAddPeerAndBackOut() {
        show()
        exchange.meet.value = FakeExchangeHost.open()
        exchange.move(MeetExchange.Ended(MeetEnd.Left), FakeExchangeHost.pager)
        waitForTag(Tags.EXCHANGE_DONE)
        exchange.calls.clear()
        compose.onNodeWithTag(Tags.EXCHANGE_DONE).performClick()
        waitGone(Tags.EXCHANGE)
        assertEquals(UmshKey.AddPeer(Destination.Peers), stack().last())
        compose.waitUntil(TIMEOUT) { "back out" in exchange.calls }
        // Nearby again under a fresh key; the page stays down.
        compose.waitForIdle()
        assertTrue(!present(Tags.EXCHANGE))

        // The system Back on a comparing page does the same.
        exchange.move(MeetExchange.Comparing(FakeExchangeHost.pager, 42, sent = false), FakeExchangeHost.pager)
        waitForTag(Tags.EXCHANGE_CODE)
        assertEquals("000 042", text(Tags.EXCHANGE_CODE).filterNot { it in ISOLATES })
        exchange.calls.clear()
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(android.view.KeyEvent.KEYCODE_BACK)
        waitGone(Tags.EXCHANGE)
        compose.waitUntil(TIMEOUT) { "back out" in exchange.calls }
    }

    @Test
    fun backOnTheAskedSheetDeclines() {
        show()
        exchange.meet.value = FakeExchangeHost.open()
        exchange.move(MeetExchange.Asked(FakeExchangeHost.pager), FakeExchangeHost.pager)
        waitForTag(Tags.EXCHANGE_NOT_NOW)
        compose.waitForIdle()
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(android.view.KeyEvent.KEYCODE_BACK)
        compose.waitUntil(TIMEOUT) { "answer false" in exchange.calls }
        assertTrue("answer true" !in exchange.calls)
    }

    @Test
    fun withNoRadioNearbyIsOneLine() {
        show()
        exchange.meet.value = FakeExchangeHost.open()
        exchange.carries.value = false
        waitForTag(Tags.NEARBY_NO_RADIO)
        assertTrue(!present(Tags.NEARBY_DEVICE))
        assertTrue(!present(Tags.NEARBY_YOU))
    }

    private companion object {
        const val TIMEOUT = 30_000L
        val ISOLATES = setOf('⁦', '⁧', '⁨', '⁩')
    }
}
