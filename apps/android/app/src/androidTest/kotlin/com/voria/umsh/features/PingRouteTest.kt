package com.voria.umsh.features

import android.Manifest
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.ViewModelStoreOwner
import androidx.lifecycle.viewmodel.compose.LocalViewModelStoreOwner
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
import com.voria.umsh.app.setRemoteDeviceReachable
import com.voria.umsh.app.stagedAir
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.inspectPublicIdentity
import com.voria.umsh.designsystem.LocalUiTimings
import com.voria.umsh.designsystem.LocalWindowOverride
import com.voria.umsh.designsystem.UiTimings
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.models.ManualPath
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PingOutcome
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Ping and Route (`ping-route.svg` 1–5) over the staged air: Sam Ihara
 * answers through Glen Alpine Relay; Tallac Ridge, made unreachable, never
 * answers, and its ping ends "No reply" after the core's own wait (about
 * 68 s, measured in P3a). Ping again's wait comes from [LocalUiTimings],
 * shortened here so the test need not sit out 8 s.
 */
class PingRouteTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    /** Android's notification dialog would cover the activity: these tests are not about it. */
    @Before
    fun noNotificationAsk() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            InstrumentationRegistry.getInstrumentation().uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
        runBlocking { fresh.host.preferences.setNotificationsAsked() }
    }

    private fun runtime(): AppRuntime = runBlocking {
        fresh.host.preferences.setFallbackScheme(true)
        fresh.host.ensureRuntime(staging = true)
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        val runtime = ready.runtime
        withTimeout(TIMEOUT) { runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        withTimeout(TIMEOUT) { runtime.radio.first { it?.carriesThisPhone == true } }
        withTimeout(TIMEOUT) { runtime.appState.first { state -> state?.peers?.any { it.address == SAM } == true } }
        runtime
    }

    /** The shell; [store] gives its ViewModels, swapped by a test to stand for a process that died. */
    private fun show(
        runtime: AppRuntime,
        timings: UiTimings = UiTimings(pingAgainAfterMs = AGAIN_MS),
        restoration: StateRestorationTester? = null,
        store: () -> ViewModelStoreOwner? = { null },
    ) {
        val content: @androidx.compose.runtime.Composable () -> Unit = {
            UmshTheme(fallbackScheme = true) {
                val owner = store() ?: checkNotNull(LocalViewModelStoreOwner.current)
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides TestWindows.Phone,
                    LocalUiTimings provides timings,
                    LocalViewModelStoreOwner provides owner,
                ) {
                    val state = rememberShellState()
                    shell = state
                    UmshShell(state)
                }
            }
        }
        if (restoration != null) restoration.setContent(content) else compose.setContent(content)
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertExists()
    }

    private fun waitFor(timeout: Long = TIMEOUT, condition: () -> Boolean) = compose.waitUntil(timeout, condition)

    private fun present(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()

    private fun waitForUnmerged(tag: String) =
        compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty() }

    private fun waitForTag(tag: String) = waitFor { present(tag) }

    private fun description(tag: String): String =
        compose.onNodeWithTag(tag).fetchSemanticsNode().config.getOrNull(SemanticsProperties.ContentDescription)?.joinToString().orEmpty()

    private fun openPage(address: String) {
        compose.runOnUiThread {
            shell.select(Destination.Peers)
            shell.openPeerFromList(address)
        }
        waitForTag(Tags.PEER_PAGE)
    }

    private fun ping() {
        compose.onNodeWithTag(Tags.PEER_VERB_PING).performClick()
        waitForTag(Tags.PING_SHEET)
    }

    private fun waitForReply(timeout: Long = TIMEOUT) {
        val replied = context.getString(R.string.ping_reply_spoken_bare)
        waitFor(timeout) { present(Tags.PING_RESULT) && description(Tags.PING_RESULT).startsWith(replied) }
    }

    private fun text(id: Int, vararg args: Any) = context.getString(id, *args)

    private fun hasSnackbar(text: String) = compose.onAllNodes(hasText(text)).fetchSemanticsNodes().isNotEmpty()

    // --- Ping -----------------------------------------------------------

    /**
     * Board 1: the round trip and hops, the reply's path with the relay
     * named by its hint (so the footer) and both legs read, Earlier after
     * a second ping; the named relay opens its page on the same stack.
     */
    @Test
    fun aReplyShowsItsPathAndANamedRepeaterOpensItsPage() {
        val runtime = runtime()
        show(runtime)
        openPage(SAM)
        ping()
        waitForReply()
        val hops = context.resources.getQuantityString(R.plurals.route_hops, 2, 2)
        assertTrue(description(Tags.PING_RESULT), description(Tags.PING_RESULT).endsWith(hops))
        val relayRow = Tags.railRepeater(RELAY_HINT.toHex())
        waitFor { compose.onAllNodes(hasTestTag(relayRow) and hasText("Glen Alpine Relay", substring = true)).fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithText(text(R.string.repeater_hint_footer)).assertExists()
        // Two legs, each read: the phone's own, and how the relay heard Sam.
        val readings = compose.onAllNodesWithTag(Tags.RAIL_LEG).fetchSemanticsNodes()
            .map { it.config.getOrNull(SemanticsProperties.ContentDescription)?.joinToString().orEmpty() }
        assertEquals(readings.toString(), 2, readings.count { "dBm" in it })

        compose.onNodeWithTag(Tags.PING_AGAIN).performClick()
        waitFor { compose.onAllNodesWithTag(Tags.PING_EARLIER_ROW).fetchSemanticsNodes().isNotEmpty() }
        waitForReply()

        compose.onNodeWithTag(relayRow).performScrollTo().performClick()
        waitFor { !present(Tags.PING_SHEET) }
        waitFor { shell.stacks.getValue(Destination.Peers).last() == UmshKey.PeerPage(RELAY, Destination.Peers) }
    }

    /**
     * Board 2, and the recreation rule's other half: while waiting the
     * elapsed time counts beside the spinner and Ping again is off for the
     * (injected) wait, then on while the ping is still out; a new ping
     * replaces it and starts the count over. Board 3: nothing comes back
     * within the core's wait, so "No reply" and the broken leg.
     */
    @Test
    fun waitingThenPingAgainThenNoReply() {
        val runtime = runtime()
        fresh.stagedAir.setRemoteDeviceReachable(false)
        show(runtime)
        openPage(TALLAC)
        ping()
        waitForUnmerged(Tags.PING_ELAPSED)
        compose.onNodeWithTag(Tags.PING_AGAIN).assertIsNotEnabled()
        assertEquals(text(R.string.waiting_for_reply), description(Tags.PING_RESULT))
        val waited = System.nanoTime()
        waitFor { runCatching { compose.onNodeWithTag(Tags.PING_AGAIN).assertIsEnabled() }.isSuccess }
        val enabledAfterMs = (System.nanoTime() - waited) / 1_000_000
        assertTrue("enabled after $enabledAfterMs ms", enabledAfterMs < AGAIN_MS + 3_000)
        assertTrue("still waiting", compose.onAllNodesWithTag(Tags.PING_ELAPSED, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty())
        // The replacement starts the wait over: Ping again is off again.
        compose.onNodeWithTag(Tags.PING_AGAIN).performClick()
        compose.onNodeWithTag(Tags.PING_AGAIN).assertIsNotEnabled()

        val noReply = text(R.string.ping_no_reply)
        waitFor(NO_REPLY_BUDGET_MS) { present(Tags.PING_RESULT) && description(Tags.PING_RESULT) == noReply }
        val broken = compose.onAllNodesWithTag(Tags.RAIL_LEG).fetchSemanticsNodes()
            .map { it.config.getOrNull(SemanticsProperties.ContentDescription)?.joinToString().orEmpty() }
        assertEquals(listOf(text(R.string.path_no_path)), broken)
        compose.onNodeWithTag(Tags.PING_AGAIN).assertIsEnabled()
    }

    /** Reset route under the path: "Route reset", then, with nothing left, "No route to reset". */
    @Test
    fun resetRouteSaysWhetherThereWasOne() {
        val runtime = runtime()
        show(runtime)
        openPage(SAM)
        ping()
        waitForReply()
        compose.onNodeWithTag(Tags.PING_RESET_ROUTE).performScrollTo().performClick()
        waitFor { hasSnackbar(text(R.string.route_reset_notice)) }
        // The notice is drawn over the sheet's foot, where the button is: its time out first.
        waitFor { !hasSnackbar(text(R.string.route_reset_notice)) }
        compose.onNodeWithTag(Tags.PING_RESET_ROUTE).performClick()
        waitFor { hasSnackbar(text(R.string.route_reset_none_notice)) }
    }

    /**
     * After process death a sheet does not reopen: the stacks come back
     * from saved state, the ViewModels (and the sheet's being open with
     * them) do not, and nothing is sent.
     */
    @Test
    fun theSheetDoesNotReopenAfterProcessDeath() {
        val runtime = runtime()
        val restoration = StateRestorationTester(compose)
        var store: ViewModelStoreOwner? = null
        show(runtime, restoration = restoration, store = { store })
        openPage(SAM)
        ping()
        waitForReply()
        val fresh = object : ViewModelStoreOwner {
            override val viewModelStore = ViewModelStore()
        }
        store = fresh
        restoration.emulateSavedInstanceStateRestore()
        waitForTag(Tags.PEER_PAGE)
        assertEquals(UmshKey.PeerPage(SAM, Destination.Peers), shell.stacks.getValue(Destination.Peers).last())
        compose.waitForIdle()
        assertTrue(!present(Tags.PING_SHEET))
        compose.runOnUiThread { fresh.viewModelStore.clear() }
    }

    // --- Route ----------------------------------------------------------

    /**
     * Board 4: a learned route, from the strip's Route cell on the page's
     * own stack (D12). Numbered path with the relay named and the footer;
     * Next send, Confirmed, Reset route and where it was learned.
     */
    @Test
    fun aLearnedRoute() {
        val runtime = runtime()
        runBlocking { assertTrue(runtime.ping(SAM).await() is PingOutcome.Reply) }
        show(runtime)
        openPage(SAM)
        waitFor { description(Tags.PEER_GLANCE_ROUTE).endsWith(context.resources.getQuantityString(R.plurals.route_hops, 2, 2)) }
        compose.onNodeWithTag(Tags.PEER_GLANCE_ROUTE).performClick()
        waitForTag(Tags.ROUTE_PAGE)
        assertEquals(UmshKey.Route(SAM, Destination.Peers), shell.stacks.getValue(Destination.Peers).last())
        waitFor { compose.onAllNodes(hasTestTag(Tags.railRepeater(RELAY_HINT.toHex())) and hasText("Glen Alpine Relay", substring = true)).fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag(Tags.ROUTE_AMBIGUITY).assertExists()
        assertRow(Tags.ROUTE_NEXT_SEND, text(R.string.route_kind_source))
        compose.onNodeWithTag(Tags.ROUTE_CONFIRMED).assertExists()
        compose.onNodeWithTag(Tags.ROUTE_HELD_UNTIL).assertDoesNotExist()
        compose.onNodeWithTag(Tags.ROUTE_RESET).performScrollTo().assertIsEnabled()
        compose.onNodeWithTag(Tags.ROUTE_EXPLANATION).performScrollTo()
        assertTrue(compose.onAllNodes(hasText("Sam Ihara", substring = true) and hasTestTag(Tags.ROUTE_EXPLANATION)).fetchSemanticsNodes().isNotEmpty())

        compose.onNodeWithTag(Tags.ROUTE_RESET).performClick()
        waitFor { rowValue(Tags.ROUTE_NEXT_SEND) == text(R.string.route_kind_unknown) }
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).performClick()
        waitFor { shell.stacks.getValue(Destination.Peers).last() == UmshKey.PeerPage(SAM, Destination.Peers) }
        // The page beneath read the route again: the strip no longer says 2 hops.
        waitFor { description(Tags.PEER_GLANCE_ROUTE).endsWith(text(R.string.route_brief_flood)) }
    }

    /**
     * Board 5: a manual path set through the runtime: Manual · 3 hops, Then
     * flood, Held until, Last ack, the hop nobody owns "Entered by hand",
     * Clear manual path and the hold's line. Clearing it leaves a route not
     * held.
     */
    @Test
    fun aHeldPathAndClearingIt() {
        val runtime = runtime()
        val path = ManualPath(listOf(Octets(RELAY_HINT), Octets(NOBODY)), floodHops = 1)
        runBlocking { assertTrue(runtime.setManualPath(SAM, path, HOLD_MS).await()) }
        show(runtime)
        openPage(SAM)
        waitFor { description(Tags.PEER_GLANCE_ROUTE).endsWith(text(R.string.route_brief_manual)) }
        compose.onNodeWithTag(Tags.PEER_GLANCE_ROUTE).performClick()
        waitForTag(Tags.ROUTE_PAGE)
        assertRow(Tags.ROUTE_NEXT_SEND, context.resources.getQuantityString(R.plurals.route_kind_manual_hops, 3, 3))
        assertRow(Tags.ROUTE_THEN_FLOOD, context.resources.getQuantityString(R.plurals.route_hops, 1, 1))
        compose.onNodeWithTag(Tags.ROUTE_HELD_UNTIL).assertExists()
        // No ack yet: drawn as a dash, read as the label then "Unknown".
        val lastAck = compose.onNodeWithTag(Tags.ROUTE_LAST_ACK).fetchSemanticsNode().config
        assertEquals(text(R.string.route_value_unknown), lastAck.getOrNull(SemanticsProperties.StateDescription))
        assertEquals(listOf(text(R.string.route_last_ack)), lastAck.getOrNull(SemanticsProperties.Text)?.map { it.text })
        compose.onNodeWithTag(Tags.ROUTE_CONFIRMED).assertDoesNotExist()
        val typed = Tags.railRepeater(NOBODY.toHex())
        assertTrue(compose.onAllNodes(hasTestTag(typed) and hasText(text(R.string.path_entered_by_hand))).fetchSemanticsNodes().isNotEmpty())
        // The relay's hop is named, so it is not marked typed.
        assertTrue(compose.onAllNodes(hasTestTag(Tags.railRepeater(RELAY_HINT.toHex())) and hasText(text(R.string.path_entered_by_hand))).fetchSemanticsNodes().isEmpty())
        compose.onNodeWithTag(Tags.ROUTE_EXPLANATION).performScrollTo()
        assertTrue(compose.onAllNodes(hasTestTag(Tags.ROUTE_EXPLANATION) and hasText(text(R.string.route_held_explanation))).fetchSemanticsNodes().isNotEmpty())
        compose.onNodeWithTag(Tags.ROUTE_RESET).assertDoesNotExist()

        compose.onNodeWithTag(Tags.ROUTE_CLEAR_MANUAL).performScrollTo().performClick()
        waitFor { !present(Tags.ROUTE_HELD_UNTIL) }
        compose.onNodeWithTag(Tags.ROUTE_CLEAR_MANUAL).assertDoesNotExist()
        assertTrue(runBlocking { !runtime.peerRoute(SAM).await().isHeld })
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).performClick()
        // The page beneath read the route again: the strip no longer says Manual.
        waitFor { description(Tags.PEER_GLANCE_ROUTE).endsWith(text(R.string.route_brief_flood)) }
    }

    // --- TalkBack (§3.10) ----------------------------------------------

    /**
     * The strip's Route cell is one button with "Open route"; the result is
     * one polite live region that reads "Waiting for a reply" while the
     * count ticks, then the result; each rail stop and leg is one node.
     */
    @Test
    fun whatTalkBackReads() {
        val runtime = runtime()
        show(runtime)
        openPage(SAM)
        val cell = compose.onNodeWithTag(Tags.PEER_GLANCE_ROUTE).fetchSemanticsNode()
        assertEquals(text(R.string.glance_open_route), cell.config[SemanticsActions.OnClick].label)
        assertEquals(Role.Button, cell.config.getOrNull(SemanticsProperties.Role))
        assertTrue(cell.children.isEmpty())
        ping()
        val result = compose.onNodeWithTag(Tags.PING_RESULT).fetchSemanticsNode()
        assertEquals(LiveRegionMode.Polite, result.config.getOrNull(SemanticsProperties.LiveRegion))
        // What the row draws (the ticking count among it) is hidden: only its description is read.
        val hidden = compose.onAllNodes(
            hasAnyAncestor(hasTestTag(Tags.PING_RESULT)) and SemanticsMatcher.keyIsDefined(SemanticsProperties.HideFromAccessibility),
            useUnmergedTree = true,
        ).fetchSemanticsNodes()
        assertTrue("the count is not read", hidden.isNotEmpty())
        waitForReply()
        val spoken = description(Tags.PING_RESULT)
        assertTrue(spoken, spoken.startsWith(text(R.string.ping_reply_spoken_bare)) && "second" in spoken)
        val relay = compose.onNodeWithTag(Tags.railRepeater(RELAY_HINT.toHex())).fetchSemanticsNode()
        assertEquals(text(R.string.open_peer_page), relay.config[SemanticsActions.OnClick].label)
        for (tag in listOf(Tags.RAIL_PHONE, Tags.RAIL_PEER)) {
            val node = compose.onNodeWithTag(tag).fetchSemanticsNode()
            assertTrue("$tag merged", node.config.isMergingSemanticsOfDescendants)
        }
        compose.onAllNodesWithTag(Tags.RAIL_LEG).fetchSemanticsNodes().forEach { leg ->
            assertTrue(leg.children.isEmpty())
        }
        val again = compose.onNodeWithTag(Tags.PING_AGAIN).fetchSemanticsNode().touchBoundsInRoot
        assertTrue("$again", again.height >= minTouch())
    }

    private fun rowValue(tag: String): String? =
        compose.onAllNodes(hasTestTag(tag)).fetchSemanticsNodes().singleOrNull()
            ?.config?.getOrNull(SemanticsProperties.Text)?.map { it.text }?.lastOrNull()

    private fun assertRow(tag: String, value: String) {
        waitFor { rowValue(tag) == value }
    }

    private fun minTouch(): Int = (48 * context.resources.displayMetrics.density).toInt() - 1

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it.toInt() and 0xFF) }

    private fun androidx.compose.ui.test.junit4.ComposeTestRule.onNodeWithText(text: String) =
        onNode(hasText(text))

    private companion object {
        const val TIMEOUT = 30_000L

        /** Ping again's wait here, shortened from 8 s. */
        const val AGAIN_MS = 1_500L

        /** The core's ping timeout on the staged air (about 68 s), with room. */
        const val NO_REPLY_BUDGET_MS = 150_000L

        const val HOLD_MS = 3_600_000L

        fun address(seed: Int) = MobileIdentity.unlock(ByteArray(32) { seed.toByte() }).use { it.publicIdentity().canonicalAddress }

        val SAM = address(0x66)
        val RELAY = address(0x77)
        val TALLAC = address(0x22)
        val RELAY_HINT: ByteArray = inspectPublicIdentity(RELAY).hint.bytes.copyOf(2)

        /** A repeater hint no staged node owns. */
        val NOBODY = byteArrayOf(0x00, 0x01)
    }
}
