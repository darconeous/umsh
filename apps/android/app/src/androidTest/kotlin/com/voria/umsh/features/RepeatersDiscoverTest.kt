package com.voria.umsh.features

import android.Manifest
import android.content.ClipboardManager
import android.os.Build
import androidx.activity.ComponentActivity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.longClick
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
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
import com.voria.umsh.app.setRemoteDeviceReachable
import com.voria.umsh.app.stagedAir
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.inspectPublicIdentity
import com.voria.umsh.designsystem.LocalWindowOverride
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.peers.LocalNeighborSource
import com.voria.umsh.features.peers.NeighborSource
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PingOutcome
import com.voria.umsh.models.RepeaterListing
import com.voria.umsh.models.RepeaterNeighbor
import java.util.Collections
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Neighboring repeaters and Discover (`repeaters-discover.svg` 1–5) over
 * the staged air: Tallac Ridge answers Peer Repeaters requests (and, made
 * unreachable, does not); the nodes in the radio's range answer Discover;
 * the core's 40 s cooldown is waited out for real. Paging needs more
 * neighbors than the staged air has, so Load more runs over a stand-in
 * source ([LocalNeighborSource]).
 */
class RepeatersDiscoverTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

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
        withTimeout(TIMEOUT) { runtime.appState.first { state -> state?.peers?.any { it.address == TALLAC } == true } }
        runtime
    }

    private fun show(runtime: AppRuntime, source: NeighborSource? = null) {
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides TestWindows.Phone,
                    LocalNeighborSource provides source,
                ) {
                    val state = rememberShellState()
                    shell = state
                    UmshShell(state)
                }
            }
        }
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertExists()
    }

    private fun waitFor(timeout: Long = TIMEOUT, condition: () -> Boolean) = compose.waitUntil(timeout, condition)

    private fun present(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String, timeout: Long = TIMEOUT) = waitFor(timeout) { present(tag) }

    private fun text(id: Int, vararg args: Any) = context.getString(id, *args)

    private fun liveRegionOf(tag: String): LiveRegionMode? =
        compose.onNodeWithTag(tag, useUnmergedTree = true).fetchSemanticsNode().config.getOrNull(SemanticsProperties.LiveRegion)

    private fun textOf(tag: String, unmerged: Boolean = false): String =
        compose.onAllNodesWithTag(tag, useUnmergedTree = unmerged).fetchSemanticsNodes().singleOrNull()
            ?.config?.getOrNull(SemanticsProperties.Text)?.joinToString { it.text }.orEmpty()

    private fun shows(text: String) = compose.onAllNodes(hasText(text, substring = true)).fetchSemanticsNodes().isNotEmpty()

    private fun enabled(tag: String) = runCatching { compose.onNodeWithTag(tag).assertIsEnabled() }.isSuccess

    private fun openNeighbors(address: String) {
        compose.runOnUiThread {
            shell.select(Destination.Peers)
            shell.openPeerFromList(address)
        }
        waitForTag(Tags.PEER_VERB_NEIGHBORS)
        compose.onNodeWithTag(Tags.PEER_VERB_NEIGHBORS).performClick()
        waitForTag(Tags.NEIGHBORS_PAGE)
        waitForTag(Tags.NEIGHBORS_FOOTER)
    }

    private fun openDiscoverFromList() {
        compose.runOnUiThread { shell.select(Destination.Peers) }
        waitForTag(Tags.PEERS_LIST)
        compose.onNodeWithTag(Tags.PEERS_LIST).performScrollToNode(hasTestTag(Tags.PEERS_DISCOVER))
        compose.onNodeWithTag(Tags.PEERS_DISCOVER).performClick()
        waitForTag(Tags.DISCOVER_PAGE)
    }

    // --- Neighbors ------------------------------------------------------

    /**
     * Board 1 and the page's promise: opening sends nothing (the store
     * still holds no listing for Tallac Ridge seconds later, though the
     * staged air answers an ask in well under one), "Not read"; Refresh
     * reads the repeater, whose listing names Glen Alpine Relay, which
     * opens its page on the same stack.
     */
    @Test
    fun openingSendsNothingAndRefreshReadsTheRepeater() {
        val runtime = runtime()
        show(runtime)
        openNeighbors(TALLAC)
        assertEquals(text(R.string.neighbors_not_read), textOf(Tags.NEIGHBORS_EMPTY))
        assertEquals(text(R.string.neighbors_nothing_read), textOf(Tags.NEIGHBORS_FOOTER))
        Thread.sleep(QUIET_MS)
        assertNull("opening the page asked nothing", runBlocking { runtime.storedNeighbors(TALLAC) })

        compose.onNodeWithTag(Tags.NEIGHBORS_REFRESH).performClick()
        waitFor(PAGE_BUDGET_MS) { textOf(Tags.NEIGHBORS_FOOTER) == text(R.string.neighbors_read_now) }
        assertNotNull(runBlocking { runtime.storedNeighbors(TALLAC) })
        assertTrue(compose.onAllNodesWithTag(Tags.NEIGHBORS_EMPTY).fetchSemanticsNodes().isEmpty())
        val glen = compose.onAllNodes(hasText("Glen Alpine Relay", substring = true) and SemanticsMatcher("a neighbor row") { node ->
            node.config.getOrNull(SemanticsProperties.TestTag)?.startsWith("neighbor_row/") == true
        })
        waitFor { glen.fetchSemanticsNodes().isNotEmpty() }
        glen[0].performScrollTo().performClick()
        waitFor { shell.stacks.getValue(Destination.Peers).last() == UmshKey.PeerPage(RELAY, Destination.Peers) }
        assertEquals(UmshKey.Neighbors(TALLAC, Destination.Peers), shell.stacks.getValue(Destination.Peers).let { it[it.size - 2] })
    }

    /**
     * §3.4 and board 1: with a route that lands at Tallac Ridge, an unknown
     * neighbor's hint has a lookup button, which sends (the spinner takes
     * its place). A row with a position and nothing to open has a long
     * press and no tap; it copies the coordinates, which Android 12 confirms
     * with a snackbar.
     */
    @Test
    fun anUnknownNeighborLooksUpAndCopiesItsCoordinates() {
        val runtime = runtime()
        landingRoute(runtime)
        val positioned = RepeaterNeighbor(
            hint = Octets(byteArrayOf(0x8C.toByte(), 0x01)),
            hintText = "8C*",
            name = null,
            rssiDbm = -95,
            snrQuarterDb = 12,
            lastHeardMinutes = 20,
            latitude = 44.0521,
            longitude = -123.0868,
            locationPrecision = null,
            regionCodes = emptyList(),
            reportedAtMs = System.currentTimeMillis(),
            peerAddress = null,
        )
        show(runtime, PagedSource(listOf(RepeaterListing(listOf(positioned), 1, null, System.currentTimeMillis()))))
        openNeighbors(TALLAC)
        compose.onNodeWithTag(Tags.NEIGHBORS_REFRESH).performClick()
        val hex = positioned.hint.hex()
        waitFor { compose.onAllNodesWithTag(Tags.hintLookup(hex), useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty() }

        val row = compose.onNodeWithTag(Tags.neighborRow(hex)).fetchSemanticsNode()
        assertNull("no tap that does nothing", row.config.getOrNull(SemanticsActions.OnClick))
        assertEquals(text(R.string.peer_actions), row.config.getOrNull(SemanticsActions.OnLongClick)?.label)
        compose.onNodeWithTag(Tags.neighborRow(hex)).performTouchInput { longClick(Offset(width * 0.3f, height / 2f)) }
        waitForTag(Tags.NEIGHBOR_MENU)
        compose.onNodeWithTag(Tags.NEIGHBOR_COPY_COORDINATES).performClick()
        waitFor { !present(Tags.NEIGHBOR_MENU) }
        val copied = compose.runOnUiThread<String?> {
            context.getSystemService(ClipboardManager::class.java).primaryClip?.getItemAt(0)?.text?.toString()
        }
        assertEquals("44.05210, -123.08680", copied)
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.S_V2) {
            waitFor { shows(text(R.string.coordinates_copied)) }
        }

        compose.onNodeWithTag(Tags.hintLookup(hex), useUnmergedTree = true).performClick()
        val waiting = text(R.string.waiting_for_reply)
        waitFor {
            compose.onAllNodes(SemanticsMatcher("waiting") { it.config.getOrNull(SemanticsProperties.StateDescription) == waiting }, useUnmergedTree = true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        assertTrue("the lookup went", !present(Tags.FAILURE_DIALOG))
    }

    /**
     * Ping Tallac Ridge until its route lands at it: a reply by flood
     * leaves no repeaters to steer by.
     */
    private fun landingRoute(runtime: AppRuntime) {
        val route = (1..PING_TRIES).firstNotNullOfOrNull {
            val outcome = runBlocking { runtime.ping(TALLAC).await() }
            val route = runBlocking { runtime.peerRoute(TALLAC).await() }
            android.util.Log.i(TAG, "ping $it: $outcome; route $route")
            route.takeIf { outcome is PingOutcome.Reply && it.discoveryVantage?.landsAtPeer == true }
        }
        assertNotNull("a route that lands at Tallac Ridge", route)
    }

    /** Load more asks for the cursor the last page gave, and the listing grows: "4 of 9", then "8 of 9". */
    @Test
    fun loadMoreAsksForTheNextPage() {
        val runtime = runtime()
        val source = PagedSource(
            listOf(
                listing(4, total = 9, cursor = Octets(byteArrayOf(0, 1, 4))),
                listing(8, total = 9, cursor = Octets(byteArrayOf(0, 1, 8))),
            ),
        )
        show(runtime, source)
        openNeighbors(TALLAC)
        compose.onNodeWithTag(Tags.NEIGHBORS_REFRESH).performClick()
        waitForTag(Tags.NEIGHBORS_LOAD_MORE)
        assertEquals(text(R.string.neighbors_count, 4, 9), textOf(Tags.NEIGHBORS_COUNT, unmerged = true))
        compose.onNodeWithTag(Tags.NEIGHBORS_LOAD_MORE).performScrollTo().performClick()
        // Eight rows push Load more below the fold on a small screen, where the list drops it.
        waitFor { compose.onAllNodes(hasTestTag(Tags.neighborRow("4007"))).fetchSemanticsNodes().isNotEmpty() || source.cursors.size == 2 }
        compose.onNodeWithTag(Tags.NEIGHBORS_LIST).performScrollToNode(hasTestTag(Tags.NEIGHBORS_LOAD_MORE))
        waitFor { textOf(Tags.NEIGHBORS_COUNT, unmerged = true) == text(R.string.neighbors_count, 8, 9) }
        assertEquals(listOf(null, Octets(byteArrayOf(0, 1, 4))), source.cursors)
        // The eighth neighbor is listed after the first page's four.
        compose.onNodeWithTag(Tags.NEIGHBORS_LIST).performScrollToNode(hasTestTag(Tags.neighborRow("4007")))
    }

    /** A repeater that answers with none: "None", not "Not read", and no Load more. */
    @Test
    fun aRepeaterThatListsNoneSaysNone() {
        val runtime = runtime()
        val none = PagedSource(listOf(RepeaterListing(emptyList(), 0, null, System.currentTimeMillis())))
        show(runtime, none)
        openNeighbors(TALLAC)
        assertEquals(text(R.string.neighbors_not_read), textOf(Tags.NEIGHBORS_EMPTY))
        compose.onNodeWithTag(Tags.NEIGHBORS_REFRESH).performClick()
        waitFor { textOf(Tags.NEIGHBORS_EMPTY) == text(R.string.neighbors_none) }
        assertTrue(compose.onAllNodesWithTag(Tags.NEIGHBORS_LOAD_MORE).fetchSemanticsNodes().isEmpty())
        // The outcome is announced.
        assertEquals(LiveRegionMode.Polite, liveRegionOf(Tags.NEIGHBORS_EMPTY))
    }

    /** Board 2: Tallac Ridge made unreachable never answers; the reason is inline, not a dialog, and nothing is kept. */
    @Test
    fun anUnansweredRefreshSaysSoInline() {
        val runtime = runtime()
        fresh.stagedAir.setRemoteDeviceReachable(false)
        show(runtime)
        openNeighbors(TALLAC)
        compose.onNodeWithTag(Tags.NEIGHBORS_REFRESH).performClick()
        waitForTag(Tags.NEIGHBORS_BUSY)
        val started = System.nanoTime()
        waitForTag(Tags.NEIGHBORS_NO_ANSWER, NO_ANSWER_BUDGET_MS)
        android.util.Log.i(TAG, "no answer after ${(System.nanoTime() - started) / 1_000_000} ms")
        assertEquals(text(R.string.neighbors_no_answer), textOf(Tags.NEIGHBORS_NO_ANSWER))
        assertEquals(text(R.string.neighbors_not_read), textOf(Tags.NEIGHBORS_EMPTY))
        assertEquals(LiveRegionMode.Polite, liveRegionOf(Tags.NEIGHBORS_NO_ANSWER))
        assertEquals(text(R.string.neighbors_nothing_read), textOf(Tags.NEIGHBORS_FOOTER))
        assertTrue(compose.onAllNodesWithTag(Tags.FAILURE_DIALOG).fetchSemanticsNodes().isEmpty())
        assertTrue(enabled(Tags.NEIGHBORS_REFRESH))
    }

    // --- Discover -------------------------------------------------------

    /**
     * Boards 3–4: from the Peers list's last row, Ask goes; the line under
     * it counts down while Ask is off; meanwhile a second unnarrowed ask is
     * refused and a narrowed lookup is not; the staged nodes in range fill
     * Heard since opened; after the core's 40 s (real time) Ask is back,
     * TalkBack is told once, and the line says who answers.
     */
    @Test
    fun theCooldownCountsDownAndAskComesBack() {
        val runtime = runtime()
        show(runtime)
        openDiscoverFromList()
        assertEquals(UmshKey.Discover(null, Destination.Peers), shell.stacks.getValue(Destination.Peers).last())
        assertEquals(text(R.string.discover_nothing_heard), textOf(Tags.DISCOVER_HEARD_EMPTY))
        assertEquals(text(R.string.discover_nearby_footer), textOf(Tags.DISCOVER_ASK_FOOTER))
        compose.onNodeWithTag(Tags.DISCOVER_ASK).performClick()
        val asked = System.nanoTime()
        val askedPrefix = text(R.string.discover_asked_wait, "").substringBefore(" Ask again")
        waitFor { textOf(Tags.DISCOVER_ASK_FOOTER).startsWith(askedPrefix) }
        compose.onNodeWithTag(Tags.DISCOVER_ASK).assertIsNotEnabled()
        val first = textOf(Tags.DISCOVER_ASK_FOOTER)
        Thread.sleep(2_100)
        val second = textOf(Tags.DISCOVER_ASK_FOOTER)
        assertNotEquals("the line counts down", first, second)
        android.util.Log.i(TAG, "footer: \"$first\" then \"$second\"")

        runBlocking {
            try {
                runtime.discover(null, emptyList()).await()
                fail("a second ask during the cooldown")
            } catch (_: MobileAppException.InvalidRequest) {
            }
            runtime.lookUpRepeaterHint(Octets(inspectPublicIdentity(RELAY).hint.bytes.copyOf(2)), emptyList()).await()
        }

        assertNull(readyDescription())

        waitFor(COOLDOWN_BUDGET_MS) { enabled(Tags.DISCOVER_ASK) }
        val back = (System.nanoTime() - asked) / 1_000_000
        android.util.Log.i(TAG, "Ask back after $back ms")
        assertTrue("Ask back after $back ms", back in 35_000L..COOLDOWN_BUDGET_MS)
        assertEquals(text(R.string.discover_nearby_footer), textOf(Tags.DISCOVER_ASK_FOOTER))
        assertEquals(text(R.string.discover_ready_spoken), readyDescription())
        val ready = compose.onNodeWithTag(Tags.DISCOVER_READY, useUnmergedTree = true).fetchSemanticsNode()
        assertEquals(LiveRegionMode.Polite, ready.config.getOrNull(SemanticsProperties.LiveRegion))

        // Each node holds its answer for a random 0.5–30 s, so by now every
        // node in range that answers has; which do is the air's. Glen Alpine
        // Relay answers the lookup as well.
        waitFor(HEARD_BUDGET_MS) { heardRows().let { RELAY in it && it.size >= 2 } }
        android.util.Log.i(TAG, "heard rows: ${heardRows()}")
        assertTrue(compose.onAllNodesWithTag(Tags.DISCOVER_HEARD_EMPTY).fetchSemanticsNodes().isEmpty())
    }

    private fun heardRows(): List<String> = compose.onAllNodes(SemanticsMatcher("a heard row") { node ->
        node.config.getOrNull(SemanticsProperties.TestTag)?.startsWith("discover_row/") == true
    }).fetchSemanticsNodes().map { it.config[SemanticsProperties.TestTag].removePrefix("discover_row/") }

    private fun readyDescription(): String? =
        compose.onNodeWithTag(Tags.DISCOVER_READY, useUnmergedTree = true).fetchSemanticsNode()
            .config.getOrNull(SemanticsProperties.ContentDescription)?.joinToString()

    /** Board 4: a node heard and not saved has an add button, which saves it; a saved one reads "Saved". */
    @Test
    fun theAddButtonSavesADiscoveredNode() {
        val runtime = runtime()
        show(runtime)
        openDiscoverFromList()
        compose.onNodeWithTag(Tags.DISCOVER_ASK).performClick()
        waitForTag(Tags.discoverSave(RELAY), HEARD_BUDGET_MS)
        compose.onNodeWithTag(Tags.discoverSave(RELAY)).performScrollTo().performClick()
        waitFor { runtime.appState.value?.peers?.firstOrNull { it.address == RELAY }?.isSaved == true }
        waitFor { !present(Tags.discoverSave(RELAY)) }
        val saved = text(R.string.discover_saved_role, text(R.string.role_repeater))
        assertTrue(compose.onAllNodes(hasTestTag(Tags.discoverRow(RELAY)) and hasText(saved, substring = true)).fetchSemanticsNodes().isNotEmpty())
        // A row opens its page, on Discover's stack.
        compose.onNodeWithTag(Tags.discoverRow(RELAY)).performClick()
        waitFor { shell.stacks.getValue(Destination.Peers).last() == UmshKey.PeerPage(RELAY, Destination.Peers) }
    }

    /**
     * Board 5: Announce my identity asks first, naming what is broadcast;
     * Cancel closes the dialog, and Announce is taken without a failure.
     * Whether a frame goes out is not visible here: the core queues the
     * announcement and reports no transmission failure for it, so the
     * gated `AnnounceBridgeTest` is what sees the frame.
     */
    @Test
    fun announcingAsksFirst() {
        val runtime = runtime()
        show(runtime)
        openDiscoverFromList()
        compose.onNodeWithTag(Tags.DISCOVER_ANNOUNCE).performScrollTo().performClick()
        waitForTag(Tags.CONFIRM_DIALOG)
        val name = runtime.identity.value.advertisedName
        val body = if (name.isBlank()) text(R.string.announce_body_nameless) else text(R.string.announce_body_named, "\u2068$name\u2069")
        assertTrue(shows(body))
        compose.onNodeWithTag(Tags.CONFIRM_CANCEL).performClick()
        waitFor { !present(Tags.CONFIRM_DIALOG) }
        compose.onNodeWithTag(Tags.DISCOVER_ANNOUNCE).performClick()
        waitForTag(Tags.CONFIRM_DIALOG)
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        waitFor { !present(Tags.CONFIRM_DIALOG) }
        Thread.sleep(QUIET_MS)
        assertTrue("announced without a failure", !present(Tags.FAILURE_DIALOG))
    }

    /**
     * The overflow's Clear discovered nodes, confirmed: Glen Alpine Relay
     * (heard, never saved) goes, and its page open on Conversations closes;
     * saved nodes stay.
     */
    @Test
    fun clearingDiscoveredNodesLeavesSavedOnesAndClosesAnUnsavedPage() {
        val runtime = runtime()
        show(runtime)
        compose.runOnUiThread {
            shell.openPeer(RELAY, Destination.Conversations)
        }
        waitFor { shell.stacks.getValue(Destination.Conversations).last() == UmshKey.PeerPage(RELAY, Destination.Conversations) }
        openDiscoverFromList()
        compose.onNodeWithTag(Tags.DISCOVER_MORE).performClick()
        waitForTag(Tags.DISCOVER_CLEAR)
        compose.onNodeWithTag(Tags.DISCOVER_CLEAR).performClick()
        waitForTag(Tags.CONFIRM_DIALOG)
        assertTrue(shows(text(R.string.clear_discovered_body)))
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        waitFor { runtime.appState.value?.peers?.none { it.address == RELAY } == true }
        waitFor { shell.stacks.getValue(Destination.Conversations).none { it is UmshKey.PeerPage } }
        val peers = runtime.appState.value!!.peers
        assertTrue("saved nodes stay", peers.any { it.address == MAYA && it.isSaved } && peers.any { it.address == TALLAC })
        assertEquals(listOf(UmshKey.ConversationsRoot), shell.stacks.getValue(Destination.Conversations).toList())
    }

    /**
     * Ask near this node on a Route page (`ping-route.svg` 4): Discover
     * pushed on the same stack (D12), aimed one hop out at Tallac Ridge,
     * which the ask then goes through.
     */
    @Test
    fun askNearThisNodeAimsDiscoverAlongTheRoute() {
        val runtime = runtime()
        // The reply may come back by flood, which leaves no repeaters to
        // steer by; ping again until the route names one (Direct or Source).
        val route = (1..PING_TRIES).firstNotNullOfOrNull {
            val outcome = runBlocking { runtime.ping(TALLAC).await() }
            val route = runBlocking { runtime.peerRoute(TALLAC).await() }
            android.util.Log.i(TAG, "ping $it: $outcome; route $route")
            route.takeIf { outcome is PingOutcome.Reply && it.discoveryVantage != null }
        }
        assertNotNull("a route with a vantage", route)
        show(runtime)
        compose.runOnUiThread {
            shell.select(Destination.Peers)
            shell.openPeerFromList(TALLAC)
            shell.openRoute(UmshKey.PeerPage(TALLAC, Destination.Peers))
        }
        waitForTag(Tags.ROUTE_ASK_NEAR)
        compose.onNodeWithTag(Tags.ROUTE_ASK_NEAR).performClick()
        waitFor { shell.stacks.getValue(Destination.Peers).last() == UmshKey.Discover(TALLAC, Destination.Peers) }
        val where = context.resources.getQuantityString(R.plurals.discover_where_hops, 1, 1, "⁨Tallac Ridge⁩")
        waitFor { textOf(Tags.DISCOVER_WHERE).contains(where) || compose.onAllNodes(hasTestTag(Tags.DISCOVER_WHERE) and hasText(where, substring = true)).fetchSemanticsNodes().isNotEmpty() }
        val ask = text(R.string.discover_ask_near, "⁨Tallac Ridge⁩")
        assertTrue(compose.onAllNodes(hasTestTag(Tags.DISCOVER_ASK) and hasText(ask, substring = true)).fetchSemanticsNodes().isNotEmpty())
        // No ready-made line for an aimed ask: none until it is sent.
        assertTrue(!present(Tags.DISCOVER_ASK_FOOTER))
        compose.onNodeWithTag(Tags.DISCOVER_ASK).performClick()
        waitForTag(Tags.DISCOVER_ASK_FOOTER)
        assertTrue(textOf(Tags.DISCOVER_ASK_FOOTER).startsWith(text(R.string.discover_asked_wait, "").substringBefore(" Ask again")))
    }

    /**
     * §3.10: the Neighbors tile is a button by its label; a neighbor row is
     * one node, opening its page; a choice's options carry their selected
     * state; Ask's return is a polite live region, silent until then.
     */
    @Test
    fun whatTalkBackReads() {
        val runtime = runtime()
        show(runtime)
        openNeighbors(TALLAC)
        compose.onNodeWithTag(Tags.NEIGHBORS_REFRESH).performClick()
        waitFor(PAGE_BUDGET_MS) { textOf(Tags.NEIGHBORS_FOOTER) == text(R.string.neighbors_read_now) }
        val row = compose.onAllNodes(SemanticsMatcher("a neighbor row") { node ->
            node.config.getOrNull(SemanticsProperties.TestTag)?.startsWith("neighbor_row/") == true
        }).fetchSemanticsNodes().first()
        val texts = row.config.getOrNull(SemanticsProperties.Text)?.map { it.text }.orEmpty()
        android.util.Log.i(TAG, "neighbor row reads: $texts")
        assertTrue("name and reading in one node: $texts", texts.size >= 2)
        compose.runOnUiThread { shell.pop() }
        waitForTag(Tags.PEER_VERB_NEIGHBORS)
        val tile = compose.onNodeWithTag(Tags.PEER_VERB_NEIGHBORS).fetchSemanticsNode()
        assertEquals(Role.Button, tile.config.getOrNull(SemanticsProperties.Role))
        assertTrue(tile.config.getOrNull(SemanticsProperties.Text)?.any { it.text == text(R.string.verb_neighbors) } == true)

        compose.runOnUiThread { shell.pop() }
        openDiscoverFromList()
        assertNull(readyDescription())
        assertEquals(LiveRegionMode.Polite, compose.onNodeWithTag(Tags.DISCOVER_READY, useUnmergedTree = true).fetchSemanticsNode().config.getOrNull(SemanticsProperties.LiveRegion))
        compose.onNodeWithTag(Tags.DISCOVER_ROLE).performClick()
        waitForTag(Tags.discoverRoleOption("all"))
        val all = compose.onNodeWithTag(Tags.discoverRoleOption("all")).fetchSemanticsNode()
        assertEquals(true, all.config.getOrNull(SemanticsProperties.Selected))
        compose.onNodeWithTag(Tags.discoverRoleOption("1")).performClick()
        waitFor { compose.onAllNodes(hasTestTag(Tags.DISCOVER_ROLE) and hasText(text(R.string.role_repeater))).fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag(Tags.DISCOVER_ROLE).performClick()
        waitForTag(Tags.discoverRoleOption("1"))
        assertEquals(true, compose.onNodeWithTag(Tags.discoverRoleOption("1")).fetchSemanticsNode().config.getOrNull(SemanticsProperties.Selected))
        assertNotNull(compose.onNodeWithTag(Tags.discoverRoleOption("1")).fetchSemanticsNode().config.getOrNull(SemanticsActions.OnClick))
    }

    /** Pages of [count] made-up neighbors, Glen Alpine Relay first (so the first row is named). */
    private fun listing(count: Int, total: Long, cursor: Octets?): RepeaterListing = RepeaterListing(
        entries = (0 until count).map { index ->
            RepeaterNeighbor(
                hint = Octets(byteArrayOf(0x40, index.toByte())),
                hintText = "4%02X*".format(index),
                name = null,
                rssiDbm = -90 - index,
                snrQuarterDb = 20 - index * 4,
                lastHeardMinutes = index * 60,
                latitude = null,
                longitude = null,
                locationPrecision = null,
                regionCodes = emptyList(),
                reportedAtMs = System.currentTimeMillis(),
                peerAddress = if (index == 0) RELAY else null,
            )
        },
        total = total,
        nextCursor = cursor,
        asOfMs = System.currentTimeMillis(),
    )

    /** Answers each ask with the next of [pages], and keeps the cursors asked for. */
    private class PagedSource(private val pages: List<RepeaterListing>) : NeighborSource {
        val cursors: MutableList<Octets?> = Collections.synchronizedList(mutableListOf())

        override suspend fun storedNeighbors(address: String): RepeaterListing? = null

        override fun requestNeighbors(address: String, cursor: Octets?, route: List<Octets>): Deferred<RepeaterListing> {
            cursors += cursor
            return CompletableDeferred(pages[minOf(cursors.size, pages.size) - 1])
        }
    }

    private companion object {
        const val TAG = "RepeatersDiscoverTest"
        const val TIMEOUT = 30_000L
        const val QUIET_MS = 4_000L
        const val PAGE_BUDGET_MS = 40_000L
        const val NO_ANSWER_BUDGET_MS = 120_000L
        /** A node holds its answer to an ask for up to 30 s (`RESPONSE_MAX_DELAY_MS`), and some. */
        const val HEARD_BUDGET_MS = 40_000L
        const val PING_TRIES = 3

        /** The core's 40 s cooldown, and some. */
        const val COOLDOWN_BUDGET_MS = 50_000L

        fun address(seed: Int) = MobileIdentity.unlock(ByteArray(32) { seed.toByte() }).use { it.publicIdentity().canonicalAddress }

        val MAYA = address(0x11)
        val TALLAC = address(0x22)
        val RELAY = address(0x77)
    }
}
