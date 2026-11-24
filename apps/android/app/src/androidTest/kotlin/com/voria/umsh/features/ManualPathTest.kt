package com.voria.umsh.features

import android.Manifest
import android.os.Build
import android.view.KeyEvent
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasAnyDescendant
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeDown
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
import com.voria.umsh.app.TestUmshApplication
import com.voria.umsh.app.TestWindows
import com.voria.umsh.app.UmshKey
import com.voria.umsh.app.UmshShell
import com.voria.umsh.app.rememberShellState
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.inspectPublicIdentity
import com.voria.umsh.designsystem.LocalWindowOverride
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.peers.manualpath.HintForm
import com.voria.umsh.features.peers.manualpath.ManualPathLimits
import com.voria.umsh.features.peers.manualpath.ManualPathScreen
import com.voria.umsh.features.peers.manualpath.RepeaterHints
import com.voria.umsh.models.ManualPath
import com.voria.umsh.models.Octets
import com.voria.umsh.services.location.LocationGrant
import com.voria.umsh.services.location.PhoneFix
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * The manual path editor, Add hop, the hint entry (`manual-path.svg` 1–6)
 * and the learned-path prompt (board 7), over the staged air: Tallac Ridge
 * and Glen Alpine Relay forward and list each other as neighbors; Sam
 * Ihara is heard only through Glen. The prompt runs on P3a's recipe: a
 * held path through a hint nobody owns, a flood after it, and two fixes
 * about 330 m apart.
 */
class ManualPathTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private val limits = ManualPathLimits.core

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
        withTimeout(TIMEOUT) { runtime.appState.first { state -> state?.peers?.let { peers -> peers.any { it.address == SAM } && peers.any { it.address == TALLAC } } == true } }
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
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertExists()
    }

    private fun waitFor(timeout: Long = TIMEOUT, condition: () -> Boolean) = compose.waitUntil(timeout, condition)

    private fun present(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()

    private fun presentUnmerged(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String, timeout: Long = TIMEOUT) = waitFor(timeout) { present(tag) }

    private fun text(id: Int, vararg args: Any) = context.getString(id, *args)

    private fun plural(id: Int, count: Int) = context.resources.getQuantityString(id, count, count)

    private fun texts(tag: String, unmerged: Boolean = false): List<String> =
        compose.onNodeWithTag(tag, useUnmergedTree = unmerged).fetchSemanticsNode().config.getOrNull(SemanticsProperties.Text).orEmpty().map { it.text }

    private fun hasTextIn(tag: String, wanted: String, substring: Boolean = true, unmerged: Boolean = false) =
        compose.onAllNodes(hasTestTag(tag) and (hasText(wanted, substring = substring) or hasAnyDescendant(hasText(wanted, substring = substring))), useUnmergedTree = unmerged).fetchSemanticsNodes().isNotEmpty()

    private fun hopCount() = texts(Tags.MANUAL_PATH_HOPS, unmerged = true).single()

    private fun hex(bytes: ByteArray) = Octets(bytes).hex()

    /** The editor for [address], from its Route page, as Edit opens it. */
    private fun openEditor(address: String) {
        compose.runOnUiThread {
            shell.select(Destination.Peers)
            shell.openPeerFromList(address)
        }
        waitForTag(Tags.PEER_PAGE)
        compose.onNodeWithTag(Tags.PEER_GLANCE_ROUTE).performClick()
        waitForTag(Tags.ROUTE_EDIT)
        compose.onNodeWithTag(Tags.ROUTE_EDIT).performClick()
        waitForTag(Tags.MANUAL_PATH_PEER)
    }

    private fun scrollTo(tag: String): SemanticsNodeInteraction = compose.onNodeWithTag(tag).performScrollTo()

    private fun hopTags() = compose.onAllNodes(androidx.compose.ui.test.SemanticsMatcher("a hop") { node ->
        node.config.getOrNull(SemanticsProperties.TestTag)?.startsWith("manual_path_hop_") == true
    }).fetchSemanticsNodes().map { it.config[SemanticsProperties.TestTag].removePrefix("manual_path_hop_") }

    private fun stepperActions() = compose.onNodeWithTag(Tags.MANUAL_PATH_FLOOD).fetchSemanticsNode().config[SemanticsActions.CustomActions].map { it.label }

    private fun floodValue(): String? = compose.onNodeWithTag(Tags.MANUAL_PATH_FLOOD).fetchSemanticsNode().config.getOrNull(SemanticsProperties.StateDescription)

    private fun hold(path: ManualPath) = runBlocking { assertTrue(fresh.host.let { (it.state.value as HostState.Ready).runtime }.setManualPath(SAM, path, HOLD_MS).await()) }

    // --- Seeding --------------------------------------------------------

    /** A route that cannot be read seeds nothing, so Save has no blank draft to hold over a held path; the reason shows. */
    @Test
    fun anUnreadRouteSeedsNothing() {
        val runtime = runtime()
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides TestWindows.Phone,
                ) {
                    // Not an address: the core refuses to read its route.
                    ManualPathScreen("not an address", onClose = {})
                }
            }
        }
        waitForTag(Tags.MANUAL_PATH_UNREAD)
        compose.onNodeWithTag(Tags.MANUAL_PATH_SAVE).assertIsNotEnabled()
        assertFalse(present(Tags.MANUAL_PATH_ADD_HOP))
    }

    /**
     * Board 1: a held path seeds its hops (the relay named, the hint nobody
     * owns typed) and its own flood; the header counts the hops to the peer.
     */
    @Test
    fun aHeldPathSeedsItsHopsAndFlood() {
        val runtime = runtime()
        hold(ManualPath(listOf(Octets(RELAY_HINT), Octets(NOBODY)), floodHops = 3))
        show(runtime)
        openEditor(SAM)
        assertEquals(listOf(hex(RELAY_HINT), hex(NOBODY)), hopTags())
        assertEquals(plural(R.plurals.route_hops, 3), hopCount())
        waitFor { hasTextIn(Tags.manualPathHop(hex(RELAY_HINT)), "Glen Alpine Relay") }
        assertTrue(hasTextIn(Tags.manualPathHop(hex(NOBODY)), text(R.string.manual_path_entered_by_hand, "").trim().removeSuffix("·").trim()))
        assertEquals(plural(R.plurals.route_hops, 3), floodValue())
        assertTrue(hasTextIn(Tags.MANUAL_PATH_FLOOD, text(R.string.route_then_flood)))
    }

    /** Board 2: a peer with no route seeds a direct path; the stepper reads Flood, at the core's flood for a new path. */
    @Test
    fun noRouteSeedsADirectPathAtTheCoresFlood() {
        val runtime = runtime()
        show(runtime)
        openEditor(MAYA)
        assertTrue(hopTags().isEmpty())
        assertEquals(plural(R.plurals.route_hops, 1), hopCount())
        assertTrue(hasTextIn(Tags.MANUAL_PATH_FLOOD, text(R.string.manual_path_flood)))
        assertEquals(plural(R.plurals.route_hops, limits.newPathFloodHops), floodValue())
    }

    // --- Then flood and Hold --------------------------------------------

    /** The stepper runs Off to the core's most, its buttons off at each end. */
    @Test
    fun thenFloodKeepsTheCoresBounds() {
        val runtime = runtime()
        show(runtime)
        openEditor(MAYA)
        repeat(limits.newPathFloodHops) { compose.onNodeWithTag(Tags.MANUAL_PATH_FLOOD_FEWER, useUnmergedTree = true).performClick() }
        assertEquals(text(R.string.route_flood_off), floodValue())
        assertEquals(listOf(text(R.string.manual_path_flood_increase)), stepperActions())
        compose.onNodeWithTag(Tags.MANUAL_PATH_FLOOD).performSemanticsAction(SemanticsActions.SetProgress) { it(limits.maxFloodHops.toFloat()) }
        assertEquals(plural(R.plurals.route_hops, limits.maxFloodHops), floodValue())
        assertEquals(listOf(text(R.string.manual_path_flood_decrease)), stepperActions())
        compose.onNodeWithTag(Tags.MANUAL_PATH_FLOOD_FEWER, useUnmergedTree = true).performClick()
        assertEquals(plural(R.plurals.route_hops, limits.maxFloodHops - 1), floodValue())
    }

    /** Hold's choices are the core's, starting at its default; choosing one moves Until. */
    @Test
    fun holdChoicesComeFromTheCore() {
        val runtime = runtime()
        show(runtime)
        openEditor(MAYA)
        scrollTo(Tags.MANUAL_PATH_HOLD).performClick()
        limits.holdChoicesMs.forEach { choice -> waitForTag("${Tags.MANUAL_PATH_HOLD_OPTION}/$choice") }
        compose.onNodeWithTag("${Tags.MANUAL_PATH_HOLD_OPTION}/${limits.holdDefaultMs}").assertIsSelected()
        val untilBefore = texts(Tags.MANUAL_PATH_UNTIL)
        val longest = limits.holdChoicesMs.last()
        compose.onNodeWithTag("${Tags.MANUAL_PATH_HOLD_OPTION}/$longest").performClick()
        waitFor { texts(Tags.MANUAL_PATH_UNTIL) != untilBefore }
    }

    // --- Add hop ---------------------------------------------------------

    /**
     * Board 3: Known repeaters by filter, then the chosen hop's Neighbors on
     * Refresh (Tallac Ridge lists Glen Alpine Relay), the title counting up
     * as each is added, the trail following; Done returns with both, the
     * neighbor with how Tallac heard it.
     */
    @Test
    fun addHopFromKnownRepeatersThenNeighbors() {
        val runtime = runtime()
        show(runtime)
        openEditor(MAYA)
        scrollTo(Tags.MANUAL_PATH_ADD_HOP).performClick()
        waitForTag(Tags.ADD_HOP_PAGE)
        waitFor { hasTextIn(Tags.TOP_APP_BAR, text(R.string.add_hop_title, "1")) }
        compose.onNodeWithTag(Tags.ADD_HOP_TAB_KNOWN).performClick()
        waitForTag(Tags.addHopKnown(TALLAC))
        compose.onNodeWithTag(Tags.ADD_HOP_FILTER).performTextInput("Tallac")
        waitFor { !present(Tags.addHopKnown(RELAY)) }
        compose.onNodeWithTag(Tags.addHopKnown(TALLAC)).performClick()

        waitFor { hasTextIn(Tags.TOP_APP_BAR, text(R.string.add_hop_title, "2")) }
        assertEquals("the filter clears", "", compose.onNodeWithTag(Tags.ADD_HOP_FILTER).fetchSemanticsNode().config.getOrNull(SemanticsProperties.EditableText)?.text)
        assertTrue(hasTextIn(Tags.ADD_HOP_CRUMB, "Tallac Ridge"))
        compose.onNodeWithTag(Tags.ADD_HOP_TAB_NEIGHBORS).assertIsSelected()
        // Opening sends nothing: Not read until Refresh.
        assertTrue(hasTextIn(Tags.ADD_HOP_EMPTY, text(R.string.neighbors_not_read)))
        compose.onNodeWithTag(Tags.ADD_HOP_REFRESH).performClick()
        val glen = Tags.addHopNeighbor(hex(RELAY_NODE_HINT))
        waitFor(NEIGHBORS_BUDGET_MS) { present(glen) }
        assertTrue(hasTextIn(Tags.ADD_HOP_FOOTER, text(R.string.neighbors_read_now)))
        compose.onNodeWithTag(glen).performClick()
        waitFor { hasTextIn(Tags.TOP_APP_BAR, text(R.string.add_hop_title, "3")) }
        // Glen lists Tallac, already on the path.
        compose.onNodeWithTag(Tags.ADD_HOP_REFRESH).performClick()
        val tallac = Tags.addHopNeighbor(hex(TALLAC_NODE_HINT))
        waitFor(NEIGHBORS_BUDGET_MS) { present(tallac) }
        assertTrue(hasTextIn(tallac, text(R.string.add_hop_in_path)))
        assertTrue(hasTextIn(Tags.ADD_HOP_FOOTER, text(R.string.add_hop_asked_through, "").substringBefore(' ')))

        compose.onNodeWithTag(Tags.ADD_HOP_DONE).performClick()
        waitForTag(Tags.MANUAL_PATH_PEER)
        assertEquals(listOf(hex(TALLAC_HINT), hex(RELAY_HINT)), hopTags())
        assertTrue("Glen as Tallac heard it", hasTextIn(Tags.manualPathHop(hex(RELAY_HINT)), "dBm"))
    }

    /** A hop known only by its hint is not an address to ask: Neighbors is out of reach and Known repeaters shows. */
    @Test
    fun aHintOnlyHopForcesKnownRepeaters() {
        val runtime = runtime()
        hold(ManualPath(listOf(Octets(NOBODY)), floodHops = 1))
        show(runtime)
        openEditor(SAM)
        scrollTo(Tags.MANUAL_PATH_ADD_HOP).performClick()
        waitForTag(Tags.ADD_HOP_PAGE)
        compose.onNodeWithTag(Tags.ADD_HOP_TAB_NEIGHBORS).assertIsNotEnabled()
        compose.onNodeWithTag(Tags.ADD_HOP_TAB_KNOWN).assertIsSelected().assertIsEnabled()
        waitForTag(Tags.addHopKnown(TALLAC))
        assertFalse(present(Tags.ADD_HOP_REFRESH))
    }

    /** The radio itself is never a known repeater, nor is the peer the path leads to. */
    @Test
    fun knownRepeatersLeaveOutTheRadioAndTheDestination() {
        val runtime = runtime()
        show(runtime)
        openEditor(TALLAC)
        scrollTo(Tags.MANUAL_PATH_ADD_HOP).performClick()
        waitForTag(Tags.ADD_HOP_PAGE)
        compose.onNodeWithTag(Tags.ADD_HOP_TAB_KNOWN).performClick()
        waitForTag(Tags.addHopKnown(RELAY))
        assertFalse(present(Tags.addHopKnown(TALLAC)))
        val radio = runtime.appState.value!!.peers.first { it.isCompanionRadio }.address
        assertFalse(present(Tags.addHopKnown(radio)))
    }

    // --- Hint entry ------------------------------------------------------

    /**
     * Boards 4–5: each problem's line; one hint fits (the Hop section, the
     * known node); one already on the path says so and Add stays off; two
     * hints fit and one is picked.
     */
    @Test
    fun hintEntryProblemsOneHintAndTwo() {
        val runtime = runtime()
        hold(ManualPath(listOf(Octets(RELAY_HINT)), floodHops = 1))
        show(runtime)
        openEditor(SAM)
        scrollTo(Tags.MANUAL_PATH_ADD_HOP).performClick()
        waitForTag(Tags.ADD_HOP_PAGE)
        compose.onNodeWithTag(Tags.ADD_HOP_ENTER_HINT).performScrollTo().performClick()
        waitForTag(Tags.HINT_ENTRY_PAGE)
        compose.onNodeWithTag(Tags.HINT_ENTRY_BASE58).assertIsSelected()
        fun footer() = texts(Tags.HINT_ENTRY_FOOTER, unmerged = true).single()
        assertEquals(text(R.string.hint_entry_base58_help), footer())
        val field = compose.onNodeWithTag(Tags.HINT_ENTRY_FIELD)
        field.performTextReplacement("0OIl")
        waitFor { footer() == text(R.string.hint_entry_base58_invalid) }
        field.performTextReplacement("z".repeat(50))
        waitFor { footer() == text(R.string.hint_entry_base58_too_long) }
        field.performTextReplacement(OUT_OF_RANGE)
        waitFor { footer() == text(R.string.hint_entry_base58_out_of_range) }

        compose.onNodeWithTag(Tags.HINT_ENTRY_HEX).performClick()
        field.performTextReplacement("5EBG")
        waitFor { footer() == text(R.string.hint_entry_hex_invalid) }
        field.performTextReplacement("5EB")
        waitFor { footer() == text(R.string.hint_entry_hex_help) }
        compose.onNodeWithTag(Tags.HINT_ENTRY_ADD).assertIsNotEnabled()

        // The relay's hint: on the path already, and named.
        field.performTextReplacement(hex(RELAY_HINT))
        waitForTag(Tags.HINT_ENTRY_IN_PATH)
        waitFor { hasTextIn(Tags.HINT_ENTRY_KNOWN, "Glen Alpine Relay") }
        compose.onNodeWithTag(Tags.HINT_ENTRY_ADD).assertIsNotEnabled()

        // Tallac's: one fits, Add goes.
        field.performTextReplacement(hex(TALLAC_HINT))
        waitFor { !present(Tags.HINT_ENTRY_IN_PATH) && hasTextIn(Tags.HINT_ENTRY_KNOWN, "Tallac Ridge") }
        compose.onNodeWithTag(Tags.HINT_ENTRY_ADD).assertIsEnabled()

        // Two fit: none until one is picked.
        compose.onNodeWithTag(Tags.HINT_ENTRY_BASE58).performClick()
        val (prefix, candidates) = twoHintPrefix()
        field.performTextReplacement(prefix)
        waitForTag(Tags.HINT_ENTRY_TWO_FIT)
        candidates.forEach { waitForTag(Tags.hintCandidate(it)) }
        compose.onNodeWithTag(Tags.HINT_ENTRY_ADD).assertIsNotEnabled()
        compose.onNodeWithTag(Tags.hintCandidate(candidates[1])).performClick()
        compose.onNodeWithTag(Tags.hintCandidate(candidates[1])).assertIsSelected()
        compose.onNodeWithTag(Tags.HINT_ENTRY_ADD).assertIsEnabled().performClick()

        // Back on Add hop, the typed hop added; Done shows it typed on the path.
        waitForTag(Tags.ADD_HOP_PAGE)
        compose.onNodeWithTag(Tags.ADD_HOP_DONE).performClick()
        waitForTag(Tags.MANUAL_PATH_PEER)
        assertEquals(listOf(hex(RELAY_HINT), candidates[1]), hopTags())
    }

    /** The full path's line, once the last hop the core allows is added. */
    @Test
    fun aFullPathSaysSo() {
        val runtime = runtime()
        val almost = (1 until limits.maxRouteHints).map { Octets(byteArrayOf(0x00, (0x10 + it).toByte())) }
        hold(ManualPath(almost, floodHops = 0))
        show(runtime)
        openEditor(SAM)
        scrollTo(Tags.MANUAL_PATH_ADD_HOP).performClick()
        waitForTag(Tags.ADD_HOP_PAGE)
        compose.onNodeWithTag(Tags.ADD_HOP_ENTER_HINT).performScrollTo().performClick()
        waitForTag(Tags.HINT_ENTRY_PAGE)
        compose.onNodeWithTag(Tags.HINT_ENTRY_HEX).performClick()
        compose.onNodeWithTag(Tags.HINT_ENTRY_FIELD).performTextReplacement("00FF")
        compose.onNodeWithTag(Tags.HINT_ENTRY_ADD).assertIsEnabled().performClick()
        waitForTag(Tags.ADD_HOP_FULL)
        assertTrue(hasTextIn(Tags.ADD_HOP_FULL, plural(R.plurals.manual_path_full, limits.maxRouteHints), substring = false))
        assertFalse(present(Tags.ADD_HOP_ENTER_HINT))
        compose.onNodeWithTag(Tags.ADD_HOP_DONE).performClick()
        waitForTag(Tags.MANUAL_PATH_PEER)
        assertFalse("no Add hop on a full path", present(Tags.MANUAL_PATH_ADD_HOP))
    }

    // --- Reorder and remove ---------------------------------------------

    /** TalkBack's Move up and Move down reorder; the remove button reads its hop and takes it off. */
    @Test
    fun reorderByActionsAndRemove() {
        val runtime = runtime()
        hold(ManualPath(listOf(Octets(RELAY_HINT), Octets(TALLAC_HINT), Octets(NOBODY)), floodHops = 1))
        show(runtime)
        openEditor(SAM)
        val first = compose.onNodeWithTag(Tags.manualPathHop(hex(RELAY_HINT))).fetchSemanticsNode()
        val actions = first.config[SemanticsActions.CustomActions].map { it.label }
        assertEquals(listOf(text(R.string.manual_path_move_down)), actions)
        val middle = compose.onNodeWithTag(Tags.manualPathHop(hex(TALLAC_HINT))).fetchSemanticsNode()
        assertEquals(listOf(text(R.string.manual_path_move_up), text(R.string.manual_path_move_down)), middle.config[SemanticsActions.CustomActions].map { it.label })
        compose.runOnUiThread { middle.config[SemanticsActions.CustomActions].first { it.label == text(R.string.manual_path_move_up) }.action() }
        waitFor { hopTags() == listOf(hex(TALLAC_HINT), hex(RELAY_HINT), hex(NOBODY)) }
        val last = compose.onNodeWithTag(Tags.manualPathHop(hex(NOBODY))).fetchSemanticsNode()
        assertEquals(listOf(text(R.string.manual_path_move_up)), last.config[SemanticsActions.CustomActions].map { it.label })

        val remove = compose.onNodeWithTag(Tags.manualPathRemove(hex(TALLAC_HINT)))
        assertEquals(text(R.string.manual_path_remove_hop, "Tallac Ridge"), remove.fetchSemanticsNode().config[SemanticsProperties.ContentDescription].single())
        remove.performClick()
        waitFor { hopTags() == listOf(hex(RELAY_HINT), hex(NOBODY)) }
    }

    /** A drag on a hop's handle moves it past the hop below. */
    @Test
    fun dragByTheHandle() {
        val runtime = runtime()
        hold(ManualPath(listOf(Octets(RELAY_HINT), Octets(TALLAC_HINT)), floodHops = 1))
        show(runtime)
        openEditor(SAM)
        compose.onNodeWithTag(Tags.manualPathHandle(hex(RELAY_HINT)), useUnmergedTree = true).performTouchInput {
            swipeDown(startY = centerY, endY = centerY + height * 2f, durationMillis = 600)
        }
        waitFor { hopTags() == listOf(hex(TALLAC_HINT), hex(RELAY_HINT)) }
    }

    // --- Ping along path, discard, save ---------------------------------

    /**
     * Ping along path on the staged air: Sam answers through the relay along
     * a draft that differs from the held path (flood 1, held 0), and the
     * held path stays as it was; changing the path clears the result.
     */
    @Test
    fun pingAlongPathThenAChangeClearsIt() {
        val runtime = runtime()
        hold(ManualPath(listOf(Octets(RELAY_HINT)), floodHops = 0))
        show(runtime)
        openEditor(SAM)
        scrollTo(Tags.MANUAL_PATH_FLOOD)
        compose.onNodeWithTag(Tags.MANUAL_PATH_FLOOD_MORE, useUnmergedTree = true).performClick()
        scrollTo(Tags.MANUAL_PATH_PING).performClick()
        waitFor(PING_BUDGET_MS) { hasTextIn(Tags.MANUAL_PATH_PING_RESULT, text(R.string.manual_path_replied, "").trim()) }
        assertTrue(hasTextIn(Tags.MANUAL_PATH_PING_RESULT, "dBm"))
        val held = runBlocking { runtime.peerRoute(SAM).await() }
        assertEquals("the ping installed nothing: the hold keeps its flood", 0, held.holdFloodHops)
        assertEquals("the ping installed nothing: the hold keeps its hops", listOf(hex(RELAY_HINT)), held.hints.map { it.octets.hex() })
        scrollTo(Tags.MANUAL_PATH_FLOOD)
        compose.onNodeWithTag(Tags.MANUAL_PATH_FLOOD_MORE, useUnmergedTree = true).performClick()
        waitFor { !present(Tags.MANUAL_PATH_PING_RESULT) }
    }

    /** Board 6: Close with changes asks; Keep editing stays; Discard leaves the route as it was. Without changes it closes at once. */
    @Test
    fun discardAsksOnlyWithChanges() {
        val runtime = runtime()
        show(runtime)
        openEditor(MAYA)
        compose.onNodeWithTag(Tags.DIALOG_CLOSE).performClick()
        waitFor { !present(Tags.MANUAL_PATH_PAGE) }
        assertFalse(present(Tags.CONFIRM_DIALOG))

        compose.onNodeWithTag(Tags.ROUTE_EDIT).performClick()
        waitForTag(Tags.MANUAL_PATH_PEER)
        compose.onNodeWithTag(Tags.MANUAL_PATH_FLOOD_MORE, useUnmergedTree = true).performClick()
        compose.onNodeWithTag(Tags.DIALOG_CLOSE).performClick()
        waitForTag(Tags.CONFIRM_DIALOG)
        assertTrue(compose.onAllNodes(hasText(text(R.string.manual_path_discard_body))).fetchSemanticsNodes().isNotEmpty())
        compose.onNodeWithTag(Tags.CONFIRM_CANCEL).performClick()
        waitFor { !present(Tags.CONFIRM_DIALOG) }
        assertTrue(present(Tags.MANUAL_PATH_PAGE))

        // Back asks too.
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
        waitForTag(Tags.CONFIRM_DIALOG)
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        waitFor { !present(Tags.MANUAL_PATH_PAGE) }
        assertTrue(present(Tags.ROUTE_PAGE))
        assertFalse("nothing held", runBlocking { runtime.peerRoute(MAYA).await() }.isHeld)
    }

    /** Save holds the path; the Route page beneath says Manual · n hops and when the hold ends. */
    @Test
    fun saveHoldsThePath() {
        val runtime = runtime()
        show(runtime)
        openEditor(SAM)
        scrollTo(Tags.MANUAL_PATH_ADD_HOP).performClick()
        waitForTag(Tags.ADD_HOP_PAGE)
        compose.onNodeWithTag(Tags.ADD_HOP_TAB_KNOWN).performClick()
        waitForTag(Tags.addHopKnown(RELAY))
        compose.onNodeWithTag(Tags.addHopKnown(RELAY)).performClick()
        waitFor { hasTextIn(Tags.TOP_APP_BAR, text(R.string.add_hop_title, "2")) }
        compose.onNodeWithTag(Tags.ADD_HOP_DONE).performClick()
        waitForTag(Tags.MANUAL_PATH_PEER)
        compose.onNodeWithTag(Tags.MANUAL_PATH_SAVE).performClick()
        waitFor { !present(Tags.MANUAL_PATH_PAGE) }
        val manual = plural(R.plurals.route_kind_manual_hops, 2)
        runCatching { waitFor { hasTextIn(Tags.ROUTE_NEXT_SEND, manual) } }.onFailure {
            throw AssertionError("Next send reads ${texts(Tags.ROUTE_NEXT_SEND)}, wanted $manual; route ${runBlocking { runtime.peerRoute(SAM).await() }}", it)
        }
        compose.onNodeWithTag(Tags.ROUTE_HELD_UNTIL).assertExists()
        val route = runBlocking { runtime.peerRoute(SAM).await() }
        assertTrue(route.isHeld)
        assertEquals(listOf(Octets(RELAY_HINT)), route.hints.map { it.octets })
        assertEquals(limits.newPathFloodHops, route.holdFloodHops)
    }

    // --- Learned-path prompt ---------------------------------------------

    /** Hold P3a's recipe path to Sam with two fixes 330 m apart, open the thread, and send one message. */
    private fun recipe(runtime: AppRuntime) {
        val location = (context.applicationContext as TestUmshApplication).testLocation
        location.grant.value = LocationGrant.Precise
        location.readings.tryEmit(PhoneFix(38.9, -120.1, accuracyMeters = 10.0, approximate = false))
        hold(ManualPath(listOf(Octets(NOBODY)), floodHops = 2))
        location.readings.tryEmit(PhoneFix(38.903, -120.1, accuracyMeters = 10.0, approximate = false))
        val conversation = runBlocking { runtime.startConversation(SAM).await() }
        show(runtime)
        compose.runOnUiThread { shell.openConversation(conversation) }
        waitForTag(Tags.THREAD)
        runBlocking { runtime.send(conversation, "Which way?", null).await() }
    }

    /** Board 7, then Use learned path: the hold goes and the relay's route is the one sent on. */
    @Test
    fun theLearnedPathIsOfferedAndUsed() {
        val runtime = runtime()
        recipe(runtime)
        waitForTag(Tags.LEARNED_PATH_SHEET, LEARNED_BUDGET_MS)
        assertTrue(hasTextIn(Tags.LEARNED_PATH_MANUAL, plural(R.plurals.learned_path_no_ack, 1)))
        assertTrue(hasTextIn(Tags.LEARNED_PATH_LEARNED, text(R.string.learned_path_carried)))
        waitFor { hasTextIn(Tags.LEARNED_PATH_LEARNED, "Glen Alpine Relay") }
        compose.onNodeWithTag(Tags.LEARNED_PATH_USE).performClick()
        waitFor { !present(Tags.LEARNED_PATH_SHEET) }
        val route = runBlocking { runtime.peerRoute(SAM).await() }
        assertFalse(route.isHeld)
        assertEquals(listOf(Octets(RELAY_HINT)), route.hints.map { it.octets })
    }

    /** Dismissing the prompt keeps the manual path and settles the question for it. */
    @Test
    fun dismissingTheOfferKeepsTheManualPath() {
        val runtime = runtime()
        recipe(runtime)
        waitForTag(Tags.LEARNED_PATH_SHEET, LEARNED_BUDGET_MS)
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
        waitFor { !present(Tags.LEARNED_PATH_SHEET) }
        waitFor { runBlocking { runtime.learnedPathOffer(SAM).await() } == null }
        assertTrue(runBlocking { runtime.peerRoute(SAM).await() }.isHeld)
        assertNull(runBlocking { runtime.learnedPathOffer(SAM).await() })
    }

    // --- TalkBack (§3.10) ------------------------------------------------

    /**
     * The stepper is one node with its value, a range and Increase /
     * Decrease; the hop's remove button names it; the Base58/Hex choice and
     * Add hop's tabs carry their selected state; the drag handle is not read.
     */
    @Test
    fun whatTalkBackReads() {
        val runtime = runtime()
        hold(ManualPath(listOf(Octets(RELAY_HINT)), floodHops = 1))
        show(runtime)
        openEditor(SAM)
        val stepper = compose.onNodeWithTag(Tags.MANUAL_PATH_FLOOD).fetchSemanticsNode().config
        assertEquals(plural(R.plurals.route_hops, 1), stepper[SemanticsProperties.StateDescription])
        assertEquals(ProgressBarRangeInfo(1f, 0f..limits.maxFloodHops.toFloat(), limits.maxFloodHops - 1), stepper[SemanticsProperties.ProgressBarRangeInfo])
        assertEquals(
            listOf(text(R.string.manual_path_flood_increase), text(R.string.manual_path_flood_decrease)),
            stepper[SemanticsActions.CustomActions].map { it.label },
        )
        val handle = compose.onNodeWithTag(Tags.manualPathHandle(hex(RELAY_HINT)), useUnmergedTree = true).fetchSemanticsNode()
        assertTrue("the handle is not read", handle.config.getOrNull(SemanticsProperties.ContentDescription) == null && handle.config.getOrNull(SemanticsActions.OnClick) == null)
        assertTrue(handle.size.width >= compose.density.dpPx48())
        val addHop = compose.onNodeWithTag(Tags.MANUAL_PATH_ADD_HOP).fetchSemanticsNode().config
        assertEquals(Role.Button, addHop.getOrNull(SemanticsProperties.Role))

        scrollTo(Tags.MANUAL_PATH_ADD_HOP).performClick()
        waitForTag(Tags.ADD_HOP_PAGE)
        compose.onNodeWithTag(Tags.ADD_HOP_TAB_NEIGHBORS).assertIsSelected()
        compose.onNodeWithTag(Tags.ADD_HOP_ENTER_HINT).performScrollTo().performClick()
        waitForTag(Tags.HINT_ENTRY_PAGE)
        compose.onNodeWithTag(Tags.HINT_ENTRY_BASE58).assertIsSelected()
        compose.onNodeWithTag(Tags.HINT_ENTRY_HEX).performClick().assertIsSelected()
    }

    private fun androidx.compose.ui.unit.Density.dpPx48(): Int = (48 * density).toInt() - 1

    private companion object {
        const val TIMEOUT = 30_000L

        /** A Peer Repeaters answer on the staged air comes within a second; the hold is the radio's. */
        const val NEIGHBORS_BUDGET_MS = 30_000L

        const val PING_BUDGET_MS = 30_000L

        /** P3a measured about 17 s from the send to the flood's ack and the candidate; with room. */
        const val LEARNED_BUDGET_MS = 90_000L

        const val HOLD_MS = 3_600_000L

        /** A Base58 prefix no address begins with: past the largest 32-byte value's first character. */
        const val OUT_OF_RANGE = "zzzz"

        fun address(seed: Int) = MobileIdentity.unlock(ByteArray(32) { seed.toByte() }).use { it.publicIdentity().canonicalAddress }

        val SAM = address(0x66)
        val RELAY = address(0x77)
        val TALLAC = address(0x22)
        val MAYA = address(0x11)
        val RELAY_NODE_HINT: ByteArray = inspectPublicIdentity(RELAY).hint.bytes
        val TALLAC_NODE_HINT: ByteArray = inspectPublicIdentity(TALLAC).hint.bytes
        val RELAY_HINT: ByteArray = RELAY_NODE_HINT.copyOf(2)
        val TALLAC_HINT: ByteArray = TALLAC_NODE_HINT.copyOf(2)

        /** A repeater hint no staged node owns. */
        val NOBODY = byteArrayOf(0x00, 0x01)
    }
}

/** A four-character Base58 prefix that two repeater hints fit, found through the core, and their hex. */
internal fun twoHintPrefix(): Pair<String, List<String>> {
    val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    for (a in "123456789ABCDEFGH") for (b in alphabet) for (c in alphabet) for (d in alphabet) {
        val prefix = "$a$b$c$d"
        val input = RepeaterHints.parse(prefix, HintForm.Base58Prefix)
        if (input.candidates.size == 2) return prefix to input.candidates.map { it.octets.hex() }
    }
    error("no prefix fits two hints")
}
