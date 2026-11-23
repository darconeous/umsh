package com.voria.umsh.app

import android.view.KeyEvent
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.requiredHeight
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.assertIsNotDisplayed
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.hasTestTag
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.designsystem.UmshTheme
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import androidx.compose.material3.adaptive.WindowAdaptiveInfo
import com.voria.umsh.designsystem.LocalWindowOverride

/** The shell (`navigation.svg`): destinations, back stacks, Back, the bar, the badge and the banner slot. */
class ShellTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState

    private fun runtime(staging: Boolean = false): AppRuntime = runBlocking {
        fresh.host.ensureRuntime(staging)
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        withTimeout(TIMEOUT) { ready.runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        withTimeout(TIMEOUT) { ready.runtime.appState.first { it != null } }
        ready.runtime
    }

    /** [height], when given, holds the shell to it whatever the display; the layout class still follows the window. */
    private fun showShell(
        runtime: AppRuntime,
        restoration: StateRestorationTester? = null,
        height: Dp? = null,
        window: WindowAdaptiveInfo = TestWindows.Phone,
    ) {
        val content: @Composable () -> Unit = {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides window,
                ) {
                    val state = rememberShellState()
                    shell = state
                    Box(if (height != null) Modifier.requiredHeight(height) else Modifier) {
                        UmshShell(state)
                    }
                }
            }
        }
        if (restoration != null) restoration.setContent(content) else compose.setContent(content)
    }

    /** The system Back key, as a person presses it. */
    private fun back() {
        compose.waitForIdle()
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
        compose.waitForIdle()
    }

    @Test
    fun startsAtConversationsWithFourDestinations() {
        showShell(runtime())
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed()
        compose.onNodeWithTag(Tags.NAV_CONVERSATIONS).assertIsSelected()
        for (tag in listOf(Tags.NAV_PEERS, Tags.NAV_MAP, Tags.NAV_SETTINGS)) {
            compose.onNodeWithTag(tag).assertIsDisplayed()
        }
        // On a phone the radio control ends the top app bar; there is no rail.
        compose.onNodeWithTag(Tags.RADIO_CONTROL).assertIsDisplayed()
        compose.onNodeWithTag(Tags.RAIL_HEADER).assertDoesNotExist()
    }

    @Test
    fun switchingDestinationsKeepsEachStack() {
        showShell(runtime())
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_YOUR_IDENTITY).performClick()
        compose.onNodeWithTag(Tags.YOUR_IDENTITY).assertIsDisplayed()
        // A pushed page keeps the bar.
        compose.onNodeWithTag(Tags.NAV_PEERS).assertIsDisplayed().performClick()
        compose.onNodeWithTag(Tags.PEERS_ROOT).assertIsDisplayed()
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.YOUR_IDENTITY).assertIsDisplayed()
        assertEquals(listOf(UmshKey.SettingsRoot, UmshKey.YourIdentity), shell.stacks.getValue(Destination.Settings).toList())
    }

    @Test
    fun reselectingPopsToTheRoot() {
        showShell(runtime())
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_YOUR_IDENTITY).performClick()
        compose.onNodeWithTag(Tags.YOUR_IDENTITY).assertIsDisplayed()
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_ROOT).assertIsDisplayed()
        compose.onNodeWithTag(Tags.YOUR_IDENTITY).assertDoesNotExist()
        // A reselect that pops does not also scroll; only one at the root does.
        assertEquals(0, shell.reselectCount(Destination.Settings))
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.runOnIdle { assertEquals(1, shell.reselectCount(Destination.Settings)) }
    }

    /**
     * Reselect scrolls the root up once: the root coming back from a pushed
     * page keeps where it was scrolled to, and a reselect there scrolls up.
     */
    @Test
    fun reselectScrollsOnceAndReturnsKeepTheScroll() {
        // Short enough that the staged Settings list overflows on any display.
        showShell(runtime(staging = true), height = SHORT_SHELL)
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        val top = identityRowTop()
        // A reselect at the root, before scrolling: the count is now 1.
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_LIST).performScrollToNode(hasTestTag(Tags.DEV_TX_FAILING))
        val scrolledTo = rowTop(Tags.DEV_TX_FAILING)
        assertTrue("the list scrolled", identityRowTop()?.let { it < top!! } ?: true)
        compose.runOnUiThread { shell.openDetail(UmshKey.YourIdentity) }
        compose.onNodeWithTag(Tags.YOUR_IDENTITY).assertIsDisplayed()
        back()
        compose.onNodeWithTag(Tags.SETTINGS_ROOT).assertIsDisplayed()
        assertEquals(scrolledTo, rowTop(Tags.DEV_TX_FAILING))
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.waitUntil(TIMEOUT) { identityRowTop() == top }
    }

    private fun rowTop(tag: String): Float? = compose.waitForIdle().let {
        compose.onAllNodesWithTag(tag).fetchSemanticsNodes().singleOrNull()?.boundsInRoot?.top
    }

    private fun identityRowTop(): Float? = rowTop(Tags.SETTINGS_YOUR_IDENTITY)

    @Test
    fun backPopsThenReturnsToConversations() {
        showShell(runtime())
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_YOUR_IDENTITY).performClick()
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_ROOT).assertIsDisplayed()
        compose.onNodeWithTag(Tags.SETTINGS_YOUR_IDENTITY).performClick()
        back()
        compose.onNodeWithTag(Tags.SETTINGS_ROOT).assertIsDisplayed()
        // At the root of Settings (or Peers, or Map), Back selects Conversations.
        back()
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed()
        compose.onNodeWithTag(Tags.NAV_CONVERSATIONS).assertIsSelected()
        compose.onNodeWithTag(Tags.NAV_MAP).performClick()
        compose.onNodeWithTag(Tags.MAP_ROOT).assertIsDisplayed()
        back()
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed()
    }

    @Test
    fun aThreadHidesTheBar() {
        val runtime = runtime()
        showShell(runtime)
        // A stored conversation's: the shell closes a thread with none.
        val public = runtime.appState.value!!.conversations.first().address
        compose.runOnUiThread { shell.openDetail(UmshKey.Thread(public)) }
        compose.onNodeWithTag(Tags.THREAD).assertIsDisplayed()
        compose.waitUntil(TIMEOUT) {
            runCatching { compose.onNodeWithTag(Tags.NAV_CONVERSATIONS).assertIsNotDisplayed() }.isSuccess
        }
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).performClick()
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed()
        compose.waitUntil(TIMEOUT) {
            runCatching { compose.onNodeWithTag(Tags.NAV_CONVERSATIONS).assertIsDisplayed() }.isSuccess
        }
    }

    /**
     * `list-detail.svg` board 1 and `navigation.svg`'s rail: on a tablet a
     * thread opens beside the list, and the navigation stays.
     */
    @Test
    fun aTabletShowsTheRailAndTheThreadBesideTheList() {
        val runtime = runtime()
        showShell(runtime, window = TestWindows.Tablet)
        // The rail, not the bar (it composes its header more than once).
        assertTrue(compose.onAllNodesWithTag(Tags.RAIL_HEADER).fetchSemanticsNodes().isNotEmpty())
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed()
        val public = runtime.appState.value!!.conversations.first().address
        compose.runOnUiThread { shell.openDetail(UmshKey.Thread(public)) }
        compose.onNodeWithTag(Tags.THREAD).assertIsDisplayed()
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed()
        compose.onNodeWithTag(Tags.NAV_CONVERSATIONS).assertIsDisplayed()
        // Beside its list a thread has no Back: the list is right there.
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).assertDoesNotExist()
    }

    @Test
    fun backStacksSurviveRecreation() {
        val restoration = StateRestorationTester(compose)
        val runtime = runtime()
        showShell(runtime, restoration)
        val public = runtime.appState.value!!.conversations.first().address
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_YOUR_IDENTITY).performClick()
        compose.runOnUiThread { shell.select(Destination.Conversations) }
        compose.runOnUiThread { shell.push(UmshKey.Thread(public)) }
        compose.waitForIdle()
        restoration.emulateSavedInstanceStateRestore()
        assertEquals(Destination.Conversations, shell.selected)
        assertEquals(listOf(UmshKey.ConversationsRoot, UmshKey.Thread(public)), shell.currentStack.toList())
        assertEquals(listOf(UmshKey.SettingsRoot, UmshKey.YourIdentity), shell.stacks.getValue(Destination.Settings).toList())
        compose.onNodeWithTag(Tags.THREAD).assertIsDisplayed()
    }

    @Test
    fun noRadioShowsItsBannerUnderTheTopBar() {
        showShell(runtime())
        compose.onNodeWithTag(Tags.RADIO_BANNER).assertIsDisplayed()
        val bar = compose.onNodeWithTag(Tags.TOP_APP_BAR).fetchSemanticsNode().boundsInRoot
        val banner = compose.onNodeWithTag(Tags.RADIO_BANNER).fetchSemanticsNode().boundsInRoot
        assertTrue("$banner under $bar", banner.top >= bar.bottom)
        val context = compose.activity
        val description = compose.onNodeWithTag(Tags.RADIO_CONTROL).fetchSemanticsNode()
            .config[SemanticsProperties.ContentDescription].single()
        assertEquals(context.getString(R.string.radio_tb_not_set_up), description)
    }

    @Test
    fun theStagedRadioIsConnectedAndTheBadgeCountsConversations() {
        val runtime = runtime(staging = true)
        withTimeoutBlocking { runtime.radio.first { it?.batteryPercent != null } }
        showShell(runtime)
        compose.onNodeWithTag(Tags.RADIO_BANNER).assertDoesNotExist()
        val radio = runtime.radio.value!!
        val description = compose.onNodeWithTag(Tags.RADIO_CONTROL).fetchSemanticsNode()
            .config[SemanticsProperties.ContentDescription].single()
        val context = compose.activity
        val percent = radio.batteryPercent!!
        assertTrue(description, description.startsWith(context.getString(R.string.radio_tb_name, radio.name)))
        assertTrue(description, description.contains(context.getString(R.string.radio_tb_connected)))
        assertTrue(
            description,
            description.contains(context.resources.getQuantityString(R.plurals.radio_tb_battery, percent, percent)),
        )
        // With a radio, the control opens Radio Detail.
        compose.onNodeWithTag(Tags.RADIO_CONTROL).assert(hasClickAction())

        val unread = runtime.appState.value!!.conversations.count { it.unreadCount > 0 }
        assertTrue("the seed has unread conversations", unread > 0)
        // What TalkBack reads on the Conversations item: its label, and the count beside it.
        val item = compose.onNodeWithTag(Tags.NAV_CONVERSATIONS).fetchSemanticsNode().config
        val count = context.resources.getQuantityString(R.plurals.nav_unread_conversations, unread, unread)
        assertTrue(item.toString(), count in item.getOrElse(SemanticsProperties.ContentDescription) { emptyList() })
        assertTrue(
            item.toString(),
            context.getString(R.string.nav_conversations) in item.getOrElse(SemanticsProperties.Text) { emptyList() }.map { it.text },
        )
    }

    @Test
    fun theStagedLinkGoingDownShowsDisconnected() {
        val runtime = runtime(staging = true)
        withTimeoutBlocking { runtime.radio.first { it?.batteryPercent != null } }
        showShell(runtime)
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_LIST).performScrollToNode(hasTestTag(Tags.DEV_LINK_UP))
        compose.onNodeWithTag(Tags.DEV_LINK_UP).performClick()
        compose.waitUntil(TIMEOUT) {
            runCatching { compose.onNodeWithTag(Tags.RADIO_BANNER).assertIsDisplayed() }.isSuccess
        }
        val context = compose.activity
        val description = compose.onNodeWithTag(Tags.RADIO_CONTROL).fetchSemanticsNode()
            .config[SemanticsProperties.ContentDescription].single()
        assertTrue(description, description.contains(context.getString(R.string.radio_tb_disconnected)))
        // The last reading stays, as a reading from before: never as live.
        val percent = runtime.radio.value!!.batteryPercent!!
        assertTrue(
            description,
            description.contains(context.resources.getQuantityString(R.plurals.radio_tb_last_battery, percent, percent)),
        )
        compose.onNodeWithTag(Tags.SETTINGS_LIST).performScrollToNode(hasTestTag(Tags.DEV_LINK_UP))
        compose.onNodeWithTag(Tags.DEV_LINK_UP).performClick()
        compose.waitUntil(TIMEOUT) {
            runCatching { compose.onNodeWithTag(Tags.RADIO_BANNER).assertDoesNotExist() }.isSuccess
        }
    }

    private fun <T> withTimeoutBlocking(block: suspend () -> T): T = runBlocking { withTimeout(TIMEOUT) { block() } }

    private companion object {
        const val TIMEOUT = 30_000L
        val SHORT_SHELL = 400.dp
    }
}
