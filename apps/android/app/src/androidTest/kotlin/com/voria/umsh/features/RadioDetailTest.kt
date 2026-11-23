package com.voria.umsh.features

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.assertTextEquals
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.Tags
import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import com.voria.umsh.services.radio.ScriptedRadioConnection
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Rule
import org.junit.Test

/**
 * Radio Detail (`radio-detail.svg` 1–5) over the real core and driver: a
 * scripted link reports the transport states the emulator cannot reach
 * (Waiting, Failed with its reason), and the staging air's radio goes up
 * and down. Opened from the radio control above the shell, from the
 * banner's Details, and from Settings › Companion radio.
 */
class RadioDetailTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun string(id: Int, vararg args: Any) = context.getString(id, *args)

    /** A live core bound to [linkId] (a scripted radio), past Welcome, drawn. */
    private fun live(linkId: String): AppRuntime {
        runBlocking { fresh.host.preferences.radioRegistry.bind(BoundRadio(RadioKind.Tcp, linkId, name = RADIO_NAME)) }
        fresh.host.ensureRuntime(staging = false)
        return show()
    }

    private fun show(): AppRuntime {
        val runtime = runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime.setOnboarding(OnboardingStep.Done).await()
            ready.runtime
        }
        compose.setContent { AppRoot(fresh.host) }
        return runtime
    }

    private fun waitForPhase(runtime: AppRuntime, phase: MobileRadioPhase) = runBlocking {
        withTimeout(TIMEOUT) { runtime.radio.first { it?.phase == phase } }
    }

    private fun waitFor(tag: String) = compose.waitUntil(TIMEOUT) {
        compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()
    }

    private fun waitForGone(tag: String) = compose.waitUntil(TIMEOUT) {
        compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isEmpty()
    }

    private fun state(): SemanticsNodeInteraction = compose.onNodeWithTag(Tags.RADIO_DETAIL_STATE)

    private fun waitForState(id: Int) = compose.waitUntil(TIMEOUT) {
        runCatching { state().assertTextEquals(string(id)) }.isSuccess
    }

    private fun back() = compose.runOnUiThread { compose.activity.onBackPressedDispatcher.onBackPressed() }

    private fun openFromTheControl() {
        waitFor(Tags.RADIO_CONTROL)
        compose.onNodeWithTag(Tags.RADIO_CONTROL).performClick()
        waitFor(Tags.RADIO_DETAIL)
    }

    /**
     * Neither request the radio could refuse is offered. A live radio's
     * Maintenance still offers Choose another radio; the staging core's
     * radio has no Maintenance at all.
     */
    private fun assertNoMaintenance(staged: Boolean = false) {
        compose.onAllNodesWithTag(Tags.RADIO_DETAIL_RESTART).assertCountEquals(0)
        compose.onAllNodesWithTag(Tags.RADIO_DETAIL_FACTORY_RESET).assertCountEquals(0)
        compose.onAllNodesWithTag(Tags.RADIO_DETAIL_CHOOSE_ANOTHER).assertCountEquals(if (staged) 0 else 1)
        compose.onAllNodes(hasText(string(R.string.radio_section_maintenance))).assertCountEquals(if (staged) 0 else 1)
    }

    @Test
    fun waitingThenStopWaiting() {
        val runtime = live("scripted:waiting")
        waitForPhase(runtime, MobileRadioPhase.WAITING_FOR_RADIO)
        // Left on Peers, so Back has a shell state to return to that is not the default.
        compose.onNodeWithTag(Tags.NAV_PEERS).performClick()
        openFromTheControl()
        compose.onNodeWithTag(Tags.RADIO_DETAIL_NAME).assertTextEquals(RADIO_NAME)
        waitForState(R.string.radio_state_waiting)
        compose.onNodeWithTag(Tags.RADIO_DETAIL_CAPTION).assertTextEquals(string(R.string.radio_waiting_caption))
        compose.onNodeWithTag(Tags.RADIO_DETAIL_PRIMARY).assertTextEquals(string(R.string.radio_stop_waiting))
        // Out of reach, the radio can take neither request.
        assertNoMaintenance()

        // Stop waiting is Disconnect: the link rests, and Connect is offered.
        compose.onNodeWithTag(Tags.RADIO_DETAIL_PRIMARY).performScrollTo().performClick()
        waitForState(R.string.radio_state_disconnected)
        compose.onNodeWithTag(Tags.RADIO_DETAIL_PRIMARY).assertTextEquals(string(R.string.radio_connect))
        runBlocking { withTimeout(TIMEOUT) { fresh.host.preferences.radioRegistry.bound.first { it?.autoConnect == false } } }
        assertNoMaintenance()

        // Choose another radio opens Choose a radio over the page; Back returns to it.
        compose.onNodeWithTag(Tags.RADIO_DETAIL_CHOOSE_ANOTHER).performScrollTo().performClick()
        waitFor(Tags.CHOOSE_RADIO)
        back()
        waitForGone(Tags.CHOOSE_RADIO)
        compose.onNodeWithTag(Tags.RADIO_DETAIL).assertIsDisplayed()

        // Back returns to the shell as it was left: Peers, still selected.
        back()
        waitForGone(Tags.RADIO_DETAIL)
        compose.onNodeWithTag(Tags.PEERS_ROOT).assertIsDisplayed()
        compose.onNodeWithTag(Tags.NAV_PEERS).assertIsSelected()
    }

    @Test
    fun failedSaysWhyThenForgetCloses() {
        val linkId = "scripted:failed"
        val runtime = live(linkId)
        waitForPhase(runtime, MobileRadioPhase.FAILED)
        openFromTheControl()
        waitForState(R.string.radio_state_failed)
        compose.onNodeWithTag(Tags.RADIO_DETAIL_REASON).assertTextContains(string(R.string.radio_problem_attachment_incomplete))
        compose.onNodeWithTag(Tags.RADIO_DETAIL_PRIMARY).assertTextEquals(string(R.string.radio_reconnect))
        assertNoMaintenance()

        // Reconnect reaches the link, which fails again, with its reason.
        val connects = ScriptedRadioConnection.connectCount(linkId)
        compose.onNodeWithTag(Tags.RADIO_DETAIL_PRIMARY).performScrollTo().performClick()
        compose.waitUntil(TIMEOUT) { ScriptedRadioConnection.connectCount(linkId) > connects }
        waitForState(R.string.radio_state_failed)
        compose.onNodeWithTag(Tags.RADIO_DETAIL_REASON).assertTextContains(string(R.string.radio_problem_attachment_incomplete))

        compose.onNodeWithTag(Tags.RADIO_DETAIL_FORGET).performScrollTo().performClick()
        compose.onNode(hasText(string(R.string.forget_radio_title))).assertIsDisplayed()
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).assertTextEquals(string(R.string.forget_radio_confirm)).performClick()
        // No radio left: the page closes, and the shell says so.
        waitForGone(Tags.RADIO_DETAIL)
        waitFor(Tags.RADIO_BANNER)
        compose.onNode(hasAnyAncestor(hasTestTag(Tags.RADIO_BANNER)) and hasText(string(R.string.banner_no_radio_title)))
            .assertIsDisplayed()
        runBlocking { withTimeout(TIMEOUT) { fresh.host.preferences.radioRegistry.bound.first { it == null } } }
    }

    @Test
    fun bannerDetailsAndTheSettingsRow() {
        val runtime = live("scripted:waiting")
        waitForPhase(runtime, MobileRadioPhase.WAITING_FOR_RADIO)
        waitFor(Tags.BANNER_ACTION)
        compose.onNodeWithTag(Tags.BANNER_ACTION).assertTextEquals(string(R.string.banner_action_details)).performClick()
        waitFor(Tags.RADIO_DETAIL)
        back()
        waitForGone(Tags.RADIO_DETAIL)

        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_COMPANION_RADIO)
            .assertTextContains(string(R.string.companion_radio_row_no_battery, RADIO_NAME, string(R.string.radio_state_waiting)))
            .performClick()
        // Inside the Settings stack: no radio control or banner (each would
        // open this page over itself), Back in its bar, returning to Settings.
        waitFor(Tags.RADIO_DETAIL)
        waitForGone(Tags.RADIO_CONTROL)
        waitForGone(Tags.RADIO_BANNER)
        waitForGone(Tags.BANNER_ACTION)
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).assertIsDisplayed().performClick()
        waitForGone(Tags.RADIO_DETAIL)
        compose.onNodeWithTag(Tags.SETTINGS_ROOT).assertIsDisplayed()
        compose.onNodeWithTag(Tags.NAV_SETTINGS).assertIsSelected()
    }

    @Test
    fun stagedRadioGoesDownAndUp() {
        fresh.host.ensureRuntime(staging = true)
        val runtime = show()
        waitForPhase(runtime, MobileRadioPhase.ATTACHED)
        openFromTheControl()
        waitForState(R.string.radio_state_connected)
        // Attached, but it cannot restart: it would refuse a factory reset too.
        assertNoMaintenance(staged = true)
        compose.onNodeWithTag(Tags.RADIO_DETAIL_PRIMARY).assertTextEquals(string(R.string.radio_disconnect)).performClick()
        compose.waitUntil(TIMEOUT) {
            runCatching { compose.onNodeWithTag(Tags.RADIO_DETAIL_PRIMARY).assertTextEquals(string(R.string.radio_connect)) }.isSuccess
        }
        compose.onNodeWithTag(Tags.RADIO_DETAIL_PRIMARY).performClick()
        waitForState(R.string.radio_state_connected)
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val RADIO_NAME = "T1000-E 4F2A"
    }
}
