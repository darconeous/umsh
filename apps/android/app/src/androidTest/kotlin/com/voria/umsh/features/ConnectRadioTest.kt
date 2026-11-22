package com.voria.umsh.features

import androidx.activity.ComponentActivity
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.Tags
import com.voria.umsh.app.debug.FakeRadioScanSource
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.onboarding.ConnectFailure
import com.voria.umsh.features.onboarding.ConnectRadioScreen
import com.voria.umsh.features.onboarding.RadioScanState
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import kotlinx.coroutines.CompletableDeferred

/** Connect a radio (`onboarding.svg` boards 4–8) over the fake search (D6). */
class ConnectRadioTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private var setUpLater = 0
    private var connected = 0

    private val shown = mutableStateOf<FakeRadioScanSource?>(null)

    /** Content is set once per test; later calls swap the source. */
    private fun show(source: FakeRadioScanSource) {
        val first = shown.value == null
        compose.runOnUiThread { shown.value = source }
        if (!first) return
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                shown.value?.let { current ->
                    key(current) {
                        ConnectRadioScreen(current, onSetUpLater = { setUpLater++ }, onConnected = { connected++ })
                    }
                }
            }
        }
    }

    @Test
    fun radiosAppearWhileLookingContinues() {
        show(FakeRadioScanSource(reveal = FakeRadioScanSource.SAMPLE_RADIOS, revealMs = 50))
        compose.onNodeWithTag(Tags.CONNECT_RADIO_SEARCHING).assertIsDisplayed()
        compose.waitUntil(5_000) { compose.onAllNodesWithTag(Tags.CONNECT_RADIO_ROW).fetchSemanticsNodes().size == 3 }
        compose.onNodeWithTag(Tags.CONNECT_RADIO_SEARCHING).assertIsDisplayed()
        // An unknown model reads as such.
        compose.onNode(hasText(context.getString(R.string.unknown_model))).assertIsDisplayed()
        compose.onNodeWithTag(Tags.SET_UP_LATER).performClick()
        assertEquals(1, setUpLater)
    }

    /** Boards 6 and 7: progress on the tapped row, the rest disabled; a failure keeps the list, and a row tries again. */
    @Test
    fun aFailedConnectionKeepsTheListAndSaysWhatToDo() {
        // The connection fails only when the test says: the in-progress
        // state is checked with no clock running against it.
        val gate = CompletableDeferred<Unit>()
        val source = FakeRadioScanSource(RadioScanState.Looking(FakeRadioScanSource.SAMPLE_RADIOS), connectGate = gate)
        show(source)
        compose.onAllNodesWithTag(Tags.CONNECT_RADIO_ROW)[0].performClick()
        compose.onNodeWithTag(Tags.CONNECT_RADIO_PROGRESS).assertIsDisplayed()
        compose.onAllNodesWithTag(Tags.CONNECT_RADIO_ROW)[1].assertIsNotEnabled()
        compose.onNodeWithTag(Tags.CONNECT_RADIO_SEARCHING).assertDoesNotExist()
        gate.complete(Unit)
        compose.waitUntil(5_000) { compose.onAllNodes(hasTestTag(Tags.CONNECT_RADIO_FAILURE)).fetchSemanticsNodes().isNotEmpty() }
        compose.onNode(hasText(context.getString(R.string.pairing_removed))).assertIsDisplayed()
        compose.onAllNodesWithTag(Tags.CONNECT_RADIO_ROW)[1].assertHasClickAction().performClick()
        assertEquals(listOf("t1000e", "tdeck"), source.connects.map { it.id })
    }

    @Test
    fun aConnectionEndsOnboarding() {
        show(FakeRadioScanSource(RadioScanState.Looking(FakeRadioScanSource.SAMPLE_RADIOS), outcome = null, connectMs = 100))
        compose.onAllNodesWithTag(Tags.CONNECT_RADIO_ROW)[2].performClick()
        compose.waitUntil(5_000) { connected == 1 }
    }

    /** Board 8 and its siblings: in place of the list, with the one action that can help. */
    @Test
    fun blockedStatesReplaceTheList() {
        val source = FakeRadioScanSource(RadioScanState.NearbyDenied)
        show(source)
        compose.onNode(hasText(context.getString(R.string.banner_nearby_denied_title))).assertIsDisplayed()
        compose.onAllNodesWithTag(Tags.CONNECT_RADIO_ROW).assertCountEquals(0)
        compose.onNodeWithTag(Tags.CONNECT_RADIO_BLOCKED_ACTION).performClick()
        compose.onAllNodesWithTag(Tags.CONNECT_RADIO_ROW).assertCountEquals(3)

        show(FakeRadioScanSource(RadioScanState.BluetoothOff))
        compose.onNode(hasText(context.getString(R.string.banner_bluetooth_off_title))).assertIsDisplayed()
        compose.onNode(hasText(context.getString(R.string.action_turn_on))).assertIsDisplayed()

        // No usable adapter: said, with nothing to tap.
        show(FakeRadioScanSource(RadioScanState.BluetoothUnavailable))
        compose.onNode(hasText(context.getString(R.string.bluetooth_unavailable))).assertIsDisplayed()
        compose.onNodeWithTag(Tags.CONNECT_RADIO_BLOCKED_ACTION).assertDoesNotExist()
    }

    @Test
    fun everyFailureHasItsLine() {
        val lines = mapOf(
            ConnectFailure.PairingRemoved to R.string.pairing_removed,
            ConnectFailure.BluetoothUnavailable to R.string.bluetooth_unavailable,
            ConnectFailure.ConnectFailed to R.string.connect_failed,
        )
        for ((failure, line) in lines) {
            show(FakeRadioScanSource(RadioScanState.Looking(FakeRadioScanSource.SAMPLE_RADIOS, failure = failure)))
            compose.onNode(hasText(context.getString(line))).assertIsDisplayed()
        }
    }
}
