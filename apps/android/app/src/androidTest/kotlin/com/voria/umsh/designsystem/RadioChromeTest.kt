package com.voria.umsh.designsystem

import android.icu.text.NumberFormat
import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertWidthIsEqualTo
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasClickAction
import androidx.compose.ui.test.hasNoClickAction
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.BannerSlot
import com.voria.umsh.app.Tags
import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.core.UlcpChargeState
import com.voria.umsh.core.UlcpHostOwnership
import com.voria.umsh.services.radio.RadioBanner
import com.voria.umsh.services.radio.RadioBanner.Reading
import com.voria.umsh.services.radio.RadioBanner.RejectReason
import com.voria.umsh.services.radio.RadioSnapshot
import java.time.Instant
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * `radio-control.svg` boards 1–3, from fake radio states: the control's
 * width and spoken state, and every banner row, including the ones the
 * emulator cannot reach (Bluetooth off, Nearby devices).
 */
class RadioChromeTest {
    @get:Rule val compose = createComposeRule()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val now = Instant.ofEpochMilli(10_000_000L)
    private val twelveMinutesAgo = now.toEpochMilli() - 12 * 60_000L

    private fun radio(
        phase: MobileRadioPhase = MobileRadioPhase.ATTACHED,
        percent: Int? = 78,
        charge: UlcpChargeState? = UlcpChargeState.DISCHARGING,
        reportsBattery: Boolean = true,
        cached: Boolean = false,
    ) = RadioSnapshot(
        phase = phase, name = "T1000-E", linkId = "link", host = UlcpHostOwnership.OURS,
        batteryPercent = percent, batteryMillivolts = null, charge = charge, batteryReadAtMs = twelveMinutesAgo,
        problem = null, carriesThisPhone = phase == MobileRadioPhase.ATTACHED, reportsBattery = reportsBattery,
        batteryCached = cached,
    )

    private val board1 = listOf(
        radio(),
        radio(charge = UlcpChargeState.CHARGING),
        radio(percent = null, charge = UlcpChargeState.CHARGED),
        radio(percent = null, charge = null),
        radio(percent = null, charge = null, reportsBattery = false),
        radio(percent = 12),
        radio(phase = MobileRadioPhase.RECONNECTING, cached = true),
        radio(phase = MobileRadioPhase.WAITING_FOR_RADIO, cached = true),
        radio(phase = MobileRadioPhase.FAILED, cached = true),
        null,
    )

    private fun SemanticsNodeInteraction.description(): String =
        fetchSemanticsNode().config[SemanticsProperties.ContentDescription].single()

    @Test
    fun everyStateHasTheSameWidthAndNoAction() {
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                Column { board1.forEach { RadioControl(it, now) } }
            }
        }
        val pills = compose.onAllNodesWithTag(Tags.RADIO_CONTROL)
        pills.assertCountEquals(board1.size)
        for (i in board1.indices) {
            pills[i].assertWidthIsEqualTo(RadioControlMetrics.Width).assert(hasNoClickAction())
        }
    }

    /** The board's sentence: its clauses joined by commas alone, never "and", on every API level. */
    private fun sentence(vararg clauses: String): String = clauses.joinToString(", ")

    @Test
    fun talkBackReadsTheBoardsClauses() {
        var shown by mutableStateOf<RadioSnapshot?>(null)
        compose.setContent { UmshTheme { RadioControl(shown, now) } }
        val spoken = board1.map { radio ->
            compose.runOnIdle { shown = radio }
            compose.onNodeWithTag(Tags.RADIO_CONTROL).description()
        }
        val name = "Companion radio T1000-E"
        assertEquals(sentence(name, "connected", "battery 78 percent"), spoken[0])
        assertEquals(sentence(name, "connected", "battery 78 percent", "charging"), spoken[1])
        assertEquals(sentence(name, "connected", "on external power"), spoken[2])
        assertEquals(sentence(name, "connected", "battery level unavailable"), spoken[3])
        assertEquals(sentence(name, "connected"), spoken[4])
        assertEquals(sentence(name, "connected", "battery 12 percent"), spoken[5])
        assertEquals(sentence(name, "reconnecting", "last battery 78 percent", "12 minutes ago"), spoken[6])
        assertEquals(sentence(name, "disconnected", "last battery 78 percent", "12 minutes ago"), spoken[7])
        assertEquals(sentence(name, "connection failed", "last battery 78 percent", "12 minutes ago"), spoken[8])
        assertEquals(context.getString(R.string.radio_tb_not_set_up), spoken[9])
    }

    /** Before the first status: an empty pill that names the radio and claims nothing, not "No companion radio". */
    @Test
    fun anUnreadRadioClaimsNothing() {
        compose.setContent { UmshTheme { RadioControl(null, now, known = false) } }
        assertEquals(context.getString(R.string.radio_tb_unnamed), compose.onNodeWithTag(Tags.RADIO_CONTROL).description())
        compose.onNodeWithTag(Tags.RADIO_CONTROL).assertWidthIsEqualTo(RadioControlMetrics.Width)
    }

    @Test
    fun everyBannerRow() {
        val last = Reading("T1000-E", 78, twelveMinutesAgo)
        val rows = listOf(
            RadioBanner.NoRadio,
            RadioBanner.Disconnected(last),
            RadioBanner.BluetoothOff(last),
            RadioBanner.NearbyDenied,
            RadioBanner.Failed(last),
            RadioBanner.TransmissionRejected(RejectReason.DutyCycle, Reading("T1000-E", 52, twelveMinutesAgo)),
            RadioBanner.TransmissionRejected(RejectReason.Status("INVALID_STATE"), Reading("T1000-E", null, null)),
        )
        val percent = { p: Int -> NumberFormat.getPercentInstance(Locale.getDefault()).format(p / 100.0) }
        var shown by mutableStateOf(rows[0])
        // The age as the app words it in this locale ("12 min. ago" in
        // English, checked by AndroidTimeFormattingTest): the rows are built
        // from the resources, so the test passes in any language.
        var age = ""
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                age = ageText(Instant.ofEpochMilli(twelveMinutesAgo), now)
                RadioProblemBanner(shown, now)
            }
        }
        compose.waitForIdle()
        val lastBattery = context.getString(R.string.banner_detail_last_battery, "T1000-E", percent(78), age)
        val status = context.getString(R.string.banner_reason_status, "\u2066INVALID_STATE\u2069")
        val expected = listOf(
            R.string.banner_no_radio_title to context.getString(R.string.banner_detail_choose_radio),
            R.string.banner_disconnected_title to lastBattery,
            R.string.banner_bluetooth_off_title to lastBattery,
            R.string.banner_nearby_denied_title to context.getString(R.string.banner_detail_needs_permission),
            R.string.banner_failed_title to lastBattery,
            R.string.banner_tx_rejected_title to context.getString(
                R.string.banner_detail_reason_battery,
                context.getString(R.string.banner_reason_duty_cycle),
                "T1000-E",
                percent(52),
            ),
            R.string.banner_tx_rejected_title to context.getString(R.string.banner_detail_reason_radio, status, "T1000-E"),
        )
        for ((i, row) in rows.withIndex()) {
            compose.runOnIdle { shown = row }
            val nodes = compose.onAllNodes(hasAnyAncestor(hasTestTag(Tags.RADIO_BANNER)) and SemanticsMatcher.keyIsDefined(SemanticsProperties.Text))
                .fetchSemanticsNodes()
            val texts = nodes.flatMap { node -> node.config[SemanticsProperties.Text].map { it.text } }
            assertEquals("row $i", listOf(context.getString(expected[i].first), expected[i].second), texts)
            // The title alone is the live region: the detail's age ticks each
            // minute, and must not have the banner read out again.
            assertEquals("row $i", listOf(true, false), nodes.map { SemanticsProperties.LiveRegion in it.config })
            // No action until its page or request exists (D14).
            compose.onAllNodesWithTag(Tags.BANNER_ACTION).assertCountEquals(0)
        }
    }

    /** The shell's own banner slot, as `UmshShell` draws it. */
    @Test
    fun theDataLoadBannerStacksAboveAndRetries() {
        var retried = 0
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                BannerSlot(dataLoadFailed = true, radioBanner = RadioBanner.NoRadio, now = now, onRetry = { retried++ })
            }
        }
        compose.onNodeWithTag(Tags.BANNER_ACTION)
            .assert(hasClickAction())
            .assert(hasAnyAncestor(hasTestTag(Tags.DATA_LOAD_BANNER)))
            .performClick()
        compose.runOnIdle { assertEquals(1, retried) }
        val top = compose.onNodeWithTag(Tags.DATA_LOAD_BANNER).fetchSemanticsNode().boundsInRoot.top
        val below = compose.onNodeWithTag(Tags.RADIO_BANNER).fetchSemanticsNode().boundsInRoot.top
        assertTrue(top < below)
    }
}
