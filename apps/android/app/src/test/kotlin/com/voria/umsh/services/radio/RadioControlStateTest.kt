package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.core.MobileRadioProblem
import com.voria.umsh.core.MobileRadioStateRecord
import com.voria.umsh.core.UlcpBatteryRecord
import com.voria.umsh.core.UlcpChargeState
import com.voria.umsh.core.UlcpHostOwnership
import com.voria.umsh.services.radio.RadioBanner.Reading
import com.voria.umsh.services.radio.RadioBanner.RejectReason
import com.voria.umsh.services.radio.RadioControlState.Extra
import com.voria.umsh.services.radio.RadioControlState.Link
import com.voria.umsh.services.radio.RadioControlState.Power
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** `radio-control.svg` boards 1–3: what the control and the banner show for each radio state. */
class RadioControlStateTest {
    private fun radio(
        phase: MobileRadioPhase = MobileRadioPhase.ATTACHED,
        percent: Int? = 78,
        charge: UlcpChargeState? = UlcpChargeState.DISCHARGING,
        reportsBattery: Boolean = true,
        problem: MobileRadioProblem? = null,
    ) = RadioSnapshot(
        phase = phase,
        name = "T1000-E",
        linkId = "link",
        host = UlcpHostOwnership.OURS,
        batteryPercent = percent,
        batteryMillivolts = null,
        charge = charge,
        batteryReadAtMs = 1_000L,
        problem = problem,
        carriesThisPhone = phase == MobileRadioPhase.ATTACHED,
        reportsBattery = reportsBattery,
    )

    @Test
    fun board1ConnectedStates() {
        assertEquals(RadioControlState(Link.Connected, Power.Level(78, null), false, "T1000-E", 1_000L),
            RadioControlState.from(radio()))
        assertEquals(Power.Level(78, Extra.Charging),
            RadioControlState.from(radio(charge = UlcpChargeState.CHARGING)).power)
        assertEquals(Power.ExternalOnly(charging = false),
            RadioControlState.from(radio(percent = null, charge = UlcpChargeState.CHARGED)).power)
        assertEquals(Power.ExternalOnly(charging = false),
            RadioControlState.from(radio(percent = null, charge = UlcpChargeState.NOT_CHARGING)).power)
        // Battery unavailable: measures one, no reading yet.
        assertEquals(Power.Unknown, RadioControlState.from(radio(percent = null, charge = null)).power)
        // No power state at all.
        assertNull(RadioControlState.from(radio(percent = null, charge = null, reportsBattery = false)).power)
        val low = RadioControlState.from(radio(percent = 12)).power as Power.Level
        assertEquals(1, low.bars)
    }

    @Test
    fun notConnectedShowsTheLastReadingDimmed() {
        for ((phase, link) in listOf(
            MobileRadioPhase.RECONNECTING to Link.Reconnecting,
            MobileRadioPhase.CONNECTING to Link.Connecting,
            MobileRadioPhase.SYNCHRONIZING to Link.Connecting,
            MobileRadioPhase.WAITING_FOR_RADIO to Link.Waiting,
            MobileRadioPhase.IDLE to Link.Disconnected,
            MobileRadioPhase.FAILED to Link.Failed,
        )) {
            val state = RadioControlState.from(radio(phase = phase, charge = UlcpChargeState.CHARGING))
            assertEquals(phase.name, link, state.link)
            // The charger's state is not kept: it says nothing about now.
            assertEquals(phase.name, Power.Level(78, null), state.power)
            assertTrue(phase.name, state.cached)
        }
        val none = RadioControlState.from(radio(phase = MobileRadioPhase.IDLE, percent = null))
        assertNull(none.power)
        assertFalse(none.cached)
    }

    /** The core keeps the last reading across links and says when it is one; the snapshot draws it so. */
    @Test
    fun aCachedReadingFromTheCoreIsDrawnDimmed() {
        fun record(phase: MobileRadioPhase, percent: Int, cached: Boolean) = MobileRadioStateRecord(
            phase = phase, name = "T1000-E", linkId = "a", host = UlcpHostOwnership.UNKNOWN, deviceKey = null,
            battery = UlcpBatteryRecord(percent.toUByte(), null, UlcpChargeState.CHARGING),
            batteryReadAtMs = 5_000uL, batteryCached = cached, alert = null, clock = null, position = null,
            provisioning = null, problem = null,
        )
        val down = RadioSnapshot.from(record(MobileRadioPhase.WAITING_FOR_RADIO, 78, cached = true))!!
        assertTrue(down.batteryCached)
        assertEquals(78, down.batteryPercent)
        assertEquals(5_000L, down.batteryReadAtMs)
        assertNull(down.charge)
        val control = RadioControlState.from(down)
        assertEquals(Power.Level(78, null), control.power)
        assertTrue(control.cached)
        assertEquals(RadioBanner.Disconnected(Reading("T1000-E", 78, 5_000L)), RadioBanner.from(down))
        // Back up with no reading yet: still the earlier link's, still dimmed, never live.
        val back = RadioSnapshot.from(record(MobileRadioPhase.ATTACHED, 78, cached = true))!!
        assertTrue(RadioControlState.from(back).cached)
        assertEquals(Power.Level(78, null), RadioControlState.from(back).power)
        // A reading over this link is live.
        val fresh = RadioSnapshot.from(record(MobileRadioPhase.ATTACHED, 60, cached = false))!!
        assertFalse(fresh.batteryCached)
        assertFalse(RadioControlState.from(fresh).cached)
        assertEquals(Power.Level(60, Extra.Charging), RadioControlState.from(fresh).power)
    }

    @Test
    fun noRadioIsItsOwnState() {
        val state = RadioControlState.from(null)
        assertEquals(Link.None, state.link)
        assertNull(state.power)
    }

    /** Before the first status, a null radio is "not read yet": the control says nothing, and there is no banner. */
    @Test
    fun anUnreadRadioIsNotNoRadio() {
        val state = RadioControlState.from(null, known = false)
        assertEquals(Link.Unknown, state.link)
        assertNull(state.power)
        assertNull(RadioBanner.from(null, known = false))
        assertNull(RadioBanner.from(radio(phase = MobileRadioPhase.FAILED), known = false))
        assertEquals(RadioBanner.NoRadio, RadioBanner.from(null, known = true))
    }

    @Test
    fun barsFollowTheLevel() {
        assertEquals(0, RadioControlState.batteryBars(0))
        assertEquals(1, RadioControlState.batteryBars(1))
        assertEquals(1, RadioControlState.batteryBars(12))
        assertEquals(3, RadioControlState.batteryBars(50))
        assertEquals(5, RadioControlState.batteryBars(78))
        assertEquals(6, RadioControlState.batteryBars(94))
        assertEquals(RadioControlState.FULL_BARS, RadioControlState.batteryBars(95))
        assertEquals(RadioControlState.FULL_BARS, RadioControlState.batteryBars(100))
    }

    @Test
    fun bannersByState() {
        val last = Reading("T1000-E", 78, 1_000L)
        assertEquals(RadioBanner.NoRadio, RadioBanner.from(null))
        assertNull(RadioBanner.from(radio()))
        assertNull(RadioBanner.from(radio(phase = MobileRadioPhase.RECONNECTING)))
        assertNull(RadioBanner.from(radio(phase = MobileRadioPhase.AWAITING_HOST)))
        assertEquals(RadioBanner.Disconnected(last), RadioBanner.from(radio(phase = MobileRadioPhase.IDLE)))
        assertEquals(RadioBanner.Disconnected(last), RadioBanner.from(radio(phase = MobileRadioPhase.WAITING_FOR_RADIO)))
        assertEquals(RadioBanner.Failed(last), RadioBanner.from(radio(phase = MobileRadioPhase.FAILED)))
        assertEquals(RadioBanner.BluetoothOff(last), RadioBanner.from(radio(phase = MobileRadioPhase.IDLE), bluetoothOff = true))
        assertEquals(RadioBanner.NearbyDenied, RadioBanner.from(radio(), nearbyDenied = true, bluetoothOff = true))
        assertEquals(RadioBanner.NoRadio, RadioBanner.from(null, nearbyDenied = true))
        assertEquals(RadioBanner.Tone.Error, RadioBanner.Failed(last).tone)
        assertEquals(RadioBanner.Tone.Warning, RadioBanner.Disconnected(last).tone)
    }

    @Test
    fun rejectedTransmissionsNameTheirReason() {
        fun rejected(code: UInt, name: String) =
            RadioBanner.from(radio(percent = 52, problem = MobileRadioProblem.TransmissionRejected(code, name)))
        val live = Reading("T1000-E", 52, 1_000L)
        assertEquals(RadioBanner.TransmissionRejected(RejectReason.DutyCycle, live), rejected(32u, "DUTY_LIMIT"))
        assertEquals(RadioBanner.TransmissionRejected(RejectReason.ChannelBusy, live), rejected(18u, "CCA_FAILURE"))
        assertEquals(RadioBanner.TransmissionRejected(RejectReason.QueueFull, live), rejected(11u, "NOMEM"))
        assertEquals(
            RadioBanner.TransmissionRejected(RejectReason.Status(4u), live),
            rejected(4u, "INVALID_STATE"),
        )
        assertEquals(
            RadioBanner.TransmissionRejected(RejectReason.RadioBusy, live),
            RadioBanner.from(radio(percent = 52, problem = MobileRadioProblem.RadioBusy)),
        )
        // A problem that is not about a transmission leaves the banner to Radio Detail.
        assertNull(RadioBanner.from(radio(problem = MobileRadioProblem.Disconnected)))
    }
}
