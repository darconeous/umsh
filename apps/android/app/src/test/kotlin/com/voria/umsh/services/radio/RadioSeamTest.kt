package com.voria.umsh.services.radio

import com.voria.umsh.R
import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.core.MobileRadioProblem
import com.voria.umsh.core.UlcpChargeState
import com.voria.umsh.core.UlcpHostOwnership
import com.voria.umsh.services.background.RadioServiceDecision
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The pure parts of the link seam: attachment tickets, problem codes, and when the service runs. */
class RadioSeamTest {
    // region RadioLinkLifecycle

    @Test
    fun phasesMoveOnlyFromTheExpectedOne() {
        val lifecycle = RadioLinkLifecycle()
        lifecycle.begin()
        assertFalse(lifecycle.advance(RadioLinkLifecycle.Phase.Services, RadioLinkLifecycle.Phase.Characteristics))
        assertEquals(RadioLinkLifecycle.Phase.Connecting, lifecycle.phase)
        assertTrue(lifecycle.advance(RadioLinkLifecycle.Phase.Connecting, RadioLinkLifecycle.Phase.Services))
        assertTrue(lifecycle.advance(RadioLinkLifecycle.Phase.Services, RadioLinkLifecycle.Phase.Characteristics))
        lifecycle.clear()
        assertEquals(RadioLinkLifecycle.Phase.Idle, lifecycle.phase)
    }

    @Test
    fun gattCallbacksBelongOnlyToAnAttachment() {
        val lifecycle = RadioLinkLifecycle()
        assertFalse(lifecycle.acceptsGatt)
        lifecycle.begin()
        assertFalse(lifecycle.acceptsGatt)
        lifecycle.advance(RadioLinkLifecycle.Phase.Connecting, RadioLinkLifecycle.Phase.Services)
        assertTrue(lifecycle.acceptsGatt)
        lifecycle.advance(RadioLinkLifecycle.Phase.Services, RadioLinkLifecycle.Phase.Characteristics)
        lifecycle.advance(RadioLinkLifecycle.Phase.Characteristics, RadioLinkLifecycle.Phase.Subscribing)
        lifecycle.advance(RadioLinkLifecycle.Phase.Subscribing, RadioLinkLifecycle.Phase.Ready)
        assertTrue(lifecycle.acceptsGatt)
        lifecycle.clear()
        assertFalse(lifecycle.acceptsGatt)
    }

    // endregion

    // region RadioTransportProblem

    /** The codes are iOS's, case for case, so both apps and the core read a number the same way. */
    @Test
    fun transportProblemCodesMatchIos() {
        val swift = File(System.getProperty("umsh.repoDir")!!, "apps/ios/UMSH/Services/Radio/RadioProblem.swift").readText()
        val body = swift.substringAfter("enum RadioTransportProblem").substringBefore("static let domain")
        val cases = Regex("""case (\w+)(?: = (\d+))?""").findAll(body).map { it.groupValues[1] to it.groupValues[2] }.toList()
        assertEquals("1", cases.first().second)
        // Swift numbers a case without its own value one past the case before it.
        var next = 0L
        val ios = cases.map { (name, value) ->
            next = value.toLongOrNull() ?: (next + 1)
            name.replaceFirstChar(Char::uppercaseChar) to next
        }
        assertEquals(ios, RadioTransportProblem.entries.map { it.name to it.code })
        assertEquals("com.voria.umsh.radio-transport", RadioTransportProblem.DOMAIN)
    }

    @Test
    fun aTransportProblemRoundTripsAndOthersAreNotOurs() {
        RadioTransportProblem.entries.forEach { assertEquals(it, RadioTransportProblem.of(it.problem)) }
        assertNull(RadioTransportProblem.of(MobileRadioProblem.Transport("android.bluetooth.gatt", 133)))
        assertNull(RadioTransportProblem.of(MobileRadioProblem.Transport(RadioTransportProblem.DOMAIN, 999)))
        assertNull(RadioTransportProblem.of(MobileRadioProblem.Disconnected))
    }

    /** Every problem is worded by a resource of this app's; a system error never by its own text. */
    @Test
    fun everyProblemHasWords() {
        RadioTransportProblem.entries.forEach { assertTrue(RadioProblemWords.text(it) != 0) }
        assertEquals(
            R.string.radio_problem_bridge_closed,
            RadioProblemWords.of(RadioTransportProblem.BridgeClosed.problem).text,
        )
        assertEquals(
            R.string.radio_problem_connection_failed,
            RadioProblemWords.of(MobileRadioProblem.Transport("android.bluetooth.gatt", 133)).text,
        )
    }

    // endregion

    // region RadioServiceDecision

    private fun radio(phase: MobileRadioPhase, percent: Int? = null, charge: UlcpChargeState? = null) = RadioSnapshot(
        phase = phase,
        name = "10.0.2.2:21838",
        linkId = "10.0.2.2:21838",
        host = UlcpHostOwnership.OURS,
        batteryPercent = percent,
        batteryMillivolts = null,
        charge = charge,
        batteryReadAtMs = null,
        problem = null,
        carriesThisPhone = phase == MobileRadioPhase.ATTACHED,
    )

    private val bound = BoundRadio(RadioKind.Tcp, "10.0.2.2:21838")

    @Test
    fun theServiceRunsWhileAWantedRadioComesUpOrIsAttached() {
        fun decide(phase: MobileRadioPhase) = RadioServiceDecision.of(true, true, bound, radio(phase), radioKnown = true)
        assertEquals(RadioServiceDecision.Link.Connected, (decide(MobileRadioPhase.ATTACHED) as RadioServiceDecision.Run).link)
        listOf(
            MobileRadioPhase.CONNECTING,
            MobileRadioPhase.PAIRING,
            MobileRadioPhase.ATTACHING,
            MobileRadioPhase.SYNCHRONIZING,
            MobileRadioPhase.AWAITING_HOST,
        ).forEach { phase ->
            assertEquals(phase.name, RadioServiceDecision.Link.Connecting, (decide(phase) as RadioServiceDecision.Run).link)
        }
        assertEquals(RadioServiceDecision.Link.Reconnecting, (decide(MobileRadioPhase.RECONNECTING) as RadioServiceDecision.Run).link)
        listOf(MobileRadioPhase.IDLE, MobileRadioPhase.FAILED, MobileRadioPhase.UNAVAILABLE, MobileRadioPhase.DISCONNECTING)
            .forEach { assertEquals(it.name, RadioServiceDecision.Stop, decide(it)) }
    }

    @Test
    fun theServiceStopsWithoutAWantedLiveRadio() {
        val attached = radio(MobileRadioPhase.ATTACHED)
        // Disconnect: the intent is gone, whatever the link still says.
        assertEquals(RadioServiceDecision.Stop, RadioServiceDecision.of(true, true, bound.copy(autoConnect = false), attached, true))
        assertEquals(RadioServiceDecision.Stop, RadioServiceDecision.of(true, true, null, attached, true))
        assertEquals(RadioServiceDecision.Stop, RadioServiceDecision.of(true, false, bound, attached, true))
        // Staging never runs it.
        assertEquals(RadioServiceDecision.Stop, RadioServiceDecision.of(false, true, bound, attached, true))
        assertEquals(RadioServiceDecision.Stop, RadioServiceDecision.of(true, true, bound, null, true))
        // Neither start nor stop while a core or its radio is still coming up.
        assertEquals(RadioServiceDecision.Pending, RadioServiceDecision.of(null, false, bound, null, false))
        assertEquals(RadioServiceDecision.Pending, RadioServiceDecision.of(true, true, bound, null, false))
    }

    // endregion
}
