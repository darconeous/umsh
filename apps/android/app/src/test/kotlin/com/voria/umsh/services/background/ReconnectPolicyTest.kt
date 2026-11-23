package com.voria.umsh.services.background

import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.core.MobileRadioTransportPhase
import com.voria.umsh.core.UlcpHostOwnership
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import com.voria.umsh.services.radio.RadioSnapshot
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** §7.2 and §7.3 as pure rules: the window, the strategies, what the service holds, and what presence observes. */
class ReconnectPolicyTest {
    private var now = 0L
    private val policy = ReconnectPolicy({ now }, windowMs = 120_000)

    // region The window

    @Test
    fun aLossStartsAWindowOfTwoMinutes() {
        assertEquals(120_000L, ReconnectPolicy.WINDOW_MS)
        assertEquals(120_000L, policy.begin(lost = true))
        assertEquals(ReconnectPolicy.Seeking.Reconnecting, policy.seeking)
        assertEquals(MobileRadioTransportPhase.RECONNECTING, policy.connectingPhase())
        now = 119_999
        assertFalse(policy.windowPassed())
        now = 120_000
        assertTrue(policy.windowPassed())
    }

    @Test
    fun aStartThatIsNoLossIsConnecting() {
        policy.begin(lost = false)
        assertEquals(ReconnectPolicy.Seeking.Connecting, policy.seeking)
        assertEquals(MobileRadioTransportPhase.CONNECTING, policy.connectingPhase())
    }

    /** Failures inside the window (status 133, a fault the driver retries) never extend it. */
    @Test
    fun lossesInsideTheWindowKeepItsEnd() {
        policy.begin(lost = true)
        now = 60_000
        assertNull(policy.begin(lost = true))
        assertEquals(120_000L, policy.windowEndsAt)
    }

    /** The user's Connect, or a wake for a radio left to presence: a new window. */
    @Test
    fun aFreshStartRestartsTheWindow() {
        policy.begin(lost = true)
        now = 100_000
        assertEquals(220_000L, policy.begin(lost = false, fresh = true))
        assertEquals(ReconnectPolicy.Seeking.Connecting, policy.seeking)
    }

    /** The Developer switch: a radio past the window takes the new strategy; one inside it, or not sought, is unchanged. */
    @Test
    fun aStrategyChangeReachesOnlyARadioPastTheWindow() {
        assertEquals(ReconnectPolicy.Seeking.None, policy.strategyChanged(ReconnectStrategy.Waiting))
        policy.begin(lost = true)
        assertEquals(ReconnectPolicy.Seeking.Reconnecting, policy.strategyChanged(ReconnectStrategy.Waiting))
        now = 120_000
        assertEquals(ReconnectPolicy.Seeking.Parked, policy.windowEnded(ReconnectStrategy.Presence))
        assertEquals(ReconnectPolicy.Seeking.Waiting, policy.strategyChanged(ReconnectStrategy.Waiting))
        assertEquals(ReconnectPolicy.Seeking.Parked, policy.strategyChanged(ReconnectStrategy.Presence))
    }

    @Test
    fun presencePastTheWindowParksTheLink() {
        policy.begin(lost = true)
        now = 120_000
        assertEquals(ReconnectPolicy.Seeking.Parked, policy.windowEnded(ReconnectStrategy.Presence))
        assertEquals(MobileRadioTransportPhase.WAITING_FOR_RADIO, policy.connectingPhase())
        assertNull(policy.windowEndsAt)
        // A wake after that is fresh.
        assertEquals(240_000L, policy.begin(lost = false))
        assertEquals(ReconnectPolicy.Seeking.Connecting, policy.seeking)
    }

    @Test
    fun waitingPastTheWindowKeepsSeeking() {
        policy.begin(lost = true)
        now = 120_000
        assertEquals(ReconnectPolicy.Seeking.Waiting, policy.windowEnded(ReconnectStrategy.Waiting))
        assertEquals(MobileRadioTransportPhase.WAITING_FOR_RADIO, policy.connectingPhase())
        // A failure while waiting stays Waiting, with no window.
        assertNull(policy.begin(lost = true))
        assertEquals(ReconnectPolicy.Seeking.Waiting, policy.seeking)
    }

    @Test
    fun theWindowEndsOnlyOnceItHasPassed() {
        policy.begin(lost = true)
        now = 1_000
        assertEquals(ReconnectPolicy.Seeking.Reconnecting, policy.windowEnded(ReconnectStrategy.Presence))
    }

    /** Attached, Disconnect, a fault given up on, Bluetooth off: no window runs. */
    @Test
    fun stoppingEndsTheWindow() {
        policy.begin(lost = true)
        policy.stop()
        assertEquals(ReconnectPolicy.Seeking.None, policy.seeking)
        now = 500_000
        assertFalse(policy.windowPassed())
        assertEquals(ReconnectPolicy.Seeking.None, policy.windowEnded(ReconnectStrategy.Presence))
    }

    // endregion

    // region The strategy a radio gets

    private val associated = BoundRadio(RadioKind.Ble, "C0:FF:EE:00:00:01", associationId = "7")

    @Test
    fun presenceNeedsCompanionSupportAndAnAssociation() {
        assertEquals(ReconnectStrategy.Presence, ReconnectStrategy.effective(ReconnectStrategy.Presence, true, associated))
        // The Developer switch.
        assertEquals(ReconnectStrategy.Waiting, ReconnectStrategy.effective(ReconnectStrategy.Waiting, true, associated))
        // No FEATURE_COMPANION_DEVICE_SETUP.
        assertEquals(ReconnectStrategy.Waiting, ReconnectStrategy.effective(ReconnectStrategy.Presence, false, associated))
        // Bound with no association (the debug bonded row).
        assertEquals(
            ReconnectStrategy.Waiting,
            ReconnectStrategy.effective(ReconnectStrategy.Presence, true, associated.copy(associationId = null)),
        )
        assertEquals(
            ReconnectStrategy.Waiting,
            ReconnectStrategy.effective(ReconnectStrategy.Presence, true, BoundRadio(RadioKind.Tcp, "10.0.2.2:21838")),
        )
    }

    // endregion

    // region What the service holds

    private fun radio(phase: MobileRadioPhase) = RadioSnapshot(
        phase = phase,
        name = "T1000-E",
        linkId = associated.linkId,
        host = UlcpHostOwnership.OURS,
        batteryPercent = 78,
        batteryMillivolts = null,
        charge = null,
        batteryReadAtMs = 0,
        problem = null,
        carriesThisPhone = phase == MobileRadioPhase.ATTACHED,
    )

    private fun decide(phase: MobileRadioPhase, strategy: ReconnectStrategy) =
        RadioServiceDecision.of(true, true, associated, radio(phase), true, strategy)

    @Test
    fun withinTheWindowTheServiceShowsReconnecting() {
        ReconnectStrategy.entries.forEach { strategy ->
            assertEquals(RadioServiceDecision.Link.Reconnecting, (decide(MobileRadioPhase.RECONNECTING, strategy) as RadioServiceDecision.Run).link)
        }
    }

    @Test
    fun pastTheWindowOnlyWaitingHoldsTheService() {
        assertEquals(RadioServiceDecision.Stop, decide(MobileRadioPhase.WAITING_FOR_RADIO, ReconnectStrategy.Presence))
        assertEquals(
            RadioServiceDecision.Link.Waiting,
            (decide(MobileRadioPhase.WAITING_FOR_RADIO, ReconnectStrategy.Waiting) as RadioServiceDecision.Run).link,
        )
    }

    /** Bluetooth off: Presence stops (its observation stays); Waiting keeps the service, its receiver seeking the radio when it is back. */
    @Test
    fun bluetoothOffUnderEachStrategy() {
        assertEquals(RadioServiceDecision.Stop, decide(MobileRadioPhase.UNAVAILABLE, ReconnectStrategy.Presence))
        assertEquals(
            RadioServiceDecision.Link.Waiting,
            (decide(MobileRadioPhase.UNAVAILABLE, ReconnectStrategy.Waiting) as RadioServiceDecision.Run).link,
        )
        // The bridged radio has no Waiting.
        val tcp = BoundRadio(RadioKind.Tcp, "10.0.2.2:21838")
        assertEquals(RadioServiceDecision.Stop, RadioServiceDecision.of(true, true, tcp, radio(MobileRadioPhase.UNAVAILABLE), true, ReconnectStrategy.Waiting))
    }

    /** A fault given up on (a lost bond included), Disconnect and Stop: nothing held under either strategy. */
    @Test
    fun failedAndDisconnectedHoldNothing() {
        ReconnectStrategy.entries.forEach { strategy ->
            assertEquals(RadioServiceDecision.Stop, decide(MobileRadioPhase.FAILED, strategy))
            assertEquals(RadioServiceDecision.Stop, decide(MobileRadioPhase.IDLE, strategy))
            assertEquals(
                RadioServiceDecision.Stop,
                RadioServiceDecision.of(true, true, associated.copy(autoConnect = false), radio(MobileRadioPhase.WAITING_FOR_RADIO), true, strategy),
            )
        }
    }

    // endregion

    // region What presence observes

    @Test
    fun presenceObservesTheWantedAssociatedRadioOnly() {
        assertEquals("7", RadioPresence.observedFor(associated, ReconnectStrategy.Presence, available = true))
        // Disconnect and DFU leave the radio bound but not wanted.
        assertNull(RadioPresence.observedFor(associated.copy(autoConnect = false), ReconnectStrategy.Presence, true))
        // Still being added: watched once it has attached.
        assertNull(
            RadioPresence.observedFor(
                associated.copy(pending = com.voria.umsh.services.radio.PendingBinding.NewAssociation),
                ReconnectStrategy.Presence,
                true,
            ),
        )
        // Forget and a factory reset clear it.
        assertNull(RadioPresence.observedFor(null, ReconnectStrategy.Presence, true))
        // The Waiting strategy, or no companion support.
        assertNull(RadioPresence.observedFor(associated, ReconnectStrategy.Waiting, true))
        assertNull(RadioPresence.observedFor(associated, ReconnectStrategy.Presence, available = false))
        assertNull(RadioPresence.observedFor(associated.copy(associationId = null), ReconnectStrategy.Presence, true))
    }

    /** The follower: the wanted radio observed, every other association told to stop, as the registry changes. */
    @Test
    fun presenceFollowsTheRegistry() {
        val calls = mutableListOf<String>()
        val observations = object : PresenceObservations {
            override val available = true

            override fun associationIds() = listOf("5", "7")

            override fun observe(associationId: String, observe: Boolean) {
                calls += "${if (observe) "+" else "-"}$associationId"
            }
        }
        val bound = MutableStateFlow<BoundRadio?>(associated)
        val preferred = MutableStateFlow(ReconnectStrategy.Presence)
        val scope = CoroutineScope(Dispatchers.Unconfined)
        RadioPresence(observations, bound, preferred, scope)
        assertEquals(listOf("-5", "+7"), calls)
        calls.clear()
        // Disconnect.
        bound.value = associated.copy(autoConnect = false)
        assertEquals(listOf("-5", "-7"), calls)
        calls.clear()
        // Connect again, then the Developer switch to Waiting.
        bound.value = associated
        preferred.value = ReconnectStrategy.Waiting
        assertEquals(listOf("-5", "+7", "-5", "-7"), calls)
        scope.cancel()
    }

    // endregion
}
