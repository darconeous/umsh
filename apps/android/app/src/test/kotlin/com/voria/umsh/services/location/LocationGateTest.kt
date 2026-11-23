package com.voria.umsh.services.location

import com.voria.umsh.core.MobileAppPolicyRecord
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test

/** What reaches the core for Share location, and in what order (§3.8, §7.6). */
class LocationGateTest {
    private val sizes = SharedPrecision.core

    private val policy = MobileAppPolicyRecord(
        advertIntervalSeconds = 3_600u,
        beaconIntervalSeconds = 0u,
        discoverable = true,
        floodHops = 10u,
        beaconFloodHops = 5u,
        locationPrecision = null,
        testMessageAlerts = false,
    )
    private val precise = PhoneFix(47.6, -122.3, 12.0, approximate = false)
    private val approximate = PhoneFix(47.61, -122.29, 2_000.0, approximate = true)

    /** The core's calls, in order. */
    private class Recorder : CoreSettingsSink {
        val calls = mutableListOf<Any?>()

        override suspend fun setPolicy(policy: MobileAppPolicyRecord) {
            calls += policy.locationPrecision ?: "off"
        }

        override suspend fun setLocation(fix: PhoneFix?) {
            calls += fix
        }
    }

    private fun gate(body: suspend LocationGate.(Recorder) -> Unit) = runBlocking {
        val core = Recorder()
        LocationGate(core, sizes).body(core)
    }

    private fun sharing(precision: UByte?) = policy.copy(locationPrecision = precision)

    @Test
    fun readingsFollowWhatTheCoreWasGiven() = gate { core ->
        push(sharing(5u), LocationGrant.Precise)
        // The relay reads for the pushed precision, not the stored one.
        assertEquals(5.toUByte() to LocationGrant.Precise, shared.first())
        deliver(precise)
        assertEquals(listOf<Any?>(5.toUByte(), precise), core.calls)
    }

    /** Turned off, a reading still in flight is neither shared nor kept for the next time. */
    @Test
    fun aLateReadingIsNotSharedLater() = gate { core ->
        push(sharing(5u), LocationGrant.Precise)
        deliver(precise)
        push(sharing(null), LocationGrant.Precise)
        deliver(precise.copy(latitudeDegrees = 1.0))
        push(sharing(5u), LocationGrant.Precise)
        assertEquals(listOf<Any?>(5.toUByte(), precise, "off", 5.toUByte()), core.calls)
    }

    @Test
    fun anApproximateReadingIsWithdrawnBeforeAFinerPrecision() = gate { core ->
        push(sharing(3u), LocationGrant.Approximate)
        deliver(approximate)
        push(sharing(5u), LocationGrant.Precise)
        assertEquals(listOf<Any?>(3.toUByte(), approximate, null, 5.toUByte()), core.calls)
    }

    @Test
    fun anApproximateReadingIsDroppedUnderAFinerPrecision() = gate { core ->
        push(sharing(5u), LocationGrant.Precise)
        deliver(approximate)
        deliver(precise)
        assertEquals(listOf<Any?>(5.toUByte(), precise), core.calls)
    }

    /** A grant change that leaves the policy as it was is not pushed again; the relay reads under the new grant. */
    @Test
    fun aGrantChangeAloneReachesOnlyTheRelay() = gate { core ->
        push(sharing(3u), LocationGrant.Precise)
        deliver(precise)
        push(sharing(3u), LocationGrant.Approximate)
        assertEquals(3.toUByte() to LocationGrant.Approximate, shared.first())
        deliver(approximate)
        assertEquals(listOf<Any?>(3.toUByte(), precise, approximate), core.calls)
    }

    @Test
    fun refusedThenApproximateShares() = gate { core ->
        push(sharing(5u), LocationGrant.None)
        deliver(null)
        push(sharing(3u), LocationGrant.Approximate)
        deliver(approximate)
        assertEquals(listOf<Any?>(5.toUByte(), null, 3.toUByte(), approximate), core.calls)
    }
}
