package com.voria.umsh.services.location

import java.util.Collections
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.emitAll
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.onSubscription
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** A source driven by the test: which readings it was asked for, and whether it is listening. */
class FakeLocationSource(grant: LocationGrant = LocationGrant.Precise, inUse: Boolean = true) : PhoneLocationSource {
    override val grant = MutableStateFlow(grant)
    override val inUse = MutableStateFlow(inUse)
    val asked: MutableList<Pair<LocationGrant, Double>> = Collections.synchronizedList(mutableListOf())
    val readings = MutableSharedFlow<PhoneFix>()

    @Volatile
    var listening = 0
        private set

    override fun refresh() = Unit

    override fun fixes(grant: LocationGrant, cellMeters: Double): Flow<PhoneFix> = flow {
        asked += grant to cellMeters
        var counted = false
        try {
            // Counted once subscribed, so a reading the test emits next is not missed.
            emitAll(
                readings.onSubscription {
                    counted = true
                    listening++
                },
            )
        } finally {
            if (counted) listening--
        }
    }

    /** What a one-shot read answers: none unless a test sets one. */
    @Volatile
    var current: PhoneFix? = null

    override suspend fun currentFix(grant: LocationGrant): PhoneFix? = current
}

/** Which readings reach the core, by sharing, grant and whether the app is in use (§3.8, §7.6). */
class LocationRelayTest {
    private val sizes = SharedPrecision.core
    private val fix = PhoneFix(47.6, -122.3, 12.0, approximate = false)

    /** Until [done], within a second: the relay runs on its own. */
    private suspend fun until(done: () -> Boolean) = withTimeout(1_000) {
        while (!done()) delay(5)
    }

    private class Run(val precision: MutableStateFlow<UByte?>, val delivered: MutableList<PhoneFix?>)

    private fun relay(source: FakeLocationSource, precision: UByte?, body: suspend Run.() -> Unit) = runBlocking<Unit> {
        val shared = MutableStateFlow(precision)
        val delivered = Collections.synchronizedList(mutableListOf<PhoneFix?>())
        val job = launch(Dispatchers.Unconfined, start = CoroutineStart.UNDISPATCHED) {
            LocationRelay(combine(shared, source.grant) { precision, grant -> precision to grant }, source, sizes) {
                delivered += it
            }.run()
        }
        Run(shared, delivered).body()
        job.cancel()
    }

    @Test
    fun notSharingReadsNothing() {
        val source = FakeLocationSource()
        relay(source, precision = null) {
            assertEquals(0, source.listening)
            assertTrue(delivered.isEmpty())
        }
        assertTrue(source.asked.isEmpty())
    }

    @Test
    fun sharingReadsToTheCellAndDelivers() {
        val source = FakeLocationSource()
        relay(source, precision = 5u) {
            until { source.listening == 1 }
            source.readings.emit(fix)
            until { delivered.isNotEmpty() }
            assertEquals(listOf<PhoneFix?>(fix), delivered.toList())
            // A new precision reads again, to its own cell.
            precision.value = 3u
            until { source.asked.size == 2 && source.listening == 1 }
            assertEquals(listOf(LocationGrant.Precise to sizes.cellMeters(5u)!!, LocationGrant.Precise to sizes.cellMeters(3u)!!), source.asked.toList())
            assertEquals(1, source.listening)
            // Turned off: listening stops; the core drops the position with the policy.
            precision.value = null
            until { source.listening == 0 }
            assertEquals(0, source.listening)
            assertEquals(listOf<PhoneFix?>(fix), delivered.toList())
        }
    }

    @Test
    fun stoppedKeepsTheLastPosition() {
        val source = FakeLocationSource()
        relay(source, precision = 5u) {
            until { source.listening == 1 }
            source.readings.emit(fix)
            until { delivered.isNotEmpty() }
            source.inUse.value = false
            until { source.listening == 0 }
            assertEquals(0, source.listening)
            // Nothing withdrawn: the core keeps sharing the last position (D9).
            assertEquals(listOf<PhoneFix?>(fix), delivered.toList())
            source.inUse.value = true
            until { source.listening == 1 }
            assertEquals(1, source.listening)
        }
    }

    @Test
    fun noGrantWithdrawsAndAGrantResumes() {
        val source = FakeLocationSource()
        relay(source, precision = 5u) {
            until { source.listening == 1 }
            source.readings.emit(fix)
            until { delivered.isNotEmpty() }
            source.grant.value = LocationGrant.None
            until { delivered.size == 2 }
            assertEquals(0, source.listening)
            assertEquals(listOf(fix, null), delivered.toList())
            // Allowed again: readings resume by themselves, approximate here.
            source.grant.value = LocationGrant.Approximate
            until { source.listening == 1 }
            assertEquals(1, source.listening)
            assertEquals(LocationGrant.Approximate, source.asked.last().first)
        }
    }

    @Test
    fun refusedFromTheStartSharesNothing() {
        val source = FakeLocationSource(grant = LocationGrant.None)
        relay(source, precision = 5u) {
            until { delivered.isNotEmpty() }
            assertEquals(0, source.listening)
            assertEquals(listOf<PhoneFix?>(null), delivered.toList())
        }
    }
}
