package com.voria.umsh.services.location

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** One reading of the phone's position: answered at once when there is none to be had. */
class PositionSourceTest {
    private val fix = PhoneFix(47.6, -122.3, 12.0, approximate = false)

    /**
     * Granted, with system location off: the one-shot read answers null at
     * once, never waiting out [PositionSource.WAIT_MS] on readings that
     * cannot come (the fake's continuous readings never emit).
     */
    @Test
    fun grantedWithLocationOffAnswersAtOnce() = runBlocking<Unit> {
        val location = FakeLocationSource(LocationGrant.Precise)
        val read = withTimeout(QUICK_MS) { PositionSource.of(location).readOnceIfGranted() }
        assertNull(read)
        assertTrue("continuous readings never asked for", location.asked.isEmpty())
    }

    @Test
    fun aCurrentFixIsTheReading() = runBlocking<Unit> {
        val location = FakeLocationSource(LocationGrant.Approximate).apply { current = fix }
        assertEquals(fix, withTimeout(QUICK_MS) { PositionSource.of(location).readOnceIfGranted() })
    }

    @Test
    fun noGrantReadsNothing() = runBlocking<Unit> {
        val location = FakeLocationSource(LocationGrant.None).apply { current = fix }
        assertNull(PositionSource.of(location).readOnceIfGranted())
    }

    private companion object {
        /** Well under [PositionSource.WAIT_MS]. */
        const val QUICK_MS = 1_000L
    }
}
