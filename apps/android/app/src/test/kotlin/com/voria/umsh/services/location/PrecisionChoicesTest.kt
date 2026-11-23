package com.voria.umsh.services.location

import android.Manifest
import com.voria.umsh.core.MobileAppPolicyRecord
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The sizes on offer and the precision the core is given, by grant (§3.8, the core's real cell sizes). */
class PrecisionChoicesTest {
    private val sizes = SharedPrecision.core

    @Test
    fun theSevenSizesTheEncodingAllows() {
        assertEquals((1..7).map { it.toUByte() }, sizes.sizes.map { it.precision })
        // Coarsest first: about 2,505 km down to about 15 cm.
        assertEquals(2_504_700.0, sizes.sizes.first().meters, 1.0)
        assertEquals(0.149, sizes.sizes.last().meters, 0.001)
    }

    @Test
    fun approximateStopsAtAbout10Km() {
        assertEquals(3.toUByte(), sizes.approximateCeiling)
        assertEquals(9_784.0, sizes.cellMeters(3u)!!, 1.0)
        assertEquals(
            listOf(true, true, true, false, false, false, false),
            sizes.sizes.map { sizes.allows(it.precision, LocationGrant.Approximate) },
        )
        // Precise, and no grant at all (nothing is read, so nothing is limited), offer every size.
        assertTrue(sizes.sizes.all { sizes.allows(it.precision, LocationGrant.Precise) })
        assertTrue(sizes.sizes.all { sizes.allows(it.precision, LocationGrant.None) })
    }

    @Test
    fun theChoiceIsClampedOnlyUnderApproximate() {
        assertEquals(3.toUByte(), sizes.effective(5u, LocationGrant.Approximate))
        assertEquals(2.toUByte(), sizes.effective(2u, LocationGrant.Approximate))
        assertEquals(3.toUByte(), sizes.effective(3u, LocationGrant.Approximate))
        assertEquals(5.toUByte(), sizes.effective(5u, LocationGrant.Precise))
        assertEquals(7.toUByte(), sizes.effective(7u, LocationGrant.None))
        assertNull(sizes.effective(null, LocationGrant.Approximate))
    }

    @Test
    fun thePolicyKeepsEverythingElse() {
        val stored = MobileAppPolicyRecord(
            advertIntervalSeconds = 3_600u,
            beaconIntervalSeconds = 0u,
            discoverable = true,
            floodHops = 10u,
            beaconFloodHops = 5u,
            locationPrecision = 5u,
            testMessageAlerts = false,
        )
        val clamped = sizes.effective(stored, LocationGrant.Approximate)
        assertEquals(stored.copy(locationPrecision = 3u), clamped)
        // Unchanged, the same record: nothing is pushed twice.
        assertSame(stored, sizes.effective(stored, LocationGrant.Precise))
        assertNull(sizes.effective(stored.copy(locationPrecision = null), LocationGrant.Approximate).locationPrecision)
    }

    @Test
    fun aRequestsAnswerAsAGrant() {
        val fine = Manifest.permission.ACCESS_FINE_LOCATION
        val coarse = Manifest.permission.ACCESS_COARSE_LOCATION
        assertEquals(LocationGrant.Precise, LocationPermission.answered(mapOf(fine to true, coarse to true)))
        assertEquals(LocationGrant.Approximate, LocationPermission.answered(mapOf(fine to false, coarse to true)))
        assertEquals(LocationGrant.None, LocationPermission.answered(mapOf(fine to false, coarse to false)))
        assertEquals(LocationGrant.None, LocationPermission.answered(emptyMap()))
        assertFalse(LocationPermission.answered(mapOf(coarse to true)) == LocationGrant.Precise)
    }
}
