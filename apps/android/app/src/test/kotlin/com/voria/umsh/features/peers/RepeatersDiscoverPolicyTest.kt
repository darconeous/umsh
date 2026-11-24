package com.voria.umsh.features.peers

import com.voria.umsh.features.conversations.ListFixtures
import com.voria.umsh.models.AdvertisedIdentity
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.RepeaterListing
import com.voria.umsh.models.RepeaterNeighbor
import com.voria.umsh.models.SignatureState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Discover's window (iOS `DiscoverPeersView.results`), a neighbor's ages (iOS `PeerRepeaterNeighbor`), and the copied coordinates. */
class RepeatersDiscoverPolicyTest {
    private fun advertised(peer: PeerSummary, heardAtMs: Long?) = peer.copy(
        lastHeardAtMs = heardAtMs,
        advertised = AdvertisedIdentity(1, 0, true, peer.advertisedName, null, null, null, null, null, SignatureState.Valid),
    )

    private fun neighbor(minutes: Int?, latitude: Double? = null, longitude: Double? = null, precision: Int? = null) = RepeaterNeighbor(
        hint = Octets(byteArrayOf(0x8C.toByte(), 0x01)),
        hintText = "8C*",
        name = null,
        rssiDbm = -95,
        snrQuarterDb = 12,
        lastHeardMinutes = minutes,
        latitude = latitude,
        longitude = longitude,
        locationPrecision = precision,
        regionCodes = emptyList(),
        reportedAtMs = REPORTED,
        peerAddress = null,
    )

    @Test
    fun theWindowHoldsAdvertisedNodesHeardSinceItOpenedNewestFirst() {
        val opened = 1_000_000L
        val early = advertised(ListFixtures.peer("Mp", "Mt. Pisgah", address = "a"), opened - 1)
        val first = advertised(ListFixtures.peer("Mx", "Marmot", address = "b"), opened)
        val later = advertised(ListFixtures.peer("4B", "Trailhead gauge", address = "c"), opened + 5_000)
        val silent = ListFixtures.peer("Hx", address = "d").copy(lastHeardAtMs = opened + 9_000)
        val radio = advertised(ListFixtures.peer("Tr", "Trail radio", address = "e", companion = true), opened + 9_000)
        val never = advertised(ListFixtures.peer("Nn", "Never", address = "f"), null)
        val shown = DiscoverWindow.of(listOf(early, first, later, silent, radio, never), opened)
        assertEquals(listOf("c", "b"), shown.map { it.address })
    }

    @Test
    fun aNeighborsAgeIsMeasuredFromWhenTheRepeaterAnswered() {
        val fresh = neighbor(minutes = 4)
        assertEquals(REPORTED - 4 * MINUTE, fresh.lastHeardAtMs)
        assertFalse(fresh.heardLongerAgoThan(RepeaterNeighbor.STALE_AGE_MS, REPORTED))
        val old = neighbor(minutes = 7 * 60)
        assertTrue(old.heardLongerAgoThan(RepeaterNeighbor.STALE_AGE_MS, REPORTED))
        // Six hours later, even the fresh one has faded.
        assertTrue(fresh.heardLongerAgoThan(RepeaterNeighbor.STALE_AGE_MS, REPORTED + 6 * 60 * MINUTE))
        // The saturated figure is "long ago": no instant, and older than any age.
        val saturated = neighbor(minutes = RepeaterNeighbor.LAST_HEARD_SATURATED)
        assertNull(saturated.lastHeardAtMs)
        assertTrue(saturated.heardLongerAgoThan(RepeaterNeighbor.STALE_AGE_MS, REPORTED))
        // No figure at all is unknown, never faded.
        val unknown = neighbor(minutes = null)
        assertNull(unknown.lastHeardAtMs)
        assertFalse(unknown.heardLongerAgoThan(RepeaterNeighbor.STALE_AGE_MS, REPORTED + 100 * 60 * MINUTE))
    }

    @Test
    fun aListingWithACursorIsNotComplete() {
        assertFalse(RepeaterListing(listOf(neighbor(1)), 9, Octets(byteArrayOf(0, 1, 4)), REPORTED).isComplete)
        assertTrue(RepeaterListing(listOf(neighbor(1)), 1, null, REPORTED).isComplete)
    }

    @Test
    fun copiedCoordinatesCarryTheDigitsTheCellSupports() {
        // 11 m is about four decimals of a degree; no cell size, five.
        assertEquals(5, CoordinateDigits.of(null))
        assertEquals(4, CoordinateDigits.of(38.0))
        assertEquals(2, CoordinateDigits.of(2_000.0))
        assertEquals(7, CoordinateDigits.of(0.001))
        assertEquals(0, CoordinateDigits.of(500_000.0))
        assertEquals("44.05210, -123.08680", coordinateText(neighbor(1, 44.0521, -123.0868)))
        assertNull(coordinateText(neighbor(1)))
    }

    @Test
    fun theSeparationIsFromTheReportingRepeater() {
        val repeater = ListFixtures.peer("9v", "Spencer Butte").copy(
            advertised = AdvertisedIdentity(1, 0, true, null, 44.0, -123.0, null, null, null, SignatureState.Valid),
        )
        val distance = separation(neighbor(1, 44.1, -123.0), repeater)
        assertEquals(11_119.5, distance!!.meters, 5.0)
        assertNull(separation(neighbor(1, 44.1, -123.0), ListFixtures.peer("Hx")))
        assertNull(separation(neighbor(1), repeater))
    }

    private companion object {
        const val MINUTE = 60_000L
        const val REPORTED = 1_700_000_000_000L
    }
}
