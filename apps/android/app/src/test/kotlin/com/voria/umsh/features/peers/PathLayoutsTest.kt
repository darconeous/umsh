package com.voria.umsh.features.peers

import com.voria.umsh.designsystem.RailLeg
import com.voria.umsh.designsystem.RailStop
import com.voria.umsh.features.conversations.ListFixtures
import com.voria.umsh.models.LegSignal
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PingReply
import com.voria.umsh.models.RepeaterHint
import com.voria.umsh.models.RouteKind
import com.voria.umsh.models.RouteState
import com.voria.umsh.models.RouteSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** A ping reply's rail (iOS `PingPath.init(reply:)`) and a route's (iOS `RouteScreen.legs`). */
class PathLayoutsTest {
    private val spencer = RepeaterHint(Octets(byteArrayOf(0x11, 0x22)), "9v*")
    private val seven = RepeaterHint(Octets(byteArrayOf(0x33, 0x44)), "7N*")
    private val own = LegSignal(-97, 65)

    private fun reply(
        hints: List<RepeaterHint> = listOf(spencer, seven),
        trace: List<LegSignal> = listOf(LegSignal(-108, -25), LegSignal(-101, 80)),
        ownSignal: LegSignal = own,
        unnamed: Int? = 0,
        hops: Int? = 3,
    ) = PingReply(800, hops, hints, trace, ownSignal, viaRouteRetry = false, unnamedHops = unnamed)

    private fun route(kind: RouteKind, hints: List<RepeaterHint> = emptyList(), flood: Int? = null, held: Boolean = false, heldFlood: Int? = null) =
        RouteSummary(
            kind = kind,
            hints = hints,
            hopCount = if (kind == RouteKind.Source) hints.size + 1 else null,
            floodHops = flood,
            holdRemainingMs = if (held) 60_000L else null,
            holdFloodHops = heldFlood,
            confirmedAgeMs = null,
        )

    // --- Ping -----------------------------------------------------------

    /** `ping-route.svg` 1: the phone's own reading first, then each repeater's, entry for entry. */
    @Test
    fun aTracedReplyReadsEachLegFromItsNearEnd() {
        val layout = PingPath.of(reply())
        assertEquals(4, layout.stops.size)
        assertTrue(layout.stops.first() is RailStop.Phone)
        assertEquals(RailStop.Peer, layout.stops.last())
        val first = layout.stops[1] as RailStop.Repeater
        val second = layout.stops[2] as RailStop.Repeater
        assertEquals(spencer, first.hint)
        assertEquals(emptyList<Octets>(), first.preceding)
        assertEquals(listOf(spencer.octets), second.preceding)
        assertEquals(
            listOf(RailLeg.Reading(own), RailLeg.Reading(LegSignal(-108, -25)), RailLeg.Reading(LegSignal(-101, 80))),
            layout.legs,
        )
    }

    @Test
    fun aMissingReadingIsAPlainLegAndNoReadingIntoThePhoneToo() {
        val layout = PingPath.of(reply(trace = listOf(LegSignal(-108, -25)), ownSignal = LegSignal(null, null)))
        assertEquals(listOf(RailLeg.Plain, RailLeg.Reading(LegSignal(-108, -25)), RailLeg.Plain), layout.legs)
    }

    /** A bridge's entry measures nothing: still a reading, drawn "Bridged". */
    @Test
    fun aBridgedTraceEntryStaysAReading() {
        val bridged = LegSignal(null, null)
        val layout = PingPath.of(reply(trace = listOf(bridged, LegSignal(-101, 80))))
        assertEquals(RailLeg.Reading(bridged), layout.legs[1])
        assertTrue(bridged.isBridged)
    }

    @Test
    fun repeatersCountedButNotNamedAreOneDashedStretchBeforeThePeer() {
        val layout = PingPath.of(reply(hints = emptyList(), trace = emptyList(), unnamed = 2, hops = 3))
        assertEquals(listOf(RailStop.Phone(null), RailStop.Peer), layout.stops)
        assertEquals(listOf(RailLeg.Unnamed(2)), layout.legs)
    }

    @Test
    fun noHopCountIsAnUnknownStretch() {
        val layout = PingPath.of(reply(hints = listOf(spencer), trace = listOf(LegSignal(-108, -25)), unnamed = null, hops = null))
        assertEquals(listOf(RailLeg.Reading(own), RailLeg.Unknown), layout.legs)
    }

    @Test
    fun waitingIsPendingAndNoReplyIsBroken() {
        assertEquals(listOf(RailLeg.Pending), PingPath.unanswered(broken = false).legs)
        assertEquals(listOf(RailLeg.Broken), PingPath.unanswered(broken = true).legs)
    }

    @Test
    fun namesFillTheRepeatersInOrderAndCueTheFooter() {
        val tallac = ListFixtures.peer("Tr4d", "Spencer Butte", role = com.voria.umsh.models.PeerRole.Repeater)
        val layout = PingPath.of(reply())
        assertFalse(layout.hasGuessedNames)
        val named = layout.named(listOf(tallac, null))
        assertEquals(tallac, (named.stops[1] as RailStop.Repeater).named)
        assertEquals(null, (named.stops[2] as RailStop.Repeater).named)
        assertTrue(named.hasGuessedNames)
    }

    // --- Route ----------------------------------------------------------

    /** `ping-route.svg` 4: numbered in send order, the radio under This phone. */
    @Test
    fun aSourceRouteIsNumberedByLeg() {
        val layout = RouteLegs.of(route(RouteKind.Source, listOf(spencer, seven)), "T1000-E")
        assertEquals(RailStop.Phone("T1000-E"), layout.stops.first())
        assertEquals(listOf(RailLeg.Numbered(1), RailLeg.Numbered(2), RailLeg.Numbered(3)), layout.legs)
        assertFalse(layout.tentative)
        assertFalse((layout.stops[1] as RailStop.Repeater).enteredByHand)
    }

    @Test
    fun aFloodIsOneDashedStretchForItsHopsAndNothingLearnedIsPending() {
        assertEquals(listOf(RailLeg.Unnamed(2)), RouteLegs.of(route(RouteKind.Flood, flood = 2), null).legs)
        assertEquals(listOf(RailLeg.Pending), RouteLegs.of(route(RouteKind.Flood, flood = 0), null).legs)
        val unknown = RouteLegs.of(route(RouteKind.Unknown), null)
        assertEquals(listOf(RailLeg.Pending), unknown.legs)
        assertTrue(unknown.tentative)
        assertTrue(RouteLegs.of(RouteState.Unavailable, null).tentative)
    }

    /** `ping-route.svg` 5: a held path's hops are its own; one naming no known node reads "Entered by hand". */
    @Test
    fun aHeldPathsHopsAreMarkedAsItsOwn() {
        val layout = RouteLegs.of(route(RouteKind.Source, listOf(spencer, seven), held = true, heldFlood = 1), null)
        assertEquals(3, layout.legs.size)
        assertTrue(layout.stops.filterIsInstance<RailStop.Repeater>().all { it.enteredByHand })
    }
}
