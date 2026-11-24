package com.voria.umsh.features.peers

import com.voria.umsh.designsystem.RailLeg
import com.voria.umsh.designsystem.RailStop
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.PingReply
import com.voria.umsh.models.RepeaterHint
import com.voria.umsh.models.RouteKind
import com.voria.umsh.models.RouteState
import com.voria.umsh.models.RouteSummary

/** A path to draw: its stops (this phone first, the peer last) and the legs between. */
data class PathLayout(val stops: List<RailStop>, val legs: List<RailLeg>, val tentative: Boolean = false) {
    /** The repeaters among [stops], in send order. */
    val repeaters: List<RepeaterHint> get() = stops.filterIsInstance<RailStop.Repeater>().map { it.hint }

    /** The same path, each repeater named by [named] (one entry per repeater, in order). */
    fun named(named: List<PeerSummary?>): PathLayout {
        var index = 0
        return copy(
            stops = stops.map { stop ->
                if (stop is RailStop.Repeater) stop.copy(named = named.getOrNull(index++)) else stop
            },
        )
    }

    /** Whether any repeater's name was guessed from its hint: the ambiguity footer's cue. */
    val hasGuessedNames: Boolean get() = stops.any { it is RailStop.Repeater && it.named != null }
}

private fun repeaterStops(hints: List<RepeaterHint>, enteredByHand: Boolean = false): List<RailStop.Repeater> =
    hints.mapIndexed { index, hint ->
        RailStop.Repeater(hint, preceding = hints.take(index).map { it.octets }, enteredByHand = enteredByHand)
    }

/** A ping reply's path (iOS `PingPath`). */
object PingPath {
    /**
     * The reply's repeaters run nearest this phone first. The leg into this
     * phone is its own radio's reading; each leg after is how the repeater
     * at its near end heard the node at its far end, entry for entry. A
     * flooded reply counts repeaters it does not name: as the core counts
     * them, one dashed stretch before the peer, rather than a direct link.
     * A reply with no hop count crossed a stretch nobody traced or counted.
     */
    fun of(reply: PingReply): PathLayout {
        val hints = reply.routeHints
        val stops = listOf(RailStop.Phone(null)) + repeaterStops(hints) + RailStop.Peer
        val legs = mutableListOf<RailLeg>(if (reply.ownSignal.isBridged) RailLeg.Plain else RailLeg.Reading(reply.ownSignal))
        hints.indices.forEach { index ->
            legs += reply.traceSignal.getOrNull(index)?.let { RailLeg.Reading(it) } ?: RailLeg.Plain
        }
        when (val unnamed = reply.unnamedHops) {
            null -> legs[legs.lastIndex] = RailLeg.Unknown
            0 -> Unit
            else -> legs[legs.lastIndex] = RailLeg.Unnamed(unnamed)
        }
        return PathLayout(stops, legs)
    }

    /** Before an answer, or with none: the phone and the peer, a dashed leg between, [broken] when nothing came. */
    fun unanswered(broken: Boolean): PathLayout =
        PathLayout(listOf(RailStop.Phone(null), RailStop.Peer), listOf(if (broken) RailLeg.Broken else RailLeg.Pending))
}

/** A cached route's path (iOS `RouteScreen.legs`). */
object RouteLegs {
    fun of(route: RouteState, radioName: String?): PathLayout = when (route) {
        RouteState.Loading, RouteState.Unavailable ->
            PathLayout(listOf(RailStop.Phone(radioName), RailStop.Peer), listOf(RailLeg.Pending), tentative = true)
        is RouteState.Loaded -> of(route.route, radioName)
    }

    /**
     * Numbered in send order. A flood names no repeaters, so its one leg is
     * a dashed stretch for the hops it spent; nothing learned is a dashed
     * leg. A held path's hops are its own: one that names no known node
     * could only have been typed in ([named] marks it, once names are in).
     */
    fun of(route: RouteSummary, radioName: String?): PathLayout {
        val stops = listOf(RailStop.Phone(radioName)) + repeaterStops(route.hints, enteredByHand = route.isHeld) + RailStop.Peer
        val legs: List<RailLeg> = when {
            route.kind == RouteKind.Unknown && !route.isHeld -> listOf(RailLeg.Pending)
            route.kind == RouteKind.Flood && route.hints.isEmpty() && !route.isHeld ->
                listOf(route.floodHops?.takeIf { it > 0 }?.let { RailLeg.Unnamed(it) } ?: RailLeg.Pending)
            else -> (1..route.hints.size + 1).map { RailLeg.Numbered(it) }
        }
        return PathLayout(stops, legs, tentative = route.kind == RouteKind.Unknown && !route.isHeld)
    }
}
