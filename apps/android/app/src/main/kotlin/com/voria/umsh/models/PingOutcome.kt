package com.voria.umsh.models

import com.voria.umsh.services.mobilecore.ReasonText

/** How one repeater heard the node a step farther from this phone; both null over a bridge. */
data class LegSignal(val rssiDbm: Int?, val snrCentibels: Int?) {
    /** Measured nothing: the leg crossed a link that is not radio. */
    val isBridged: Boolean get() = rssiDbm == null && snrCentibels == null
}

/** A ping's answer (the core's `MobileAppPingReplyRecord`). */
data class PingReply(
    val roundTripMs: Long?,
    /** Radio links the reply crossed, the last one into this phone among them: a direct reply is one. */
    val hopCount: Int?,
    /** The repeaters it named, nearest this phone first. */
    val routeHints: List<RepeaterHint>,
    /** How each of [routeHints] heard the node one step farther from this phone, entry for entry. */
    val traceSignal: List<LegSignal>,
    /** This phone's radio's reading of the last leg. */
    val ownSignal: LegSignal,
    /** Only the ping's retry was answered: the first attempt or its answer was lost. */
    val viaRouteRetry: Boolean,
    /** Repeaters crossed that [routeHints] does not name; null when the hop count is unknown. */
    val unnamedHops: Int?,
)

/** How a ping ended. */
sealed interface PingOutcome {
    data class Reply(val reply: PingReply) : PingOutcome

    /** Nothing came back within the core's wait. */
    data object TimedOut : PingOutcome

    /** A newer ping to the same node replaced it. */
    data object Canceled : PingOutcome

    /** It could not be sent: no radio, the core not running, the radio not this phone's. */
    data class Unavailable(val reason: ReasonText, val error: Throwable) : PingOutcome
}
