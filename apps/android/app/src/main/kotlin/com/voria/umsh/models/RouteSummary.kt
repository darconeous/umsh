package com.voria.umsh.models

/** How the next frame to a peer goes. */
enum class RouteKind { Unknown, Direct, Source, Flood }

/** A two-byte repeater hint and the text the core rendered for it. */
data class RepeaterHint(val octets: Octets, val text: String)

/** The way to a peer, as the session knows it now (the core's `MobileAppRouteRecord`). */
data class RouteSummary(
    val kind: RouteKind,
    /** The path's repeaters, in send order. */
    val hints: List<RepeaterHint>,
    val hopCount: Int?,
    val floodHops: Int?,
    /** How long a held path is held for yet; null when nothing is held. */
    val holdRemainingMs: Long?,
    val holdFloodHops: Int?,
    /** How long ago the route was last acknowledged. */
    val confirmedAgeMs: Long?,
    /** Two-octet region codes a flood route was learned in. */
    val floodRegions: List<Octets> = emptyList(),
    /** When the hold ends, wall-clock milliseconds, from when the route was read; null when nothing is held. */
    val holdUntilMs: Long? = null,
    /** When the route was last acknowledged, wall-clock milliseconds, from when it was read. */
    val confirmedAtMs: Long? = null,
    /** Where an ask for identities near the peer can be steered; null when there is no honest way. */
    val discoveryVantage: DiscoveryVantage? = null,
    /** Acknowledgments that came back by flood while a path was held. */
    val fallbackAcks: Int = 0,
    /** The route the session learned while a path was held. */
    val candidate: RouteCandidate? = null,
) {
    /** A path chosen by hand is held. */
    val isHeld: Boolean get() = holdRemainingMs != null

    /** Heard with no repeater between: a direct route, or a source route naming none. */
    val isDirect: Boolean get() = kind == RouteKind.Direct || (kind == RouteKind.Source && hints.isEmpty())

    /** How far a held path that names no repeaters floods from the start; null otherwise. */
    val heldFloodFromStart: Int?
        get() = holdFloodHops?.takeIf { isHeld && hints.isEmpty() && it > 0 }
}

/** A route the session learned while a path to the peer was held. */
data class RouteCandidate(
    val kind: RouteKind,
    /** Its repeaters, in send order. */
    val hints: List<RepeaterHint>,
    val hopCount: Int?,
)

/**
 * A path chosen by hand (the core's `MobileMeshExplicitPath`): repeaters
 * in send order, then how far the frame may flood past the last of them.
 * No repeaters is a direct path, flooding [floodHops] from the start.
 */
data class ManualPath(val hints: List<Octets>, val floodHops: Int)

/** What a peer's own advertisement says about forwarding (the core's `MobileRepeaterEvidence`). */
enum class RepeaterEvidence { Yes, Unknown, No }

/** Where a Discover ask can be steered to reach a peer's neighborhood (the core's record). */
data class DiscoveryVantage(
    /** The repeaters to steer through, in send order. Never empty. */
    val repeaters: List<RepeaterHint>,
    /** The ask ends at the peer; otherwise at the last of [repeaters]. */
    val landsAtPeer: Boolean,
    val evidence: RepeaterEvidence,
)

/** A peer page's route: being read, read, or not to be had (no radio, the core stopped). */
sealed interface RouteState {
    data object Loading : RouteState

    data class Loaded(val route: RouteSummary) : RouteState

    data object Unavailable : RouteState
}
