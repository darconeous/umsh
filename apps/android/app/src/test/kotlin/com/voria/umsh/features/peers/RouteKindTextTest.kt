package com.voria.umsh.features.peers

import com.voria.umsh.R
import com.voria.umsh.models.Octets
import com.voria.umsh.models.RepeaterHint
import com.voria.umsh.models.RouteKind
import com.voria.umsh.models.RouteState
import com.voria.umsh.models.RouteSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The core's typed route kind to resources (iOS `RoutePresentation`, with the boards' Manual · n hops). */
class RouteKindTextTest {
    private val hint = RepeaterHint(Octets(byteArrayOf(1, 2)), "9v*")

    private fun route(
        kind: RouteKind,
        hints: Int = 0,
        hopCount: Int? = null,
        held: Boolean = false,
        heldFlood: Int? = null,
    ) = RouteSummary(
        kind = kind,
        hints = List(hints) { hint },
        hopCount = hopCount,
        floodHops = null,
        holdRemainingMs = if (held) 1L else null,
        holdFloodHops = heldFlood,
        confirmedAgeMs = null,
    )

    private fun loaded(route: RouteSummary) = RouteState.Loaded(route)

    @Test
    fun nextSendForLearnedRoutes() {
        assertEquals(RouteText.Plain(R.string.route_kind_source), RouteKindText.nextSend(route(RouteKind.Source, hints = 2, hopCount = 3)))
        assertEquals(RouteText.Plain(R.string.route_brief_direct), RouteKindText.nextSend(route(RouteKind.Source)))
        assertEquals(RouteText.Plain(R.string.route_brief_direct), RouteKindText.nextSend(route(RouteKind.Direct)))
        assertEquals(RouteText.Plain(R.string.route_brief_flood), RouteKindText.nextSend(route(RouteKind.Flood)))
        assertEquals(RouteText.Plain(R.string.route_kind_unknown), RouteKindText.nextSend(route(RouteKind.Unknown)))
        assertEquals(RouteText.Plain(R.string.route_kind_unavailable), RouteKindText.nextSend(RouteState.Unavailable))
        assertNull(RouteKindText.nextSend(RouteState.Loading))
    }

    /** `ping-route.svg` 5: "Manual · 4 hops"; floods from the start and a held direct path have their own words. */
    @Test
    fun nextSendForHeldPaths() {
        assertEquals(
            RouteText.Counted(R.plurals.route_kind_manual_hops, 4),
            RouteKindText.nextSend(route(RouteKind.Source, hints = 3, hopCount = 4, held = true, heldFlood = 1)),
        )
        assertEquals(
            RouteText.Counted(R.plurals.route_kind_manual_hops, 3),
            RouteKindText.nextSend(route(RouteKind.Source, hints = 2, held = true)),
        )
        assertEquals(
            RouteText.Counted(R.plurals.route_kind_manual_flood, 2),
            RouteKindText.nextSend(route(RouteKind.Flood, held = true, heldFlood = 2)),
        )
        assertEquals(
            RouteText.Plain(R.string.route_kind_manual_direct),
            RouteKindText.nextSend(route(RouteKind.Direct, held = true, heldFlood = 0)),
        )
    }

    @Test
    fun briefForTheStrip() {
        assertEquals(RouteText.Counted(R.plurals.route_hops, 3), RouteKindText.brief(loaded(route(RouteKind.Source, hints = 2, hopCount = 3))))
        assertEquals(RouteText.Plain(R.string.route_brief_direct), RouteKindText.brief(loaded(route(RouteKind.Source))))
        assertEquals(RouteText.Plain(R.string.route_brief_flood), RouteKindText.brief(loaded(route(RouteKind.Unknown))))
        assertEquals(RouteText.Plain(R.string.route_brief_manual), RouteKindText.brief(loaded(route(RouteKind.Source, hints = 1, held = true))))
        assertNull(RouteKindText.brief(loaded(route(RouteKind.Source, hints = 2))))
        assertNull(RouteKindText.brief(RouteState.Unavailable))
        assertNull(RouteKindText.brief(RouteState.Loading))
    }

    @Test
    fun replyHopsAndFlood() {
        assertEquals(RouteText.Plain(R.string.route_brief_direct), RouteKindText.replyHops(1))
        assertEquals(RouteText.Counted(R.plurals.route_hops, 3), RouteKindText.replyHops(3))
        assertNull(RouteKindText.replyHops(null))
        assertEquals(RouteText.Plain(R.string.route_flood_off), RouteKindText.flood(0))
        assertEquals(RouteText.Counted(R.plurals.route_hops, 1), RouteKindText.flood(1))
    }
}
