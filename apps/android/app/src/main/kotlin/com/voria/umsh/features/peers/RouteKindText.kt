package com.voria.umsh.features.peers

import androidx.annotation.PluralsRes
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import com.voria.umsh.R
import com.voria.umsh.models.RouteKind
import com.voria.umsh.models.RouteState
import com.voria.umsh.models.RouteSummary

/** A resource to show: a plain string, or a counted one. */
sealed interface RouteText {
    data class Plain(@param:StringRes val id: Int) : RouteText

    data class Counted(@param:PluralsRes val id: Int, val count: Int) : RouteText
}

/**
 * The words for the core's typed route kind (Part E 6: the core sends no
 * display text): the glance strip's word or two, the Route page's Next
 * send, and a ping reply's hops. Pure, so the choices are tested on the JVM.
 */
object RouteKindText {
    /** The strip's "Direct", "3 hops", "Flood", "Manual"; null while unread, unavailable, or a source route of no known length. */
    fun brief(route: RouteState): RouteText? {
        val loaded = (route as? RouteState.Loaded)?.route ?: return null
        if (loaded.isHeld) return RouteText.Plain(R.string.route_brief_manual)
        return when (loaded.kind) {
            RouteKind.Unknown, RouteKind.Flood -> RouteText.Plain(R.string.route_brief_flood)
            RouteKind.Direct -> RouteText.Plain(R.string.route_brief_direct)
            RouteKind.Source -> when {
                loaded.isDirect -> RouteText.Plain(R.string.route_brief_direct)
                else -> loaded.hopCount?.let { RouteText.Counted(R.plurals.route_hops, it) }
            }
        }
    }

    /**
     * Next send (`ping-route.svg` 4–5): "Source route", "Manual · 4 hops",
     * and the direct, flood and not-learned forms; "Unavailable" when there
     * is no session to ask.
     */
    fun nextSend(route: RouteState): RouteText? = when (route) {
        RouteState.Loading -> null
        RouteState.Unavailable -> RouteText.Plain(R.string.route_kind_unavailable)
        is RouteState.Loaded -> nextSend(route.route)
    }

    fun nextSend(route: RouteSummary): RouteText {
        if (route.isHeld) {
            route.heldFloodFromStart?.let { return RouteText.Counted(R.plurals.route_kind_manual_flood, it) }
            if (route.hints.isEmpty()) return RouteText.Plain(R.string.route_kind_manual_direct)
            return RouteText.Counted(R.plurals.route_kind_manual_hops, route.hopCount ?: (route.hints.size + 1))
        }
        return when (route.kind) {
            RouteKind.Unknown -> RouteText.Plain(R.string.route_kind_unknown)
            RouteKind.Direct -> RouteText.Plain(R.string.route_brief_direct)
            RouteKind.Source -> RouteText.Plain(if (route.isDirect) R.string.route_brief_direct else R.string.route_kind_source)
            RouteKind.Flood -> RouteText.Plain(R.string.route_brief_flood)
        }
    }

    /** The hops a ping reply crossed: "Direct" for one, else "3 hops"; null when it did not say. */
    fun replyHops(hopCount: Int?): RouteText? = when (hopCount) {
        null -> null
        1 -> RouteText.Plain(R.string.route_brief_direct)
        else -> RouteText.Counted(R.plurals.route_hops, hopCount)
    }

    /** A flood allowance: "Off", or "1 hop". */
    fun flood(hops: Int): RouteText =
        if (hops == 0) RouteText.Plain(R.string.route_flood_off) else RouteText.Counted(R.plurals.route_hops, hops)
}

@Composable
fun RouteText.resolve(): String = when (this) {
    is RouteText.Plain -> stringResource(id)
    is RouteText.Counted -> pluralStringResource(id, count, count)
}
