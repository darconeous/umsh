package com.voria.umsh.features.peers.manualpath

import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.listSaver
import com.voria.umsh.core.MobileLimitsRecord
import com.voria.umsh.core.mobileLimits
import com.voria.umsh.models.ManualPath
import com.voria.umsh.models.Octets
import com.voria.umsh.models.RepeaterHint
import com.voria.umsh.models.RouteSummary

/**
 * The core's bounds and choices for a manual path (`mobile_limits()`): read
 * once, since they are constants, and handed in so a test can give its own.
 */
data class ManualPathLimits(
    /** Most repeaters a path names. */
    val maxRouteHints: Int,
    /** The Then flood stepper's top: Off up to this. */
    val maxFloodHops: Int,
    /** The flood allowance a new path starts with. */
    val newPathFloodHops: Int,
    /** How long a path can be held, shortest first. */
    val holdChoicesMs: List<Long>,
    /** The hold a new path starts with; one of [holdChoicesMs]. */
    val holdDefaultMs: Long,
) {
    companion object {
        fun of(record: MobileLimitsRecord) = ManualPathLimits(
            maxRouteHints = record.maxRouteHints.toInt(),
            maxFloodHops = record.maxFloodHops.toInt(),
            newPathFloodHops = record.manualPathFloodHops.toInt(),
            holdChoicesMs = record.manualPathHoldChoicesMs.map { it.toLong() },
            holdDefaultMs = record.manualPathHoldDefaultMs.toLong(),
        )

        /** The core's. */
        val core: ManualPathLimits by lazy { of(mobileLimits()) }
    }
}

/**
 * One repeater on a path being edited: its hint, the node it was picked as
 * when it came from a list ([node], an address), whether it was typed
 * ([typed]: by hand in the hint entry, or held already, which only typing
 * or a list could have made), and how the hop before heard it when it was
 * picked from that hop's neighbors.
 */
data class DraftHop(
    val hint: RepeaterHint,
    val node: String? = null,
    val typed: Boolean = false,
    val rssiDbm: Int? = null,
    val snrQuarterDb: Int? = null,
)

/**
 * A manual path being edited (`manual-path.svg` 1–2): its repeaters in send
 * order, how far the frame floods past the last of them (from the start,
 * when there are none), and how long it is to be held. Immutable; each edit
 * gives a new draft, and every edit keeps the core's bounds.
 */
data class ManualPathDraft(
    val hops: List<DraftHop>,
    val floodHops: Int,
    val holdMs: Long,
) {
    /** What would be held, or pinged along. */
    val path: ManualPath get() = ManualPath(hops.map { it.hint.octets }, floodHops)

    /** No room for another repeater. */
    fun isFull(limits: ManualPathLimits): Boolean = hops.size >= limits.maxRouteHints

    /** Whether a repeater with this two-byte hint is on the path already. */
    fun contains(hint: Octets): Boolean = hops.any { it.hint.octets == hint }

    /** [hop] at the end; unchanged when the path is full or already holds its hint. */
    fun adding(hop: DraftHop, limits: ManualPathLimits): ManualPathDraft =
        if (isFull(limits) || contains(hop.hint.octets)) this else copy(hops = hops + hop)

    fun removing(index: Int): ManualPathDraft =
        if (index !in hops.indices) this else copy(hops = hops.filterIndexed { at, _ -> at != index })

    /** The hop at [from] moved to [to], the others closing up around it. */
    fun moving(from: Int, to: Int): ManualPathDraft {
        if (from !in hops.indices || to !in hops.indices || from == to) return this
        val moved = hops.toMutableList()
        moved.add(to, moved.removeAt(from))
        return copy(hops = moved)
    }

    /** Then flood, held between Off and the core's most. */
    fun withFlood(hops: Int, limits: ManualPathLimits): ManualPathDraft = copy(floodHops = hops.coerceIn(0, limits.maxFloodHops))

    /** A hold among the core's choices; any other is ignored. */
    fun withHold(holdMs: Long, limits: ManualPathLimits): ManualPathDraft =
        if (holdMs in limits.holdChoicesMs) copy(holdMs = holdMs) else this

    companion object {
        /**
         * A draft from the route as the session knows it: its repeaters,
         * and, for a held path, its own flood allowance; a new one starts
         * at the core's. A held path's hops count as typed: a hand put each
         * there. The hold starts at the core's default.
         */
        fun seed(route: RouteSummary?, limits: ManualPathLimits): ManualPathDraft {
            val held = route?.isHeld == true
            val hops = route?.hints.orEmpty().take(limits.maxRouteHints).map { DraftHop(it, typed = held) }
            val flood = route?.holdFloodHops?.takeIf { held } ?: limits.newPathFloodHops
            return ManualPathDraft(hops, flood.coerceIn(0, limits.maxFloodHops), limits.holdDefaultMs)
        }

        /** Each field as a value a saved-state bundle holds, so a draft outlives the process. */
        val Saver: Saver<ManualPathDraft, Any> = listSaver(
            save = { draft ->
                buildList<Any> {
                    add(draft.floodHops)
                    add(draft.holdMs)
                    draft.hops.forEach { hop ->
                        add(hop.hint.octets.hex())
                        add(hop.hint.text)
                        add(hop.node ?: "")
                        add(hop.typed)
                        add(hop.rssiDbm ?: NONE)
                        add(hop.snrQuarterDb ?: NONE)
                    }
                }
            },
            restore = { saved ->
                val hops = saved.drop(2).chunked(HOP_FIELDS).map { fields ->
                    DraftHop(
                        hint = RepeaterHint(Octets(hexBytes(fields[0] as String)), fields[1] as String),
                        node = (fields[2] as String).ifEmpty { null },
                        typed = fields[3] as Boolean,
                        rssiDbm = (fields[4] as Int).takeIf { it != NONE },
                        snrQuarterDb = (fields[5] as Int).takeIf { it != NONE },
                    )
                }
                ManualPathDraft(hops, saved[0] as Int, saved[1] as Long)
            },
        )

        private const val HOP_FIELDS = 6

        /** No reading. */
        private const val NONE = Int.MIN_VALUE

        private fun hexBytes(hex: String): ByteArray = ByteArray(hex.length / 2) { index ->
            hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}
