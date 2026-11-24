package com.voria.umsh.features.peers.manualpath

import androidx.compose.runtime.saveable.SaverScope
import com.voria.umsh.models.ManualPath
import com.voria.umsh.models.Octets
import com.voria.umsh.models.RepeaterHint
import com.voria.umsh.models.RouteKind
import com.voria.umsh.models.RouteSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The editor's draft: seeded from the route, kept inside the core's bounds, and saved whole (§3.5). */
class ManualPathDraftTest {
    private val limits = ManualPathLimits(
        maxRouteHints = 3,
        maxFloodHops = 15,
        newPathFloodHops = 1,
        holdChoicesMs = listOf(HALF_HOUR, HOUR, 4 * HOUR),
        holdDefaultMs = HOUR,
    )

    private fun hint(first: Int, text: String = "h$first*") = RepeaterHint(Octets(byteArrayOf(first.toByte(), 0x01)), text)

    private fun route(hints: Int, held: Boolean, heldFlood: Int? = null) = RouteSummary(
        kind = RouteKind.Source,
        hints = List(hints) { hint(it + 1) },
        hopCount = hints + 1,
        floodHops = null,
        holdRemainingMs = if (held) HOUR else null,
        holdFloodHops = heldFlood,
        confirmedAgeMs = null,
    )

    @Test
    fun aLearnedRouteSeedsItsHopsAndTheCoresFloodAndHold() {
        val draft = ManualPathDraft.seed(route(2, held = false), limits)
        assertEquals(listOf(hint(1), hint(2)), draft.hops.map { it.hint })
        assertFalse("a learned hop was not typed", draft.hops.any { it.typed })
        assertEquals(limits.newPathFloodHops, draft.floodHops)
        assertEquals(limits.holdDefaultMs, draft.holdMs)
    }

    @Test
    fun aHeldPathSeedsItsOwnFloodAndCountsItsHopsAsTyped() {
        val draft = ManualPathDraft.seed(route(1, held = true, heldFlood = 4), limits)
        assertEquals(4, draft.floodHops)
        assertTrue(draft.hops.single().typed)
    }

    @Test
    fun noRouteSeedsADirectPath() {
        val draft = ManualPathDraft.seed(null, limits)
        assertTrue(draft.hops.isEmpty())
        assertEquals(ManualPath(emptyList(), limits.newPathFloodHops), draft.path)
    }

    @Test
    fun aSeedLongerThanTheCoreAllowsIsCut() {
        assertEquals(limits.maxRouteHints, ManualPathDraft.seed(route(5, held = false), limits).hops.size)
    }

    @Test
    fun theLimitsHold() {
        var draft = ManualPathDraft.seed(null, limits)
        draft = draft.adding(DraftHop(hint(1)), limits).adding(DraftHop(hint(1)), limits)
        assertEquals("a hint once", 1, draft.hops.size)
        draft = draft.adding(DraftHop(hint(2)), limits).adding(DraftHop(hint(3)), limits)
        assertTrue(draft.isFull(limits))
        assertSame("full", draft, draft.adding(DraftHop(hint(4)), limits))
        assertEquals(15, draft.withFlood(40, limits).floodHops)
        assertEquals(0, draft.withFlood(-1, limits).floodHops)
        assertEquals(4 * HOUR, draft.withHold(4 * HOUR, limits).holdMs)
        assertEquals("not a choice", draft.holdMs, draft.withHold(2 * HOUR, limits).holdMs)
    }

    @Test
    fun reorderAndRemove() {
        val draft = ManualPathDraft(listOf(DraftHop(hint(1)), DraftHop(hint(2)), DraftHop(hint(3))), 1, HOUR)
        assertEquals(listOf(2, 3, 1), draft.moving(0, 2).hops.map { it.hint.octets[0].toInt() })
        assertEquals(listOf(1, 3, 2), draft.moving(2, 1).hops.map { it.hint.octets[0].toInt() })
        assertSame(draft, draft.moving(0, 3))
        assertEquals(listOf(1, 3), draft.removing(1).hops.map { it.hint.octets[0].toInt() })
        assertEquals(
            ManualPath(listOf(Octets(byteArrayOf(1, 1)), Octets(byteArrayOf(3, 1))), 1),
            draft.removing(1).path,
        )
    }

    @Test
    fun theSaverKeepsEveryField() {
        val draft = ManualPathDraft(
            listOf(
                DraftHop(hint(0x5e, "5E*"), node = "8veFkQTG", typed = false, rssiDbm = -95, snrQuarterDb = 12),
                DraftHop(hint(0x7a, "7N*"), typed = true),
            ),
            floodHops = 2,
            holdMs = 4 * HOUR,
        )
        val scope = SaverScope { true }
        val saved = with(ManualPathDraft.Saver) { scope.save(draft) }!!
        assertEquals(draft, ManualPathDraft.Saver.restore(saved))
    }

    private companion object {
        const val HOUR = 3_600_000L
        const val HALF_HOUR = HOUR / 2
    }
}
