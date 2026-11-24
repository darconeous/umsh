package com.voria.umsh.features.conversations

import com.voria.umsh.models.Octets
import org.junit.Assert.assertEquals
import org.junit.Test

/** Message details' route rows: the order they list in, and what each lookup is steered through. */
class RouteHopTest {
    private fun hop(byte: Int) = Octets(byteArrayOf(byte.toByte(), 0))

    @Test
    fun senderFirstEachSteeredByTheHopsNearerThisPhone() {
        // As the core records a route: the hop nearest this phone first.
        val nearest = hop(1)
        val middle = hop(2)
        val farthest = hop(3)
        val listed = RouteHop.listed(listOf(nearest, middle, farthest))
        assertEquals(listOf(farthest, middle, nearest), listed.map { it.hint })
        assertEquals(
            listOf(listOf(nearest, middle), listOf(nearest), emptyList()),
            listed.map { it.preceding },
        )
    }

    @Test
    fun noRouteListsNothing() {
        assertEquals(emptyList<RouteHop>(), RouteHop.listed(emptyList()))
    }
}
