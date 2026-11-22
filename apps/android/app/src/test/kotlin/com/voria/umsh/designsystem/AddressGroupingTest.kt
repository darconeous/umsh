package com.voria.umsh.designsystem

import org.junit.Assert.assertEquals
import org.junit.Test

class AddressGroupingTest {
    /** identity.svg board 1: six groups, then five. */
    @Test
    fun groupsOfFour() {
        val address = "Ju8QmN2rT5vXbC7kLpZ4wYhD9sFgE3aRtUiKqP6nM1xW"
        assertEquals(44, address.length)
        assertEquals(
            "Ju8Q mN2r T5vX bC7k LpZ4 wYhD 9sFg E3aR tUiK qP6n M1xW",
            AddressGrouping.grouped(address),
        )
    }

    @Test
    fun leadingPaddingIsKept() {
        assertEquals("111t hX6L ZfHD ZZKU s92f ebYZ hYRc Xddm zfzF 2NvT kPNE", AddressGrouping.grouped("111thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE"))
    }

    @Test
    fun identifierPlaceholdersAreIsolated() {
        val text = withIdentifiers("Node hint 0", listOf("AP5R"), monospace = false)
        assertEquals("Node hint ⁦AP5R⁩", text.text)
        assertEquals(1, text.getTtsAnnotations(0, text.length).size)
    }
}
