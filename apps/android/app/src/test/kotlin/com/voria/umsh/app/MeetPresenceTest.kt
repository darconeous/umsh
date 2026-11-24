package com.voria.umsh.app

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runCurrent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class MeetPresenceTest {
    private val scope = TestScope(UnconfinedTestDispatcher())
    private val shown = MutableStateFlow(false)
    private val started = MutableStateFlow(true)
    private val asked = mutableListOf<Boolean>()
    private var refuse = false

    private fun presence() = MeetPresence(scope, shown, started) { wanted ->
        asked += wanted
        if (refuse) error("stopped")
    }

    @Test
    fun nothingIsSaidUntilTheMeetIsFirstWanted() {
        presence()
        started.value = false
        started.value = true
        scope.runCurrent()
        assertEquals(emptyList<Boolean>(), asked)
        scope.cancel()
    }

    @Test
    fun aMeetingPageOpensItAndLeavingItClosesIt() {
        val presence = presence()
        shown.value = true
        assertTrue(presence.wanted)
        shown.value = false
        assertFalse(presence.wanted)
        assertEquals(listOf(true, false), asked)
        scope.cancel()
    }

    @Test
    fun onlyAChangeIsSaid() {
        presence()
        shown.value = true
        shown.value = true
        started.value = true
        assertEquals(listOf(true), asked)
        scope.cancel()
    }

    /** The app leaving the foreground closes the meet; returning reopens it on the same page. */
    @Test
    fun theAppStoppingClosesItAndStartingReopensIt() {
        presence()
        shown.value = true
        started.value = false
        started.value = true
        assertEquals(listOf(true, false, true), asked)
        scope.cancel()
    }

    /** Stopped, or no owner: logged, and the next change asks again. */
    @Test
    fun aRefusalIsNotTheEnd() {
        val presence = presence()
        refuse = true
        shown.value = true
        refuse = false
        shown.value = false
        shown.value = true
        assertEquals(listOf(true, false, true), asked)
        assertTrue(presence.wanted)
        scope.cancel()
    }
}
