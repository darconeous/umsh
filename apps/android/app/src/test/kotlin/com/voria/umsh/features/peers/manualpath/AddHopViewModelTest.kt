package com.voria.umsh.features.peers.manualpath

import com.voria.umsh.core.MobileAppException
import com.voria.umsh.features.peers.NeighborSource
import com.voria.umsh.models.Octets
import com.voria.umsh.models.RepeaterListing
import java.util.concurrent.Executors
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Add hop's Neighbors: the stored listing on opening, asks down the path so
 * far, an answer about an earlier hop dropped once the page moved on, and
 * the two inline problems.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class AddHopViewModelTest {
    private val main = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

    @Before
    fun setUp() = Dispatchers.setMain(main)

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        main.close()
    }

    private class Source : NeighborSource {
        val stored = mutableMapOf<String, RepeaterListing>()
        val asked = mutableListOf<Triple<String, Octets?, List<Octets>>>()
        val answers = mutableListOf<CompletableDeferred<RepeaterListing>>()

        override suspend fun storedNeighbors(address: String): RepeaterListing? = stored[address]

        override fun requestNeighbors(address: String, cursor: Octets?, route: List<Octets>): Deferred<RepeaterListing> {
            asked += Triple(address, cursor, route)
            return CompletableDeferred<RepeaterListing>().also(answers::add)
        }
    }

    private fun listing(at: Long) = RepeaterListing(emptyList(), total = 0, nextCursor = null, asOfMs = at)

    private fun eventually(condition: () -> Boolean) = runBlocking {
        withTimeout(5_000) { while (!condition()) delay(10) }
    }

    @Test
    fun opensOnTheStoreAndAsksDownThePathSoFar() {
        val source = Source().apply { stored["A"] = listing(1) }
        val viewModel = AddHopViewModel(source)
        val route = listOf(Octets(byteArrayOf(1, 2)))
        viewModel.ask(Vantage("A", route))
        eventually { viewModel.listing.value == listing(1) }
        assertFalse(viewModel.fresh.value)
        assertTrue("opening sends nothing", source.asked.isEmpty())

        viewModel.refresh()
        assertEquals(listOf(Triple("A", null as Octets?, route)), source.asked)
        source.answers.single().complete(listing(2))
        eventually { viewModel.listing.value == listing(2) && viewModel.fresh.value && !viewModel.busy.value }
    }

    @Test
    fun anAnswerAboutTheHopBeforeIsDropped() {
        val source = Source()
        val viewModel = AddHopViewModel(source)
        viewModel.ask(Vantage("A", emptyList()))
        viewModel.refresh()
        viewModel.ask(Vantage("B", emptyList()))
        source.answers.single().complete(listing(9))
        // The answer resumes on the main thread; anything queued after it
        // runs after it, so this waits for it to be handled.
        runBlocking(main) {}
        assertNull(viewModel.listing.value)
        assertFalse(viewModel.busy.value)

        // B's own answer still lands, so the drop was A's alone.
        viewModel.refresh()
        source.answers.last().complete(listing(10))
        eventually { viewModel.listing.value == listing(10) }
    }

    @Test
    fun noAnswerAndNotSentAreTheirOwnLines() {
        val source = Source()
        val viewModel = AddHopViewModel(source)
        viewModel.ask(Vantage("A", emptyList()))
        viewModel.refresh()
        source.answers.last().completeExceptionally(MobileAppException.NoAnswer())
        eventually { viewModel.problem.value == AddHopProblem.NoAnswer }
        viewModel.refresh()
        source.answers.last().completeExceptionally(MobileAppException.NotRunning())
        eventually { viewModel.problem.value == AddHopProblem.NotSent }
    }

    @Test
    fun aHintOnlyPreviousHopAsksNothing() {
        val source = Source()
        val viewModel = AddHopViewModel(source)
        viewModel.ask(null)
        viewModel.refresh()
        assertTrue(source.asked.isEmpty())
    }
}
