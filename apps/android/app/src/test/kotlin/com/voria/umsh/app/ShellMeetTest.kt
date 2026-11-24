package com.voria.umsh.app

import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.voria.umsh.core.MobileStagingAirException
import com.voria.umsh.features.peers.RuntimeExchangeHost
import com.voria.umsh.models.MeetExchange
import com.voria.umsh.models.MeetState
import java.util.concurrent.Executors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The shell's half of the exchange over the real core and the staged air:
 * Add peer on top opens the meet, an attempt under way is the exchange
 * page's step, leaving that page backs out for both and the page does not
 * come back for the attempt it left, and leaving the app closes the meet.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ShellMeetTest {
    @get:Rule val temp = TemporaryFolder()

    private val main = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
    private lateinit var staged: StagedHost
    private val models = ViewModelStore()
    private val started = MutableStateFlow(true)

    @Before
    fun setUp() = Dispatchers.setMain(main)

    @After
    fun tearDown() = runBlocking {
        withContext(main) { models.clear() }
        staged.close()
        Dispatchers.resetMain()
        main.close()
    }

    private suspend fun shell(runtime: AppRuntime): ShellViewModel = withContext(main) {
        val exchange = RuntimeExchangeHost(runtime)
        ViewModelProvider.create(
            models,
            viewModelFactory { initializer { ShellViewModel(runtime, processStarted = started, exchange = exchange) } },
        )[ShellViewModel::class]
    }

    private suspend fun AppRuntime.meetWhere(what: String, predicate: (MeetState?) -> Boolean): MeetState? =
        try {
            withTimeout(StagedHost.TIMEOUT) { meet.first(predicate) }
        } catch (error: Exception) {
            throw AssertionError("never: $what (last ${meet.value})", error)
        }

    private suspend fun ShellViewModel.stepWhere(what: String, predicate: (MeetStep) -> Boolean): MeetStep =
        try {
            withTimeout(StagedHost.TIMEOUT) { meetStep.first(predicate) }
        } catch (error: Exception) {
            throw AssertionError("never: $what (last ${currentMeetStep()})", error)
        }

    /** The staged T-LoRa Pager opens Add peer, once its session hears the phone's. */
    private suspend fun peerOpensAddPeer(asking: Boolean) = withTimeout(StagedHost.TIMEOUT) {
        while (true) {
            try {
                staged.air.air.peerOpensAddPeer(asking)
                break
            } catch (_: MobileStagingAirException.NoPhone) {
                delay(StagedHost.POLL_MS)
            }
        }
    }

    @Test
    fun leavingTheExchangePageBacksOutForBothAndItStaysClosed() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        val shell = shell(runtime)
        assertEquals(MeetStep.None, shell.currentMeetStep())

        // Add peer on top: the meet opens.
        withContext(main) { shell.topPageChanged(UmshKey.AddPeer(Destination.Peers)) }
        runtime.meetWhere("open") { it?.exchange == MeetExchange.Idle }
        peerOpensAddPeer(asking = false)
        val listed = runtime.meetWhere("the pager listed") { it?.devices?.isNotEmpty() == true }!!

        // Tapping its row: the attempt is under way, the exchange page's step.
        runtime.askToExchange(listed.devices.first().id).await()
        shell.stepWhere("under way") { it == MeetStep.UnderWay }
        withContext(main) { shell.topPageChanged(UmshKey.Exchange(Destination.Peers)) }
        runtime.meetWhere("comparing") { it?.exchange is MeetExchange.Comparing }

        // Back to Add peer: the step drops at once and stays down, and the core backs out.
        val step = withContext(main) {
            shell.topPageChanged(UmshKey.AddPeer(Destination.Peers))
            shell.currentMeetStep()
        }
        assertEquals(MeetStep.None, step)
        val after = runtime.meetWhere("a fresh meet") { it != null && !it.exchange.isUnderWay }
        assertTrue("open again, not closed: ${after?.exchange}", after?.exchange != MeetExchange.Closed)
        assertEquals(MeetStep.None, shell.currentMeetStep())
    }

    @Test
    fun contactsCrossedIsTheNewPeersStep() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        val shell = shell(runtime)
        withContext(main) { shell.topPageChanged(UmshKey.AddPeer(Destination.Conversations)) }
        runtime.meetWhere("open") { it?.exchange == MeetExchange.Idle }
        peerOpensAddPeer(asking = true)
        runtime.meetWhere("asked") { it?.exchange is MeetExchange.Asked }
        assertEquals("asked is a sheet over Add peer, not the page", MeetStep.None, shell.currentMeetStep())
        runtime.answerExchange(true).await()
        shell.stepWhere("comparing") { it == MeetStep.UnderWay }
        runtime.meetWhere("comparing") { it?.exchange is MeetExchange.Comparing }
        runtime.confirmCode(true).await()
        val step = shell.stepWhere("exchanged") { it is MeetStep.Exchanged } as MeetStep.Exchanged
        assertTrue(runtime.appState.value!!.peers.any { it.address == step.peerAddress })
    }

    @Test
    fun leavingTheAppClosesTheMeetAndReturningOpensItAgain() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        val shell = shell(runtime)
        withContext(main) { shell.topPageChanged(UmshKey.AddPeer(Destination.Peers)) }
        val colors = mutableListOf(runtime.meetWhere("open") { it?.exchange == MeetExchange.Idle }!!.ownColorRgb)
        repeat(2) {
            started.value = false
            runtime.meetWhere("closed") { it == null || it.exchange == MeetExchange.Closed }
            started.value = true
            colors += runtime.meetWhere("open again") { it?.exchange == MeetExchange.Idle }!!.ownColorRgb
        }
        assertFreshKeys(colors)
    }

    @Test
    fun decliningAnAskOpensAgainUnderAFreshKey() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        val shell = shell(runtime)
        withContext(main) { shell.topPageChanged(UmshKey.AddPeer(Destination.Peers)) }
        val colors = mutableListOf(runtime.meetWhere("open") { it?.exchange == MeetExchange.Idle }!!.ownColorRgb)
        repeat(2) {
            peerOpensAddPeer(asking = true)
            runtime.meetWhere("asked") { it?.exchange is MeetExchange.Asked }
            runtime.answerExchange(false).await()
            colors += runtime.meetWhere("open again") { it?.exchange == MeetExchange.Idle }!!.ownColorRgb
        }
        assertFreshKeys(colors)
    }

    @Test
    fun anAppPageOverAddPeerClosesTheMeetAndBackOpensIt() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        val shell = shell(runtime)
        withContext(main) { shell.topPageChanged(UmshKey.AddPeer(Destination.Peers)) }
        runtime.meetWhere("open") { it?.exchange == MeetExchange.Idle }
        // Radio Detail from the radio control, over Add peer: nothing can be asked unseen.
        withContext(main) { shell.topPageChanged(UmshKey.RadioDetail) }
        runtime.meetWhere("closed") { it == null || it.exchange == MeetExchange.Closed }
        withContext(main) { shell.topPageChanged(UmshKey.AddPeer(Destination.Peers)) }
        runtime.meetWhere("open again") { it?.exchange == MeetExchange.Idle }
    }

    /**
     * Each reopening is under a new key. A color is one of 256, so two keys
     * share one now and then; three in a row never do in practice.
     */
    private fun assertFreshKeys(colors: List<Int?>) {
        assertTrue("every visit has a color: $colors", colors.all { it != null })
        assertTrue("a fresh key each time: $colors", colors.toSet().size > 1)
    }
}
