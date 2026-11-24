package com.voria.umsh.app

import com.voria.umsh.core.MobileStagingAirException
import com.voria.umsh.core.inspectPublicIdentity
import com.voria.umsh.models.MeetExchange
import com.voria.umsh.models.MeetState
import com.voria.umsh.services.identity.IdentityOperations
import com.voria.umsh.models.KeyProtection
import com.voria.umsh.services.preferences.OnboardingStep
import java.time.Clock
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Add peer's exchange as the runtime publishes it, over the real core and
 * the staged air, whose speaking peer opens Add peer and asks.
 */
class MeetPumpTest {
    @get:Rule val temp = TemporaryFolder()

    private lateinit var staged: StagedHost

    @After
    fun tearDown() = runBlocking { staged.close() }

    private suspend fun AppRuntime.meetWhere(what: String, predicate: (MeetState) -> Boolean): MeetState =
        try {
            withTimeout(StagedHost.TIMEOUT) { meet.first { it != null && predicate(it) }!! }
        } catch (error: Exception) {
            throw AssertionError("never: $what (last ${meet.value})", error)
        }

    /** The staged peer opens Add peer and asks, once its session hears the phone's. */
    private suspend fun peerAsks() = withTimeout(StagedHost.TIMEOUT) {
        while (true) {
            try {
                staged.air.air.peerOpensAddPeer(true)
                break
            } catch (_: MobileStagingAirException.NoPhone) {
                delay(StagedHost.POLL_MS)
            }
        }
    }

    @Test
    fun anAskIsAnsweredComparedAndExchanged() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        assertNull("closed until wanted", runtime.meet.value)

        runtime.setMeetWanted(true).await()
        runtime.meetWhere("the meet open") { it.exchange == MeetExchange.Idle }
        peerAsks()
        val asked = runtime.meetWhere("asked") { it.exchange is MeetExchange.Asked }
        assertEquals(asked.device, (asked.exchange as MeetExchange.Asked).device)

        runtime.core.answerExchange(true)
        val comparing = runtime.meetWhere("comparing") { it.exchange is MeetExchange.Comparing }
        val code = (comparing.exchange as MeetExchange.Comparing).code
        assertTrue("six digits at most: $code", code in 0..999_999)

        runtime.core.confirmCode(true)
        val exchanged = runtime.meetWhere("exchanged") { it.exchange is MeetExchange.Exchanged }
        val contact = exchanged.exchange as MeetExchange.Exchanged
        // Published after the lists: the new peer is already there to open.
        assertNotNull(runtime.appState.value?.peers?.firstOrNull { it.address == contact.peerAddress })

        runtime.setMeetWanted(false).await()
        withTimeout(StagedHost.TIMEOUT) { runtime.meet.first { it == null || it.exchange == MeetExchange.Closed } }
    }

    /** A runtime that starts over a core whose meet is already open reads it from the status. */
    @Test
    fun aRuntimeStartingOverAnOpenMeetReadsItFromTheStatus() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        val first = staged.start()
        first.setMeetWanted(true).await()
        peerAsks()
        val asked = first.meetWhere("asked") { it.exchange is MeetExchange.Asked }
        // The first stops observing; the second's first read is the status.
        first.detach()
        val second = AppRuntime(
            core = first.core,
            kind = CoreKind.Staging,
            platformModel = first.platformModel,
            generation = first.generation + 1,
            owner = inspectPublicIdentity(first.ownerAddress),
            identityOps = IdentityOperations(MemoryIdentityVault(VaultLog())),
            protection = { KeyProtection.Software },
            preferences = staged.preferences,
            initialOnboarding = OnboardingStep.Done,
            seed = null,
            foregroundSignals = emptyFlow(),
            clock = Clock.systemUTC(),
            scope = staged.scope,
        )
        try {
            assertNull(second.meet.value)
            second.start()
            val seeded = second.meetWhere("the status's meet") { it.exchange is MeetExchange.Asked }
            assertEquals(asked.device, seeded.device)
        } finally {
            second.detach()
        }
    }
}
