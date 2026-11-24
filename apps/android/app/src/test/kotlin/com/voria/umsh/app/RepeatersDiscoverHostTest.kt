package com.voria.umsh.app

import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.inspectPublicIdentity
import com.voria.umsh.features.peers.DiscoverWindow
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PeerRole
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Neighboring repeaters and Discover over the real core and the staged
 * air, in real time: Tallac Ridge answers Peer Repeaters requests; the
 * nodes in the radio's range answer identity requests; the core's
 * discovery cooldown holds an unnarrowed ask back and lets a narrowed one go.
 */
class RepeatersDiscoverHostTest {
    @get:Rule val temp = TemporaryFolder()

    private lateinit var staged: StagedHost

    @After
    fun tearDown() = runBlocking { staged.close() }

    private fun address(seed: Int) =
        MobileIdentity.unlock(ByteArray(32) { seed.toByte() }).use { it.publicIdentity().canonicalAddress }

    /**
     * Reading the stored listing sends nothing: none before an ask, none a
     * while later; the first page then replaces it, names the neighbors the
     * core matched, and is what a later read returns.
     */
    @Test
    fun theStoredListingIsReadUntilAPageIsAskedFor() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        val tallac = address(0x22)
        assertNull("never asked", runtime.storedNeighbors(tallac))
        delay(QUIET_MS)
        assertNull("reading asked for nothing", runtime.storedNeighbors(tallac))

        val listing = withTimeout(PAGE_BUDGET_MS) { runtime.requestNeighbors(tallac, null).await() }
        println("listing: total=${listing.total} next=${listing.nextCursor} entries=${listing.entries.map { "${it.hintText}/${it.name}/${it.peerAddress}/${it.rssiDbm}/${it.snrQuarterDb}/${it.lastHeardMinutes}" }}")
        assertTrue("one neighbor at least: $listing", listing.entries.isNotEmpty())
        val glen = address(0x77)
        assertTrue("Glen Alpine Relay named: $listing", listing.entries.any { it.peerAddress == glen })
        assertEquals(listing, runtime.storedNeighbors(tallac))
    }

    /** An unanswered ask is `NoAnswer`, and keeps nothing. */
    @Test
    fun anUnreachableRepeaterDoesNotAnswer() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        staged.air.air.setRemoteDeviceReachable(false)
        val tallac = address(0x22)
        val started = System.currentTimeMillis()
        try {
            withTimeout(NO_ANSWER_BUDGET_MS) { runtime.requestNeighbors(tallac, null).await() }
            fail("an answer from an unreachable repeater")
        } catch (_: MobileAppException.NoAnswer) {
            println("no answer after ${System.currentTimeMillis() - started} ms")
        }
        assertNull(runtime.storedNeighbors(tallac))
    }

    /**
     * An ask goes once per cooldown: a second unnarrowed one is refused
     * while [AppRuntime.discoveryWaitMs] counts down, wherever it was made,
     * but a narrowed lookup still goes. The nodes in range answer, and the
     * window shows them.
     */
    @Test
    fun theCooldownHoldsAnAskBackButNotALookup() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        val opened = System.currentTimeMillis()
        assertEquals(0L, runtime.discoveryWaitMs())
        runtime.discover(null, emptyList()).await()
        val wait = runtime.discoveryWaitMs()
        println("wait after ask: $wait ms")
        assertTrue("a wait: $wait", wait in 30_000L..40_000L)
        try {
            runtime.discover(PeerRole.Repeater, emptyList()).await()
            fail("a second ask during the cooldown")
        } catch (_: MobileAppException.InvalidRequest) {
        }
        val glenHint = Octets(inspectPublicIdentity(address(0x77)).hint.bytes.copyOf(2))
        runtime.lookUpRepeaterHint(glenHint, emptyList()).await()

        // Each node holds its answer for a random 0.5–30 s, and which staged
        // nodes answer varies run to run; Glen Alpine Relay answers the
        // lookup as well, so it and one other are what is certain.
        val glen = address(0x77)
        val heard = withTimeout(HEARD_BUDGET_MS) {
            var shown = DiscoverWindow.of(runtime.appState.value?.peers.orEmpty(), opened)
            while (shown.size < 2 || shown.none { it.address == glen }) {
                delay(POLL_MS)
                shown = DiscoverWindow.of(runtime.appState.value?.peers.orEmpty(), opened)
            }
            shown
        }
        println("heard: ${heard.map { it.advertisedName ?: it.address }}")
        assertTrue("newest first", heard.zipWithNext().all { (a, b) -> (a.lastHeardAtMs ?: 0) >= (b.lastHeardAtMs ?: 0) })
    }

    /**
     * The host is ready before the start sets the owner (staging seeds
     * first), so a page restored then reads the store early: the read waits
     * for the owner and answers, rather than failing as if nothing were held.
     */
    @Test
    fun aStoreReadBeforeTheOwnerIsSetWaitsForIt() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        staged.host.ensureRuntime(staging = true)
        val ready = withTimeout(StagedHost.TIMEOUT) { staged.host.state.first { it is HostState.Ready } } as HostState.Ready
        val runtime = ready.runtime
        // The precondition, asked of the core itself: no owner yet. A start
        // that beat the test here leaves nothing to check, so it is skipped.
        val ownerUnset = try {
            runtime.core.peerRepeaters(address(0x22))
            false
        } catch (_: MobileAppException.NoOwner) {
            true
        }
        assumeTrue("the owner was set before the read", ownerUnset)
        val early = async { runtime.storedNeighbors(address(0x22)) }
        assertNull(withTimeout(StagedHost.TIMEOUT) { early.await() })
        assertNotNull(withTimeout(StagedHost.TIMEOUT) { runtime.lifecycle.first { it is MobileAppLifecycle.Running } })
    }

    private companion object {
        const val QUIET_MS = 3_000L
        const val PAGE_BUDGET_MS = 40_000L
        const val NO_ANSWER_BUDGET_MS = 120_000L
        const val HEARD_BUDGET_MS = 40_000L
        const val POLL_MS = 100L
    }
}
