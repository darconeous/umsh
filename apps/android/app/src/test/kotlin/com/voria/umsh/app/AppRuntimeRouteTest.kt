package com.voria.umsh.app

import com.voria.umsh.core.MobileAppChatRequest
import com.voria.umsh.core.MobileAppPingResult
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.MobileMeshRouteKind
import com.voria.umsh.core.MobileAppRouteRecord
import com.voria.umsh.core.inspectPublicIdentity
import com.voria.umsh.designsystem.RailLeg
import com.voria.umsh.features.peers.PingPath
import com.voria.umsh.models.ManualPath
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PingOutcome
import com.voria.umsh.models.RouteKind
import com.voria.umsh.services.location.PhoneFix
import com.voria.umsh.services.location.PositionSource
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Routes and pings over the real core and the staged air, in real time. */
class AppRuntimeRouteTest {
    @get:Rule val temp = TemporaryFolder()

    private lateinit var staged: StagedHost

    @After
    fun tearDown() = runBlocking { staged.close() }

    /** The fixes the runtime reads, in turn; the last repeats. */
    private class Fixes(vararg val fixes: PhoneFix?) : PositionSource {
        val reads = AtomicInteger()

        override suspend fun readOnceIfGranted(): PhoneFix? = fixes[minOf(reads.getAndIncrement(), fixes.lastIndex)]
    }

    private fun address(seed: Int) =
        MobileIdentity.unlock(ByteArray(32) { seed.toByte() }).use { it.publicIdentity().canonicalAddress }

    private fun fix(latitude: Double) = PhoneFix(latitude, -120.1, accuracyMeters = 10.0, approximate = false)

    private suspend fun routeWhere(address: String, what: String, predicate: (MobileAppRouteRecord) -> Boolean) =
        withTimeout(ROUTE_WAIT_MS) {
            var route = staged.runtime.core.peerRoute(address)
            while (!predicate(route)) {
                delay(POLL_MS)
                route = staged.runtime.core.peerRoute(address)
            }
            route
        }.also { assertNotNull(what, it) }

    /**
     * The staging recipe for a learned path: hold a path to Sam Ihara (heard
     * only through Glen Alpine Relay) through a repeater hint nobody owns,
     * with a flood after it. The first send misses its acknowledgment, the
     * flood is acknowledged through the relay, and the way it went is kept
     * as the candidate. One acknowledgment by flood offers it only once the
     * phone has moved, which the second of two injected fixes, about 330 m
     * from the first, says.
     */
    @Test
    fun aHeldPathNobodyForwardsIsOfferedTheLearnedOneOnceThePhoneMoved() = runBlocking<Unit> {
        val positions = Fixes(fix(38.9), fix(38.903))
        staged = StagedHost(temp.newFolder(), positions)
        val runtime = staged.start()
        val sam = address(0x66)
        val relayHint = address(0x77).let { com.voria.umsh.core.inspectPublicIdentity(it).hint.bytes.copyOf(2) }

        val nobody = ManualPath(listOf(Octets(byteArrayOf(0x00, 0x01))), floodHops = 2)
        assertTrue(runtime.setManualPath(sam, nobody, HOLD_MS).await())
        assertEquals("the hold read where the phone was", 1, positions.reads.get())
        assertNull("nothing learned yet", runtime.learnedPathOffer(sam).await())

        runtime.startConversation(sam).await()
        runtime.core.sendChat(sam, MobileAppChatRequest.Typed("Which way?", null), "Which way?")
        val learned = routeWhere(sam, "a candidate") { it.fallbackAcks > 0u && it.candidate != null }
        assertEquals(1, learned.fallbackAcks.toInt())
        val candidate = checkNotNull(learned.candidate)
        assertEquals(MobileMeshRouteKind.SOURCE, candidate.kind)
        assertEquals(1, candidate.hints.size)
        assertArrayEquals(relayHint, candidate.hints.single().bytes)

        val reads = positions.reads.get()
        val offered = runtime.learnedPathOffer(sam).await()
        assertNotNull("offered once the phone moved", offered)
        assertEquals("one reading, asked for by the core", reads + 1, positions.reads.get())
        assertTrue(offered!!.isHeld)
        assertEquals(1, offered.fallbackAcks)
        assertEquals(RouteKind.Source, offered.candidate?.kind)
        assertEquals(listOf(Octets(relayHint)), offered.candidate?.hints?.map { it.octets })

        // Keep manual path settles it: asked once per saved path.
        runtime.keepManualPath(sam).await()
        assertNull("settled", runtime.learnedPathOffer(sam).await())
        assertTrue("still held", runtime.peerRoute(sam).await().isHeld)
    }

    /** Use learned path drops the hold: the learned route is the one sent on, and nothing is offered again. */
    @Test
    fun usingTheLearnedPathDropsTheHold() = runBlocking<Unit> {
        val positions = Fixes(fix(38.9), fix(38.903))
        staged = StagedHost(temp.newFolder(), positions)
        val runtime = staged.start()
        val sam = address(0x66)
        val relayHint = inspectPublicIdentity(address(0x77)).hint.bytes.copyOf(2)
        assertTrue(runtime.setManualPath(sam, ManualPath(listOf(Octets(byteArrayOf(0x00, 0x01))), floodHops = 2), HOLD_MS).await())
        runtime.startConversation(sam).await()
        runtime.core.sendChat(sam, MobileAppChatRequest.Typed("Which way?", null), "Which way?")
        routeWhere(sam, "a candidate") { it.fallbackAcks > 0u && it.candidate != null }
        val revision = runtime.routeRevisions.value[sam] ?: 0L
        assertNotNull(runtime.learnedPathOffer(sam).await())

        assertTrue(runtime.adoptLearnedPath(sam).await())
        val route = runtime.peerRoute(sam).await()
        assertFalse(route.isHeld)
        assertEquals(listOf(Octets(relayHint)), route.hints.map { it.octets })
        assertTrue("pages showing the route read it again", (runtime.routeRevisions.value[sam] ?: 0L) > revision)
        assertNull(runtime.learnedPathOffer(sam).await())
    }

    /**
     * The same recipe with no fix to be had when the core asks: one
     * acknowledgment by flood offers nothing. The core did ask (a second
     * reading, answered with none), so the nothing is the no-fix answer.
     */
    @Test
    fun withNoFixOneFloodAcknowledgmentOffersNothing() = runBlocking<Unit> {
        val positions = Fixes(fix(38.9), null)
        staged = StagedHost(temp.newFolder(), positions)
        val runtime = staged.start()
        val sam = address(0x66)
        val nobody = ManualPath(listOf(Octets(byteArrayOf(0x00, 0x01))), floodHops = 2)
        assertTrue(runtime.setManualPath(sam, nobody, HOLD_MS).await())
        assertEquals("the hold read where the phone was", 1, positions.reads.get())
        runtime.startConversation(sam).await()
        runtime.core.sendChat(sam, MobileAppChatRequest.Typed("Which way?", null), "Which way?")
        routeWhere(sam, "a candidate") { it.fallbackAcks > 0u && it.candidate != null }
        assertNull(runtime.learnedPathOffer(sam).await())
        assertEquals("one reading, asked for by the core and answered with none", 2, positions.reads.get())
    }

    /**
     * A ping to the managed repeater while it hears nothing times out. How
     * long is the MAC's (its acknowledgment waits, retries and flood
     * fallback), not a timer of the app's: measured here, and budgeted by the
     * screens' tests.
     */
    @Test
    fun aPingNobodyAnswersTimesOut() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        staged.air.air.setRemoteDeviceReachable(false)
        val started = System.nanoTime()
        val result = withTimeout(PING_BUDGET_MS) { runtime.core.ping(address(MANAGED_SEED), null) }
        val waitedMs = (System.nanoTime() - started) / 1_000_000
        println("ping timed out after $waitedMs ms")
        assertEquals(MobileAppPingResult.TimedOut, result)
    }

    /**
     * `ping-route.svg` 1 over the staged air: Sam Ihara answers through Glen
     * Alpine Relay. The reply names the relay, carries the phone's reading
     * and the relay's, so the rail reads both legs, and the relay's hint is
     * named by the core. It teaches a route, which Reset route then forgets
     * (and a second reset finds none).
     */
    @Test
    fun aPingThroughTheRelayDrawsBothLegsAndTeachesARoute() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        val sam = address(0x66)
        val relay = address(0x77)
        val outcome = withTimeout(PING_BUDGET_MS) { runtime.ping(sam).await() }
        val reply = (outcome as PingOutcome.Reply).reply
        assertEquals(2, reply.hopCount)
        assertEquals(1, reply.routeHints.size)
        assertEquals(0, reply.unnamedHops)
        assertNotNull("the phone's own reading", reply.ownSignal.rssiDbm)
        val layout = PingPath.of(reply)
        assertTrue(layout.legs.toString(), layout.legs.all { it is RailLeg.Reading })
        assertEquals(listOf(relay), runtime.hopNames.names(layout.repeaters.map { it.octets }))

        val learned = runtime.peerRoute(sam).await()
        assertEquals(RouteKind.Source, learned.kind)
        assertEquals(listOf(reply.routeHints.single()), learned.hints)
        assertTrue("reset forgets it", runtime.clearRoute(sam).await())
        assertEquals(RouteKind.Unknown, runtime.peerRoute(sam).await().kind)
        assertFalse("nothing left to reset", runtime.clearRoute(sam).await())
    }

    /** `ping-route.svg` 5's facts as the runtime maps them: held, until when, its flood allowance; cleared, learned again. */
    @Test
    fun aHeldPathReadsAsHeldUntilCleared() = runBlocking<Unit> {
        staged = StagedHost(temp.newFolder())
        val runtime = staged.start()
        val sam = address(0x66)
        val relayHint = inspectPublicIdentity(address(0x77)).hint.bytes.copyOf(2)
        val before = System.currentTimeMillis()
        assertTrue(runtime.setManualPath(sam, ManualPath(listOf(Octets(relayHint)), floodHops = 1), HOLD_MS).await())
        val held = runtime.peerRoute(sam).await()
        assertTrue(held.isHeld)
        assertEquals(1, held.holdFloodHops)
        assertEquals(1, held.hints.size)
        val until = checkNotNull(held.holdUntilMs)
        assertTrue("held until about now + the hold", until in before + HOLD_MS - 5_000..System.currentTimeMillis() + HOLD_MS)
        assertTrue(runtime.clearManualPath(sam).await())
        assertFalse(runtime.peerRoute(sam).await().isHeld)
    }

    private companion object {
        const val MANAGED_SEED = 0x22
        const val HOLD_MS = 600_000L
        const val ROUTE_WAIT_MS = 60_000L
        const val POLL_MS = 100L

        /** The measured timeout (about 68 s on the staged air) with room. */
        const val PING_BUDGET_MS = 120_000L
    }
}
