package com.voria.umsh.features

import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.Tags
import com.voria.umsh.app.setRemoteDeviceReachable
import com.voria.umsh.app.stagedAir
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.features.peers.LocalNeighborSource
import com.voria.umsh.features.peers.NeighborSource
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PingOutcome
import com.voria.umsh.models.RepeaterListing
import com.voria.umsh.models.RepeaterNeighbor
import com.voria.umsh.services.preferences.OnboardingStep
import java.io.File
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Screenshots of `repeaters-discover.svg` 1–5 for the build report, in the
 * real app root over the staged air. Off unless the run passes `-e shots
 * <suffix>`, the suffix naming the device's appearance. Board 1 pages over
 * a stand-in source (the staged air's repeater lists one neighbor); board 2
 * waits out the core's no-answer timeout (about 72 s).
 */
class RepeatersDiscoverShots {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val suffix: String? get() = InstrumentationRegistry.getArguments().getString("shots")

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun onlyWhenAsked() = assumeTrue(suffix != null)

    private fun shot(name: String) {
        compose.waitForIdle()
        Thread.sleep(SETTLE_MS)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val bitmap = instrumentation.uiAutomation.takeScreenshot() ?: return
        val directory = File(instrumentation.targetContext.getExternalFilesDir(null), "shots").apply { mkdirs() }
        File(directory, "$name-$suffix.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    private fun start(source: NeighborSource? = null): AppRuntime {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            InstrumentationRegistry.getInstrumentation().uiAutomation.grantRuntimePermission(context.packageName, android.Manifest.permission.POST_NOTIFICATIONS)
        }
        runBlocking {
            fresh.host.preferences.setFallbackScheme(true)
            fresh.host.preferences.setNotificationsAsked()
        }
        fresh.host.ensureRuntime(staging = true)
        val runtime = runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime.setOnboarding(OnboardingStep.Done).await()
            withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
            withTimeout(TIMEOUT) { ready.runtime.appState.first { state -> state?.peers?.any { it.address == TALLAC } == true } }
            ready.runtime
        }
        compose.setContent {
            CompositionLocalProvider(LocalNeighborSource provides source) { AppRoot(fresh.host) }
        }
        return runtime
    }

    private fun present(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()

    private fun waitFor(tag: String, timeout: Long = TIMEOUT) = compose.waitUntil(timeout) { present(tag) }

    private fun peers() {
        waitFor(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitFor(Tags.PEERS_LIST)
    }

    private fun openTallac() {
        peers()
        compose.onNodeWithTag(Tags.PEERS_LIST).performScrollToNode(hasTestTag(Tags.peerRow(TALLAC)))
        compose.onNodeWithTag(Tags.peerRow(TALLAC)).performClick()
        waitFor(Tags.PEER_VERB_NEIGHBORS)
    }

    private fun openNeighbors() {
        openTallac()
        compose.onNodeWithTag(Tags.PEER_VERB_NEIGHBORS).performClick()
        waitFor(Tags.NEIGHBORS_FOOTER)
    }

    private fun openDiscoverFromList() {
        peers()
        compose.onNodeWithTag(Tags.PEERS_LIST).performScrollToNode(hasTestTag(Tags.PEERS_DISCOVER))
        compose.onNodeWithTag(Tags.PEERS_DISCOVER).performClick()
        waitFor(Tags.DISCOVER_PAGE)
    }

    @Test
    fun board1Neighbors() {
        val runtime = start(Board1Source)
        // Board 1 draws the lookup on the unknown hint, which needs a route that lands at Tallac Ridge.
        val landed = (1..PING_TRIES).any {
            val outcome = runBlocking { runtime.ping(TALLAC).await() }
            outcome is PingOutcome.Reply && runBlocking { runtime.peerRoute(TALLAC).await() }.discoveryVantage?.landsAtPeer == true
        }
        assertTrue("a route that lands at Tallac Ridge", landed)
        openNeighbors()
        compose.onNodeWithTag(Tags.NEIGHBORS_REFRESH).performClick()
        waitFor(Tags.NEIGHBORS_LOAD_MORE)
        compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(Tags.hintLookup("8c01"), useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty() }
        shot("repeaters-discover-1")
    }

    @Test
    fun board2NoAnswer() {
        start()
        fresh.stagedAir.setRemoteDeviceReachable(false)
        openNeighbors()
        compose.onNodeWithTag(Tags.NEIGHBORS_REFRESH).performClick()
        waitFor(Tags.NEIGHBORS_NO_ANSWER, NO_ANSWER_BUDGET_MS)
        shot("repeaters-discover-2")
    }

    @Test
    fun board3Discover() {
        start()
        openDiscoverFromList()
        shot("repeaters-discover-3")
    }

    @Test
    fun board4AskedNearANode() {
        val runtime = start()
        val outcome = runBlocking { runtime.ping(TALLAC).await() }
        assertTrue("a route learned: $outcome", outcome is PingOutcome.Reply)
        openTallac()
        compose.onNodeWithTag(Tags.PEER_GLANCE_ROUTE).performClick()
        waitFor(Tags.ROUTE_ASK_NEAR)
        compose.onNodeWithTag(Tags.ROUTE_ASK_NEAR).performScrollTo().performClick()
        waitFor(Tags.DISCOVER_ASK)
        compose.onNodeWithTag(Tags.DISCOVER_ASK).performClick()
        waitFor(Tags.DISCOVER_ASK_FOOTER)
        compose.waitUntil(HEARD_BUDGET_MS) { present(Tags.discoverRow(RELAY)) }
        Thread.sleep(2_000)
        shot("repeaters-discover-4")
    }

    @Test
    fun board5Announce() {
        start()
        openDiscoverFromList()
        compose.onNodeWithTag(Tags.DISCOVER_ANNOUNCE).performScrollTo().performClick()
        waitFor(Tags.CONFIRM_DIALOG)
        shot("repeaters-discover-5")
        compose.onNodeWithTag(Tags.CONFIRM_CANCEL).performClick()
    }

    /** Board 1's first page: a named neighbor, an unknown repeater hint, one heard an hour ago, and one faded. */
    private object Board1Source : NeighborSource {
        override suspend fun storedNeighbors(address: String): RepeaterListing? = null

        override fun requestNeighbors(address: String, cursor: Octets?, route: List<Octets>): Deferred<RepeaterListing> {
            val now = System.currentTimeMillis()
            fun neighbor(hint: Int, text: String, name: String?, rssi: Int, snr: Int, minutes: Int, peer: String?, lat: Double? = null, lon: Double? = null) =
                RepeaterNeighbor(
                    hint = Octets(byteArrayOf((hint shr 8).toByte(), hint.toByte())),
                    hintText = text,
                    name = name,
                    rssiDbm = rssi,
                    snrQuarterDb = snr,
                    lastHeardMinutes = minutes,
                    latitude = lat,
                    longitude = lon,
                    locationPrecision = if (lat != null) 9 else null,
                    regionCodes = emptyList(),
                    reportedAtMs = now,
                    peerAddress = peer,
                )
            return CompletableDeferred(
                RepeaterListing(
                    entries = listOf(
                        neighbor(0x1234, "EUzY", null, -88, 30, 4, RELAY, 44.0, -123.1),
                        neighbor(0x8C01, "8C*", null, -95, 12, 20, null),
                        neighbor(0xB070, "Bq7d", "Skinner Ridge", -96, 14, 60, null),
                        neighbor(0xC0B0, "Cb*", "Coburg Hills", -104, -14, 26 * 60, null),
                    ),
                    total = 9,
                    nextCursor = Octets(byteArrayOf(0, 1, 4)),
                    asOfMs = now,
                ),
            )
        }
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 800L
        const val NO_ANSWER_BUDGET_MS = 150_000L
        const val HEARD_BUDGET_MS = 40_000L
        const val PING_TRIES = 3

        fun address(seed: Int) = MobileIdentity.unlock(ByteArray(32) { seed.toByte() }).use { it.publicIdentity().canonicalAddress }

        val TALLAC = address(0x22)
        val RELAY = address(0x77)
    }
}
