package com.voria.umsh.features

import android.Manifest
import android.content.Intent
import android.graphics.Bitmap
import android.os.Build
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.Tags
import com.voria.umsh.models.PingOutcome
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import java.io.File
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/**
 * Ping over `make android-bridge` (gated: `-e bridge <address>` names
 * `umshctl`'s own node on the bridge's "peer" host, which must be running
 * with `phy on`). The live core reaches the bridge's "phone" host. Once
 * this logs `READY phone=<address>`, the run sends to that address from the
 * peer host and then keeps it listening (`umshctl listen --from <address>`).
 * The reply crosses one radio link and carries the phone radio's reading of
 * it. Once through the runtime, then from the peer page's sheet.
 */
class PingBridgeTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createEmptyComposeRule()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val peer: String? get() = InstrumentationRegistry.getArguments().getString("bridge")

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }

    private fun description(tag: String): String =
        compose.onAllNodesWithTag(tag).fetchSemanticsNodes().singleOrNull()
            ?.config?.getOrNull(SemanticsProperties.ContentDescription)?.joinToString().orEmpty()

    @Test
    fun aPingCrossesOneHopWithItsSignal() {
        val address = peer
        assumeTrue("needs -e bridge <address>", address != null)
        address!!
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
        runBlocking {
            fresh.host.preferences.setNotificationsAsked()
            fresh.host.preferences.radioRegistry.bind(BoundRadio(RadioKind.Tcp, BRIDGE))
        }
        val scenario = ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java))
        val runtime = runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime.setOnboarding(OnboardingStep.Done).await()
            withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
            ready.runtime.core.savePeer(address, null, true)
            ready.runtime.reload(full = true).await()
            ready.runtime
        }
        // The run reads this line, sends to the phone from the peer host, then keeps that
        // host listening for the phone: a unicast names its sender only by hint, so each
        // side must hold the other's key before the ping's answer can be read.
        android.util.Log.i(TAG, "READY phone=${runtime.identity.value.address}")
        runBlocking {
            withTimeout(HEARD_TIMEOUT) { runtime.appState.first { state -> state?.peers?.any { it.address == address && it.lastHeardAtMs != null } == true } }
        }
        android.util.Log.i(TAG, "heard the peer host")
        Thread.sleep(LISTEN_SETTLE_MS)

        val outcome = runBlocking { runtime.ping(address).await() }
        android.util.Log.i(TAG, "runtime ping: $outcome")
        assertTrue("a reply: $outcome", outcome is PingOutcome.Reply)
        val reply = (outcome as PingOutcome.Reply).reply
        assertEquals(1, reply.hopCount)
        assertTrue("no repeaters named: ${reply.routeHints}", reply.routeHints.isEmpty())
        assertTrue("the phone radio's reading: ${reply.ownSignal}", !reply.ownSignal.isBridged)

        waitForTag(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitForTag(Tags.PEERS_LIST)
        compose.onNodeWithTag(Tags.PEERS_LIST).performScrollToNode(hasTestTag(Tags.peerRow(address)))
        compose.onNodeWithTag(Tags.peerRow(address)).performClick()
        waitForTag(Tags.PEER_VERB_PING)
        compose.onNodeWithTag(Tags.PEER_VERB_PING).performClick()
        val replied = context.getString(R.string.ping_reply_spoken_bare)
        compose.waitUntil(PING_TIMEOUT) { description(Tags.PING_RESULT).startsWith(replied) }
        android.util.Log.i(TAG, "sheet reads: ${description(Tags.PING_RESULT)}")
        shot()
        scenario.onActivity { it.finish() }
    }

    private fun shot() {
        compose.waitForIdle()
        Thread.sleep(800)
        val bitmap = instrumentation.uiAutomation.takeScreenshot() ?: return
        val directory = File(context.getExternalFilesDir(null), "shots").apply { mkdirs() }
        File(directory, "ping-bridge.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    private companion object {
        const val TAG = "PingBridgeTest"
        const val BRIDGE = "10.0.2.2:21838"
        const val TIMEOUT = 30_000L
        const val PING_TIMEOUT = 90_000L
        const val HEARD_TIMEOUT = 180_000L

        /** Time for the run to attach the peer host's listener after its send. */
        const val LISTEN_SETTLE_MS = 10_000L
    }
}
