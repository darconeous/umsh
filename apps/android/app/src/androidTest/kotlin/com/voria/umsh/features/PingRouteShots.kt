package com.voria.umsh.features

import android.graphics.Bitmap
import android.view.KeyEvent
import android.view.inputmethod.InputMethodManager
import androidx.activity.ComponentActivity
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextInput
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.Tags
import com.voria.umsh.app.setRemoteDeviceReachable
import com.voria.umsh.app.stagedAir
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.models.ManualPath
import com.voria.umsh.models.Octets
import com.voria.umsh.core.inspectPublicIdentity
import com.voria.umsh.services.preferences.OnboardingStep
import java.io.File
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Screenshots of `ping-route.svg` 1–5 for the build report, in the real
 * app root over the staged air. Off unless the run passes `-e shots
 * <suffix>`, the suffix naming the device's appearance. They land in the
 * app's external files, under `shots/`. Board 3 waits out the core's ping
 * timeout (about 68 s).
 */
class PingRouteShots {
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

    private fun start(): AppRuntime {
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
            withTimeout(TIMEOUT) { ready.runtime.appState.first { state -> state?.peers?.any { it.address == SAM } == true } }
            ready.runtime
        }
        compose.setContent { AppRoot(fresh.host) }
        return runtime
    }

    private fun waitForUnmerged(tag: String) =
        compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty() }

    private fun waitFor(tag: String, timeout: Long = TIMEOUT) =
        compose.waitUntil(timeout) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }

    private fun description(tag: String): String =
        compose.onAllNodesWithTag(tag).fetchSemanticsNodes().singleOrNull()
            ?.config?.getOrNull(SemanticsProperties.ContentDescription)?.joinToString().orEmpty()

    private fun back() {
        compose.waitForIdle()
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
        compose.waitForIdle()
    }

    private fun hideKeyboard() = compose.runOnUiThread {
        val view = compose.activity.window.decorView
        view.context.getSystemService(InputMethodManager::class.java).hideSoftInputFromWindow(view.windowToken, 0)
    }

    /** Sam is heard, not saved: found through search. */
    private fun openSam() {
        waitFor(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitFor(Tags.PEERS_SEARCH)
        compose.onNodeWithTag(Tags.PEERS_SEARCH).performClick()
        compose.onNodeWithTag(Tags.PEERS_SEARCH_FIELD).performTextInput("Sam")
        waitFor(Tags.peerRow(SAM))
        hideKeyboard()
        compose.onNodeWithTag(Tags.peerRow(SAM)).performClick()
        waitFor(Tags.PEER_PAGE)
    }

    private fun waitForReply() {
        val replied = context.getString(R.string.ping_reply_spoken_bare)
        compose.waitUntil(TIMEOUT) { description(Tags.PING_RESULT).startsWith(replied) }
    }

    @Test
    fun pingAndRoute() {
        val runtime = start()
        openSam()
        compose.onNodeWithTag(Tags.PEER_VERB_PING).performClick()
        waitForReply()
        compose.onNodeWithTag(Tags.PING_AGAIN).performClick()
        waitFor(Tags.PING_EARLIER_ROW)
        waitForReply()
        shot("ping-route-1")
        back()
        compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(Tags.PING_SHEET).fetchSemanticsNodes().isEmpty() }

        compose.onNodeWithTag(Tags.PEER_GLANCE_ROUTE).performClick()
        waitFor(Tags.ROUTE_PAGE)
        compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(Tags.ROUTE_EXPLANATION).fetchSemanticsNodes().isNotEmpty() }
        shot("ping-route-4")
        back()
        back()

        val relayHint = inspectPublicIdentity(RELAY).hint.bytes.copyOf(2)
        runBlocking {
            runtime.setManualPath(SAM, ManualPath(listOf(Octets(relayHint), Octets(byteArrayOf(0x00, 0x01))), floodHops = 1), 3_600_000L).await()
        }
        compose.onNodeWithTag(Tags.PEERS_SEARCH_RESULTS).performScrollToNode(hasTestTag(Tags.peerRow(SAM)))
        compose.onNodeWithTag(Tags.peerRow(SAM)).performClick()
        waitFor(Tags.PEER_PAGE)
        compose.onNodeWithTag(Tags.PEER_GLANCE_ROUTE).performClick()
        waitFor(Tags.ROUTE_HELD_UNTIL)
        shot("ping-route-5")
    }

    /** Boards 2 and 3: Tallac Ridge, made unreachable, waited on, then no reply after the core's wait. */
    @Test
    fun waitingAndNoReply() {
        start()
        fresh.stagedAir.setRemoteDeviceReachable(false)
        waitFor(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitFor(Tags.PEERS_LIST)
        compose.onNodeWithTag(Tags.PEERS_LIST).performScrollToNode(hasTestTag(Tags.peerRow(TALLAC)))
        compose.onNodeWithTag(Tags.peerRow(TALLAC)).performClick()
        waitFor(Tags.PEER_VERB_PING)
        compose.onNodeWithTag(Tags.PEER_VERB_PING).performClick()
        waitForUnmerged(Tags.PING_ELAPSED)
        Thread.sleep(1_000)
        shot("ping-route-2")
        val noReply = context.getString(R.string.ping_no_reply)
        compose.waitUntil(NO_REPLY_BUDGET_MS) { description(Tags.PING_RESULT) == noReply }
        shot("ping-route-3")
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 800L
        const val NO_REPLY_BUDGET_MS = 150_000L

        fun address(seed: Int) = MobileIdentity.unlock(ByteArray(32) { seed.toByte() }).use { it.publicIdentity().canonicalAddress }

        val SAM = address(0x66)
        val RELAY = address(0x77)
        val TALLAC = address(0x22)
    }
}
