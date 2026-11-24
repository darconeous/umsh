package com.voria.umsh.features

import android.Manifest
import android.content.Intent
import android.os.Build
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.Tags
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/**
 * Announce my identity over `make android-bridge` (gated: `-e announce
 * <seconds>`, how long the run needs to attach a capture on the bridge's
 * "peer" host after this logs `READY phone=<address>`). The live core
 * reaches the bridge's "phone" host; Discover's Announce, confirmed, sends
 * the advertisement over the simulated air, where the capture hears it.
 */
class AnnounceBridgeTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createEmptyComposeRule()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val settleSeconds: Long? get() = InstrumentationRegistry.getArguments().getString("announce")?.toLongOrNull()

    private fun present(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    @Test
    fun announcingReachesTheAir() {
        val settle = settleSeconds
        assumeTrue("needs -e announce <seconds>", settle != null)
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
            ready.runtime
        }
        android.util.Log.i(TAG, "READY phone=${runtime.identity.value.address}")
        Thread.sleep(settle!! * 1_000)

        waitForTag(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        compose.waitUntil(TIMEOUT) { present(Tags.PEERS_LIST) || present(Tags.PEERS_EMPTY_DISCOVER) }
        if (present(Tags.PEERS_LIST)) {
            compose.onNodeWithTag(Tags.PEERS_LIST).performScrollToNode(hasTestTag(Tags.PEERS_DISCOVER))
            compose.onNodeWithTag(Tags.PEERS_DISCOVER).performClick()
        } else {
            compose.onNodeWithTag(Tags.PEERS_EMPTY_DISCOVER).performClick()
        }
        waitForTag(Tags.DISCOVER_ANNOUNCE)
        compose.onNodeWithTag(Tags.DISCOVER_ANNOUNCE).performScrollTo().performClick()
        waitForTag(Tags.CONFIRM_DIALOG)
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        compose.waitUntil(TIMEOUT) { !present(Tags.CONFIRM_DIALOG) }
        android.util.Log.i(TAG, "ANNOUNCED")
        Thread.sleep(AFTER_MS)
        assertTrue("announced without a failure", !present(Tags.FAILURE_DIALOG))
        scenario.onActivity { it.finish() }
    }

    private companion object {
        const val TAG = "AnnounceBridgeTest"
        const val BRIDGE = "10.0.2.2:21838"
        const val TIMEOUT = 30_000L
        const val AFTER_MS = 5_000L
    }
}
