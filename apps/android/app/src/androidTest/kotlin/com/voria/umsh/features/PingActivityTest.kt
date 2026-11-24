package com.voria.umsh.features

import android.Manifest
import android.content.Intent
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
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.Tags
import com.voria.umsh.app.setRemoteDeviceReachable
import com.voria.umsh.app.stagedAir
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.services.preferences.OnboardingStep
import java.text.NumberFormat
import java.util.Locale
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * The recreation rule in the real activity: rotating (a real recreation)
 * while a ping is waited on keeps the sheet on that same ping. A second
 * ping would start the count over, so the count after the recreation still
 * reads past the time waited before it.
 */
class PingActivityTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createEmptyComposeRule()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun noNotificationAsk() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            InstrumentationRegistry.getInstrumentation().uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
        runBlocking { fresh.host.preferences.setNotificationsAsked() }
    }

    private fun runtime(): AppRuntime = runBlocking {
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        ready.runtime.setOnboarding(OnboardingStep.Done).await()
        withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
        withTimeout(TIMEOUT) { ready.runtime.appState.first { state -> state?.peers?.any { it.address == TALLAC } == true } }
        ready.runtime
    }

    private fun waitForUnmerged(tag: String) =
        compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty() }

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }

    /** The elapsed count on show, in seconds. */
    private fun elapsedSeconds(): Double {
        val text = compose.onNodeWithTag(Tags.PING_ELAPSED, useUnmergedTree = true).fetchSemanticsNode().config.getOrNull(SemanticsProperties.Text)!!.single().text
        return NumberFormat.getNumberInstance(Locale.getDefault()).parse(text.substringBefore(' '))!!.toDouble()
    }

    @Test
    fun rotatingWhileWaitingKeepsTheSamePing() {
        val scenario = ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_STAGING, true))
        runtime()
        fresh.stagedAir.setRemoteDeviceReachable(false)
        waitForTag(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitForTag(Tags.PEERS_LIST)
        compose.onNodeWithTag(Tags.PEERS_LIST).performScrollToNode(hasTestTag(Tags.peerRow(TALLAC)))
        compose.onNodeWithTag(Tags.peerRow(TALLAC)).performClick()
        waitForTag(Tags.PEER_VERB_PING)
        compose.onNodeWithTag(Tags.PEER_VERB_PING).performClick()
        waitForUnmerged(Tags.PING_ELAPSED)
        compose.waitUntil(TIMEOUT) { elapsedSeconds() >= WAITED_S }

        scenario.recreate()
        waitForTag(Tags.PING_SHEET)
        waitForUnmerged(Tags.PING_ELAPSED)
        val after = elapsedSeconds()
        assertTrue("the count went on from $WAITED_S s: $after s", after >= WAITED_S)
        scenario.close()
    }

    private companion object {
        const val TIMEOUT = 30_000L

        /** Waited before the recreation: well past what a new ping's count could reach by the time it is read. */
        const val WAITED_S = 4.0

        val TALLAC = MobileIdentity.unlock(ByteArray(32) { 0x22 }).use { it.publicIdentity().canonicalAddress }
    }
}
