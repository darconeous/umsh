package com.voria.umsh.features

import android.Manifest
import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.res.Configuration
import android.os.Build
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.Tags
import com.voria.umsh.app.stagedAir
import com.voria.umsh.core.MobileStagingAirException
import com.voria.umsh.features.peers.ExchangeCode
import com.voria.umsh.models.MeetExchange
import com.voria.umsh.services.preferences.OnboardingStep
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * The exchange in the real activity across a rotation: the same attempt,
 * the same code, the page still up, and the meet never closed by it.
 */
class ExchangeActivityTest {
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
        ready.runtime
    }

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun text(tag: String): String = compose.onNodeWithTag(tag, useUnmergedTree = true).fetchSemanticsNode().config
        .getOrNull(SemanticsProperties.Text)?.joinToString("") { it.text }.orEmpty()

    @Test
    fun aRotationWhileComparingKeepsTheExchange() {
        val scenario = ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_STAGING, true))
        val runtime = runtime()
        waitForTag(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitForTag(Tags.PEERS_ADD)
        compose.onNodeWithTag(Tags.PEERS_ADD).performClick()
        waitForTag(Tags.ADD_PEER)
        runBlocking {
            withTimeout(TIMEOUT) { runtime.meet.first { it?.exchange == MeetExchange.Idle } }
            withTimeout(TIMEOUT) {
                while (true) {
                    try {
                        fresh.stagedAir.air.peerOpensAddPeer(true)
                        break
                    } catch (_: MobileStagingAirException.NoPhone) {
                        delay(50)
                    }
                }
            }
        }
        waitForTag(Tags.EXCHANGE_ACCEPT)
        compose.onNodeWithTag(Tags.EXCHANGE_ACCEPT).performClick()
        waitForTag(Tags.EXCHANGE_SAME)
        val before = runtime.meet.value!!.exchange as MeetExchange.Comparing
        val shown = text(Tags.EXCHANGE_CODE)

        // A real rotation, both ways.
        for (orientation in listOf(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE, ActivityInfo.SCREEN_ORIENTATION_PORTRAIT)) {
            scenario.onActivity { it.requestedOrientation = orientation }
            // Let the recreation land before asking Compose anything: waiting
            // for idle across it can hang the test framework, not the app.
            val wanted = if (orientation == ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE) Configuration.ORIENTATION_LANDSCAPE else Configuration.ORIENTATION_PORTRAIT
            val deadline = System.currentTimeMillis() + TIMEOUT
            while (true) {
                var now = Configuration.ORIENTATION_UNDEFINED
                scenario.onActivity { now = it.resources.configuration.orientation }
                if (now == wanted) break
                if (System.currentTimeMillis() >= deadline) fail("orientation never became $wanted")
                Thread.sleep(100)
            }
            Thread.sleep(SETTLE_MS)
            waitForTag(Tags.EXCHANGE_SAME)
            val after = runtime.meet.value!!.exchange as MeetExchange.Comparing
            assertEquals("the same attempt", before.code, after.code)
            // The same device; its nearness is live, so it may move meanwhile.
            assertEquals(before.device.id, after.device.id)
            assertEquals(before.device.model, after.device.model)
            assertEquals(before.device.colorRgb, after.device.colorRgb)
            assertEquals(shown, text(Tags.EXCHANGE_CODE))
            assertEquals(ExchangeCode.grouped(before.code), shown.filter { it.isDigit() || it == ' ' })
        }

        // And it still finishes.
        compose.onNodeWithTag(Tags.EXCHANGE_SAME).performClick()
        waitForTag(Tags.PEER_PAGE)
        scenario.onActivity { it.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED }
        scenario.close()
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 1_500L
    }
}
