package com.voria.umsh.features

import android.Manifest
import android.content.Intent
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
import com.voria.umsh.models.MeetExchange
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/**
 * Two phones exchanging contacts over `make android-bridge
 * ANDROID_BRIDGE_LAN=` (gated: `-e exchangeBridge asker|answerer`, with
 * `-e port` the bridge host interface and `-e ending same|different`).
 * Each opens Peers › Add peer and waits for the other on Nearby (`NEARBY`);
 * once both have, the run writes `go.txt` into the asker's files, the
 * asker taps its row, and the answerer takes the ask from its sheet. Each logs the
 * code it shows (`CODE`), which the run compares. With `same`, both press
 * Same and each lands on the other's page (`LANDED`, against the other's
 * `OWN`). With `different`, the asker presses Different, and both end on
 * "Codes differ. Nothing saved." (`ENDED`) with nothing stored.
 */
class ExchangeBridgeTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createEmptyComposeRule()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val arguments get() = InstrumentationRegistry.getArguments()

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String, timeout: Long = TIMEOUT) = compose.waitUntil(timeout) { present(tag) }

    private fun text(tag: String): String = compose.onNodeWithTag(tag, useUnmergedTree = true).fetchSemanticsNode().config
        .getOrNull(SemanticsProperties.Text)?.joinToString("") { it.text }.orEmpty()

    private fun launch(port: Int): AppRuntime {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
        runBlocking {
            fresh.host.preferences.setNotificationsAsked()
            fresh.host.preferences.radioRegistry.bind(BoundRadio(RadioKind.Tcp, "10.0.2.2:$port"))
        }
        ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java))
        return runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime.setOnboarding(OnboardingStep.Done).await()
            withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
            ready.runtime
        }
    }

    @Test
    fun exchange() {
        val role = arguments.getString("exchangeBridge")
        assumeTrue("needs -e exchangeBridge asker|answerer", role == "asker" || role == "answerer")
        val port = arguments.getString("port")!!.toInt()
        val ending = arguments.getString("ending") ?: "same"
        val runtime = launch(port)
        val own = runtime.identity.value.address
        log("OWN $own")
        val peersBefore = runtime.appState.value?.peers?.map { it.address }?.toSet().orEmpty()

        waitForTag(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitForTag(Tags.PEERS_ADD)
        compose.onNodeWithTag(Tags.PEERS_ADD).performClick()
        waitForTag(Tags.ADD_PEER)

        // Each sees the other on Nearby.
        waitForTag(Tags.NEARBY_DEVICE, MEET_TIMEOUT)
        val other = runtime.meet.value!!.devices.first()
        log("NEARBY model=${other.model} nearness=${other.nearness} own-color=${runtime.meet.value!!.ownColorRgb?.let { "%06x".format(it) }}")

        val codes = java.util.concurrent.CopyOnWriteArrayList<Int>()
        val watcher = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch {
            runtime.meet.collect { meet -> (meet?.exchange as? MeetExchange.Comparing)?.let { codes += it.code } }
        }
        if (role == "asker") {
            // Only once the other lists this phone too (the run reads both NEARBY lines): an
            // ask can otherwise reach it before this phone's Hello, and it is asked by a
            // device its Nearby never showed.
            runBlocking { awaitFile("go.txt") }
            compose.onNodeWithTag(Tags.NEARBY_DEVICE).performClick()
        } else {
            waitForTag(Tags.EXCHANGE_ACCEPT, MEET_TIMEOUT)
            log("ASKED")
            compose.onNodeWithTag(Tags.EXCHANGE_ACCEPT).performClick()
        }

        if (ending == "different" && role == "answerer") {
            // The other presses Different as soon as its code shows, so this
            // side's code may be up for only a moment: the code is read from
            // the exchange as it passes.
            compose.waitUntil(MEET_TIMEOUT) { present(Tags.EXCHANGE_ENDED) }
            log("CODE ${codes.firstOrNull()}")
        } else {
            waitForTag(Tags.EXCHANGE_CODE, MEET_TIMEOUT)
            val comparing = runtime.meet.value!!.exchange as MeetExchange.Comparing
            log("CODE ${comparing.code} shown=${text(Tags.EXCHANGE_CODE).filter { it.isDigit() }}")
        }
        watcher.cancel()

        if (ending == "different") {
            if (role == "asker") compose.onNodeWithTag(Tags.EXCHANGE_DIFFERENT).performClick()
            compose.waitUntil(MEET_TIMEOUT) { present(Tags.EXCHANGE_ENDED) }
            val ended = text(Tags.EXCHANGE_ENDED)
            log("ENDED $ended")
            assertEquals(context.getString(com.voria.umsh.R.string.exchange_codes_differ), ended)
            assertEquals("nothing saved", peersBefore, runtime.appState.value?.peers?.map { it.address }?.toSet().orEmpty())
            return
        }

        compose.onNodeWithTag(Tags.EXCHANGE_SAME).performClick()
        val exchanged = runBlocking {
            withTimeout(MEET_TIMEOUT) { runtime.meet.first { it?.exchange is MeetExchange.Exchanged } }!!.exchange as MeetExchange.Exchanged
        }
        waitForTag(Tags.PEER_PAGE, MEET_TIMEOUT)
        val stored = runtime.appState.value!!.peers.first { it.address == exchanged.peerAddress }
        log("LANDED ${exchanged.peerAddress} signed=${exchanged.signed} saved=${stored.isSaved} new=${exchanged.peerAddress !in peersBefore}")
        // Stay up while the other side's last frames arrive.
        Thread.sleep(SETTLE_MS)
    }

    private suspend fun awaitFile(name: String) {
        val file = java.io.File(context.getExternalFilesDir(null), name)
        withTimeout(MEET_TIMEOUT) { while (!file.exists()) kotlinx.coroutines.delay(POLL_MS) }
        file.delete()
    }

    private fun log(line: String) = android.util.Log.i(TAG, line)

    private companion object {
        const val TAG = "ExchangeBridgeTest"
        const val TIMEOUT = 30_000L
        const val MEET_TIMEOUT = 120_000L
        const val SETTLE_MS = 5_000L
        const val POLL_MS = 200L
    }
}
