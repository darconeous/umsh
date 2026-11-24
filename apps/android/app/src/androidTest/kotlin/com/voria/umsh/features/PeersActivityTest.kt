package com.voria.umsh.features

import android.Manifest
import android.content.Intent
import android.os.Build
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.Tags
import com.voria.umsh.features.peers.PeerSort
import com.voria.umsh.services.preferences.OnboardingStep
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/** The Peers order across a restart, and a Next time heard notice's tap, in the real activity. */
class PeersActivityTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createEmptyComposeRule()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    /** Android's notification dialog would cover the activity: this test is not about it. */
    @Before
    fun noNotificationAsk() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            InstrumentationRegistry.getInstrumentation().uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
        runBlocking { fresh.host.preferences.setNotificationsAsked() }
    }

    private fun launch(): ActivityScenario<MainActivity> = ActivityScenario.launch(
        Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_STAGING, true),
    )

    private fun runtime(): AppRuntime = runBlocking {
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        ready.runtime.setOnboarding(OnboardingStep.Done).await()
        withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
        withTimeout(TIMEOUT) { ready.runtime.appState.first { state -> state?.peers?.any { !it.isSaved && !it.isCompanionRadio } == true } }
        ready.runtime
    }

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }

    private fun sortChipText(): List<String> =
        compose.onAllNodes(hasTestTag(Tags.PEERS_SORT) or hasAnyAncestor(hasTestTag(Tags.PEERS_SORT)), useUnmergedTree = true)
            .fetchSemanticsNodes().flatMap { node -> node.config.getOrNull(SemanticsProperties.Text).orEmpty().map { it.text } }

    @Test
    fun theOrderIsRememberedAcrossARestart() {
        val first = launch()
        runtime()
        compose.onNodeWithTag(Tags.NAV_PEERS).performClick()
        waitForTag(Tags.PEERS_SORT)
        compose.onNodeWithTag(Tags.PEERS_SORT).performClick()
        compose.onNodeWithTag(Tags.peersSortOption(PeerSort.LatestMessage.name)).performClick()
        compose.waitUntil(TIMEOUT) { runBlocking { fresh.host.preferences.peersSort.first() } == PeerSort.LatestMessage.name }
        first.close()

        val again = launch()
        runtime()
        compose.onNodeWithTag(Tags.NAV_PEERS).performClick()
        waitForTag(Tags.PEERS_SORT)
        val latest = context.getString(R.string.peers_sort_latest_message)
        compose.waitUntil(TIMEOUT) { latest in sortChipText() }
        again.close()
    }

    /**
     * Notification taps: a node that sends no text opens its page on Peers;
     * one that does opens its conversation.
     */
    @Test
    fun aHeardNoticeOpensThePageOrTheConversation() {
        val scenario = launch()
        val runtime = runtime()
        val relay = runtime.appState.value!!.peers.first { it.advertisedName == "Glen Alpine Relay" }
        scenario.onActivity { it.takeRequest(MainActivity.peerIntent(it, relay.address)) }
        waitForTag(Tags.PEER_PAGE)
        // Peers is selected beneath it.
        compose.onNodeWithTag(Tags.NAV_PEERS).assertIsSelected()

        val maya = runtime.appState.value!!.peers.first { it.advertisedName == "Maya Ortiz" }
        scenario.onActivity { it.takeRequest(MainActivity.peerIntent(it, maya.address)) }
        waitForTag(Tags.THREAD)
        assertTrue(runtime.appState.value!!.directConversations.any { it.peer.address == maya.address })
        scenario.close()
    }

    private companion object {
        const val TIMEOUT = 30_000L
    }
}
