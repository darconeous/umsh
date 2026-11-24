package com.voria.umsh.features

import android.Manifest
import android.content.Intent
import android.os.Build
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextInput
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.Tags
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.services.preferences.OnboardingStep
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * The draft in the real activity: a recreation (rotation, or the saved
 * state a process restored after death reads back) keeps the unsaved
 * hops, the flood, and the Add hop page open over the editor with its
 * filter.
 */
class ManualPathActivityTest {
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

    private fun present(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun hopTags() = compose.onAllNodes(SemanticsMatcher("a hop") { node ->
        node.config.getOrNull(SemanticsProperties.TestTag)?.startsWith("manual_path_hop_") == true
    }).fetchSemanticsNodes().map { it.config[SemanticsProperties.TestTag] }

    private fun floodValue(): String? = compose.onNodeWithTag(Tags.MANUAL_PATH_FLOOD).fetchSemanticsNode().config.getOrNull(SemanticsProperties.StateDescription)

    @Test
    fun theDraftAndItsPageSurviveARecreation() {
        val scenario = ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_STAGING, true))
        runtime()
        waitForTag(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitForTag(Tags.PEERS_LIST)
        compose.onNodeWithTag(Tags.PEERS_LIST).performScrollToNode(hasTestTag(Tags.peerRow(MAYA)))
        compose.onNodeWithTag(Tags.peerRow(MAYA)).performClick()
        waitForTag(Tags.PEER_GLANCE_ROUTE)
        compose.onNodeWithTag(Tags.PEER_GLANCE_ROUTE).performClick()
        waitForTag(Tags.ROUTE_EDIT)
        compose.onNodeWithTag(Tags.ROUTE_EDIT).performClick()
        waitForTag(Tags.MANUAL_PATH_PEER)

        // One hop from Known repeaters, the flood up one, then Add hop again with a filter typed.
        compose.onNodeWithTag(Tags.MANUAL_PATH_ADD_HOP).performScrollTo().performClick()
        waitForTag(Tags.ADD_HOP_PAGE)
        compose.onNodeWithTag(Tags.ADD_HOP_TAB_KNOWN).performClick()
        waitForTag(Tags.addHopKnown(TALLAC))
        compose.onNodeWithTag(Tags.addHopKnown(TALLAC)).performClick()
        compose.waitUntil(TIMEOUT) { present(Tags.ADD_HOP_CRUMB) && compose.onAllNodesWithTag(Tags.ADD_HOP_CRUMB).fetchSemanticsNodes().any { node -> node.config.getOrNull(SemanticsProperties.Text).orEmpty().any { "Tallac" in it.text } } }
        compose.onNodeWithTag(Tags.ADD_HOP_DONE).performClick()
        waitForTag(Tags.MANUAL_PATH_PEER)
        compose.onNodeWithTag(Tags.MANUAL_PATH_FLOOD_MORE, useUnmergedTree = true).performScrollTo().performClick()
        val hops = hopTags()
        val flood = floodValue()
        assertEquals(1, hops.size)
        assertEquals(context.resources.getQuantityString(R.plurals.route_hops, 2, 2), flood)
        compose.onNodeWithTag(Tags.MANUAL_PATH_ADD_HOP).performScrollTo().performClick()
        waitForTag(Tags.ADD_HOP_PAGE)
        compose.onNodeWithTag(Tags.ADD_HOP_TAB_KNOWN).performClick()
        compose.onNodeWithTag(Tags.ADD_HOP_FILTER).performTextInput("Glen")

        scenario.recreate()
        waitForTag(Tags.ADD_HOP_PAGE)
        compose.onNodeWithTag(Tags.ADD_HOP_TAB_KNOWN).assertIsSelected()
        assertTrue(
            "the filter kept",
            compose.onNodeWithTag(Tags.ADD_HOP_FILTER).fetchSemanticsNode().config.getOrNull(SemanticsProperties.EditableText)?.text == "Glen",
        )
        compose.onNodeWithTag(Tags.ADD_HOP_DONE).performClick()
        waitForTag(Tags.MANUAL_PATH_PEER)
        assertEquals(hops, hopTags())
        assertEquals(flood, floodValue())
        scenario.close()
    }

    private companion object {
        const val TIMEOUT = 30_000L

        fun address(seed: Int) = MobileIdentity.unlock(ByteArray(32) { seed.toByte() }).use { it.publicIdentity().canonicalAddress }

        val TALLAC = address(0x22)
        val MAYA = address(0x11)
    }
}
