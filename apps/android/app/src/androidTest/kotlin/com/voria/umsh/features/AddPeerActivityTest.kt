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
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.Tags
import com.voria.umsh.services.preferences.OnboardingStep
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Add peer in the real activity across a recreation (§2.2): the field and
 * the open preview with its typed name come back, and nothing is saved by
 * coming back.
 */
class AddPeerActivityTest {
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
        withTimeout(TIMEOUT) { ready.runtime.appState.first { it != null } }
        ready.runtime
    }

    private fun present(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun editable(tag: String): String? =
        compose.onNodeWithTag(tag).fetchSemanticsNode().config.getOrNull(SemanticsProperties.EditableText)?.text

    @Test
    fun theFieldAndThePreviewSurviveARecreation() {
        val scenario = ActivityScenario.launch<MainActivity>(Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_STAGING, true))
        val runtime = runtime()
        waitForTag(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitForTag(Tags.PEERS_ADD)
        compose.onNodeWithTag(Tags.PEERS_ADD).performClick()
        waitForTag(Tags.ADD_PEER)
        val signed = ImportFixtures.signedLink(0x61)
        compose.onNodeWithTag(Tags.ADD_PEER_FIELD).performTextReplacement(signed.link)
        // Below Nearby, and on a 320 dp phone under the keyboard: scrolled to, as a holder would.
        compose.onNodeWithTag(Tags.ADD_PEER_PREVIEW).performScrollTo().performClick()
        waitForTag(Tags.IMPORT_SHEET)
        compose.onNodeWithTag(Tags.IMPORT_NAME).performScrollTo().performTextReplacement("Ridge marmot")

        scenario.recreate()
        waitForTag(Tags.IMPORT_SHEET)
        assertEquals("Ridge marmot", editable(Tags.IMPORT_NAME))
        assertNull(runtime.appState.value!!.peers.firstOrNull { it.address == signed.address })

        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(android.view.KeyEvent.KEYCODE_BACK)
        compose.waitUntil(TIMEOUT) { !present(Tags.IMPORT_SHEET) }
        assertEquals(signed.link, editable(Tags.ADD_PEER_FIELD))
        assertNull(runtime.appState.value!!.peers.firstOrNull { it.address == signed.address })
        scenario.close()
    }

    private companion object {
        const val TIMEOUT = 30_000L
    }
}
