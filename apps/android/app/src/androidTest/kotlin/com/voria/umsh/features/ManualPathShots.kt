package com.voria.umsh.features

import android.graphics.Bitmap
import android.view.inputmethod.InputMethodManager
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.TestUmshApplication
import com.voria.umsh.app.Tags
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.inspectPublicIdentity
import com.voria.umsh.models.ManualPath
import com.voria.umsh.models.Octets
import com.voria.umsh.services.location.LocationGrant
import com.voria.umsh.services.location.PhoneFix
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
 * Screenshots of `manual-path.svg` 1–7 for the build report, in the real
 * app root over the staged air. Off unless the run passes `-e shots
 * <suffix>`, the suffix naming the device's appearance; they land in the
 * app's external files, under `shots/`.
 */
class ManualPathShots {
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

    private fun present(tag: String) = compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()

    private fun waitFor(tag: String, timeout: Long = TIMEOUT) = compose.waitUntil(timeout) { present(tag) }

    private fun hideKeyboard() = compose.runOnUiThread {
        val view = compose.activity.window.decorView
        view.context.getSystemService(InputMethodManager::class.java).hideSoftInputFromWindow(view.windowToken, 0)
    }

    /** Sam's route editor, Sam found through search. */
    private fun openSamEditor() {
        waitFor(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitFor(Tags.PEERS_SEARCH)
        compose.onNodeWithTag(Tags.PEERS_SEARCH).performClick()
        compose.onNodeWithTag(Tags.PEERS_SEARCH_FIELD).performTextInput("Sam")
        waitFor(Tags.peerRow(SAM))
        hideKeyboard()
        compose.onNodeWithTag(Tags.peerRow(SAM)).performClick()
        waitFor(Tags.PEER_GLANCE_ROUTE)
        compose.onNodeWithTag(Tags.PEER_GLANCE_ROUTE).performClick()
        waitFor(Tags.ROUTE_EDIT)
        compose.onNodeWithTag(Tags.ROUTE_EDIT).performClick()
        waitFor(Tags.MANUAL_PATH_PEER)
    }

    /** Boards 1–6 in one pass: the editor after a ping along it, Add hop, the two hint pages, a direct path, and the discard ask. */
    @Test
    fun editor() {
        val runtime = start()
        runBlocking { runtime.setManualPath(SAM, ManualPath(listOf(Octets(RELAY_HINT)), floodHops = 1), HOUR_MS).await() }
        openSamEditor()
        compose.onNodeWithTag(Tags.MANUAL_PATH_PING).performScrollTo().performClick()
        val replied = context.getString(R.string.manual_path_replied, "").trim()
        compose.waitUntil(TIMEOUT) {
            compose.onAllNodesWithTag(Tags.MANUAL_PATH_PING_RESULT).fetchSemanticsNodes().isNotEmpty() &&
                compose.onAllNodes(androidx.compose.ui.test.hasTestTag(Tags.MANUAL_PATH_PING_RESULT) and androidx.compose.ui.test.hasText(replied, substring = true)).fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag(Tags.MANUAL_PATH_HEADER).performScrollTo()
        shot("manual-path-1")

        // Boards 4 and 5, from Add hop 2: Tallac Ridge's prefix (a node not
        // yet on the path, so Add is enabled), then a prefix two hints fit.
        compose.onNodeWithTag(Tags.MANUAL_PATH_ADD_HOP).performScrollTo().performClick()
        waitFor(Tags.ADD_HOP_PAGE)
        compose.onNodeWithTag(Tags.ADD_HOP_ENTER_HINT).performScrollTo().performClick()
        waitFor(Tags.HINT_ENTRY_PAGE)
        compose.onNodeWithTag(Tags.HINT_ENTRY_FIELD).performTextInput(TALLAC.take(5))
        waitFor(Tags.HINT_ENTRY_KNOWN)
        shot("manual-path-4")
        val (prefix, candidates) = twoHintPrefix()
        compose.onNodeWithTag(Tags.HINT_ENTRY_FIELD).performTextReplacement(prefix)
        waitFor(Tags.hintCandidate(candidates[1]))
        shot("manual-path-5")
        hideKeyboard()
        compose.onNodeWithTag(Tags.DIALOG_CLOSE).performClick()
        compose.waitUntil(TIMEOUT) { !present(Tags.HINT_ENTRY_PAGE) }

        // Board 3: Tallac Ridge from Known repeaters, then its neighbors on Refresh.
        waitFor(Tags.ADD_HOP_TAB_KNOWN)
        compose.onNodeWithTag(Tags.ADD_HOP_TAB_KNOWN).performClick()
        waitFor(Tags.addHopKnown(TALLAC))
        compose.onNodeWithTag(Tags.addHopKnown(TALLAC)).performClick()
        waitFor(Tags.ADD_HOP_REFRESH)
        compose.onNodeWithTag(Tags.ADD_HOP_REFRESH).performClick()
        waitFor(Tags.addHopNeighbor(Octets(inspectPublicIdentity(RELAY).hint.bytes).hex()))
        shot("manual-path-3")
        compose.onNodeWithTag(Tags.ADD_HOP_DONE).performClick()
        waitFor(Tags.MANUAL_PATH_PEER)

        // Board 6: the discard ask over the changed draft.
        compose.onNodeWithTag(Tags.DIALOG_CLOSE).performClick()
        waitFor(Tags.CONFIRM_DIALOG)
        shot("manual-path-6")
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        compose.waitUntil(TIMEOUT) { !present(Tags.MANUAL_PATH_PAGE) }

        // Board 2: every hop removed, a direct path.
        compose.onNodeWithTag(Tags.ROUTE_EDIT).performClick()
        waitFor(Tags.MANUAL_PATH_PEER)
        compose.onNodeWithTag(Tags.manualPathRemove(Octets(RELAY_HINT).hex())).performClick()
        compose.waitUntil(TIMEOUT) { !present(Tags.manualPathHop(Octets(RELAY_HINT).hex())) }
        shot("manual-path-2")
    }

    /** Board 7: P3a's recipe, the prompt over Sam's thread. */
    @Test
    fun learnedPathPrompt() {
        val runtime = start()
        val location = (context.applicationContext as TestUmshApplication).testLocation
        location.grant.value = LocationGrant.Precise
        location.readings.tryEmit(PhoneFix(38.9, -120.1, accuracyMeters = 10.0, approximate = false))
        runBlocking { runtime.setManualPath(SAM, ManualPath(listOf(Octets(byteArrayOf(0x00, 0x01))), floodHops = 2), HOUR_MS).await() }
        location.readings.tryEmit(PhoneFix(38.903, -120.1, accuracyMeters = 10.0, approximate = false))
        val conversation = runBlocking { runtime.startConversation(SAM).await() }
        waitFor(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_CONVERSATIONS)[0].performClick()
        waitFor(Tags.conversationRow(conversation))
        compose.onNodeWithTag(Tags.conversationRow(conversation)).performClick()
        waitFor(Tags.THREAD)
        runBlocking { runtime.send(conversation, "Which way from here?", null).await() }
        waitFor(Tags.LEARNED_PATH_USE, LEARNED_BUDGET_MS)
        Thread.sleep(1_000)
        shot("manual-path-7")
    }

    private companion object {
        const val TIMEOUT = 90_000L
        const val SETTLE_MS = 800L
        const val LEARNED_BUDGET_MS = 90_000L
        const val HOUR_MS = 3_600_000L

        fun address(seed: Int) = MobileIdentity.unlock(ByteArray(32) { seed.toByte() }).use { it.publicIdentity().canonicalAddress }

        val SAM = address(0x66)
        val RELAY = address(0x77)
        val TALLAC = address(0x22)
        val RELAY_HINT: ByteArray = inspectPublicIdentity(RELAY).hint.bytes.copyOf(2)
    }
}
