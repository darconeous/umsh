package com.voria.umsh.features

import android.graphics.Bitmap
import android.view.inputmethod.InputMethodManager
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.longClick
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.compose.ui.test.performTouchInput
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.Tags
import com.voria.umsh.features.peers.PeerSort
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
 * Screenshots of `peers-list.svg` and `peer-page.svg`, for the build
 * report. Off unless the run passes `-e shots <suffix>`; the suffix names
 * the appearance the device is set to. They land in the app's external
 * files, under `shots/`.
 */
class PeersShots {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val suffix: String? get() = InstrumentationRegistry.getArguments().getString("shots")

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

    private fun start(staging: Boolean): AppRuntime {
        runBlocking { fresh.host.preferences.setFallbackScheme(true) }
        fresh.host.ensureRuntime(staging = staging)
        val runtime = runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime.setOnboarding(OnboardingStep.Done).await()
            if (staging) {
                withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
                withTimeout(TIMEOUT) { ready.runtime.appState.first { state -> state?.peers?.any { !it.isSaved && !it.isCompanionRadio } == true } }
            }
            ready.runtime
        }
        compose.setContent { AppRoot(fresh.host) }
        return runtime
    }

    private fun hideKeyboard() = compose.runOnUiThread {
        val view = compose.activity.window.decorView
        view.context.getSystemService(InputMethodManager::class.java).hideSoftInputFromWindow(view.windowToken, 0)
    }

    private fun waitFor(tag: String) = compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty() }

    private fun address(runtime: AppRuntime, name: String) = runtime.appState.value!!.peers.first { it.advertisedName == name }.address

    private fun openPeers() {
        waitFor(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitFor(Tags.PEERS_LIST)
    }

    private fun row(address: String, list: String = Tags.PEERS_LIST) =
        compose.onNodeWithTag(list).performScrollToNode(hasTestTag(Tags.peerRow(address))).let { compose.onNodeWithTag(Tags.peerRow(address)) }

    /** Boards 1–5 of `peers-list.svg`: the list, the sort menu, search, long press and Remove. */
    @Test
    fun peersList() {
        val runtime = start(staging = true)
        openPeers()
        shot("peers-list-1")
        compose.onNodeWithTag(Tags.PEERS_SORT).performClick()
        waitFor(Tags.peersSortOption(PeerSort.Alphabetical.name))
        shot("peers-list-2")
        compose.onNodeWithTag(Tags.peersSortOption(PeerSort.Alphabetical.name)).performClick()

        compose.onNodeWithTag(Tags.PEERS_SEARCH).performClick()
        compose.onNodeWithTag(Tags.PEERS_SEARCH_FIELD).performTextInput("al")
        waitFor(Tags.PEERS_SEARCH_DISCOVERED)
        // The keyboard down, so the groups show.
        hideKeyboard()
        shot("peers-list-3")
        compose.onNodeWithTag(Tags.PEERS_SEARCH_CLOSE).performClick()
        waitFor(Tags.PEERS_LIST)

        val maya = address(runtime, "Maya Ortiz")
        row(maya).performTouchInput { longClick() }
        waitFor(Tags.PEER_MENU)
        shot("peers-list-4")
        compose.onNodeWithTag(Tags.PEER_MENU_REMOVE).performClick()
        waitFor(Tags.REMOVE_PEER_DIALOG)
        shot("peers-list-5")
    }

    /** Board 6: no node known, on the live core with no radio. */
    @Test
    fun peersListEmpty() {
        start(staging = false)
        waitFor(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitFor(Tags.PEERS_EMPTY)
        shot("peers-list-6")
    }

    /** `peer-page.svg` 1–3 and 6: a chat node, scrolled to the end, a repeater, and Rename. */
    @Test
    fun peerPages() {
        val runtime = start(staging = true)
        openPeers()
        val maya = address(runtime, "Maya Ortiz")
        row(maya).performClick()
        waitFor(Tags.PEER_PAGE)
        shot("peer-page-1")
        compose.onNodeWithTag(Tags.PEER_REMOVE).performScrollTo()
        shot("peer-page-2")
        compose.onNodeWithTag(Tags.PEER_NAME).performScrollTo().performClick()
        waitFor(Tags.RENAME_DIALOG)
        compose.onNodeWithTag(Tags.RENAME_FIELD).performTextReplacement("Maya at camp")
        shot("peer-page-6")
        compose.onNodeWithTag(Tags.CONFIRM_CANCEL).performClick()
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).performClick()
        waitFor(Tags.PEERS_LIST)

        row(address(runtime, "Tallac Ridge")).performClick()
        waitFor(Tags.PEER_PAGE)
        shot("peer-page-3")
    }

    /**
     * Board 4: a node stored by its address alone, never heard and not on
     * Peers. The address is the Ed25519 base point's, a key no device holds.
     */
    @Test
    fun peerPageNeverAdvertised() {
        val runtime = start(staging = true)
        runBlocking {
            runtime.core.savePeer(NEVER_HEARD, null, false)
            runtime.reload(full = true).await()
            runtime.demotePeer(NEVER_HEARD).await()
        }
        openPeers()
        compose.onNodeWithTag(Tags.PEERS_SEARCH).performClick()
        compose.onNodeWithTag(Tags.PEERS_SEARCH_FIELD).performTextInput(NEVER_HEARD.take(8))
        waitFor(Tags.peerRow(NEVER_HEARD))
        compose.onNodeWithTag(Tags.peerRow(NEVER_HEARD)).performClick()
        waitFor(Tags.PEER_PAGE)
        shot("peer-page-4")
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 1_000L
        const val NEVER_HEARD = "6x5SYnLroiN7WYq8NQYU9KHcH4YjpBbwpUfVu3EB7ieH"
    }
}
