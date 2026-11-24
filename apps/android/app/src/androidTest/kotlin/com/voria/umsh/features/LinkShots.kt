package com.voria.umsh.features

import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.LinkOrigin
import com.voria.umsh.app.OpenRequest
import com.voria.umsh.app.OpenRequests
import com.voria.umsh.app.Tags
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
 * Screenshots of `peer-page.svg` 5 (a page a link opened, with Close), of
 * `add-peer.svg` 5 (a bad link's import sheet), and of the undrawn link
 * states (a channel link's sheet, a link in a message) for the build
 * report, in the real app root over the staged air. Off unless the run
 * passes `-e shots <suffix>`; they land in the app's external files, under
 * `shots/`.
 */
class LinkShots {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val suffix: String? get() = InstrumentationRegistry.getArguments().getString("shots")
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val requests = OpenRequests()

    @Before
    fun onlyWhenAsked() = assumeTrue(suffix != null)

    private fun shot(name: String) {
        compose.waitForIdle()
        Thread.sleep(SETTLE_MS)
        val bitmap = instrumentation.uiAutomation.takeScreenshot() ?: return
        val directory = File(context.getExternalFilesDir(null), "shots").apply { mkdirs() }
        File(directory, "$name-$suffix.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    private fun start(): AppRuntime {
        runBlocking {
            fresh.host.preferences.setFallbackScheme(true)
            fresh.host.preferences.setNotificationsAsked()
        }
        fresh.host.ensureRuntime(staging = true)
        val runtime = runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime.setOnboarding(OnboardingStep.Done).await()
            withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
            withTimeout(TIMEOUT) { ready.runtime.appState.first { state -> state?.peers?.any { it.advertisedName == "Maya Ortiz" } == true } }
            ready.runtime
        }
        compose.setContent { AppRoot(fresh.host, requests) }
        waitFor(Tags.SHELL)
        return runtime
    }

    private fun waitFor(tag: String) = compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty() }

    private fun waitForText(tag: String, text: String) = compose.waitUntil(TIMEOUT) {
        compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes()
            .any { node -> node.config.getOrNull(SemanticsProperties.Text)?.any { it.text.contains(text) } == true }
    }

    /** `peer-page.svg` 5: Marmot's signed link, opened from another app. */
    @Test
    fun linkedPage() {
        start()
        requests.offer(OpenRequest.Link(ImportFixtures.signedLink(0x6A).link, LinkOrigin.OtherApp))
        waitFor(Tags.TOP_BAR_CLOSE)
        waitForText(Tags.PEER_NAME, "Marmot")
        shot("peer-page-5")
    }

    /** `add-peer.svg` 5: a bad link's import sheet. */
    @Test
    fun linkSheets() {
        start()
        requests.offer(OpenRequest.Link("umsh:x:Mx4eTq8VbN3k", LinkOrigin.OtherApp))
        waitFor(Tags.ADD_PEER_PROBLEM)
        shot("link-bad")
    }

    /** A link in a message, and the page it opens over the thread. */
    @Test
    fun linkInAMessage() {
        val runtime = start()
        val maya = runtime.appState.value!!.peers.first { it.advertisedName == "Maya Ortiz" }
        val marmot = ImportFixtures.signedLink(0x6B)
        val conversation = runBlocking { runtime.startConversation(maya.address).await() }
        runBlocking { runtime.send(conversation, "Add Marmot: ${marmot.link}", null).await() }
        requests.offer(OpenRequest.Conversation(conversation))
        waitFor(Tags.THREAD)
        shot("link-message")
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 900L
    }
}
