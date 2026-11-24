package com.voria.umsh.features

import android.Manifest
import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import java.util.regex.Pattern
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.Tags
import com.voria.umsh.features.scanner.CameraPresence
import com.voria.umsh.features.scanner.LocalCameraPresence
import com.voria.umsh.features.scanner.LocalFrameSource
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
 * Screenshots of `share.svg` 1–4 and `qr-scanner.svg` 1–3 for the build
 * report, in the real app root over the staged air, the camera's picture
 * made by the test ([FakeFrameSource]). Off unless the run passes
 * `-e shots <suffix>`; they land in the app's external files, under
 * `shots/`.
 */
class ScannerShots {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val suffix: String? get() = InstrumentationRegistry.getArguments().getString("shots")
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val camera = FakeFrameSource()

    @Before
    fun onlyWhenAsked() = assumeTrue(suffix != null)

    private fun shot(name: String, settle: Long = SETTLE_MS) {
        compose.waitForIdle()
        Thread.sleep(settle)
        val bitmap = instrumentation.uiAutomation.takeScreenshot() ?: return
        val directory = File(context.getExternalFilesDir(null), "shots").apply { mkdirs() }
        File(directory, "$name-$suffix.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    private fun start(): AppRuntime {
        instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.CAMERA)
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
        compose.setContent {
            CompositionLocalProvider(LocalFrameSource provides camera, LocalCameraPresence provides CameraPresence { true }) {
                AppRoot(fresh.host)
            }
        }
        return runtime
    }

    private fun waitFor(tag: String) = compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty() }

    /** Back through UiAutomator: the Sharesheet is another app's window, which plain key injection may not reach. */
    private fun back() = UiDevice.getInstance(instrumentation).pressBack()

    private fun openPeers() {
        waitFor(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitFor(Tags.PEERS_LIST)
    }

    /** `share.svg` 1–3: a peer's share sheet, Android's Sharesheet over it, and a copy confirmed. */
    @Test
    fun share() {
        val runtime = start()
        openPeers()
        val maya = runtime.appState.value!!.peers.first { it.advertisedName == "Maya Ortiz" }.address
        compose.onNodeWithTag(Tags.PEERS_LIST).performScrollToNode(hasTestTag(Tags.peerRow(maya)))
        compose.onNodeWithTag(Tags.peerRow(maya)).performClick()
        waitFor(Tags.PEER_SHARE)
        compose.onNodeWithTag(Tags.PEER_SHARE).performClick()
        waitFor(Tags.QR_IMAGE)
        shot("share-1")
        compose.onNodeWithTag(Tags.QR_SHARE).performClick()
        // The system's own sheet: give it time to draw its targets.
        UiDevice.getInstance(instrumentation).waitForIdle()
        shot("share-2", settle = 3_000)
        back()
        Thread.sleep(SETTLE_MS)
        back()
        compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(Tags.QR_SHEET).fetchSemanticsNodes().isEmpty() }
        compose.onNodeWithTag(Tags.PEER_ADDRESS).performScrollTo().performClick()
        // Android 13 and later: the system's overlay; 12: the page's snackbar.
        shot("share-3", settle = 900)
        // The system's copy overlay outlives the test: dismissed, so the next shots are clean.
        UiDevice.getInstance(instrumentation)
            .findObject(By.res(Pattern.compile("com\\.android\\.systemui:id/.*dismiss.*")))
            ?.click()
    }

    /** `share.svg` 4: Show your code from Add peer. */
    @Test
    fun yourCode() {
        start()
        openPeers()
        compose.onNodeWithTag(Tags.PEERS_ADD).performClick()
        waitFor(Tags.ADD_PEER_SHOW_CODE)
        compose.onNodeWithTag(Tags.ADD_PEER_SHOW_CODE).performScrollTo().performClick()
        waitFor(Tags.QR_IMAGE)
        shot("share-4")
    }

    /** `qr-scanner.svg` 1–3: scanning, another code's pill, and a node code's preview over Peers. */
    @Test
    fun scanner() {
        start()
        openPeers()
        // Board 1: a code held up, not yet read.
        camera.feeding = false
        val marmot = ImportFixtures.signedLink(0x51).link
        camera.show(marmot)
        compose.onNodeWithTag(Tags.PEERS_SCAN).performClick()
        waitFor(Tags.SCANNER_TORCH)
        shot("qr-scanner-1")
        // Board 2.
        camera.show("https://example.org/trailhead")
        camera.feeding = true
        waitFor(Tags.SCANNER_PILL)
        shot("qr-scanner-2")
        // Board 3: Marmot's signed code.
        camera.show(marmot)
        waitFor(Tags.IMPORT_SHEET)
        shot("qr-scanner-3")
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 700L
    }
}
