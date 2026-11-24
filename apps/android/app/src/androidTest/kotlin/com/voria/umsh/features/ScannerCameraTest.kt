package com.voria.umsh.features

import android.Manifest
import android.graphics.Bitmap
import android.os.ParcelFileDescriptor
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.app.TestWindows
import com.voria.umsh.app.UmshShell
import com.voria.umsh.app.rememberShellState
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.designsystem.LocalWindowOverride
import com.voria.umsh.designsystem.UmshTheme
import java.io.File
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/**
 * The scanner through the real CameraX pipeline on an emulator whose back
 * camera is the virtual scene, with a `umsh:` code as its wall poster
 * (`-camera-back virtualscene -virtualscene-poster wall=<png>`, the camera
 * posed facing it). Gated: `-e camera poster -e poster <the poster's link>`
 * reads the code and expects its import preview; `-e camera viewfinder`
 * only shows the live picture for a few seconds (with `-e shots`, board 1).
 * The camera permission is granted here.
 */
class ScannerCameraTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val arguments get() = InstrumentationRegistry.getArguments()

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun shot(name: String) {
        val suffix = arguments.getString("shots") ?: return
        val bitmap = instrumentation.uiAutomation.takeScreenshot() ?: return
        val directory = File(context.getExternalFilesDir(null), "shots").apply { mkdirs() }
        File(directory, "$name-$suffix.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    private fun openScanner() {
        instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.CAMERA)
        val runtime = runBlocking {
            fresh.host.preferences.setFallbackScheme(true)
            fresh.host.ensureRuntime(staging = true)
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            withTimeout(TIMEOUT) { ready.runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
            ready.runtime
        }
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides TestWindows.Phone,
                ) {
                    UmshShell(rememberShellState())
                }
            }
        }
        compose.waitUntil(TIMEOUT) { present(Tags.NAV_PEERS) }
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        compose.waitUntil(TIMEOUT) { present(Tags.PEERS_SCAN) }
        compose.onNodeWithTag(Tags.PEERS_SCAN).performClick()
    }

    @Test
    fun theCameraReadsThePoster() {
        assumeTrue("-e camera poster", arguments.getString("camera") == "poster")
        val expected = checkNotNull(arguments.getString("poster")) { "-e poster <link>" }
        openScanner()
        val started = System.nanoTime()
        compose.waitUntil(DECODE_TIMEOUT) { present(Tags.IMPORT_SHEET) }
        val seconds = (System.nanoTime() - started) / 1e9
        // The preview shows the poster's address, in groups of four.
        val bare = expected.removePrefix("umsh:n:").substringBefore(':')
        val shown = compose.onAllNodes(hasText(bare.take(4), substring = true), useUnmergedTree = true).fetchSemanticsNodes()
        assertTrue("the preview names ${bare.take(4)}…", shown.isNotEmpty())
        shell("log -t umsh.test scanner-camera-poster-read %.1fs".format(seconds))
        shot("qr-scanner-3-camera")
    }

    @Test
    fun theViewfinderShowsTheCamera() {
        assumeTrue("-e camera viewfinder", arguments.getString("camera") == "viewfinder")
        openScanner()
        compose.waitUntil(TIMEOUT) { present(Tags.SCANNER_VIEWFINDER) }
        Thread.sleep(VIEW_MS)
        shot("qr-scanner-1-camera")
        assertTrue(present(Tags.SCANNER_VIEWFINDER))
        assertTrue(!present(Tags.SCANNER_CAMERA_OFF))
    }

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command))
            .use { it.readBytes().decodeToString() }

    private companion object {
        const val TIMEOUT = 20_000L
        const val DECODE_TIMEOUT = 60_000L
        const val VIEW_MS = 4_000L
    }
}
