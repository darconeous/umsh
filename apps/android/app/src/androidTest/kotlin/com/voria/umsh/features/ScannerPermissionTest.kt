package com.voria.umsh.features

import android.Manifest
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.os.ParcelFileDescriptor
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.core.content.ContextCompat
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
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
import com.voria.umsh.features.scanner.CameraPresence
import com.voria.umsh.features.scanner.LocalCameraPresence
import com.voria.umsh.features.scanner.LocalFrameSource
import java.io.File
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/**
 * The camera ask (`permissions.svg` 2–3), answered in Android's own dialog:
 * asked as the scanner first opens, Don't allow leaves the page saying
 * camera access is off, and Allow camera asks again, While using the app
 * shows the viewfinder. Gated (`-e camera ask`), with the camera revoked
 * and its flags cleared before the run (`pm revoke <package>
 * android.permission.CAMERA`, `pm clear-permission-flags <package>
 * android.permission.CAMERA user-set user-fixed`): revoking ends the app's
 * process, so not from here. With `-e shots <suffix>` it also takes boards
 * 2 and 3.
 */
class ScannerPermissionTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val camera = FakeFrameSource()

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    private fun shot(name: String) {
        val suffix = InstrumentationRegistry.getArguments().getString("shots") ?: return
        Thread.sleep(SETTLE_MS)
        val bitmap = instrumentation.uiAutomation.takeScreenshot() ?: return
        val directory = File(context.getExternalFilesDir(null), "shots").apply { mkdirs() }
        File(directory, "$name-$suffix.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    @Test
    fun askedOnFirstOpenRefusedThenAllowed() {
        assumeTrue("-e camera ask", InstrumentationRegistry.getArguments().getString("camera") == "ask")
        assumeTrue(
            "the camera is granted: revoke it before the run",
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED,
        )
        val runtime = runBlocking {
            fresh.host.preferences.setFallbackScheme(true)
            fresh.host.ensureRuntime(staging = true)
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            withTimeout(TIMEOUT) { ready.runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
            withTimeout(TIMEOUT) { ready.runtime.appState.first { it != null } }
            ready.runtime
        }
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides TestWindows.Phone,
                    LocalFrameSource provides camera,
                    LocalCameraPresence provides CameraPresence { true },
                ) {
                    UmshShell(rememberShellState())
                }
            }
        }
        waitForTag(Tags.CONVERSATIONS_ROOT)
        waitForTag(Tags.CONVERSATIONS_SCAN)
        compose.onNodeWithTag(Tags.CONVERSATIONS_SCAN).performClick()

        // Board 2: Android's dialog over the scanner, with nothing beneath it yet.
        val device = UiDevice.getInstance(instrumentation)
        val deny = dialogButton(device, "permission_deny_button")
        // The app's window has lost focus to the dialog, so the compose tree is not read here; the
        // test's clock is moved on so the scanner's page has finished coming in beneath the dialog.
        runCatching { compose.mainClock.advanceTimeBy(PAGE_IN_MS) }
        shot("permissions-2")
        deny.click()

        // Board 3: the page says the camera is off, with Allow camera; Android still asks.
        waitForTag(Tags.SCANNER_CAMERA_OFF)
        shot("permissions-3")
        assertEquals(false, runBlocking { fresh.host.preferences.cameraBlocked.first() })

        compose.onNodeWithTag(Tags.SCANNER_ALLOW).performClick()
        val allow = dialogButton(device, "permission_allow_foreground_only_button")
        allow.click()
        waitForTag(Tags.SCANNER_VIEWFINDER)
        shell("log -t umsh.test scanner-camera-ask-granted")
    }

    /**
     * A button of Android's dialog, once it is up. The scanner asks from an
     * effect, which runs only as the test's clock advances, so the wait
     * goes through the compose rule rather than UiAutomator alone.
     */
    private fun dialogButton(device: UiDevice, id: String): UiObject2 {
        var button: UiObject2? = null
        compose.waitUntil(TIMEOUT) {
            button = device.findObject(By.res(CONTROLLER, id))
            button != null
        }
        return checkNotNull(button)
    }

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command))
            .use { it.readBytes().decodeToString() }

    private companion object {
        const val TIMEOUT = 15_000L
        const val SETTLE_MS = 800L
        const val PAGE_IN_MS = 2_000L
        const val CONTROLLER = "com.android.permissioncontroller"
    }
}
