package com.voria.umsh.features

import android.graphics.Bitmap
import android.view.inputmethod.InputMethodManager
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeUp
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.test.performScrollToIndex
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.material3.Surface
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.Tags
import com.voria.umsh.app.TestUmshApplication
import com.voria.umsh.app.debug.BannersBoard
import com.voria.umsh.app.debug.FakeRadioScanSource
import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.designsystem.ConfirmDialog
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import java.io.File
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * Screenshots of `radio-detail.svg` and the banners of `radio-control.svg`,
 * for the build report. Off unless the run passes `-e shots <suffix>`; the
 * suffix names the appearance the device is set to (light or dark). They
 * land in the app's external files, under `shots/`.
 */
class RadioDetailShots {
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

    private fun start(staging: Boolean, linkId: String? = null): AppRuntime {
        runBlocking {
            fresh.host.preferences.setFallbackScheme(true)
            linkId?.let { fresh.host.preferences.radioRegistry.bind(BoundRadio(RadioKind.Tcp, it, name = RADIO_NAME)) }
        }
        fresh.host.ensureRuntime(staging = staging)
        val runtime = runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime.setOnboarding(OnboardingStep.Done).await()
            ready.runtime
        }
        compose.setContent { AppRoot(fresh.host) }
        return runtime
    }

    private fun waitForPhase(runtime: AppRuntime, phase: MobileRadioPhase) = runBlocking {
        withTimeout(TIMEOUT) { runtime.radio.first { it?.phase == phase } }
    }

    private fun waitFor(tag: String) = compose.waitUntil(TIMEOUT) {
        compose.onAllNodesWithTag(tag).fetchSemanticsNodes().isNotEmpty()
    }

    private fun openDetail() {
        waitFor(Tags.RADIO_CONTROL)
        // Beside the rail the control is in the rail's header.
        compose.onAllNodesWithTag(Tags.RADIO_CONTROL)[0].performClick()
        waitFor(Tags.RADIO_DETAIL)
    }

    /**
     * Boards 1 and 2: the staged radio connected, then the rest of the page.
     * It cannot restart, so it has no Maintenance section.
     */
    @Test
    fun connected() {
        val runtime = start(staging = true)
        waitForPhase(runtime, MobileRadioPhase.ATTACHED)
        openDetail()
        shot("01-connected")
        compose.onNodeWithTag(Tags.RADIO_DETAIL).performTouchInput { swipeUp() }
        compose.onNodeWithTag(Tags.RADIO_DETAIL).performTouchInput { swipeUp() }
        shot("02-rest")
    }

    /**
     * Board 5's confirmation, drawn alone: no radio the emulator reaches
     * restarts on request, so none offers it on the page.
     */
    @Test
    fun factoryResetConfirmation() {
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                Surface(Modifier.fillMaxSize()) {
                    ConfirmDialog(
                        title = stringResource(R.string.factory_reset_title),
                        body = stringResource(R.string.factory_reset_body),
                        confirm = stringResource(R.string.factory_reset_confirm),
                        onConfirm = {},
                        onDismiss = {},
                    )
                }
            }
        }
        waitFor(Tags.CONFIRM_DIALOG)
        shot("05-factory-reset")
    }

    /** Board 3, and the banner with Details over Conversations (`radio-control.svg` 4). */
    @Test
    fun waiting() {
        val runtime = start(staging = false, linkId = "scripted:waiting")
        waitForPhase(runtime, MobileRadioPhase.WAITING_FOR_RADIO)
        waitFor(Tags.BANNER_ACTION)
        shot("10-banner-details-on-root")
        openDetail()
        shot("03-waiting")
    }

    /** Board 4. */
    @Test
    fun failed() {
        val runtime = start(staging = false, linkId = "scripted:failed")
        waitForPhase(runtime, MobileRadioPhase.FAILED)
        openDetail()
        shot("04-failed")
    }

    /** Board 6: Companion radio from Settings, beside the list on an expanded window (run with a tablet-sized display). */
    @Test
    fun settings() {
        val runtime = start(staging = true)
        waitForPhase(runtime, MobileRadioPhase.ATTACHED)
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        // By its click action: on a short landscape window a tap can land on
        // whatever scrolled under it.
        compose.onNodeWithTag(Tags.SETTINGS_COMPANION_RADIO).performSemanticsAction(SemanticsActions.OnClick)
        waitFor(Tags.RADIO_DETAIL)
        // On this AVD at a tablet size, the Developer section's text field
        // takes focus as Settings opens (debug only): let it go for the shot.
        compose.runOnUiThread {
            val view = compose.activity.window.decorView
            view.findFocus()?.let { focused ->
                compose.activity.getSystemService(InputMethodManager::class.java)
                    .hideSoftInputFromWindow(focused.windowToken, 0)
            }
            view.clearFocus()
        }
        compose.onNodeWithTag(Tags.SETTINGS_LIST).performScrollToIndex(0)
        shot("06-settings-companion-radio")
    }

    /**
     * `radio-picker.svg` board 2 without the system's dialog: Choose a
     * radio from Radio Detail, a radio connecting, the others and the
     * pinned current radio dimmed. The rows are the stand-in search's.
     */
    @Test
    fun pickerConnecting() {
        val application = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as TestUmshApplication
        application.radioSearchFactory = { FakeRadioScanSource.scenario("connecting") }
        val runtime = start(staging = false, linkId = "scripted:waiting")
        waitForPhase(runtime, MobileRadioPhase.WAITING_FOR_RADIO)
        openDetail()
        compose.onNodeWithTag(Tags.RADIO_DETAIL_CHOOSE_ANOTHER).performScrollTo().performClick()
        waitFor(Tags.CONNECT_RADIO_PROGRESS)
        shot("12-picker-connecting")
    }

    /** `radio-control.svg` boards 2–3: every banner with its action. */
    @Test
    fun banners() {
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                Surface(Modifier.fillMaxSize()) { Column(Modifier.windowInsetsPadding(WindowInsets.safeDrawing)) { BannersBoard() } }
            }
        }
        shot("11-banners")
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 800L
        const val RADIO_NAME = "T1000-E 4F2A"
    }
}
