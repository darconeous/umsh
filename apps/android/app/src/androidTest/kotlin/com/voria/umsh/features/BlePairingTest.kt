package com.voria.umsh.features

import android.Manifest
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.ComposeTimeoutException
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.Tags
import com.voria.umsh.app.TestUmshApplication
import com.voria.umsh.services.preferences.OnboardingStep
import java.util.regex.Pattern
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExternalResource

/**
 * First launch against a real radio over Bluetooth (§9, Bumble run 2): Welcome,
 * Connect a radio, the radio's row, Android's companion device confirmation,
 * the pairing dialog (a passkey when one is given), attached and claimed.
 *
 * Gated off CI: it runs only with `-e ble pairing`, against the Bumble test
 * peripheral in its pairing window (`make android-ble-peripheral`, factory
 * reset first). `-e passkey 123456` answers a passkey radio. The radio is
 * forgotten after, so the run can be repeated.
 */
class BlePairingTest {
    /** Gated, and Nearby devices granted before the activity starts, so its Bluetooth status reads them. */
    @get:Rule(order = 0) val gate = object : ExternalResource() {
        override fun before() {
            assumeTrue("Bumble run only: -e ble pairing", arguments.getString("ble") == "pairing")
            val packageName = instrumentation.targetContext.packageName
            // Nearby devices and notifications are other tests' business.
            val granted = mutableListOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) granted += Manifest.permission.POST_NOTIFICATIONS
            granted.forEach { instrumentation.uiAutomation.grantRuntimePermission(packageName, it) }
        }
    }

    @get:Rule(order = 1) val fresh = FreshHostRule()

    @get:Rule(order = 2) val compose = createAndroidComposeRule<ComponentActivity>()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val application get() = instrumentation.targetContext.applicationContext as TestUmshApplication
    private val arguments get() = InstrumentationRegistry.getArguments()
    private val device: UiDevice get() = UiDevice.getInstance(instrumentation)

    @Before
    fun realSearch() {
        application.radioSearchFactory = { application.realRadioSearch() }
    }

    @Test
    fun aRadioIsAddedOnFirstLaunch() {
        try {
            fresh.host.ensureRuntime(staging = false)
            val runtime = runBlocking {
                (withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready).runtime
            }
            compose.setContent { AppRoot(fresh.host) }
            waitFor(Tags.WELCOME_CONTINUE)
            compose.onNodeWithTag(Tags.WELCOME_CONTINUE).performClick()
            waitFor(Tags.CONNECT_RADIO_ROW, SCAN_TIMEOUT)
            compose.onNodeWithTag(Tags.CONNECT_RADIO_ROW).performClick()

            // Android's confirmation, drawn by the system. The page raises it
            // from an effect, which runs only while Compose's test clock is
            // pumped, so every wait for a system dialog goes through the rule.
            systemDialog(By.text(ALLOW), DIALOG_TIMEOUT, "no companion device confirmation").click()

            // The pairing dialog: a passkey typed in, or a Just Works confirmation where Android shows one.
            val passkey = arguments.getString("passkey")
            if (passkey != null) {
                val field = pairingPrompt(By.clazz("android.widget.EditText")) ?: throw AssertionError("no passkey dialog")
                field.text = passkey
                device.findObject(By.text(OK)).click()
            } else {
                pairingPrompt(By.text(PAIR))?.click()
            }

            compose.waitUntil(ATTACH_TIMEOUT) { runtime.radio.value?.carriesThisPhone == true }
            val attached = runtime.radio.value!!
            compose.waitUntil(TIMEOUT) { runtime.onboarding.value == OnboardingStep.Done }
            val bound = runBlocking { fresh.host.preferences.radioRegistry.bound() }
            assertNotNull(bound)
            assertEquals(attached.linkId, bound!!.linkId)
            val association = bound.associationId
            assertNotNull("bound without an association", association)
            assertEquals(association, application.associations.associationFor(bound.linkId))
            Log.i(TAG, "attached at ${bound.linkId}, association $association; idle allowlist: ${allowlisted()}")
        } finally {
            // Left as found, passed or not: the next run adds it again.
            fresh.host.forgetRadio().let { runBlocking { it.join() } }
        }
    }

    /**
     * The pairing dialog's [selector]. API 31–32 may post Android's
     * pairing request as a notification instead (the app is not one
     * Android shows it over); it is opened from the shade.
     */
    private fun pairingPrompt(selector: BySelector): UiObject2? {
        runCatching { systemDialog(selector, JUST_WORKS_WAIT, "") }.getOrNull()?.let { return it }
        device.openNotification()
        val request = runCatching { systemDialog(By.text(PAIRING_REQUEST), JUST_WORKS_WAIT, "") }.getOrNull()
        if (request == null) {
            device.pressBack()
            return null
        }
        request.click()
        return runCatching { systemDialog(selector, DIALOG_TIMEOUT, "") }.getOrNull()
    }

    private fun systemDialog(selector: BySelector, timeout: Long, missing: String): UiObject2 {
        var found: UiObject2? = null
        try {
            compose.waitUntil(timeout) {
                found = device.findObject(selector)
                found != null
            }
        } catch (_: ComposeTimeoutException) {
            throw AssertionError(missing)
        }
        return found!!
    }

    private fun waitFor(tag: String, timeout: Long = TIMEOUT) =
        compose.waitUntil(timeout) { compose.onAllNodes(hasTestTag(tag)).fetchSemanticsNodes().isNotEmpty() }

    /** Whether Android's idle allowlist holds the app, as `dumpsys deviceidle whitelist` says. */
    private fun allowlisted(): Boolean {
        val output = instrumentation.uiAutomation.executeShellCommand("dumpsys deviceidle whitelist")
        val text = ParcelFileDescriptor.AutoCloseInputStream(output).bufferedReader().use { it.readText() }
        return text.lines().any { it.contains(",${instrumentation.targetContext.packageName},") }
    }

    private companion object {
        const val TAG = "BlePairingTest"
        const val TIMEOUT = 15_000L
        const val SCAN_TIMEOUT = 30_000L
        const val DIALOG_TIMEOUT = 20_000L
        const val JUST_WORKS_WAIT = 8_000L
        const val ATTACH_TIMEOUT = 90_000L

        val ALLOW: Pattern = Pattern.compile("(?i)allow")
        val OK: Pattern = Pattern.compile("(?i)ok")
        val PAIR: Pattern = Pattern.compile("(?i)pair")
        val PAIRING_REQUEST: Pattern = Pattern.compile("(?i)pairing request")
    }
}
