package com.voria.umsh.features

import android.Manifest
import android.content.pm.PackageManager
import android.os.ParcelFileDescriptor
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.core.content.ContextCompat
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.Tags
import com.voria.umsh.app.TestUmshApplication
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.services.location.LocationGrant
import com.voria.umsh.services.preferences.OnboardingStep
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/**
 * Share location on Your identity (§3.8, `identity.svg` 1–2, 6,
 * `permissions.svg` 4–6): the rows, the Precision dialog, and the
 * effective precision under each grant. The grant comes from the test's
 * own source, so no system dialog is raised, except in the gated run at
 * the end.
 */
class ShareLocationTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val application get() = context.applicationContext as TestUmshApplication
    private val location get() = application.testLocation

    private fun text(id: Int, vararg args: Any) = context.getString(id, *args)

    /** Past Welcome, Settings › Your identity, with [grant] and sharing as [sharing]. */
    private fun open(grant: LocationGrant, sharing: Boolean = false): AppRuntime {
        location.grant.value = grant
        fresh.host.ensureRuntime(staging = false)
        val runtime = runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime.also {
                it.setOnboarding(OnboardingStep.Done).await()
                if (sharing) it.setPolicy { shareLocation = true }.await()
                withTimeout(TIMEOUT) { it.lifecycle.first { state -> state is MobileAppLifecycle.Running } }
            }
        }
        compose.setContent { AppRoot(fresh.host) }
        compose.waitUntil(TIMEOUT) { compose.onAllNodes(hasTestTag(Tags.NAV_SETTINGS)).fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_YOUR_IDENTITY).performClick()
        compose.onNodeWithTag(Tags.YOUR_IDENTITY).assertIsDisplayed()
        return runtime
    }

    private fun effective(runtime: AppRuntime, expected: UByte?) = runBlocking {
        withTimeout(TIMEOUT) { runtime.effectivePolicy.first { it.locationPrecision == expected } }
    }

    private fun stored(runtime: AppRuntime): UByte? = runBlocking { runtime.policy.first().locationPrecision }

    private fun rowShows(tag: String, value: String) =
        compose.waitUntil(TIMEOUT) { runCatching { compose.onNodeWithTag(tag).assertTextContains(value) }.isSuccess }

    private fun gone(tag: String) =
        compose.waitUntil(TIMEOUT) { compose.onAllNodes(hasTestTag(tag)).fetchSemanticsNodes().isEmpty() }

    private fun shown(tag: String) =
        compose.waitUntil(TIMEOUT) { compose.onAllNodes(hasTestTag(tag)).fetchSemanticsNodes().isNotEmpty() }

    private val area38m get() = text(com.voria.umsh.R.string.share_location_area, "38 m")
    private val areaApproximate get() = text(com.voria.umsh.R.string.share_location_area, "9.8 km")

    @Test
    fun turningItOnWithPreciseSharesTheChoice() {
        val runtime = open(LocationGrant.Precise)
        compose.onNodeWithTag(Tags.IDENTITY_SHARE_LOCATION).performScrollTo().assertIsOff()
        rowShows(Tags.IDENTITY_SHARE_LOCATION, text(com.voria.umsh.R.string.share_location_off))
        compose.onNodeWithTag(Tags.IDENTITY_PRECISION).assertDoesNotExist()

        compose.onNodeWithTag(Tags.IDENTITY_SHARE_LOCATION).performClick()
        rowShows(Tags.IDENTITY_SHARE_LOCATION, area38m)
        compose.onNodeWithTag(Tags.IDENTITY_SHARE_LOCATION).assertIsOn()
        rowShows(Tags.IDENTITY_PRECISION, text(com.voria.umsh.R.string.precision_about, "38 m"))
        compose.onNodeWithTag(Tags.IDENTITY_LOCATION_OFF).assertDoesNotExist()
        assertEquals(5.toUByte(), stored(runtime))
        effective(runtime, 5u)

        compose.onNodeWithTag(Tags.IDENTITY_SHARE_LOCATION).performClick()
        rowShows(Tags.IDENTITY_SHARE_LOCATION, text(com.voria.umsh.R.string.share_location_off))
        gone(Tags.IDENTITY_PRECISION)
        effective(runtime, null)
    }

    @Test
    fun choosingASizeAppliesItAndCloses() {
        val runtime = open(LocationGrant.Precise, sharing = true)
        compose.onNodeWithTag(Tags.IDENTITY_PRECISION).performScrollTo().performClick()
        shown(Tags.PRECISION_DIALOG)
        listOf("2,505 km", "157 km", "9.8 km", "611 m", "38 m", "2.4 m", "15 cm").forEachIndexed { index, size ->
            compose.onNodeWithTag("${Tags.PRECISION_OPTION}_${index + 1}")
                .assertTextContains(text(com.voria.umsh.R.string.precision_about, size))
                .assertIsEnabled()
        }
        compose.onNodeWithTag(Tags.PRECISION_PRECISE_OFF).assertDoesNotExist()
        compose.onNodeWithTag("${Tags.PRECISION_OPTION}_4").performClick()
        gone(Tags.PRECISION_DIALOG)
        rowShows(Tags.IDENTITY_PRECISION, text(com.voria.umsh.R.string.precision_about, "611 m"))
        rowShows(Tags.IDENTITY_SHARE_LOCATION, text(com.voria.umsh.R.string.share_location_area, "611 m"))
        assertEquals(4.toUByte(), stored(runtime))
        effective(runtime, 4u)
    }

    /** Approximate alone: the area and the core's precision stop at about 9.8 km; precise later restores the choice. */
    @Test
    fun approximateClampsUntilPreciseIsGranted() {
        val runtime = open(LocationGrant.Approximate, sharing = true)
        rowShows(Tags.IDENTITY_SHARE_LOCATION, areaApproximate)
        rowShows(Tags.IDENTITY_PRECISION, text(com.voria.umsh.R.string.precision_about, "9.8 km"))
        assertEquals(5.toUByte(), stored(runtime))
        effective(runtime, 3u)

        compose.onNodeWithTag(Tags.IDENTITY_PRECISION).performScrollTo().performClick()
        shown(Tags.PRECISION_DIALOG)
        (1..3).forEach { compose.onNodeWithTag("${Tags.PRECISION_OPTION}_$it").assertIsEnabled() }
        (4..7).forEach { compose.onNodeWithTag("${Tags.PRECISION_OPTION}_$it").assertIsNotEnabled() }
        compose.onNodeWithTag(Tags.PRECISION_PRECISE_OFF)
            .assertTextContains(text(com.voria.umsh.R.string.precise_location_off))
        compose.onNodeWithTag(Tags.PRECISION_ALLOW).assertIsDisplayed()
        compose.onNodeWithTag("${Tags.PRECISION_OPTION}_3").assertIsSelected()

        // The clamped size, tapped: the dialog closes and the choice stays.
        compose.onNodeWithTag("${Tags.PRECISION_OPTION}_3").performClick()
        gone(Tags.PRECISION_DIALOG)
        assertEquals(5.toUByte(), stored(runtime))
        compose.onNodeWithTag(Tags.IDENTITY_PRECISION).performScrollTo().performClick()
        shown(Tags.PRECISION_DIALOG)

        // Precise granted (as by the dialog's Allow): the choice returns untouched.
        location.grant.value = LocationGrant.Precise
        gone(Tags.PRECISION_PRECISE_OFF)
        compose.onNodeWithTag("${Tags.PRECISION_OPTION}_5").assertIsEnabled().assertIsSelected()
        compose.onNodeWithTag("${Tags.PRECISION_OPTION}_5").performClick()
        gone(Tags.PRECISION_DIALOG)
        rowShows(Tags.IDENTITY_SHARE_LOCATION, area38m)
        effective(runtime, 5u)
    }

    /** Refused: the switch keeps the choice, a line says nothing is shared, and no Precision row. */
    @Test
    fun refusedSaysSoAndResumesOnceAllowed() {
        val runtime = open(LocationGrant.None, sharing = true)
        compose.onNodeWithTag(Tags.IDENTITY_SHARE_LOCATION).performScrollTo().assertIsOn()
        rowShows(Tags.IDENTITY_SHARE_LOCATION, area38m)
        compose.onNodeWithTag(Tags.IDENTITY_LOCATION_OFF).performScrollTo()
            .assertTextContains(text(com.voria.umsh.R.string.location_off))
        compose.onNodeWithTag(Tags.IDENTITY_LOCATION_ALLOW).assertIsDisplayed()
        compose.onNodeWithTag(Tags.IDENTITY_PRECISION).assertDoesNotExist()
        effective(runtime, 5u)

        location.grant.value = LocationGrant.Approximate
        gone(Tags.IDENTITY_LOCATION_OFF)
        rowShows(Tags.IDENTITY_SHARE_LOCATION, areaApproximate)
        shown(Tags.IDENTITY_PRECISION)
        effective(runtime, 3u)
    }

    /**
     * The real ask, answered in Android's dialog: Approximate, then While
     * using the app. Gated (`-e location ask`), with location revoked
     * before the run (`pm revoke <package> android.permission.ACCESS_FINE_LOCATION`
     * and `…ACCESS_COARSE_LOCATION`): revoking ends the app's process.
     */
    @Test
    fun theSystemDialogGrantsApproximate() {
        assumeTrue("-e location ask", InstrumentationRegistry.getArguments().getString("location") == "ask")
        assumeTrue(
            "location is granted: revoke it before the run",
            ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_COARSE_LOCATION) != PackageManager.PERMISSION_GRANTED,
        )
        application.useRealLocation()
        val runtime = open(LocationGrant.None)
        compose.onNodeWithTag(Tags.IDENTITY_SHARE_LOCATION).performScrollTo().performClick()
        val device = UiDevice.getInstance(instrumentation)
        val coarse = device.wait(Until.findObject(By.res(CONTROLLER, "permission_location_accuracy_radio_coarse")), TIMEOUT)
            ?: device.wait(Until.findObject(By.text("Approximate")), TIMEOUT)
        coarse.click()
        val whileInUse = device.wait(Until.findObject(By.res(CONTROLLER, "permission_allow_foreground_only_button")), TIMEOUT)
        whileInUse.click()
        compose.waitUntil(TIMEOUT) { runtime.locationGrant.value == LocationGrant.Approximate }
        rowShows(Tags.IDENTITY_SHARE_LOCATION, areaApproximate)
        assertEquals(5.toUByte(), stored(runtime))
        effective(runtime, 3u)
        shell("log -t umsh.test share-location-approximate-granted")
    }

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command))
            .use { it.readBytes().decodeToString() }

    private companion object {
        const val TIMEOUT = 10_000L
        const val CONTROLLER = "com.android.permissioncontroller"
    }
}
