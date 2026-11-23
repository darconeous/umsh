package com.voria.umsh.features

import android.content.Intent
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.Tags
import com.voria.umsh.services.notifications.NotificationPermission
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Assume.assumeTrue
import org.junit.Rule
import org.junit.Test

/**
 * The POST_NOTIFICATIONS ask (§6.1, §9): once, after a radio first carries
 * the phone, with the app in front; never on Android 12. Android's dialog
 * is seen as the activity pausing, and dismissed with Back.
 *
 * On Android 13 and later this needs the permission not granted, and
 * revoking it ends the app's process, so not from here: the run revokes it
 * first (`pm revoke <package> android.permission.POST_NOTIFICATIONS`), or
 * the test is skipped.
 */
class NotificationAskTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createEmptyComposeRule()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val preferences get() = fresh.host.preferences

    private fun launch(): ActivityScenario<MainActivity> = ActivityScenario.launch(
        Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_STAGING, true),
    )

    /** The staged air carries the phone: the first attach. */
    private fun attached() = runBlocking {
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
    }

    private fun ActivityScenario<MainActivity>.waitFor(state: Lifecycle.State) =
        compose.waitUntil(TIMEOUT) { this.state == state }

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command))
            .use { it.readBytes().decodeToString() }

    /** Android's dialog, once it has the focus (a Back before that reaches the app), dismissed with Back. */
    private fun dismissDialog() {
        compose.waitUntil(TIMEOUT) { shell("dumpsys window").lineSequence().any { "mCurrentFocus" in it && "GrantPermissions" in it } }
        shell("input keyevent KEYCODE_BACK")
    }

    private fun asked() = runBlocking { preferences.notificationsAsked() }

    private fun blocked() = runBlocking { preferences.notificationsBlocked.first() }

    @Test
    fun askedOnceAfterTheFirstAttachAndBackLeavesItAskable() {
        assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
        assumeFalse("POST_NOTIFICATIONS is granted: revoke it before the run", NotificationPermission.granted(context))
        val first = launch()
        attached()
        compose.waitUntil(TIMEOUT) { asked() }
        // Android's dialog is up over the activity.
        first.waitFor(Lifecycle.State.STARTED)
        dismissDialog()
        first.waitFor(Lifecycle.State.RESUMED)
        assertFalse(NotificationPermission.granted(context))
        // Dismissed is not refused for good: Android would still show it.
        assertFalse(blocked())
        first.close()

        // Not asked again.
        val again = launch()
        attached()
        again.waitFor(Lifecycle.State.RESUMED)
        Thread.sleep(SETTLE_MS)
        assertEquals(Lifecycle.State.RESUMED, again.state)

        // Settings says they are off, and its Turn on asks again.
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_NOTIFICATIONS).performScrollTo().performClick()
        compose.onNodeWithTag(Tags.NOTIFICATIONS_OFF_CARD).assertIsDisplayed()
        compose.onNodeWithTag(Tags.NOTIFICATIONS_TURN_ON).performClick()
        again.waitFor(Lifecycle.State.STARTED)
        dismissDialog()
        again.waitFor(Lifecycle.State.RESUMED)
        assertFalse(blocked())
        again.close()
    }

    @Test
    fun notAskedBeforeAndroid13() {
        assumeTrue(Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU)
        val scenario = launch()
        attached()
        scenario.waitFor(Lifecycle.State.RESUMED)
        Thread.sleep(SETTLE_MS)
        assertTrue(NotificationPermission.granted(context))
        assertFalse(asked())
        assertEquals(Lifecycle.State.RESUMED, scenario.state)
        scenario.close()
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 3_000L
    }
}
