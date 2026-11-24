package com.voria.umsh.features

import android.content.Intent
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
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

    /** Android's dialog has the focus. */
    private fun dialogUp() = shell("dumpsys window").lineSequence().any { "mCurrentFocus" in it && "GrantPermissions" in it }

    /** Android's dialog, once it has the focus (a Back before that reaches the app), dismissed with Back. */
    private fun dismissDialog() {
        compose.waitUntil(TIMEOUT) { dialogUp() }
        shell("input keyevent KEYCODE_BACK")
    }

    private fun asked() = runBlocking { preferences.notificationsAsked() }

    /**
     * The app's activity is the one resumed, by the system's own record: a
     * link delivered by `am start` arrives as a new intent, after which the
     * scenario ignores the activity's lifecycle (its intent no longer matches).
     */
    /** The app's activity has stopped (Home pauses it first; only a stop is leaving). */
    private fun stopped(): Boolean {
        var stopped = false
        instrumentation.runOnMainSync {
            val monitor = ActivityLifecycleMonitorRegistry.getInstance()
            stopped = monitor.getActivitiesInStage(Stage.STOPPED).any { it is MainActivity }
        }
        return stopped
    }

    private fun resumed(): Boolean = shell("dumpsys activity activities").lines()
        .any { it.trimStart().startsWith("ResumedActivity:") && it.contains("${context.packageName}/.app.MainActivity") }

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

    /**
     * D7's cost: a link arriving while the first ask is up closes Android's
     * dialog unanswered. That is no answer: the ask is not used up, and not
     * blocked, and it does not come back over the link's page, only once the
     * app has been left and is back with a radio attached.
     */
    @Test
    fun aLinkClosingTheAskLeavesItForLater() {
        assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
        assumeFalse("POST_NOTIFICATIONS is granted: revoke it before the run", NotificationPermission.granted(context))
        launch()
        attached()
        compose.waitUntil(TIMEOUT) { asked() }
        compose.waitUntil(TIMEOUT) { dialogUp() }
        shell("am start -a android.intent.action.VIEW -d umsh:gs:hike-club ${context.packageName}")
        compose.waitUntil(TIMEOUT) { !asked() }
        compose.waitUntil(TIMEOUT) { resumed() }
        compose.waitUntil(TIMEOUT) { compose.onAllNodesWithTag(Tags.CHANNEL_JOIN, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty() }
        assertFalse(blocked())
        // Not again over the link's page.
        Thread.sleep(SETTLE_MS)
        assertTrue(resumed())
        assertFalse(asked())

        // Left and back, with the radio still attached: asked again.
        shell("input keyevent KEYCODE_HOME")
        compose.waitUntil(TIMEOUT) { stopped() }
        shell("am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -n ${context.packageName}/.app.MainActivity")
        compose.waitUntil(TIMEOUT) { asked() }
        dismissDialog()
        compose.waitUntil(TIMEOUT) { resumed() }
        assertFalse(blocked())
        // Finished directly: the scenario no longer follows the activity, and would wait on it.
        instrumentation.runOnMainSync {
            ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED).filterIsInstance<MainActivity>().forEach { it.finish() }
        }
        compose.waitUntil(TIMEOUT) { !resumed() }
    }

    /**
     * Next time heard (§3.2), refused so far: the tap arms the node in the
     * core and then asks, once per tap; Back leaves it armed. Disarming
     * never asks.
     */
    @Test
    fun nextTimeHeardArmsThenAsks() {
        assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
        assumeFalse("POST_NOTIFICATIONS is granted: revoke it before the run", NotificationPermission.granted(context))
        // The first attach's ask is the test above's.
        runBlocking { preferences.setNotificationsAsked() }
        val scenario = launch()
        attached()
        scenario.waitFor(Lifecycle.State.RESUMED)
        val runtime = (fresh.host.state.value as HostState.Ready).runtime
        fun tallac() = runtime.appState.value!!.peers.first { it.advertisedName == "Tallac Ridge" }
        compose.waitUntil(TIMEOUT) { runtime.appState.value?.peers?.any { it.advertisedName == "Tallac Ridge" } == true }
        compose.onNodeWithTag(Tags.NAV_PEERS).performClick()
        compose.onNodeWithTag(Tags.PEERS_LIST).performScrollToNode(hasTestTag(Tags.peerRow(tallac().address)))
        compose.onNodeWithTag(Tags.peerRow(tallac().address)).performClick()
        compose.onNodeWithTag(Tags.PEER_NOTIFY_HEARD).performScrollTo().performClick()
        scenario.waitFor(Lifecycle.State.STARTED)
        dismissDialog()
        scenario.waitFor(Lifecycle.State.RESUMED)
        assertTrue(tallac().notifyWhenHeard)
        assertFalse(NotificationPermission.granted(context))

        compose.onNodeWithTag(Tags.PEER_NOTIFY_HEARD).performClick()
        compose.waitUntil(TIMEOUT) { !tallac().notifyWhenHeard }
        Thread.sleep(SETTLE_MS)
        assertEquals(Lifecycle.State.RESUMED, scenario.state)
        scenario.close()
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
