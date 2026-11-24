package com.voria.umsh.features

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.test.junit4.v2.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.core.content.ContextCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.Tags
import com.voria.umsh.services.preferences.OnboardingStep
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * `umsh:` view intents in the real activity (D7): a cold launch, a link
 * arriving at the running app, a recreation that does not open it twice,
 * one waiting through onboarding across a recreation, a notification's tap
 * that never reaches the link route, and Close going back out of the app.
 */
class LinkActivityTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createEmptyComposeRule()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext

    @Before
    fun noNotificationAsk() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
        runBlocking { fresh.host.preferences.setNotificationsAsked() }
    }

    private fun launcherIntent(): Intent = Intent(context, MainActivity::class.java).putExtra(MainActivity.EXTRA_STAGING, true)

    private fun runtime(onboarded: Boolean = true): AppRuntime = runBlocking {
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        if (onboarded) ready.runtime.setOnboarding(OnboardingStep.Done).await()
        withTimeout(TIMEOUT) { ready.runtime.appState.first { state -> state?.peers?.any { it.advertisedName == "Maya Ortiz" } == true } }
        ready.runtime
    }

    private fun present(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().isNotEmpty()

    private fun count(tag: String) = compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().size

    private fun waitForTag(tag: String) = compose.waitUntil(TIMEOUT) { present(tag) }

    /** Whether [condition] became true within [millis]. */
    private fun waitFor(millis: Long, condition: () -> Boolean): Boolean =
        runCatching { compose.waitUntil(millis, condition) }.isSuccess

    private fun hasTextIn(tag: String, wanted: String): Boolean =
        compose.onAllNodesWithTag(tag, useUnmergedTree = true).fetchSemanticsNodes().any { node ->
            node.config.getOrNull(SemanticsProperties.Text)?.any { it.text.contains(wanted) } == true
        }

    /**
     * A link opened as `adb shell am start -a VIEW -d <link> <package>`
     * opens it, on the staging core: by the package, not the component, so
     * the manifest's filter resolves it, as it does for another app's link.
     */
    private fun openByShell(link: String, args: String = "") {
        shell("am start -a android.intent.action.VIEW -d $link $args --ez ${MainActivity.EXTRA_STAGING} true ${context.packageName}")
    }

    /** The app started as the launcher starts it (by its component: the launcher's filter has no DEFAULT), on the staging core. */
    private fun launch() {
        shell("am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER --ez ${MainActivity.EXTRA_STAGING} true -n ${context.packageName}/.app.MainActivity")
    }

    /** This process's MainActivity instances, in any stage. */
    private fun activities(): List<android.app.Activity> = Stage.values().flatMap { stage ->
        ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(stage)
    }.filterIsInstance<MainActivity>().distinct()

    /** Activities this test started by the shell are finished, so the next test starts cold. */
    @After
    fun finishActivities() {
        instrumentation.runOnMainSync { activities().forEach { it.finish() } }
        instrumentation.waitForIdleSync()
    }

    /** The app is off the screen: its MainActivity stopped, and none other (an earlier test's is destroyed) shown. */
    private fun stopped(): Boolean {
        var stopped = false
        instrumentation.runOnMainSync {
            val monitor = ActivityLifecycleMonitorRegistry.getInstance()
            val stages = activities().map(monitor::getLifecycleStageOf)
            stopped = Stage.STOPPED in stages && stages.all { it == Stage.STOPPED || it == Stage.DESTROYED }
        }
        return stopped
    }

    /** The app's activity is the one resumed, by the system's own record. */
    private fun resumed(): Boolean = shell("dumpsys activity activities").lines()
        .any { it.trimStart().startsWith("ResumedActivity:") && it.contains("${context.packageName}/.app.MainActivity") }

    private fun shell(command: String): String =
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command))
            .use { it.readBytes().decodeToString() }

    /**
     * The app's activities in the system's task records: one MainActivity, ever. Only the
     * tasks' `Hist #n` entries count; elsewhere the dump names records that are gone (API 36's
     * RotationHistory keeps the activity an earlier test rotated).
     */
    private fun mainActivities(): Int =
        Regex("""Hist\s+#\d+: ActivityRecord\{(\w+) u\d+ ${Regex.escape(context.packageName)}/\.app\.MainActivity""")
            .findAll(shell("dumpsys activity activities")).map { it.groupValues[1] }.toSet().size

    /**
     * Cold (no activity yet): the link launches the app onto the node's
     * page, above the shell, with Close; Close leaves the app. Started by
     * the shell, as `adb shell am start` does, rather than through
     * ActivityScenario: a new intent replaces the activity's own, which
     * ActivityScenario tracks the activity by.
     */
    @Test
    fun aLinkLaunchesTheAppOntoItsPageAndCloseLeaves() {
        val marmot = ImportFixtures.signedLink(0x71)
        openByShell(marmot.link)
        runtime()
        waitForTag(Tags.PEER_PAGE)
        compose.waitUntil(TIMEOUT) { hasTextIn(Tags.PEER_NAME, "Marmot") }
        assertTrue(present(Tags.TOP_BAR_CLOSE))
        assertFalse(present(Tags.SHELL))
        assertEquals(1, mainActivities())

        // Another app opened it: Close goes back there, and the page is gone when UMSH comes back.
        compose.onNodeWithTag(Tags.TOP_BAR_CLOSE).performClick()
        compose.waitUntil(TIMEOUT) { !resumed() }
        launch()
        compose.waitUntil(TIMEOUT) { resumed() }
        waitForTag(Tags.SHELL)
        assertFalse(present(Tags.PEER_PAGE))
        assertEquals(1, mainActivities())
    }

    /** Warm, on another screen: the link reaches the running activity (one instance), and a recreation opens it once. */
    @Test
    fun aLinkReachesTheRunningAppOnceAcrossARecreation() {
        launch()
        runtime()
        waitForTag(Tags.NAV_PEERS)
        compose.onAllNodesWithTag(Tags.NAV_PEERS)[0].performClick()
        waitForTag(Tags.PEERS_LIST)

        val marmot = ImportFixtures.signedLink(0x72)
        openByShell(marmot.link)
        waitForTag(Tags.PEER_PAGE)
        compose.waitUntil(TIMEOUT) { hasTextIn(Tags.PEER_NAME, "Marmot") }
        assertEquals(1, mainActivities())

        instrumentation.runOnMainSync { activities().forEach { it.recreate() } }
        compose.waitForIdle()
        waitForTag(Tags.PEER_PAGE)
        // Restored with the stacks, not opened again over itself: one page, for as long as a second would take.
        assertFalse(waitFor(SETTLE_MS) { count(Tags.PEER_PAGE) > 1 })
        assertEquals(1, mainActivities())

        // Another app's link, across the recreation: Back leaves the app, and the launcher brings back Peers.
        UiDevice.getInstance(instrumentation).pressBack()
        compose.waitUntil(TIMEOUT) { !resumed() }
        launch()
        compose.waitUntil(TIMEOUT) { resumed() }
        waitForTag(Tags.PEERS_LIST)
        assertFalse(present(Tags.PEER_PAGE))
    }

    /**
     * A link's page left by Home rather than Close, and brought back by the
     * launcher: the link's flow is over, so Close returns to the shell
     * instead of leaving the app again.
     */
    @Test
    fun aLinksPageBroughtBackByTheLauncherClosesToTheShell() {
        val marmot = ImportFixtures.signedLink(0x75)
        openByShell(marmot.link)
        runtime()
        waitForTag(Tags.PEER_PAGE)
        compose.waitUntil(TIMEOUT) { hasTextIn(Tags.PEER_NAME, "Marmot") }

        UiDevice.getInstance(instrumentation).pressHome()
        // Gone from the screen, not merely paused by the transition home.
        compose.waitUntil(TIMEOUT) { stopped() }
        launch()
        compose.waitUntil(TIMEOUT) { resumed() }
        waitForTag(Tags.PEER_PAGE)
        compose.onNodeWithTag(Tags.TOP_BAR_CLOSE).performClick()
        waitForTag(Tags.SHELL)
        assertFalse(present(Tags.PEER_PAGE))
        assertTrue(resumed())
    }

    /**
     * A web page's link can carry the app's own extras: it opens its link
     * and nothing they ask (no conversation, no Radio Detail).
     */
    @Test
    fun aBrowsersLinkOpensOnlyItsLink() {
        launch()
        val runtime = runtime()
        waitForTag(Tags.SHELL)
        val maya = runtime.appState.value!!.peers.first { it.advertisedName == "Maya Ortiz" }
        val conversations = runtime.appState.value!!.conversations.map { it.address }.toSet()

        val marmot = ImportFixtures.signedLink(0x76)
        openByShell(
            marmot.link,
            "-c android.intent.category.BROWSABLE --es ${MainActivity.EXTRA_PEER} ${maya.address} " +
                "--es ${MainActivity.EXTRA_CONVERSATION} ${maya.address} --ez ${MainActivity.EXTRA_RADIO_DETAIL} true",
        )
        waitForTag(Tags.PEER_PAGE)
        compose.waitUntil(TIMEOUT) { hasTextIn(Tags.PEER_NAME, "Marmot") }
        assertFalse(waitFor(SETTLE_MS) { present(Tags.RADIO_DETAIL) || present(Tags.THREAD) || count(Tags.PEER_PAGE) > 1 })
        assertEquals(conversations, runtime.appState.value!!.conversations.map { it.address }.toSet())
    }

    /** A link opened during onboarding waits until it is done, also across a recreation (its saved state). */
    @Test
    fun aLinkWaitsOutOnboardingAcrossARecreation() {
        val marmot = ImportFixtures.signedLink(0x73)
        // The live core: a fresh one starts at Welcome (staging starts onboarded).
        val link = Intent(Intent.ACTION_VIEW, Uri.parse(marmot.link), context, MainActivity::class.java)
        val scenario = ActivityScenario.launch<MainActivity>(link)
        val runtime = runBlocking {
            val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
            ready.runtime
        }
        waitForTag(Tags.ONBOARDING)
        scenario.recreate()
        waitForTag(Tags.ONBOARDING)
        assertFalse(present(Tags.PEER_PAGE))

        runBlocking { runtime.setOnboarding(OnboardingStep.Done).await() }
        waitForTag(Tags.PEER_PAGE)
        compose.waitUntil(TIMEOUT) { hasTextIn(Tags.PEER_NAME, "Marmot") }
        scenario.close()
    }

    /** A notification's tap is a view intent too, of its own scheme: it opens its conversation, never the link route. */
    @Test
    fun aNotificationsTapNeverReachesTheLinkRoute() {
        val scenario = ActivityScenario.launch<MainActivity>(launcherIntent())
        val runtime = runtime()
        val maya = runtime.appState.value!!.peers.first { it.advertisedName == "Maya Ortiz" }
        val conversation = runBlocking { runtime.startConversation(maya.address).await() }
        scenario.onActivity { activity ->
            val tap = MainActivity.conversationIntent(activity, conversation)
                .setData(Uri.Builder().scheme("umsh-notification").authority("open").appendPath(conversation).build())
            activity.takeRequest(tap)
        }
        waitForTag(Tags.THREAD)
        assertFalse(present(Tags.LINK_IMPORT_SHEET))
        assertFalse(present(Tags.PEER_PAGE))
        scenario.close()
    }

    /**
     * D7's cost: a link arriving while Android's camera dialog is up closes
     * the dialog, and the ask reads as dismissed, not refused. Gated (`-e
     * camera link`), with the camera not granted (a fresh install).
     */
    @Test
    fun aLinkUnderTheCameraDialogLeavesTheAskDismissed() {
        assumeTrue("-e camera link", InstrumentationRegistry.getArguments().getString("camera") == "link")
        assumeTrue(
            "the camera is granted: reinstall before the run",
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED,
        )
        launch()
        runtime()
        waitForTag(Tags.CONVERSATIONS_SCAN)
        compose.onNodeWithTag(Tags.CONVERSATIONS_SCAN).performClick()
        val device = UiDevice.getInstance(instrumentation)
        compose.waitUntil(TIMEOUT) { device.findObject(By.res(CONTROLLER, "permission_deny_button")) != null }

        val marmot = ImportFixtures.signedLink(0x74)
        shell("am start -a android.intent.action.VIEW -d ${marmot.link} ${context.packageName}")
        compose.waitUntil(TIMEOUT) { device.findObject(By.res(CONTROLLER, "permission_deny_button")) == null }
        waitForTag(Tags.PEER_PAGE)
        assertEquals(false, runBlocking { fresh.host.preferences.cameraBlocked.first() })
        assertEquals(PackageManager.PERMISSION_DENIED, ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA))
        // No dialog left in any task: the system's records of it, if any, are of one finished.
        val records = shell("dumpsys activity activities").lines().filter { it.contains("GrantPermissionsActivity") }
        records.forEach { android.util.Log.i("umsh.test", "camera dialog record: ${it.trim()}") }
        assertFalse(records.any { it.trimStart().startsWith("* Hist") || it.contains("ResumedActivity") })
        shell("log -t umsh.test link-under-camera-dialog-dismissed")
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SETTLE_MS = 1_500L
        const val CONTROLLER = "com.android.permissioncontroller"
    }
}
