package com.voria.umsh.features

import android.Manifest
import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.graphics.Bitmap
import android.os.Build
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.core.app.NotificationManagerCompat
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.CoreKind
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.MainActivity
import com.voria.umsh.app.Tags
import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.core.UlcpChargeState
import com.voria.umsh.core.UlcpHostOwnership
import com.voria.umsh.services.background.RadioServiceDecision
import com.voria.umsh.services.background.RadioServiceNotification
import com.voria.umsh.services.notifications.NotificationChannels
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.services.radio.RadioKind
import com.voria.umsh.services.radio.RadioSnapshot
import java.io.File
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test

/**
 * The radio notification's states (`notifications.svg` 3): title, text and
 * action for each, built as the service builds them, and its tap opening
 * Radio Detail. With `-e shots <light|dark>` each of the five states is
 * posted in turn and the shade captured.
 */
class RadioNotificationTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<MainActivity>()

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val now = 1_800_000_000_000L

    @Before
    fun allowNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    @After
    fun clear() {
        NotificationManagerCompat.from(context).cancel(SHOT_ID)
    }

    private fun run(link: RadioServiceDecision.Link, percent: Int?, charge: UlcpChargeState?, readAgoMs: Long) = RadioServiceDecision.Run(
        link,
        RadioKind.Ble,
        RadioSnapshot(
            phase = when (link) {
                RadioServiceDecision.Link.Connected -> MobileRadioPhase.ATTACHED
                RadioServiceDecision.Link.Connecting -> MobileRadioPhase.CONNECTING
                RadioServiceDecision.Link.Reconnecting -> MobileRadioPhase.RECONNECTING
                RadioServiceDecision.Link.Waiting -> MobileRadioPhase.WAITING_FOR_RADIO
            },
            name = "T1000-E",
            linkId = "C0:FF:EE:00:00:01",
            host = UlcpHostOwnership.OURS,
            batteryPercent = percent,
            batteryMillivolts = null,
            charge = charge,
            batteryReadAtMs = now - readAgoMs,
            problem = null,
            carriesThisPhone = link == RadioServiceDecision.Link.Connected,
            reportsBattery = true,
            batteryCached = link != RadioServiceDecision.Link.Connected,
        ),
    )

    /** The board's catalog: Connected, Charging, External power, Reconnecting, Waiting. */
    private val catalog get() = listOf(
        run(RadioServiceDecision.Link.Connected, 78, UlcpChargeState.DISCHARGING, 0),
        run(RadioServiceDecision.Link.Connected, 78, UlcpChargeState.CHARGING, 0),
        run(RadioServiceDecision.Link.Connected, 100, UlcpChargeState.CHARGED, 0),
        run(RadioServiceDecision.Link.Reconnecting, 78, null, 2 * 60_000L),
        run(RadioServiceDecision.Link.Waiting, 64, null, 60 * 60_000L),
    )

    private fun Notification.title() = extras.getCharSequence(Notification.EXTRA_TITLE)?.toString()

    private fun Notification.text() = extras.getCharSequence(Notification.EXTRA_TEXT)?.toString()

    @Test
    fun eachStateReadsAsTheBoardDrawsIt() {
        val built = catalog.map { RadioServiceNotification.build(context, it, now) }
        val disconnect = context.getString(R.string.radio_disconnect)
        val stop = context.getString(R.string.radio_notif_stop)
        assertEquals(
            listOf("Connected to T1000-E", "Connected to T1000-E", "Connected to T1000-E", "Reconnecting to T1000-E", "Waiting for T1000-E"),
            built.map { it.title() },
        )
        assertEquals(
            listOf("Battery 78%", "Charging 78%", "External power", "Last battery 78%, 2 min. ago", "Last battery 64%, 1 hr. ago"),
            built.map { it.text() },
        )
        assertEquals(listOf(disconnect, disconnect, disconnect, disconnect, stop), built.map { it.actions.single().title.toString() })
        assertEquals(
            listOf(R.drawable.ic_sensors, R.drawable.ic_sensors, R.drawable.ic_sensors, R.drawable.ic_sensors, R.drawable.ic_sensors_off),
            built.map { it.smallIcon.resId },
        )
        built.forEach { notification ->
            assertEquals(NotificationChannels.RADIO, notification.channelId)
            assertEquals(Notification.VISIBILITY_PUBLIC, notification.visibility)
            assertEquals("T1000-E", notification.extras.getCharSequence(Notification.EXTRA_SUB_TEXT)?.toString())
            assertTrue(notification.contentIntent.isActivity)
        }
        // Before anything is read: Connecting, with no text.
        val first = RadioServiceNotification.build(context, null, now)
        assertEquals(context.getString(R.string.radio_notif_connecting_unnamed), first.title())
        assertNull(first.text())
        shoot()
    }

    /**
     * The notification's tap: its PendingIntent is Radio Detail's (the same
     * token Android keeps for that intent), and the running activity,
     * handed that intent, opens Radio Detail. (Sending the PendingIntent
     * itself would start the activity in a task of its own here, beside the
     * test's.)
     */
    @Test
    fun theTapOpensRadioDetail() {
        // The staged radio: Radio Detail closes itself with no radio to show.
        fresh.host.setStaging(true)
        val ready = runBlocking {
            withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready && it.runtime.kind == CoreKind.Staging } }
        } as HostState.Ready
        runBlocking {
            withTimeout(TIMEOUT) { ready.runtime.radio.first { it != null } }
            ready.runtime.setOnboarding(OnboardingStep.Done).await()
        }
        compose.waitUntil(TIMEOUT) { compose.onAllNodes(androidx.compose.ui.test.hasTestTag(Tags.CONVERSATIONS_ROOT)).fetchSemanticsNodes().isNotEmpty() }
        val tap = RadioServiceNotification.build(context, catalog.first(), now).contentIntent
        val radioDetail = PendingIntent.getActivity(
            context,
            0,
            MainActivity.radioDetailIntent(context),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_NO_CREATE,
        )
        assertNotNull(radioDetail)
        assertEquals(radioDetail, tap)
        compose.activityRule.scenario.onActivity { it.takeRequest(MainActivity.radioDetailIntent(it)) }
        compose.waitUntil(TIMEOUT) { compose.onAllNodes(androidx.compose.ui.test.hasTestTag(Tags.RADIO_DETAIL)).fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithTag(Tags.RADIO_DETAIL).assertIsDisplayed()
    }

    /** `-e shots <suffix>`: each of the catalog's states posted on its own, expanded in the shade, and captured. */
    private fun shoot() {
        val suffix = InstrumentationRegistry.getArguments().getString("shots") ?: return
        val manager = NotificationManagerCompat.from(context)
        val automation = instrumentation.uiAutomation
        val directory = File(context.getExternalFilesDir(null), "shots").apply { mkdirs() }
        catalog.zip(STATE_NAMES).forEachIndexed { index, (run, name) ->
            @Suppress("MissingPermission")
            manager.notify(SHOT_ID, RadioServiceNotification.build(context, run, now))
            Thread.sleep(POST_MS)
            assertEquals(1, context.getSystemService(NotificationManager::class.java).activeNotifications.count { it.id == SHOT_ID })
            automation.executeShellCommand("cmd statusbar expand-notifications").close()
            Thread.sleep(SHADE_MS)
            expandAll(automation.rootInActiveWindow)
            Thread.sleep(SHADE_MS)
            val bitmap = automation.takeScreenshot()
            automation.executeShellCommand("cmd statusbar collapse").close()
            Thread.sleep(POST_MS)
            bitmap?.let { shot ->
                File(directory, "notifications-3-${index + 1}-$name-$suffix.png").outputStream().use { shot.compress(Bitmap.CompressFormat.PNG, 100, it) }
            }
        }
        manager.cancel(SHOT_ID)
    }

    /** Opens every collapsed group or notification on screen, so each shows its text and action. */
    private fun expandAll(node: android.view.accessibility.AccessibilityNodeInfo?) {
        node ?: return
        if (node.contentDescription?.toString() == "Expand" && node.isClickable) {
            node.performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_CLICK)
        }
        (0 until node.childCount).forEach { expandAll(node.getChild(it)) }
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val SHADE_MS = 3_000L
        const val POST_MS = 500L

        /** Clear of the service's own ID (1) and the message notifications'. */
        const val SHOT_ID = 9_100
        val STATE_NAMES = listOf("connected", "charging", "external-power", "reconnecting", "waiting")
    }
}
