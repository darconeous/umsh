package com.voria.umsh.features

import android.Manifest
import android.app.Notification
import android.app.NotificationManager
import android.content.Intent
import android.graphics.Bitmap
import android.os.Build
import android.os.Bundle
import android.service.notification.StatusBarNotification
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.pm.ShortcutManagerCompat
import androidx.core.os.BundleCompat
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.EraseMode
import com.voria.umsh.app.EraseOutcome
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.ReplyOutcome
import com.voria.umsh.app.ShellState
import com.voria.umsh.app.Tags
import com.voria.umsh.app.TestWindows
import com.voria.umsh.app.UmshApplication
import com.voria.umsh.app.UmshKey
import com.voria.umsh.app.UmshShell
import com.voria.umsh.app.rememberShellState
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileNotificationEventRecord
import com.voria.umsh.designsystem.LocalWindowOverride
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.services.notifications.MessageNotifier
import com.voria.umsh.services.notifications.NotificationChannels
import com.voria.umsh.services.radio.StagingRadioConnection
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
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
 * Message notifications (P2d) over real cores, read back from Android's own
 * list of the app's notifications: what is posted and where, what is left
 * alone for the conversation on screen, Reply and Mark as read through the
 * notification's own PendingIntents, EMERGENCY's missing Reply, the lock
 * screen option and what an erase withdraws. With `-e shots <light|dark>`
 * the shade is also captured into the app's external files, under `shots/`.
 */
class NotificationsTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private lateinit var shell: ShellState

    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context get() = instrumentation.targetContext
    private val notifier: MessageNotifier get() = (context.applicationContext as UmshApplication).notifier
    private val air: StagingRadioConnection get() = checkNotNull(fresh.host.stagingRadio.value) { "no staged air" }

    @Before
    fun allowNotifications() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.POST_NOTIFICATIONS)
        }
        NotificationManagerCompat.from(context).cancelAll()
    }

    @After
    fun clear() {
        notifier.keyguardLocked = { false }
        NotificationManagerCompat.from(context).cancelAll()
        ShortcutManagerCompat.removeAllDynamicShortcuts(context)
    }

    private fun runtime(staging: Boolean = true): AppRuntime = runBlocking {
        fresh.host.preferences.setFallbackScheme(true)
        fresh.host.ensureRuntime(staging)
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        val runtime = ready.runtime
        withTimeout(TIMEOUT) { runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        if (staging) {
            withTimeout(TIMEOUT) { runtime.appState.first { state -> state?.directConversations?.isNotEmpty() == true } }
            withTimeout(TIMEOUT) { runtime.radio.first { it?.carriesThisPhone == true } }
        }
        runtime
    }

    private fun show(runtime: AppRuntime) {
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                CompositionLocalProvider(
                    LocalAppRuntime provides runtime,
                    LocalAppCoreHost provides fresh.host,
                    LocalWindowOverride provides TestWindows.Phone,
                ) {
                    val state = rememberShellState()
                    shell = state
                    UmshShell(state)
                }
            }
        }
        compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed()
    }

    private fun direct(runtime: AppRuntime): String = runtime.appState.value!!.directConversations.first().address

    /** The staged named channel's conversation, which the speaking peer can talk on. */
    private fun namedChannel(runtime: AppRuntime): String =
        runtime.appState.value!!.channelConversations.first { it.channel.kind == ChannelKind.Named }.address

    /**
     * The app's own notifications. Android 16 adds a summary of its own (tag
     * `…g:Aggregate_AlertingSection`) once the shade bundles them, which the
     * app never posts.
     */
    private fun active(): List<StatusBarNotification> =
        context.getSystemService(NotificationManager::class.java).activeNotifications
            .filter { it.notification.flags and Notification.FLAG_GROUP_SUMMARY == 0 }

    private fun conversationNotification(address: String): StatusBarNotification? =
        active().firstOrNull { it.tag == address && it.id == MessageNotifier.MESSAGE_ID }

    private fun waitForNotification(condition: (List<StatusBarNotification>) -> Boolean) =
        compose.waitUntil(TIMEOUT) { condition(active()) }

    private fun lines(notification: Notification): List<NotificationCompat.MessagingStyle.Message> =
        NotificationCompat.MessagingStyle.extractMessagingStyleFromNotification(notification)?.messages.orEmpty()

    private fun peerSays(body: String, onChannel: Boolean = false) = runBlocking { air.air.peerSays(body, onChannel) }

    /** The transcript holds [body], read from the core. */
    private fun waitForMessage(runtime: AppRuntime, address: String, body: String, outbound: Boolean = false) =
        compose.waitUntil(TIMEOUT) {
            runBlocking { runtime.transcriptNewest(address, 50) }.messages.any { it.body == body && it.isOutbound == outbound }
        }

    private fun action(notification: Notification, label: String): Notification.Action? =
        notification.actions?.firstOrNull { it.title.toString() == label }

    private fun shot(name: String) {
        val suffix = InstrumentationRegistry.getArguments().getString("shots") ?: return
        val automation = instrumentation.uiAutomation
        automation.executeShellCommand("cmd statusbar expand-notifications").close()
        Thread.sleep(SHADE_MS)
        // Android 16 bundles an app's notifications; the shot shows them opened.
        expandFirstGroup(automation.rootInActiveWindow)
        Thread.sleep(SHADE_MS)
        val bitmap = automation.takeScreenshot()
        automation.executeShellCommand("cmd statusbar collapse").close()
        Thread.sleep(SHADE_MS)
        bitmap ?: return
        val directory = File(context.getExternalFilesDir(null), "shots").apply { mkdirs() }
        File(directory, "$name-$suffix.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    /** Clicks the first "Expand" control on screen (the shade's bundle of this app's notifications). */
    private fun expandFirstGroup(node: android.view.accessibility.AccessibilityNodeInfo?): Boolean {
        node ?: return false
        if (node.contentDescription?.toString() == "Expand" && node.isClickable) {
            return node.performAction(android.view.accessibility.AccessibilityNodeInfo.ACTION_CLICK)
        }
        return (0 until node.childCount).any { expandFirstGroup(node.getChild(it)) }
    }

    @Test
    fun aPeerMessageIsPostedAsItsConversation() {
        val runtime = runtime()
        show(runtime)
        val address = direct(runtime)
        peerSays("Are you at the saddle yet?")
        waitForNotification { conversationNotification(address) != null }
        val posted = conversationNotification(address)!!.notification
        assertEquals(NotificationChannels.DIRECT, posted.channelId)
        assertEquals(address, posted.shortcutId)
        assertEquals(Notification.CATEGORY_MESSAGE, posted.category)
        assertEquals(Notification.VISIBILITY_PRIVATE, posted.visibility)
        assertEquals(context.getString(R.string.notification_public_title), posted.publicVersion.extras.getCharSequence(Notification.EXTRA_TITLE).toString())
        assertEquals(context.getString(R.string.notification_public_text), posted.publicVersion.extras.getCharSequence(Notification.EXTRA_TEXT).toString())
        assertEquals("Are you at the saddle yet?", lines(posted).last().text.toString())
        assertNotNull(lines(posted).last().person?.icon)
        val reply = action(posted, context.getString(R.string.notification_reply))
        assertNotNull(reply)
        assertEquals(Notification.Action.SEMANTIC_ACTION_REPLY, reply!!.semanticAction)
        assertTrue(reply.remoteInputs.orEmpty().isNotEmpty())
        val read = action(posted, context.getString(R.string.notification_mark_read))
        assertEquals(Notification.Action.SEMANTIC_ACTION_MARK_AS_READ, read?.semanticAction)
        assertTrue(ShortcutManagerCompat.getDynamicShortcuts(context).any { it.id == address })

        // A second line joins the first, in the same notification.
        peerSays("Copy, heading up now.")
        waitForNotification { lines(conversationNotification(address)!!.notification).size == 2 }

        // A channel's is a group, titled by the channel, each line naming its sender.
        val channel = namedChannel(runtime)
        peerSays("Trail's clear past the second bridge.", onChannel = true)
        waitForNotification { conversationNotification(channel) != null }
        val group = conversationNotification(channel)!!.notification
        assertEquals(NotificationChannels.CHANNELS, group.channelId)
        val style = NotificationCompat.MessagingStyle.extractMessagingStyleFromNotification(group)!!
        assertTrue(style.isGroupConversation)
        assertNotNull(style.conversationTitle)
        assertNotNull(style.messages.last().person?.name)
        shot("notifications-1-shade")
    }

    @Test
    fun theConversationOnScreenIsLeftAloneAndAnotherIsTold() {
        val runtime = runtime()
        show(runtime)
        val address = direct(runtime)
        compose.runOnUiThread { shell.openDetail(UmshKey.Thread(address)) }
        compose.onNodeWithTag(Tags.THREAD).assertIsDisplayed()
        compose.waitUntil(TIMEOUT) { runtime.visibleConversation.value == address }
        peerSays("I can see you from here.")
        waitForMessage(runtime, address, "I can see you from here.")
        // The drain posts after the lists it reads; give it the same moment.
        Thread.sleep(SETTLE_MS)
        assertNull(conversationNotification(address))

        val channel = namedChannel(runtime)
        peerSays("Anyone near the ridge?", onChannel = true)
        waitForNotification { conversationNotification(channel) != null }
        assertNull(conversationNotification(address))
    }

    @Test
    fun openingAConversationWithdrawsItsNotification() {
        val runtime = runtime()
        show(runtime)
        val address = direct(runtime)
        peerSays("Ping")
        waitForNotification { conversationNotification(address) != null }
        compose.runOnUiThread { shell.openDetail(UmshKey.Thread(address)) }
        waitForNotification { conversationNotification(address) == null }
    }

    @Test
    fun replyFromTheNotificationSendsIt() {
        val runtime = runtime()
        show(runtime)
        val address = direct(runtime)
        peerSays("Are you at the saddle yet?")
        waitForNotification { conversationNotification(address) != null }
        sendReply(address, "Copy, heading up now.")
        waitForMessage(runtime, address, "Copy, heading up now.", outbound = true)
        // The notification is posted again with the reply as this phone's line, which ends its spinner.
        waitForNotification { shown ->
            val notification = shown.firstOrNull { it.tag == address && it.id == MessageNotifier.MESSAGE_ID }?.notification
            notification != null && lines(notification).last().let { it.text.toString() == "Copy, heading up now." && it.person == null }
        }
    }

    @Test
    fun aReplyThatCannotGoIsKeptAsTheDraftAndSaysSo() {
        val runtime = runtime()
        show(runtime)
        val address = direct(runtime)
        peerSays("Are you at the saddle yet?")
        waitForNotification { conversationNotification(address) != null }
        air.setLinkUp(false)
        compose.waitUntil(TIMEOUT) { runtime.radio.value?.carriesThisPhone != true }
        sendReply(address, "Copy, heading up now.")
        // The radio is waited for, then the words go under the draft.
        compose.waitUntil(REPLY_TIMEOUT) {
            runtime.appState.value?.directConversations?.firstOrNull { it.address == address }?.draftText == "Copy, heading up now."
        }
        val failed = context.getString(R.string.notice_reply_failed)
        waitForNotification { shown ->
            shown.any { it.tag == address && it.notification.channelId == NotificationChannels.PROBLEMS && it.notification.extras.getCharSequence(Notification.EXTRA_TEXT).toString() == failed }
        }
        assertTrue(runBlocking { runtime.transcriptNewest(address, 50) }.messages.none { it.isOutbound && it.body == "Copy, heading up now." })
    }

    @Test
    fun markAsReadReadsItAndTakesItAway() {
        val runtime = runtime()
        show(runtime)
        val address = direct(runtime)
        peerSays("Are you at the saddle yet?")
        waitForNotification { conversationNotification(address) != null }
        compose.waitUntil(TIMEOUT) { (runtime.appState.value?.directConversations?.first { it.address == address }?.unreadCount ?: 0) > 0 }
        val read = action(conversationNotification(address)!!.notification, context.getString(R.string.notification_mark_read))!!
        read.actionIntent.send()
        waitForNotification { conversationNotification(address) == null }
        compose.waitUntil(TIMEOUT) { runtime.appState.value?.directConversations?.first { it.address == address }?.unreadCount == 0L }
    }

    @Test
    fun emergencyOffersNoReply() {
        val runtime = runtime()
        show(runtime)
        val emergency = runtime.appState.value!!.channels.first { it.canonicalName == "emergency" }
        val address = runBlocking { runtime.openChannelConversation(emergency.id).await() }
        runBlocking {
            notifier.post(
                runtime,
                MobileNotificationEventRecord.Message(address, emergency.id, null, "Ana", null, "Rockfall at the trailhead.", false, null),
            )
        }
        waitForNotification { conversationNotification(address) != null }
        val posted = conversationNotification(address)!!.notification
        assertEquals(NotificationChannels.EMERGENCY, posted.channelId)
        assertNull(action(posted, context.getString(R.string.notification_reply)))
        assertNotNull(action(posted, context.getString(R.string.notification_mark_read)))
    }

    @Test
    fun hiddenOnTheLockScreenUntilUnlocked() {
        val runtime = runtime()
        runBlocking { fresh.host.preferences.setHideLockScreenContents(true) }
        show(runtime)
        val address = direct(runtime)
        notifier.keyguardLocked = { true }
        peerSays("Are you at the saddle yet?")
        waitForNotification { conversationNotification(address) != null }
        val hidden = conversationNotification(address)!!.notification
        assertEquals(context.getString(R.string.notification_public_title), hidden.extras.getCharSequence(Notification.EXTRA_TITLE).toString())
        assertEquals(context.getString(R.string.notification_public_text), hidden.extras.getCharSequence(Notification.EXTRA_TEXT).toString())
        assertTrue(hidden.actions.isNullOrEmpty())
        assertNotNull(BundleCompat.getParcelable(hidden.extras, MessageNotifier.EXTRA_REAL, Notification::class.java))

        notifier.keyguardLocked = { false }
        notifier.revealHidden()
        waitForNotification { shown ->
            val notification = shown.firstOrNull { it.tag == address && it.id == MessageNotifier.MESSAGE_ID }?.notification
            notification != null && lines(notification).lastOrNull()?.text.toString() == "Are you at the saddle yet?" &&
                !notification.actions.isNullOrEmpty()
        }
        // No second alert: the revealed one is posted to alert only once.
        val revealed = conversationNotification(address)!!.notification
        assertTrue(revealed.flags and Notification.FLAG_ONLY_ALERT_ONCE != 0)
    }

    @Test
    fun anEraseWithdrawsEveryNotificationAndShortcut() {
        val runtime = runtime(staging = false)
        // Any conversation's: the live core here has no radio to hear one on.
        val address = "AnotherNodeAddressThatIsNotStored"
        runBlocking {
            notifier.post(runtime, MobileNotificationEventRecord.Message(address, null, address, "Juniper", null, "Hello", false, null))
        }
        waitForNotification { conversationNotification(address) != null }
        assertTrue(ShortcutManagerCompat.getDynamicShortcuts(context).any { it.id == address })
        val outcome = runBlocking { fresh.host.erase(EraseMode.IdentityOnly, thenMint = false).await() }
        assertEquals(EraseOutcome.Done, outcome)
        waitForNotification { shown -> shown.none { it.tag != null } }
        assertTrue(ShortcutManagerCompat.getDynamicShortcuts(context).isEmpty())
    }

    /**
     * A burst into one conversation, with a reply ending among it, from
     * several threads at once: every line stays. Posts are made in turn from
     * what the notifier keeps, never read back from Android mid-flight, and
     * spaced so Android sheds none.
     */
    @Test
    fun aBurstKeepsEveryLine() {
        val runtime = runtime(staging = false)
        val address = "AnotherNodeAddressThatIsNotStored"
        fun message(body: String) = MobileNotificationEventRecord.Message(address, null, address, "Juniper", null, body, false, null)
        val bodies = (1..5).map { "Line $it" }
        runBlocking {
            notifier.post(runtime, message("Line 0"))
            coroutineScope {
                bodies.forEach { body -> launch(Dispatchers.Default) { notifier.post(runtime, message(body)) } }
                launch(Dispatchers.Default) { notifier.replyFinished(runtime, address, "On my way", ReplyOutcome.Sent) }
            }
        }
        val expected = (listOf("Line 0") + bodies + "On my way").toSet()
        assertEquals(MessageNotifier.MAX_LINES, expected.size)
        waitForNotification { shown ->
            val posted = shown.firstOrNull { it.tag == address && it.id == MessageNotifier.MESSAGE_ID }?.notification
            posted != null && lines(posted).map { it.text.toString() }.toSet() == expected
        }
    }

    @Test
    fun noticesSayWhatWentWrongApartFromMessages() {
        val runtime = runtime()
        show(runtime)
        val state = runtime.appState.value!!
        val first = state.directConversations[0].address
        val second = state.directConversations.getOrElse(1) { state.directConversations[0] }.address
        runBlocking {
            notifier.post(runtime, MobileNotificationEventRecord.DeliveryFailure(first, null, "Copy, heading up now.", false))
            notifier.post(runtime, MobileNotificationEventRecord.DeliveryFailure(second, null, "Thanks! Got it.", true))
            notifier.replyFinished(runtime, first, "On my way", com.voria.umsh.app.ReplyOutcome.Failed(savedAsDraft = true))
            notifier.post(runtime, MobileNotificationEventRecord.PeerHeard(second))
        }
        waitForNotification { shown -> shown.count { it.tag != null } >= 4 }
        val notices = active().filter { it.tag != null }
        val problems = notices.filter { it.notification.channelId == NotificationChannels.PROBLEMS }
        assertEquals(3, problems.size)
        problems.forEach { notice ->
            // Notices are not messages: no style, no Reply.
            assertNull(NotificationCompat.MessagingStyle.extractMessagingStyleFromNotification(notice.notification))
            assertTrue(notice.notification.actions.isNullOrEmpty())
            assertNotNull(notice.notification.publicVersion)
        }
        val texts = problems.map { it.notification.extras.getCharSequence(Notification.EXTRA_TEXT).toString() }
        assertTrue(texts.contains(context.getString(R.string.notice_reply_failed)))
        assertTrue(texts.any { it.contains("Copy, heading up now.") })
        assertTrue(notices.any { it.notification.channelId == NotificationChannels.DIRECT && it.tag == second && it.id != MessageNotifier.MESSAGE_ID })
        shot("notifications-5-notices")

        // Another failure in the same conversation takes the last one's place: a run of them never piles up.
        runBlocking { notifier.post(runtime, MobileNotificationEventRecord.DeliveryFailure(first, null, "Second try.", false)) }
        waitForNotification { shown ->
            shown.any { it.tag == first && it.notification.extras.getCharSequence(Notification.EXTRA_TEXT).toString().contains("Second try.") }
        }
        val after = active().filter { it.tag != null && it.notification.channelId == NotificationChannels.PROBLEMS }
        assertEquals(after.joinToString { "${it.tag}/${it.id}" }, 3, after.size)
        assertTrue(after.none { it.notification.extras.getCharSequence(Notification.EXTRA_TEXT).toString().contains("Copy, heading up now.") })
    }

    @Test
    fun hiddenNotificationsShowOnlyThePublicWords() {
        val runtime = runtime()
        runBlocking { fresh.host.preferences.setHideLockScreenContents(true) }
        show(runtime)
        notifier.keyguardLocked = { true }
        peerSays("Are you at the saddle yet?")
        peerSays("Trail's clear past the second bridge.", onChannel = true)
        waitForNotification { shown -> shown.count { it.id == MessageNotifier.MESSAGE_ID } >= 2 }
        active().filter { it.id == MessageNotifier.MESSAGE_ID }.forEach { hidden ->
            assertEquals(
                context.getString(R.string.notification_public_text),
                hidden.notification.extras.getCharSequence(Notification.EXTRA_TEXT).toString(),
            )
        }
        shot("notifications-4-hidden")
    }

    @Test
    fun settingsListsEachCategoryAndKeepsTheLockScreenChoice() {
        val runtime = runtime()
        show(runtime)
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_NOTIFICATIONS).performScrollTo().performClick()
        compose.onNodeWithTag(Tags.NOTIFICATIONS_PAGE).assertIsDisplayed()
        NotificationChannels.categories.forEach { category ->
            compose.onNodeWithTag("${Tags.NOTIFICATIONS_CATEGORY}_${category.id}")
                .performScrollTo()
                .assertTextContains(context.getString(category.name))
        }
        // The radio's channel is low importance: it says so.
        compose.onNodeWithTag("${Tags.NOTIFICATIONS_CATEGORY}_${NotificationChannels.RADIO}")
            .assertTextContains(context.getString(R.string.notification_category_silent))
        compose.onNodeWithTag(Tags.NOTIFICATIONS_ALL).performScrollTo().assertIsDisplayed()
        // Notifications are allowed here: no card.
        compose.onAllNodesWithTag(Tags.NOTIFICATIONS_OFF_CARD).assertCountEquals(0)
        compose.onNodeWithTag(Tags.NOTIFICATIONS_HIDE_LOCK_SCREEN).performScrollTo().assertIsOff().performClick()
        compose.waitUntil(TIMEOUT) { runBlocking { fresh.host.preferences.hideLockScreenContents.first() } }
        compose.onNodeWithTag(Tags.NOTIFICATIONS_HIDE_LOCK_SCREEN).assertIsOn()
        settingsShot("settings-5-notifications")
    }

    private fun settingsShot(name: String) {
        val suffix = InstrumentationRegistry.getArguments().getString("shots") ?: return
        compose.waitForIdle()
        Thread.sleep(SHADE_MS)
        val bitmap = instrumentation.uiAutomation.takeScreenshot() ?: return
        val directory = File(context.getExternalFilesDir(null), "shots").apply { mkdirs() }
        File(directory, "$name-$suffix.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    }

    /** Reply as the shade does: the action's PendingIntent, with what was typed filled in. */
    private fun sendReply(address: String, text: String) {
        val reply = action(conversationNotification(address)!!.notification, context.getString(R.string.notification_reply))!!
        val input = reply.remoteInputs.single()
        val fillIn = Intent()
        android.app.RemoteInput.addResultsToIntent(
            arrayOf(input),
            fillIn,
            Bundle().apply { putCharSequence(input.resultKey, text) },
        )
        reply.actionIntent.send(context, 0, fillIn)
    }

    private companion object {
        const val TIMEOUT = 30_000L

        /** The 15 s the reply waits for the radio, and the rest. */
        const val REPLY_TIMEOUT = 45_000L
        const val SETTLE_MS = 1_500L
        const val SHADE_MS = 3_000L
    }
}
