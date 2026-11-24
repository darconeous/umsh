package com.voria.umsh.app

import android.Manifest
import android.content.Context
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.VisibleForTesting
import androidx.core.app.ActivityCompat
import androidx.core.splashscreen.SplashScreen.Companion.installSplashScreen
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.voria.umsh.BuildConfig
import com.voria.umsh.features.channels.ChannelKeyText
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.notifications.NotificationPermission
import com.voria.umsh.services.permissions.PermissionAsking
import java.io.IOException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    private val host: AppCoreHost get() = (application as UmshApplication).coreHost

    /** Pages notifications, shortcuts and links asked to open; the shell takes each and clears it. */
    private val openRequests = OpenRequests()

    private val askNotifications = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { results ->
        notificationAskPending = false
        // The one permission asked for.
        val granted = results.isNotEmpty() && results.values.all { it }
        // Asked once, after a refusal Android still shows the dialog to
        // Settings' Turn on, unless this refusal was its last. Back or a tap
        // outside is not one: by the same rule as every other ask.
        val blocked = PermissionAsking.blockedAfterAnswer(
            results = results,
            granted = granted,
            dialogShown = notificationDialogShown,
            rationaleBefore = notificationRationaleBefore,
            rationaleAfter = ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.POST_NOTIFICATIONS),
        )
        if (blocked == null) {
            // Closed unanswered, under the app (a link arriving, D7): not
            // asked after all, so the next time the app is resumed with a
            // radio attached asks again; not this time, over the link's page.
            AppLog.i(TAG, "notifications: not answered")
            notificationAskDeferred = true
            lifecycleScope.launch { runCatching { host.preferences.setNotificationsAsked(false) } }
            return@registerForActivityResult
        }
        AppLog.i(TAG, "notifications: ${if (granted) "granted" else "refused"}")
        if (granted) {
            // A radio service started before this shows nothing until posted again.
            (application as UmshApplication).radioService.repostNotification()
            return@registerForActivityResult
        }
        lifecycleScope.launch { runCatching { host.preferences.setNotificationsBlocked(blocked) } }
    }

    /** The notifications ask in flight, and what [PermissionAsking.blockedAfterRefusal] needs of it; kept across a recreation. */
    private var notificationAskPending = false
    private var notificationRationaleBefore = false
    private var notificationDialogShown = false

    /** An ask closed unanswered: none again until the app has been left and comes back. */
    private var notificationAskDeferred = false

    @OptIn(ExperimentalCoroutinesApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        installSplashScreen().setKeepOnScreenCondition { host.state.value is HostState.Starting }
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // Opened: a stop the user made is over, and the radio may come back in the background again.
        (application as UmshApplication).userStop.opened()
        savedInstanceState?.let { saved ->
            notificationAskPending = saved.getBoolean(STATE_ASK_PENDING)
            notificationRationaleBefore = saved.getBoolean(STATE_RATIONALE_BEFORE)
            notificationDialogShown = saved.getBoolean(STATE_DIALOG_SHOWN)
            notificationAskDeferred = saved.getBoolean(STATE_ASK_DEFERRED)
            // A link the shell had not opened yet (onboarding, or the store
            // still loading) waits on across process death; one holding a
            // private key only within this process (§3.8).
            saved.getString(STATE_LINK)?.let(ChannelKeyText::open)?.let { link ->
                val origin = saved.getString(STATE_LINK_ORIGIN)?.let(LinkOrigin::valueOf) ?: LinkOrigin.OtherApp
                openRequests.offer(OpenRequest.Link(link, origin))
            }
        }
        // The activity pausing while the ask is out is Android's dialog showing.
        lifecycle.addObserver(
            LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_PAUSE && notificationAskPending) notificationDialogShown = true
                if (event == Lifecycle.Event.ON_STOP && !isChangingConfigurations) notificationAskDeferred = false
            },
        )
        // Debug builds: `--ez umsh.staging true|false` picks the core, for
        // tests and screenshot runs. Only on a fresh launch: not a restore,
        // and not a relaunch from Recents, which replays the first intent;
        // never from a browser, whose page could set it.
        val fresh = savedInstanceState == null &&
            intent.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY == 0
        val staging = if (BuildConfig.DEBUG && fresh && !LinkRoute.fromBrowser(intent.categories) && intent.hasExtra(EXTRA_STAGING)) {
            intent.getBooleanExtra(EXTRA_STAGING, false)
        } else {
            null
        }
        // Not on a restore: the system hands back the first intent, whose
        // conversation was opened then; a later tap arrives by onNewIntent.
        if (fresh) takeRequest(intent)
        host.ensureRuntime(staging)
        lifecycleScope.launch {
            // A task resumed after an erase goes to the first-launch path,
            // never the old shell.
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                host.state.collect { if (it is HostState.NeedsFirstLaunch) host.ensureRuntime() }
            }
        }
        lifecycleScope.launch {
            // Notifications are asked for once a radio first carries this
            // phone, in front: a first attach while away waits for the next
            // time the app is resumed with a radio attached.
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                host.state.flatMapLatest { (it as? HostState.Ready)?.runtime?.radioAttached ?: emptyFlow() }
                    .collect { askForNotificationsOnce() }
            }
        }
        setContent { AppRoot(host, openRequests) }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(STATE_ASK_PENDING, notificationAskPending)
        outState.putBoolean(STATE_RATIONALE_BEFORE, notificationRationaleBefore)
        outState.putBoolean(STATE_DIALOG_SHOWN, notificationDialogShown)
        outState.putBoolean(STATE_ASK_DEFERRED, notificationAskDeferred)
        openRequests.link?.let { link ->
            outState.putString(STATE_LINK, ChannelKeyText.seal(link.uri))
            outState.putString(STATE_LINK_ORIGIN, link.origin.name)
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        takeRequest(intent)
    }

    /**
     * Taken once: a recreation keeps the same intent, and must not open it
     * again, so what is taken is cleared from it (a link is marked taken). A `umsh` view intent is a
     * link ([LinkRoute]); a notification's tap carries its own scheme and
     * its extras. Tests hand one in directly.
     *
     * The app's own extras are honored only on an intent that is not a
     * link: a web page's link can carry any extras it likes, and must open
     * nothing but its link ([LinkRoute.honorsAppExtras]).
     */
    @VisibleForTesting
    internal fun takeRequest(intent: Intent) {
        val link = LinkRoute.linkOf(intent.action, intent.scheme, intent.dataString)
        // Marked taken rather than its data removed: the data is part of
        // the intent's identity, which the system and tests match it by.
        if (link != null && !intent.getBooleanExtra(EXTRA_LINK_TAKEN, false)) {
            openRequests.offer(OpenRequest.Link(link, LinkOrigin.OtherApp))
            intent.putExtra(EXTRA_LINK_TAKEN, true)
        }
        if (LinkRoute.honorsAppExtras(link, intent.categories)) {
            intent.getStringExtra(EXTRA_CONVERSATION)?.let { openRequests.offer(OpenRequest.Conversation(it)) }
            intent.getStringExtra(EXTRA_PEER)?.let { openRequests.offer(OpenRequest.Peer(it)) }
            if (intent.getBooleanExtra(EXTRA_RADIO_DETAIL, false)) openRequests.offer(OpenRequest.RadioDetail)
        }
        intent.removeExtra(EXTRA_CONVERSATION)
        intent.removeExtra(EXTRA_PEER)
        intent.removeExtra(EXTRA_RADIO_DETAIL)
    }

    private suspend fun askForNotificationsOnce() {
        if (NotificationPermission.granted(this) || notificationAskDeferred) return
        val preferences = host.preferences
        try {
            if (preferences.notificationsAsked()) return
            preferences.setNotificationsAsked()
        } catch (error: IOException) {
            // Not asked: a question that cannot be remembered would come back every time.
            AppLog.e(TAG, "notifications not asked: ${error.javaClass.simpleName}")
            return
        }
        AppLog.i(TAG, "asking for notifications")
        notificationAskPending = true
        notificationRationaleBefore = ActivityCompat.shouldShowRequestPermissionRationale(this, Manifest.permission.POST_NOTIFICATIONS)
        notificationDialogShown = false
        askNotifications.launch(arrayOf(Manifest.permission.POST_NOTIFICATIONS))
    }

    companion object {
        const val EXTRA_STAGING = "umsh.staging"

        /** The conversation a notification or shortcut opens, by its address. */
        const val EXTRA_CONVERSATION = "umsh.conversation"

        /** A node a Next time heard notice is about, by its address. */
        const val EXTRA_PEER = "umsh.peer"

        /** Radio Detail: the radio notification's tap. */
        const val EXTRA_RADIO_DETAIL = "umsh.radioDetail"

        private const val TAG = "umsh.activity"
        private const val STATE_ASK_PENDING = "umsh.notifications.pending"
        private const val STATE_RATIONALE_BEFORE = "umsh.notifications.rationale"
        private const val STATE_DIALOG_SHOWN = "umsh.notifications.shown"
        private const val STATE_ASK_DEFERRED = "umsh.notifications.deferred"
        /** On a view intent whose link was taken ([takeRequest]). */
        private const val EXTRA_LINK_TAKEN = "umsh.linkTaken"
        private const val STATE_LINK = "umsh.link"
        private const val STATE_LINK_ORIGIN = "umsh.link.origin"

        /**
         * Opens the app at [address]'s conversation: the existing activity,
         * brought to front, or a new one. An action, as shortcuts need one.
         */
        fun conversationIntent(context: Context, address: String): Intent =
            Intent(context, MainActivity::class.java)
                .setAction(Intent.ACTION_VIEW)
                .putExtra(EXTRA_CONVERSATION, address)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)

        /** Opens the app at a node: its conversation if it sends text, else its page on Peers. */
        fun peerIntent(context: Context, address: String): Intent =
            Intent(context, MainActivity::class.java)
                .setAction(Intent.ACTION_VIEW)
                .putExtra(EXTRA_PEER, address)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)

        /** Opens the app at Radio Detail: the existing activity, brought to front, or a new one. */
        fun radioDetailIntent(context: Context): Intent =
            Intent(context, MainActivity::class.java)
                .setAction(ACTION_RADIO_DETAIL)
                .putExtra(EXTRA_RADIO_DETAIL, true)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)

        /** Distinguishes the radio notification's intent from a launcher's, so neither replaces the other's PendingIntent. */
        private const val ACTION_RADIO_DETAIL = "com.voria.umsh.action.RADIO_DETAIL"
    }
}
