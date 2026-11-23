package com.voria.umsh.services.background

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.os.SystemClock
import androidx.core.app.ServiceCompat
import com.voria.umsh.app.StartOrigin
import com.voria.umsh.app.UmshApplication
import com.voria.umsh.services.mobilecore.AppLog
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Holds the process at foreground priority while the live radio is coming
 * up, attached, coming back within the reconnect window, or (Waiting
 * strategy) waited for, and carries its notification. It does not own the
 * link: the host does, so the service only follows
 * [RadioServiceController.decision] and stops itself when that says Stop.
 *
 * Started by the app's own screens ([Reason.App]), or headless: by
 * companion presence when the radio is back ([Reason.Presence]), by a
 * notification action that needs the radio ([Reason.Action]), and after an
 * update on API 31–35 ([Reason.Update]). A headless
 * start brings the live core up (never minting), seeks the wanted radio,
 * and follows the decision once the radio is being sought, so the rest the
 * link was in a moment before does not stop it at once.
 *
 * `START_NOT_STICKY`: a killed service is not restarted by the system;
 * presence or the next open brings it back.
 */
class RadioForegroundService : Service() {
    /** What started the service. */
    enum class Reason { App, Presence, Action, Update }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var following = false

    /** The controller that was current when this service was made; it hears of the end from this one. */
    private lateinit var controller: RadioServiceController

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        controller = (application as UmshApplication).radioService
        controller.serviceChanged(running = true)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val application = application as UmshApplication
        if (intent?.action == ACTION_DISCONNECT) {
            // Disconnect and Stop: both end the radio's standing intent (§6.4).
            AppLog.i(TAG, "action: Disconnect from the radio notification")
            application.coreHost.disconnectRadio()
            // Started by the action alone: there is nothing to hold.
            if (!following) stopSelf()
            return START_NOT_STICKY
        }
        val reason = intent?.getStringExtra(EXTRA_REASON)
            ?.let { name -> Reason.entries.firstOrNull { it.name == name } }
            ?: Reason.App
        val current = controller.decision.value as? RadioServiceDecision.Run
        try {
            ServiceCompat.startForeground(
                this,
                RadioServiceNotification.ID,
                RadioServiceNotification.build(this, current),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
            )
        } catch (error: Exception) {
            // Android refused the type (a prerequisite revoked) or the start
            // came too late: the link goes on without the service.
            AppLog.w(TAG, "radio service not in the foreground: ${error.javaClass.simpleName}")
            stopSelf()
            return START_NOT_STICKY
        }
        if (reason != Reason.App) AppLog.i(TAG, "radio service started headless (${reason.name.lowercase()})")
        // Started by something other than the app's own screens, the core
        // may not be running yet: bring it up, never minting. With no live
        // core after that (no identity, staging on) there is nothing to hold.
        val live = application.coreHost.ensureRuntime(origin = StartOrigin.Headless)
        val headless = reason != Reason.App
        val follow = !following
        following = true
        scope.launch {
            if (!live.await()) {
                AppLog.i(TAG, "radio service stopping: no live core")
                stop()
                return@launch
            }
            if (headless) {
                // The radio is back (presence), needed (an action) or left unsought by an update: sought now.
                application.coreHost.wakeRadio().join()
                if (follow) settle()
            }
            if (follow) follow(controller)
        }
        return START_NOT_STICKY
    }

    /**
     * After a headless start, until the decision says Run: the link the
     * wake just armed reaches the core a moment later, and the rest it was
     * in (Waiting, left to presence) would otherwise stop the service
     * before the radio is sought. Bounded: a radio that is not sought
     * after all (resting after a fault) stops it then.
     */
    private suspend fun settle() {
        val settled = withTimeoutOrNull(SETTLE_MS) {
            controller.decision.first { it is RadioServiceDecision.Run }
        }
        if (settled == null) AppLog.i(TAG, "radio service: the radio was not sought within ${SETTLE_MS / 1000} s")
    }

    private fun stop() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun follow(controller: RadioServiceController) {
        AppLog.i(TAG, "radio service running")
        scope.launch {
            controller.reposts.collect { (controller.decision.value as? RadioServiceDecision.Run)?.let(::post) }
        }
        scope.launch {
            var shown: RadioServiceDecision.Link? = null
            var shownAt = 0L
            controller.decision.collectLatest { decision ->
                when (decision) {
                    RadioServiceDecision.Pending -> Unit
                    RadioServiceDecision.Stop -> {
                        AppLog.i(TAG, "radio service stopping")
                        stop()
                    }
                    is RadioServiceDecision.Run -> {
                        // A state change shows at once; anything else (a
                        // battery reading) at most every two seconds.
                        if (decision.link == shown) {
                            val wait = UPDATE_INTERVAL_MS - (SystemClock.elapsedRealtime() - shownAt)
                            if (wait > 0) delay(wait)
                        }
                        post(decision)
                        shown = decision.link
                        shownAt = SystemClock.elapsedRealtime()
                        // The last battery reading's age moves on while nothing else does.
                        while (RadioServiceNotification.showsAge(decision)) {
                            delay(AGE_INTERVAL_MS)
                            post(decision)
                            shownAt = SystemClock.elapsedRealtime()
                        }
                    }
                }
            }
        }
    }

    /** The same notification, changed in place: a foreground service updates its own this way. */
    private fun post(run: RadioServiceDecision.Run) {
        try {
            ServiceCompat.startForeground(
                this,
                RadioServiceNotification.ID,
                RadioServiceNotification.build(this, run),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
            )
        } catch (error: Exception) {
            AppLog.w(TAG, "radio notification not updated: ${error.javaClass.simpleName}")
        }
    }

    /** Android 15 and later time some service types out; not this one, but stop cleanly if it ever does. */
    override fun onTimeout(startId: Int, fgsType: Int) {
        AppLog.w(TAG, "radio service timed out")
        stopSelf()
    }

    override fun onDestroy() {
        scope.cancel()
        following = false
        controller.serviceChanged(running = false)
        super.onDestroy()
    }

    companion object {
        const val ACTION_DISCONNECT = "com.voria.umsh.action.RADIO_DISCONNECT"
        private const val EXTRA_REASON = "umsh.reason"
        private const val TAG = "umsh.service"
        private const val UPDATE_INTERVAL_MS = 2_000L

        /** Ages are shown in whole minutes. */
        private const val AGE_INTERVAL_MS = 60_000L

        /** How long a headless start waits for the radio to be sought before it follows the decision. */
        private const val SETTLE_MS = 10_000L

        /** Starts the service for [reason]. */
        fun startIntent(context: Context, reason: Reason): Intent =
            Intent(context, RadioForegroundService::class.java).putExtra(EXTRA_REASON, reason.name)
    }
}
