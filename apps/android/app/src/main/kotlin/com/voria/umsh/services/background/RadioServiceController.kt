package com.voria.umsh.services.background

import android.Manifest
import android.app.ForegroundServiceStartNotAllowedException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import com.voria.umsh.app.AppCoreHost
import com.voria.umsh.app.CoreKind
import com.voria.umsh.app.HostState
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.first
import java.io.IOException

/**
 * Starts the radio's foreground service when a remembered radio starts
 * coming up, and publishes what the service shows. The service stops
 * itself when [decision] says so.
 *
 * A start Android refuses (in the background, with no exemption) is made
 * again on the next foreground while [decision] still says Run, as is one
 * for a service that has since ended on its own.
 *
 * The service only holds the process at foreground priority and carries the
 * notification; the host owns the link. One per process.
 */
class RadioServiceController(
    private val context: Context,
    private val host: AppCoreHost,
    foregroundSignals: Flow<Unit>,
    private val scope: CoroutineScope,
    /** The Developer switch's choice of what follows the reconnect window; Presence otherwise. */
    preferredStrategy: StateFlow<ReconnectStrategy> = MutableStateFlow(ReconnectStrategy.Presence),
    /** This phone has companion-device support, so presence can wake the app. */
    presenceAvailable: Boolean = false,
    /** Bluetooth is on now, read afresh: a frozen process may have missed the adapter's broadcast. */
    private val bluetoothOn: () -> Boolean = { true },
    /** Returns once Bluetooth is on. */
    private val awaitBluetoothOn: suspend () -> Unit = {},
    /** The user stopped the app and has not opened it since ([UserStop]): nothing starts it in the background. */
    private val stoppedByUser: suspend () -> Boolean = { false },
) {
    private val _reposts = MutableSharedFlow<Unit>(extraBufferCapacity = 1, onBufferOverflow = BufferOverflow.DROP_OLDEST)

    /**
     * The app came to the front with the service running: its notification
     * is posted again. One started while notifications were not allowed is
     * not shown, and nothing else would show it once they are.
     */
    val reposts: SharedFlow<Unit> = _reposts.asSharedFlow()

    /** Notifications were just allowed: the running service's notification is posted again, so it shows. */
    fun repostNotification() {
        _reposts.tryEmit(Unit)
    }

    /** Set by the service between its creation and its end; main thread. */
    private var serviceRunning = false

    @OptIn(ExperimentalCoroutinesApi::class)
    val decision: StateFlow<RadioServiceDecision> = host.state.flatMapLatest { state ->
        when (state) {
            HostState.Starting -> flowOf(RadioServiceDecision.Pending)
            is HostState.Ready -> {
                val runtime = state.runtime
                if (runtime.kind != CoreKind.Live) {
                    flowOf(RadioServiceDecision.Stop)
                } else {
                    combine(
                        host.radio,
                        host.preferences.radioRegistry.bound,
                        runtime.radio,
                        runtime.radioKnown,
                        preferredStrategy,
                    ) { connection, bound, radio, known, preferred ->
                        val strategy = ReconnectStrategy.effective(preferred, presenceAvailable, bound)
                        RadioServiceDecision.of(live = true, connection != null, bound, radio, known, strategy)
                    }
                }
            }
            else -> flowOf(RadioServiceDecision.Stop)
        }
    }.stateIn(scope, SharingStarted.Eagerly, RadioServiceDecision.Pending)

    init {
        scope.launch {
            decision.map { it as? RadioServiceDecision.Run }
                .distinctUntilChanged { old, new -> (old != null) == (new != null) }
                .collect { run -> if (run != null) start(run.kind) }
        }
        scope.launch {
            foregroundSignals.collect {
                val run = decision.value as? RadioServiceDecision.Run ?: return@collect
                if (!serviceRunning) start(run.kind) else repostNotification()
            }
        }
    }

    /**
     * A notification action needs the radio: start the service for the
     * bound radio if none runs, so the process waits for the link at
     * foreground priority (§6.3). The action's own exemption lets it start
     * from the background; the service stops itself if it has nothing to
     * hold. Nothing with no radio bound.
     */
    suspend fun startForAction() {
        val bound = wantedRadio() ?: return
        withContext(Dispatchers.Main) {
            // Running already: the link is held, or armed and waiting.
            if (!serviceRunning) start(bound.kind, RadioForegroundService.Reason.Action)
        }
    }

    /**
     * Android's companion presence saw the radio [matches] names (§7.3):
     * the service starts, from the background if need be (an associated
     * app's exemption), brings the live core up headless, and seeks the
     * radio. Nothing for a radio no longer bound or wanted.
     *
     * With Bluetooth off the appearance is held until it comes on: the link
     * could not come up now, and Android reports no new appearance for a
     * radio it still counts as present, so this may be the process's only
     * wake. A later appearance or a disappearance ends the hold.
     *
     * Nothing while the user's stop holds ([UserStop]).
     */
    suspend fun startForPresence(matches: (BoundRadio) -> Boolean) {
        val bound = boundRadio()?.takeIf(matches)
        withContext(Dispatchers.Main) {
            val next = HeadlessStart.of(HeadlessStart.Trigger.Presence, bound, stoppedByUser, bluetoothOn, serviceRunning)
            if (next == HeadlessStart.HoldForBluetooth || next == HeadlessStart.Start) {
                heldPresence?.cancel()
                heldPresence = null
            }
            when (next) {
                HeadlessStart.NotWanted -> AppLog.i(TAG, "presence: not the wanted radio; nothing to do")
                HeadlessStart.StoppedByUser -> AppLog.i(TAG, "presence: stopped by the user; nothing until the app is opened")
                HeadlessStart.HoldForBluetooth -> {
                    AppLog.i(TAG, "presence: Bluetooth is off; held until it is on")
                    heldPresence = scope.launch {
                        awaitBluetoothOn()
                        heldPresence = null
                        startForPresence(matches)
                    }
                }
                HeadlessStart.Skip -> Unit
                HeadlessStart.Start -> bound?.let { start(it.kind, RadioForegroundService.Reason.Presence) }
            }
        }
    }

    /**
     * The app was just updated (API 31–35, where nothing else brings the
     * radio back until it leaves and returns): the service starts for the
     * wanted radio from the update broadcast's exemption, as presence would
     * start it. Nothing with no radio wanted or one still being added,
     * with Bluetooth off (presence wakes it once Bluetooth is on and the
     * radio is seen), while the user's stop holds, or with the service
     * already running.
     */
    suspend fun startForUpdate() {
        val bound = boundRadio()
        withContext(Dispatchers.Main) {
            when (HeadlessStart.of(HeadlessStart.Trigger.Update, bound, stoppedByUser, bluetoothOn, serviceRunning)) {
                HeadlessStart.NotWanted -> AppLog.i(TAG, "update: no radio wanted; nothing to do")
                HeadlessStart.StoppedByUser -> AppLog.i(TAG, "update: stopped by the user; nothing until the app is opened")
                HeadlessStart.HoldForBluetooth, HeadlessStart.Skip ->
                    if (!serviceRunning) AppLog.i(TAG, "update: Bluetooth is off; left to presence")
                HeadlessStart.Start -> bound?.let { start(it.kind, RadioForegroundService.Reason.Update) }
            }
        }
    }

    /** Android's presence lost the radio: an appearance held for Bluetooth is dropped. */
    fun presenceEnded() {
        scope.launch(Dispatchers.Main) {
            heldPresence?.cancel()
            heldPresence = null
        }
    }

    /** An appearance waiting for Bluetooth to come on; main thread. */
    private var heldPresence: Job? = null

    /** The bound radio, if it is wanted and not still being added; null when none is, or the registry cannot be read. */
    private suspend fun wantedRadio(): BoundRadio? = boundRadio()?.takeIf { it.autoConnect && it.pending == null }

    /** The bound radio; null when none is, or the registry cannot be read. */
    private suspend fun boundRadio(): BoundRadio? = try {
        host.preferences.radioRegistry.bound.first()
    } catch (error: IOException) {
        AppLog.w(TAG, "radio registry unread: ${error.javaClass.simpleName}")
        null
    }

    /**
     * A Nearby devices request was answered in the app. A Bluetooth radio's
     * service held back for want of the grant starts now; the dialog brings
     * no foreground signal of its own.
     */
    fun nearbyDevicesAnswered() {
        val run = decision.value as? RadioServiceDecision.Run ?: return
        if (!serviceRunning) start(run.kind)
    }

    /** The service's own report: created ([running]) or destroyed. */
    fun serviceChanged(running: Boolean) {
        serviceRunning = running
    }

    /**
     * Start the service, if Android lets it run. A Bluetooth radio's
     * service needs Nearby devices granted (Android 14 and later refuse the
     * connected-device type without it); the bridged radio's is covered by
     * the debug build's network permission.
     */
    private fun start(kind: RadioKind, reason: RadioForegroundService.Reason = RadioForegroundService.Reason.App) {
        if (!prerequisitesMet(kind)) {
            AppLog.w(TAG, "radio service not started: Nearby devices not granted")
            return
        }
        try {
            ContextCompat.startForegroundService(context, RadioForegroundService.startIntent(context, reason))
            AppLog.i(TAG, "radio service started (${reason.name.lowercase()})")
        } catch (error: ForegroundServiceStartNotAllowedException) {
            // In the background with no exemption: the next foreground starts it.
            AppLog.w(TAG, "radio service not started: ${error.javaClass.simpleName}")
        } catch (error: SecurityException) {
            AppLog.w(TAG, "radio service not started: ${error.javaClass.simpleName}")
        }
    }

    private fun prerequisitesMet(kind: RadioKind): Boolean = when (kind) {
        RadioKind.Ble -> ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) ==
            PackageManager.PERMISSION_GRANTED
        RadioKind.Tcp, RadioKind.Staging -> true
    }

    private companion object {
        const val TAG = "umsh.service"
    }
}
