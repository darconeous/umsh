package com.voria.umsh.features.peers

import android.os.SystemClock
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.models.PingOutcome
import com.voria.umsh.services.mobilecore.AppLog
import java.time.Instant
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** One ping sent from a peer page, and how it ended. */
data class PingRecord(val id: Long, val sentAt: Instant, val outcome: PingOutcome)

/** The ping being waited on: when it went, by the wall clock and by the elapsed one. */
data class OutstandingPing(val id: Long, val sentAt: Instant, val startedAtElapsedMs: Long)

/**
 * A peer page's pings (`ping-route.svg` 1–3). Sending is a user action
 * (Ping, Ping again), never the sheet appearing: the in-flight ping is the
 * runtime's, so a rotation re-attaches to it here and a closed page does
 * not cancel it. The sheet's being open lives here too, not in saved
 * state, so after process death it does not reopen. A newer ping replaces
 * the one waited on; the older one's [PingOutcome.Canceled] is dropped.
 * [history] is this visit's pings, newest first.
 */
class PingViewModel(
    private val runtime: AppRuntime,
    val address: String,
    /** How long a ping waits before Ping again is offered ([com.voria.umsh.designsystem.UiTimings]). */
    private val againAfterMs: Long,
    private val elapsedMs: () -> Long = SystemClock::elapsedRealtime,
    private val wall: () -> Instant = Instant::now,
) : ViewModel() {
    private val _shown = MutableStateFlow(false)

    /** Whether the sheet is open. */
    val shown: StateFlow<Boolean> = _shown.asStateFlow()

    private val _outstanding = MutableStateFlow<OutstandingPing?>(null)
    val outstanding: StateFlow<OutstandingPing?> = _outstanding.asStateFlow()

    private val _latest = MutableStateFlow<PingRecord?>(null)

    /** The newest ping that ended, shown as the result while none is outstanding. */
    val latest: StateFlow<PingRecord?> = _latest.asStateFlow()

    private val _history = MutableStateFlow<List<PingRecord>>(emptyList())
    val history: StateFlow<List<PingRecord>> = _history.asStateFlow()

    private val _canPingAgain = MutableStateFlow(true)

    /** Off for a while after a ping goes out, so a quick reply is not trampled; on once one ends. */
    val canPingAgain: StateFlow<Boolean> = _canPingAgain.asStateFlow()

    private val _resetting = MutableStateFlow(false)
    val resetting: StateFlow<Boolean> = _resetting.asStateFlow()

    private val _failure = MutableStateFlow<Throwable?>(null)

    /** Reset route did not go through. */
    val failure: StateFlow<Throwable?> = _failure.asStateFlow()

    private val _notices = Channel<Int>(Channel.BUFFERED)

    /** "Route reset", "No route to reset". */
    val notices: Flow<Int> = _notices.receiveAsFlow()

    private var nextId = 0L
    private var againJob: Job? = null

    /** The reply's repeaters, named (one entry per repeater, in order), with the hints they answer. */
    @OptIn(ExperimentalCoroutinesApi::class)
    val replyNames: StateFlow<NamedHops> = _latest.flatMapLatest { record ->
        val reply = (record?.outcome as? PingOutcome.Reply)?.reply
        if (reply == null || reply.routeHints.isEmpty()) {
            flowOf(NamedHops.NONE)
        } else {
            runtime.hopNames.peers(reply.routeHints.map { it.octets }, runtime.appState)
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_MS), NamedHops.NONE)

    /** The page's Ping: the sheet opens on the ping this sends. */
    fun ping() {
        _shown.value = true
        send()
    }

    /** Ping again, in the sheet. */
    fun pingAgain() {
        if (_outstanding.value != null && !_canPingAgain.value) return
        send()
    }

    /** The sheet closed: a ping still out goes on, and its answer is kept for Earlier. A notice not yet shown goes. */
    fun dismiss() {
        _shown.value = false
        while (_notices.tryReceive().isSuccess) continue
    }

    private fun send() {
        val id = ++nextId
        val sentAt = wall()
        _outstanding.value = OutstandingPing(id, sentAt, elapsedMs())
        _canPingAgain.value = false
        againJob?.cancel()
        againJob = viewModelScope.launch {
            delay(againAfterMs)
            _canPingAgain.value = true
        }
        val sent = runtime.ping(address)
        viewModelScope.launch {
            // Never throws but for cancellation: a ping that could not go is Unavailable.
            val outcome = sent.await()
            // Replaced by a newer ping, whose wait is the one on show.
            if (_outstanding.value?.id != id) return@launch
            _outstanding.value = null
            againJob?.cancel()
            _canPingAgain.value = true
            if (outcome == PingOutcome.Canceled) return@launch
            val record = PingRecord(id, sentAt, outcome)
            _history.value = listOf(record) + _history.value.take(KEPT - 1)
            _latest.value = record
        }
    }

    /** Reset route: forget the learned route, so the next send floods and learns again. */
    fun resetRoute() {
        if (_resetting.value) return
        _resetting.value = true
        val reset = runtime.clearRoute(address)
        viewModelScope.launch {
            try {
                val hadRoute = reset.await()
                // Only the sheet shows it: once it closed, the notice would come up over a later ping.
                if (_shown.value) _notices.trySend(if (hadRoute) R.string.route_reset_notice else R.string.route_reset_none_notice)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "route not reset: ${error.javaClass.simpleName}")
                _failure.value = error
            } finally {
                _resetting.value = false
            }
        }
    }

    fun dismissFailure() {
        _failure.value = null
    }

    private companion object {
        const val TAG = "umsh.ping"
        const val STOP_MS = 5_000L

        /** This visit's pings kept for Earlier. */
        const val KEPT = 20
    }
}
