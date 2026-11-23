package com.voria.umsh.features.radio

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppCoreHost
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.core.RadioPresetRecord
import com.voria.umsh.core.ulcpRadioPresets
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.radio.RadioSnapshot
import java.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** A restart or factory reset that did not reach the radio, for its failure dialog. */
data class RadioRequestFailure(val request: Request, val error: Throwable) {
    enum class Request { Restart, FactoryReset }
}

/**
 * Radio Detail's state and commands. The radio's state is the core's
 * ([AppRuntime.radio]); the commands go to the live radio through the host,
 * or, while the staging core runs, to the staged radio.
 */
class RadioDetailViewModel(private val runtime: AppRuntime, private val host: AppCoreHost) : ViewModel() {
    val radio: StateFlow<RadioSnapshot?> = runtime.radio

    /** The core has said what radio there is: until then a null [radio] is not "none". */
    val radioKnown: StateFlow<Boolean> = runtime.radioKnown

    val now: StateFlow<Instant> = runtime.now

    /** The model identifier the bound radio was recorded with; null for none (staging, a bridged radio). */
    val boundModelId: StateFlow<Int?> = host.preferences.radioRegistry.bound
        .map { it?.modelId }
        .catch { emit(null) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), null)

    /** The companion radio's own node among the peers, for Radio identity. */
    val identity: StateFlow<PeerSummary?> = runtime.appState
        .map { state -> state?.peers?.firstOrNull { it.isCompanionRadio } }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), null)

    private val _failure = MutableStateFlow<RadioRequestFailure?>(null)

    /** A restart or factory reset that did not reach the radio, for the page showing now. */
    val failure: StateFlow<RadioRequestFailure?> = _failure.asStateFlow()

    private val _resetAccepted = MutableStateFlow(false)

    /** The radio took a factory reset: the page closes, from its own composition. */
    val resetAccepted: StateFlow<Boolean> = _resetAccepted.asStateFlow()

    /** Radio Detail pages composed now: above the shell, in the Settings stack, or both. */
    private var pages = 0

    /** Bumped each time the last page is left; a request's answer is for the visit that sent it. */
    private var visit = 0

    /** The vetted profiles, to name the radio's settings when they match one. */
    val presets: List<RadioPresetRecord> by lazy {
        runCatching { ulcpRadioPresets() }.getOrElse { emptyList() }
    }

    fun disconnect() {
        AppLog.i(TAG, "radio detail: disconnect")
        val staged = host.stagingRadio.value
        if (staged != null) staged.setLinkUp(false) else host.disconnectRadio()
    }

    /** Reconnect, Connect: a user's request, with a fresh recovery budget. */
    fun reconnect() {
        AppLog.i(TAG, "radio detail: reconnect")
        val staged = host.stagingRadio.value
        if (staged != null) staged.setLinkUp(true) else host.reconnectRadio()
    }

    /** Forget: the staged radio is never remembered, so there it only goes down. */
    fun forget() {
        AppLog.i(TAG, "radio detail: forget")
        val staged = host.stagingRadio.value
        if (staged != null) staged.setLinkUp(false) else host.forgetRadio()
    }

    fun restart() = request(RadioRequestFailure.Request.Restart)

    fun factoryReset() = request(RadioRequestFailure.Request.FactoryReset)

    fun dismissFailure() {
        _failure.value = null
    }

    fun resetAcceptedSeen() {
        _resetAccepted.value = false
    }

    fun pageShown() {
        pages += 1
    }

    /**
     * A page left composition. Unless the window is only being recreated
     * ([recreating]), leaving the last one ends the visit: what it was shown
     * goes, and answers still on their way are dropped, not shown later out
     * of context.
     */
    fun pageLeft(recreating: Boolean) {
        pages -= 1
        if (pages > 0 || recreating) return
        visit += 1
        _failure.value = null
        _resetAccepted.value = false
    }

    private fun request(request: RadioRequestFailure.Request) {
        AppLog.i(TAG, "radio detail: $request")
        val sentIn = visit
        viewModelScope.launch {
            val outcome = try {
                val staged = host.stagingRadio.value
                when (request) {
                    RadioRequestFailure.Request.Restart ->
                        if (staged != null) staged.restart() else host.restartRadio().await()
                    RadioRequestFailure.Request.FactoryReset ->
                        if (staged != null) staged.factoryReset() else host.factoryResetRadio().await()
                }
                null
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "radio $request not sent: ${error.javaClass.simpleName}")
                error
            }
            if (visit != sentIn) return@launch
            when {
                outcome != null -> _failure.value = RadioRequestFailure(request, outcome)
                request == RadioRequestFailure.Request.FactoryReset -> _resetAccepted.value = true
            }
        }
    }

    private companion object {
        const val TAG = "umsh.radio"
        const val STOP_TIMEOUT_MS = 5_000L
    }
}
