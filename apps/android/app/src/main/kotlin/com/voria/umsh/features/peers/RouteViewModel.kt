package com.voria.umsh.features.peers

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.R
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.RouteState
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** A Route page command that did not go through, for its dialog. */
sealed interface RouteFailure {
    val error: Throwable

    data class NotReset(override val error: Throwable) : RouteFailure

    data class NotCleared(override val error: Throwable) : RouteFailure
}

/**
 * The Route page (`ping-route.svg` 4–5): the way to one peer as the
 * session knows it, read on open, whenever the peer is heard again, once
 * the core runs, and whenever this phone changes it (here or elsewhere); its hops named by [com.voria.umsh.features.peers.HopNames];
 * Reset route or, for a held path, Clear manual path.
 */
class RouteViewModel(private val runtime: AppRuntime, val address: String) : ViewModel() {
    /** The peer's live row; null until read, and once it is gone (the shell closes the page then). */
    val peer: StateFlow<PeerSummary?> = runtime.appState
        .map { state -> state?.peers?.firstOrNull { it.address == address } }
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    private val _route = MutableStateFlow<RouteState>(RouteState.Loading)
    val route: StateFlow<RouteState> = _route.asStateFlow()

    /** The route's repeaters, named (one entry per repeater, in send order), with the hints they answer. */
    @OptIn(ExperimentalCoroutinesApi::class)
    val hopNames: StateFlow<NamedHops> = _route.map { state ->
        (state as? RouteState.Loaded)?.route?.hints?.map { it.octets }.orEmpty()
    }.distinctUntilChanged().flatMapLatest { hints ->
        runtime.hopNames.peers(hints, runtime.appState)
    }.stateIn(viewModelScope, SharingStarted.Eagerly, NamedHops.NONE)

    private val _busy = MutableStateFlow(false)

    /** Reset route or Clear manual path is on its way. */
    val busy: StateFlow<Boolean> = _busy.asStateFlow()

    private val _failure = MutableStateFlow<RouteFailure?>(null)
    val failure: StateFlow<RouteFailure?> = _failure.asStateFlow()

    private val _notices = Channel<Int>(Channel.BUFFERED)

    /** "No route to reset". */
    val notices: Flow<Int> = _notices.receiveAsFlow()

    init {
        viewModelScope.launch {
            combine(
                peer.map { it?.lastHeardAtMs }.distinctUntilChanged(),
                runtime.lifecycle.map { it is MobileAppLifecycle.Running }.distinctUntilChanged(),
                runtime.routeRevisions.map { it[address] ?: 0L }.distinctUntilChanged(),
            ) { heard, running, revision -> Triple(heard, running, revision) }.collect { load() }
        }
    }

    private suspend fun load() {
        _route.value = try {
            RouteState.Loaded(runtime.peerRoute(address).await())
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            AppLog.d(TAG, "route unread: ${error.javaClass.simpleName}")
            RouteState.Unavailable
        }
    }

    /** Forget the learned route; the page shows what replaces it, and says so when there was none. */
    fun resetRoute() = perform({ runtime.clearRoute(address) }, RouteFailure::NotReset) { hadRoute ->
        if (!hadRoute) _notices.trySend(R.string.route_reset_none_notice)
    }

    /** Drop the held path: learned routes take over again. */
    fun clearManualPath() = perform({ runtime.clearManualPath(address) }, RouteFailure::NotCleared) {}

    private fun perform(command: () -> Deferred<Boolean>, failure: (Throwable) -> RouteFailure, done: (Boolean) -> Unit) {
        if (_busy.value) return
        _busy.value = true
        val sent = command()
        viewModelScope.launch {
            try {
                // The runtime's route revision reads the route again.
                done(sent.await())
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "route command failed: ${error.javaClass.simpleName}")
                _failure.value = failure(error)
            } finally {
                _busy.value = false
            }
        }
    }

    fun dismissFailure() {
        _failure.value = null
    }

    private companion object {
        const val TAG = "umsh.route"
    }
}
