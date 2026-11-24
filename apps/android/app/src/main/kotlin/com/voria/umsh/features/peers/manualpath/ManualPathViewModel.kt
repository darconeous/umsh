package com.voria.umsh.features.peers.manualpath

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.models.ManualPath
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.PingOutcome
import com.voria.umsh.models.RouteSummary
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * The route the editor is seeded from: being read, read (null when the peer
 * has none), or unreadable for now. Only a read seeds: a blank draft saved
 * over a held path the read missed would replace it.
 */
sealed interface SeedRoute {
    data object Loading : SeedRoute

    data class Read(val route: RouteSummary?) : SeedRoute

    data class Unavailable(val error: Throwable) : SeedRoute
}

/** A Ping along path: the path it tested, and how it ended (null while it waits). */
data class PathPing(val path: ManualPath, val outcome: PingOutcome?)

/** Saving did not hold the path: the session refused it, or the command failed. */
sealed interface SaveFailure {
    data object Refused : SaveFailure

    data class Failed(val error: Throwable) : SaveFailure
}

/**
 * The manual path editor (`manual-path.svg` 1–2, 6): the route it starts
 * from, read until a read succeeds (again once the core runs, or the route
 * changes); Ping along path, which installs nothing; and Save. The
 * draft itself is the page's saved state, not this, so it outlives the
 * process. Pings and saves run in the runtime's scope and are re-attached
 * after a rotation; a page closed meanwhile still finishes the save.
 */
class ManualPathViewModel(
    private val runtime: AppRuntime,
    val address: String,
    val limits: ManualPathLimits = ManualPathLimits.core,
) : ViewModel() {
    /** The peer's live row; null until read, and once it is gone (the shell closes the page then). */
    val peer: StateFlow<PeerSummary?> = runtime.appState
        .map { state -> state?.peers?.firstOrNull { it.address == address } }
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    private val _seed = MutableStateFlow<SeedRoute>(SeedRoute.Loading)
    val seed: StateFlow<SeedRoute> = _seed.asStateFlow()

    private val _ping = MutableStateFlow<PathPing?>(null)

    /** The latest Ping along path; shown only while the draft still tests that path. */
    val ping: StateFlow<PathPing?> = _ping.asStateFlow()

    private val _saving = MutableStateFlow(false)
    val saving: StateFlow<Boolean> = _saving.asStateFlow()

    private val _failure = MutableStateFlow<SaveFailure?>(null)
    val failure: StateFlow<SaveFailure?> = _failure.asStateFlow()

    private val saves = Channel<Unit>(Channel.CONFLATED)

    /** The path is held: the editor closes. */
    val saved: Flow<Unit> = saves.receiveAsFlow()

    init {
        viewModelScope.launch {
            combine(
                runtime.lifecycle.map { it is MobileAppLifecycle.Running }.distinctUntilChanged(),
                runtime.routeRevisions.map { it[address] ?: 0L }.distinctUntilChanged(),
            ) { running, revision -> running to revision }.collect {
                if (_seed.value !is SeedRoute.Read) readSeed()
            }
        }
    }

    private suspend fun readSeed() {
        _seed.value = try {
            SeedRoute.Read(runtime.peerRoute(address).await())
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            AppLog.d(TAG, "route unread: ${error.javaClass.simpleName}")
            SeedRoute.Unavailable(error)
        }
    }

    /** Ping the peer along [path], installing nothing; a newer ping replaces one still waiting. */
    fun ping(path: ManualPath) {
        val sent = runtime.ping(address, path)
        _ping.value = PathPing(path, null)
        viewModelScope.launch {
            val outcome = sent.await()
            // A newer ping ended this one; the newer one reports.
            if (outcome is PingOutcome.Canceled) return@launch
            if (_ping.value?.path == path) _ping.value = PathPing(path, outcome)
        }
    }

    /** Hold [path] for [holdMs]; the editor closes once the session holds it. */
    fun save(path: ManualPath, holdMs: Long) {
        if (_saving.value) return
        _saving.value = true
        _failure.value = null
        val sent: Deferred<Boolean> = runtime.setManualPath(address, path, holdMs)
        viewModelScope.launch {
            try {
                if (sent.await()) saves.trySend(Unit) else _failure.value = SaveFailure.Refused
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "manual path not saved: ${error.javaClass.simpleName}")
                _failure.value = SaveFailure.Failed(error)
            } finally {
                _saving.value = false
            }
        }
    }

    fun dismissFailure() {
        _failure.value = null
    }

    private companion object {
        const val TAG = "umsh.manualpath"
    }
}
