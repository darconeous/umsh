package com.voria.umsh.features.peers

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.models.DiscoveryVantage
import com.voria.umsh.models.PeerRole
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * Discover's window (iOS `DiscoverPeersView.results`): nodes that
 * identified themselves while the page was open. A live filter over the
 * peers everything else reads, so a node heard here is an ordinary row.
 */
object DiscoverWindow {
    /** Advertised, not the companion radio, heard at or after [openedAtMs]; newest first. */
    fun of(peers: List<PeerSummary>, openedAtMs: Long): List<PeerSummary> = peers
        .filter { !it.isCompanionRadio && it.advertised != null && (it.lastHeardAtMs ?: Long.MIN_VALUE) >= openedAtMs }
        .sortedByDescending { it.lastHeardAtMs }
}

/** A Discover command that did not go through, for its dialog. */
sealed interface DiscoverFailure {
    val error: Throwable

    data class NotAsked(override val error: Throwable) : DiscoverFailure

    data class NotAnnounced(override val error: Throwable) : DiscoverFailure

    data class NotCleared(override val error: Throwable) : DiscoverFailure

    data class NotSaved(override val error: Throwable) : DiscoverFailure
}

/**
 * Discover peers (`repeaters-discover.svg` 3–5): ask the nodes in range,
 * or near [vantagePeer] along its route, to identify themselves; show who
 * did while the page is open; announce this phone. The core keeps one
 * cooldown for every unnarrowed ask, wherever it was made, so [waitMs]
 * reads it each second rather than counting here. The vantage is read from
 * the peer's route when the page opens, so a page restored after process
 * death asks near where the route goes now.
 */
class DiscoverViewModel(
    private val runtime: AppRuntime,
    val vantagePeer: String?,
    /** Wall-clock milliseconds, as the core stamps when a node was heard. */
    clock: () -> Long = System::currentTimeMillis,
) : ViewModel() {
    /** The window's lower bound. */
    val openedAtMs: Long = clock()

    /** The vantage peer's live row; null without one, and once it is gone (the shell closes the page then). */
    val vantagePeerRow: StateFlow<PeerSummary?> = runtime.appState
        .map { state -> vantagePeer?.let { address -> state?.peers?.firstOrNull { it.address == address } } }
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    private val _vantage = MutableStateFlow<DiscoveryVantage?>(null)

    /** Where an ask near [vantagePeer] goes; null when there is none, or no honest way there. */
    val vantage: StateFlow<DiscoveryVantage?> = _vantage.asStateFlow()

    private val _vantageRead = MutableStateFlow(vantagePeer == null)

    /**
     * [vantage] is settled. Until then an ask aimed at [vantagePeer] waits,
     * rather than going out nearby while the route is read.
     */
    val vantageRead: StateFlow<Boolean> = _vantageRead.asStateFlow()

    /** Who identified themselves since the page opened. */
    val heard: StateFlow<List<PeerSummary>> = runtime.appState
        .map { state -> DiscoverWindow.of(state?.peers.orEmpty(), openedAtMs) }
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.Eagerly, emptyList())

    /** The radio carries this phone: the only way an ask or an announcement goes out. */
    val canSend: StateFlow<Boolean> = runtime.radio
        .map { it?.carriesThisPhone == true }
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.Eagerly, runtime.radio.value?.carriesThisPhone == true)

    private val polls = MutableStateFlow(0)

    /** Milliseconds until another ask may go; read again each second while shown. */
    @OptIn(ExperimentalCoroutinesApi::class)
    val waitMs: StateFlow<Long> = polls.flatMapLatest {
        flow {
            while (true) {
                val wait = runtime.discoveryWaitMs()
                emit(wait)
                // On the second boundary while waiting, so the count steps evenly.
                delay(if (wait > 0) (wait - 1) % SECOND_MS + 1 else SECOND_MS)
            }
        }
    }.distinctUntilChanged().stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), runtime.discoveryWaitMs())

    private val _askedHere = MutableStateFlow(false)

    /** This page sent the ask the current wait follows. */
    val askedHere: StateFlow<Boolean> = _askedHere.asStateFlow()

    private val _asking = MutableStateFlow(false)
    val asking: StateFlow<Boolean> = _asking.asStateFlow()

    private val _failure = MutableStateFlow<DiscoverFailure?>(null)
    val failure: StateFlow<DiscoverFailure?> = _failure.asStateFlow()

    init {
        if (vantagePeer != null) {
            viewModelScope.launch {
                runtime.lifecycle.filter { it is MobileAppLifecycle.Running }.first()
                _vantage.value = try {
                    runtime.peerRoute(vantagePeer).await().discoveryVantage
                } catch (error: CancellationException) {
                    throw error
                } catch (error: Exception) {
                    AppLog.d(TAG, "route unread: ${error.javaClass.simpleName}")
                    null
                }
                _vantageRead.value = true
            }
        }
    }

    /**
     * Ask nodes with [role] (all, when null) to identify themselves: in
     * range of this phone, or where [vantage] lands. A refusal because an
     * ask made elsewhere holds this one back is not a failure: the wait
     * line already says how long.
     */
    fun ask(role: PeerRole?, vantage: DiscoveryVantage?) {
        if (_asking.value) return
        _asking.value = true
        val asked = runtime.discover(role, vantage?.repeaters?.map { it.octets }.orEmpty())
        viewModelScope.launch {
            try {
                asked.await()
                _askedHere.value = true
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileAppException.InvalidRequest) {
                if (runtime.discoveryWaitMs() <= 0) _failure.value = DiscoverFailure.NotAsked(error)
            } catch (error: Exception) {
                AppLog.w(TAG, "discover not sent: ${error.javaClass.simpleName}")
                _failure.value = DiscoverFailure.NotAsked(error)
            } finally {
                _asking.value = false
                polls.value++
            }
        }
    }

    /** Broadcast this phone's signed identity, once confirmed. */
    fun announce() = perform({ runtime.advertise() }, DiscoverFailure::NotAnnounced)

    /** Drop every node heard over the air that nothing keeps; pages about them close. */
    fun clearDiscovered() = perform({ runtime.clearDiscovered() }, DiscoverFailure::NotCleared)

    /** A discovered node's add button. */
    fun save(peer: PeerSummary) = perform({ runtime.promotePeer(peer.address) }, DiscoverFailure::NotSaved)

    private fun perform(command: () -> Deferred<Unit>, failure: (Throwable) -> DiscoverFailure) {
        val sent = command()
        viewModelScope.launch {
            try {
                sent.await()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "discover command failed: ${error.javaClass.simpleName}")
                _failure.value = failure(error)
            }
        }
    }

    fun dismissFailure() {
        _failure.value = null
    }

    private companion object {
        const val TAG = "umsh.discover"
        const val SECOND_MS = 1_000L
        const val STOP_TIMEOUT_MS = 5_000L
    }
}
