package com.voria.umsh.features.peers

import androidx.compose.runtime.staticCompositionLocalOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.models.DiscoveryVantage
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.RepeaterListing
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/**
 * Where a repeater's neighbor listing comes from: this phone's store, which
 * sends nothing, and an ask across the mesh, one page at a time. The
 * runtime is the one source; a test may stand in for it.
 */
interface NeighborSource {
    /**
     * What the repeater last said, from the store; null when it was never
     * asked. Sends nothing; waits for the store to be readable, so a page
     * restored before the start finishes reads what is held.
     */
    suspend fun storedNeighbors(address: String): RepeaterListing?

    /**
     * Ask for the page at [cursor] (the first with none), down [route]
     * (repeater hints in send order; none for the session's own route);
     * the listing as it then stands.
     */
    fun requestNeighbors(address: String, cursor: Octets?, route: List<Octets> = emptyList()): Deferred<RepeaterListing>
}

/** A stand-in for the runtime's listings, for a test; null in the app. */
val LocalNeighborSource = staticCompositionLocalOf<NeighborSource?> { null }

/**
 * Neighboring repeaters (`repeaters-discover.svg` 1–2): what one repeater
 * reports hearing. Opens on what the store holds and puts nothing on the
 * air until asked: Refresh asks for the first page, which replaces what
 * was held; Load more for the next. A repeater that does not answer is an
 * inline line ([noAnswer]), not a failure dialog: the next Refresh may
 * reach it. Asks run in the runtime's scope, so rotating keeps the one
 * outstanding, and a page closed meanwhile still keeps what was answered.
 */
class NeighborsViewModel(
    private val runtime: AppRuntime,
    val address: String,
    private val source: NeighborSource = runtime,
) : ViewModel() {
    /** The repeater's live row; null until read, and once it is gone (the shell closes the page then). */
    val reporter: StateFlow<PeerSummary?> = runtime.appState
        .map { state -> state?.peers?.firstOrNull { it.address == address } }
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    private val _listing = MutableStateFlow<RepeaterListing?>(null)

    /** Null while never asked (Not read). */
    val listing: StateFlow<RepeaterListing?> = _listing.asStateFlow()

    private val _loaded = MutableStateFlow(false)

    /** The store was read. */
    val loaded: StateFlow<Boolean> = _loaded.asStateFlow()

    private val _fresh = MutableStateFlow(false)

    /** [listing] was answered during this visit, rather than read from the store. */
    val fresh: StateFlow<Boolean> = _fresh.asStateFlow()

    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy.asStateFlow()

    private val _noAnswer = MutableStateFlow(false)

    /** The last ask went unanswered. */
    val noAnswer: StateFlow<Boolean> = _noAnswer.asStateFlow()

    private val _failure = MutableStateFlow<Throwable?>(null)

    /** An ask that could not go out, for its dialog. */
    val failure: StateFlow<Throwable?> = _failure.asStateFlow()

    private val _vantage = MutableStateFlow<DiscoveryVantage?>(null)

    /**
     * The route to the repeater, as an ask after one of its neighbors goes
     * down it; null when the route cannot honestly land at the repeater.
     */
    val lookupRoute: StateFlow<List<Octets>?> = _vantage
        .map { vantage -> vantage?.takeIf { it.landsAtPeer }?.repeaters?.map { it.octets } }
        .stateIn(viewModelScope, SharingStarted.Eagerly, null)

    init {
        viewModelScope.launch {
            val stored = try {
                source.storedNeighbors(address)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.d(TAG, "neighbors unread: ${error.javaClass.simpleName}")
                null
            }
            // Refresh is offered before the store is read; an answer that
            // came in first is newer than anything stored.
            if (!_fresh.value) _listing.value = stored
            _loaded.value = true
        }
        viewModelScope.launch {
            combine(
                runtime.lifecycle.map { it is MobileAppLifecycle.Running }.distinctUntilChanged(),
                runtime.routeRevisions.map { it[address] ?: 0L }.distinctUntilChanged(),
            ) { running, revision -> running to revision }.collect { loadVantage() }
        }
    }

    private suspend fun loadVantage() {
        _vantage.value = try {
            runtime.peerRoute(address).await().discoveryVantage
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            AppLog.d(TAG, "route unread: ${error.javaClass.simpleName}")
            null
        }
    }

    /** Ask for the top of the listing again. */
    fun refresh() = ask(null)

    /** Ask for the page after the last one held. */
    fun loadMore() {
        _listing.value?.nextCursor?.let(::ask)
    }

    private fun ask(cursor: Octets?) {
        if (_busy.value) return
        _busy.value = true
        _noAnswer.value = false
        val asked = source.requestNeighbors(address, cursor)
        viewModelScope.launch {
            try {
                _listing.value = asked.await()
                _fresh.value = true
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileAppException.NoAnswer) {
                _noAnswer.value = true
            } catch (error: Exception) {
                AppLog.w(TAG, "neighbors not asked: ${error.javaClass.simpleName}")
                _failure.value = error
            } finally {
                _busy.value = false
            }
        }
    }

    /**
     * Ask the node behind a neighbor's hint who it is, down [lookupRoute]
     * so it hears the ask one hop past the repeater.
     */
    fun lookUp(hint: Octets): Deferred<Unit> = runtime.lookUpRepeaterHint(hint, lookupRoute.value.orEmpty())

    fun dismissFailure() {
        _failure.value = null
    }

    private companion object {
        const val TAG = "umsh.neighbors"
    }
}
