package com.voria.umsh.features.peers

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.designsystem.ListEnvironment
import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** What the Peers root shows: the list, or search's two groups. */
sealed interface PeersContent {
    /** The store is not read yet. */
    data object Loading : PeersContent

    data class List(val sections: PeerSections, val conversations: Set<String>) : PeersContent

    data class Search(val results: PeerSearchResults, val conversations: Set<String>) : PeersContent
}

/** A removal asked for, waiting on its dialog. */
data class PendingRemoval(val peer: PeerSummary, val choice: RemovalChoice)

/** A list action that failed, for its dialog. */
sealed interface PeersFailure {
    val error: Throwable

    data class NotSaved(override val error: Throwable) : PeersFailure

    data class NotChanged(override val error: Throwable) : PeersFailure

    data class NotRemoved(override val error: Throwable) : PeersFailure

    data class NotDeleted(override val error: Throwable) : PeersFailure
}

/**
 * The Peers root (`peers-list.svg`): sections in the order chosen (kept
 * across launches), one role filter, search, and the long-press actions.
 */
class PeersViewModel(
    private val runtime: AppRuntime,
    environment: ListEnvironment,
    savedSort: Flow<String?>,
    private val saveSort: suspend (String) -> Unit,
) : ViewModel() {
    private val environment = MutableStateFlow(environment)
    private val _filter = MutableStateFlow<PeerFilter?>(null)
    private val _query = MutableStateFlow("")
    private val _searching = MutableStateFlow(false)
    private val _pendingRemoval = MutableStateFlow<PendingRemoval?>(null)
    private val _failure = MutableStateFlow<PeersFailure?>(null)

    val sort: StateFlow<PeerSort> = savedSort.map(PeerSort::named)
        .stateIn(viewModelScope, SharingStarted.Eagerly, PeerSort.Alphabetical)
    val filter: StateFlow<PeerFilter?> = _filter.asStateFlow()
    val query: StateFlow<String> = _query.asStateFlow()
    val searching: StateFlow<Boolean> = _searching.asStateFlow()
    val pendingRemoval: StateFlow<PendingRemoval?> = _pendingRemoval.asStateFlow()
    val failure: StateFlow<PeersFailure?> = _failure.asStateFlow()

    // The stored order itself, not [sort]'s default: the list waits for it rather than redrawing in another order.
    private val arrangement = combine(savedSort.map(PeerSort::named), _filter, this.environment) { sort, filter, env ->
        PeerArrangement(sort, filter, env.names, env.collation)
    }

    val content: StateFlow<PeersContent> = combine(runtime.appState, arrangement, _query, _searching) { state, arrangement, query, searching ->
        content(state, arrangement, query, searching)
    }.flowOn(Dispatchers.Default).stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), PeersContent.Loading)

    fun setEnvironment(environment: ListEnvironment) {
        this.environment.value = environment
    }

    fun setSort(sort: PeerSort) {
        viewModelScope.launch {
            try {
                saveSort(sort.name)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                // The order stays as it was: nothing to tell the user beyond the list not moving.
                AppLog.w(TAG, "sort not kept: ${error.javaClass.simpleName}")
            }
        }
    }

    /** One filter at a time; choosing the chosen one again clears it. */
    fun toggleFilter(filter: PeerFilter) {
        _filter.value = if (_filter.value == filter) null else filter
    }

    fun setQuery(query: String) {
        _query.value = query
    }

    fun setSearching(open: Boolean) {
        _searching.value = open
        if (!open) _query.value = ""
    }

    // region Long press

    fun setFavorite(peer: PeerSummary, favorite: Boolean) =
        perform({ runtime.setFavorite(peer.address, favorite) }, PeersFailure::NotChanged)

    /** Save a node heard over the air: the long press's Save, and search's add button. */
    fun save(peer: PeerSummary) = perform({ runtime.promotePeer(peer.address) }, PeersFailure::NotSaved)

    fun askToRemove(peer: PeerSummary) {
        val conversations = runtime.appState.value?.directConversations.orEmpty()
        val choice = RemovalChoice.forList(peer, conversations.any { it.peer.address == peer.address }) ?: return
        _pendingRemoval.value = PendingRemoval(peer, choice)
    }

    fun cancelRemoval() {
        _pendingRemoval.value = null
    }

    /** Remove peer: off Peers, conversation kept. */
    fun demote() {
        val pending = _pendingRemoval.value ?: return
        _pendingRemoval.value = null
        perform({ runtime.demotePeer(pending.peer.address) }, PeersFailure::NotRemoved)
    }

    /** Delete peer, with its conversation when it has one. Pages about it close when the shell sees it gone. */
    fun delete() {
        val pending = _pendingRemoval.value ?: return
        _pendingRemoval.value = null
        val withConversation = pending.choice is RemovalChoice.WithConversation
        perform({ runtime.deletePeer(pending.peer.address, withConversation) }, PeersFailure::NotDeleted)
    }

    // endregion

    fun dismissFailure() {
        _failure.value = null
    }

    /** Await a runtime command (it runs in the runtime's scope), and report a failure. */
    private fun perform(command: () -> Deferred<Unit>, failure: (Throwable) -> PeersFailure) {
        val deferred = command()
        viewModelScope.launch {
            try {
                deferred.await()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "peer command failed: ${error.javaClass.simpleName}")
                _failure.value = failure(error)
            }
        }
    }

    private fun content(state: AppStateSnapshot?, arrangement: PeerArrangement, query: String, searching: Boolean): PeersContent {
        if (state == null) return PeersContent.Loading
        val conversations = state.directConversations.mapTo(HashSet()) { it.peer.address }
        return if (searching && query.isNotBlank()) {
            PeersContent.Search(PeerSearchResults.of(state, query, arrangement), conversations)
        } else {
            PeersContent.List(PeerSections.of(state, arrangement), conversations)
        }
    }

    private companion object {
        const val TAG = "umsh.peers"
        const val STOP_TIMEOUT_MS = 5_000L
    }
}
