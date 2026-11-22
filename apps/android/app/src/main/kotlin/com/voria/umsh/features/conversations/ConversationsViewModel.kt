package com.voria.umsh.features.conversations

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.designsystem.ListEnvironment
import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** What the list shows. */
sealed interface ConversationsContent {
    /** The store has not been read yet, or launch is still setting up: never claim emptiness early. */
    data object Loading : ConversationsContent

    data object Empty : ConversationsContent

    data class Rows(val rows: List<ConversationRow>) : ConversationsContent

    companion object {
        /**
         * [rows] (null before the first read) as the list shows them. A first
         * launch reads the store before the core has opened Public's chat:
         * until the core is up, empty means not yet, not none (as iOS).
         */
        fun of(rows: List<ConversationRow>?, lifecycle: MobileAppLifecycle): ConversationsContent = when {
            rows == null -> Loading
            rows.isNotEmpty() -> Rows(rows)
            lifecycle is MobileAppLifecycle.Idle || lifecycle is MobileAppLifecycle.Starting -> Loading
            else -> Empty
        }
    }
}

/** A failure the list reports in a dialog. */
sealed interface ListFailure {
    val error: Throwable

    data class NotRemoved(val removal: Removal, override val error: Throwable) : ListFailure
    data class NotOpened(override val error: Throwable) : ListFailure
}

/**
 * The Conversations root (`conversation-list.svg`): the rows, search, and
 * the confirmations before a row is removed.
 */
class ConversationsViewModel(private val runtime: AppRuntime, environment: ListEnvironment) : ViewModel() {
    private val environment = MutableStateFlow(environment)

    private val _query = MutableStateFlow("")
    val query: StateFlow<String> = _query.asStateFlow()

    private val _searching = MutableStateFlow(false)

    /** The search view is open; it stays open with an empty query. */
    val searching: StateFlow<Boolean> = _searching.asStateFlow()

    private val _pendingRemoval = MutableStateFlow<Removal?>(null)

    /** The row whose removal is being confirmed. */
    val pendingRemoval: StateFlow<Removal?> = _pendingRemoval.asStateFlow()

    private val _failure = MutableStateFlow<ListFailure?>(null)
    val failure: StateFlow<ListFailure?> = _failure.asStateFlow()

    // Held until the screen takes it: the screen may be between
    // compositions (a rotation, another destination) when a start returns.
    private val _opened = Channel<String>(Channel.BUFFERED)

    /** A conversation search started or found, to open: its address. Each is delivered once. */
    val opened: Flow<String> = _opened.receiveAsFlow()

    val content: StateFlow<ConversationsContent> =
        combine(runtime.appState, runtime.lifecycle, runtime.identity, this.environment) { state, lifecycle, identity, env ->
            content(state, lifecycle, identity.advertisedName, env)
        }.flowOn(Dispatchers.Default).stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), initialContent())

    /** What the query found; null while it is blank. */
    val results: StateFlow<SearchResults?> =
        combine(runtime.appState, content, _query, this.environment) { state, content, query, env ->
            val rows = (content as? ConversationsContent.Rows)?.rows.orEmpty()
            state?.let { ConversationList.search(it, rows, query, env.names, env.collation) }
        }.flowOn(Dispatchers.Default).stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), null)

    fun setEnvironment(environment: ListEnvironment) {
        this.environment.value = environment
    }

    fun setQuery(query: String) {
        _query.value = query
    }

    fun setSearching(open: Boolean) {
        _searching.value = open
        if (!open) _query.value = ""
    }

    // region Removing a row: the swipe and the row's action only ask.

    fun askToRemove(removal: Removal) {
        _pendingRemoval.value = removal
    }

    fun cancelRemoval() {
        _pendingRemoval.value = null
    }

    fun confirmRemoval() {
        val removal = _pendingRemoval.value ?: return
        _pendingRemoval.value = null
        // A thread showing it closes when the shell sees it gone from the lists.
        perform({ runtime.deleteConversation(removal.address) }, { ListFailure.NotRemoved(removal, it) }) { }
    }

    // endregion

    // region Opening from search

    /** A saved or discovered peer: its conversation, started the first time. */
    fun open(peer: PeerSummary) = perform({ runtime.startConversation(peer.address) }, ListFailure::NotOpened, ::opened)

    /** A joined channel: its chat, started the first time. */
    fun open(channel: ChannelSummary) =
        perform({ runtime.openChannelConversation(channel.id) }, ListFailure::NotOpened, ::opened)

    private fun opened(address: String) {
        setSearching(false)
        _opened.trySend(address)
    }

    // endregion

    fun dismissFailure() {
        _failure.value = null
    }

    /** Await a runtime command (it runs in the runtime's scope, not this one), and report how it went. */
    private fun <T> perform(command: () -> Deferred<T>, failure: (Throwable) -> ListFailure, done: (T) -> Unit) {
        val deferred = command()
        viewModelScope.launch {
            try {
                done(deferred.await())
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "list command failed: ${error.javaClass.simpleName}")
                _failure.value = failure(error)
            }
        }
    }

    private fun initialContent(): ConversationsContent = content(
        runtime.appState.value,
        runtime.lifecycle.value,
        runtime.identity.value.advertisedName,
        environment.value,
    )

    private fun content(
        state: AppStateSnapshot?,
        lifecycle: MobileAppLifecycle,
        ownName: String,
        env: ListEnvironment,
    ): ConversationsContent = ConversationsContent.of(
        state?.let { ConversationList.rows(it, env.names, env.collation, ownName) },
        lifecycle,
    )

    private companion object {
        const val TAG = "umsh.conversations"
        const val STOP_TIMEOUT_MS = 5_000L
    }
}
