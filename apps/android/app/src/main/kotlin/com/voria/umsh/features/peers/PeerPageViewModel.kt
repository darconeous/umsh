package com.voria.umsh.features.peers

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.ulcpLocationCellMeters
import com.voria.umsh.models.DirectConversationSummary
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.models.RouteState
import com.voria.umsh.services.location.PhoneFix
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** What one state read knows of the page's node. */
data class PeerPageModel(
    val peer: PeerSummary,
    /** The direct conversation with it, if there is one. */
    val conversation: DirectConversationSummary?,
    /** The companion radio's own row, the distance's fallback reference. */
    val radio: PeerSummary?,
)

/** A page action that failed, for its dialog. */
sealed interface PeerPageFailure {
    val error: Throwable

    data class NotChanged(override val error: Throwable) : PeerPageFailure

    data class NotSaved(override val error: Throwable) : PeerPageFailure

    data class NotRenamed(override val error: Throwable) : PeerPageFailure

    data class NotRemoved(override val error: Throwable) : PeerPageFailure

    data class NotDeleted(override val error: Throwable) : PeerPageFailure

    data class NotCleared(override val error: Throwable) : PeerPageFailure

    data class NotAsked(override val error: Throwable) : PeerPageFailure

    data class NotOpened(override val error: Throwable) : PeerPageFailure
}

/**
 * One peer's page (`peer-page.svg`): the live row by address, its route
 * (read again whenever the node is heard), its conversation's size, and
 * the page's commands. Every command runs in the runtime's scope; a page
 * closed meanwhile does not cancel it.
 */
class PeerPageViewModel(
    private val runtime: AppRuntime,
    val address: String,
    /** How long an identity ask shows as outstanding (iOS `HintDiscoveryButton.wait`). */
    private val askWaitMs: Long = ASK_WAIT_MS,
    private val cellMeters: (Int) -> Double? = { ulcpLocationCellMeters(it.toUByte()) },
) : ViewModel() {
    /** Null until the store is read, and once the node is gone (the shell closes the page then). */
    val model: StateFlow<PeerPageModel?> = runtime.appState.map { state ->
        state?.let {
            val peer = it.peers.firstOrNull { peer -> peer.address == address } ?: return@let null
            PeerPageModel(
                peer = peer,
                conversation = it.directConversations.firstOrNull { conversation -> conversation.peer.address == address },
                radio = it.peers.firstOrNull { row -> row.isCompanionRadio },
            )
        }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, null)

    private val _route = MutableStateFlow<RouteState>(RouteState.Loading)
    val route: StateFlow<RouteState> = _route.asStateFlow()

    private val _messageCount = MutableStateFlow(0L)
    val messageCount: StateFlow<Long> = _messageCount.asStateFlow()

    private val phoneFix = MutableStateFlow<PhoneFix?>(null)

    /** From the phone when location is already granted, else the radio; null when neither or the node has no position. */
    val distance: StateFlow<PeerDistance?> = combine(model, phoneFix) { model, fix ->
        model?.let { PeerDistance.of(it.peer, fix, it.radio, cellMeters) }
    }.stateIn(viewModelScope, SharingStarted.Eagerly, null)

    // Switches drawn at the value asked for until the store answers.
    private val _pendingFavorite = MutableStateFlow<Boolean?>(null)
    val pendingFavorite: StateFlow<Boolean?> = _pendingFavorite.asStateFlow()
    private val _pendingWatch = MutableStateFlow<Boolean?>(null)
    val pendingWatch: StateFlow<Boolean?> = _pendingWatch.asStateFlow()
    private val _pendingMessages = MutableStateFlow<Boolean?>(null)
    val pendingMessages: StateFlow<Boolean?> = _pendingMessages.asStateFlow()

    private val _asking = MutableStateFlow(false)

    /** An identity ask is out: the Advertised row's spinner, for a while or until the node answers. */
    val asking: StateFlow<Boolean> = _asking.asStateFlow()
    private var askJob: Job? = null

    private val _busy = MutableStateFlow(false)

    /** Message or Identify is on its way: their tiles wait. */
    val busy: StateFlow<Boolean> = _busy.asStateFlow()

    private val _failure = MutableStateFlow<PeerPageFailure?>(null)
    val failure: StateFlow<PeerPageFailure?> = _failure.asStateFlow()

    private val _sharing = MutableStateFlow(false)

    /** The share sheet is open (`share.svg` 1): kept across a rotation, not after process death. */
    val sharing: StateFlow<Boolean> = _sharing.asStateFlow()

    fun share(shown: Boolean) {
        _sharing.value = shown
    }

    private val _conversationOpened = Channel<String>(Channel.CONFLATED)

    /** Message's conversation, opened: the shell shows it. */
    val conversationOpened: Flow<String> = _conversationOpened.receiveAsFlow()

    init {
        // The route, read on open, whenever the node is heard again, once
        // the core runs, and whenever this phone changes it (a reply, a
        // reset, a held path cleared: here, in Ping, or on the Route page).
        viewModelScope.launch {
            combine(
                model.map { it?.peer?.lastHeardAtMs }.distinctUntilChanged(),
                runtime.lifecycle.map { it is MobileAppLifecycle.Running }.distinctUntilChanged(),
                runtime.routeRevisions.map { it[address] ?: 0L }.distinctUntilChanged(),
            ) { heard, running, revision -> Triple(heard, running, revision) }.collect { loadRoute() }
        }
        // The conversation's size, read again as its transcript changes.
        viewModelScope.launch {
            combine(
                model.map { it?.conversation != null }.distinctUntilChanged(),
                runtime.transcriptRevisions.map { it[address] ?: 0L }.distinctUntilChanged(),
            ) { has, revision -> has to revision }.collect { (has, _) ->
                _messageCount.value = if (has) count() else 0L
            }
        }
        // Once, and only under a grant already given: a page never asks for
        // location. Not until the node advertises a position, since without
        // one there is no distance to measure.
        viewModelScope.launch {
            model.first { it?.peer?.advertised?.let { node -> node.latitude != null && node.longitude != null } == true }
            phoneFix.value = try {
                runtime.phoneFixIfGranted()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                null
            }
        }
        // The store answering clears what the switches were drawn at.
        viewModelScope.launch {
            model.collect { shown ->
                val peer = shown?.peer ?: return@collect
                if (_pendingFavorite.value == peer.isFavorite) _pendingFavorite.value = null
                if (_pendingWatch.value == peer.notifyWhenHeard) _pendingWatch.value = null
                if (_pendingMessages.value == shown.conversation?.notificationsEnabled) _pendingMessages.value = null
            }
        }
    }

    private suspend fun count(): Long = try {
        runtime.messageCount(address)
    } catch (error: CancellationException) {
        throw error
    } catch (error: Exception) {
        AppLog.w(TAG, "message count unread: ${error.javaClass.simpleName}")
        _messageCount.value
    }

    private suspend fun loadRoute() {
        val loaded = try {
            RouteState.Loaded(runtime.peerRoute(address).await())
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            // Not running yet, or no radio session: the strip says so with a dash.
            AppLog.d(TAG, "route unread: ${error.javaClass.simpleName}")
            RouteState.Unavailable
        }
        _route.value = loaded
    }

    // region Commands

    fun setFavorite(favorite: Boolean) {
        _pendingFavorite.value = favorite
        perform({ runtime.setFavorite(address, favorite) }, PeerPageFailure::NotChanged) { _pendingFavorite.value = null }
    }

    /** Arms always: a refused notification permission is asked for by the page after. */
    fun setNotifyWhenHeard(armed: Boolean) {
        _pendingWatch.value = armed
        perform({ runtime.setNotifyWhenHeard(address, armed) }, PeerPageFailure::NotChanged) { _pendingWatch.value = null }
    }

    fun setMessageNotifications(enabled: Boolean) {
        _pendingMessages.value = enabled
        perform({ runtime.setConversationNotifications(address, enabled) }, PeerPageFailure::NotChanged) {
            _pendingMessages.value = null
        }
    }

    /** Empty falls back to the name the node advertises. */
    fun rename(name: String) = perform({ runtime.setAlias(address, name) }, PeerPageFailure::NotRenamed)

    fun addToPeers() = perform({ runtime.promotePeer(address) }, PeerPageFailure::NotSaved)

    /** Remove peer: off Peers, the conversation and this page stay. */
    fun demote() = perform({ runtime.demotePeer(address) }, PeerPageFailure::NotRemoved)

    /** Delete peer: the shell closes this page once the node is gone (and the thread, with the conversation). */
    fun delete(withConversation: Boolean) =
        perform({ runtime.deletePeer(address, withConversation) }, PeerPageFailure::NotDeleted)

    fun clearMessages() = perform({ runtime.clearMessages(address) }, PeerPageFailure::NotCleared)

    /** Identify, or the Advertised row's Ask again: the spinner shows once the radio took the ask. */
    fun askIdentity() {
        if (_busy.value || _asking.value) return
        _busy.value = true
        val sent = runtime.fetchIdentity(address)
        viewModelScope.launch {
            try {
                sent.await()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "identity not asked: ${error.javaClass.simpleName}")
                _failure.value = PeerPageFailure.NotAsked(error)
                return@launch
            } finally {
                _busy.value = false
            }
            waitForAnswer()
        }
    }

    /** Shown as outstanding for a while, or until the node's advertisement changes, whichever is first. */
    private fun waitForAnswer() {
        askJob?.cancel()
        val before = model.value?.peer?.advertisementReceivedAtMs
        _asking.value = true
        askJob = viewModelScope.launch {
            val answered = launch {
                model.filter { it != null && it.peer.advertisementReceivedAtMs != before }.first()
                _asking.value = false
            }
            delay(askWaitMs)
            answered.cancel()
            _asking.value = false
        }
    }

    /** Message: the conversation, opened (or found open), for the shell to show. */
    fun message() {
        if (_busy.value) return
        _busy.value = true
        val opened = runtime.startConversation(address)
        viewModelScope.launch {
            try {
                _conversationOpened.trySend(opened.await())
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "conversation not opened: ${error.javaClass.simpleName}")
                _failure.value = PeerPageFailure.NotOpened(error)
            } finally {
                _busy.value = false
            }
        }
    }

    fun dismissFailure() {
        _failure.value = null
    }

    private fun perform(command: () -> Deferred<Unit>, failure: (Throwable) -> PeerPageFailure, onFailure: () -> Unit = {}) {
        val deferred = command()
        viewModelScope.launch {
            try {
                deferred.await()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "peer page command failed: ${error.javaClass.simpleName}")
                onFailure()
                _failure.value = failure(error)
            }
        }
    }

    // endregion

    companion object {
        const val ASK_WAIT_MS = 15_000L
        private const val TAG = "umsh.peer"
    }
}
