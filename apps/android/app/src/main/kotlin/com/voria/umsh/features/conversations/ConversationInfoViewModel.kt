package com.voria.umsh.features.conversations

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.models.ChannelConversationSummary
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

/** A Conversation info command that failed, for its dialog. */
sealed interface ConversationInfoFailure {
    val error: Throwable

    data class NotChanged(override val error: Throwable) : ConversationInfoFailure

    data class NotCleared(override val error: Throwable) : ConversationInfoFailure
}

/**
 * A channel conversation's page (`conversation-info.svg` 1, 2, 5; D6, with
 * no Routing): the conversation as the lists hold it, its message count
 * (read again as its transcript changes), its notifications, EMERGENCY's
 * test-message switch, and clearing its messages. Commands run in the
 * runtime's scope, so a rotation cancels none.
 */
class ConversationInfoViewModel(private val runtime: AppRuntime, val address: String) : ViewModel() {
    /** Null until read, and once the conversation is gone (the shell closes the page then). */
    val conversation: StateFlow<ChannelConversationSummary?> = runtime.appState
        .map { state -> state?.channelConversations?.firstOrNull { it.address == address } }
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.Eagerly, runtime.appState.value?.channelConversations?.firstOrNull { it.address == address })

    /** Null until counted. */
    private val _messageCount = MutableStateFlow<Long?>(null)
    val messageCount: StateFlow<Long?> = _messageCount.asStateFlow()

    /** Whether messages starting "TEST:" on `EMERGENCY` notify: a phone-wide preference, as on iOS. Null until read. */
    val testMessageAlerts: StateFlow<Boolean?> = runtime.policy
        .map { it.testMessageAlerts }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), null)

    // Switches drawn at the value asked for until the store answers.
    private val _pendingNotifications = MutableStateFlow<Boolean?>(null)
    val pendingNotifications: StateFlow<Boolean?> = _pendingNotifications.asStateFlow()

    private val _failure = MutableStateFlow<ConversationInfoFailure?>(null)
    val failure: StateFlow<ConversationInfoFailure?> = _failure.asStateFlow()

    init {
        viewModelScope.launch {
            combine(
                conversation.map { it != null }.distinctUntilChanged(),
                runtime.transcriptRevisions.map { it[address] ?: 0L }.distinctUntilChanged(),
            ) { has, revision -> has to revision }.collect { (has, _) -> if (has) count() }
        }
        viewModelScope.launch {
            conversation.collect { shown ->
                if (shown != null && _pendingNotifications.value == shown.channel.notificationsEnabled) _pendingNotifications.value = null
            }
        }
    }

    private suspend fun count() {
        _messageCount.value = try {
            runtime.messageCount(address)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            AppLog.w(TAG, "message count unread: ${error.javaClass.simpleName}")
            _messageCount.value
        }
    }

    fun setNotifications(enabled: Boolean) {
        val channel = conversation.value?.channel ?: return
        _pendingNotifications.value = enabled
        perform(runtime.setChannelNotifications(channel.id, enabled), ConversationInfoFailure::NotChanged) {
            _pendingNotifications.value = null
        }
    }

    fun setTestMessageAlerts(enabled: Boolean) =
        perform(runtime.setPolicy { testMessageAlerts = enabled }, ConversationInfoFailure::NotChanged)

    /** Erase this phone's copy; the conversation, its draft and its place stay. */
    fun clearMessages() = perform(runtime.clearMessages(address), ConversationInfoFailure::NotCleared)

    fun dismissFailure() {
        _failure.value = null
    }

    private fun perform(command: Deferred<Unit>, failure: (Throwable) -> ConversationInfoFailure, onFailure: () -> Unit = {}) {
        viewModelScope.launch {
            try {
                command.await()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "conversation info command failed: ${error.javaClass.simpleName}")
                onFailure()
                _failure.value = failure(error)
            }
        }
    }

    private companion object {
        const val TAG = "umsh.info"
        const val STOP_TIMEOUT_MS = 5_000L
    }
}
