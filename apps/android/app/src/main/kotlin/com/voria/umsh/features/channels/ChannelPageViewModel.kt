package com.voria.umsh.features.channels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** A command on the channel page that failed, for its dialog. */
sealed interface ChannelPageFailure {
    val error: Throwable

    data class NotOpened(override val error: Throwable) : ChannelPageFailure
    data class NotLeft(override val error: Throwable) : ChannelPageFailure
    data class NotChanged(override val error: Throwable) : ChannelPageFailure
    data class NotShared(override val error: Throwable) : ChannelPageFailure
}

/**
 * A channel's page (`channels.svg` 10–13): the channel as the lists hold
 * it, its conversation, its alias, its invitation, and leaving. Commands
 * run in the runtime's scope, so a rotation cancels none; the invitation
 * sheet stays open across a rotation, not after process death.
 */
class ChannelPageViewModel(private val runtime: AppRuntime, private val id: String) : ViewModel() {
    /** Null until read, and once this phone no longer holds it. */
    val channel: StateFlow<ChannelSummary?> = runtime.appState
        .map { state -> state?.channels?.firstOrNull { it.id == id } }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), runtime.appState.value?.channels?.firstOrNull { it.id == id })

    private val _failure = MutableStateFlow<ChannelPageFailure?>(null)
    val failure: StateFlow<ChannelPageFailure?> = _failure.asStateFlow()

    private val _invitation = MutableStateFlow<String?>(null)

    /** The invitation the sheet shows; null when it is closed. */
    val invitation: StateFlow<String?> = _invitation.asStateFlow()

    private val _conversations = Channel<String>(Channel.BUFFERED)

    /** Conversation: its address, opened, once; the shell shows it. */
    val conversationOpened: Flow<String> = _conversations.receiveAsFlow()

    fun openConversation() = perform(runtime.openChannelConversation(id), ChannelPageFailure::NotOpened) { _conversations.send(it) }

    fun leave() = perform(runtime.leaveChannel(id), ChannelPageFailure::NotLeft) {}

    fun setAlias(alias: String) = perform(runtime.setChannelAlias(id, alias), ChannelPageFailure::NotChanged) {}

    /** Share: the invitation, made by the core, in its sheet. */
    fun share() = perform(runtime.channelInvitation(id), ChannelPageFailure::NotShared) { _invitation.value = it }

    fun closeInvitation() {
        _invitation.value = null
    }

    fun dismissFailure() {
        _failure.value = null
    }

    private fun <T> perform(command: Deferred<T>, failure: (Throwable) -> ChannelPageFailure, done: suspend (T) -> Unit) {
        viewModelScope.launch {
            try {
                done(command.await())
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "channel command failed: ${error.javaClass.simpleName}")
                _failure.value = failure(error)
            }
        }
    }

    private companion object {
        const val TAG = "umsh.channels"
        const val STOP_TIMEOUT_MS = 5_000L
    }
}
