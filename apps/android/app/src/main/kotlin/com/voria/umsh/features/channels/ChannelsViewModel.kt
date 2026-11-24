package com.voria.umsh.features.channels

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.models.ChannelKind
import com.voria.umsh.models.ChannelSummary
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

/** The channels Settings › Channels lists, and the ones Join channel suggests. */
object ChannelLists {
    /** Every channel this phone has joined, in the core's order; the radio's own are never here. */
    fun joined(channels: List<ChannelSummary>): List<ChannelSummary> = channels.filter { it.joinedPhone }

    /** Built-in channels this phone left, offered again only in Join channel (`channels.svg` 5). */
    fun suggested(channels: List<ChannelSummary>): List<ChannelSummary> =
        channels.filter { it.kind == ChannelKind.Builtin && !it.joinedPhone }

    /** Joined channels with no conversation yet, for New channel chat (`new-channel-chat.svg`). */
    fun withoutConversation(channels: List<ChannelSummary>): List<ChannelSummary> =
        channels.filter { it.joinedPhone && it.conversationAddress == null }
}

/**
 * Settings › Channels (`channels.svg` 1–3): the joined channels, and
 * leaving one from its row. A channel's page closing once it is left is
 * the shell's.
 */
class ChannelsViewModel(private val runtime: AppRuntime) : ViewModel() {
    /** Null until the store is first read: an unread list never claims to be empty. */
    val channels: StateFlow<List<ChannelSummary>?> = runtime.appState
        .map { state -> state?.channels?.let(ChannelLists::joined) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), runtime.appState.value?.channels?.let(ChannelLists::joined))

    private val _failure = MutableStateFlow<Throwable?>(null)

    /** Why a leave failed, for its dialog. */
    val failure: StateFlow<Throwable?> = _failure.asStateFlow()

    fun leave(id: String) {
        val leaving = runtime.leaveChannel(id)
        viewModelScope.launch {
            try {
                leaving.await()
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.w(TAG, "channel not left: ${error.javaClass.simpleName}")
                _failure.value = error
            }
        }
    }

    fun dismissFailure() {
        _failure.value = null
    }

    private companion object {
        const val TAG = "umsh.channels"
        const val STOP_TIMEOUT_MS = 5_000L
    }
}
