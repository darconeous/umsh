package com.voria.umsh.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.services.radio.RadioBanner
import com.voria.umsh.services.radio.RadioSnapshot
import java.time.Instant
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn

/** The radio as the shell shows it; [known] false before the core has said what radio there is. */
data class ShownRadio(val radio: RadioSnapshot?, val known: Boolean)

/** The shell's own state: the radio control, the banners, the unread badge, and which threads still have a conversation. */
class ShellViewModel(private val runtime: AppRuntime) : ViewModel() {
    /**
     * One value, so the control and banner never see "known" beside a radio
     * not yet published: the runtime publishes the radio before it marks it
     * known, and this reads the radio after the mark.
     */
    val radio: StateFlow<ShownRadio> = combine(runtime.radio, runtime.radioKnown) { _, _ -> shownRadio() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), shownRadio())

    val now: StateFlow<Instant> = runtime.now

    val radioBanner: StateFlow<RadioBanner?> = radio
        .map { RadioBanner.from(it.radio, known = it.known) }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), RadioBanner.from(radio.value.radio, known = radio.value.known))

    /** Stored data failed to read: what is shown may be out of date. */
    val dataLoadFailed: StateFlow<Boolean> = runtime.stateLoadError

    /** Conversations with unread messages, not messages: the Conversations badge. */
    val unreadConversations: StateFlow<Int> = runtime.appState
        .map { state -> state?.conversations?.count { it.unreadCount > 0 } ?: 0 }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), 0)

    /** The conversations stored, by address; null before the first read. */
    val conversations: StateFlow<Set<String>?> = runtime.appState
        .map(::addresses)
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), addresses(runtime.appState.value))

    fun retryLoad() {
        runtime.reload(full = true)
    }

    private fun addresses(state: AppStateSnapshot?): Set<String>? = state?.conversations?.mapTo(HashSet()) { it.address }

    private fun shownRadio(): ShownRadio {
        val known = runtime.radioKnown.value
        return ShownRadio(runtime.radio.value, known)
    }

    private companion object {
        const val STOP_TIMEOUT_MS = 5_000L
    }
}
