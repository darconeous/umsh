package com.voria.umsh.features.peers

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.designsystem.ListEnvironment
import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.DisplayNames
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.services.format.Collation
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.flow.stateIn

/** The Peers list's sections, as iOS and `peers-list.svg` board 1 order them. */
data class PeerSections(
    val favorites: List<PeerSummary>,
    val saved: List<PeerSummary>,
    /** This phone's own companion radio, the node least often looked for. */
    val radios: List<PeerSummary>,
) {
    val isEmpty: Boolean get() = favorites.isEmpty() && saved.isEmpty() && radios.isEmpty()

    companion object {
        /**
         * Saved nodes, and the companion radio whatever its tier; nodes heard
         * but not saved stay out (search finds them). Each section by name,
         * ties by when the phone first stored them.
         */
        fun of(state: AppStateSnapshot, names: DisplayNames, collation: Collation): PeerSections {
            val order = compareBy<PeerSummary, String>(collation) { names.peer(it) }.thenBy { it.id }
            val shown = state.peers.filter { it.isSaved || it.isCompanionRadio }
            return PeerSections(
                favorites = shown.filter { !it.isCompanionRadio && it.isFavorite }.sortedWith(order),
                saved = shown.filter { !it.isCompanionRadio && !it.isFavorite }.sortedWith(order),
                radios = shown.filter { it.isCompanionRadio }.sortedWith(order),
            )
        }
    }
}

/** The read-only Peers list (D3): rows have no action until the peer page (Phase 3). */
class PeersViewModel(runtime: AppRuntime, environment: ListEnvironment) : ViewModel() {
    private val environment = MutableStateFlow(environment)

    /** Null until the store is read. */
    val sections: StateFlow<PeerSections?> = combine(runtime.appState, this.environment) { state, env ->
        state?.let { PeerSections.of(it, env.names, env.collation) }
    }.flowOn(Dispatchers.Default).stateIn(
        viewModelScope,
        SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS),
        runtime.appState.value?.let { PeerSections.of(it, environment.names, environment.collation) },
    )

    fun setEnvironment(environment: ListEnvironment) {
        this.environment.value = environment
    }

    private companion object {
        const val STOP_TIMEOUT_MS = 5_000L
    }
}
