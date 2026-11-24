package com.voria.umsh.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.navigation3.runtime.NavKey
import com.voria.umsh.features.peers.ExchangeHost
import com.voria.umsh.features.peers.RuntimeExchangeHost
import com.voria.umsh.models.MeetExchange
import com.voria.umsh.services.radio.BluetoothStatus
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioBanner
import com.voria.umsh.services.radio.RadioKind
import com.voria.umsh.services.radio.RadioSnapshot
import java.time.Instant
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** The radio as the shell shows it; [known] false before the core has said what radio there is. */
data class ShownRadio(val radio: RadioSnapshot?, val known: Boolean)

/**
 * An opened link for the import sheet: its text, where it came from (for
 * the page it may lead to), and which opening it is, so the same link
 * opened again starts the sheet over rather than keeping what was edited.
 */
data class LinkImport(val uri: String, val origin: LinkOrigin, val opening: Long)

/** Where Add peer's exchange stands, for the pages the shell shows over Add peer. */
sealed interface MeetStep {
    /** On Nearby, asked, closed, or leaving an attempt: Add peer, with no exchange page. */
    data object None : MeetStep

    /** An attempt under way or just ended: the exchange page. */
    data object UnderWay : MeetStep

    /** Contacts crossed: the new peer's page in place of Add peer and the exchange. */
    data class Exchanged(val peerAddress: String) : MeetStep
}

/**
 * The shell's own state: the radio control, the banners, the unread badge,
 * which threads and peer pages still have what they show, and whether Add
 * peer's exchange is wanted open. It survives a rotation, so a rotation
 * neither closes the exchange nor reopens it.
 */
class ShellViewModel(
    private val runtime: AppRuntime,
    bluetooth: StateFlow<BluetoothStatus> = MutableStateFlow(BluetoothStatus.Ready),
    bound: Flow<BoundRadio?> = flowOf(null),
    /** The app is started (the process's lifecycle, not the activity's). */
    processStarted: Flow<Boolean> = flowOf(true),
    /** Add peer's contact exchange; the runtime's unless a test gives its own. */
    private val exchange: ExchangeHost = RuntimeExchangeHost(runtime),
) : ViewModel() {
    /**
     * One value, so the control and banner never see "known" beside a radio
     * not yet published: the runtime publishes the radio before it marks it
     * known, and this reads the radio after the mark.
     */
    val radio: StateFlow<ShownRadio> = combine(runtime.radio, runtime.radioKnown) { _, _ -> shownRadio() }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), shownRadio())

    val now: StateFlow<Instant> = runtime.now

    /**
     * The phone's own Bluetooth matters only to a Bluetooth radio: off, or
     * Nearby devices not granted, it is what the banner says, live.
     */
    val radioBanner: StateFlow<RadioBanner?> = combine(radio, bluetooth, bound) { shown, status, boundRadio ->
        val ble = boundRadio?.kind == RadioKind.Ble
        RadioBanner.from(
            shown.radio,
            bluetoothOff = ble && status.adapter != BluetoothStatus.Adapter.On &&
                status.adapter != BluetoothStatus.Adapter.Missing,
            nearbyDenied = ble && !status.nearbyGranted,
            known = shown.known,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), RadioBanner.from(radio.value.radio, known = radio.value.known))

    /** Stored data failed to read: what is shown may be out of date. */
    val dataLoadFailed: StateFlow<Boolean> = runtime.stateLoadError

    /** Conversations with unread messages, not messages: the Conversations badge. */
    val unreadConversations: StateFlow<Int> = runtime.appState
        .map { state -> state?.conversations?.count { it.unreadCount > 0 } ?: 0 }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), 0)

    private val _linkImport = MutableStateFlow<LinkImport?>(null)

    /**
     * An opened link that names no node (or a channel), shown in the import
     * sheet with what is wrong with it. Kept across a rotation; after process
     * death the sheet does not reopen.
     */
    val linkImport: StateFlow<LinkImport?> = _linkImport

    private var openings = 0L

    /** [uri], opened from [origin]: a new opening, even of the link already shown. */
    fun showLinkImport(uri: String, origin: LinkOrigin) {
        _linkImport.value = LinkImport(uri, origin, ++openings)
    }

    fun closeLinkImport() {
        _linkImport.value = null
    }

    /** The app was left: the sheet's link no longer leads back out of it ([ShellState.appLeft]). */
    fun appLeft() {
        _linkImport.update { shown -> shown?.copy(origin = LinkOrigin.InApp) }
    }

    private val _linkFailure = MutableStateFlow<Throwable?>(null)

    /** An opened link that could not be stored: the failure dialog's error. */
    val linkFailure: StateFlow<Throwable?> = _linkFailure

    fun linkFailed(error: Throwable?) {
        _linkFailure.value = error
    }

    private val meetPageShown = MutableStateFlow(false)

    private val meetPresence = MeetPresence(viewModelScope, meetPageShown, processStarted, exchange::setWanted)

    /**
     * Backing out of an attempt, until the core reports it left: the
     * exchange page is gone, and must not come back for the attempt it left.
     */
    private val leaving = MutableStateFlow(false)

    /**
     * What the exchange page follows ([ShellState.followMeet]), each time it
     * may have changed. The shell reads [currentMeetStep] after telling
     * [topPageChanged], in the same pass, so a page just left is never
     * pushed back by a step that has not caught up.
     */
    val meetStep: Flow<MeetStep> = combine(exchange.meet, leaving) { meet, leaving -> step(meet?.exchange, leaving) }

    /** The step now, with the leaving [topPageChanged] may just have begun. */
    fun currentMeetStep(): MeetStep = step(exchange.meet.value?.exchange, leaving.value)

    private var lastTop: NavKey? = null

    init {
        viewModelScope.launch {
            // The attempt left (or another began past it): nothing more to hide.
            exchange.meet.collect { meet -> if (meet?.exchange?.isUnderWay != true) leaving.value = false }
        }
    }

    /** The page on screen changed to [top] ([ShellState.shownTop]). */
    fun topPageChanged(top: NavKey?) {
        val left = lastTop
        lastTop = top
        meetPageShown.value = top is MeetsNearby
        // The exchange page closed over its Add peer (Back, predictive back,
        // Done): the attempt is left for both, under a fresh key.
        if (left is UmshKey.Exchange && top == UmshKey.AddPeer(left.destination)) leaveExchange()
    }

    /** Back out of the attempt under way, or ended; nothing when none is. */
    private fun leaveExchange() {
        if (exchange.meet.value?.exchange?.isUnderWay != true) return
        leaving.value = true
        val backingOut = exchange.backOut()
        viewModelScope.launch {
            val taken = try {
                backingOut.await()
                true
            } catch (error: CancellationException) {
                // This model is going; the runtime's own work is not.
                if (!backingOut.isCancelled) throw error
                false
            } catch (_: Exception) {
                false
            }
            // Not taken: the attempt stands, and its page may show again.
            if (!taken) leaving.value = false
        }
    }

    override fun onCleared() {
        // The shell is gone for good (a mode switch, a new identity): the
        // exchange closes with it. In the runtime's scope, which outlives this.
        if (meetPresence.wanted) runtime.setMeetWanted(false)
    }

    fun retryLoad() {
        runtime.reload(full = true)
    }

    private fun step(exchange: MeetExchange?, leaving: Boolean): MeetStep = when {
        exchange is MeetExchange.Exchanged -> MeetStep.Exchanged(exchange.peerAddress)
        exchange?.isUnderWay == true && !leaving -> MeetStep.UnderWay
        else -> MeetStep.None
    }

    private fun shownRadio(): ShownRadio {
        val known = runtime.radioKnown.value
        return ShownRadio(runtime.radio.value, known)
    }

    private companion object {
        const val STOP_TIMEOUT_MS = 5_000L
    }
}
