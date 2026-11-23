package com.voria.umsh.app.debug

import com.voria.umsh.features.onboarding.ConnectFailure
import com.voria.umsh.features.onboarding.FoundRadio
import com.voria.umsh.features.onboarding.RadioScanSource
import com.voria.umsh.features.onboarding.RadioScanState
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * Connect a radio's stand-in search (D6): debug builds and the UI tests.
 * Radios appear one by one; connecting to one answers [outcome] after a
 * pause. Allow and Turn on go back to looking.
 */
class FakeRadioScanSource(
    initial: RadioScanState = RadioScanState.Looking(emptyList()),
    /** What connecting ends in: a failure, or null for connected. */
    private val outcome: ConnectFailure? = ConnectFailure.PairingRemoved,
    /** Radios to reveal while looking, one per [revealMs]; none when [initial] already holds them. */
    private val reveal: List<FoundRadio> = emptyList(),
    private val revealMs: Long = 800,
    private val connectMs: Long = 1_500,
    /** For the tests: connecting answers when this completes, in place of [connectMs]. */
    private val connectGate: CompletableDeferred<Unit>? = null,
) : RadioScanSource {
    private val _state = MutableStateFlow(initial)
    override val state: StateFlow<RadioScanState> = _state.asStateFlow()

    private var scope: CoroutineScope? = null
    private var revealing: Job? = null

    /** What [connect] was asked for, in order: for the tests. */
    val connects = mutableListOf<FoundRadio>()

    override fun start() {
        if (scope != null) return
        val running = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate).also { scope = it }
        revealing = running.launch {
            for (radio in reveal) {
                delay(revealMs)
                val looking = _state.value as? RadioScanState.Looking ?: return@launch
                if (looking.radios.none { it.id == radio.id }) _state.value = looking.copy(radios = looking.radios + radio)
            }
        }
    }

    override fun stop() {
        scope?.cancel()
        scope = null
    }

    override fun connect(radio: FoundRadio) {
        connects += radio
        val looking = _state.value as? RadioScanState.Looking ?: return
        _state.value = looking.copy(connecting = radio.id, failure = null)
        scope?.launch {
            if (connectGate != null) connectGate.await() else delay(connectMs)
            _state.value = if (outcome == null) {
                RadioScanState.Connected
            } else {
                looking.copy(connecting = null, failure = outcome)
            }
        }
    }

    override fun allow() = lookAgain()

    override fun turnOn() = lookAgain()

    private fun lookAgain() {
        _state.value = RadioScanState.Looking(SAMPLE_RADIOS)
    }

    companion object {
        /** `onboarding.svg` board 5: what radios in pairing mode advertise. Data, as a radio sends it. */
        val SAMPLE_RADIOS = listOf(
            FoundRadio("t1000e", "T1000-E 4F2A", 2),
            FoundRadio("tdeck", "Ridge T-Deck", 11),
            FoundRadio("unknown", "UMSH radio", null),
        )

        /** The preview's states, by name, for `--es scenario`. */
        fun scenario(name: String?): FakeRadioScanSource = when (name) {
            "looking" -> FakeRadioScanSource()
            "connecting" -> FakeRadioScanSource(
                RadioScanState.Looking(SAMPLE_RADIOS, connecting = SAMPLE_RADIOS.first().id),
                connectMs = Long.MAX_VALUE / 2,
            )
            "failed" -> FakeRadioScanSource(RadioScanState.Looking(SAMPLE_RADIOS, failure = ConnectFailure.PairingRemoved))
            "denied" -> FakeRadioScanSource(RadioScanState.NearbyDenied)
            "off" -> FakeRadioScanSource(RadioScanState.BluetoothOff)
            "unavailable" -> FakeRadioScanSource(RadioScanState.BluetoothUnavailable)
            "found" -> FakeRadioScanSource(RadioScanState.Looking(SAMPLE_RADIOS))
            // Live-feeling: looking, then the radios appear one by one.
            else -> FakeRadioScanSource(reveal = SAMPLE_RADIOS)
        }
    }
}
