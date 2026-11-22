package com.voria.umsh.features.onboarding

import kotlinx.coroutines.flow.StateFlow

/** A radio in pairing mode, as it advertises itself. */
data class FoundRadio(
    val id: String,
    /** The name the radio advertises. */
    val name: String,
    /** Its model, looked up from the model identifier it advertises; null when unknown. */
    val model: String?,
)

/** Why connecting to a found radio failed; the list stays, and tapping a row tries again. */
enum class ConnectFailure {
    /** The radio was not in its pairing window. */
    PairingRemoved,
    BluetoothUnavailable,
    ConnectFailed,
}

/** What Connect a radio shows (`onboarding.svg` boards 4–8). */
sealed interface RadioScanState {
    /** Searching; [connecting] is the row being attached, [failure] the last attempt's. */
    data class Looking(
        val radios: List<FoundRadio>,
        val connecting: String? = null,
        val failure: ConnectFailure? = null,
    ) : RadioScanState

    /** Nearby devices refused; Allow asks again. */
    data object NearbyDenied : RadioScanState

    /** Bluetooth is off; Turn on asks Android to turn it on. */
    data object BluetoothOff : RadioScanState

    /** This phone has no usable Bluetooth adapter: said, never a crash. */
    data object BluetoothUnavailable : RadioScanState

    /** A radio is attached: onboarding ends. */
    data object Connected : RadioScanState
}

/**
 * Where Connect a radio finds radios. Phase 2's Bluetooth search
 * implements it; in Phase 1 a fake does, reached from the Developer
 * section and the UI tests (D6).
 */
interface RadioScanSource {
    val state: StateFlow<RadioScanState>

    /** Start looking: the page is shown. */
    fun start()

    /** Stop looking: the page is gone. */
    fun stop()

    fun connect(radio: FoundRadio)

    /** Ask for Nearby devices again. */
    fun allow()

    /** Ask Android to turn Bluetooth on. */
    fun turnOn()
}
