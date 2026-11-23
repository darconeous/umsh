package com.voria.umsh.features.onboarding

import android.app.Activity
import android.content.IntentSender
import androidx.activity.result.ActivityResult
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.emptyFlow

/** A radio in pairing mode, as it advertises itself. */
data class FoundRadio(
    val id: String,
    /** The name the radio advertises; null until its scan response is heard. */
    val name: String?,
    /** The model identifier it advertises (`boards.json`); null when it gives none. */
    val modelId: Int?,
)

/** Something only the page can do for the search: Android's own dialogs. */
sealed interface ScanRequest {
    /** Ask for Nearby devices (or open the app's settings once Android stops asking). */
    data object AskNearbyDevices : ScanRequest

    /** Ask Android to turn Bluetooth on. */
    data object TurnOnBluetooth : ScanRequest

    /**
     * Show Android's confirmation that the app may manage the radio
     * (CompanionDeviceManager); its result goes back through
     * [RadioScanSource.confirmed].
     */
    data class ConfirmRadio(val sender: IntentSender) : ScanRequest
}

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
 * Where Connect a radio finds radios: the Bluetooth search
 * (`BleRadioScanSource`), or a fake reached from the Developer section and
 * the UI tests (D6).
 */
interface RadioScanSource {
    val state: StateFlow<RadioScanState>

    /** Dialogs the page should raise for the search; none for a search that needs none. */
    val requests: Flow<ScanRequest> get() = emptyFlow()

    /** Start looking: the page is shown. */
    fun start()

    /** Stop looking: the page is gone. */
    fun stop()

    fun connect(radio: FoundRadio)

    /** Ask for Nearby devices again. */
    fun allow()

    /** Ask Android to turn Bluetooth on. */
    fun turnOn()

    /** How the confirmation [ScanRequest.ConfirmRadio] raised ended; null when the page could not show it. */
    fun confirmed(result: ActivityResult?) = Unit

    /** The page's activity while the page is shown, and null as it goes. */
    fun showing(activity: Activity?) = Unit
}
