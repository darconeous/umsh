package com.voria.umsh.services.radio

import android.app.Activity
import android.companion.CompanionDeviceManager
import android.content.IntentSender
import android.os.SystemClock
import androidx.activity.result.ActivityResult
import com.voria.umsh.features.onboarding.ConnectFailure
import com.voria.umsh.features.onboarding.FoundRadio
import com.voria.umsh.features.onboarding.RadioScanSource
import com.voria.umsh.features.onboarding.RadioScanState
import com.voria.umsh.features.onboarding.ScanRequest
import com.voria.umsh.services.mobilecore.AppLog
import java.lang.ref.WeakReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * The radios in their pairing window, as Connect a radio lists them (§3.3,
 * D16): in the order first heard, never re-sorted, each dropped once it
 * has not been heard in its pairing window for [PRUNE_MS]. Choose a radio
 * also lists the radios this phone has [associated] out of their window
 * (§2.2). Pure, so the JVM tests cover it; the times are the caller's
 * monotonic clock.
 */
class PairingRadioList {
    private class Entry(val address: String, var name: String?, var modelId: Int?, var heardAtMs: Long)

    private val entries = LinkedHashMap<String, Entry>()

    /**
     * [advertisement] heard from [address], a radio this phone has
     * [associated] or not; true when the list changed.
     */
    fun heard(address: String, advertisement: RadioAdvertisement, nowMs: Long, associated: Boolean = false): Boolean {
        // A radio out of its window (bonded elsewhere, or closed) is not
        // listed, and hearing it so does not keep an entry alive; one this
        // phone has associated needs no window to be chosen again.
        if (!advertisement.pairing && !(associated && advertisement.hasService)) return false
        val entry = entries[address]
        if (entry == null) {
            entries[address] = Entry(address, advertisement.name, advertisement.modelId, nowMs)
            return true
        }
        entry.heardAtMs = nowMs
        val name = advertisement.name ?: entry.name
        val model = advertisement.modelId ?: entry.modelId
        if (name == entry.name && model == entry.modelId) return false
        entry.name = name
        entry.modelId = model
        return true
    }

    /** Drop what has gone quiet; true when the list changed. */
    fun prune(nowMs: Long): Boolean = entries.values.removeAll { nowMs - it.heardAtMs > PRUNE_MS }

    /**
     * The scan resumes after a pause, which no entry is held to: each has
     * [RESUME_GRACE_MS] to be heard again. A radio that took a new address
     * meanwhile soon drops its old row; one still there keeps its place.
     */
    fun resumed(nowMs: Long) = entries.values.forEach {
        it.heardAtMs = maxOf(it.heardAtMs, nowMs - PRUNE_MS + RESUME_GRACE_MS)
    }

    fun clear() = entries.clear()

    val radios: List<FoundRadio> get() = entries.values.map { FoundRadio(it.address, it.name, it.modelId) }

    companion object {
        const val PRUNE_MS = 10_000L
        const val RESUME_GRACE_MS = 3_000L
    }
}

/** Starts a scan, reporting each radio heard; [BleScanner] in the app. */
interface RadioScanner {
    fun start(onHeard: (HeardRadio) -> Unit, onFailed: (Int) -> Unit): Boolean

    fun stop()
}

/** How connecting to a radio the search found ended. */
sealed interface ConnectOutcome {
    /** It carries this phone. */
    data object Connected : ConnectOutcome

    /** Android's confirmation was declined: nothing changed, and nothing is said. */
    data object Declined : ConnectOutcome

    data class Failed(val failure: ConnectFailure) : ConnectOutcome
}

/**
 * The page a radio is being connected from: where Android's confirmation
 * is raised, and the activity CompanionDeviceManager asks through on API
 * 31–32, which take a request only from an activity's.
 */
interface ConfirmationPage {
    /** CompanionDeviceManager as the page's activity has it; null while no page is shown. */
    val companionDevices: CompanionDeviceManager?

    /** Show Android's confirmation [sender] from the page; how it ended, or null when it could not be shown. */
    suspend fun confirm(sender: IntentSender): ActivityResult?
}

/** Connects to a radio the search found, confirmed through [page][ConfirmationPage]. */
fun interface ScannedRadioConnector {
    suspend fun connect(radio: HeardRadio, page: ConfirmationPage): ConnectOutcome
}

/**
 * Connect a radio over Bluetooth (§3.3), and Choose a radio (§3.4):
 * Nearby devices asked for when the page opens without it, then Bluetooth
 * turned on, then a scan for the ULCP service listing the radios in their
 * pairing window. Tapping one hands it to [connector], which raises
 * Android's confirmation through the page; the list stays, and a failure
 * says why. A declined confirmation says nothing.
 *
 * The scan pauses while a radio connects (as iOS ends discovery), so it
 * does not compete with connection setup and pairing, and nothing is
 * pruned meanwhile: a radio that stops advertising once connected keeps
 * its row. A scan Android fails is started again after a backoff.
 */
class BleRadioScanSource(
    private val bluetooth: StateFlow<BluetoothStatus>,
    private val scanner: RadioScanner,
    private val connector: ScannedRadioConnector,
    private val clock: () -> Long = SystemClock::elapsedRealtime,
    /**
     * The addresses of the radios this phone has associated (uppercase),
     * listed out of their pairing window too; none for Connect a radio.
     * Read as the search starts and after each attempt.
     */
    private val associated: () -> Set<String> = { emptySet() },
) : RadioScanSource {
    private val list = PairingRadioList()

    /** [associated] as last read. */
    private var associatedNow: Set<String> = emptySet()

    /** The device each listed radio was heard from, kept for the connection. */
    private val heard = HashMap<String, HeardRadio>()

    private val _state = MutableStateFlow(stateFor(bluetooth.value))
    override val state: StateFlow<RadioScanState> = _state.asStateFlow()

    private val _requests = Channel<ScanRequest>(Channel.BUFFERED)
    override val requests: Flow<ScanRequest> = _requests.receiveAsFlow()

    private var scope: CoroutineScope? = null
    private var scanning = false
    private var connecting: Job? = null
    private var connectingId: String? = null
    private var failure: ConnectFailure? = null

    /** Android's confirmation the page is showing, answered by [confirmed]. */
    private var confirmation: CompletableDeferred<ActivityResult?>? = null

    /** Scans Android failed in a row; reset by a radio heard. */
    private var scanFailures = 0
    private var restart: Job? = null

    /** Each dialog is raised by the search once per opening; the page's buttons raise them again. */
    private var askedNearby = false
    private var askedBluetooth = false

    /** Looking from now; once, however often the page asks (a window recreated keeps one search). */
    override fun start() {
        if (scope != null) return
        val running = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate).also { scope = it }
        askedNearby = false
        askedBluetooth = false
        // A search opened again starts over: what it heard before may be
        // gone, and the radio it connected last time is not this time's.
        list.clear()
        heard.clear()
        failure = null
        associatedNow = associated()
        _state.value = stateFor(bluetooth.value)
        running.launch { bluetooth.collect(::follow) }
        running.launch {
            while (isActive) {
                delay(PRUNE_EVERY_MS)
                if (connecting == null && list.prune(clock())) publish()
            }
        }
    }

    override fun stop() {
        stopScan()
        scope?.cancel()
        scope = null
        restart = null
        scanFailures = 0
        connecting = null
        connectingId = null
        confirmation = null
    }

    override fun connect(radio: FoundRadio) {
        val target = heard[radio.id] ?: return
        if (connecting != null) return
        val scope = scope ?: return
        AppLog.i(TAG, "connect a radio: connecting")
        failure = null
        connectingId = radio.id
        stopScan()
        publish()
        connecting = scope.launch {
            val outcome = connector.connect(target, page)
            connecting = null
            connectingId = null
            confirmation = null
            if (outcome == ConnectOutcome.Connected) {
                _state.value = RadioScanState.Connected
            } else {
                AppLog.i(TAG, "connect a radio: $outcome")
                failure = (outcome as? ConnectOutcome.Failed)?.failure
                // The attempt may have released one radio and let another go.
                associatedNow = associated()
                list.resumed(clock())
                follow(bluetooth.value)
            }
        }
    }

    /** The activity of the page shown now, held weakly: a window recreated or gone is not kept. */
    private var activity: WeakReference<Activity>? = null

    override fun showing(activity: Activity?) {
        this.activity = activity?.let(::WeakReference)
    }

    private val page = object : ConfirmationPage {
        override val companionDevices: CompanionDeviceManager?
            get() = activity?.get()?.getSystemService(CompanionDeviceManager::class.java)

        override suspend fun confirm(sender: IntentSender): ActivityResult? = this@BleRadioScanSource.confirm(sender)
    }

    /** Raise Android's confirmation through the page, and wait for how it ended. */
    private suspend fun confirm(sender: IntentSender): ActivityResult? {
        val answer = CompletableDeferred<ActivityResult?>()
        confirmation = answer
        _requests.trySend(ScanRequest.ConfirmRadio(sender))
        return answer.await()
    }

    override fun confirmed(result: ActivityResult?) {
        confirmation?.complete(result)
        confirmation = null
    }

    override fun allow() {
        _requests.trySend(ScanRequest.AskNearbyDevices)
    }

    override fun turnOn() {
        _requests.trySend(ScanRequest.TurnOnBluetooth)
    }

    private fun follow(status: BluetoothStatus) {
        when {
            status.adapter == BluetoothStatus.Adapter.Missing -> stopScan()
            !status.nearbyGranted -> {
                stopScan()
                if (!askedNearby) {
                    askedNearby = true
                    _requests.trySend(ScanRequest.AskNearbyDevices)
                }
            }
            status.adapter != BluetoothStatus.Adapter.On -> {
                stopScan()
                if (!askedBluetooth && status.adapter == BluetoothStatus.Adapter.Off) {
                    askedBluetooth = true
                    _requests.trySend(ScanRequest.TurnOnBluetooth)
                }
            }
            else -> startScan()
        }
        publish()
    }

    private fun startScan() {
        if (scanning || connecting != null || restart != null) return
        scanning = scanner.start(
            onHeard = { radio -> scope?.launch { onHeard(radio) } },
            onFailed = { code -> scope?.launch { scanFailed(code) } },
        )
        if (!scanning) scanFailed(null)
    }

    /**
     * Android failed the scan, or would not start one: started again after
     * a backoff, while the page stays open and Bluetooth stays usable.
     */
    private fun scanFailed(code: Int?) {
        val scope = scope ?: return
        scanning = false
        scanFailures += 1
        val after = if (scanFailures == 1) FIRST_RESTART_MS else RESTART_MS
        AppLog.w(TAG, "ble scan failed (${code ?: "not started"}); again in $after ms")
        restart?.cancel()
        restart = scope.launch {
            delay(after)
            restart = null
            follow(bluetooth.value)
        }
    }

    private fun stopScan() {
        if (!scanning) return
        scanning = false
        scanner.stop()
    }

    private fun onHeard(radio: HeardRadio) {
        if (!scanning) return
        scanFailures = 0
        val associated = radio.address.uppercase() in associatedNow
        if (list.heard(radio.address, radio.advertisement, clock(), associated)) {
            heard[radio.address] = radio
            publish()
        } else if (radio.advertisement.pairing || associated) {
            heard[radio.address] = radio
        }
    }

    private fun publish() {
        if (_state.value == RadioScanState.Connected) return
        val shown = stateFor(bluetooth.value)
        _state.value = if (shown is RadioScanState.Looking) {
            RadioScanState.Looking(list.radios, connecting = connectingId, failure = failure)
        } else {
            shown
        }
    }

    private fun stateFor(status: BluetoothStatus): RadioScanState = when {
        status.adapter == BluetoothStatus.Adapter.Missing -> RadioScanState.BluetoothUnavailable
        !status.nearbyGranted -> RadioScanState.NearbyDenied
        status.adapter != BluetoothStatus.Adapter.On -> RadioScanState.BluetoothOff
        else -> RadioScanState.Looking(emptyList())
    }

    private companion object {
        const val TAG = "umsh.radio"
        const val PRUNE_EVERY_MS = 1_000L
        const val FIRST_RESTART_MS = 5_000L
        const val RESTART_MS = 30_000L
    }
}
