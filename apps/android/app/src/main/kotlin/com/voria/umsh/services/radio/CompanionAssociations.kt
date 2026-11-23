package com.voria.umsh.services.radio

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.bluetooth.BluetoothDevice
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.companion.AssociationInfo
import android.companion.AssociationRequest
import android.companion.BluetoothLeDeviceFilter
import android.companion.CompanionDeviceManager
import android.companion.DeviceNotAssociatedException
import android.companion.ObservingDevicePresenceRequest
import android.content.Context
import android.content.Intent
import android.content.IntentSender
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import androidx.activity.result.ActivityResult
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import com.voria.umsh.services.background.PresenceObservations
import com.voria.umsh.services.background.RadioPresenceService
import com.voria.umsh.services.mobilecore.AppLog
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeoutOrNull

/** What asking Android to associate a radio came to (§7.1 step 2). */
sealed interface Association {
    /** Allowed: [id] is the association's (API 31–32: its MAC string), [address] the device's as CDM recorded it. */
    data class Made(val id: String, val address: String?) : Association

    /** "Don't allow", or the dialog dismissed: nothing changes. */
    data object Declined : Association

    /**
     * No device came of it: the radio was not found, or its pairing
     * window closed (and its address changed) while the dialog was open.
     */
    data object NoDevice : Association

    /** Android refused for its own reasons; logged, never shown. */
    data object Failed : Association
}

/** The radios this phone has associated, and asking for another: [CompanionAssociations] in the app. */
interface RadioAssociations : RadioBindings {
    /** This phone associates radios at all; without, radios connect with none. */
    val available: Boolean

    /** The association the radio heard at [address] already has; null when it has none. */
    fun associationFor(address: String): String?

    /**
     * Ask Android to associate the radio heard at [device], through its
     * own confirmation, which [confirm] raises from the page and answers
     * with its result (null when the page could not show it).
     */
    suspend fun associate(device: BluetoothDevice, page: ConfirmationPage): Association
}

/**
 * The radios this app is associated with through CompanionDeviceManager,
 * and asking for a new one (§7.1, §3.4): one radio at a time, by the
 * address its scan reported, single-device, no device profile. The
 * association is what lets Android wake the app when the radio comes
 * back, keeps an associated app on the device-idle allowlist, and lets it
 * start its foreground service from the background.
 *
 * API 33+ uses `associate(request, executor, callback)` and
 * `getMyAssociations()`, keyed by association ID; API 31–32 the older
 * `associate(request, callback, handler)` and `getAssociations()`, keyed
 * by MAC string. Without `FEATURE_COMPANION_DEVICE_SETUP` nothing here
 * does anything, and radios connect without an association.
 */
class CompanionAssociations(context: Context) : RadioAssociations, PresenceObservations {
    private val context = context.applicationContext

    private val manager: CompanionDeviceManager? =
        if (this.context.packageManager.hasSystemFeature(PackageManager.FEATURE_COMPANION_DEVICE_SETUP)) {
            this.context.getSystemService(CompanionDeviceManager::class.java)
        } else {
            null
        }

    override val available: Boolean get() = manager != null

    /**
     * The radios associated now: each one's address (uppercase, as
     * Android's Bluetooth reports it) and its association. Empty when
     * CompanionDeviceManager cannot be asked.
     */
    fun inventory(): Map<String, String> {
        val manager = manager ?: return emptyMap()
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                manager.myAssociations.mapNotNull { info ->
                    info.deviceMacAddress?.toString()?.uppercase()?.let { it to info.id.toString() }
                }.toMap()
            } else {
                @Suppress("DEPRECATION")
                manager.associations.associate { it.uppercase() to it }
            }
        } catch (error: RuntimeException) {
            AppLog.w(TAG, "associations unread: ${error.javaClass.simpleName}")
            emptyMap()
        }
    }

    override fun associationFor(address: String): String? = inventory()[address.uppercase()]

    override fun associationIds(): Collection<String> = inventory().values

    override fun observe(associationId: String, observe: Boolean) = observePresence(associationId, observe)

    /** Android's own confirmation (`radio-pairing.svg` 3), single-device, filtered to the address heard. */
    override suspend fun associate(device: BluetoothDevice, page: ConfirmationPage): Association {
        // API 31–32 take a request only through an activity's manager (theirs
        // casts its context to one); later APIs take the application's.
        val manager = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            manager
        } else {
            manager?.let { page.companionDevices }
        } ?: return Association.Failed.also { AppLog.w(TAG, "association not asked: no page to ask from") }
        val events = Channel<Event>(Channel.UNLIMITED)
        // Set once this ask has ended: an association Android makes after
        // that (the page left with the confirmation answered) is undone as
        // it arrives.
        val abandoned = AtomicBoolean(false)
        val callback = object : CompanionDeviceManager.Callback() {
            @Deprecated("API 31–32 form")
            override fun onDeviceFound(intentSender: IntentSender) {
                events.trySend(Event.Pending(intentSender))
            }

            override fun onAssociationPending(intentSender: IntentSender) {
                events.trySend(Event.Pending(intentSender))
            }

            // Called from API 33 on, where AssociationInfo exists.
            @RequiresApi(Build.VERSION_CODES.TIRAMISU)
            override fun onAssociationCreated(associationInfo: AssociationInfo) {
                if (abandoned.get()) {
                    AppLog.i(TAG, "association made after its ask ended; removing it")
                    release(associationInfo.id.toString())
                    return
                }
                events.trySend(Event.Created(associationInfo.id.toString(), associationInfo.deviceMacAddress?.toString()))
            }

            override fun onFailure(error: CharSequence?) {
                events.trySend(Event.Failure(error?.toString()))
            }
        }
        val request = request(device)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                manager.associate(request, MainExecutor, callback)
            } else {
                @Suppress("DEPRECATION")
                manager.associate(request, callback, Handler(Looper.getMainLooper()))
            }
        } catch (error: RuntimeException) {
            AppLog.w(TAG, "association not asked: ${error.javaClass.simpleName}")
            return Association.Failed
        }
        var ended = false
        try {
            return asked(device, page, events).also { made ->
                ended = true
                if (made !is Association.Made) abandoned.set(true)
            }
        } finally {
            if (!ended) {
                // Called off (the page left) before an answer: whatever
                // association this ask made already goes now, and one made
                // later goes as it arrives. The radio was not associated
                // before (the connector asks only then).
                abandoned.set(true)
                val made = generateSequence { events.tryReceive().getOrNull() }
                    .filterIsInstance<Event.Created>().map { it.id }.toSet() + listOfNotNull(associationFor(device.address))
                if (made.isNotEmpty()) AppLog.i(TAG, "association ask called off; removing what it made")
                made.forEach(::release)
            }
        }
    }

    /** The events of one ask, up to how it ended. */
    private suspend fun asked(device: BluetoothDevice, page: ConfirmationPage, events: Channel<Event>): Association {
        var created: Event.Created? = null
        // Discovery ends with a dialog or a failure; one that does neither
        // is given up on, as a radio not found.
        val first = withTimeoutOrNull(DISCOVERY_WAIT_MS) {
            var next = events.receive()
            while (next is Event.Created) {
                created = next
                next = events.receive()
            }
            next
        }
        val event = when (first) {
            null -> {
                AppLog.w(TAG, "association: no dialog or failure in ${DISCOVERY_WAIT_MS / 1000} s")
                return Association.NoDevice
            }
            is Event.Failure -> {
                // Before any dialog: discovery found nothing, or CDM refused.
                AppLog.w(TAG, "association failed before its dialog: ${first.reason}")
                return AssociationResults.beforeDialog(first.reason)
            }
            is Event.Pending -> first
            is Event.Created -> error("unreachable")
        }
        val result = page.confirm(event.sender)
        if (result == null) {
            AppLog.w(TAG, "association dialog not shown")
            return Association.Failed
        }
        return finish(result, created, events)
    }

    private suspend fun finish(result: ActivityResult, created: Event.Created?, events: Channel<Event>): Association {
        val data = result.data
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            @Suppress("DEPRECATION") // The API 31–32 form: the device CDM found, as its scan result.
            val scanned = data?.let { IntentCompat.getParcelableExtra(it, CompanionDeviceManager.EXTRA_DEVICE, ScanResult::class.java) }
            val address = scanned?.device?.address
            return when (ending(result.resultCode, address != null, events)) {
                // API 31–32 key an association by its MAC string.
                AssociationResults.Ending.Made -> Association.Made(address!!, address)
                AssociationResults.Ending.NoDevice -> Association.NoDevice
                AssociationResults.Ending.Declined -> Association.Declined
                AssociationResults.Ending.Failed -> Association.Failed
            }
        }
        var made = created ?: data?.let(::associationIn)
        if (result.resultCode == Activity.RESULT_OK && made == null) {
            // The result and the callback race; the callback follows shortly.
            made = withTimeoutOrNull(CREATED_WAIT_MS) {
                var found: Event.Created? = null
                while (found == null) found = events.receive() as? Event.Created
                found
            }
        }
        return when (ending(result.resultCode, made != null, events)) {
            AssociationResults.Ending.Made -> Association.Made(made!!.id, made.address?.uppercase())
            AssociationResults.Ending.NoDevice -> Association.NoDevice
            AssociationResults.Ending.Declined -> Association.Declined
            AssociationResults.Ending.Failed -> Association.Failed
        }
    }

    private suspend fun ending(resultCode: Int, hasDevice: Boolean, events: Channel<Event>): AssociationResults.Ending {
        val reason = if (resultCode == Activity.RESULT_OK) null else failureAlongside(events)
        val ending = AssociationResults.classify(resultCode, hasDevice, reason)
        AppLog.i(TAG, "association dialog: result $resultCode, ${if (hasDevice) "a device" else "no device"}, ${reason ?: "no failure"} → $ending")
        return ending
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun associationIn(data: Intent): Event.Created? =
        IntentCompat.getParcelableExtra(data, CompanionDeviceManager.EXTRA_ASSOCIATION, AssociationInfo::class.java)
            ?.let { Event.Created(it.id.toString(), it.deviceMacAddress?.toString()) }

    /** What CDM's callback said as a dialog ended without an association, if it said anything soon. */
    private suspend fun failureAlongside(events: Channel<Event>): String? = withTimeoutOrNull(FAILURE_WAIT_MS) {
        var reason: String? = null
        while (reason == null) {
            val failure = events.receive() as? Event.Failure ?: continue
            reason = failure.reason.orEmpty()
        }
        reason
    }?.takeIf { it.isNotEmpty() }

    /** Forget's order (D18): the bond (API 36+) while the association still names it, then the association. */
    override fun release(associationId: String) {
        removeBond(associationId)
        disassociate(associationId)
    }

    /**
     * Forget the association: the app no longer manages the radio, and
     * Android no longer wakes the app for it. [id] as [Association.Made]
     * gave it.
     */
    fun disassociate(id: String) {
        val manager = manager ?: return
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                val number = numbered(manager, id) ?: return AppLog.w(TAG, "association not found")
                manager.disassociate(number)
            } else {
                @Suppress("DEPRECATION")
                manager.disassociate(id)
            }
            AppLog.i(TAG, "association removed")
        } catch (error: RuntimeException) {
            AppLog.w(TAG, "association not removed: ${error.javaClass.simpleName}")
        }
    }

    /**
     * API 36+: remove the system's bond with the associated radio (D18).
     * Its result arrives as `ACTION_BOND_STATE_CHANGED`, which is logged,
     * not waited for. Below 36 the bond stays: no public call removes it.
     */
    @SuppressLint("MissingPermission")
    fun removeBond(id: String) {
        val manager = manager ?: return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA) {
            AppLog.i(TAG, "bond kept (API ${Build.VERSION.SDK_INT})")
            return
        }
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
            AppLog.w(TAG, "bond kept: Nearby devices not granted")
            return
        }
        try {
            val number = numbered(manager, id) ?: return AppLog.w(TAG, "bond kept: association not found")
            AppLog.i(TAG, "bond removal ${if (manager.removeBond(number)) "asked" else "refused"}")
        } catch (error: RuntimeException) {
            AppLog.w(TAG, "bond not removed: ${error.javaClass.simpleName}")
        }
    }

    /**
     * Ask Android to tell the app when the associated radio [id] appears
     * and disappears ([observe]), or to stop (§7.3, D6): on API 36 by
     * association ID (`ObservingDevicePresenceRequest`), before that by the
     * address the association recorded (API 31–32: [id] is that address).
     * What Android says is [RadioPresenceService]'s to hear. Asking again
     * changes nothing; a refusal is logged and dropped.
     */
    @SuppressLint("MissingPermission")
    fun observePresence(id: String, observe: Boolean) {
        val manager = manager ?: return
        val verb = if (observe) "observing" else "not observing"
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA) {
                val number = numbered(manager, id) ?: return AppLog.w(TAG, "presence: association not found")
                val request = ObservingDevicePresenceRequest.Builder().setAssociationId(number).build()
                if (observe) manager.startObservingDevicePresence(request) else manager.stopObservingDevicePresence(request)
            } else {
                val address = addressOf(manager, id) ?: return AppLog.w(TAG, "presence: association not found")
                @Suppress("DEPRECATION")
                if (observe) manager.startObservingDevicePresence(address) else manager.stopObservingDevicePresence(address)
            }
            AppLog.i(TAG, "presence: $verb association $id")
        } catch (error: DeviceNotAssociatedException) {
            AppLog.w(TAG, "presence: $verb refused, not associated")
        } catch (error: RuntimeException) {
            AppLog.w(TAG, "presence: $verb refused: ${error.javaClass.simpleName}")
        }
    }

    /** The address association [id] recorded; on API 31–32 the ID is that address. */
    private fun addressOf(manager: CompanionDeviceManager, id: String): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return id
        val number = numbered(manager, id) ?: return null
        return manager.myAssociations.firstOrNull { it.id == number }?.deviceMacAddress?.toString()?.uppercase()
    }

    /**
     * Whether a presence event names [radio]'s association: by ID (API 33+)
     * or by address (API 31–32, and IDs recorded there before an upgrade).
     */
    fun names(radio: BoundRadio, associationId: Int?, address: String?): Boolean {
        val recorded = radio.associationId ?: return false
        if (associationId != null) {
            if (recorded.toIntOrNull() == associationId) return true
            val manager = manager ?: return false
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                return try {
                    numbered(manager, recorded) == associationId
                } catch (_: RuntimeException) {
                    false
                }
            }
            return false
        }
        return address != null && (address.equals(recorded, ignoreCase = true) || address.equals(radio.linkId, ignoreCase = true))
    }

    /**
     * API 33+: the association [id] names. An ID recorded on API 31–32 is
     * the radio's MAC string, and after an upgrade it is found by that.
     */
    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun numbered(manager: CompanionDeviceManager, id: String): Int? = id.toIntOrNull()
        ?: manager.myAssociations.firstOrNull { it.deviceMacAddress?.toString().equals(id, ignoreCase = true) }?.id

    /** One radio, by the address its scan reported and the ULCP service, single-device. */
    private fun request(device: BluetoothDevice): AssociationRequest {
        val scan = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(RadioGatt.service))
            .setDeviceAddress(device.address)
            .build()
        return AssociationRequest.Builder()
            .addDeviceFilter(BluetoothLeDeviceFilter.Builder().setScanFilter(scan).build())
            .setSingleDevice(true)
            .build()
    }

    private sealed interface Event {
        data class Pending(val sender: IntentSender) : Event

        data class Created(val id: String, val address: String?) : Event

        data class Failure(val reason: String?) : Event
    }

    private object MainExecutor : Executor {
        private val handler = Handler(Looper.getMainLooper())

        override fun execute(command: Runnable) {
            handler.post(command)
        }
    }

    private companion object {
        const val TAG = "umsh.radio"
        const val CREATED_WAIT_MS = 5_000L

        /** Longer than CDM's own discovery (about 20 s), which ends in a dialog or a failure. */
        const val DISCOVERY_WAIT_MS = 30_000L
        const val FAILURE_WAIT_MS = 1_000L
    }
}

/**
 * How a CompanionDeviceManager dialog ended, read from what Android gave
 * back. Pure, for the JVM tests. Failure reasons are CDM's internal words,
 * read only to tell a lapsed search from a refusal; never shown.
 */
object AssociationResults {
    /** API 35+: `CompanionDeviceManager.RESULT_DISCOVERY_TIMEOUT`. */
    const val RESULT_DISCOVERY_TIMEOUT = 2

    /** API 35+: `CompanionDeviceManager.RESULT_USER_REJECTED`. */
    const val RESULT_USER_REJECTED = 1

    /** API 35+: `CompanionDeviceManager.RESULT_INTERNAL_ERROR`. */
    const val RESULT_INTERNAL_ERROR = 3

    /** API 35+: `CompanionDeviceManager.RESULT_SECURITY_ERROR`. */
    const val RESULT_SECURITY_ERROR = 4

    private const val RESULT_OK = -1
    private const val RESULT_CANCELED = 0

    /** How a dialog ended. */
    enum class Ending { Made, NoDevice, Declined, Failed }

    /**
     * The dialog's [resultCode]; [hasDevice]: an association (or, API
     * 31–32, a device) came back with it; [failureReason]: what CDM's
     * callback said alongside, if anything.
     */
    fun classify(resultCode: Int, hasDevice: Boolean, failureReason: String? = null): Ending = when {
        resultCode == RESULT_OK && hasDevice -> Ending.Made
        // Allowed, but nothing to associate: the radio went from under the dialog.
        resultCode == RESULT_OK -> Ending.NoDevice
        resultCode == RESULT_DISCOVERY_TIMEOUT -> Ending.NoDevice
        resultCode == RESULT_INTERNAL_ERROR || resultCode == RESULT_SECURITY_ERROR -> Ending.Failed
        failureReason?.let(::lapsed) == true -> Ending.NoDevice
        resultCode == RESULT_CANCELED || resultCode == RESULT_USER_REJECTED -> Ending.Declined
        else -> Ending.Failed
    }

    /** CDM's words for a search that ran out of time: "discovery_timeout", "Timed out". */
    private fun lapsed(reason: String): Boolean =
        reason.replace(" ", "").replace("_", "").let { it.contains("timeout", ignoreCase = true) || it.contains("timedout", ignoreCase = true) }

    /** A failure with no dialog shown: a search that found nothing reads as no device. */
    fun beforeDialog(reason: String?): Association = when {
        reason == null -> Association.NoDevice
        lapsed(reason) || reason.contains("not found", ignoreCase = true) -> Association.NoDevice
        reason.contains("cancel", ignoreCase = true) -> Association.Declined
        else -> Association.Failed
    }
}
