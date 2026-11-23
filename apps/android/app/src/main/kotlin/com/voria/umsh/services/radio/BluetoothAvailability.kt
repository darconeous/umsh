package com.voria.umsh.services.radio

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import com.voria.umsh.core.MobileRadioProblem
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.permissions.NearbyDevicesPermission
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** The phone's own Bluetooth, as a Bluetooth radio link needs it. */
data class BluetoothStatus(val adapter: Adapter, val nearbyGranted: Boolean) {
    enum class Adapter { On, Off, TurningOn, TurningOff, Missing }

    /** A link can run: Bluetooth on and Nearby devices granted. */
    val usable: Boolean get() = adapter == Adapter.On && nearbyGranted

    /** Why a link cannot run now, as the problem it reports; null when it can. */
    val problem: MobileRadioProblem?
        get() = when {
            adapter == Adapter.Missing -> RadioTransportProblem.BluetoothUnsupported.problem
            !nearbyGranted -> RadioTransportProblem.BluetoothUnauthorized.problem
            adapter == Adapter.TurningOn -> RadioTransportProblem.BluetoothStarting.problem
            adapter != Adapter.On -> RadioTransportProblem.BluetoothOff.problem
            else -> null
        }

    companion object {
        /** The JVM tests' phone, and the default where nothing reads one. */
        val Ready = BluetoothStatus(Adapter.On, nearbyGranted = true)
    }
}

/**
 * Whether Bluetooth is on and Nearby devices granted, kept current while
 * the process lives: the adapter's state broadcast (receivable without a
 * permission), and the grant read again whenever [refresh] is called (each
 * time the app comes to the front, and after a request is answered).
 *
 * A manifest receiver for the adapter's state is not possible, so a frozen
 * or killed process learns of a change only when it runs again (§7.2).
 */
class BluetoothAvailability(context: Context) {
    private val context = context.applicationContext
    private val manager: BluetoothManager? = this.context.getSystemService(BluetoothManager::class.java)

    private val _status = MutableStateFlow(read())
    val status: StateFlow<BluetoothStatus> = _status.asStateFlow()

    init {
        ContextCompat.registerReceiver(
            this.context,
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    refresh()
                }
            },
            IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    /** Read both again; a change is published. */
    fun refresh() {
        val now = read()
        val before = _status.value
        if (now != before) AppLog.i(TAG, "bluetooth: ${now.adapter}, nearby devices ${if (now.nearbyGranted) "granted" else "not granted"}")
        _status.value = now
    }

    private fun read(): BluetoothStatus {
        val granted = NearbyDevicesPermission.granted(context)
        val adapter = manager?.adapter ?: return BluetoothStatus(BluetoothStatus.Adapter.Missing, granted)
        val state = when (adapter.state) {
            BluetoothAdapter.STATE_ON -> BluetoothStatus.Adapter.On
            BluetoothAdapter.STATE_TURNING_ON -> BluetoothStatus.Adapter.TurningOn
            BluetoothAdapter.STATE_TURNING_OFF -> BluetoothStatus.Adapter.TurningOff
            BluetoothAdapter.STATE_OFF -> BluetoothStatus.Adapter.Off
            else -> BluetoothStatus.Adapter.Off
        }
        return BluetoothStatus(state, granted)
    }

    private companion object {
        const val TAG = "umsh.radio"
    }
}
