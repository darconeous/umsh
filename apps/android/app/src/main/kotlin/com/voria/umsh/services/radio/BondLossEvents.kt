package com.voria.umsh.services.radio

import android.bluetooth.BluetoothDevice
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import com.voria.umsh.services.mobilecore.AppLog

/**
 * API 36+: the radio at [address] no longer has this phone's keys
 * (`ACTION_KEY_MISSING`: after its factory reset, its bond store wiped, or
 * this phone evicted). Before 36 the loss shows only as the protected CCCD
 * write being refused, which [BleRadioLink] maps the same way. Nothing is
 * registered below 36.
 */
class BondLossEvents(
    private val context: Context,
    private val address: String,
    private val onLost: () -> Unit,
) {
    private var registered = false

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val device = IntentCompat.getParcelableExtra(intent, BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
            if (device?.address != address) return
            AppLog.w(TAG, "ble: keys missing for the bound radio")
            onLost()
        }
    }

    fun start() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.BAKLAVA || registered) return
        registered = true
        // Exported, as the bond receivers: the Bluetooth process sends it,
        // and it is protected, so no app can.
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter(BluetoothDevice.ACTION_KEY_MISSING),
            ContextCompat.RECEIVER_EXPORTED,
        )
    }

    fun stop() {
        if (!registered) return
        registered = false
        runCatching { context.unregisterReceiver(receiver) }
    }

    private companion object {
        const val TAG = "umsh.radio"
    }
}
