package com.voria.umsh.services.radio

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothProfile
import android.bluetooth.BluetoothStatusCodes
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import com.voria.umsh.services.mobilecore.AppLog

/**
 * [GattPort] over Android's `BluetoothGatt`, for one attachment to
 * [device] (§4.2). API 33+ uses the value-carrying callbacks and the
 * write calls' status codes; API 31–32 the deprecated forms, copying each
 * value on the binder thread before it is handed on.
 *
 * Bond results come from `ACTION_BOND_STATE_CHANGED` for this device, and
 * on API 36+ a lost bond from [BondLossEvents]; each receiver is exported,
 * since the Bluetooth process sends them. Every call needs Nearby
 * devices (`BLUETOOTH_CONNECT`), which the connection checks before it
 * opens a port; one revoked meanwhile surfaces as a refused call.
 */
@SuppressLint("MissingPermission")
class AndroidGattPort(
    context: Context,
    private val device: BluetoothDevice,
    private val listener: (GattEvent) -> Unit,
) : GattPort {
    private val context = context.applicationContext

    @Volatile
    private var gatt: BluetoothGatt? = null

    /** The handles handed out, so a CCCD or write result is matched to them. */
    @Volatile
    private var frameOut: BluetoothGattCharacteristic? = null

    @Volatile
    private var bonding = false
    private var closed = false
    private val bondLoss = BondLossEvents(this.context, device.address) { listener(GattEvent.BondLost) }

    private val bondReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val changed = IntentCompat.getParcelableExtra(intent, BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
            if (changed?.address != device.address) return
            val state = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, BluetoothDevice.BOND_NONE)
            val previous = intent.getIntExtra(BluetoothDevice.EXTRA_PREVIOUS_BOND_STATE, BluetoothDevice.BOND_NONE)
            AppLog.i(TAG, "ble: bond state $previous → $state")
            when (state) {
                // Bonded, and pairing again unasked: the radio refused this
                // phone's keys (on API 31–35, Android's own re-pairing after
                // a protected write is how a radio that lost them shows).
                BluetoothDevice.BOND_BONDING -> if (!bonding && previous == BluetoothDevice.BOND_BONDED) {
                    listener(GattEvent.BondLost)
                }
                BluetoothDevice.BOND_BONDED -> if (bonding) {
                    bonding = false
                    listener(GattEvent.Bonded)
                }
                BluetoothDevice.BOND_NONE -> if (bonding) {
                    bonding = false
                    listener(GattEvent.BondFailed)
                }
            }
        }
    }

    private val encryptionReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val changed = IntentCompat.getParcelableExtra(intent, BluetoothDevice.EXTRA_DEVICE, BluetoothDevice::class.java)
            if (changed?.address == device.address) AppLog.i(TAG, "ble: encryption changed")
        }
    }

    init {
        // Exported: the Bluetooth process (not system_server) sends these,
        // and a receiver that is not exported never hears it. They are
        // protected broadcasts, so no app can send one.
        ContextCompat.registerReceiver(
            this.context,
            bondReceiver,
            IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED),
            ContextCompat.RECEIVER_EXPORTED,
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA) {
            ContextCompat.registerReceiver(
                this.context,
                encryptionReceiver,
                IntentFilter(BluetoothDevice.ACTION_ENCRYPTION_CHANGE),
                ContextCompat.RECEIVER_EXPORTED,
            )
        }
        bondLoss.start()
    }

    override val bonded: Boolean get() = device.bondState == BluetoothDevice.BOND_BONDED

    private val callback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> listener(GattEvent.Connected)
                BluetoothProfile.STATE_DISCONNECTED -> listener(GattEvent.Disconnected(status))
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            listener(GattEvent.MtuChanged(mtu, status))
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            listener(GattEvent.ServicesDiscovered(status, if (status == BluetoothGatt.GATT_SUCCESS) lookup(gatt) else ServiceLookup.Missing))
        }

        override fun onServiceChanged(gatt: BluetoothGatt) {
            listener(GattEvent.ServiceChanged)
        }

        override fun onDescriptorWrite(gatt: BluetoothGatt, descriptor: BluetoothGattDescriptor, status: Int) {
            if (descriptor.characteristic === frameOut) listener(GattEvent.DescriptorWritten(status))
        }

        override fun onCharacteristicWrite(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic, status: Int) {
            if (characteristic.uuid == RadioGatt.frameIn) listener(GattEvent.Written(status))
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
        ) {
            if (characteristic.uuid == RadioGatt.frameOut) listener(GattEvent.Notified(value.copyOf()))
        }

        @Deprecated("API 31–32 deliver notifications here")
        override fun onCharacteristicChanged(gatt: BluetoothGatt, characteristic: BluetoothGattCharacteristic) {
            @Suppress("DEPRECATION")
            val value = characteristic.value ?: ByteArray(0)
            if (characteristic.uuid == RadioGatt.frameOut) listener(GattEvent.Notified(value.copyOf()))
        }
    }

    override fun connect(autoConnect: Boolean) {
        gatt = device.connectGatt(context, autoConnect, callback, BluetoothDevice.TRANSPORT_LE)
        if (gatt == null) listener(GattEvent.Disconnected(RadioGatt.GATT_FAILURE))
    }

    override fun disconnect() {
        gatt?.disconnect()
    }

    override fun close() {
        if (closed) return
        closed = true
        gatt?.close()
        gatt = null
        runCatching { context.unregisterReceiver(bondReceiver) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA) runCatching { context.unregisterReceiver(encryptionReceiver) }
        bondLoss.stop()
    }

    override fun createBond() {
        when (device.bondState) {
            BluetoothDevice.BOND_BONDED -> listener(GattEvent.Bonded)
            // Already under way (the radio asked for security on connect):
            // its result arrives as for one started here.
            BluetoothDevice.BOND_BONDING -> {
                bonding = true
                // Done between the two reads: its broadcast may have gone by.
                if (device.bondState == BluetoothDevice.BOND_BONDED) {
                    bonding = false
                    listener(GattEvent.Bonded)
                }
            }
            else -> {
                bonding = true
                // On the connected device, which the stack knows is LE (§7.1).
                if (!device.createBond()) {
                    bonding = false
                    listener(GattEvent.BondFailed)
                }
            }
        }
    }

    override fun requestMtu(mtu: Int) {
        if (gatt?.requestMtu(mtu) != true) listener(GattEvent.MtuChanged(RadioGatt.DEFAULT_MTU, RadioGatt.GATT_FAILURE))
    }

    override fun discoverServices() {
        if (gatt?.discoverServices() != true) listener(GattEvent.ServicesDiscovered(RadioGatt.GATT_FAILURE, ServiceLookup.Missing))
    }

    override fun enableNotifications(frameOut: GattHandle) {
        val characteristic = (frameOut as Handle).characteristic
        val gatt = gatt
        val descriptor = characteristic.getDescriptor(RadioGatt.cccd)
        if (gatt == null || descriptor == null || !gatt.setCharacteristicNotification(characteristic, true)) {
            listener(GattEvent.DescriptorWritten(RadioGatt.GATT_FAILURE))
            return
        }
        val value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
        val started = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            gatt.writeDescriptor(descriptor, value) == BluetoothStatusCodes.SUCCESS
        } else {
            @Suppress("DEPRECATION")
            descriptor.value = value
            @Suppress("DEPRECATION")
            gatt.writeDescriptor(descriptor)
        }
        if (!started) listener(GattEvent.DescriptorWritten(RadioGatt.GATT_FAILURE))
    }

    override fun write(frameIn: GattHandle, value: ByteArray) {
        val characteristic = (frameIn as Handle).characteristic
        val gatt = gatt ?: return listener(GattEvent.WriteRefused(-1))
        val type = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            when (val code = gatt.writeCharacteristic(characteristic, value, type)) {
                BluetoothStatusCodes.SUCCESS -> Unit
                BluetoothStatusCodes.ERROR_GATT_WRITE_REQUEST_BUSY -> listener(GattEvent.WriteBusy)
                else -> listener(GattEvent.WriteRefused(code))
            }
        } else {
            characteristic.writeType = type
            @Suppress("DEPRECATION")
            characteristic.value = value
            @Suppress("DEPRECATION")
            if (!gatt.writeCharacteristic(characteristic)) listener(GattEvent.WriteRefused(-1))
        }
    }

    private fun lookup(gatt: BluetoothGatt): ServiceLookup {
        val service = gatt.getService(RadioGatt.service) ?: return ServiceLookup.Missing
        val frameIn = service.getCharacteristic(RadioGatt.frameIn)
        val frameOut = service.getCharacteristic(RadioGatt.frameOut)
        if (frameIn == null || frameOut == null) return ServiceLookup.Incompatible
        this.frameOut = frameOut
        return ServiceLookup.Found(
            frameIn = Handle(frameIn),
            frameOut = Handle(frameOut),
            frameInWritable = frameIn.properties and BluetoothGattCharacteristic.PROPERTY_WRITE != 0,
        )
    }

    private class Handle(val characteristic: BluetoothGattCharacteristic) : GattHandle

    companion object {
        private const val TAG = "umsh.radio"

        /** Ports for [device]: one per attachment, each closed before the next opens. */
        fun factory(context: Context, device: BluetoothDevice) = GattPortFactory { listener ->
            AndroidGattPort(context, device, listener)
        }
    }
}
