package com.voria.umsh.services.radio

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.ParcelUuid
import com.voria.umsh.services.mobilecore.AppLog

/**
 * What a radio's advertising says (`ulcp-ble.md` §Advertising), read from
 * the primary packet and the scan response together.
 */
data class RadioAdvertisement(
    /** General discoverability: the flags of a radio in its pairing window. */
    val discoverable: Boolean,
    /** The model identifier (`boards.json`), from manufacturer data `0xFFFF`; null when absent or unassigned. */
    val modelId: Int?,
    /** The advertised name, from the scan response; null until it arrives. */
    val name: String?,
    val hasService: Boolean,
) {
    /**
     * In its pairing window: keyed on the primary packet, which the spec
     * makes carry the general-discoverable flag and the model element then,
     * so a scan response that arrives late changes only the name.
     */
    val pairing: Boolean get() = hasService && (discoverable || modelId != null)

    companion object {
        private const val TYPE_FLAGS = 0x01
        private const val TYPE_UUID128_INCOMPLETE = 0x06
        private const val TYPE_UUID128_COMPLETE = 0x07
        private const val TYPE_NAME_SHORT = 0x08
        private const val TYPE_NAME_COMPLETE = 0x09
        private const val TYPE_MANUFACTURER = 0xFF
        private const val FLAG_GENERAL_DISCOVERABLE = 0x02
        private const val COMPANY_ID = 0xFFFF

        /** The ULCP service UUID as advertised: little-endian. */
        private val serviceLe: ByteArray = run {
            val uuid = RadioGatt.service
            val bytes = ByteArray(16)
            for (i in 0 until 8) bytes[15 - i] = (uuid.mostSignificantBits ushr (56 - 8 * i)).toByte()
            for (i in 0 until 8) bytes[7 - i] = (uuid.leastSignificantBits ushr (56 - 8 * i)).toByte()
            bytes
        }

        /**
         * Parse advertising data (AD structures, as `ScanRecord.getBytes()`
         * returns them). Malformed structures end the parse; what came
         * before them stands.
         */
        fun parse(bytes: ByteArray): RadioAdvertisement {
            var discoverable = false
            var modelId: Int? = null
            var name: String? = null
            var complete = false
            var hasService = false
            var at = 0
            while (at < bytes.size) {
                val length = bytes[at].toInt() and 0xFF
                if (length == 0 || at + 1 + length > bytes.size) break
                val type = bytes[at + 1].toInt() and 0xFF
                val data = bytes.copyOfRange(at + 2, at + 1 + length)
                when (type) {
                    TYPE_FLAGS -> if (data.isNotEmpty()) discoverable = data[0].toInt() and FLAG_GENERAL_DISCOVERABLE != 0
                    TYPE_UUID128_COMPLETE, TYPE_UUID128_INCOMPLETE ->
                        if (data.toList().chunked(16).any { it.toByteArray().contentEquals(serviceLe) }) hasService = true
                    TYPE_MANUFACTURER -> if (data.size >= 4) {
                        val company = (data[0].toInt() and 0xFF) or ((data[1].toInt() and 0xFF) shl 8)
                        if (company == COMPANY_ID) {
                            val model = ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
                            modelId = model.takeIf { it != 0 }
                        }
                    }
                    TYPE_NAME_COMPLETE, TYPE_NAME_SHORT -> if (!complete || type == TYPE_NAME_COMPLETE) {
                        name = data.decodeToString().takeIf { it.isNotBlank() }
                        complete = type == TYPE_NAME_COMPLETE
                    }
                }
                at += 1 + length
            }
            return RadioAdvertisement(discoverable, modelId, name, hasService)
        }
    }
}

/**
 * One radio heard: its own device (kept for the connection, §7.1), the
 * address the scan reported it at, and what it advertised.
 */
class HeardRadio(val device: BluetoothDevice, val address: String, val advertisement: RadioAdvertisement)

/**
 * A Bluetooth scan for the ULCP service, while Connect a radio or Choose a
 * radio is open: the service UUID filtered by the controller, low latency,
 * every advertisement reported (so a radio that stops is noticed).
 */
@SuppressLint("MissingPermission")
class BleScanner(context: Context) : RadioScanner {
    private val manager: BluetoothManager? = context.getSystemService(BluetoothManager::class.java)
    @Volatile private var callback: ScanCallback? = null

    /** Start, reporting each radio heard to [onHeard] (binder thread). False when no scan could start. */
    override fun start(onHeard: (HeardRadio) -> Unit, onFailed: (Int) -> Unit): Boolean {
        stop()
        val scanner = manager?.adapter?.bluetoothLeScanner ?: return false
        val callback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) = report(result)

            override fun onBatchScanResults(results: MutableList<ScanResult>) = results.forEach(::report)

            override fun onScanFailed(errorCode: Int) {
                AppLog.w(TAG, "ble scan failed: $errorCode")
                // Nothing to stop: a failed scan was never registered.
                if (this@BleScanner.callback === this) this@BleScanner.callback = null
                onFailed(errorCode)
            }

            private fun report(result: ScanResult) {
                val bytes = result.scanRecord?.bytes ?: return
                onHeard(HeardRadio(result.device, result.device.address, RadioAdvertisement.parse(bytes)))
            }
        }
        val filter = ScanFilter.Builder().setServiceUuid(ParcelUuid(RadioGatt.service)).build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .build()
        return try {
            scanner.startScan(listOf(filter), settings, callback)
            this.callback = callback
            AppLog.i(TAG, "ble scan started")
            true
        } catch (error: SecurityException) {
            AppLog.w(TAG, "ble scan not started: ${error.javaClass.simpleName}")
            false
        }
    }

    override fun stop() {
        val callback = callback ?: return
        this.callback = null
        try {
            manager?.adapter?.bluetoothLeScanner?.stopScan(callback)
        } catch (error: SecurityException) {
            AppLog.w(TAG, "ble scan not stopped: ${error.javaClass.simpleName}")
        } catch (error: IllegalStateException) {
            // Bluetooth went off under the scan: it ended with it.
        }
        AppLog.i(TAG, "ble scan stopped")
    }

    private companion object {
        const val TAG = "umsh.radio"
    }
}
