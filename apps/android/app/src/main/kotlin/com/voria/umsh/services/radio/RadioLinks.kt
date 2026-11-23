package com.voria.umsh.services.radio

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.content.Context
import android.os.SystemClock
import com.voria.umsh.services.background.ReconnectStrategy
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map

/** The links this build can reach a bound radio over. */
class RadioLinks(
    context: Context,
    private val bluetooth: BluetoothAvailability,
    private val associations: CompanionAssociations,
    /** The Developer switch's choice of what follows the reconnect window; Presence otherwise. */
    private val preferredStrategy: StateFlow<ReconnectStrategy>,
) : RadioLinkFactory {
    private val context = context.applicationContext

    override fun make(radio: BoundRadio, registry: RadioRegistry, events: RadioConnectionEvents): RadioConnection? =
        when (radio.kind) {
            RadioKind.Ble -> {
                // The scan's own device when the radio was just found, which the
                // stack knows is LE (§7.1); the bonded address otherwise.
                var device: BluetoothDevice? = ScannedDevices.take(radio.linkId)
                BleRadioConnection(
                    radio,
                    registry,
                    events,
                    bluetooth.status,
                    ports = { linkId ->
                        val target = device ?: remoteDevice(linkId)?.also { device = it }
                        target?.let { AndroidGattPort.factory(context, it) }
                    },
                    // Only a radio Connect a radio just found is bonded here.
                    pairing = device != null,
                    bindings = associations,
                    strategy = preferredStrategy.map { ReconnectStrategy.effective(it, associations.available, radio) },
                    clock = SystemClock::elapsedRealtime,
                )
            }
            RadioKind.Tcp -> bridgedRadioConnection(radio, registry, events)
            // The staged radio is the staging core's, never bound.
            RadioKind.Staging -> null
        }

    @SuppressLint("MissingPermission")
    private fun remoteDevice(address: String): BluetoothDevice? = try {
        context.getSystemService(BluetoothManager::class.java)?.adapter?.getRemoteDevice(address)
    } catch (_: IllegalArgumentException) {
        null
    }
}

/**
 * The devices a scan found, handed from Connect a radio to the connection
 * it is about to bind: a `BluetoothDevice` from a scan result carries what
 * the stack learned of it (LE, its address type), which one made from the
 * address alone does not.
 */
object ScannedDevices {
    private val devices = ConcurrentHashMap<String, BluetoothDevice>()

    fun offer(address: String, device: BluetoothDevice) {
        devices[address] = device
    }

    fun take(address: String): BluetoothDevice? = devices.remove(address)

    /** [device], if it is still waiting at [address]: the bind it was offered for never took it. */
    fun discard(address: String, device: BluetoothDevice) {
        devices.remove(address, device)
    }
}
