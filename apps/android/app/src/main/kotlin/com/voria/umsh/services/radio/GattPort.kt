package com.voria.umsh.services.radio

import java.util.UUID

/** The ULCP GATT service (`ulcp-ble.md`; iOS `RadioGatt`). */
object RadioGatt {
    val service: UUID = UUID.fromString("21EB6B15-0001-4CCF-92E4-A079171BEC97")

    /** Host to radio: ULCP frames, GATT-segmented, written with response. */
    val frameIn: UUID = UUID.fromString("21EB6B15-0002-4CCF-92E4-A079171BEC97")

    /** Radio to host: ULCP frames as notifications. */
    val frameOut: UUID = UUID.fromString("21EB6B15-0003-4CCF-92E4-A079171BEC97")

    /** The Client Characteristic Configuration descriptor. */
    val cccd: UUID = UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    /** What a phone asks for; the radio answers with what it can hold (255 on the nRF radios). */
    const val REQUESTED_MTU = 517

    /** ATT's own minimum, which every link has before an exchange. */
    const val DEFAULT_MTU = 23

    /** `BluetoothGatt.GATT_SUCCESS`, `GATT_FAILURE`, and the security refusals, as plain values for the JVM. */
    const val GATT_SUCCESS = 0
    const val GATT_INSUFFICIENT_AUTHENTICATION = 5
    const val GATT_INSUFFICIENT_ENCRYPTION = 15
    const val GATT_FAILURE = 257

    /** The status domain a GATT status travels under to the driver. */
    const val GATT_DOMAIN = "android.bluetooth.gatt"

    /** The domain of `BluetoothStatusCodes`, a request Android refused before sending it. */
    const val STATUS_DOMAIN = "android.bluetooth.status"
}

/** A characteristic as the port hands it out: opaque to [BleRadioLink]. */
interface GattHandle

/** What service discovery found of the ULCP service. */
sealed interface ServiceLookup {
    data object Missing : ServiceLookup

    /** The service, without both its characteristics. */
    data object Incompatible : ServiceLookup

    data class Found(val frameIn: GattHandle, val frameOut: GattHandle, val frameInWritable: Boolean) : ServiceLookup
}

/** What a [GattPort] reports, from whatever thread the platform calls back on. */
sealed interface GattEvent {
    data object Connected : GattEvent

    data class Disconnected(val status: Int) : GattEvent

    data object Bonded : GattEvent

    /** The bond attempt ended without a bond: refused, cancelled, or timed out in the dialog. */
    data object BondFailed : GattEvent

    /**
     * The radio no longer has this phone's keys: `ACTION_KEY_MISSING` on API
     * 36+, and on every level a bonded radio Android starts pairing again unasked.
     */
    data object BondLost : GattEvent

    data class MtuChanged(val mtu: Int, val status: Int) : GattEvent

    data class ServicesDiscovered(val status: Int, val lookup: ServiceLookup) : GattEvent

    /** The radio's attribute database changed: every handle is stale. */
    data object ServiceChanged : GattEvent

    data class DescriptorWritten(val status: Int) : GattEvent

    data class Written(val status: Int) : GattEvent

    /** API 33+: the stack had another write in flight (`ERROR_GATT_WRITE_REQUEST_BUSY`); the write did not start. */
    data object WriteBusy : GattEvent

    /** The write was refused before it went out (a `BluetoothStatusCodes` value, or -1 where Android gives none). */
    data class WriteRefused(val code: Int) : GattEvent

    data class Notified(val value: ByteArray) : GattEvent {
        override fun equals(other: Any?) = other is Notified && value.contentEquals(other.value)

        override fun hashCode() = value.contentHashCode()
    }
}

/**
 * One attachment's GATT client, the seam under [BleRadioLink]: Android's
 * `BluetoothGatt` in the app, scripted fakes in the tests. Every call
 * returns at once; results arrive as [GattEvent]s. A call the platform
 * refuses outright is reported as its failed result, so the link sees one
 * path for both.
 *
 * The hidden `BluetoothGatt.refresh()` is never called: a changed service
 * is rediscovered ([GattEvent.ServiceChanged]).
 */
interface GattPort {
    /** The radio is bonded to this phone now. */
    val bonded: Boolean

    fun connect(autoConnect: Boolean)

    fun disconnect()

    /** Final: the client is released, and nothing more is reported. */
    fun close()

    /** On the connected device: [GattEvent.Bonded] or [GattEvent.BondFailed]. */
    fun createBond()

    fun requestMtu(mtu: Int)

    fun discoverServices()

    /** Local notifications on, then the CCCD written: [GattEvent.DescriptorWritten]. */
    fun enableNotifications(frameOut: GattHandle)

    /** With response: [GattEvent.Written], [GattEvent.WriteBusy] or [GattEvent.WriteRefused]. */
    fun write(frameIn: GattHandle, value: ByteArray)
}

/** Opens a [GattPort] for one attachment, reporting to [listener]. */
fun interface GattPortFactory {
    fun open(listener: (GattEvent) -> Unit): GattPort
}
