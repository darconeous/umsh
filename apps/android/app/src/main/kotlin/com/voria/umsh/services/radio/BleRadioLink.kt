package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileException
import com.voria.umsh.core.MobileGattReassembler
import com.voria.umsh.core.MobileRadioProblem
import com.voria.umsh.core.MobileRadioTransportPhase
import com.voria.umsh.core.ulcpGattSegments
import com.voria.umsh.services.mobilecore.AppLog

/**
 * One Bluetooth attachment to a companion radio, over a [GattPort]
 * (§4.2): connect, bond when asked to, MTU, discovery, notifications on,
 * then frames each way in ULCP's GATT segments. It holds no Android
 * Bluetooth class, so the JVM tests run it over fakes.
 *
 * What happens to the link afterward (reconnecting, giving up) is the
 * connection's: this reports the attachment's progress, its faults (each
 * attachment's first only reaches the driver), and its end.
 *
 * Confined to the connection's executor ([scheduler]): every port event
 * is posted there, tagged with the port it came from, and dropped once
 * that port is no longer this link's.
 */
class BleRadioLink(private val scheduler: LinkScheduler, private val sink: Sink) {
    /** What the link tells its connection; always on the executor. */
    interface Sink {
        /** Connecting, Attaching or Pairing: where the attachment stands. */
        fun phase(phase: MobileRadioTransportPhase)

        /** Notifications are on: the driver may start the session. */
        fun ready()

        fun received(frame: ByteArray)

        fun writesFailed(rawTransactionIds: List<UByte>, problem: MobileRadioProblem)

        /** The attachment cannot go on; the driver decides what follows. */
        fun fault(problem: MobileRadioProblem)

        /**
         * The bond this attachment asked for did not come about: the
         * system's dialog was declined, or went unanswered. The attachment
         * cannot go on, and trying again would raise the dialog again.
         */
        fun bondFailed()

        /** The link went down on its own, with the platform's [status]; the port is closed. */
        fun lost(status: Int)
    }

    private val lifecycle = RadioLinkLifecycle()
    private val queue = GattQueue(scheduler, ::issue, ::deadlinePassed)
    private val reassembler = MobileGattReassembler()

    private var port: GattPort? = null
    private var handles: ServiceLookup.Found? = null
    private var needsBond = false

    /** The negotiated ATT MTU; the ATT default until an exchange says otherwise. */
    var mtu: Int = RadioGatt.DEFAULT_MTU
        private set

    val phase: RadioLinkLifecycle.Phase get() = lifecycle.phase

    val isReady: Boolean get() = lifecycle.phase == RadioLinkLifecycle.Phase.Ready && handles != null

    /** The port is open: connecting, attaching or attached. */
    val isOpen: Boolean get() = port != null

    /**
     * Open an attachment over a port from [factory]. [autoConnect]: the
     * platform waits for the radio rather than trying once. [bond]: this
     * is the radio's first pairing, and it is asked to bond once connected
     * if it is not bonded yet. Otherwise a radio found unbonded has lost
     * its bond, and the attachment is refused rather than letting the
     * protected CCCD write raise a pairing dialog nobody asked for.
     */
    fun open(factory: GattPortFactory, autoConnect: Boolean, bond: Boolean) {
        close()
        lifecycle.begin()
        needsBond = bond
        mtu = RadioGatt.DEFAULT_MTU
        val opened = arrayOfNulls<GattPort>(1)
        val port = factory.open { event -> scheduler.post { if (port === opened[0]) handle(event) } }
        opened[0] = port
        this.port = port
        sink.phase(MobileRadioTransportPhase.CONNECTING)
        if (!bond && !port.bonded) {
            // Past its first pairing, a radio Android holds no bond for has
            // lost it, and a background connect could never resolve its
            // private address anyway: refused without trying.
            AppLog.w(TAG, "ble: the bound radio is no longer bonded")
            sink.fault(RadioTransportProblem.AttachmentRefused.problem)
            return
        }
        port.connect(autoConnect)
    }

    /** Down deliberately: the port is disconnected and released, and nothing more is reported. */
    fun close() {
        val port = port ?: return
        this.port = null
        lifecycle.clear()
        reset()
        port.disconnect()
        port.close()
    }

    /** Segment [frame] and queue each ATT value. */
    fun send(frame: ByteArray, rawTransactionId: UByte?) {
        val handles = handles
        if (!isReady || handles == null) {
            // A frame the driver sent as the link went: it learns of the loss from the transport.
            AppLog.d(TAG, "ble: frame dropped, link not ready")
            return
        }
        val values = try {
            // ATT_MTU − 3 octets per value, and never more than an
            // attribute value can hold; the SAR header is one of them.
            ulcpGattSegments(frame, minOf(mtu - ATT_HEADER, ATT_VALUE_MAX).toUShort())
        } catch (_: MobileException) {
            sink.fault(RadioTransportProblem.UnsendableFrame.problem)
            return
        }
        for (segment in values) queue.enqueue(GattQueue.Op.Write(handles.frameIn, segment.value, rawTransactionId))
    }

    /** A session is starting: no partial frame in either direction survives. */
    fun resetFraming() {
        reassembler.reset()
        queue.drainWrites()
    }

    private fun reset() {
        queue.clear()
        handles = null
        reassembler.reset()
    }

    private fun handle(event: GattEvent) {
        val port = port ?: return
        when (event) {
            GattEvent.Connected -> {
                if (!lifecycle.advance(RadioLinkLifecycle.Phase.Connecting, RadioLinkLifecycle.Phase.Services)) return
                AppLog.i(TAG, "ble: connected")
                sink.phase(MobileRadioTransportPhase.ATTACHING)
                if (!port.bonded) {
                    if (!needsBond) {
                        // Lost between the open and the connection.
                        AppLog.w(TAG, "ble: the bound radio is no longer bonded")
                        sink.fault(RadioTransportProblem.AttachmentRefused.problem)
                        return
                    }
                    sink.phase(MobileRadioTransportPhase.PAIRING)
                    queue.enqueue(GattQueue.Op.Bond())
                }
                queue.enqueue(GattQueue.Op.Mtu())
                queue.enqueue(GattQueue.Op.Discover())
            }
            is GattEvent.Disconnected -> {
                AppLog.i(TAG, "ble: disconnected (status ${event.status})")
                this.port = null
                lifecycle.clear()
                reset()
                port.close()
                if (event.status in KEYS_REFUSED) {
                    // The radio refused this phone's keys as the link was
                    // encrypted (API 36 then sends KEY_MISSING, after the
                    // port is gone): the bond is lost, not the link.
                    AppLog.w(TAG, "ble: the radio refused this phone's keys")
                    sink.fault(RadioTransportProblem.AttachmentRefused.problem)
                } else {
                    sink.lost(event.status)
                }
            }
            GattEvent.Bonded -> {
                val op = queue.current as? GattQueue.Op.Bond ?: return
                AppLog.i(TAG, "ble: bonded")
                sink.phase(MobileRadioTransportPhase.ATTACHING)
                queue.complete(op)
            }
            GattEvent.BondFailed -> {
                if (queue.current !is GattQueue.Op.Bond) return
                AppLog.w(TAG, "ble: bond refused")
                sink.bondFailed()
            }
            GattEvent.BondLost -> {
                AppLog.w(TAG, "ble: the radio lost this phone's keys")
                sink.fault(RadioTransportProblem.AttachmentRefused.problem)
            }
            is GattEvent.MtuChanged -> {
                val op = queue.current as? GattQueue.Op.Mtu ?: return
                // A refused exchange leaves the default, which still carries frames.
                if (event.status == RadioGatt.GATT_SUCCESS && event.mtu >= RadioGatt.DEFAULT_MTU) mtu = event.mtu
                AppLog.i(TAG, "ble: ATT MTU $mtu")
                queue.complete(op)
            }
            is GattEvent.ServicesDiscovered -> discovered(event)
            GattEvent.ServiceChanged -> serviceChanged()
            is GattEvent.DescriptorWritten -> subscribed(event.status)
            is GattEvent.Written -> written(event.status)
            GattEvent.WriteBusy -> {
                if (queue.current !is GattQueue.Op.Write) return
                queue.retryCurrent(BUSY_RETRY_MS)
            }
            is GattEvent.WriteRefused -> {
                val op = queue.current as? GattQueue.Op.Write ?: return
                // Over the handles a changed database retired: it never started, and nothing waits on it.
                if (queue.isStale(op)) return queue.complete(op)
                sink.fault(MobileRadioProblem.Transport(RadioGatt.STATUS_DOMAIN, event.code.toLong()))
            }
            is GattEvent.Notified -> notified(event.value)
        }
    }

    private fun discovered(event: GattEvent.ServicesDiscovered) {
        val op = queue.current as? GattQueue.Op.Discover ?: return
        if (lifecycle.phase != RadioLinkLifecycle.Phase.Services) return
        if (event.status != RadioGatt.GATT_SUCCESS) {
            sink.fault(gattProblem(event.status))
            return
        }
        val found = when (val lookup = event.lookup) {
            ServiceLookup.Missing -> return sink.fault(RadioTransportProblem.ServiceMissing.problem)
            ServiceLookup.Incompatible -> return sink.fault(RadioTransportProblem.ServiceIncompatible.problem)
            is ServiceLookup.Found -> lookup
        }
        if (!found.frameInWritable) {
            sink.fault(RadioTransportProblem.WriteModeUnsupported.problem)
            return
        }
        handles = found
        lifecycle.advance(RadioLinkLifecycle.Phase.Services, RadioLinkLifecycle.Phase.Characteristics)
        lifecycle.advance(RadioLinkLifecycle.Phase.Characteristics, RadioLinkLifecycle.Phase.Subscribing)
        // Leaves room for the system's pairing dialog and a passkey.
        sink.phase(MobileRadioTransportPhase.PAIRING)
        queue.complete(op)
        queue.enqueue(GattQueue.Op.Subscribe(found.frameOut))
    }

    private fun subscribed(status: Int) {
        val op = queue.current as? GattQueue.Op.Subscribe ?: return
        if (queue.isStale(op)) return queue.complete(op)
        when (status) {
            RadioGatt.GATT_SUCCESS -> {
                if (!lifecycle.advance(RadioLinkLifecycle.Phase.Subscribing, RadioLinkLifecycle.Phase.Ready)) return
                queue.complete(op)
                AppLog.i(TAG, "ble: notifications on")
                sink.ready()
            }
            // The protected CCCD refused on a bonded link: the radio has
            // lost this phone's keys (API 31–35 learn it only here).
            RadioGatt.GATT_INSUFFICIENT_AUTHENTICATION,
            RadioGatt.GATT_INSUFFICIENT_ENCRYPTION,
            -> sink.fault(RadioTransportProblem.AttachmentRefused.problem)
            else -> sink.fault(gattProblem(status))
        }
    }

    private fun written(status: Int) {
        val op = queue.current as? GattQueue.Op.Write ?: return
        // A frame over the old handles: the driver has failed it already.
        if (queue.isStale(op)) return queue.complete(op)
        if (status == RadioGatt.GATT_SUCCESS) {
            queue.complete(op)
            return
        }
        if (status in INVALIDATING) {
            sink.fault(gattProblem(status))
            return
        }
        // This write failed, and every frame queued behind it would arrive
        // without its start: they fail with it, and the link stays.
        val queued = queue.drainWrites()
        queue.complete(op)
        val ids = (listOf(op) + queued).mapNotNull { it.rawTransactionId }.distinct()
        AppLog.w(TAG, "ble: write failed (status $status), ${queued.size + 1} values dropped")
        sink.writesFailed(ids, gattProblem(status))
    }

    private fun notified(value: ByteArray) {
        if (!isReady) return
        val frame = try {
            reassembler.push(value)
        } catch (error: MobileException) {
            // BLE delivers each segment whole and in order: a frame lost in
            // reassembly means the link failed at what it is for, and the
            // session ends with it (ulcp-ble.md §Sessions; iOS does the same).
            AppLog.e(TAG, "ble: a frame from the radio was lost (${error.javaClass.simpleName}, ${value.size} B); closing")
            sink.fault(RadioTransportProblem.LinkLost.problem)
            return
        } ?: return
        sink.received(frame)
    }

    /** The radio's database changed: every handle is stale, so the attach starts over at discovery. */
    private fun serviceChanged() {
        if (!lifecycle.acceptsGatt || lifecycle.phase == RadioLinkLifecycle.Phase.Services) return
        AppLog.i(TAG, "ble: services changed; rediscovering")
        handles = null
        reassembler.reset()
        lifecycle.begin()
        lifecycle.advance(RadioLinkLifecycle.Phase.Connecting, RadioLinkLifecycle.Phase.Services)
        // Reporting the attach ends the driver's session; anything handed
        // to the radio over the old handles is failed there.
        sink.phase(MobileRadioTransportPhase.ATTACHING)
        // The stack still holds an operation in flight: discovery waits for its answer.
        queue.restart(GattQueue.Op.Discover())
    }

    private fun issue(op: GattQueue.Op) {
        val port = port ?: return
        when (op) {
            is GattQueue.Op.Bond -> port.createBond()
            is GattQueue.Op.Mtu -> port.requestMtu(RadioGatt.REQUESTED_MTU)
            is GattQueue.Op.Discover -> port.discoverServices()
            is GattQueue.Op.Subscribe -> port.enableNotifications(op.frameOut)
            is GattQueue.Op.Write -> port.write(op.frameIn, op.value)
        }
    }

    private fun deadlinePassed(op: GattQueue.Op) {
        val port = port ?: return
        AppLog.w(TAG, "ble: ${op.javaClass.simpleName} unanswered in ${op.deadlineMs} ms")
        when (op) {
            is GattQueue.Op.Bond -> if (port.bonded) {
                // Bonded, but no word of it arrived: the bond stands.
                sink.phase(MobileRadioTransportPhase.ATTACHING)
                queue.complete(op)
            } else {
                sink.bondFailed()
            }
            is GattQueue.Op.Write -> sink.fault(RadioTransportProblem.WriteUnacknowledged.problem)
            else -> sink.fault(RadioTransportProblem.AttachmentIncomplete.problem)
        }
    }

    companion object {
        private const val TAG = "umsh.radio"

        /** The ATT write header: opcode and handle. */
        private const val ATT_HEADER = 3

        /** The largest attribute value (Core Vol 3 Part F §3.2.9), whatever the MTU. */
        private const val ATT_VALUE_MAX = 512

        private const val BUSY_RETRY_MS = 20L

        /**
         * GATT statuses that mean the link itself is gone or unusable (§4.2):
         * a generic error, a supervision timeout, the radio or this phone
         * ending the link, a lost link layer, a failed connection.
         */
        val INVALIDATING = setOf(133, 8, 19, 22, 34, 62)

        /** Link ends that mean the keys were refused: authentication failure, PIN or key missing (HCI 0x05, 0x06). */
        val KEYS_REFUSED = setOf(5, 6)

        fun gattProblem(status: Int): MobileRadioProblem =
            MobileRadioProblem.Transport(RadioGatt.GATT_DOMAIN, status.toLong())
    }
}
