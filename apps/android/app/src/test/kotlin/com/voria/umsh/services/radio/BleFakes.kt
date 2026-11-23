package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileGattReassembler
import com.voria.umsh.core.MobileHdlcDecoder
import com.voria.umsh.core.MobileQueuedNoticeRecord
import com.voria.umsh.core.MobileVirtualRadio
import com.voria.umsh.core.MobileVirtualRadioListener
import com.voria.umsh.core.MobileWireSink
import com.voria.umsh.core.ulcpGattSegments
import com.voria.umsh.core.ulcpHdlcEncode
import java.io.File
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger

/**
 * A scheduler on a manual clock: posted work runs at once, on the
 * caller's thread, and scheduled work when [advance] passes its time.
 */
class ManualScheduler : LinkScheduler {
    private class Timer(val at: Long, val order: Long, val block: () -> Unit)

    private val timers = mutableListOf<Timer>()
    private var order = 0L

    var now = 0L
        private set

    override fun post(block: () -> Unit) = block()

    override fun schedule(delayMs: Long, block: () -> Unit) {
        timers += Timer(now + delayMs, order++, block)
    }

    fun advance(ms: Long) {
        val until = now + ms
        while (true) {
            val due = timers.filter { it.at <= until }.minWithOrNull(compareBy<Timer>({ it.at }, { it.order })) ?: break
            timers.remove(due)
            now = due.at
            due.block()
        }
        now = until
    }
}

/** A handle the fakes hand out, named for the log. */
class FakeHandle(val name: String) : GattHandle {
    override fun toString() = name
}

/**
 * A [GattPort] that only records what it is asked; the test answers with
 * [emit]. One per [open], as Android gives one `BluetoothGatt` per
 * attachment.
 */
class FakeGattPort(private val listener: (GattEvent) -> Unit) : GattPort {
    val calls = mutableListOf<String>()
    val written = mutableListOf<ByteArray>()

    /**
     * As Android's GATT client: an operation issued while another awaits
     * its answer is refused, as [AndroidGattPort] reports a refusal on API
     * 33 and later. Off unless a test asks.
     */
    var oneAtATime = false

    /** The GATT operation issued and not yet answered through [emit]. */
    private var inFlight: String? = null

    /** Whether [call] goes ahead; refused with [refusal] while another is in flight. */
    private fun admit(call: String, refusal: GattEvent): Boolean {
        if (oneAtATime && inFlight != null) {
            calls += "refused $call"
            listener(refusal)
            return false
        }
        inFlight = call
        calls += call
        return true
    }

    /** Bonded unless a test says otherwise: only a first pairing bonds. */
    override var bonded = true
    var closed = false
        private set

    override fun connect(autoConnect: Boolean) {
        calls += if (autoConnect) "connect(auto)" else "connect"
    }

    override fun disconnect() {
        calls += "disconnect"
    }

    override fun close() {
        calls += "close"
        closed = true
    }

    override fun createBond() {
        calls += "bond"
    }

    override fun requestMtu(mtu: Int) {
        admit("mtu $mtu", GattEvent.MtuChanged(RadioGatt.DEFAULT_MTU, RadioGatt.GATT_FAILURE))
    }

    override fun discoverServices() {
        admit("discover", GattEvent.ServicesDiscovered(RadioGatt.GATT_FAILURE, ServiceLookup.Missing))
    }

    override fun enableNotifications(frameOut: GattHandle) {
        admit("subscribe $frameOut", GattEvent.DescriptorWritten(RadioGatt.GATT_FAILURE))
    }

    override fun write(frameIn: GattHandle, value: ByteArray) {
        if (admit("write ${value.size}", GattEvent.WriteBusy)) written += value
    }

    /** Raise [event]; an operation's answer frees the client for the next. */
    fun emit(event: GattEvent) {
        when (event) {
            is GattEvent.MtuChanged, is GattEvent.ServicesDiscovered, is GattEvent.DescriptorWritten, is GattEvent.Written -> inFlight = null
            else -> Unit
        }
        listener(event)
    }

    /** The calls since the last look. */
    fun take(): List<String> = calls.toList().also { calls.clear() }

    companion object {
        val frameIn = FakeHandle("frameIn")
        val frameOut = FakeHandle("frameOut")
        val found = ServiceLookup.Found(frameIn, frameOut, frameInWritable = true)
    }
}

/** Hands out [FakeGattPort]s, keeping each. */
class FakeGattPorts : GattPortFactory {
    val opened = mutableListOf<FakeGattPort>()
    val last: FakeGattPort get() = opened.last()

    /** Whether each port opens on a bonded radio. */
    var bonded = true

    override fun open(listener: (GattEvent) -> Unit) = FakeGattPort(listener).also {
        it.bonded = bonded
        opened += it
    }
}

/**
 * A radio over Bluetooth, in process (§4.3): the ULCP GATT surface over a
 * real device session, a [MobileVirtualRadio] with its PHY off (no LAN).
 * Frame In segments are reassembled and handed to the device; the device's
 * frames go back out as Frame Out notifications in ULCP's segments.
 *
 * Every event is raised on the port's caller's thread, which in the app is
 * the connection's executor; the link posts each one, so nothing reenters.
 */
class FakeRadioPeripheral(stateDir: File) : GattPortFactory, AutoCloseable {
    /** The ATT MTU granted to an exchange. */
    @Volatile var grantedMtu = 247

    /** The CCCD is refused for want of keys (the radio lost them; API 31–35). */
    @Volatile var refuseCccd = false

    /** The bond is refused (the person declined the system's dialog). */
    @Volatile var refuseBond = false

    /** The bond is never answered (the system's dialog left open). */
    @Volatile var holdBond = false

    @Volatile var bonded = false

    /** A connect ends at once with this status: nothing at the address (147), or Android's generic 133. */
    @Volatile var unreachable: Int? = null

    /**
     * The radio is out of range: a direct connect times out (147), and a
     * background connect waits, unanswered, until [comeBack].
     */
    @Volatile var away = false

    /** The background connect waiting for the radio, if any. */
    @Volatile private var waiting: Port? = null

    val opened = AtomicInteger()
    val portsClosed = AtomicInteger()
    val bondAttempts = AtomicInteger()
    val framesIn: MutableList<ByteArray> = Collections.synchronizedList(mutableListOf())

    private val device = MobileVirtualRadio.start(stateDir.path, false, Quiet)

    @Volatile private var current: Port? = null

    /** The port the device's session is attached to: only it detaches the device. */
    @Volatile private var holder: Port? = null

    /** Every port opened, in order. */
    val ports: MutableList<Port> = Collections.synchronizedList(mutableListOf())

    override fun open(listener: (GattEvent) -> Unit): GattPort = Port(listener).also {
        opened.incrementAndGet()
        ports += it
        current = it
    }

    /**
     * The radio forgets this phone's keys while attached: API 36 hears of
     * it (`ACTION_KEY_MISSING`), and from then on the protected CCCD is
     * refused. The phone's own bond stays.
     */
    fun loseBond() {
        refuseCccd = true
        current?.listener?.invoke(GattEvent.BondLost)
    }

    /** The radio is in range again: a background connect waiting for it connects. */
    fun comeBack() {
        away = false
        waiting?.let { port ->
            waiting = null
            if (current === port) port.listener(GattEvent.Connected)
        }
    }

    /** A background connect is waiting for the radio. */
    val sought: Boolean get() = waiting != null && waiting === current

    /** The radio drops the link, as a supervision timeout would. */
    fun drop() {
        current?.let { port ->
            port.detach()
            port.listener(GattEvent.Disconnected(8))
        }
    }

    override fun close() {
        device.detach()
        device.stop()
    }

    inner class Port(val listener: (GattEvent) -> Unit) : GattPort {
        private val reassembler = MobileGattReassembler()
        private val decoder = MobileHdlcDecoder()
        private var mtu = RadioGatt.DEFAULT_MTU
        private var attached = false

        @Volatile var closed = false
            private set

        override val bonded: Boolean get() = this@FakeRadioPeripheral.bonded

        override fun connect(autoConnect: Boolean) {
            if (away) {
                if (autoConnect) waiting = this else listener(GattEvent.Disconnected(147))
                return
            }
            listener(unreachable?.let { GattEvent.Disconnected(it) } ?: GattEvent.Connected)
        }

        override fun disconnect() = detach()

        override fun close() {
            portsClosed.incrementAndGet()
            closed = true
            if (waiting === this) waiting = null
            detach()
        }

        override fun createBond() {
            bondAttempts.incrementAndGet()
            if (holdBond) return
            if (refuseBond) {
                listener(GattEvent.BondFailed)
            } else {
                this@FakeRadioPeripheral.bonded = true
                listener(GattEvent.Bonded)
            }
        }

        override fun requestMtu(mtu: Int) {
            this.mtu = minOf(mtu, grantedMtu)
            listener(GattEvent.MtuChanged(this.mtu, RadioGatt.GATT_SUCCESS))
        }

        override fun discoverServices() =
            listener(GattEvent.ServicesDiscovered(RadioGatt.GATT_SUCCESS, FakeGattPort.found))

        override fun enableNotifications(frameOut: GattHandle) {
            if (refuseCccd || !this@FakeRadioPeripheral.bonded) {
                listener(GattEvent.DescriptorWritten(RadioGatt.GATT_INSUFFICIENT_AUTHENTICATION))
                return
            }
            attached = true
            holder = this
            device.attach(Sink(this))
            listener(GattEvent.DescriptorWritten(RadioGatt.GATT_SUCCESS))
        }

        override fun write(frameIn: GattHandle, value: ByteArray) {
            val frame = reassembler.push(value)
            if (frame != null) {
                framesIn += frame
                device.receive(ulcpHdlcEncode(frame))
            }
            listener(GattEvent.Written(RadioGatt.GATT_SUCCESS))
        }

        /** The device's bytes for this port: whole frames out as notifications. */
        fun fromDevice(bytes: ByteArray) {
            if (!attached || current !== this) return
            for (frame in decoder.push(bytes)) {
                for (segment in ulcpGattSegments(frame, (mtu - 3).toUShort())) {
                    listener(GattEvent.Notified(segment.value))
                }
            }
        }

        /** This port's session ends; the device is detached only while this port holds it. */
        fun detach() {
            if (!attached) return
            attached = false
            if (holder !== this) return
            holder = null
            device.detach()
        }
    }

    private class Sink(private val port: Port) : MobileWireSink {
        override fun onWire(bytes: ByteArray) = port.fromDevice(bytes)
    }

    private object Quiet : MobileVirtualRadioListener {
        override fun onQueued(notice: MobileQueuedNoticeRecord) = Unit
    }
}
