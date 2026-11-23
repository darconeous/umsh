package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileGattReassembler
import com.voria.umsh.core.MobileRadioProblem
import com.voria.umsh.core.MobileRadioTransportPhase
import com.voria.umsh.core.MobileRadioTransportPhase.ATTACHING
import com.voria.umsh.core.MobileRadioTransportPhase.CONNECTING
import com.voria.umsh.core.MobileRadioTransportPhase.PAIRING
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** One Bluetooth attachment over a scripted port (§4.2, §4.3): no device, no Android. */
class BleRadioLinkTest {
    private class Recorded : BleRadioLink.Sink {
        val phases = mutableListOf<MobileRadioTransportPhase>()
        val faults = mutableListOf<MobileRadioProblem>()
        val received = mutableListOf<ByteArray>()
        val failedWrites = mutableListOf<List<UByte>>()
        val lost = mutableListOf<Int>()
        var ready = 0
        var bondFailures = 0

        override fun bondFailed() {
            bondFailures += 1
        }

        override fun phase(phase: MobileRadioTransportPhase) {
            phases += phase
        }

        override fun ready() {
            ready += 1
        }

        override fun received(frame: ByteArray) {
            received += frame
        }

        override fun writesFailed(rawTransactionIds: List<UByte>, problem: MobileRadioProblem) {
            failedWrites += rawTransactionIds
        }

        override fun fault(problem: MobileRadioProblem) {
            faults += problem
        }

        override fun lost(status: Int) {
            lost += status
        }
    }

    private val scheduler = ManualScheduler()
    private val sink = Recorded()
    private val link = BleRadioLink(scheduler, sink)
    private val ports = FakeGattPorts()
    private val port get() = ports.last

    /** Open, and answer every step up to notifications on. */
    private fun attached(mtu: Int = 247, bonded: Boolean = true): FakeGattPort {
        link.open(ports, autoConnect = false, bond = true)
        port.bonded = bonded
        port.emit(GattEvent.Connected)
        if (!bonded) port.emit(GattEvent.Bonded)
        port.emit(GattEvent.MtuChanged(mtu, RadioGatt.GATT_SUCCESS))
        port.emit(GattEvent.ServicesDiscovered(RadioGatt.GATT_SUCCESS, FakeGattPort.found))
        port.emit(GattEvent.DescriptorWritten(RadioGatt.GATT_SUCCESS))
        assertTrue(link.isReady)
        port.take()
        return port
    }

    private fun refused(problem: MobileRadioProblem) = RadioTransportProblem.of(problem)

    @Test
    fun eachOperationWaitsForThePreviousOnesAnswer() {
        link.open(ports, autoConnect = false, bond = true)
        port.bonded = false
        assertEquals(listOf("connect"), port.take())
        port.emit(GattEvent.Connected)
        // Bond first; the MTU exchange waits behind it.
        assertEquals(listOf("bond"), port.take())
        port.emit(GattEvent.Bonded)
        assertEquals(listOf("mtu ${RadioGatt.REQUESTED_MTU}"), port.take())
        port.emit(GattEvent.MtuChanged(185, RadioGatt.GATT_SUCCESS))
        assertEquals(listOf("discover"), port.take())
        port.emit(GattEvent.ServicesDiscovered(RadioGatt.GATT_SUCCESS, FakeGattPort.found))
        assertEquals(listOf("subscribe frameOut"), port.take())
        assertEquals(0, sink.ready)
        port.emit(GattEvent.DescriptorWritten(RadioGatt.GATT_SUCCESS))
        assertEquals(1, sink.ready)
        assertEquals(185, link.mtu)
        assertEquals(listOf(CONNECTING, ATTACHING, PAIRING, ATTACHING, PAIRING), sink.phases)
        assertTrue(sink.faults.isEmpty())
    }

    @Test
    fun aBondedRadioIsNotAskedToBond() {
        link.open(ports, autoConnect = true, bond = true)
        assertEquals(listOf("connect(auto)"), port.take())
        port.bonded = true
        port.emit(GattEvent.Connected)
        assertEquals(listOf("mtu ${RadioGatt.REQUESTED_MTU}"), port.take())
    }

    @Test
    fun aRefusedMtuExchangeKeepsTheDefault() {
        link.open(ports, autoConnect = false, bond = false)
        port.emit(GattEvent.Connected)
        port.emit(GattEvent.MtuChanged(RadioGatt.DEFAULT_MTU, RadioGatt.GATT_FAILURE))
        assertEquals(RadioGatt.DEFAULT_MTU, link.mtu)
        assertTrue(port.take().last() == "discover")
    }

    @Test
    fun anUnansweredOperationFaultsAtItsDeadline() {
        link.open(ports, autoConnect = false, bond = false)
        port.emit(GattEvent.Connected)
        scheduler.advance(9_999)
        assertTrue(sink.faults.isEmpty())
        scheduler.advance(1)
        assertEquals(listOf(RadioTransportProblem.AttachmentIncomplete), sink.faults.map(::refused))
    }

    @Test
    fun anUnansweredBondFailsTheBond() {
        link.open(ports, autoConnect = false, bond = true)
        port.bonded = false
        port.emit(GattEvent.Connected)
        scheduler.advance(60_000)
        assertEquals(1, sink.bondFailures)
        assertTrue(sink.faults.isEmpty())
    }

    /** The bond came about but its broadcast never arrived: the deadline finds it and the attach goes on. */
    @Test
    fun aBondMadeWithoutWordStandsAtTheDeadline() {
        link.open(ports, autoConnect = false, bond = true)
        port.bonded = false
        port.emit(GattEvent.Connected)
        port.take()
        port.bonded = true
        scheduler.advance(60_000)
        assertEquals(listOf("mtu ${RadioGatt.REQUESTED_MTU}"), port.take())
        assertEquals(0, sink.bondFailures)
        assertTrue(sink.faults.isEmpty())
    }

    /** Past its first pairing, a radio found unbonded has lost its bond: refused, never asked to bond. */
    @Test
    fun anUnbondedRadioPastItsFirstPairingIsRefused() {
        link.open(ports, autoConnect = true, bond = false)
        port.bonded = false
        port.emit(GattEvent.Connected)
        assertEquals(listOf("connect(auto)"), port.take())
        assertEquals(listOf(RadioTransportProblem.AttachmentRefused), sink.faults.map(::refused))
        assertFalse(sink.phases.contains(PAIRING))
    }

    /** One Android holds no bond for is refused before any connection is tried. */
    @Test
    fun anUnbondedRadioIsNotEvenConnected() {
        ports.bonded = false
        link.open(ports, autoConnect = true, bond = false)
        assertTrue(port.take().isEmpty())
        assertEquals(listOf(RadioTransportProblem.AttachmentRefused), sink.faults.map(::refused))
    }

    /** The link ends for want of keys as it is encrypted: a lost bond, not a lost link. */
    @Test
    fun aLinkEndedForRefusedKeysIsALostBond() {
        link.open(ports, autoConnect = true, bond = false)
        port.emit(GattEvent.Connected)
        port.emit(GattEvent.Disconnected(5))
        assertTrue(sink.lost.isEmpty())
        assertEquals(listOf(RadioTransportProblem.AttachmentRefused), sink.faults.map(::refused))
        assertFalse(link.isOpen)
    }

    /** However large the MTU, no value is longer than an attribute can hold. */
    @Test
    fun valuesNeverExceedTheAttributeMaximum() {
        val port = attached(mtu = RadioGatt.REQUESTED_MTU)
        // The largest frame: 511 octets in the first value, one in the next.
        link.send(ByteArray(512) { it.toByte() }, null)
        port.emit(GattEvent.Written(RadioGatt.GATT_SUCCESS))
        assertEquals(2, port.written.size)
        assertEquals(512, port.written.first().size)
        assertTrue(port.written.all { it.size <= 512 })
    }

    @Test
    fun anAnsweredOperationsDeadlineIsMoot() {
        attached()
        scheduler.advance(120_000)
        assertTrue(sink.faults.isEmpty())
    }

    @Test
    fun anUnacknowledgedWriteFaults() {
        attached()
        link.send(byteArrayOf(1, 2, 3), null)
        scheduler.advance(GattQueue.WRITE_DEADLINE_MS)
        assertEquals(listOf(RadioTransportProblem.WriteUnacknowledged), sink.faults.map(::refused))
    }

    @Test
    fun aBusyWriteGoesAgainUnchanged() {
        val port = attached()
        link.send(byteArrayOf(1, 2, 3), null)
        assertEquals(1, port.written.size)
        port.emit(GattEvent.WriteBusy)
        assertEquals(1, port.written.size)
        scheduler.advance(20)
        assertEquals(2, port.written.size)
        assertArrayEquals(port.written[0], port.written[1])
        port.emit(GattEvent.Written(RadioGatt.GATT_SUCCESS))
        assertTrue(sink.faults.isEmpty())
    }

    @Test
    fun anOldPortsLateCallbackIsDropped() {
        link.open(ports, autoConnect = false, bond = false)
        val first = port
        link.open(ports, autoConnect = false, bond = false)
        assertTrue(first.closed)
        val second = port
        second.take()
        first.emit(GattEvent.Connected)
        first.emit(GattEvent.Disconnected(8))
        assertTrue(second.take().isEmpty())
        assertTrue(sink.lost.isEmpty())
        second.emit(GattEvent.Connected)
        assertEquals(listOf("mtu ${RadioGatt.REQUESTED_MTU}"), second.take())
    }

    @Test
    fun aClosedLinkReportsNothingMore() {
        val port = attached()
        link.close()
        assertEquals(listOf("disconnect", "close"), port.take())
        port.emit(GattEvent.Disconnected(0))
        port.emit(GattEvent.Notified(byteArrayOf(0)))
        assertTrue(sink.lost.isEmpty())
        assertTrue(sink.received.isEmpty())
    }

    @Test
    fun aFailedWriteFailsItsFrameAndThoseQueuedBehindIt() {
        val port = attached(mtu = RadioGatt.DEFAULT_MTU)
        link.send(ByteArray(50) { it.toByte() }, 7u)
        link.send(ByteArray(10), 9u)
        link.send(ByteArray(10), null)
        assertEquals(1, port.written.size)
        port.emit(GattEvent.Written(3))
        assertEquals(listOf(listOf<UByte>(7u, 9u)), sink.failedWrites)
        // The link stays: one frame lost is not a lost link.
        assertTrue(sink.faults.isEmpty())
        assertTrue(link.isReady)
        link.send(byteArrayOf(1), null)
        assertEquals(2, port.written.size)
    }

    @Test
    fun aWriteStatusThatEndsTheLinkFaults() {
        val port = attached()
        link.send(byteArrayOf(1), null)
        port.emit(GattEvent.Written(133))
        assertEquals(listOf(BleRadioLink.gattProblem(133)), sink.faults)
        assertTrue(sink.failedWrites.isEmpty())
    }

    @Test
    fun aRefusedWriteCallFaults() {
        val port = attached()
        link.send(byteArrayOf(1), null)
        port.emit(GattEvent.WriteRefused(6))
        assertEquals(1, sink.faults.size)
    }

    @Test
    fun framesAreSegmentedToTheMtuAndReassembled() {
        val port = attached(mtu = RadioGatt.DEFAULT_MTU)
        val frame = ByteArray(100) { it.toByte() }
        link.send(frame, null)
        while (port.written.size < 6) {
            val before = port.written.size
            port.emit(GattEvent.Written(RadioGatt.GATT_SUCCESS))
            if (port.written.size == before) break
        }
        assertTrue(port.written.size > 1)
        assertTrue(port.written.all { it.size <= RadioGatt.DEFAULT_MTU - 3 })
        val reassembler = MobileGattReassembler()
        val whole = port.written.firstNotNullOfOrNull { reassembler.push(it) }
        assertArrayEquals(frame, whole)

        // And the radio's segments come back as one frame.
        val segments = com.voria.umsh.core.ulcpGattSegments(frame, (RadioGatt.DEFAULT_MTU - 3).toUShort())
        segments.forEach { port.emit(GattEvent.Notified(it.value)) }
        assertEquals(1, sink.received.size)
        assertArrayEquals(frame, sink.received.single())
    }

    @Test
    fun aSegmentThatCannotBeReassembledEndsTheSession() {
        val port = attached()
        port.emit(GattEvent.Notified(ByteArray(0)))
        assertEquals(listOf(RadioTransportProblem.LinkLost), sink.faults.map(::refused))
    }

    @Test
    fun aChangedDatabaseIsDiscoveredAgain() {
        val port = attached()
        sink.phases.clear()
        port.emit(GattEvent.ServiceChanged)
        assertFalse(link.isReady)
        assertEquals(listOf(ATTACHING), sink.phases)
        assertEquals(listOf("discover"), port.take())
        port.emit(GattEvent.ServicesDiscovered(RadioGatt.GATT_SUCCESS, FakeGattPort.found))
        assertEquals(listOf("subscribe frameOut"), port.take())
        port.emit(GattEvent.DescriptorWritten(RadioGatt.GATT_SUCCESS))
        assertEquals(2, sink.ready)
    }

    /**
     * The database changes with a frame's write in flight. Android takes one
     * GATT operation at a time, so discovery waits for that write's answer
     * rather than being refused; the stale answer only frees the stack.
     */
    @Test
    fun aChangedDatabaseWaitsForTheWriteInFlight() {
        val port = attached()
        port.oneAtATime = true
        link.send(ByteArray(40) { it.toByte() }, rawTransactionId = 4u)
        assertEquals(listOf("write ${port.written.last().size}"), port.take().take(1))
        port.emit(GattEvent.ServiceChanged)
        // Nothing issued behind the write still in flight.
        assertEquals(emptyList<String>(), port.take())
        port.emit(GattEvent.Written(RadioGatt.GATT_SUCCESS))
        assertEquals(listOf("discover"), port.take())
        port.emit(GattEvent.ServicesDiscovered(RadioGatt.GATT_SUCCESS, FakeGattPort.found))
        assertEquals(listOf("subscribe frameOut"), port.take())
        port.emit(GattEvent.DescriptorWritten(RadioGatt.GATT_SUCCESS))
        assertEquals(2, sink.ready)
        assertTrue(sink.faults.isEmpty())
        assertTrue(sink.failedWrites.isEmpty())
    }

    /** The same while the stack answers the stale write busy: it is not issued again over the old handles. */
    @Test
    fun aStaleWriteAnsweredBusyIsNotIssuedAgain() {
        val port = attached()
        link.send(ByteArray(10), rawTransactionId = null)
        port.take()
        port.emit(GattEvent.ServiceChanged)
        port.emit(GattEvent.WriteBusy)
        scheduler.advance(1_000)
        assertEquals(listOf("discover"), port.take())
        assertTrue(sink.faults.isEmpty())
    }

    @Test
    fun aMissingOrIncompatibleServiceFaults() {
        link.open(ports, autoConnect = false, bond = false)
        port.emit(GattEvent.Connected)
        port.emit(GattEvent.MtuChanged(247, RadioGatt.GATT_SUCCESS))
        port.emit(GattEvent.ServicesDiscovered(RadioGatt.GATT_SUCCESS, ServiceLookup.Missing))
        assertEquals(listOf(RadioTransportProblem.ServiceMissing), sink.faults.map(::refused))
    }

    @Test
    fun aRefusedSubscriptionIsALostBond() {
        link.open(ports, autoConnect = false, bond = true)
        port.bonded = true
        port.emit(GattEvent.Connected)
        port.emit(GattEvent.MtuChanged(247, RadioGatt.GATT_SUCCESS))
        port.emit(GattEvent.ServicesDiscovered(RadioGatt.GATT_SUCCESS, FakeGattPort.found))
        port.emit(GattEvent.DescriptorWritten(RadioGatt.GATT_INSUFFICIENT_ENCRYPTION))
        assertEquals(listOf(RadioTransportProblem.AttachmentRefused), sink.faults.map(::refused))
    }

    @Test
    fun aLostBondIsARefusal() {
        val port = attached()
        port.emit(GattEvent.BondLost)
        assertEquals(listOf(RadioTransportProblem.AttachmentRefused), sink.faults.map(::refused))
    }

    @Test
    fun aDeclinedBondFailsTheBond() {
        link.open(ports, autoConnect = false, bond = true)
        port.bonded = false
        port.emit(GattEvent.Connected)
        port.emit(GattEvent.BondFailed)
        assertEquals(1, sink.bondFailures)
        assertTrue(sink.faults.isEmpty())
    }

    @Test
    fun aDroppedLinkIsReportedAndItsPortClosed() {
        val port = attached()
        port.emit(GattEvent.Disconnected(8))
        assertEquals(listOf(8), sink.lost)
        assertTrue(port.closed)
        assertFalse(link.isOpen)
        // Nothing more from it.
        port.emit(GattEvent.Disconnected(8))
        assertEquals(listOf(8), sink.lost)
    }
}
