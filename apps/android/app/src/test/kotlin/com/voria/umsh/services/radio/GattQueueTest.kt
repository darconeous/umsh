package com.voria.umsh.services.radio

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** The GATT queue alone: one operation at a time, and deadlines counted from the first issue. */
class GattQueueTest {
    private val scheduler = ManualScheduler()
    private val issued = mutableListOf<GattQueue.Op>()
    private val missed = mutableListOf<GattQueue.Op>()
    private val queue = GattQueue(scheduler, { issued += it }, { missed += it })

    private fun write() = GattQueue.Op.Write(FakeGattPort.frameIn, byteArrayOf(1), null)

    @Test
    fun theNextGoesOutOnlyOnceThePreviousIsAnswered() {
        val first = write()
        val second = write()
        queue.enqueue(first)
        queue.enqueue(second)
        assertEquals(listOf<GattQueue.Op>(first), issued)
        // A stray answer for one not in flight changes nothing.
        queue.complete(second)
        assertEquals(1, issued.size)
        queue.complete(first)
        assertEquals(listOf<GattQueue.Op>(first, second), issued)
        queue.complete(second)
        assertTrue(queue.isIdle)
    }

    @Test
    fun anAnsweredOperationsDeadlineIsMoot() {
        val op = write()
        queue.enqueue(op)
        queue.complete(op)
        scheduler.advance(GattQueue.WRITE_DEADLINE_MS * 2)
        assertTrue(missed.isEmpty())
    }

    @Test
    fun anUnansweredOperationMissesItsDeadline() {
        val op = GattQueue.Op.Discover()
        queue.enqueue(op)
        scheduler.advance(op.deadlineMs - 1)
        assertTrue(missed.isEmpty())
        scheduler.advance(1)
        assertEquals(listOf<GattQueue.Op>(op), missed)
    }

    /** The stack answering busy forever: the write still runs out of time, from its first issue. */
    @Test
    fun aWriteBusyForeverMissesItsDeadline() {
        val op = write()
        queue.enqueue(op)
        val retryMs = 20L
        var elapsed = 0L
        while (missed.isEmpty() && elapsed <= GattQueue.WRITE_DEADLINE_MS) {
            // Busy, answered at once, and issued again after the pause.
            queue.retryCurrent(retryMs)
            scheduler.advance(retryMs)
            elapsed += retryMs
        }
        assertEquals(listOf<GattQueue.Op>(op), missed)
        assertEquals(GattQueue.WRITE_DEADLINE_MS, elapsed)
        assertTrue(issued.size > 2)
        assertTrue(issued.all { it === op })
    }

    @Test
    fun aRetriedWriteKeepsItsPlaceAtTheFront() {
        val first = write()
        val second = write()
        queue.enqueue(first)
        queue.enqueue(second)
        queue.retryCurrent(20)
        scheduler.advance(20)
        assertSame(first, issued.last())
        assertSame(first, queue.current)
    }
}
