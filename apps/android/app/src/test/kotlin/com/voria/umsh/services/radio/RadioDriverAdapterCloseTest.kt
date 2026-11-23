package com.voria.umsh.services.radio

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Closing a connection takes its link down, whatever its executor is doing at the time. */
class RadioDriverAdapterCloseTest {
    /**
     * The executor is busy when [RadioDriverAdapter.close] runs, so the
     * link's stop queues behind other work, and the executor is shut down
     * only once the link is down. Shut down from `close()` itself, Android's
     * executor cancels the queued stop (its shutdown policy cancels pending
     * work; the host JVM's keeps work already due, so this asserts the
     * order rather than the loss) and leaves the platform's link (a
     * `BluetoothGatt`) open.
     */
    @Test
    fun closeStopsTheLinkBeforeTheExecutorEnds() {
        val connection = RecordingRadioConnection("bridge:1", MemoryRadioRegistry(), RadioConnectionEvents { })
        val gate = CountDownLatch(1)
        connection.hold(gate)
        connection.close()
        gate.countDown()
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while ("stop" !in connection.log && System.nanoTime() < deadline) Thread.sleep(10)
        assertTrue("the link was never stopped: ${connection.log}", "stop" in connection.log)
        assertEquals("the executor ended before the link did", true, connection.executorOpenAtStop)
    }
}
