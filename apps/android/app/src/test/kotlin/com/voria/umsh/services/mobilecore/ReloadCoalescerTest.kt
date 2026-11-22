package com.voria.umsh.services.mobilecore

import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReloadCoalescerTest {
    @Test
    fun oneRunsAndOneQueuesWhateverIsAsked() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val started = Collections.synchronizedList(mutableListOf<Boolean>())
        val gate = CompletableDeferred<Unit>()
        val firstRunning = CompletableDeferred<Unit>()
        val reloads = ReloadCoalescer(scope) { full ->
            started += full
            if (started.size == 1) {
                firstRunning.complete(Unit)
                gate.await()
            }
        }
        val first = reloads.request(full = false)
        firstRunning.await()
        // Asked while the first runs: they share one queued reload, which a
        // full request makes full.
        val queued = listOf(
            reloads.request(full = false),
            reloads.request(full = true),
            reloads.request(full = false),
        )
        assertTrue(queued.all { it === queued[0] })
        assertFalse(queued[0].isCompleted)
        gate.complete(Unit)
        withTimeout(5_000) { (queued + first).awaitAll() }
        assertEquals(listOf(false, true), started.toList())
        scope.cancel()
    }

    /**
     * Once the queued reload has started it may already have read, so a
     * request made then does not join it: it queues a read of its own.
     */
    @Test
    fun aRequestAfterTheQueueStartsAwaitsTheNextRead() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val reads = AtomicInteger()
        val firstGate = CompletableDeferred<Unit>()
        val secondRunning = CompletableDeferred<Unit>()
        val secondGate = CompletableDeferred<Unit>()
        val reloads = ReloadCoalescer(scope) {
            when (reads.incrementAndGet()) {
                1 -> firstGate.await()
                2 -> {
                    secondRunning.complete(Unit)
                    secondGate.await()
                }
            }
        }
        reloads.request(full = false)
        val queued = reloads.request(full = false)
        firstGate.complete(Unit)
        withTimeout(5_000) { secondRunning.await() }

        val later = reloads.request(full = false)
        assertTrue(later !== queued)
        secondGate.complete(Unit)
        withTimeout(5_000) { later.await() }
        assertEquals(3, reads.get())
        scope.cancel()
    }

    @Test
    fun aCanceledScopeStillAnswersItsCallers() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        scope.cancel()
        val reloads = ReloadCoalescer(scope) { error("never runs") }
        withTimeout(5_000) { reloads.request(full = true).await() }
    }
}
