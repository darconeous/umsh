package com.voria.umsh.services.mobilecore

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * Runs state reloads one at a time, with at most one more queued.
 *
 * A request joins the queued reload when there is one, and otherwise
 * queues a new one; either way the reload it awaits starts after the
 * request, so what it publishes includes whatever the caller changed
 * first. A full request makes the queued reload full.
 */
class ReloadCoalescer(
    private val scope: CoroutineScope,
    private val perform: suspend (full: Boolean) -> Unit,
) {
    private val lock = Any()
    private var queued: CompletableDeferred<Unit>? = null
    private var queuedFull = false
    private var running: Job? = null

    fun request(full: Boolean): Deferred<Unit> = synchronized(lock) {
        queuedFull = queuedFull || full
        queued ?: CompletableDeferred<Unit>().also {
            queued = it
            if (running == null) launchNext()
        }
    }

    /** Under [lock]. */
    private fun launchNext() {
        val done = queued ?: return
        val full = queuedFull
        queued = null
        queuedFull = false
        val job = scope.launch { perform(full) }
        running = job
        // Also when the scope was already canceled and the body never ran,
        // so no caller waits forever.
        job.invokeOnCompletion {
            done.complete(Unit)
            synchronized(lock) {
                running = null
                launchNext()
            }
        }
    }
}
