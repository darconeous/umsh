package com.voria.umsh.services.mobilecore

import com.voria.umsh.core.MobileAppCoreListener
import kotlinx.coroutines.channels.SendChannel

/**
 * The core's listener: wakes the runtime's drain and nothing else.
 *
 * Called on whichever thread published, and infallible to the core, so it
 * only offers to a conflated channel; a closed channel after a detach is
 * ignored.
 */
class CoreWake(private val wakes: SendChannel<Unit>) : MobileAppCoreListener {
    override fun onChangesPending() {
        runCatching { wakes.trySend(Unit) }
    }
}
