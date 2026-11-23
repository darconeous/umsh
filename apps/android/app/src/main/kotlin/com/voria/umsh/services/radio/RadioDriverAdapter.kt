package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileRadioDriver
import com.voria.umsh.core.MobileRadioProblem
import com.voria.umsh.core.MobileRadioTransportPhase
import com.voria.umsh.core.MobileRadioTransportStateRecord
import com.voria.umsh.core.RadioLink
import com.voria.umsh.services.mobilecore.AppLog
import java.io.IOException
import java.lang.ref.WeakReference
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.resume
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * The radio side of a companion radio, over `MobileRadioDriver` (iOS
 * `RadioDriverAdapter`). The driver runs the ULCP session and owns the
 * radio's whole state; the core holds it and publishes what it says. This
 * class reports the transport's state to the driver, carries out the link
 * calls the driver makes, and keeps the registry in step with them.
 *
 * Subclasses are the transports: they own the physical link, the framing
 * its medium needs, and its reconnects. Everything a subclass does runs on
 * this connection's one executor: every driver callback hops to it, and so
 * must every platform callback (socket reads, GATT, broadcasts). No lock
 * ever covers a call into the driver or the platform.
 */
abstract class RadioDriverAdapter(
    final override val kind: RadioKind,
    final override val linkId: String,
    protected val registry: RadioRegistry,
    private val events: RadioConnectionEvents,
    /** The registry's name for the radio, as it was when this connection was made. */
    name: String? = null,
) : RadioConnection {
    @Volatile
    private var executorThread: Thread? = null

    private val executor = ScheduledThreadPoolExecutor(1) { runnable ->
        Thread(runnable, "umsh-radio-${kind.name.lowercase()}").apply { isDaemon = true }.also { executorThread = it }
    }.apply {
        removeOnCancelPolicy = true
        executeExistingDelayedTasksAfterShutdownPolicy = false
    }

    private val bridge = DriverLinkBridge(this)

    /** Tests: the link calls the driver makes, made directly. */
    internal val linkForTests: RadioLink get() = bridge

    /** One per connection, stopped once by [close]. */
    final override val driver: MobileRadioDriver = MobileRadioDriver(bridge)

    /** Registry writes: off the executor, and never waited for by it. */
    private val background = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val closed = AtomicBoolean(false)

    /**
     * What the transport calls the radio: the registry's name, then each
     * name the radio reports for itself. The core names the radio by what
     * the transport says whenever it is not attached, so the transport
     * keeps it current, and every surface shows the same name attached or
     * not. Executor-confined.
     */
    protected var radioName: String? = name
        private set

    // Executor-confined.
    private var faultReported = false
    private var abandoned = false
    private var abandonReported = false

    init {
        AppLog.i(TAG, "driver started ($kind, ${openDrivers.incrementAndGet()} open)")
    }

    /** The subclass is fully made: the driver's calls reach it from now on. Call once, last in `init`. */
    protected fun adopt() {
        bridge.adapter = WeakReference(this)
    }

    // region The transport's half, for subclasses

    /** Bring the link up, or keep it coming. [userInitiated]: the user asked, not the standing intent. */
    protected abstract fun startLink(userInitiated: Boolean)

    /** Deliberately down: nothing reconnects, and the transport reports where it rests. */
    protected abstract fun stopLink()

    /** Queue one complete frame; [rawTransactionId] tags a raw transmit's write. */
    protected abstract fun linkSend(frame: ByteArray, rawTransactionId: UByte?)

    /** Discard partly framed input and anything queued to send: a session is starting. */
    protected abstract fun linkResetFraming()

    /** Tear the link down; with [retrying], take the ordinary link-loss path if there is one. */
    protected abstract fun linkInvalidate(retrying: Boolean)

    /** The radio attached; where the transport remembers which radio it is bound to, now. */
    protected open fun linkDidAttach() = Unit

    /** The radio is erasing itself: stop reconnecting, and leave the link up so the command goes out. */
    protected open fun linkAbandonBinding() = Unit

    /** The radio entered DFU: stop reconnecting and take the link down; the binding stays. */
    protected open fun linkDidEnterDfu() = Unit

    /** After [forget], or the link dropped after a factory reset: what the platform holds for the radio goes. */
    protected open suspend fun releaseBinding() = Unit

    /** [close] ran: whatever the transport watches off the executor stops. Any thread. */
    protected open fun linkClosed() = Unit

    /** The transport carries no frames, and stands at [phase]. Every state it comes to is reported. */
    protected fun reportTransport(phase: MobileRadioTransportPhase, name: String?, problem: MobileRadioProblem? = null) {
        checkOnExecutor()
        AppLog.i(TAG, "$kind transport: $phase${problem?.let { " (${describe(it)})" }.orEmpty()}")
        driver.transportChanged(MobileRadioTransportStateRecord(phase, name, linkId, problem))
    }

    /** The link carries frames: the driver starts the ULCP session. */
    protected fun reportLinkReady(boundRadio: Boolean) {
        checkOnExecutor()
        faultReported = false
        AppLog.i(TAG, "$kind link ready")
        driver.linkReady(boundRadio)
    }

    /** The transport found the link unusable; reported once per attachment. */
    protected fun reportFault(problem: MobileRadioProblem) {
        checkOnExecutor()
        if (faultReported) return
        faultReported = true
        AppLog.w(TAG, "$kind fault: ${describe(problem)}")
        driver.linkFault(problem)
    }

    protected fun reportReceived(frame: ByteArray) {
        checkOnExecutor()
        driver.linkReceived(frame)
    }

    protected fun reportWritesFailed(rawTransactionIds: List<UByte>, problem: MobileRadioProblem) {
        checkOnExecutor()
        if (rawTransactionIds.isNotEmpty()) {
            driver.linkWritesFailed(ByteArray(rawTransactionIds.size) { rawTransactionIds[it].toByte() }, problem)
        }
    }

    /** The link went down. After a factory reset, this is when the binding is let go. */
    protected fun linkDropped() {
        checkOnExecutor()
        if (!abandoned || abandonReported) return
        abandonReported = true
        AppLog.i(TAG, "$kind radio erased itself; letting it go")
        background.launch {
            releaseBinding()
            events.bindingDropped(this@RadioDriverAdapter)
        }
    }

    /** A registry write, off the executor and never waited for. */
    protected fun writeRegistry(block: suspend () -> Unit) {
        background.launch { write(block) }
    }

    /** Run [block] on the executor; false once it has shut down. */
    protected fun post(block: () -> Unit): Boolean = try {
        executor.execute { guarded(block) }
        true
    } catch (_: RejectedExecutionException) {
        false
    }

    protected fun postDelayed(delayMs: Long, block: () -> Unit) {
        try {
            executor.schedule({ guarded(block) }, delayMs, TimeUnit.MILLISECONDS)
        } catch (_: RejectedExecutionException) {
            // Closed: nothing more is scheduled.
        }
    }

    protected fun checkOnExecutor() {
        check(Thread.currentThread() === executorThread) { "off the $kind radio executor" }
    }

    protected val isClosed: Boolean get() = closed.get()

    // endregion

    // region RadioConnection

    override suspend fun connect() {
        if (isClosed) return
        AppLog.i(TAG, "action: connect ($kind)")
        driver.resetRecoveryBudget()
        write { registry.setAutoConnect(linkId, true) }
        onExecutor {
            // Asked for again after a factory reset let it go: it is wanted now.
            abandoned = false
            abandonReported = false
            startLink(userInitiated = true)
        }
    }

    override suspend fun autoConnect() {
        onExecutor { startLink(userInitiated = false) }
    }

    override suspend fun releaseHost() {
        if (isClosed) return
        driver.releaseHost()
    }

    override suspend fun disconnect() {
        if (isClosed) return
        AppLog.i(TAG, "action: disconnect ($kind)")
        releaseHost()
        write { registry.setAutoConnect(linkId, false) }
        onExecutor { stopLink() }
    }

    override suspend fun forget(keepBinding: Boolean) {
        if (isClosed) return
        AppLog.i(TAG, "action: forget ($kind${if (keepBinding) ", binding kept" else ""})")
        releaseHost()
        onExecutor { stopLink() }
        if (!keepBinding) releaseBinding()
        write { registry.clear(linkId) }
    }

    override suspend fun restart() {
        AppLog.i(TAG, "action: restart ($kind)")
        driver.reboot()
    }

    override suspend fun factoryReset() {
        AppLog.i(TAG, "action: factory reset ($kind)")
        driver.factoryReset()
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        // Shut down from the executor, after the link is down: shutting it
        // down here would cancel this task with every other queued one
        // (each is a zero-delay schedule), and leave the platform's link open.
        post {
            try {
                stopLink()
            } finally {
                executor.shutdown()
            }
        }
        linkClosed()
        driver.stop()
        AppLog.i(TAG, "driver stopped ($kind, ${openDrivers.decrementAndGet()} open)")
    }

    // endregion

    // region The driver's calls, on the executor

    private fun handleDidAttach() = linkDidAttach()

    /**
     * The driver acted on the link's trouble: the incident a reported fault
     * opened is over, and the next attachment's first fault is its own
     * (an attachment that fails before it is ready included).
     */
    private fun handleInvalidate(retry: Boolean) {
        faultReported = false
        // Giving up ends the standing intent where it is kept, as DFU does:
        // a later process, or a presence wake, never seeks the radio again
        // on its own (§7.2). Only the user's Connect sets it again.
        if (!retry) writeRegistry { registry.setAutoConnect(linkId, false) }
        linkInvalidate(retry)
    }

    private fun handleDidReportName(name: String) {
        radioName = name
        background.launch { write { registry.setName(linkId, name) } }
    }

    private fun handleAbandonBinding() {
        abandoned = true
        background.launch { write { registry.clear(linkId) } }
        linkAbandonBinding()
    }

    private fun handleDidEnterDfu() {
        background.launch { write { registry.setAutoConnect(linkId, false) } }
        linkDidEnterDfu()
    }

    // endregion

    private suspend fun onExecutor(block: () -> Unit) {
        if (isClosed) return
        suspendCancellableCoroutine { continuation ->
            val posted = post {
                try {
                    if (!isClosed) block()
                } finally {
                    continuation.resume(Unit)
                }
            }
            if (!posted) continuation.resume(Unit)
        }
    }

    private suspend fun write(block: suspend () -> Unit) {
        try {
            block()
        } catch (error: IOException) {
            AppLog.e(TAG, "radio registry not written: ${error.javaClass.simpleName}")
        }
    }

    private fun guarded(block: () -> Unit) {
        try {
            block()
        } catch (error: Exception) {
            AppLog.e(TAG, "$kind radio task failed: ${error.javaClass.simpleName}")
        }
    }

    /**
     * Carries the driver's link calls onto the executor, in the order the
     * driver made them. Holds the adapter weakly: the driver holds this
     * until it stops, and the adapter holds the driver. Calls made before
     * the subclass adopts it are dropped, as iOS drops them.
     */
    private class DriverLinkBridge(owner: RadioDriverAdapter) : RadioLink {
        private val executorOwner = WeakReference(owner)

        @Volatile
        var adapter: WeakReference<RadioDriverAdapter>? = null

        private fun perform(body: RadioDriverAdapter.() -> Unit) {
            val owner = executorOwner.get() ?: return
            owner.post { adapter?.get()?.body() }
        }

        override fun send(frame: ByteArray, rawTransactionId: UByte?) = perform { linkSend(frame, rawTransactionId) }

        override fun resetFraming() = perform { linkResetFraming() }

        override fun invalidate(retry: Boolean) = perform { handleInvalidate(retry) }

        override fun didAttach() = perform { handleDidAttach() }

        override fun didReportName(name: String) = perform { handleDidReportName(name) }

        override fun abandonBinding() = perform { handleAbandonBinding() }

        override fun didEnterDfu() = perform { handleDidEnterDfu() }
    }

    companion object {
        const val TAG = "umsh.radio"

        private val openDrivers = AtomicInteger()

        /** A problem for the log: never message text, only what it is. */
        fun describe(problem: MobileRadioProblem): String =
            RadioTransportProblem.of(problem)?.name ?: when (problem) {
                is MobileRadioProblem.Transport -> "${problem.domain} ${problem.code}"
                else -> problem.javaClass.simpleName
            }
    }
}
