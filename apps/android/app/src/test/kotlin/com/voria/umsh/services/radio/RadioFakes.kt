package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileRadioDriver
import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.core.MobileRadioStateRecord
import com.voria.umsh.core.MobileRadioTransportPhase
import java.util.Collections
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withTimeout

/** A registry in memory, with the same name-the-radio guard as the real one. */
class MemoryRadioRegistry(initial: BoundRadio? = null) : RadioRegistry {
    override val bound = MutableStateFlow(initial)

    override suspend fun bind(radio: BoundRadio) {
        bound.value = radio
    }

    override suspend fun setAutoConnect(linkId: String, enabled: Boolean) {
        bound.update { radio -> if (radio?.linkId == linkId) radio.copy(autoConnect = enabled) else radio }
    }

    override suspend fun attached(linkId: String) {
        bound.update { radio -> if (radio?.linkId == linkId) radio.copy(autoConnect = true, pending = null) else radio }
    }

    override suspend fun setName(linkId: String, name: String) {
        bound.update { radio -> if (radio?.linkId == linkId) radio.copy(name = name) else radio }
    }

    override suspend fun clear(linkId: String) {
        bound.update { radio -> if (radio?.linkId == linkId) null else radio }
    }
}

/**
 * A connection whose link is only a record of what it was asked: the
 * adapter's own bookkeeping (registry, executor, driver) is real.
 */
class RecordingRadioConnection(
    linkId: String,
    registry: RadioRegistry,
    events: RadioConnectionEvents,
    /** Every connection's entries too, in order with others' (a vault's, say). */
    private val shared: MutableList<String>? = null,
) : RadioDriverAdapter(RadioKind.Tcp, linkId, registry, events) {
    /** This connection's own entries. */
    val log: MutableList<String> = object : java.util.AbstractList<String>() {
        private val entries = Collections.synchronizedList(mutableListOf<String>())
        override val size get() = entries.size
        override fun get(index: Int) = entries[index]
        override fun add(index: Int, element: String) {
            entries.add(index, element)
            shared?.add(element)
        }
    }

    @Volatile var linkUp = false

    init {
        adopt()
    }

    override fun startLink(userInitiated: Boolean) {
        log += if (userInitiated) "connect" else "autoConnect"
        linkUp = true
        reportTransport(MobileRadioTransportPhase.CONNECTING, linkId)
    }

    /** Whether the executor still took work as the link stopped, the last time it did. */
    @Volatile var executorOpenAtStop: Boolean? = null

    override fun stopLink() {
        log += "stop"
        executorOpenAtStop = post { }
        drop()
    }

    override suspend fun releaseHost() {
        log += "release"
        super.releaseHost()
    }

    override fun linkSend(frame: ByteArray, rawTransactionId: UByte?) = Unit

    override fun linkResetFraming() = Unit

    override fun linkInvalidate(retrying: Boolean) {
        log += "invalidate"
        drop()
    }

    override fun linkAbandonBinding() {
        log += "abandon"
    }

    override fun linkDidEnterDfu() {
        log += "dfu"
        drop()
    }

    override suspend fun releaseBinding() {
        log += "releaseBinding"
    }

    override fun close() {
        log += "close"
        super.close()
    }

    /** Keep the executor busy until [gate] opens: work posted meanwhile queues behind it. */
    fun hold(gate: java.util.concurrent.CountDownLatch) {
        check(post { gate.await() })
    }

    /** The radio's end went away. */
    fun dropFromRadio() {
        check(post { drop() })
    }

    private fun drop() {
        val wasUp = linkUp
        linkUp = false
        reportTransport(MobileRadioTransportPhase.IDLE, linkId)
        if (wasUp) linkDropped()
    }
}

/** Wait until the driver's published state matches. */
suspend fun MobileRadioDriver.awaitState(timeoutMs: Long = 10_000, predicate: (MobileRadioStateRecord) -> Boolean): MobileRadioStateRecord =
    withTimeout(timeoutMs) {
        while (true) {
            val state = state()
            if (predicate(state)) return@withTimeout state
            delay(20)
        }
        @Suppress("UNREACHABLE_CODE")
        error("unreachable")
    }

suspend fun MobileRadioDriver.awaitPhase(phase: MobileRadioPhase, timeoutMs: Long = 10_000) =
    awaitState(timeoutMs) { it.phase == phase }
