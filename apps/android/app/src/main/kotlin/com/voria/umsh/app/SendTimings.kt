package com.voria.umsh.app

import com.voria.umsh.models.ChatMessage
import com.voria.umsh.models.DeliveryState
import com.voria.umsh.models.MessageRef

/**
 * Measurement only (D8): for each message sent, how long after the send
 * its caption changed, and how long until it settled (acknowledged, or
 * failed). Logged, so timers that run late under Doze show on a Pixel
 * (G-8). Nothing acts on it.
 *
 * Thread-safe; the runtime feeds it what it reads.
 */
class SendTimings(private val log: (String) -> Unit) {
    private class Watched(val ref: MessageRef, val sentAtMs: Long, var delivery: DeliveryState?)

    private val watched = HashMap<String, MutableList<Watched>>()

    /** The conversations with a message still watched. */
    fun addresses(): Set<String> = synchronized(this) { watched.keys.toSet() }

    /**
     * [address] took a send at [sentAtMs]; [newest] is its transcript's
     * newest page, read after it at [nowMs]. A message no longer pending
     * by then changed before the read: that change is logged at the read,
     * and a message already settled is not watched.
     */
    fun sent(address: String, sentAtMs: Long, newest: List<ChatMessage>, nowMs: Long) {
        val message = newest.lastOrNull { it.isOutbound && !it.isStatus } ?: return
        var line: String? = null
        synchronized(this) {
            val list = watched.getOrPut(address) { mutableListOf() }
            if (list.none { it.ref == message.ref }) {
                if (message.delivery != null && message.delivery != DeliveryState.Pending) {
                    line = "send timing: ${DeliveryState.Pending} → ${message.delivery} by ${nowMs - sentAtMs} ms (first read)"
                }
                if (message.delivery !in SETTLED) list += Watched(message.ref, sentAtMs, message.delivery)
            }
            if (list.isEmpty()) watched.remove(address)
        }
        line?.let(log)
    }

    /** [address]'s transcript changed; [newest] is its newest page now. */
    fun changed(address: String, newest: List<ChatMessage>, nowMs: Long) {
        val lines = mutableListOf<String>()
        synchronized(this) {
            val list = watched[address] ?: return
            val iterator = list.iterator()
            while (iterator.hasNext()) {
                val entry = iterator.next()
                val elapsed = nowMs - entry.sentAtMs
                val message = newest.firstOrNull { it.ref == entry.ref }
                if (message == null || elapsed > WATCH_MS) {
                    // Scrolled past the page read, or gone: no longer measured.
                    if (elapsed > WATCH_MS) lines += "send timing: still ${entry.delivery} after $elapsed ms; no longer watched"
                    iterator.remove()
                    continue
                }
                if (message.delivery != entry.delivery) {
                    lines += "send timing: ${entry.delivery} → ${message.delivery} after $elapsed ms"
                    entry.delivery = message.delivery
                }
                if (message.delivery in SETTLED) iterator.remove()
            }
            if (list.isEmpty()) watched.remove(address)
        }
        lines.forEach(log)
    }

    companion object {
        /** A message is watched for at most this long. */
        const val WATCH_MS = 10 * 60 * 1000L

        /** How many of a conversation's newest messages are read to find one watched. */
        const val PAGE = 16

        private val SETTLED = setOf(DeliveryState.Acknowledged, DeliveryState.Failed, DeliveryState.Undelivered)
    }
}
