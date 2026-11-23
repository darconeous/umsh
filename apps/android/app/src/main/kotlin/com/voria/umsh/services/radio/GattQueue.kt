package com.voria.umsh.services.radio

/**
 * Android's GATT client takes one operation at a time, across every kind:
 * a second one issued before the first's callback is dropped or refused.
 * So every operation of an attachment (bond, MTU, discovery, CCCD, writes)
 * goes through this queue, and the next is issued only once the previous
 * one's result has arrived.
 *
 * Each operation has a deadline, armed when it is first issued; one that
 * passes with the operation still in flight, or waiting to go out again
 * after the stack was busy, is reported to [onDeadline]. Confined to the
 * link's executor.
 */
class GattQueue(
    private val scheduler: LinkScheduler,
    private val issue: (Op) -> Unit,
    private val onDeadline: (Op) -> Unit,
) {
    sealed class Op(val deadlineMs: Long) {
        /** Its deadline is running: armed at the first issue, not again at a retry. */
        internal var armed = false

        /** The system's pairing dialog may be up. */
        class Bond : Op(60_000)

        class Mtu : Op(10_000)

        class Discover : Op(10_000)

        /** Writing the CCCD can raise the pairing dialog too. */
        class Subscribe(val frameOut: GattHandle) : Op(60_000)

        /** One ATT value of a frame; [rawTransactionId] tags a raw transmit's writes. */
        class Write(val frameIn: GattHandle, val value: ByteArray, val rawTransactionId: UByte?) : Op(WRITE_DEADLINE_MS)
    }

    private val pending = ArrayDeque<Op>()

    /** The operation issued and not yet answered. */
    var current: Op? = null
        private set

    /**
     * The operation that was in flight when the attachment started over
     * ([restart]): the stack still holds it, so the next waits for its
     * answer, but that answer means nothing now.
     */
    private var stale: Op? = null

    val isIdle: Boolean get() = current == null && pending.isEmpty()

    /** [op] was in flight when the attachment started over: its answer only frees the stack. */
    fun isStale(op: Op): Boolean = op === stale

    fun enqueue(op: Op) {
        pending.addLast(op)
        next()
    }

    /** [op] answered: the next one goes out. A late or stray answer changes nothing. */
    fun complete(op: Op) {
        if (current !== op) return
        if (stale === op) stale = null
        current = null
        next()
    }

    /**
     * The write in flight did not start (the stack was busy): it goes back
     * to the front and is issued again after [delayMs]. A stale one is
     * not issued again: it is done with.
     */
    fun retryCurrent(delayMs: Long) {
        val op = current ?: return
        if (op === stale) return complete(op)
        current = null
        pending.addFirst(op)
        scheduler.schedule(delayMs) { next() }
    }

    /** The writes still queued, taken out; the one in flight is not among them. */
    fun drainWrites(): List<Op.Write> {
        val writes = pending.filterIsInstance<Op.Write>()
        pending.removeAll { it is Op.Write }
        return writes
    }

    /** Everything dropped, the operation in flight with it: the attachment is over. */
    fun clear() {
        pending.clear()
        current = null
        stale = null
    }

    /**
     * The attachment starts over at [first], over the same connection:
     * everything queued is dropped, and [first] goes out once the
     * operation in flight, if any, has been answered (the stack takes one
     * at a time). That answer is stale ([isStale]).
     */
    fun restart(first: Op) {
        pending.clear()
        stale = current
        pending.addLast(first)
        next()
    }

    private fun next() {
        if (current != null) return
        val op = pending.removeFirstOrNull() ?: return
        current = op
        if (!op.armed) {
            op.armed = true
            // From the first issue: a write the stack keeps refusing as busy
            // runs out of time as one it never answers does.
            scheduler.schedule(op.deadlineMs) { if (current === op || pending.firstOrNull() === op) onDeadline(op) }
        }
        issue(op)
    }

    companion object {
        /** As iOS's `writeUnacknowledged`. */
        const val WRITE_DEADLINE_MS = 8_000L
    }
}

/** Where a link's work runs: the connection's one executor in the app, a manual clock in tests. */
interface LinkScheduler {
    fun post(block: () -> Unit)

    fun schedule(delayMs: Long, block: () -> Unit)
}
