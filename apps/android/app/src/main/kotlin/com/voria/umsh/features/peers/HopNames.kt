package com.voria.umsh.features.peers

import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.Octets
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Names for one hint list: [peers] answer [hints], and no other list. A
 * route or reply that moved on to new hints is not drawn with the old
 * names while the new ones are asked for.
 */
data class NamedHops(val hints: List<Octets>, val peers: List<PeerSummary?>) {
    /** The names for [current], or none while these answer another list. */
    fun forHints(current: List<Octets>): List<PeerSummary?> = if (current == hints) peers else emptyList()

    companion object {
        val NONE = NamedHops(emptyList(), emptyList())
    }
}

/**
 * The stored node each two-byte repeater hint most likely names, by the
 * core's rule (`name_repeater_hints`, the one the neighbor and
 * message-repeater records are named by). For hints the core hands out
 * unnamed: a route's, a ping reply's, a discovery vantage's, and hints
 * typed or edited by hand. Answers are remembered per hint list until the
 * stored nodes are read again ([revision]), since the query reads them all.
 */
class HopNames(
    private val query: suspend (List<Octets>) -> List<String?>,
    private val revision: StateFlow<Long>,
) {
    private val lock = Mutex()
    private var memoRevision = Long.MIN_VALUE
    private val memo = LinkedHashMap<List<Octets>, List<String?>>()

    /** How many times the core was asked; for tests. */
    @Volatile
    var queries: Int = 0
        private set

    /**
     * Each hint's node address, or null. A query that fails (the core busy
     * or stopped) names none and is not remembered, so the next ask tries again.
     */
    suspend fun names(hints: List<Octets>): List<String?> {
        if (hints.isEmpty()) return emptyList()
        val at = revision.value
        lock.withLock {
            if (memoRevision != at) {
                memo.clear()
                memoRevision = at
            }
            memo[hints]?.let { return it }
        }
        val named = try {
            queries++
            query(hints)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            AppLog.d(TAG, "hops unnamed: ${error.javaClass.simpleName}")
            return List(hints.size) { null }
        }
        lock.withLock {
            if (memoRevision == at) {
                if (memo.size >= KEPT) memo.remove(memo.keys.first())
                memo[hints] = named
            }
        }
        return named
    }

    /**
     * Each hint's node, read again whenever the stored nodes are, and
     * looked up in [state]'s peers (a node named but not yet in the lists
     * reads as unnamed until they catch up).
     */
    fun peers(hints: List<Octets>, state: StateFlow<AppStateSnapshot?>): Flow<NamedHops> {
        if (hints.isEmpty()) return flowOf(NamedHops.NONE)
        val addresses = revision.map { names(hints) }.distinctUntilChanged()
        return combine(addresses, state) { named, snapshot ->
            val peers = snapshot?.peers.orEmpty().associateBy { it.address }
            NamedHops(hints, named.map { address -> address?.let(peers::get) })
        }.distinctUntilChanged()
    }

    private companion object {
        const val TAG = "umsh.hops"

        /** Hint lists remembered at once: a few open pages' worth. */
        const val KEPT = 32
    }
}
