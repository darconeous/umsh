package com.voria.umsh.features.peers.manualpath

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.features.peers.NeighborSource
import com.voria.umsh.models.Octets
import com.voria.umsh.models.RepeaterListing
import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** Why an ask for the previous hop's neighbors came to nothing, for its inline line. */
enum class AddHopProblem {
    /** It went out and nothing came back. */
    NoAnswer,

    /** It could not go out. */
    NotSent,
}

/** Who is asked for the next hop's candidates: a node, and the hops ahead of it in send order. */
data class Vantage(val address: String, val route: List<Octets>)

/**
 * Add hop's Neighbors (`manual-path.svg` 3): what the previous hop reports
 * hearing. Opens on what the store holds and puts nothing on the air until
 * Refresh; each ask goes down the path chosen so far. Choosing a hop moves
 * the page on to the next ([ask] about a new [Vantage]), and an answer for
 * the hop before is dropped.
 */
class AddHopViewModel(private val source: NeighborSource) : ViewModel() {
    private var vantage: Vantage? = null

    /** Bumped for each vantage, so an answer about an earlier one lands nowhere. */
    private var generation = 0

    private val _listing = MutableStateFlow<RepeaterListing?>(null)

    /** What the previous hop said, as far as asked; null while never asked (Not read). */
    val listing: StateFlow<RepeaterListing?> = _listing.asStateFlow()

    private val _fresh = MutableStateFlow(false)

    /** [listing] was answered on this visit, rather than read from the store. */
    val fresh: StateFlow<Boolean> = _fresh.asStateFlow()

    private val _busy = MutableStateFlow(false)
    val busy: StateFlow<Boolean> = _busy.asStateFlow()

    private val _problem = MutableStateFlow<AddHopProblem?>(null)
    val problem: StateFlow<AddHopProblem?> = _problem.asStateFlow()

    /** The node to ask, or null when the previous hop is known only by its hint, which is not an address to ask. */
    fun ask(about: Vantage?) {
        if (about == vantage) return
        vantage = about
        val at = ++generation
        _listing.value = null
        _fresh.value = false
        _busy.value = false
        _problem.value = null
        about ?: return
        viewModelScope.launch {
            val stored = try {
                source.storedNeighbors(about.address)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                AppLog.d(TAG, "neighbors unread: ${error.javaClass.simpleName}")
                null
            }
            if (at == generation && _listing.value == null) _listing.value = stored
        }
    }

    /** Ask the previous hop for the top of its listing. */
    fun refresh() = request(null)

    /** Ask for the page after the last one held. */
    fun loadMore() {
        _listing.value?.nextCursor?.let(::request)
    }

    private fun request(cursor: Octets?) {
        val about = vantage ?: return
        if (_busy.value) return
        val at = generation
        _busy.value = true
        _problem.value = null
        val asked = source.requestNeighbors(about.address, cursor, about.route)
        viewModelScope.launch {
            val problem = try {
                val listing = asked.await()
                if (at == generation) {
                    _listing.value = listing
                    _fresh.value = true
                }
                null
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileAppException.NoAnswer) {
                AddHopProblem.NoAnswer
            } catch (error: Exception) {
                AppLog.w(TAG, "neighbors not asked: ${error.javaClass.simpleName}")
                AddHopProblem.NotSent
            }
            if (at == generation) {
                _problem.value = problem
                _busy.value = false
            }
        }
    }

    private companion object {
        const val TAG = "umsh.addhop"
    }
}
