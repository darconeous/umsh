package com.voria.umsh.app

import com.voria.umsh.services.mobilecore.AppLog
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.dropWhile
import kotlinx.coroutines.launch

/**
 * Whether Add peer's contact exchange is wanted open: while a page that
 * meets ([MeetsNearby]) is the page on screen ([ShellState.shownTop]: the
 * selected destination's top, with no app-level page over the shell) and
 * the app is started. The process's lifecycle does not flap on a rotation or under a
 * permission dialog or chooser, so neither closes the meet; leaving the app
 * does, as iOS's scene phase does. Whether the radio lets it open is the
 * core's.
 *
 * The one caller of `set_meet_wanted`, and only on a change: the core
 * starts with the meet unwanted, so nothing is said until it is first
 * wanted.
 */
class MeetPresence(
    scope: CoroutineScope,
    meetPageShown: Flow<Boolean>,
    processStarted: Flow<Boolean>,
    private val setWanted: suspend (Boolean) -> Unit,
) {
    /** What was last asked of the core. */
    @Volatile
    var wanted: Boolean = false
        private set

    init {
        scope.launch {
            combine(meetPageShown, processStarted) { shown, started -> shown && started }
                .distinctUntilChanged()
                .dropWhile { !it }
                .collect(::ask)
        }
    }

    private suspend fun ask(wanted: Boolean) {
        this.wanted = wanted
        try {
            setWanted(wanted)
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            // Stopped, or no owner: the next change asks again.
            AppLog.w(TAG, "meet ${if (wanted) "open" else "close"} not taken: ${error.javaClass.simpleName}")
        }
    }

    private companion object {
        const val TAG = "umsh.meet"
    }
}
