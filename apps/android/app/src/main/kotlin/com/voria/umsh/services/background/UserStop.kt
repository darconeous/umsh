package com.voria.umsh.services.background

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.edit
import com.voria.umsh.services.mobilecore.AppLog
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * A deliberate stop is honored until the app is opened (DP-84). After App
 * info's Force stop (and Task Manager's Stop, which Android records the
 * same way), Android still binds the presence service when the radio is
 * near, rebinds it after an update, and sends the update broadcast; none
 * of those may start the radio's service or seek the radio until the user
 * opens the app.
 *
 * Android records why each of the app's processes ended. A process reads
 * the records it has not read before, once, as it starts; one that ended
 * at the user's request sets "stopped until opened". The flag is kept, so
 * it holds through any number of later process starts, whatever ended
 * them, until an activity opens ([opened]).
 *
 * One per process.
 */
class UserStop(private val store: Store, private val exits: () -> List<Exit>, private val scope: CoroutineScope) {
    /** One ended process, as Android recorded it. */
    data class Exit(
        val timestampMs: Long,
        /** The user's own stop: Force stop or Task Manager's Stop ([userRequested]). */
        val userRequested: Boolean,
    )

    /** What is kept across processes. */
    interface Store {
        /** Null when nothing was ever kept. */
        fun read(): State?

        fun write(state: State)
    }

    data class State(
        val stoppedUntilOpened: Boolean,
        /** The newest exit already read; older ones are never read again. */
        val lastExitMs: Long,
    )

    /** Complete once this process has read the records. */
    private val ready = CompletableDeferred<Unit>()

    /** The kept state, as this process last left it. */
    private val current = AtomicReference(State(stoppedUntilOpened = false, lastExitMs = 0))

    init {
        scope.launch {
            val kept = runCatching { store.read() }.getOrNull()
            val read = runCatching(exits).getOrElse {
                AppLog.w(TAG, "process exits unread: ${it.javaClass.simpleName}")
                emptyList()
            }
            val next = next(kept, read)
            if (next.stoppedUntilOpened) {
                AppLog.i(TAG, "stopped by the user: nothing starts the radio in the background until the app is opened")
            }
            if (next != kept) runCatching { store.write(next) }
            current.set(next)
            ready.complete(Unit)
        }
    }

    /** Stopped by the user, and not opened since. Waits for this process's read of the records. */
    suspend fun stopped(): Boolean {
        ready.await()
        return current.get().stoppedUntilOpened
    }

    /** The app was opened: the stop is over. Applied after this process's read, so the read never undoes it. */
    fun opened() {
        scope.launch {
            ready.await()
            val before = current.getAndUpdate { it.copy(stoppedUntilOpened = false) }
            if (!before.stoppedUntilOpened) return@launch
            runCatching { store.write(current.get()) }
            AppLog.i(TAG, "opened: the radio may start in the background again")
        }
    }

    companion object {
        private const val TAG = "umsh.service"

        /**
         * The kept state after reading [exits] (any order). Only exits newer
         * than the last one read count; the first read of all (no state kept)
         * reads only the newest, so an install never starts stopped for a
         * stop from before the flag existed. The flag is only ever set here;
         * [opened] clears it.
         */
        fun next(kept: State?, exits: List<Exit>): State {
            val newest = exits.maxOfOrNull { it.timestampMs }
            val since = kept?.lastExitMs ?: newest?.let { it - 1 } ?: return kept ?: State(false, 0)
            val stopped = exits.any { it.timestampMs > since && it.userRequested }
            return State(
                stoppedUntilOpened = (kept?.stoppedUntilOpened ?: false) || stopped,
                lastExitMs = maxOf(since, newest ?: since),
            )
        }

        /**
         * The app's ended processes, from Android. An exit at the user's
         * request counts unless it was an update's or a background kill
         * ([userRequested]).
         */
        fun exits(context: Context): List<Exit> {
            val sdk = Build.VERSION.SDK_INT
            val updatedAtMs = updatedAtMs(context)
            return context.getSystemService(ActivityManager::class.java)
                .getHistoricalProcessExitReasons(context.packageName, 0, 0)
                .map { info -> Exit(info.timestamp, userRequested(info.reason, info.description, info.timestamp, updatedAtMs, sdk)) }
        }

        private fun updatedAtMs(context: Context): Long {
            val packages = context.packageManager
            return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                packages.getPackageInfo(context.packageName, PackageManager.PackageInfoFlags.of(0)).lastUpdateTime
            } else {
                @Suppress("DEPRECATION")
                packages.getPackageInfo(context.packageName, 0).lastUpdateTime
            }
        }

        /**
         * Whether an exit for [reason], recorded with [description] at
         * [timestampMs], was the user's own stop.
         *
         * Android records more than Force stop and Task Manager's Stop as
         * the user's request. A background kill (another app's
         * `killBackgroundProcesses`, a memory cleaner, `am kill`) is
         * described as one and is not a stop. Before API 34 an update is
         * recorded as the user's request too, described as the installer's
         * stop; with no description, an exit around the time of the last
         * update is taken for the update's.
         */
        fun userRequested(reason: Int, description: String?, timestampMs: Long, updatedAtMs: Long, sdk: Int): Boolean {
            if (reason != ApplicationExitInfo.REASON_USER_REQUESTED) return false
            if (description != null && description.startsWith(KILL_BACKGROUND)) return false
            if (sdk >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return true
            if (description != null) return !description.contains(INSTALLER_STOP)
            return timestampMs !in (updatedAtMs - UPDATE_SLACK_BEFORE_MS)..(updatedAtMs + UPDATE_SLACK_AFTER_MS)
        }

        /** Kept in a preferences file of its own: it belongs to the install, not to a host's store. */
        fun preferences(context: Context): Store = object : Store {
            private val file by lazy { context.getSharedPreferences(FILE, Context.MODE_PRIVATE) }

            override fun read(): State? = file.takeIf { it.contains(KEY_LAST_EXIT) }?.let {
                State(it.getBoolean(KEY_STOPPED, false), it.getLong(KEY_LAST_EXIT, 0))
            }

            override fun write(state: State) {
                file.edit {
                    putBoolean(KEY_STOPPED, state.stoppedUntilOpened)
                    putLong(KEY_LAST_EXIT, state.lastExitMs)
                }
            }
        }

        private const val FILE = "umsh.background"
        private const val KEY_STOPPED = "stoppedUntilOpened"
        private const val KEY_LAST_EXIT = "lastExitMs"

        /** How Android describes a background kill: "kill background". */
        private const val KILL_BACKGROUND = "kill background"

        /** How API 31–33 describe an update's stop: "stop <package> due to installPackageLI". */
        private const val INSTALLER_STOP = "installPackageLI"

        /**
         * An update ends the process during the install, a moment before its
         * time is recorded (the same second on the API 31 emulator). Used
         * only for an exit with no description: a Force stop this close
         * before an update is then taken for the update's.
         */
        const val UPDATE_SLACK_BEFORE_MS = 10_000L
        const val UPDATE_SLACK_AFTER_MS = 5_000L
    }
}
