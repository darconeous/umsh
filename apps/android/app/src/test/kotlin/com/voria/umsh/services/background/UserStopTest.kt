package com.voria.umsh.services.background

import android.app.ApplicationExitInfo
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** DP-84 and DP-94: a deliberate stop holds until the app is opened, across process starts; an update is not one. */
class UserStopTest {
    private val scope = CoroutineScope(Dispatchers.Default)

    @After
    fun tearDown() {
        scope.cancel()
    }

    /** The kept state, as the preferences file would hold it. */
    private class MemoryStore : UserStop.Store {
        @Volatile var state: UserStop.State? = null

        override fun read() = state

        override fun write(state: UserStop.State) {
            this.state = state
        }
    }

    private fun stop(at: Long) = UserStop.Exit(at, userRequested = true)

    private fun other(at: Long) = UserStop.Exit(at, userRequested = false)

    /** One process start over [store], with Android's records [exits]. */
    private fun process(store: MemoryStore, vararg exits: UserStop.Exit) = UserStop(store, { exits.toList() }, scope)

    @Test
    fun aForceStopHoldsThroughLaterProcessStartsUntilOpened() = runBlocking<Unit> {
        val store = MemoryStore()
        assertFalse(process(store, other(100)).stopped())
        // Force stop; the presence wake starts a process.
        assertTrue(process(store, stop(200), other(100)).stopped())
        // That process is killed some other way; the rebind starts another.
        assertTrue(process(store, other(300), stop(200), other(100)).stopped())
        // An update ends the next one (API 34+ records its own reason).
        assertTrue(process(store, other(400), other(300), stop(200), other(100)).stopped())
        // The user opens the app in a later process.
        val opened = process(store, other(500), other(400), other(300), stop(200))
        assertTrue(opened.stopped())
        opened.opened()
        withTimeout(5_000) { while (store.state?.stoppedUntilOpened != false) delay(10) }
        assertFalse(opened.stopped())
        // The old stop is never read again.
        assertFalse(process(store, other(600), other(500), other(400), other(300), stop(200)).stopped())
        // A new one is.
        assertTrue(process(store, stop(700), other(600)).stopped())
    }

    @Test
    fun openingInTheProcessThatReadTheStopClearsIt() = runBlocking<Unit> {
        val store = MemoryStore()
        process(store, other(100)).stopped()
        // Opened before this process has read the records: the read never undoes it.
        val process = process(store, stop(200), other(100))
        process.opened()
        withTimeout(5_000) { while (store.state != UserStop.State(false, 200)) delay(10) }
        assertFalse(process.stopped())
    }

    @Test
    fun theFirstReadCountsOnlyTheNewestExit() {
        // A stop from before anything was kept, followed by other exits: not this install's concern.
        assertFalse(UserStop.next(null, listOf(other(300), stop(200))).stoppedUntilOpened)
        assertTrue(UserStop.next(null, listOf(stop(300), other(200))).stoppedUntilOpened)
        assertEquals(UserStop.State(false, 0), UserStop.next(null, emptyList()))
    }

    @Test
    fun anUpdateIsNotTheUsersStop() {
        val user = ApplicationExitInfo.REASON_USER_REQUESTED
        val updatedAt = 1_000_000L
        // API 31–33: an update reads as the user's request, described as the installer's stop.
        assertFalse(UserStop.userRequested(user, INSTALLER, updatedAt - 800, updatedAt, sdk = 31))
        assertFalse(UserStop.userRequested(user, INSTALLER, updatedAt - 120_000, updatedAt, sdk = 33))
        // A Force stop right before or after an update is still the user's.
        assertTrue(UserStop.userRequested(user, FORCE_STOP, updatedAt - 800, updatedAt, sdk = 31))
        assertTrue(UserStop.userRequested(user, FORCE_STOP, updatedAt + 1_000, updatedAt, sdk = 33))
        // With no description, the time of the last update tells them apart.
        assertFalse(UserStop.userRequested(user, null, updatedAt - 800, updatedAt, sdk = 31))
        assertFalse(UserStop.userRequested(user, null, updatedAt + 1_000, updatedAt, sdk = 33))
        assertTrue(UserStop.userRequested(user, null, updatedAt - 15_000, updatedAt, sdk = 31))
        assertTrue(UserStop.userRequested(user, null, updatedAt + 60_000, updatedAt, sdk = 31))
        // API 34 and later record an update as its own reason.
        assertTrue(UserStop.userRequested(user, FORCE_STOP, updatedAt, updatedAt, sdk = 34))
        assertTrue(UserStop.userRequested(user, null, updatedAt, updatedAt, sdk = 34))
        assertFalse(UserStop.userRequested(PACKAGE_UPDATED, null, updatedAt, updatedAt, sdk = 36))
        assertFalse(UserStop.userRequested(ApplicationExitInfo.REASON_LOW_MEMORY, null, 0, updatedAt, sdk = 36))
    }

    @Test
    fun aBackgroundKillIsNotTheUsersStop() {
        // Another app's killBackgroundProcesses, a memory cleaner, or `am kill`, as the API 31 and 36 emulators record it.
        val user = ApplicationExitInfo.REASON_USER_REQUESTED
        for (sdk in listOf(31, 33, 34, 36)) {
            assertFalse(UserStop.userRequested(user, "kill background", 5_000_000, 1_000_000, sdk))
            assertTrue(UserStop.userRequested(user, FORCE_STOP, 5_000_000, 1_000_000, sdk))
        }
    }

    @Test
    fun theUpdateBroadcastStartsTheServiceOnlyBelow36() {
        assertTrue(AppUpdatedReceiver.startsService(31))
        assertTrue(AppUpdatedReceiver.startsService(35))
        assertFalse(AppUpdatedReceiver.startsService(36))
    }

    private companion object {
        /** `ApplicationExitInfo.REASON_PACKAGE_UPDATED`, API 34. */
        const val PACKAGE_UPDATED = 16

        /** The descriptions the API 31 emulator records for an update's stop and a Force stop. */
        const val INSTALLER = "stop com.voria.umsh due to installPackageLI"
        const val FORCE_STOP = "stop com.voria.umsh due to from pid 1983"
    }
}
