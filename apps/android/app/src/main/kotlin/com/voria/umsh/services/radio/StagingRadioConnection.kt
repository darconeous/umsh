package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileAppCore
import com.voria.umsh.core.MobileStagingAir
import com.voria.umsh.services.mobilecore.AppLog
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * The staged mesh's radio, handed to the staging core (debug builds only).
 *
 * The air's state directory survives relaunches, so the staged nodes keep
 * their counters. Teardown follows the host's order: the core lets the radio
 * go and stops, then [stop] ends the air for good.
 */
class StagingRadioConnection private constructor(val air: MobileStagingAir) {
    /** Staged actions outlive the screen that asked for them, as iOS's background tasks do. */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** Bring the staged radio's link up or down. */
    fun setLinkUp(up: Boolean) {
        runCatching { if (up) air.connect() else air.disconnect() }
            .onFailure { AppLog.w(TAG, "staged link not changed: ${it.javaClass.simpleName}") }
    }

    /** Whether every transmission the staged radio makes fails; the air keeps no getter. */
    @Volatile
    var transmissionsFailing = false
        private set

    fun setTransmissionsFailing(failing: Boolean) {
        runCatching { air.setTransmissionsFailing(failing) }
            .onSuccess { transmissionsFailing = failing }
            .onFailure { AppLog.w(TAG, "staged transmissions not changed: ${it.javaClass.simpleName}") }
    }

    /**
     * A staged peer acts after [delayMs]: long enough to leave the screen,
     * which is the point of testing what arrives while elsewhere.
     */
    fun later(delayMs: Long, action: suspend MobileStagingAir.() -> Unit) {
        scope.launch {
            delay(delayMs)
            if (isStopped) return@launch
            try {
                air.action()
            } catch (error: Exception) {
                AppLog.w(TAG, "staged action failed: ${error.javaClass.simpleName}")
            }
        }
    }

    @Volatile
    var isStopped = false
        private set

    /** Final: a stopped air is never restarted; the next staging start makes another. */
    fun stop() {
        if (isStopped) return
        isStopped = true
        scope.cancel()
        runCatching { air.stop() }
        air.close()
    }

    companion object {
        private const val TAG = "umsh.staging"

        /**
         * Start the air and give [core] its radio. Null when the air will not
         * start or the core will not take it: staging then runs with no
         * radio, so it can still be switched off.
         */
        suspend fun attach(core: MobileAppCore, stateDirectory: File, wifiScanOnly: Boolean): StagingRadioConnection? {
            val air = try {
                stateDirectory.mkdirs()
                MobileStagingAir.start(stateDirectory.path, wifiScanOnly)
            } catch (error: Exception) {
                AppLog.e(TAG, "staged air did not start: ${error.javaClass.simpleName}")
                return null
            }
            val connection = StagingRadioConnection(air)
            return try {
                air.connect()
                core.useRadio(air.radio())
                AppLog.i(TAG, "staged radio attached")
                connection
            } catch (error: Exception) {
                AppLog.e(TAG, "staged radio not taken: ${error.javaClass.simpleName}")
                connection.stop()
                null
            }
        }
    }
}
