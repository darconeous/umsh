package com.voria.umsh.app

import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileAppPingResult
import com.voria.umsh.core.MobileIdentity
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/** The staged air's failure wrapper on the device: what the screens' tests arrange with it. */
class StagedAirTest {
    @get:Rule val fresh = FreshHostRule()

    private fun runtime(): AppRuntime = runBlocking {
        fresh.host.ensureRuntime(true)
        val ready = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        withTimeout(TIMEOUT) { ready.runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        withTimeout(TIMEOUT) { ready.runtime.radio.first { it?.carriesThisPhone == true } }
        ready.runtime
    }

    private val managed =
        MobileIdentity.unlock(ByteArray(32) { 0x22 }).use { it.publicIdentity().canonicalAddress }

    @Test
    fun anUnreachableRepeaterLetsAPingTimeOut() = runBlocking<Unit> {
        val runtime = runtime()
        fresh.stagedAir.setRemoteDeviceReachable(false)
        val result = withTimeout(PING_BUDGET_MS) { runtime.core.ping(managed, null) }
        assertEquals(MobileAppPingResult.TimedOut, result)
    }

    private companion object {
        const val TIMEOUT = 30_000L

        /** About 68 s measured on the staged air, with room. */
        const val PING_BUDGET_MS = 120_000L
    }
}
