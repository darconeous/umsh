package com.voria.umsh.app

import androidx.test.platform.app.InstrumentationRegistry
import java.security.KeyStore
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** Each test gets a host of its own, and leaves nothing behind. */
class HostIsolationTest {
    @get:Rule val fresh = FreshHostRule()

    private val application: TestUmshApplication
        get() = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as TestUmshApplication

    private fun aliases(prefix: String) =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.aliases().toList().filter { it.startsWith(prefix) }

    @Test
    fun aTestStartsWithNothingAndLeavesNothing() = runBlocking<Unit> {
        val first = application.paths!!
        // Nothing from another test: no files, no keys, nothing brought up.
        assertFalse(first.filesDirectory.parentFile!!.exists())
        assertEquals(emptyList<String>(), aliases("${first.keyAliasPrefix}."))
        assertEquals(HostState.Starting, fresh.host.state.value)

        fresh.host.ensureRuntime()
        val minted = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        assertTrue(first.identity.exists())
        assertTrue(aliases("${first.keyAliasPrefix}.").isNotEmpty())

        // What the rule does between tests.
        application.reset()
        assertFalse(first.filesDirectory.parentFile!!.exists())
        assertEquals(emptyList<String>(), aliases("${first.keyAliasPrefix}."))
        val second = application.paths!!
        assertNotEquals(first, second)

        fresh.host.ensureRuntime()
        val next = withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        assertNotEquals(minted.runtime.ownerAddress, next.runtime.ownerAddress)
    }

    private companion object {
        const val TIMEOUT = 30_000L
    }
}
