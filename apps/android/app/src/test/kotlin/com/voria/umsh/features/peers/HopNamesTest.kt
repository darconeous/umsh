package com.voria.umsh.features.peers

import com.voria.umsh.app.StagedHost
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.inspectPublicIdentity
import com.voria.umsh.models.Octets
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Hop names: remembered per hint list until the stored nodes are read again, over a fake and over the real core. */
class HopNamesTest {
    @get:Rule val temp = TemporaryFolder()

    private var staged: StagedHost? = null

    @After
    fun tearDown() = runBlocking<Unit> { staged?.close() }

    private val a = Octets(byteArrayOf(1, 2))
    private val b = Octets(byteArrayOf(3, 4))

    @Test
    fun remembersUntilTheRevisionMoves() = runBlocking {
        val revision = MutableStateFlow(1L)
        var answer = listOf("alpha", null)
        val names = HopNames({ answer }, revision)
        assertEquals(listOf("alpha", null), names.names(listOf(a, b)))
        answer = listOf("beta", null)
        assertEquals("remembered", listOf("alpha", null), names.names(listOf(a, b)))
        assertEquals(1, names.queries)
        revision.value = 2
        assertEquals(listOf("beta", null), names.names(listOf(a, b)))
        assertEquals(2, names.queries)
        assertEquals("no hints, no query", emptyList<String?>(), names.names(emptyList()))
        assertEquals(2, names.queries)
    }

    @Test
    fun aFailedQueryNamesNoneAndIsAskedAgain() = runBlocking {
        var fail = true
        val names = HopNames({ hints -> if (fail) throw MobileAppException.Busy() else hints.map { "x" } }, MutableStateFlow(1L))
        assertEquals(listOf(null, null), names.names(listOf(a, b)))
        fail = false
        assertEquals(listOf("x", "x"), names.names(listOf(a, b)))
        assertEquals(2, names.queries)
    }

    /**
     * Over the staging core: the relay's hint names the relay, a hint nobody
     * owns names none, and a peers change asks again. The counts use a
     * revision of the test's own: the staged air's hearings reload the
     * peers, and so move the runtime's, at moments the test does not choose.
     */
    @Test
    fun theCoreNamesTheRelayAndAPeersChangeAsksAgain() = runBlocking<Unit> {
        val host = StagedHost(temp.newFolder()).also { staged = it }
        val runtime = host.start()
        val relay = address(0x77)
        val relayHint = Octets(inspectPublicIdentity(relay).hint.bytes.copyOf(2))
        val nobody = Octets(byteArrayOf(0x00, 0x01))
        val revision = MutableStateFlow(0L)
        val names = HopNames(runtime::nameRepeaterHints, revision)
        assertEquals(listOf(relay, null), names.names(listOf(relayHint, nobody)))
        assertEquals(1, names.queries)
        names.names(listOf(relayHint, nobody))
        assertEquals("remembered", 1, names.queries)

        runtime.setAlias(relay, "Glen").await()
        revision.value = 1
        assertEquals(listOf(relay, null), names.names(listOf(relayHint, nobody)))
        assertEquals("asked again after the peers changed", 2, names.queries)

        // The runtime's own, on its peers revision, names the same.
        assertEquals(listOf(relay, null), runtime.hopNames.names(listOf(relayHint, nobody)))
        val peers = withTimeout(TIMEOUT) { runtime.hopNames.peers(listOf(relayHint), runtime.appState).first { it.peers.single() != null } }
        assertEquals(relay, peers.peers.single()?.address)
        assertNull(runtime.hopNames.peers(listOf(nobody), runtime.appState).first().peers.single())
    }

    private fun address(seed: Int) =
        MobileIdentity.unlock(ByteArray(32) { seed.toByte() }).use { it.publicIdentity().canonicalAddress }

    private companion object {
        const val TIMEOUT = 30_000L
    }
}
