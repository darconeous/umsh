package com.voria.umsh.app

import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.services.preferences.AppPreferences
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import com.voria.umsh.services.radio.RadioLinkFactory
import com.voria.umsh.services.radio.RecordingRadioConnection
import java.time.Clock
import java.util.Collections
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * The host's radio: made with the live core from what the registry names,
 * torn down in order, one at a time; and the start that may not mint.
 */
class RadioHostTest {
    @get:Rule val temp = TemporaryFolder()

    private val fixtures = mutableListOf<Fixture>()

    @After
    fun tearDown() = runBlocking<Unit> {
        fixtures.forEach { it.close() }
    }

    private inner class Fixture {
        val log = VaultLog()
        val vaults = MemoryVaults(log)
        val paths = AppPaths(temp.newFolder(), temp.newFolder())
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val foreground = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
        val preferences = AppPreferences(paths.preferences, scope)
        val made: MutableList<RecordingRadioConnection> = Collections.synchronizedList(mutableListOf())
        val links = RadioLinkFactory { radio, registry, events ->
            RecordingRadioConnection(radio.linkId, registry, events, log.events).also {
                log.events += "made ${radio.linkId}"
                made += it
            }
        }
        val host = AppCoreHost(paths, vaults, preferences, { 65026u }, Clock.systemUTC(), foreground, true, scope, radioLinks = links)
        val registry get() = preferences.radioRegistry

        init {
            fixtures += this
        }

        suspend fun state(predicate: (HostState) -> Boolean): HostState =
            withTimeout(TIMEOUT) { host.state.first(predicate) }

        suspend fun ready(kind: CoreKind = CoreKind.Live, after: Long = 0): AppRuntime {
            val ready = state { it is HostState.Ready && it.runtime.kind == kind && it.runtime.generation > after }
            return (ready as HostState.Ready).runtime
        }

        suspend fun close() {
            withTimeout(TIMEOUT) { host.shutdown() }
            scope.cancel()
        }
    }

    private suspend fun until(predicate: () -> Boolean) = withTimeout(TIMEOUT) {
        while (!predicate()) delay(20)
    }

    private val bridged = BoundRadio(RadioKind.Tcp, "10.0.2.2:21838")

    // region Starting without a person

    @Test
    fun aHeadlessStartNeverMints() = runBlocking<Unit> {
        val fixture = Fixture()
        assertFalse(fixture.host.ensureRuntime(origin = StartOrigin.Headless).await())
        assertEquals(HostState.NeedsFirstLaunch, fixture.host.state.value)
        assertTrue(fixture.log.snapshot().none { it == "identity.store" })
        assertEquals(0, fixture.host.openCores)
        // The person's own start mints, as a first launch always has.
        fixture.host.ensureRuntime()
        fixture.ready()
        assertEquals(1, fixture.log.snapshot().count { it == "identity.store" })
    }

    @Test
    fun aHeadlessStartRunsTheStoredIdentity() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.vaults.identity.secret = ByteArray(32) { 9 }
        assertTrue(fixture.host.ensureRuntime(origin = StartOrigin.Headless).await())
        fixture.ready(CoreKind.Live)
        assertTrue(fixture.log.snapshot().none { it == "identity.store" })
    }

    /** Headless never switches kinds: with staging wanted, it starts nothing, and says so. */
    @Test
    fun aHeadlessStartLeavesStagingAlone() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.vaults.identity.secret = ByteArray(32) { 9 }
        fixture.preferences.setStagingEnabled(true)
        assertFalse(fixture.host.ensureRuntime(origin = StartOrigin.Headless).await())
        assertEquals(HostState.Starting, fixture.host.state.value)
        assertEquals(0, fixture.host.openCores)
    }

    // endregion

    // region One radio, owned by the host

    @Test
    fun theLiveCoreTakesTheBoundRadioAndConnects() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.registry.bind(bridged)
        fixture.host.ensureRuntime()
        val runtime = fixture.ready()
        val connection = fixture.made.single()
        assertSame(connection, fixture.host.radio.value)
        until { "autoConnect" in connection.log }
        // Its state reaches the screens through the core alone.
        withTimeout(TIMEOUT) { runtime.radio.first { it?.phase == MobileRadioPhase.CONNECTING } }
    }

    @Test
    fun aRadioNotWantedIsHeldButNotConnected() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.registry.bind(bridged.copy(autoConnect = false))
        fixture.host.ensureRuntime()
        fixture.ready()
        val connection = fixture.made.single()
        delay(300)
        assertFalse("autoConnect" in connection.log)
    }

    /** Staging and back: the live radio closes with its core, and one comes back with the next. */
    @Test
    fun switchingToStagingAndBackLeavesOneRadio() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.registry.bind(bridged)
        fixture.host.ensureRuntime()
        val live = fixture.ready()
        val first = fixture.made.single()
        fixture.host.setStaging(true)
        fixture.ready(CoreKind.Staging, after = live.generation)
        assertTrue("close" in first.log)
        assertNull(fixture.host.radio.value)
        fixture.host.setStaging(false)
        fixture.ready(CoreKind.Live, after = live.generation + 1)
        assertEquals(2, fixture.made.size)
        assertFalse("close" in fixture.made[1].log)
        assertSame(fixture.made[1], fixture.host.radio.value)
    }

    /** The radio stops before the secret goes, and the new identity gets it back. */
    @Test
    fun eraseStopsTheRadioFirst() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.registry.bind(bridged)
        fixture.host.ensureRuntime()
        val runtime = fixture.ready()
        runtime.running()
        assertEquals(EraseOutcome.Done, fixture.host.erase(EraseMode.IdentityOnly, thenMint = true).await())
        val events = fixture.log.snapshot()
        assertTrue(events.toString(), events.indexOf("close") in 0 until events.indexOf("identity.delete"))
        fixture.ready(after = runtime.generation)
        assertEquals(2, fixture.made.size)
        assertEquals(bridged, fixture.registry.bound())
    }

    @Test
    fun disconnectKeepsTheRadioButNotTheIntent() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.registry.bind(bridged)
        fixture.host.ensureRuntime()
        fixture.ready()
        val connection = fixture.made.single()
        fixture.host.disconnectRadio().join()
        // The host key goes while the link can still carry it.
        assertTrue(connection.log.toString(), connection.log.indexOf("release") in 0 until connection.log.indexOf("stop"))
        assertEquals(bridged.copy(autoConnect = false), fixture.registry.bound())
        assertSame(connection, fixture.host.radio.value)
    }

    /** Disconnect while the staging core holds no live radio: the intent still goes. */
    @Test
    fun disconnectWhileStagingRunsKeepsTheRadioDown() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.registry.bind(bridged)
        fixture.host.ensureRuntime()
        val live = fixture.ready()
        fixture.host.setStaging(true)
        fixture.ready(CoreKind.Staging, after = live.generation)
        fixture.host.disconnectRadio().join()
        assertEquals(bridged.copy(autoConnect = false), fixture.registry.bound())
        fixture.host.setStaging(false)
        fixture.ready(CoreKind.Live, after = live.generation + 1)
        val second = fixture.made.last()
        delay(300)
        assertFalse("autoConnect" in second.log)
    }

    @Test
    fun connectingAnotherRadioLetsTheFirstGo() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.registry.bind(bridged)
        fixture.host.ensureRuntime()
        fixture.ready()
        val first = fixture.made.single()
        val other = BoundRadio(RadioKind.Tcp, "10.0.2.2:21839")
        fixture.host.connectRadio(other).bound.join()
        // The old radio's host key goes before its connection does.
        assertTrue(first.log.toString(), first.log.indexOf("release") in 0 until first.log.indexOf("close"))
        val second = fixture.made.last()
        assertSame(second, fixture.host.radio.value)
        assertEquals(listOf("connect"), second.log.filter { it == "connect" || it == "autoConnect" })
        assertEquals(other, fixture.registry.bound())
    }

    @Test
    fun forgetLetsTheRadioGo() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.registry.bind(bridged)
        fixture.host.ensureRuntime()
        val runtime = fixture.ready()
        val connection = fixture.made.single()
        fixture.host.forgetRadio().join()
        assertTrue("releaseBinding" in connection.log)
        assertTrue("close" in connection.log)
        assertNull(fixture.registry.bound())
        assertNull(fixture.host.radio.value)
        withTimeout(TIMEOUT) { runtime.radio.first { it == null } }
    }

    /** A radio this phone had before an attempt to choose it again: let go, but still associated. */
    @Test
    fun forgetCanKeepTheBinding() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.registry.bind(bridged)
        fixture.host.ensureRuntime()
        fixture.ready()
        val connection = fixture.made.single()
        fixture.host.forgetRadio(keepBinding = true).join()
        assertFalse("releaseBinding" in connection.log)
        assertTrue("close" in connection.log)
        assertNull(fixture.registry.bound())
    }

    // endregion

    // region The radio's own hooks

    /**
     * A factory reset: the binding goes at once and nothing reconnects, but
     * the link stays up so the command reaches the radio; once it drops,
     * the radio is let go.
     */
    @Test
    fun aFactoryResetLetsTheRadioGoOnceItsLinkDrops() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.registry.bind(bridged)
        fixture.host.ensureRuntime()
        fixture.ready()
        val connection = fixture.made.single()
        until { "autoConnect" in connection.log }
        connection.linkForTests.abandonBinding()
        until { "abandon" in connection.log }
        withTimeout(TIMEOUT) { fixture.registry.bound.first { it == null } }
        assertSame(connection, fixture.host.radio.value)
        assertFalse("close" in connection.log)

        connection.dropFromRadio()
        until { fixture.host.radio.value == null }
        assertTrue("releaseBinding" in connection.log)
        until { "close" in connection.log }
    }

    /**
     * Connect on the radio a factory reset let go, before its link drops:
     * remembered again, and kept when the link then drops.
     */
    @Test
    fun connectAfterAFactoryResetKeepsTheRadio() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.registry.bind(bridged)
        fixture.host.ensureRuntime()
        fixture.ready()
        val connection = fixture.made.single()
        until { "autoConnect" in connection.log }
        connection.linkForTests.abandonBinding()
        withTimeout(TIMEOUT) { fixture.registry.bound.first { it == null } }

        fixture.host.connectRadio(bridged).bound.join()
        assertEquals(bridged, fixture.registry.bound())
        assertEquals(1, fixture.made.size)
        connection.dropFromRadio()
        delay(300)
        assertFalse("releaseBinding" in connection.log)
        assertSame(connection, fixture.host.radio.value)
        assertEquals(bridged, fixture.registry.bound())
    }

    /** DFU: nothing reconnects, and the binding stays for the radio coming back. */
    @Test
    fun dfuKeepsTheBinding() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.registry.bind(bridged)
        fixture.host.ensureRuntime()
        fixture.ready()
        val connection = fixture.made.single()
        connection.linkForTests.didEnterDfu()
        until { "dfu" in connection.log }
        withTimeout(TIMEOUT) { fixture.registry.bound.first { it == bridged.copy(autoConnect = false) } }
        delay(200)
        assertSame(connection, fixture.host.radio.value)
        assertFalse("releaseBinding" in connection.log)
    }

    // endregion

    private suspend fun AppRuntime.running() =
        withTimeout(TIMEOUT) { lifecycle.first { it is com.voria.umsh.core.MobileAppLifecycle.Running } }

    private companion object {
        const val TIMEOUT = 20_000L
    }
}
