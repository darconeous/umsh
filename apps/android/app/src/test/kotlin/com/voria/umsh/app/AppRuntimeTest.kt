package com.voria.umsh.app

import com.voria.umsh.core.MobileAppConfigRecord
import com.voria.umsh.core.MobileAppCore
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileAppStore
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.seedStaging
import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.KeyProtection
import com.voria.umsh.services.identity.IdentityOperations
import com.voria.umsh.services.identity.IdentityVaultException
import com.voria.umsh.services.mobilecore.ParityFormat
import com.voria.umsh.services.mobilecore.StoreDetail
import com.voria.umsh.services.preferences.AppPreferences
import com.voria.umsh.services.preferences.OnboardingStep
import java.io.File
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Collections
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import kotlinx.coroutines.CompletableDeferred
import com.voria.umsh.services.mobilecore.AppLog

/**
 * The host and the runtime over the real core (host build, through JNA),
 * with in-memory vaults and temporary files around them.
 */
class AppRuntimeTest {
    @get:Rule val temp = TemporaryFolder()

    private val fixtures = mutableListOf<Fixture>()

    @After
    fun tearDown() = runBlocking<Unit> {
        fixtures.forEach { it.close() }
    }

    private inner class Fixture(clock: Clock = Clock.systemUTC()) {
        val log = VaultLog()
        val vaults = MemoryVaults(log)
        val paths = AppPaths(temp.newFolder(), temp.newFolder())
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val foreground = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
        val preferences = AppPreferences(paths.preferences, scope)
        val host = AppCoreHost(paths, vaults, preferences, { 65026u }, clock, foreground, true, scope)

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

    private suspend fun AppRuntime.running() =
        withTimeout(TIMEOUT) { lifecycle.first { it is MobileAppLifecycle.Running } }

    private suspend fun AppRuntime.stateWhere(predicate: (AppStateSnapshot) -> Boolean): AppStateSnapshot =
        withTimeout(TIMEOUT) { appState.first { it != null && predicate(it) }!! }

    private fun address(seed: Int) =
        MobileIdentity.unlock(ByteArray(32) { seed.toByte() }).use { it.publicIdentity().canonicalAddress }

    /** A first launch mints, the listener carries the start, and the built-in channels show. */
    @Test
    fun aFirstLaunchMintsAndRuns() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.host.ensureRuntime()
        val runtime = fixture.ready()
        assertEquals(listOf("identity.store"), fixture.log.snapshot())
        assertEquals(OnboardingStep.Welcome, runtime.onboarding.value)
        // Only the drain sets Running: the listener was attached before the start.
        runtime.running()
        // The core's bootstrap: both built-in channels joined, and Public's
        // conversation opened. Running publishes after the lists it came
        // with, so a list never reads as empty under it.
        val state = checkNotNull(runtime.appState.value)
        assertEquals(
            setOf("public", "emergency"),
            state.channels.filter { it.joinedPhone }.mapNotNull { it.canonicalName }.toSet(),
        )
        assertEquals(listOf("public"), state.channelConversations.map { it.channel.canonicalName })
        assertEquals(KeyProtection.Software, withTimeout(TIMEOUT) { runtime.identity.first { it.protection == KeyProtection.Software } }.protection)
        assertEquals(1, fixture.host.openCores)
    }

    /** What the core changes reaches the lists through the drain alone. */
    @Test
    fun theDrainCarriesTheCoresChanges() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.host.ensureRuntime()
        val runtime = fixture.ready()
        runtime.running()
        val peer = address(41)
        runtime.core.savePeer(peer, "Ridge", true)
        val state = runtime.stateWhere { snapshot -> snapshot.directConversations.any { it.address == peer } }
        assertEquals("Ridge", state.peers.single { it.address == peer }.alias)
    }

    /** A draft shows at once, and a flush saves it. */
    @Test
    fun draftsShowAtOnceAndFlush() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.host.ensureRuntime()
        val runtime = fixture.ready()
        runtime.running()
        val public = runtime.stateWhere { snapshot -> snapshot.channelConversations.any { it.channel.canonicalName == "public" } }
            .channelConversations.single { it.channel.canonicalName == "public" }.address
        runtime.saveDraft(public, "on my way")
        assertEquals("on my way", runtime.appState.value!!.channelConversations.single { it.address == public }.draftText)
        runtime.flushDrafts().await()
        assertEquals("on my way", runtime.core.state(true).channelConversations.single { it.conversationAddress == public }.draftText)
    }

    /**
     * Staging seeds before the first read, so the first lists published are
     * already the staged mesh: the same peers as the seeded parity golden.
     */
    @Test
    fun stagingSeedsBeforeTheFirstRead() = runBlocking<Unit> {
        val clock = Clock.fixed(Instant.ofEpochMilli(SEEDED_NOW_MS), ZoneOffset.UTC)
        val log = VaultLog()
        val identity = MemoryIdentityVault(log).apply { secret = ByteArray(32) { 5 } }
        val vault = MemorySecretVault("staging", log)
        val store = MobileAppStore.open(temp.newFolder().resolve("staging.sqlite").path)
        val core = MobileAppCore(store, vault, MobileAppConfigRecord(temp.newFolder().path, 65026u))
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        val owner = MobileIdentity.unlock(ByteArray(32) { 5 }).use { it.publicIdentity() }
        val runtime = AppRuntime(
            core = core,
            kind = CoreKind.Staging,
            generation = 1,
            owner = owner,
            identityOps = IdentityOperations(identity),
            protection = { KeyProtection.Software },
            preferences = AppPreferences(File(temp.newFolder(), "p.preferences_pb"), scope),
            initialOnboarding = OnboardingStep.Welcome,
            seed = { ownerId, nowMs -> seedStaging(store, vault, ownerId, nowMs) },
            foregroundSignals = emptyFlow(),
            clock = clock,
            scope = scope,
        )
        // Unconfined: every value the runtime publishes, none conflated away.
        val published = Collections.synchronizedList(mutableListOf<AppStateSnapshot>())
        val watching = launch(Dispatchers.Unconfined, start = CoroutineStart.UNDISPATCHED) {
            runtime.appState.collect { it?.let(published::add) }
        }
        runtime.start()
        runtime.running()
        watching.cancel()

        val golden = File(ParityFormat.directory, "seeded.golden").readLines()
            .takeWhile { !it.startsWith("## transcript") }
            .filter { it.startsWith("peer ") }
        val first = ParityFormat.stateLines(published.first()).filter { it.startsWith("peer ") }
            .sortedWith(ParityFormat::bytewise)
        assertTrue(golden.isNotEmpty())
        assertEquals(golden, first)
        assertEquals(OnboardingStep.Done, runtime.onboarding.value)

        runtime.detach()
        core.stop()
        core.close()
        store.close()
        scope.cancel()
    }

    /** A switch stops the old core and its air before the next opens. */
    @Test
    fun aSwitchLeavesOneCoreAndStopsTheAir() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.host.ensureRuntime(staging = true)
        val staging = fixture.ready(CoreKind.Staging)
        staging.running()
        // The launch extra holds for this process; it is not the stored choice.
        assertFalse(fixture.preferences.stagingEnabled())
        val air = fixture.host.stagingRadio.value!!
        // The staged radio is the core's radio.
        withTimeout(TIMEOUT) { staging.radio.first { it != null } }
        assertTrue(staging.stateWhere { it.peers.isNotEmpty() }.peers.isNotEmpty())

        fixture.host.setStaging(false).join()
        val live = fixture.ready(CoreKind.Live, after = staging.generation)
        assertTrue(air.isStopped)
        assertNull(fixture.host.stagingRadio.value)
        assertEquals(1, fixture.host.openCores)
        live.running()
        // Read, and none: not merely unread.
        withTimeout(TIMEOUT) { live.radioKnown.first { it } }
        assertNull(live.radio.value)
        assertEquals(staging.ownerAddress, live.ownerAddress)
    }

    /**
     * Erase identity: the secret goes first, then the keys under it, and the
     * other kind's counters; then a new identity comes up at Welcome.
     */
    @Test
    fun eraseTakesTheSecretFirstThenMints() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.host.ensureRuntime()
        val before = fixture.ready()
        before.running()
        before.setOnboarding(OnboardingStep.Done).await()
        val stagingCounters = fixture.paths.counters(CoreKind.Staging).apply { mkdirs() }
        File(stagingCounters, "reservation").writeText("x")

        val outcome = fixture.host.erase(EraseMode.IdentityOnly, thenMint = true).await()
        assertEquals(EraseOutcome.Done, outcome)
        val events = fixture.log.snapshot()
        val deleted = events.indexOf("identity.delete")
        assertTrue(events.toString(), deleted >= 0 && deleted < events.indexOf("live.deleteAll"))
        assertFalse(stagingCounters.exists())

        val after = fixture.ready(after = before.generation)
        assertNotEquals(before.ownerAddress, after.ownerAddress)
        assertEquals(OnboardingStep.Welcome, after.onboarding.value)
        after.running()
        assertEquals(1, fixture.host.openCores)
    }

    /** A secret that will not go stops the erase there, and the phone stays the node it was. */
    @Test
    fun aFailedSecretDeleteChangesNothingElse() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.host.ensureRuntime()
        val before = fixture.ready()
        before.running()
        val peer = address(42)
        before.core.savePeer(peer, null, true)
        before.stateWhere { snapshot -> snapshot.peers.any { it.address == peer } }
        fixture.vaults.identity.failDelete = IdentityVaultException.Unavailable("test")

        val outcome = fixture.host.erase(EraseMode.Everything, thenMint = false).await()
        assertTrue(outcome is EraseOutcome.Failed)
        assertFalse(fixture.log.snapshot().any { it.endsWith(".deleteAll") })

        val after = fixture.ready(after = before.generation)
        assertEquals(before.ownerAddress, after.ownerAddress)
        after.stateWhere { snapshot -> snapshot.peers.any { it.address == peer } }
    }

    /** A delete that threw after the secret went still erased it: the erase goes on, nothing minted over the old keys. */
    @Test
    fun aDeleteThatFailsAfterTheSecretWentStillErases() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.host.ensureRuntime()
        val before = fixture.ready()
        before.running()
        fixture.vaults.identity.failDelete = IdentityVaultException.Unavailable("test")
        fixture.vaults.identity.failDeleteAfterForgetting = true

        assertEquals(EraseOutcome.Done, fixture.host.erase(EraseMode.IdentityOnly, thenMint = false, announce = false).await())
        assertEquals(HostState.NeedsFirstLaunch, fixture.host.state.value)
        assertTrue(fixture.log.snapshot().contains("live.deleteAll"))
    }

    /**
     * The core could not erase (its channel keys would not go): Erase
     * identity keeps the store it promised to keep, and says it did not
     * finish rather than Done.
     */
    @Test
    fun anEraseLeavingKeysIsIncompleteAndKeepsTheStore() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.host.ensureRuntime()
        val before = fixture.ready()
        before.running()
        fixture.vaults.live.failDeleteAll = IllegalStateException("not ready")

        val outcome = fixture.host.erase(EraseMode.IdentityOnly, thenMint = false).await()
        assertTrue(outcome.toString(), outcome is EraseOutcome.Incomplete)
        assertTrue((outcome as EraseOutcome.Incomplete).details.contains("live channel keys"))
        assertEquals(outcome, fixture.host.eraseFailure.value)
        assertNull(fixture.vaults.identity.secret)
        assertTrue(fixture.paths.store(CoreKind.Live).exists())
        assertEquals(HostState.NeedsFirstLaunch, fixture.host.state.value)
    }

    /** Staging never erases the live identity (D16), whatever asks. */
    @Test
    fun stagingRefusesToErase() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.host.ensureRuntime()
        val live = fixture.ready()
        live.running()
        fixture.host.setStaging(true).join()
        val staged = fixture.ready(CoreKind.Staging)

        assertEquals(EraseOutcome.Refused, fixture.host.erase(EraseMode.IdentityOnly, thenMint = true).await())
        assertNull(fixture.host.eraseFailure.value)
        assertFalse(fixture.log.snapshot().contains("identity.delete"))
        assertSame(staged, (fixture.host.state.value as HostState.Ready).runtime)
    }

    /** A store that will not open is erased by its files, and the next launch starts clean. */
    @Test
    fun anUnopenableStoreIsErasedByFiles() = runBlocking<Unit> {
        val fixture = Fixture()
        val store = fixture.paths.store(CoreKind.Live).apply { parentFile!!.mkdirs() }
        store.writeBytes(ByteArray(8192) { (it * 31).toByte() })
        fixture.host.ensureRuntime()
        val unavailable = fixture.state { it is HostState.StoreUnavailable } as HostState.StoreUnavailable
        val detail = unavailable.detail
        assertTrue(detail.toString(), detail is StoreDetail.Failed && detail.code == 26)

        assertEquals(EraseOutcome.Done, fixture.host.erase(EraseMode.Everything, thenMint = false).await())
        assertEquals(HostState.NeedsFirstLaunch, fixture.host.state.value)
        assertFalse(store.exists())
        assertTrue(fixture.log.snapshot().contains("live.deleteAll"))

        fixture.host.ensureRuntime()
        fixture.ready().running()
    }

    /** A Keystore that is not ready mints nothing, and the next foreground tries again. */
    @Test
    fun anUnavailableIdentityIsRetriedOnForeground() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.vaults.identity.failLoad = IdentityVaultException.Unavailable("test")
        fixture.host.ensureRuntime()
        fixture.state { it is HostState.IdentityUnavailable }
        assertNull(fixture.vaults.identity.secret)

        fixture.vaults.identity.failLoad = null
        fixture.foreground.emit(Unit)
        fixture.ready().running()
    }

    /** A stored secret that cannot be opened is reported, never minted over. */
    @Test
    fun aLostIdentityIsNeverMintedOver() = runBlocking<Unit> {
        val fixture = Fixture()
        val stored = ByteArray(32) { 9 }
        fixture.vaults.identity.secret = stored
        fixture.vaults.identity.failLoad = IdentityVaultException.Lost("AEADBadTagException")
        fixture.host.ensureRuntime()
        val lost = fixture.state { it is HostState.IdentityLost } as HostState.IdentityLost
        assertEquals("AEADBadTagException", lost.detail)
        assertTrue(stored.contentEquals(fixture.vaults.identity.secret))
        assertFalse(fixture.log.snapshot().contains("identity.store"))
    }

    /** A start whose unlock the Keystore refuses for now is tried again on the next foreground. */
    @Test
    fun aFailedUnlockIsRetriedOnForeground() = runBlocking<Unit> {
        // The runtime logs the failed unlock once the retry is armed: the
        // foreground below is sent only after that, never on a timer.
        val unlockFailed = CompletableDeferred<Unit>()
        val previous = AppLog.sink
        AppLog.sink = AppLog.Sink { level, tag, message ->
            if (message.startsWith("identity not unlocked")) unlockFailed.complete(Unit)
            previous.write(level, tag, message)
        }
        try {
            val fixture = Fixture()
            // Load 1 is the host's (it mints); load 2 is the runtime's unlock.
            fixture.vaults.identity.failLoadCalls = mapOf(2 to IdentityVaultException.Unavailable("test"))
            fixture.host.ensureRuntime()
            val runtime = fixture.ready()
            withTimeout(TIMEOUT) { unlockFailed.await() }
            // Nothing started without the identity.
            assertTrue(runtime.lifecycle.value is MobileAppLifecycle.Idle)

            fixture.foreground.emit(Unit)
            runtime.running()
        } finally {
            AppLog.sink = previous
        }
    }

    /** An identity found lost at the start replaces the runtime with the lost state. */
    @Test
    fun anUnlockThatFindsTheIdentityLostIsShown() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.vaults.identity.failLoadCalls = mapOf(2 to IdentityVaultException.Lost("KeyPermanentlyInvalidatedException"))
        fixture.host.ensureRuntime()
        val lost = fixture.state { it is HostState.IdentityLost } as HostState.IdentityLost
        assertEquals("KeyPermanentlyInvalidatedException", lost.detail)
        assertEquals(0, fixture.host.openCores)
    }

    /** A staging store that will not open does not keep the switch from going back to live. */
    @Test
    fun anUnopenableStagingStoreCanBeLeft() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.paths.store(CoreKind.Staging).apply { parentFile!!.mkdirs() }
            .writeBytes(ByteArray(8192) { (it * 31).toByte() })
        fixture.host.ensureRuntime(staging = true)
        fixture.state { it is HostState.StoreUnavailable }

        fixture.host.setStaging(false).join()
        fixture.ready(CoreKind.Live).running()
    }

    /** A damaged preferences file reads as defaults instead of failing every launch. */
    @Test
    fun aDamagedPreferencesFileReadsAsDefaults() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.paths.preferences.apply { parentFile!!.mkdirs() }.writeBytes(ByteArray(64) { 0x7f })
        fixture.host.ensureRuntime()
        fixture.ready().running()
    }

    /**
     * Welcome's Continue can come before the start has set the owner: the
     * save waits for the start rather than failing with no owner.
     */
    @Test
    fun aNameSavedAsTheRuntimeComesUpWaitsForTheOwner() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.host.ensureRuntime()
        // At once: Ready is published as soon as the runtime is made, before its start.
        val runtime = fixture.ready()
        assertEquals("Juniper", runtime.saveName("  Juniper ").await())
        runtime.running()
        assertEquals("Juniper", runtime.identity.value.advertisedName)
        assertEquals("Juniper", runtime.core.state(true).advertisedName)
    }

    /** A failed in-app erase is announced by the host, which outlives the shell that asked; Manage space's is not. */
    @Test
    fun aFailedEraseIsAnnouncedOnlyWhenAsked() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.host.ensureRuntime()
        fixture.ready().running()
        fixture.vaults.identity.failDelete = IdentityVaultException.Unavailable("test")

        assertTrue(fixture.host.erase(EraseMode.IdentityOnly, thenMint = false, announce = false).await() is EraseOutcome.Failed)
        assertNull(fixture.host.eraseFailure.value)
        assertTrue(fixture.host.erase(EraseMode.IdentityOnly, thenMint = true).await() is EraseOutcome.Failed)
        assertTrue((fixture.host.eraseFailure.value as? EraseOutcome.Failed)?.error is IdentityVaultException.Unavailable)
        fixture.host.dismissEraseFailure()
        assertNull(fixture.host.eraseFailure.value)
    }

    /**
     * Manage space's figures: read with or without a running core, never
     * minting, the name from the live store, and the identity gone after
     * Erase identity while the content stays.
     */
    @Test
    fun theStorageSummaryStartsNothing() = runBlocking<Unit> {
        val fixture = Fixture()
        // Nothing stored yet: no identity, and nothing minted by asking.
        val empty = fixture.host.storageSummary()
        assertNull(empty.identity)
        assertFalse(empty.identityStored)
        assertEquals(0, fixture.host.openCores)
        assertTrue(fixture.log.snapshot().none { it == "identity.store" })

        fixture.host.ensureRuntime()
        val runtime = fixture.ready()
        runtime.saveName("Juniper").await()
        runtime.running()
        val running = fixture.host.storageSummary()
        assertEquals("Juniper", running.identity?.name)
        assertEquals(runtime.identity.value.hint, running.identity?.hint)
        assertTrue(running.contentBytes > 0)
        assertFalse(running.stagingOn)

        // A process started for Manage space: the store, not a running core.
        fixture.host.shutdown()
        val stopped = fixture.host.storageSummary()
        assertEquals("Juniper", stopped.identity?.name)
        assertEquals(0, fixture.host.openCores)

        assertEquals(EraseOutcome.Done, fixture.host.erase(EraseMode.IdentityOnly, thenMint = false, announce = false).await())
        assertEquals(HostState.NeedsFirstLaunch, fixture.host.state.value)
        val erased = fixture.host.storageSummary()
        assertNull(erased.identity)
        assertFalse(erased.identityStored)
        assertTrue(erased.contentBytes > 0)
    }

    /**
     * A repeat of the erase under way shares its answer; a different one
     * runs after it, and answers for its own erasure: Start over in
     * Manage space never finishes on an in-app Erase identity's Done.
     */
    @Test
    fun onlyTheSameEraseSharesAnAnswer() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.host.ensureRuntime()
        fixture.ready().running()

        val identityOnly = fixture.host.erase(EraseMode.IdentityOnly, thenMint = true)
        val repeat = fixture.host.erase(EraseMode.IdentityOnly, thenMint = true)
        val everything = fixture.host.erase(EraseMode.Everything, thenMint = false, announce = false)
        assertSame(identityOnly, repeat)
        assertNotSame(identityOnly, everything)

        assertEquals(EraseOutcome.Done, everything.await())
        assertEquals(EraseOutcome.Done, identityOnly.await())
        // Everything ran last: nothing minted, so the next launch is a first one.
        assertEquals(HostState.NeedsFirstLaunch, fixture.host.state.value)
        assertFalse(fixture.host.storageSummary().identityStored)
    }

    /** While the staging core runs, Manage space's figures open no core over the live store: one core at a time. */
    @Test
    fun theStorageSummaryLeavesTheLiveStoreAloneWhileStaging() = runBlocking<Unit> {
        val fixture = Fixture()
        fixture.host.ensureRuntime(staging = false)
        val live = fixture.ready()
        live.saveName("Juniper").await()
        live.running()

        fixture.host.setStaging(true).join()
        val staging = fixture.ready(CoreKind.Staging, after = live.generation)
        staging.running()
        val summary = fixture.host.storageSummary()
        assertTrue(summary.stagingOn)
        assertEquals(live.identity.value.hint, summary.identity?.hint)
        // The name is the live store's, which only a second core could read.
        assertEquals("", summary.identity?.name)
        assertEquals(1, fixture.host.openCores)
    }

    private companion object {
        const val TIMEOUT = 30_000L

        /** The seeded parity store's `now_ms`. */
        const val SEEDED_NOW_MS = 1_790_000_000_000L
    }
}
