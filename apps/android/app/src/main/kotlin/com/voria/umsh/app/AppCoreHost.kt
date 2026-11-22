package com.voria.umsh.app

import com.voria.umsh.core.MobileAppConfigRecord
import com.voria.umsh.core.MobileAppCore
import com.voria.umsh.core.MobileAppStore
import com.voria.umsh.core.MobileStoreException
import com.voria.umsh.core.SecretVault
import com.voria.umsh.core.seedStaging
import com.voria.umsh.services.identity.IdentityOperations
import com.voria.umsh.services.identity.IdentityVault
import com.voria.umsh.services.identity.IdentityVaultException
import com.voria.umsh.models.NodeHint
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.mobilecore.RecordMapping
import com.voria.umsh.services.mobilecore.StoreDetail
import com.voria.umsh.services.preferences.AppPreferences
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.services.radio.StagingRadioConnection
import java.io.File
import java.io.IOException
import java.time.Clock
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** The vaults a host keeps its secrets in, one per kind of secret. */
interface VaultFactory {
    val identity: IdentityVault

    /** The channel-key vault for [kind]'s core; the same instance on every call. */
    fun channelKeys(kind: CoreKind): SecretVault
}

/** What the process can show: a running core, or why there is none. */
sealed interface HostState {
    /** Opening, switching or erasing. */
    data object Starting : HostState

    data class Ready(val runtime: AppRuntime) : HostState

    /** [kind]'s store will not open; replaces everything. */
    data class StoreUnavailable(val detail: StoreDetail, val kind: CoreKind) : HostState

    /** The Keystore is not ready; retried on the next foreground. */
    data object IdentityUnavailable : HostState

    /**
     * A stored identity can never be opened again. [detail] is diagnostic.
     * [erasable] is false while staging is on: staging never erases the
     * live identity (D16).
     */
    data class IdentityLost(val detail: String, val erasable: Boolean) : HostState

    /** Erased: the next launch path mints a new identity. */
    data object NeedsFirstLaunch : HostState
}

enum class EraseMode {
    /** The secret and the keys under it; messages and peers stay, unreachable. */
    IdentityOnly,

    /** Everything this phone holds, like Clear storage. */
    Everything,
}

/** What Manage space shows: the identity at stake and the space used. */
data class StorageSummary(
    /** The stored identity, when it can be read; null when there is none or it cannot be. */
    val identity: StoredIdentity?,
    /** A secret is stored, readable or not: Erase identity has something to erase. */
    val identityStored: Boolean,
    /** The stores and the files SQLite keeps beside them. */
    val contentBytes: Long,
    /** The identity and the channel-key vaults. */
    val keyBytes: Long,
    /** Debug builds: staging is on, so erasing is left out (D16). */
    val stagingOn: Boolean,
)

data class StoredIdentity(val hint: NodeHint, val name: String)

sealed interface EraseOutcome {
    data object Done : EraseOutcome

    /** The identity secret would not go, so nothing else did. */
    data class Failed(val error: IdentityVaultException) : EraseOutcome

    /**
     * The identity secret went, but some of what it reached did not:
     * keys or counters are still stored. [details] is diagnostic.
     */
    data class Incomplete(val details: String) : EraseOutcome

    /** Debug builds: staging is on, and staging never erases the live identity (D16). Nothing was done. */
    data object Refused : EraseOutcome
}

/**
 * Opens the stores and makes one core at a time over them.
 *
 * One per process, made by `UmshApplication` and reached by anything that
 * needs the core (Phase 2's foreground service too). Constructing it opens
 * nothing: `MainActivity` calls [ensureRuntime]. Bringing up, switching and
 * erasing run in the host's own scope behind one mutex, so a caller's
 * cancellation never stops one between steps and two never overlap.
 */
class AppCoreHost(
    private val paths: AppPaths,
    private val vaults: VaultFactory,
    val preferences: AppPreferences,
    /** `platforms.json`: 65026 for a phone, 65027 for a tablet. */
    private val platformModel: () -> UShort,
    private val clock: Clock,
    private val foregroundSignals: Flow<Unit>,
    /** Debug builds: the staging core may be chosen. */
    private val stagingAvailable: Boolean,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
    private val io: CoroutineDispatcher = Dispatchers.IO,
) {
    private class Opened(
        val kind: CoreKind,
        val core: MobileAppCore,
        val runtime: AppRuntime,
        val runtimeScope: CoroutineScope,
        val air: StagingRadioConnection?,
    )

    private val _state = MutableStateFlow<HostState>(HostState.Starting)
    val state: StateFlow<HostState> = _state.asStateFlow()

    private val _stagingRadio = MutableStateFlow<StagingRadioConnection?>(null)

    private val _eraseFailure = MutableStateFlow<EraseOutcome?>(null)

    /**
     * An in-app erase that failed or did not finish ([EraseOutcome.Failed]
     * or [EraseOutcome.Incomplete]). Held here, not by the screen that
     * asked: the runtime comes back as a new one, and with it a new shell.
     */
    val eraseFailure: StateFlow<EraseOutcome?> = _eraseFailure.asStateFlow()

    fun dismissEraseFailure() {
        _eraseFailure.value = null
    }

    /** Debug builds: the staged radio while the staging core holds it. */
    val stagingRadio: StateFlow<StagingRadioConnection?> = _stagingRadio.asStateFlow()

    private val mutex = Mutex()
    private val stores = HashMap<CoreKind, MobileAppStore>()
    private val identity = IdentityOperations(vaults.identity)

    /** Written under [mutex]; read without it by [flushDrafts] and [timeChanged] on the main thread. */
    @Volatile
    private var current: Opened? = null
    private var generation = 0L

    /** The kind [bringUp] last tried, so a store unavailable for another kind can be left. */
    private var lastKind: CoreKind? = null

    /**
     * Debug builds: the launch extra's choice, for this process only. The
     * stored choice is the Developer switch's, and the extra never writes it.
     */
    @Volatile
    private var stagingOverride: Boolean? = null

    /** Cores made and not yet closed; tests hold it to one. */
    @Volatile
    var openCores = 0
        private set

    init {
        scope.launch {
            foregroundSignals.collect {
                if (_state.value is HostState.IdentityUnavailable) ensureRuntime()
            }
        }
    }

    /**
     * Bring a runtime up when there is none to show: at launch, after an
     * erase that minted nothing, and to retry an identity the Keystore was
     * not ready to give. [staging], from a debug launch extra, overrides
     * the wanted kind until the process ends or the switch is used.
     */
    fun ensureRuntime(staging: Boolean? = null): Job = scope.launch {
        if (staging != null && stagingAvailable) stagingOverride = staging
        mutex.withLock {
            val shown = _state.value
            if (current == null && shown !is HostState.StoreUnavailable && shown !is HostState.IdentityLost) {
                bringUp()
            }
        }
        followDesiredKind()
    }

    /** Debug builds: switch to or from the staging core; the last switch wins. */
    fun setStaging(enabled: Boolean): Job = scope.launch {
        if (!stagingAvailable) return@launch
        chooseStaging(enabled)
        followDesiredKind()
    }

    /** The Developer switch's choice: stored, and it replaces a launch extra's. */
    private suspend fun chooseStaging(enabled: Boolean) {
        stagingOverride = null
        try {
            preferences.setStagingEnabled(enabled)
        } catch (error: IOException) {
            // Followed for this process even when it cannot be kept.
            AppLog.e(TAG, "staging choice not stored: ${error.javaClass.simpleName}")
            stagingOverride = enabled
        }
    }

    /** Save the running core's pending drafts: the app is leaving the foreground. */
    fun flushDrafts() {
        current?.runtime?.flushDrafts()
    }

    fun timeChanged() {
        current?.runtime?.timeChanged()
    }

    /**
     * Erase this phone's identity, and with [EraseMode.Everything] all it
     * holds. The one way anything erases: in-app Erase identity, Manage
     * space, Start over.
     *
     * The running core stops first; then the identity secret goes, and if
     * it will not, nothing else does and the runtime comes back. Then the
     * live store's content and keys, through a radioless core when the
     * store opens and by deleting files when it does not. [thenMint] brings
     * up a new identity at Welcome; otherwise the state is
     * [HostState.NeedsFirstLaunch]. With [announce], a failure is also
     * published as [eraseFailure], for the app's own screens; Manage space
     * shows its own.
     */
    fun erase(mode: EraseMode, thenMint: Boolean, announce: Boolean = true): Deferred<EraseOutcome> = synchronized(this) {
        // The same request again while it runs (a double tap) shares its
        // answer, announced if either asked. Any other runs after it,
        // behind the mutex: its answer is its own erasure's.
        erasing?.takeIf { it.outcome.isActive && it.mode == mode && it.thenMint == thenMint }?.let { running ->
            if (announce) running.announce = true
            return@synchronized running.outcome
        }
        val request = Erasing(mode, thenMint, announce)
        request.outcome = scope.async {
            val outcome = mutex.withLock { performErase(mode, thenMint) }
            if (request.announce && (outcome is EraseOutcome.Failed || outcome is EraseOutcome.Incomplete)) {
                _eraseFailure.value = outcome
            }
            outcome
        }
        erasing = request
        request.outcome
    }

    private class Erasing(val mode: EraseMode, val thenMint: Boolean, @Volatile var announce: Boolean) {
        lateinit var outcome: Deferred<EraseOutcome>
    }

    /**
     * Manage space's figures. Starts nothing: the name comes from the
     * running live core, or, with no core running, a radioless one over
     * the live store that never starts. While the staging core runs the
     * name is left out: one core at a time (§2.2). The identity is read,
     * never minted. In the host's scope, like every step behind the mutex:
     * a caller that goes away mid-read never cuts the radioless core's stop
     * short.
     */
    suspend fun storageSummary(): StorageSummary = scope.async { mutex.withLock { summarize() } }.await()

    /** Under [mutex]. */
    private suspend fun summarize(): StorageSummary =
        withContext(io) {
            val running = current
            val identity = if (running?.kind == CoreKind.Live) {
                running.runtime.identity.value.let { StoredIdentity(it.hint, it.advertisedName) }
            } else {
                identity.peek()?.let { public ->
                    val name = if (running == null) liveName(public.canonicalAddress) else null
                    StoredIdentity(RecordMapping.hint(public), name.orEmpty())
                }
            }
            StorageSummary(
                identity = identity,
                identityStored = identity != null || this@AppCoreHost.identity.stored(),
                contentBytes = CoreKind.entries.sumOf { kind -> paths.storeFiles(kind).sumOf { it.length() } },
                keyBytes = sizeOf(paths.identity) + CoreKind.entries.sumOf { sizeOf(paths.channelKeys(it)) },
                stagingOn = stagingOn(),
            )
        }

    /** Debug builds: the staging core runs or is wanted, so the live identity is not erased (D16). */
    private suspend fun stagingOn(): Boolean = current?.kind == CoreKind.Staging || desiredKind() == CoreKind.Staging

    /** Under [mutex], with no core open: the stored name, through a core that never starts. */
    private suspend fun liveName(owner: String): String? = try {
        val store = store(CoreKind.Live)
        paths.counters(CoreKind.Live).mkdirs()
        MobileAppCore(store, vaults.channelKeys(CoreKind.Live), config(CoreKind.Live)).use { core ->
            openCores++
            try {
                core.setOwner(owner)
                core.state(true).advertisedName
            } finally {
                core.stop()
                openCores--
            }
        }
    } catch (error: Exception) {
        AppLog.w(TAG, "name unread: ${error.javaClass.simpleName}")
        null
    }

    private fun sizeOf(file: File): Long = file.walkBottomUp().filter { it.isFile }.sumOf { it.length() }

    /** The last erase asked for; guarded by `this`. */
    private var erasing: Erasing? = null

    /**
     * Debug builds: turn staging off and throw the staged set away: its
     * content, and the staging channel keys.
     */
    fun resetStagedData(): Deferred<Boolean> = scope.async {
        chooseStaging(false)
        followDesiredKind()
        mutex.withLock {
            if (current?.kind == CoreKind.Staging) return@withLock false
            try {
                withContext(io) {
                    val staging = try {
                        store(CoreKind.Staging)
                    } catch (_: MobileStoreException) {
                        null
                    }
                    if (staging != null) {
                        // Content, not the file: the store stays open for the
                        // next staging core, and SQLite treats a file unlinked
                        // under an open connection as corrupt.
                        staging.eraseAllContent()
                    } else {
                        // It will not open, so nothing holds it: the files go.
                        deleteFiles(paths.storeFiles(CoreKind.Staging))
                    }
                    vaults.channelKeys(CoreKind.Staging).deleteAll()
                }
                true
            } catch (error: Exception) {
                AppLog.e(TAG, "staged data not reset: ${error.javaClass.simpleName}")
                false
            }
        }
    }

    /** Stop the running core and close the stores. The host is done after this. */
    suspend fun shutdown() = mutex.withLock {
        tearDown()
        withContext(io) {
            stores.values.forEach { it.close() }
            stores.clear()
        }
        _state.value = HostState.Starting
    }

    private suspend fun desiredKind(): CoreKind =
        if (stagingAvailable && (stagingOverride ?: preferences.stagingEnabled())) CoreKind.Staging else CoreKind.Live

    /**
     * Switch until the running core is the wanted kind; switches never
     * overlap. A store shown unavailable for the kind no longer wanted is
     * left for the wanted one.
     */
    private suspend fun followDesiredKind() = mutex.withLock {
        while (true) {
            val running = current
            if (running == null) {
                val wanted = desiredKind()
                if (_state.value !is HostState.StoreUnavailable || lastKind == wanted) return@withLock
                AppLog.i(TAG, "leaving the unavailable $lastKind store")
                bringUp()
                continue
            }
            if (running.kind == desiredKind()) return@withLock
            AppLog.i(TAG, "switching from ${running.kind}")
            _state.value = HostState.Starting
            tearDown()
            bringUp()
        }
    }

    /** Under [mutex], with no core open. */
    private suspend fun bringUp() {
        check(current == null)
        val kind = desiredKind()
        lastKind = kind
        _state.value = HostState.Starting
        val store = try {
            withContext(io) { store(kind) }
        } catch (error: MobileStoreException) {
            val detail = StoreDetail.from(error, paths.store(kind).name)
            AppLog.e(TAG, "store unavailable: ${detail.render()}")
            _state.value = HostState.StoreUnavailable(detail, kind)
            return
        }
        val loaded = try {
            withContext(io) {
                identity.load(beforeMint = { preferences.setOnboarding(OnboardingStep.Welcome) })
            }
        } catch (error: IOException) {
            // The first-run step could not be recorded, so nothing was
            // minted: a new identity must never skip Welcome.
            val detail = StoreDetail.Other(paths.preferences.name, error.javaClass.simpleName)
            AppLog.e(TAG, "preferences unwritable: ${detail.render()}")
            _state.value = HostState.StoreUnavailable(detail, kind)
            return
        }
        val owner = when (loaded) {
            is IdentityOperations.Loaded.Unavailable -> {
                _state.value = HostState.IdentityUnavailable
                return
            }
            is IdentityOperations.Loaded.Lost -> {
                AppLog.e(TAG, "identity lost: ${loaded.detail}")
                _state.value = HostState.IdentityLost(loaded.detail, erasable = kind == CoreKind.Live)
                return
            }
            is IdentityOperations.Loaded.Ready -> loaded.identity
        }
        val vault = vaults.channelKeys(kind)
        val core = try {
            withContext(io) {
                paths.counters(kind).mkdirs()
                MobileAppCore(store, vault, config(kind))
            }
        } catch (error: Exception) {
            AppLog.e(TAG, "core not made: ${error.javaClass.simpleName}")
            _state.value = HostState.StoreUnavailable(StoreDetail.Other(paths.store(kind).name, error.javaClass.simpleName), kind)
            return
        }
        openCores++
        val air = if (kind == CoreKind.Staging) {
            StagingRadioConnection.attach(core, paths.stagingAir, preferences.stagingWifiScanOnly.first())
        } else {
            null
        }
        val runtimeScope = CoroutineScope(scope.coroutineContext + SupervisorJob(scope.coroutineContext[Job]))
        val runtimeGeneration = ++generation
        val runtime = AppRuntime(
            core = core,
            kind = kind,
            generation = runtimeGeneration,
            owner = owner,
            identityOps = identity,
            protection = vaults.identity::protection,
            preferences = preferences,
            initialOnboarding = preferences.onboarding.first(),
            seed = if (kind == CoreKind.Staging) {
                { ownerId, nowMs -> seedStaging(store, vault, ownerId, nowMs) }
            } else {
                null
            },
            foregroundSignals = foregroundSignals,
            clock = clock,
            scope = runtimeScope,
            onIdentityLost = { detail -> identityLost(runtimeGeneration, detail) },
        )
        current = Opened(kind, core, runtime, runtimeScope, air)
        runtime.start()
        _stagingRadio.value = air
        _state.value = HostState.Ready(runtime)
        AppLog.i(TAG, "runtime ${runtime.generation} up ($kind)")
    }

    /**
     * Under [mutex]: stop the running core. Drafts saved, observation
     * ended, the radio withdrawn, the core stopped, then (staging) the air
     * ended, so two cores never hold a radio.
     */
    private suspend fun tearDown() {
        val opened = current ?: return
        current = null
        _stagingRadio.value = null
        runCatching { opened.runtime.flushDrafts().await() }
        opened.runtime.detach()
        opened.runtime.seedFinished()
        // Everything the runtime runs (reloads, commands, draft timers)
        // ends before the core does: a call into a closed core throws.
        opened.runtimeScope.coroutineContext.job.cancelAndJoin()
        runCatching { opened.core.useRadio(null) }
            .onFailure { AppLog.w(TAG, "radio not withdrawn: ${it.javaClass.simpleName}") }
        opened.core.stop()
        withContext(io) { opened.air?.stop() }
        opened.core.close()
        openCores--
    }

    /**
     * The running core's identity would not unlock and never will: the
     * runtime goes, and the screen says so. A runtime already replaced is
     * ignored.
     */
    private fun identityLost(generation: Long, detail: String) {
        scope.launch {
            mutex.withLock {
                if (current?.runtime?.generation != generation) return@withLock
                AppLog.e(TAG, "identity lost while running: $detail")
                val erasable = current?.kind == CoreKind.Live
                tearDown()
                _state.value = HostState.IdentityLost(detail, erasable)
            }
        }
    }

    private suspend fun performErase(mode: EraseMode, thenMint: Boolean): EraseOutcome {
        // The rule is the host's, not only the screens': whatever asks.
        if (stagingOn()) {
            AppLog.w(TAG, "erase refused: staging is on")
            return EraseOutcome.Refused
        }
        AppLog.i(TAG, "erasing: $mode")
        _state.value = HostState.Starting
        tearDown()
        // The secret before anything else: if it cannot be destroyed,
        // nothing is, and the phone stays the node it was.
        try {
            withContext(io) { vaults.identity.delete() }
        } catch (error: IdentityVaultException) {
            AppLog.e(TAG, "identity not erased: ${error.javaClass.simpleName}")
            // A delete that failed after the secret went still erased it:
            // carry on, rather than minting over the old identity's keys.
            if (withContext(io) { identity.stored() }) {
                bringUp()
                return EraseOutcome.Failed(error)
            }
            AppLog.w(TAG, "the secret is gone; erasing the rest")
        }
        val left = mutableListOf<String>()
        withContext(io) {
            val live = try {
                store(CoreKind.Live)
            } catch (_: MobileStoreException) {
                null
            }
            if (live == null || !eraseThroughCore(live, mode)) {
                // The core did not erase. With the identity gone nothing it
                // reached is usable: its keys and counters go here. The
                // store's files go only when it will not open, or when
                // everything was asked for; Erase identity keeps messages
                // and peers.
                if (live == null || mode == EraseMode.Everything) {
                    AppLog.w(TAG, "erasing the live store's files")
                    stores.remove(CoreKind.Live)?.close()
                    if (!deleteFiles(paths.storeFiles(CoreKind.Live))) left += "live store"
                }
                if (!deleteTree(paths.counters(CoreKind.Live))) left += "live counters"
                deleteChannelKeys(CoreKind.Live)?.let { left += "live channel keys: $it" }
                deleteChannelKeys(CoreKind.Staging)?.let { left += "staging channel keys: $it" }
            }
            // The identity is shared by both kinds, so erasing it in one
            // erases both: the core removed its own counters, and this the
            // other's.
            if (!deleteTree(paths.counters(CoreKind.Staging))) left += "staging counters"
            if (mode == EraseMode.Everything) {
                stores.remove(CoreKind.Staging)?.close()
                if (!deleteFiles(paths.storeFiles(CoreKind.Staging))) left += "staging store"
                if (!deleteTree(paths.stagingAir)) left += "staged air"
                deleteChannelKeys(CoreKind.Staging)?.let { left += "staging channel keys: $it" }
            }
        }
        if (mode == EraseMode.Everything) {
            try {
                preferences.clear()
            } catch (error: IOException) {
                // The identity and the content are gone; what stays is settings.
                AppLog.e(TAG, "preferences not cleared: ${error.javaClass.simpleName}")
            }
        }
        if (thenMint) {
            bringUp()
        } else {
            _state.value = HostState.NeedsFirstLaunch
        }
        return if (left.isEmpty()) EraseOutcome.Done else EraseOutcome.Incomplete(left.distinct().joinToString("; "))
    }

    /** A radioless core that never starts, over [store], erases it. False when it could not. */
    private suspend fun eraseThroughCore(store: MobileAppStore, mode: EraseMode): Boolean = try {
        paths.counters(CoreKind.Live).mkdirs()
        MobileAppCore(store, vaults.channelKeys(CoreKind.Live), config(CoreKind.Live)).use { core ->
            openCores++
            try {
                core.erase(alsoContent = mode == EraseMode.Everything)
            } finally {
                core.stop()
                openCores--
            }
        }
        true
    } catch (error: Exception) {
        AppLog.e(TAG, "core erase incomplete: ${error.javaClass.simpleName}")
        false
    }

    /** Null when [kind]'s channel keys are gone; otherwise why not (diagnostic). */
    private fun deleteChannelKeys(kind: CoreKind): String? =
        runCatching { vaults.channelKeys(kind).deleteAll() }.exceptionOrNull()?.let {
            AppLog.e(TAG, "$kind channel keys not erased: ${it.javaClass.simpleName}")
            it.javaClass.simpleName
        }

    /** True when none of [files] is left. */
    private fun deleteFiles(files: List<File>): Boolean = files.fold(true) { gone, file ->
        val deleted = !file.exists() || file.delete()
        if (!deleted) AppLog.e(TAG, "not deleted: ${file.name}")
        gone && deleted
    }

    /** True when [directory] is gone. */
    private fun deleteTree(directory: File): Boolean {
        directory.deleteRecursively()
        return !directory.exists().also { if (it) AppLog.e(TAG, "not deleted: ${directory.name}") }
    }

    /** [kind]'s store, opened once and kept: the core shares its one connection. */
    private fun store(kind: CoreKind): MobileAppStore = stores.getOrPut(kind) {
        val file = paths.store(kind)
        file.parentFile?.mkdirs()
        MobileAppStore.open(file.path)
    }

    private fun config(kind: CoreKind) = MobileAppConfigRecord(paths.counters(kind).path, platformModel())

    private companion object {
        const val TAG = "umsh.host"
    }
}
