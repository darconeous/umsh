package com.voria.umsh.app

import com.voria.umsh.core.MobileAppConfigRecord
import com.voria.umsh.core.MobileAppCore
import com.voria.umsh.core.MobileAppStore
import com.voria.umsh.core.MobileRadioException
import com.voria.umsh.core.MobileStoreException
import com.voria.umsh.core.SecretVault
import com.voria.umsh.core.seedStaging
import com.voria.umsh.services.identity.IdentityOperations
import com.voria.umsh.services.identity.IdentityVault
import com.voria.umsh.services.identity.IdentityVaultException
import com.voria.umsh.services.location.PhoneLocationSource
import com.voria.umsh.services.location.PositionSource
import com.voria.umsh.models.NodeHint
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.mobilecore.RecordMapping
import com.voria.umsh.services.mobilecore.StoreDetail
import com.voria.umsh.services.preferences.AppPreferences
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.services.radio.BluetoothStatus
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.PendingBinding
import com.voria.umsh.services.radio.RadioBindings
import com.voria.umsh.services.radio.RadioConnection
import com.voria.umsh.services.radio.RadioConnectionEvents
import com.voria.umsh.services.radio.RadioLinkFactory
import com.voria.umsh.services.radio.StagingRadioConnection
import java.io.File
import java.io.IOException
import java.time.Clock
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
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
import kotlinx.coroutines.withTimeoutOrNull

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

/**
 * One [AppCoreHost.connectRadio]: the radio chosen, and the bind, which
 * [bound] completes. A later choice supersedes it, and from then on
 * forgetting it ([AppCoreHost.forgetRadio]) leaves the later one alone.
 */
class RadioChoice internal constructor(val radio: BoundRadio, val bound: Job)

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

/**
 * What tells the person about a runtime's events while no screen does: the
 * notifier. One per process, handed every runtime the host makes.
 */
interface RuntimeNotifications {
    /** [runtime] is made and about to start; [scope] ends with it. */
    fun attach(runtime: AppRuntime, scope: CoroutineScope)

    /** The identity is being erased: what was posted about it goes. */
    fun withdrawAll()

    object None : RuntimeNotifications {
        override fun attach(runtime: AppRuntime, scope: CoroutineScope) = Unit

        override fun withdrawAll() = Unit
    }
}

/** Who asks for a runtime, which decides what a start may do. */
enum class StartOrigin {
    /** An activity the person sees: it may mint a first identity, which begins at Welcome. */
    Activity,

    /**
     * No UI: the radio's foreground service, presence, a notification
     * action. Never mints, never shows anything, never switches kinds: it
     * starts the live core over the stored identity, or nothing.
     */
    Headless,
}

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
 * needs the core (the radio's foreground service too). Constructing it
 * opens nothing: `MainActivity` calls [ensureRuntime]. Bringing up,
 * switching and erasing run in the host's own scope behind one mutex, so a
 * caller's cancellation never stops one between steps and two never
 * overlap.
 *
 * The host also owns the live radio's connection, one at a time, made with
 * the live core from what [AppPreferences.radioRegistry] names and torn
 * down with it. Its state is never read here: it reaches the screens only
 * through the core, as every radio state does.
 */
class AppCoreHost(
    private val paths: AppPaths,
    private val vaults: VaultFactory,
    val preferences: AppPreferences,
    /** `platforms.json`: 65026 for a phone, 65027 for a tablet. */
    val platformModel: () -> UShort,
    private val clock: Clock,
    private val foregroundSignals: Flow<Unit>,
    /** Debug builds: the staging core may be chosen. */
    private val stagingAvailable: Boolean,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
    private val io: CoroutineDispatcher = Dispatchers.IO,
    /** Makes the connection a bound radio names; none in tests that need no radio. */
    private val radioLinks: RadioLinkFactory = RadioLinkFactory { _, _, _ -> null },
    /** Posts what each runtime asks to be told; nothing in tests that read the events themselves. */
    private val notifications: RuntimeNotifications = RuntimeNotifications.None,
    /** The phone's Bluetooth and Nearby devices grant, for the banners; always usable in tests. */
    val bluetooth: StateFlow<BluetoothStatus> = MutableStateFlow(BluetoothStatus.Ready),
    /** Releases a radio's association (and API 36+ bond) when no connection holds it to do so. */
    private val bindings: RadioBindings = RadioBindings { },
    /** This phone's location readings and grant, for Share location; none in tests that never share one. */
    private val location: PhoneLocationSource = PhoneLocationSource.None,
    /** One reading of the phone's position under a grant already given; tests hand in fixes of their own. */
    private val positions: PositionSource = PositionSource.of(location),
) {
    private class Opened(
        val kind: CoreKind,
        val core: MobileAppCore,
        val runtime: AppRuntime,
        val runtimeScope: CoroutineScope,
        val air: StagingRadioConnection?,
    ) {
        /** The live radio's connection; written under [mutex]. */
        @Volatile
        var connection: RadioConnection? = null
    }

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

    private val _radio = MutableStateFlow<RadioConnection?>(null)

    /**
     * The live radio's connection, for its commands (connect, disconnect,
     * forget, restart, factory reset); null with no radio set up, or while
     * the staging core runs. Its state is the core's to report: read
     * [AppRuntime.radio], never this.
     */
    val radio: StateFlow<RadioConnection?> = _radio.asStateFlow()

    private val radioEvents = RadioConnectionEvents { connection ->
        scope.launch {
            mutex.withLock {
                val opened = current ?: return@withLock
                if (opened.connection === connection) detachRadio(opened)
            }
        }
    }

    private val mutex = Mutex()
    private val stores = HashMap<CoreKind, MobileAppStore>()
    private val identity = IdentityOperations(vaults.identity)

    /** Written under [mutex]; read without it by [flushDrafts] and [timeChanged] on the main thread. */
    @Volatile
    private var current: Opened? = null
    private var generation = 0L

    /** The kind [bringUp] last tried, so a store unavailable for another kind can be left. */
    private var lastKind: CoreKind? = null

    /** An attempt to add a radio that the last process ended in has been undone; once, at the first start. */
    private var cutOffAttemptUndone = false

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
     *
     * A [StartOrigin.Headless] start never mints and never switches: with
     * no stored identity it leaves [HostState.NeedsFirstLaunch], and with
     * staging wanted it does nothing.
     *
     * Completes with whether the live core is running afterward, so a
     * headless caller that finds none stops itself.
     */
    fun ensureRuntime(staging: Boolean? = null, origin: StartOrigin = StartOrigin.Activity): Deferred<Boolean> {
        val live = CompletableDeferred<Boolean>()
        // Launched, not async: a failure still reaches the scope's handler.
        scope.launch { live.complete(startRuntime(staging, origin)) }
            .invokeOnCompletion { live.complete(false) }
        return live
    }

    /**
     * The runtime a notification action works in, bringing the live one up
     * headless if none runs (never minting). Whatever runs is used, the
     * staging core too. Null when none is up within [timeoutMs].
     */
    suspend fun runtimeForAction(timeoutMs: Long): AppRuntime? {
        withTimeoutOrNull(timeoutMs) { ensureRuntime(origin = StartOrigin.Headless).await() }
        return (_state.value as? HostState.Ready)?.runtime
    }

    private suspend fun startRuntime(staging: Boolean?, origin: StartOrigin): Boolean {
        val headless = origin == StartOrigin.Headless
        if (!headless && staging != null && stagingAvailable) stagingOverride = staging
        mutex.withLock {
            val shown = _state.value
            if (current == null && shown !is HostState.StoreUnavailable && shown !is HostState.IdentityLost) {
                if (headless && desiredKind() != CoreKind.Live) {
                    AppLog.i(TAG, "headless start skipped: staging is on")
                    return@withLock
                }
                bringUp(mint = !headless)
            }
        }
        if (!headless) followDesiredKind()
        return current?.kind == CoreKind.Live
    }

    /** The last [connectRadio]; any earlier choice has been superseded. */
    private val latestChoice = AtomicReference<RadioChoice?>(null)

    /**
     * Bind the live core to [radio] and connect, as the user chose it
     * (Connect a radio, Choose a radio, and the debug bridge). A radio
     * already bound to another is released first (its host key cleared on
     * the radio), then let go, then the new one connects: the host holds
     * one connection. With the staging core running the choice is only
     * remembered, for the live core's next start.
     */
    fun connectRadio(radio: BoundRadio): RadioChoice {
        // Lazy, so the choice is the latest before its bind can run.
        val bind = scope.launch(start = CoroutineStart.LAZY) { bind(radio) }
        return RadioChoice(radio, bind).also {
            latestChoice.set(it)
            bind.start()
        }
    }

    private suspend fun bind(radio: BoundRadio) {
        mutex.withLock {
            val opened = current?.takeIf { it.kind == CoreKind.Live }
            val existing = opened?.connection
            if (existing != null && existing.kind == radio.kind && existing.linkId == radio.linkId) {
                // Held, but perhaps no longer remembered (a factory reset
                // let it go while its link stays up): remembered again.
                val stored = boundRadio()
                if (stored?.kind != radio.kind || stored.linkId != radio.linkId) {
                    try {
                        // Held already: not an attempt under way.
                        preferences.radioRegistry.bind(radio.copy(pending = null))
                    } catch (error: IOException) {
                        AppLog.e(TAG, "radio not bound: ${error.javaClass.simpleName}")
                        return@withLock
                    }
                }
                existing.connect()
                return@withLock
            }
            if (opened != null && existing != null) {
                existing.releaseHost()
                detachRadio(opened)
            }
            try {
                preferences.radioRegistry.bind(radio)
            } catch (error: IOException) {
                AppLog.e(TAG, "radio not bound: ${error.javaClass.simpleName}")
                return@withLock
            }
            if (opened != null) attachRadio(opened, radio)?.connect()
        }
    }

    /** Disconnect: the radio is released, the link goes down, and nothing reconnects until asked. */
    fun disconnectRadio(): Job = scope.launch {
        mutex.withLock {
            val connection = current?.connection
            if (connection != null) {
                connection.disconnect()
                return@withLock
            }
            // Bound, but not held now (the staging core runs): only the intent changes.
            try {
                preferences.radioRegistry.bound()?.let { preferences.radioRegistry.setAutoConnect(it.linkId, false) }
            } catch (error: IOException) {
                AppLog.e(TAG, "radio not disconnected: ${error.javaClass.simpleName}")
            }
        }
    }

    /**
     * Reconnect, as the user asked (Radio Detail): the held radio's recovery
     * budget starts over and the standing intent is set again. Nothing when
     * no live radio is held.
     */
    fun reconnectRadio(): Job = scope.launch {
        mutex.withLock { current?.connection?.connect() }
    }

    /**
     * Seek the wanted radio now, as its standing intent asks (§7.2, §7.3):
     * companion presence saw it, or a notification action needs it. A
     * radio left to presence after the reconnect window is sought again
     * with a new window; one already sought goes on as it was; one the
     * user disconnected, or the driver gave up on, is left alone. Never a
     * new recovery budget.
     */
    fun wakeRadio(): Job = scope.launch {
        mutex.withLock {
            val connection = current?.takeIf { it.kind == CoreKind.Live }?.connection ?: return@withLock
            val bound = boundRadio()
            if (bound == null || !bound.autoConnect || bound.kind != connection.kind || bound.linkId != connection.linkId) {
                AppLog.i(TAG, "wake: the radio is not wanted; nothing sought")
                return@withLock
            }
            AppLog.i(TAG, "wake: seeking the radio")
            connection.autoConnect()
        }
    }

    /**
     * Restart the held radio. Completes when the radio took the request;
     * fails with the driver's `MobileRadioException` when it did not, or
     * with `RadioUnavailable` when no live radio is held.
     */
    fun restartRadio(): Deferred<Unit> = scope.async { heldRadio().restart() }

    /** Factory reset the held radio; fails as [restartRadio] does. */
    fun factoryResetRadio(): Deferred<Unit> = scope.async { heldRadio().factoryReset() }

    /**
     * The live radio's connection, read without the lock: a request to the
     * radio can take seconds, and nothing else should wait behind it.
     */
    private fun heldRadio(): RadioConnection =
        current?.connection ?: throw MobileRadioException.RadioUnavailable()

    /**
     * Forget the bound radio: released, its link down, and no longer
     * remembered; its association and (API 36+) its bond go too, unless
     * [keepBinding] (a radio that was this phone's before an attempt to
     * choose it again failed).
     *
     * With [choice], only what that choice bound is forgotten, and only
     * while no later choice has superseded it: an attempt called off late
     * never takes down the radio a later attempt chose.
     */
    fun forgetRadio(keepBinding: Boolean = false, choice: RadioChoice? = null): Job = scope.launch {
        mutex.withLock {
            if (choice != null) {
                forgetChoice(choice, keepBinding)
                return@withLock
            }
            val opened = current
            val connection = opened?.connection
            if (opened != null && connection != null) {
                connection.forget(keepBinding)
                detachRadio(opened)
            } else {
                // Bound, but not held now (the staging core runs): what is remembered goes.
                val bound = try {
                    preferences.radioRegistry.bound()?.also { preferences.radioRegistry.clear(it.linkId) }
                } catch (error: IOException) {
                    AppLog.e(TAG, "radio not forgotten: ${error.javaClass.simpleName}")
                    null
                }
                if (!keepBinding) bound?.associationId?.let { release(it) }
            }
        }
    }

    /** Under [mutex]: forget what [choice] bound, if it is still the latest. */
    private suspend fun forgetChoice(choice: RadioChoice, keepBinding: Boolean) {
        val radio = choice.radio
        val latest = latestChoice.get()
        if (latest !== choice) {
            // Superseded: the later choice holds what it holds. An
            // association made for this one goes, unless the later choice
            // took the same radio and with it the association.
            AppLog.i(TAG, "radio choice superseded; leaving the later one")
            if (!keepBinding && (latest?.radio?.kind != radio.kind || latest.radio.linkId != radio.linkId)) {
                radio.associationId?.let { release(it) }
            }
            return
        }
        val opened = current
        val connection = opened?.connection
        if (opened != null && connection != null && connection.kind == radio.kind && connection.linkId == radio.linkId) {
            connection.forget(keepBinding)
            detachRadio(opened)
            return
        }
        // Never held (the bind did not take, or the staging core runs):
        // its registry entry, if it got one, and its association go.
        try {
            preferences.radioRegistry.clear(radio.linkId)
        } catch (error: IOException) {
            AppLog.e(TAG, "radio not forgotten: ${error.javaClass.simpleName}")
        }
        if (!keepBinding) radio.associationId?.let { release(it) }
    }

    private suspend fun release(associationId: String) = withContext(io) { bindings.release(associationId) }

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

    /** Under [mutex], with no core open. [mint]: a missing identity may be made (a visible start only). */
    private suspend fun bringUp(mint: Boolean = true) {
        check(current == null)
        if (!cutOffAttemptUndone) {
            cutOffAttemptUndone = true
            undoCutOffAttempt()
        }
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
                identity.load(mintIfAbsent = mint, beforeMint = { preferences.setOnboarding(OnboardingStep.Welcome) })
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
            is IdentityOperations.Loaded.Absent -> {
                AppLog.i(TAG, "no identity, and this start may not make one")
                _state.value = HostState.NeedsFirstLaunch
                return
            }
            is IdentityOperations.Loaded.Ready -> loaded.identity
        }
        val vault = vaults.channelKeys(kind)
        // Read once: the runtime shows the model this core advertises, even
        // after the screen it was read from changes width.
        val config = config(kind)
        val core = try {
            withContext(io) {
                paths.counters(kind).mkdirs()
                MobileAppCore(store, vault, config)
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
            platformModel = config.platformModel,
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
            location = location,
            positions = positions,
        )
        val opened = Opened(kind, core, runtime, runtimeScope, air)
        current = opened
        // Before the start: nothing the core reports is drained unheard.
        notifications.attach(runtime, runtimeScope)
        runtime.start()
        _stagingRadio.value = air
        // The core takes its radio while still starting: the driver exists
        // before the identity unlocks, and its states reach the runtime
        // through the listener the start has just set.
        val bound = if (kind == CoreKind.Live) boundRadio() else null
        val connection = bound?.let { attachRadio(opened, it) }
        _state.value = HostState.Ready(runtime)
        AppLog.i(TAG, "runtime ${runtime.generation} up ($kind)")
        if (connection != null && bound.autoConnect) connection.autoConnect()
    }

    /**
     * Under [mutex], before the process's first core: a radio still being
     * added when the last process ended (Connect a radio or Choose a radio,
     * before it attached) is undone, as the attempt would have undone it,
     * rather than connected as this phone's. Its registry entry goes, and an
     * association made for the attempt with it (and on API 36+ its bond).
     */
    private suspend fun undoCutOffAttempt() {
        val bound = boundRadio() ?: return
        val pending = bound.pending ?: return
        AppLog.i(TAG, "a radio still being added when the app last ended; letting it go")
        try {
            preferences.radioRegistry.clear(bound.linkId)
        } catch (error: IOException) {
            AppLog.e(TAG, "radio not forgotten: ${error.javaClass.simpleName}")
            return
        }
        if (pending == PendingBinding.NewAssociation) bound.associationId?.let { release(it) }
    }

    private suspend fun boundRadio(): BoundRadio? = try {
        preferences.radioRegistry.bound()
    } catch (error: IOException) {
        AppLog.e(TAG, "radio registry unread: ${error.javaClass.simpleName}")
        null
    }

    /**
     * Under [mutex]: make [bound]'s connection and give the core its
     * driver. Null when this build cannot reach that kind of radio, or the
     * core would not take it.
     */
    private suspend fun attachRadio(opened: Opened, bound: BoundRadio): RadioConnection? {
        val connection = radioLinks.make(bound, preferences.radioRegistry, radioEvents) ?: run {
            AppLog.w(TAG, "no link for a ${bound.kind} radio in this build")
            return null
        }
        try {
            opened.core.useRadio(connection.driver)
        } catch (error: Exception) {
            AppLog.e(TAG, "the core did not take the radio: ${error.javaClass.simpleName}")
            withContext(io) { connection.close() }
            return null
        }
        opened.connection = connection
        _radio.value = connection
        return connection
    }

    /** Under [mutex]: the core lets the radio go, then the connection closes for good. */
    private suspend fun detachRadio(opened: Opened) {
        val connection = opened.connection ?: return
        opened.connection = null
        _radio.value = null
        runCatching { opened.core.useRadio(null) }
            .onFailure { AppLog.w(TAG, "radio not withdrawn: ${it.javaClass.simpleName}") }
        withContext(io) { connection.close() }
    }

    /**
     * Under [mutex]: stop the running core. Drafts saved, observation
     * ended, the radio withdrawn and (live) its connection closed, the core
     * stopped, then (staging) the air ended, so two cores never hold a
     * radio.
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
        if (opened.connection != null) {
            detachRadio(opened)
        } else {
            runCatching { opened.core.useRadio(null) }
                .onFailure { AppLog.w(TAG, "radio not withdrawn: ${it.javaClass.simpleName}") }
        }
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
        // The shade is outside the app's files: a message from a
        // conversation about to go would otherwise stay there, quoting it.
        notifications.withdrawAll()
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
