package com.voria.umsh.app

import com.voria.umsh.core.MobileAppCore
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileAppPolicyRecord
import com.voria.umsh.core.MobileAppStartFailure
import com.voria.umsh.core.MobileAppStatusRecord
import com.voria.umsh.core.MobileAppTranscriptPageRecord
import com.voria.umsh.core.MobileException
import com.voria.umsh.core.MobileStoredChatCursorRecord
import com.voria.umsh.core.PublicIdentityRecord
import com.voria.umsh.models.AppStateSnapshot
import com.voria.umsh.models.KeyProtection
import com.voria.umsh.models.LocalIdentity
import com.voria.umsh.models.MessageRef
import com.voria.umsh.models.TranscriptCursor
import com.voria.umsh.models.TranscriptPage
import com.voria.umsh.services.identity.IdentityOperations
import com.voria.umsh.services.identity.IdentityVaultException
import com.voria.umsh.services.mobilecore.AppLog
import com.voria.umsh.services.mobilecore.CoreWake
import com.voria.umsh.services.mobilecore.RecordMapping
import com.voria.umsh.services.mobilecore.ReloadCoalescer
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.services.preferences.PolicyPreferences
import com.voria.umsh.services.preferences.RuntimePreferences
import com.voria.umsh.services.radio.RadioSnapshot
import java.time.Clock
import java.time.Instant
import java.util.concurrent.atomic.AtomicLong
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Something the person must be told once, as a failure dialog. */
sealed interface FailureNotice {
    /** This phone's identity did not start, for [reason]. */
    data class StartFailed(val reason: MobileAppStartFailure) : FailureNotice
}

/**
 * One core, observed: what the screens read, and the commands they send.
 *
 * Touches no `Context`, Keystore or file: the host hands it everything,
 * so the JVM tests drive it over a real core with fakes around it. Commands
 * run in [scope], not a caller's, and come back as `Deferred`s: a screen
 * that goes away does not cancel what it asked for.
 */
class AppRuntime(
    val core: MobileAppCore,
    val kind: CoreKind,
    /** Bumped for every runtime the host makes; the UI is keyed on it. */
    val generation: Long,
    owner: PublicIdentityRecord,
    private val identityOps: IdentityOperations,
    private val protection: () -> KeyProtection,
    private val preferences: RuntimePreferences,
    initialOnboarding: OnboardingStep,
    /** Staging only: rewrite the staged mesh relative to now, before every start. */
    private val seed: (suspend (owner: String, nowMs: Long) -> Unit)?,
    private val foregroundSignals: Flow<Unit>,
    private val clock: Clock,
    private val scope: CoroutineScope,
    /** The stored identity will never unlock again; the host replaces this runtime. */
    private val onIdentityLost: (detail: String) -> Unit = {},
    /** For the core's synchronous queries, which share the store's one connection. */
    private val read: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(2),
    /** How long typing pauses before a draft is saved; a test holds it off to see what else saves one. */
    private val draftDebounceMs: Long = DRAFT_DEBOUNCE_MS,
) {
    val ownerAddress: String = owner.canonicalAddress

    private val _lifecycle = MutableStateFlow<MobileAppLifecycle>(MobileAppLifecycle.Idle)
    val lifecycle: StateFlow<MobileAppLifecycle> = _lifecycle.asStateFlow()

    private val _radio = MutableStateFlow<RadioSnapshot?>(null)

    /** The companion radio; null when there is none, or (see [radioKnown]) before it is read. */
    val radio: StateFlow<RadioSnapshot?> = _radio.asStateFlow()

    private val _radioKnown = MutableStateFlow(false)

    /** The core has said what radio there is: until then, [radio]'s null is "not read yet", not "none". */
    val radioKnown: StateFlow<Boolean> = _radioKnown.asStateFlow()

    private val _identity = MutableStateFlow(
        LocalIdentity(ownerAddress, RecordMapping.hint(owner), advertisedName = "", KeyProtection.Unknown),
    )
    val identity: StateFlow<LocalIdentity> = _identity.asStateFlow()

    private val _appState = MutableStateFlow<AppStateSnapshot?>(null)

    /** Peers, channels and conversations; null until the first read. */
    val appState: StateFlow<AppStateSnapshot?> = _appState.asStateFlow()

    private val _transcriptRevisions = MutableStateFlow<Map<String, Long>>(emptyMap())

    /** How many times each conversation's messages changed; an open transcript re-reads on a change. */
    val transcriptRevisions: StateFlow<Map<String, Long>> = _transcriptRevisions.asStateFlow()

    private val _forwardSecretConversations = MutableStateFlow<Set<String>>(emptySet())
    val forwardSecretConversations: StateFlow<Set<String>> = _forwardSecretConversations.asStateFlow()

    private val _emergencyCertified = MutableStateFlow(false)
    val emergencyCertified: StateFlow<Boolean> = _emergencyCertified.asStateFlow()

    private val _stateLoadError = MutableStateFlow(false)

    /** The store failed a read: what is shown may be out of date. */
    val stateLoadError: StateFlow<Boolean> = _stateLoadError.asStateFlow()

    private val _failureNotice = MutableStateFlow<FailureNotice?>(null)
    val failureNotice: StateFlow<FailureNotice?> = _failureNotice.asStateFlow()

    private val _onboarding = MutableStateFlow(if (kind == CoreKind.Staging) OnboardingStep.Done else initialOnboarding)

    /** Never shown in staging. */
    val onboarding: StateFlow<OnboardingStep> = _onboarding.asStateFlow()

    private val _now = MutableStateFlow(clock.instant())

    /** Ticks each minute while attached, and on a time, zone or locale change. */
    val now: StateFlow<Instant> = _now.asStateFlow()

    /** The conversation on screen, which Phase 2's notifications leave alone. */
    val visibleConversation = MutableStateFlow<String?>(null)

    /** The loops this runtime runs while attached: the drain, collectors, the clock. */
    private val attachment = SupervisorJob(scope.coroutineContext[Job])
    private val attached = CoroutineScope(scope.coroutineContext + attachment)
    private val wakes = Channel<Unit>(Channel.CONFLATED)
    private val reloads = ReloadCoalescer(scope, ::performReload)
    private val startLock = Mutex()
    private val shownStartFailures = HashSet<MobileAppStartFailure>()
    private var seedJob: Job? = null
    private var started = false

    /** The start: owner set, lists read, the core started. Commands that need the owner wait for it. */
    @Volatile
    private var startJob: Job? = null

    /** The identity did not unlock for a start; the next foreground tries again. */
    @Volatile
    private var startPending = false

    /** Bumped by a name save, so a read that began before it does not undo it. */
    private val nameRevision = AtomicLong()

    private val draftLock = Any()
    private val pendingDrafts = HashMap<String, String>()
    private val draftTimers = HashMap<String, Job>()

    /**
     * Attach to the core and bring the identity up: listener first, so
     * nothing the core reports goes unread; the policy before the core can
     * act on one; staging's seed before the owner is set, so the first
     * lists published are already the staged mesh; the lists before the
     * start, since reading needs only the owner.
     */
    fun start(): Job {
        check(!started) { "a runtime starts once" }
        started = true
        core.setListener(CoreWake(wakes))
        attached.launch {
            // The drain is the one writer of what the core reports: the
            // first status is read here, before any change it drains, so a
            // newer change is never overwritten by an older read.
            runCatching { withContext(read) { core.status() } }
                .onSuccess(::apply)
                .onFailure { AppLog.w(TAG, "status unread: ${it.javaClass.simpleName}") }
            // A wake raised before the listener is not raised again.
            wakes.trySend(Unit)
            for (wake in wakes) drain()
        }
        return attached.launch {
            pushPolicy(preferences.policy.first())
            attached.launch { preferences.policy.drop(1).collect(::pushPolicy) }
            if (kind == CoreKind.Live) attached.launch { preferences.onboarding.collect { _onboarding.value = it } }
            attached.launch { foregroundSignals.collect { onForeground() } }
            attached.launch { tickClock() }
            attached.launch(Dispatchers.IO) {
                val protection = protection()
                _identity.update { it.copy(protection = protection) }
            }

            seed?.let { seed ->
                // In the runtime's scope, not the attachment's, and not
                // cancelable once begun: the seed writes in several steps,
                // and the host waits for it before stopping the core.
                val job = scope.launch {
                    withContext(NonCancellable) {
                        try {
                            seed(ownerAddress, clock.millis())
                        } catch (error: Exception) {
                            AppLog.e(TAG, "staged content not seeded: ${error.javaClass.simpleName}")
                        }
                    }
                }
                seedJob = job
                job.join()
            }
            // After the seed: setting the owner raises every list, and a
            // drain reading them before the seed would publish an empty mesh.
            withContext(read) { core.setOwner(ownerAddress) }
            reload(full = true).await()
            startCore()
        }.also { startJob = it }
    }

    /**
     * Stop observing: the drain, the collectors and the clock end, and the
     * listener is cleared. The core and its radio keep running; the host
     * stops them.
     */
    fun detach() {
        attachment.cancel()
        wakes.close()
        runCatching { core.clearListener() }
    }

    /** Wait for a staged seed this runtime began. */
    suspend fun seedFinished() {
        seedJob?.join()
    }

    /** Re-read the lists; a full read takes the peers and reports too. */
    fun reload(full: Boolean): Deferred<Unit> = reloads.request(full)

    fun dismissFailureNotice() {
        _failureNotice.value = null
    }

    /** The clock, zone or locale changed. */
    fun timeChanged() {
        _now.value = clock.instant()
    }

    // region Commands

    /** Save this phone's advertised name; trimmed, empty clears it. Answers what was saved. */
    fun saveName(name: String): Deferred<String> = scope.async {
        // The write needs the owner, which the start sets: a Continue that
        // beats the start waits for it rather than failing with no owner.
        startJob?.join()
        val trimmed = name.trim()
        core.setAdvertisedName(trimmed)
        // After the write: a read that began before this bump may have read
        // the old name, and one that begins after it reads the new one.
        nameRevision.incrementAndGet()
        _identity.update { it.copy(advertisedName = trimmed) }
        trimmed
    }

    fun advertise(): Deferred<Unit> = scope.async { core.advertiseIdentity() }

    /** The stored policy, every time it changes: what the settings rows show. */
    val policy: Flow<MobileAppPolicyRecord> get() = preferences.policy

    /** Change the policy; the core gets it from the preferences. */
    fun setPolicy(edit: PolicyPreferences.Editor.() -> Unit): Deferred<Unit> =
        scope.async { preferences.editPolicy(edit) }

    fun setOnboarding(step: OnboardingStep): Deferred<Unit> = scope.async {
        preferences.setOnboarding(step)
        _onboarding.value = step
    }

    /**
     * This phone's `umsh:` link: the core's, carrying the signed identity,
     * when it can give one; otherwise the bare address's, which is still
     * this node. Never fails for the core's sake: stopped, busy (an erase
     * under way) or a signing refusal all leave the bare link, as on iOS.
     */
    fun shareUri(): Deferred<String> = scope.async {
        try {
            core.identityShareUri()
        } catch (error: CancellationException) {
            throw error
        } catch (error: Exception) {
            if (error !is MobileAppException.NotRunning) AppLog.w(TAG, "bare link shared: ${error.javaClass.simpleName}")
            com.voria.umsh.core.nodeUriForAddress(ownerAddress)
        }
    }

    fun markRead(address: String, throughMs: Long?): Deferred<Unit> = scope.async {
        core.markRead(address, throughMs)
        reload(full = false).await()
    }

    /**
     * Delete a conversation and its history from this phone, direct or a
     * channel's. For a channel this is leaving its chat: the channel stays
     * joined, and a new message there opens the conversation again (as iOS;
     * leaving the channel itself is the channel page's, Phase 3).
     */
    fun deleteConversation(address: String): Deferred<Unit> = scope.async {
        core.deleteConversation(address)
        reload(full = false).await()
    }

    /** Open the conversation with a stored peer, or find it open: its address. */
    fun startConversation(peerAddress: String): Deferred<String> = scope.async {
        val address = core.startConversation(peerAddress)
        reload(full = false).await()
        address
    }

    /** Open a joined channel's conversation, or find it open: its address. */
    fun openChannelConversation(channelId: String): Deferred<String> = scope.async {
        val address = core.openChannelConversation(channelId)
        reload(full = false).await()
        address
    }

    /**
     * Keep what is typed: shown at once, saved after a pause. A draft is
     * saved even when what asked for it has gone.
     */
    fun saveDraft(address: String, text: String) {
        synchronized(draftLock) {
            pendingDrafts[address] = text
            draftTimers.remove(address)?.cancel()
            draftTimers[address] = scope.launch {
                delay(draftDebounceMs)
                withContext(NonCancellable) { persistDraft(address) }
            }
        }
        _appState.update { it?.let(::withPendingDrafts) }
    }

    /** Save every pending draft now: on leaving a thread, and when the app stops. */
    fun flushDrafts(): Deferred<Unit> = scope.async {
        val addresses = synchronized(draftLock) {
            draftTimers.values.forEach { it.cancel() }
            draftTimers.clear()
            pendingDrafts.keys.toList()
        }
        withContext(NonCancellable) { addresses.forEach { persistDraft(it) } }
    }

    private suspend fun persistDraft(address: String) {
        val text = synchronized(draftLock) { pendingDrafts[address] } ?: return
        try {
            core.saveDraft(address, text)
        } catch (error: MobileAppException) {
            AppLog.w(TAG, "draft not saved: ${error.javaClass.simpleName}")
            return
        }
        synchronized(draftLock) { pendingDrafts.remove(address, text) }
    }

    private fun withPendingDrafts(state: AppStateSnapshot): AppStateSnapshot {
        val pending = synchronized(draftLock) { HashMap(pendingDrafts) }
        if (pending.isEmpty()) return state
        return state.copy(
            directConversations = state.directConversations.map { conversation ->
                pending[conversation.address]?.let { conversation.copy(draftText = it) } ?: conversation
            },
            channelConversations = state.channelConversations.map { conversation ->
                pending[conversation.address]?.let { conversation.copy(draftText = it) } ?: conversation
            },
        )
    }

    // endregion

    // region Transcripts

    suspend fun transcriptNewest(address: String, limit: Int): TranscriptPage =
        page { core.transcriptNewest(address, limit.toUInt()) }

    suspend fun transcriptBefore(address: String, cursor: TranscriptCursor, limit: Int): TranscriptPage =
        page { core.transcriptBefore(address, cursor(cursor), limit.toUInt()) }

    suspend fun transcriptAfter(
        address: String,
        cursor: TranscriptCursor,
        including: Boolean,
        limit: Int,
    ): TranscriptPage = page { core.transcriptAfter(address, cursor(cursor), including, limit.toUInt()) }

    /** The page around [message]; null when it is no longer stored. */
    suspend fun transcriptAround(address: String, message: MessageRef, radius: Int): TranscriptPage? =
        withContext(read) { core.transcriptAround(address, RecordMapping.ref(message), radius.toUInt()) }
            ?.let { RecordMapping.page(it, _appState.value?.peers.orEmpty()) }

    private suspend fun page(query: () -> MobileAppTranscriptPageRecord): TranscriptPage {
        val record = withContext(read) { query() }
        return RecordMapping.page(record, _appState.value?.peers.orEmpty())
    }

    private fun cursor(cursor: TranscriptCursor) = MobileStoredChatCursorRecord(cursor.createdAtMs, cursor.rowId)

    // endregion

    // region The core's changes

    /** Apply one batch of what the core changed. One loop runs these in turn. */
    private suspend fun drain() {
        val changes = try {
            withContext(read) { core.pollChanges() }
        } catch (error: Exception) {
            if (error is CancellationException) throw error
            AppLog.w(TAG, "changes unread: ${error.javaClass.simpleName}")
            return
        }
        changes.radio?.let { apply(RadioSnapshot.from(it)) }
        changes.forwardSecretConversations?.let { _forwardSecretConversations.value = it.toSet() }
        changes.emergencyCertified?.let { _emergencyCertified.value = it }
        val transcripts = changes.transcripts.toMutableSet()
        if (changes.allTranscripts) {
            // A change the core could not place: re-reading every shown
            // transcript costs a bounded query each; missing the right one
            // leaves it showing something no longer true.
            _appState.value?.conversations?.mapTo(transcripts) { it.address }
            visibleConversation.value?.let(transcripts::add)
        }
        // Before the lists publish: the reload carries the bumped revision.
        if (transcripts.isNotEmpty()) {
            _transcriptRevisions.update { revisions ->
                revisions.toMutableMap().apply { transcripts.forEach { merge(it, 1L, Long::plus) } }
            }
        }
        if (changes.peersChanged || changes.channelsChanged || changes.exchangedPeer != null) {
            reload(full = true).await()
        } else if (changes.conversationsChanged || transcripts.isNotEmpty()) {
            reload(full = false).await()
        }
        // After the lists it came with: a start reports Running with the
        // conversations it opened, and Running over lists not yet read
        // would show them as none.
        changes.lifecycle?.let(::apply)
        // Notifications are Phase 2's: drained and left.
    }

    private fun apply(status: MobileAppStatusRecord) {
        apply(status.lifecycle)
        apply(RadioSnapshot.from(status.radio))
        _forwardSecretConversations.value = status.forwardSecretConversations.toSet()
        _emergencyCertified.value = status.emergencyCertified
    }

    private fun apply(radio: RadioSnapshot?) {
        if (radio?.phase != _radio.value?.phase) AppLog.i(TAG, "radio: ${radio?.phase ?: "none"}")
        _radio.value = radio
        _radioKnown.value = true
    }

    private fun apply(lifecycle: MobileAppLifecycle) {
        if (lifecycle != _lifecycle.value) AppLog.i(TAG, "lifecycle: ${lifecycle.javaClass.simpleName}")
        _lifecycle.value = lifecycle
        if (lifecycle !is MobileAppLifecycle.Failed) return
        AppLog.e(TAG, "the core did not start: ${lifecycle.reason}")
        if (shownStartFailures.add(lifecycle.reason)) {
            _failureNotice.value = FailureNotice.StartFailed(lifecycle.reason)
        }
    }

    private suspend fun performReload(full: Boolean) {
        try {
            // Before the read: a name saved after this point is newer than what it reads.
            val revision = nameRevision.get()
            val previous = _appState.value
            var isFull = full || previous == null
            var record = withContext(read) { core.state(!isFull) }
            // A conversation with a peer not yet read needs the peers too,
            // rather than a row with nothing to draw.
            if (!isFull) {
                val known = previous?.peers.orEmpty().mapTo(HashSet()) { it.id }
                if (record.directConversations.any { it.peer.stored.id !in known }) {
                    isFull = true
                    record = withContext(read) { core.state(false) }
                }
            }
            val mapped = withPendingDrafts(RecordMapping.state(record, _transcriptRevisions.value, _appState.value))
            _appState.value = mapped
            // A name saved while the read ran is newer than the one it read.
            if (revision == nameRevision.get()) {
                _identity.update { it.copy(advertisedName = record.advertisedName.orEmpty()) }
            }
            if (isFull) _stateLoadError.value = false
        } catch (error: CancellationException) {
            throw error
        } catch (error: MobileAppException.Store) {
            AppLog.e(TAG, "state unread: store ${error.error.javaClass.simpleName}")
            _stateLoadError.value = true
        } catch (error: MobileAppException) {
            // No owner yet, or the core busy or stopped: the lists stand.
            AppLog.d(TAG, "state unread: ${error.javaClass.simpleName}")
        }
    }

    // endregion

    // region Starting

    /**
     * Start the core on the stored identity, unlocked afresh: a start
     * consumes it, and a failed one needs another. A core already starting
     * or running is left alone.
     */
    private suspend fun startCore() {
        if (!startLock.tryLock()) return
        try {
            val status = try {
                withContext(read) { core.status() }
            } catch (error: MobileAppException) {
                AppLog.w(TAG, "status unread: ${error.javaClass.simpleName}")
                return
            }
            val lifecycle = status.lifecycle
            if (lifecycle !is MobileAppLifecycle.Idle && lifecycle !is MobileAppLifecycle.Failed) return
            val unlocked = try {
                withContext(Dispatchers.IO) { identityOps.unlock() }
            } catch (error: CancellationException) {
                throw error
            } catch (error: IdentityVaultException.Lost) {
                startPending = false
                onIdentityLost(error.detail)
                return
            } catch (error: MobileException) {
                // A stored secret the core refuses is no less lost.
                startPending = false
                onIdentityLost("unlock: ${error.javaClass.simpleName}")
                return
            } catch (error: Exception) {
                // The Keystore not ready: the secret stays stored, and the
                // next foreground tries again. Pending before the line is
                // logged, so whoever reads it finds the retry armed.
                startPending = true
                AppLog.e(TAG, "identity not unlocked: ${error.javaClass.simpleName}")
                return
            }
            startPending = false
            AppLog.i(TAG, "starting the core ($kind)")
            unlocked.use {
                try {
                    core.start(it)
                } catch (_: MobileAppException.Busy) {
                    // Another start got there first.
                } catch (error: MobileAppException) {
                    // A failed start arrives as the lifecycle, and is shown there.
                    AppLog.e(TAG, "start failed: ${error.javaClass.simpleName}")
                }
            }
        } finally {
            startLock.unlock()
        }
    }

    private suspend fun onForeground() {
        // Schedules that came due while the phone slept go now.
        runCatching { core.resumed() }
        if (_lifecycle.value is MobileAppLifecycle.Failed || startPending) {
            AppLog.i(TAG, "retrying the start")
            startLock.withLock { } // a start under way finishes first
            startCore()
        }
    }

    private suspend fun pushPolicy(policy: MobileAppPolicyRecord) {
        try {
            core.setPolicy(policy)
        } catch (error: MobileAppException) {
            AppLog.w(TAG, "policy not taken: ${error.javaClass.simpleName}")
        }
    }

    private suspend fun tickClock() {
        while (true) {
            delay(MINUTE_MS - clock.millis() % MINUTE_MS)
            _now.value = clock.instant()
        }
    }

    // endregion

    private companion object {
        const val TAG = "umsh.runtime"
        const val DRAFT_DEBOUNCE_MS = 500L
        const val MINUTE_MS = 60_000L
    }
}
