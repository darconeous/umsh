package com.voria.umsh.features.conversations

import androidx.compose.foundation.text.input.setTextAndPlaceCursorAtEnd
import androidx.compose.runtime.snapshots.Snapshot
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.ViewModelStore
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.CoreKind
import com.voria.umsh.app.MemoryIdentityVault
import com.voria.umsh.app.MemorySecretVault
import com.voria.umsh.app.VaultLog
import com.voria.umsh.core.MobileAppConfigRecord
import com.voria.umsh.core.MobileAppCore
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.core.MobileAppStore
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.seedStaging
import com.voria.umsh.models.KeyProtection
import com.voria.umsh.services.identity.IdentityOperations
import com.voria.umsh.services.preferences.AppPreferences
import com.voria.umsh.services.preferences.OnboardingStep
import java.io.File
import java.time.Clock
import java.util.concurrent.Executors
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertNotEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** The thread's view model over a real staged core. */
@OptIn(ExperimentalCoroutinesApi::class)
class ThreadViewModelTest {
    @get:Rule val temp = TemporaryFolder()

    private val main = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

    @Before
    fun setUp() = Dispatchers.setMain(main)

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        main.close()
    }

    /**
     * The draft reaches the store when its thread goes, not only after the
     * typing pause: the pause is held off here, so only leaving can save it.
     */
    @Test
    fun leavingTheThreadSavesItsDraft() = runBlocking<Unit> {
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
            platformModel = 65026u,
            generation = 1,
            owner = owner,
            identityOps = IdentityOperations(identity),
            protection = { KeyProtection.Software },
            preferences = AppPreferences(File(temp.newFolder(), "p.preferences_pb"), scope),
            initialOnboarding = OnboardingStep.Welcome,
            seed = { ownerId, nowMs -> seedStaging(store, vault, ownerId, nowMs) },
            foregroundSignals = emptyFlow(),
            clock = Clock.systemUTC(),
            scope = scope,
            draftDebounceMs = HELD_OFF_MS,
        )
        runtime.start()
        withTimeout(TIMEOUT) { runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
        val address = withTimeout(TIMEOUT) {
            runtime.appState.first { state -> state?.directConversations?.any { it.draftText.isEmpty() } == true }
        }!!.directConversations.first { it.draftText.isEmpty() }.address
        fun stored(): String? =
            core.state(true).directConversations.first { it.peer.identity.canonicalAddress == address }.draftText

        val models = ViewModelStore()
        val thread = withContext(main) {
            ViewModelProvider.create(models, viewModelFactory { initializer { ThreadViewModel(runtime, address) } })[ThreadViewModel::class]
        }
        // Typed where the app types: on the main thread, where the view model watches the field.
        withContext(main) {
            thread.draft.setTextAndPlaceCursorAtEnd("Copy that")
            Snapshot.sendApplyNotifications()
        }
        // Shown at once, but not saved: the pause is held off.
        withTimeout(TIMEOUT) { runtime.appState.first { state -> state?.conversations?.any { it.address == address && it.draftText == "Copy that" } == true } }
        assertNotEquals("Copy that", stored())

        withContext(main) { models.clear() }
        withTimeout(TIMEOUT) { while (stored() != "Copy that") delay(POLL_MS) }

        runtime.detach()
        core.stop()
        core.close()
        store.close()
        scope.cancel()
    }

    private companion object {
        const val TIMEOUT = 30_000L
        const val POLL_MS = 20L
        const val HELD_OFF_MS = 3_600_000L
    }
}
