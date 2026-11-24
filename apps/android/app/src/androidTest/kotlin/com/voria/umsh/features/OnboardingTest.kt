package com.voria.umsh.features

import android.content.ClipboardManager
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsFocused
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.AppRoot
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.CoreKind
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.LocalAppCoreHost
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.app.TestUmshApplication
import com.voria.umsh.core.MobileAppConfigRecord
import com.voria.umsh.core.MobileAppCore
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileAppPolicyRecord
import com.voria.umsh.core.MobileAppStore
import com.voria.umsh.core.MobileIdentity
import com.voria.umsh.core.MobileStoreException
import com.voria.umsh.core.generateIdentitySecret
import com.voria.umsh.designsystem.NoticeHost
import com.voria.umsh.designsystem.UmshTheme
import com.voria.umsh.features.onboarding.WelcomeContent
import com.voria.umsh.features.onboarding.WelcomeFailure
import com.voria.umsh.features.onboarding.WelcomeScreen
import com.voria.umsh.models.KeyProtection
import com.voria.umsh.models.NodeHint
import com.voria.umsh.models.Octets
import com.voria.umsh.services.identity.CoreSecretVault
import com.voria.umsh.services.identity.IdentityOperations
import com.voria.umsh.services.identity.KeystoreIdentityVault
import com.voria.umsh.services.identity.KeystoreSecretVault
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.services.preferences.PolicyPreferences
import com.voria.umsh.services.preferences.RuntimePreferences
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind
import java.io.File
import java.io.IOException
import java.time.Clock
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.util.Locale

/** First launch (`onboarding.svg` boards 1–3): Welcome replaces the shell until a name is saved, or left empty. */
class OnboardingTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    private fun waitFor(tag: String) =
        compose.waitUntil(TIMEOUT) { compose.onAllNodes(hasTestTag(tag)).fetchSemanticsNodes().isNotEmpty() }

    /**
     * Boards 1–4 and Set up later: a name, then Connect a radio over
     * Welcome (Back returns to it), then Conversations without a radio.
     */
    @Test
    fun aFirstLaunchAsksForANameThenARadioThenShowsConversations() {
        fresh.host.ensureRuntime(staging = false)
        val runtime = runBlocking {
            (withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready).runtime
        }
        compose.setContent { AppRoot(fresh.host) }
        waitFor(Tags.WELCOME)
        compose.onNodeWithTag(Tags.SHELL).assertDoesNotExist()
        compose.onNodeWithTag(Tags.WELCOME_NAME).assertIsFocused()
        compose.onNodeWithTag(Tags.WELCOME_NAME).performTextInput("Juniper")
        compose.onNodeWithTag(Tags.WELCOME_CONTINUE).performClick()

        waitFor(Tags.CONNECT_RADIO)
        assertEquals(OnboardingStep.ConnectRadio, runtime.onboarding.value)
        compose.activityRule.scenario.onActivity { it.onBackPressedDispatcher.onBackPressed() }
        waitFor(Tags.WELCOME_CONTINUE)
        compose.waitUntil(TIMEOUT) { runtime.onboarding.value == OnboardingStep.Welcome }
        compose.onNodeWithTag(Tags.WELCOME_CONTINUE).performClick()
        waitFor(Tags.CONNECT_RADIO)
        compose.onNodeWithTag(Tags.SET_UP_LATER).performClick()

        waitFor(Tags.CONVERSATIONS_ROOT)
        assertEquals(OnboardingStep.Done, runtime.onboarding.value)
        assertEquals("Juniper", runtime.identity.value.advertisedName)
        assertEquals("Juniper", runBlocking { runtime.core.state(true).advertisedName })
    }

    /** A radio already set up (bound before Welcome finished): Continue goes straight to Conversations. */
    @Test
    fun continueWithARadioSetUpSkipsConnectARadio() {
        fresh.host.ensureRuntime(staging = false)
        val runtime = runBlocking {
            (withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready).runtime
        }
        // Bound without connecting: only the registry says a radio is set up.
        runBlocking {
            fresh.host.preferences.radioRegistry.bind(BoundRadio(RadioKind.Tcp, "10.0.2.2:21838", autoConnect = false))
        }
        compose.setContent { AppRoot(fresh.host) }
        waitFor(Tags.WELCOME_CONTINUE)
        compose.onNodeWithTag(Tags.WELCOME_CONTINUE).performClick()

        waitFor(Tags.CONVERSATIONS_ROOT)
        compose.onNodeWithTag(Tags.CONNECT_RADIO).assertDoesNotExist()
        assertEquals(OnboardingStep.Done, runtime.onboarding.value)
    }

    /**
     * Board 3 through the real path: Continue's ViewModel, the runtime and a
     * core that refuses the write (it has no owner). The dialog says the
     * name was not saved, the name stays typed, and Welcome stays.
     */
    @Test
    fun aNameThatWontSaveSaysWhyAndKeepsTheName() {
        val bench = Bench(owned = false)
        showWelcome(bench.runtime)
        compose.onNodeWithTag(Tags.WELCOME_NAME).performTextInput("Juniper")
        compose.onNodeWithTag(Tags.WELCOME_CONTINUE).performClick()
        waitFor(Tags.FAILURE_DIALOG)
        compose.onNode(hasText(context.getString(R.string.name_save_failed_title))).assertIsDisplayed()
        compose.onNode(hasText(context.getString(R.string.name_save_failed_body))).assertIsDisplayed()
        compose.onNodeWithTag(Tags.FAILURE_OK).performClick()
        compose.onNodeWithTag(Tags.FAILURE_DIALOG).assertDoesNotExist()
        compose.onNodeWithTag(Tags.WELCOME_NAME).assertTextContains("Juniper")
        assertEquals(OnboardingStep.Welcome, bench.runtime.onboarding.value)
        assertEquals(OnboardingStep.Welcome, bench.preferences.step.value)
        assertEquals("", bench.runtime.identity.value.advertisedName)
    }

    /**
     * The name saved, then the step would not: the dialog does not say the
     * name was lost, because it was not, and Welcome stays.
     */
    @Test
    fun aStepThatWontSaveSaysTheNameWasKept() {
        val bench = Bench(owned = true, stepFails = true)
        showWelcome(bench.runtime)
        compose.onNodeWithTag(Tags.WELCOME_NAME).performTextInput("Juniper")
        compose.onNodeWithTag(Tags.WELCOME_CONTINUE).performClick()
        waitFor(Tags.FAILURE_DIALOG)
        compose.onNode(hasText(context.getString(R.string.setup_step_failed_title))).assertIsDisplayed()
        compose.onNode(hasText(context.getString(R.string.name_save_failed_title))).assertDoesNotExist()
        compose.onNodeWithTag(Tags.FAILURE_OK).performClick()
        compose.onNodeWithTag(Tags.WELCOME_NAME).assertTextContains("Juniper")
        assertEquals(OnboardingStep.Welcome, bench.runtime.onboarding.value)
        assertEquals("Juniper", runBlocking { bench.core.state(true).advertisedName })
    }

    /** Board 3's reason line: what Android reported, and Copy details. */
    @Test
    fun theFailureDialogSaysWhatAndroidReported() {
        val failure = mutableStateOf<WelcomeFailure?>(null)
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                WelcomeContent(
                    hint = HINT,
                    initialName = "",
                    saving = false,
                    failure = failure.value,
                    onContinue = {
                        failure.value = WelcomeFailure.NameNotSaved(
                            MobileAppException.Store(MobileStoreException.Failed(13, "database or disk is full")),
                        )
                    },
                    onDismissFailure = { failure.value = null },
                )
            }
        }
        compose.onNodeWithTag(Tags.WELCOME_NAME).performTextInput("Juniper")
        compose.onNodeWithTag(Tags.WELCOME_CONTINUE).performClick()
        val reported = context.getString(R.string.failure_reason_android, context.getString(R.string.android_reason_full))
        // The English wording, where the device reads English; the checks below hold in any language.
        if (Locale.getDefault().language == "en") assertEquals("Android reported: the disk is full.", reported)
        compose.onNode(hasTestTag(Tags.FAILURE_DIALOG)).assertIsDisplayed()
        compose.onNode(hasText(context.getString(R.string.name_save_failed_title))).assertIsDisplayed()
        compose.onNode(hasText(reported)).assertIsDisplayed()

        compose.onNodeWithTag(Tags.FAILURE_COPY_DETAILS).performClick()
        compose.waitForIdle()
        val clip = context.getSystemService(ClipboardManager::class.java).primaryClip?.getItemAt(0)?.text?.toString()
        assertTrue(clip.orEmpty(), clip.orEmpty().startsWith("com.voria.umsh.core.MobileAppException\$Store"))
        if (android.os.Build.VERSION.SDK_INT <= android.os.Build.VERSION_CODES.S_V2) {
            // Drawn in the dialog's own window, not under its scrim.
            compose.onNode(hasText(context.getString(R.string.details_copied))).assertIsDisplayed()
        }
        compose.onNodeWithTag(Tags.FAILURE_OK).performClick()
        compose.onNodeWithTag(Tags.FAILURE_DIALOG).assertDoesNotExist()
        compose.onNodeWithTag(Tags.WELCOME_NAME).assertTextContains("Juniper")
    }

    /** A stored name that arrives after the page is drawn is taken up, until the field is typed in. */
    @Test
    fun aStoredNameIsTakenUpUntilTyped() {
        val stored = mutableStateOf("")
        compose.setContent {
            UmshTheme(fallbackScheme = true) {
                WelcomeContent(HINT, stored.value, saving = false, failure = null, onContinue = {}, onDismissFailure = {})
            }
        }
        stored.value = "Juniper"
        compose.waitForIdle()
        compose.onNodeWithTag(Tags.WELCOME_NAME).assertTextContains("Juniper")
        compose.onNodeWithTag(Tags.WELCOME_NAME).performTextInput(" Ridge")
        stored.value = "Other"
        compose.waitForIdle()
        compose.onNodeWithTag(Tags.WELCOME_NAME).assertTextContains("Juniper Ridge")
    }

    private fun showWelcome(runtime: AppRuntime) {
        compose.setContent {
            // The test's host stands in for the app's: Continue reads its (empty) radio registry.
            CompositionLocalProvider(LocalAppRuntime provides runtime, LocalAppCoreHost provides fresh.host) {
                UmshTheme(fallbackScheme = true) { NoticeHost { WelcomeScreen() } }
            }
        }
        waitFor(Tags.WELCOME)
    }

    /** Preferences whose step write can be made to fail. */
    private class StepPreferences(private val fails: Boolean) : RuntimePreferences {
        val step = MutableStateFlow(OnboardingStep.Welcome)
        override val policy: Flow<MobileAppPolicyRecord> = emptyFlow()
        override val onboarding: Flow<OnboardingStep> = step

        override suspend fun setOnboarding(step: OnboardingStep) {
            if (fails) throw IOException("no space left on device")
            this.step.value = step
        }

        override suspend fun editPolicy(edit: PolicyPreferences.Editor.() -> Unit) = Unit
    }

    /**
     * A runtime over a store of its own that is never started: [owned]
     * sets the core's owner, so its store writes are taken; without it the
     * core refuses them.
     */
    private inner class Bench(owned: Boolean, stepFails: Boolean = false) {
        private val paths = (context.applicationContext as TestUmshApplication).paths!!
        private val dir = File(paths.filesDirectory, "bench").apply { mkdirs() }
        private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
        private val store = MobileAppStore.open(File(dir, "app.sqlite").path)
        private val owner = MobileIdentity.unlock(generateIdentitySecret()).use { it.publicIdentity() }
        val preferences = StepPreferences(stepFails)
        val core = MobileAppCore(
            store,
            CoreSecretVault(KeystoreSecretVault(File(dir, "keys"), "${paths.keyAliasPrefix}.bench")),
            MobileAppConfigRecord(File(dir, "counters").apply { mkdirs() }.path, 65026u),
        )
        val runtime = AppRuntime(
            core = core,
            kind = CoreKind.Live,
            platformModel = 65026u,
            generation = 1,
            owner = owner,
            identityOps = IdentityOperations(KeystoreIdentityVault(KeystoreSecretVault(File(dir, "identity"), "${paths.keyAliasPrefix}.benchid"))),
            protection = { KeyProtection.Software },
            preferences = preferences,
            initialOnboarding = OnboardingStep.Welcome,
            seed = null,
            foregroundSignals = emptyFlow(),
            clock = Clock.systemUTC(),
            scope = scope,
        )

        init {
            if (owned) runBlocking { core.setOwner(owner.canonicalAddress) }
            benches += this
        }

        fun close() {
            scope.cancel()
            runBlocking { core.stop() }
            core.close()
            store.close()
        }
    }

    private val benches = mutableListOf<Bench>()

    @After
    fun closeBenches() {
        benches.forEach { it.close() }
    }

    private companion object {
        const val TIMEOUT = 30_000L
        val HINT = NodeHint(Octets(byteArrayOf(0x1e, 0x7b, 0x45)), "Ju8Q")
    }
}
