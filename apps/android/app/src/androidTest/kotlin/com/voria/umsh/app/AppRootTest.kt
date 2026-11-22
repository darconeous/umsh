package com.voria.umsh.app

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.voria.umsh.services.preferences.OnboardingStep
import com.voria.umsh.features.settings.YourIdentityViewModel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * What keeps or discards a shell (`AppRoot`, `RuntimeShell`, `ShellStores`):
 * the same shell comes back after recreation; a new runtime is a new shell,
 * and the old one's ViewModels are cleared.
 */
class AppRootTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ComponentActivity>()

    class Probe : ViewModel() {
        @Volatile var cleared = false

        override fun onCleared() {
            cleared = true
        }
    }

    private fun ready(after: Long = 0): AppRuntime = runBlocking {
        val ready = withTimeout(TIMEOUT) {
            fresh.host.state.first { it is HostState.Ready && it.runtime.generation > after }
        } as HostState.Ready
        // Past Welcome: these tests are about the shell.
        ready.runtime.setOnboarding(OnboardingStep.Done).await()
        ready.runtime
    }

    private val stores: ShellStores get() = ViewModelProvider(compose.activity)[ShellStores::class.java]

    private fun openYourIdentity() {
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_YOUR_IDENTITY).performClick()
        compose.onNodeWithTag(Tags.YOUR_IDENTITY).assertIsDisplayed()
    }

    @Test
    fun recreationTakesTheShellBack() {
        fresh.host.ensureRuntime(staging = false)
        ready()
        val restoration = StateRestorationTester(compose)
        restoration.setContent { AppRoot(fresh.host) }
        openYourIdentity()
        val before = compose.runOnIdle { stores.keys.single() }
        restoration.emulateSavedInstanceStateRestore()
        compose.onNodeWithTag(Tags.YOUR_IDENTITY).assertIsDisplayed()
        compose.onNodeWithTag(Tags.TOP_BAR_BACK).assertIsDisplayed()
        // The same shell key, so the same back stacks.
        compose.runOnIdle { assertEquals(before, stores.keys.single()) }
    }

    @Test
    fun aModeSwitchIsANewShell() {
        fresh.host.ensureRuntime(staging = false)
        val live = ready()
        compose.setContent { AppRoot(fresh.host) }
        openYourIdentity()
        val old = compose.runOnIdle { stores.keys.single() }
        val probe = compose.runOnIdle { ViewModelProvider(stores.owner(old))[Probe::class.java] }

        runBlocking { fresh.host.setStaging(true).join() }
        ready(after = live.generation)
        compose.waitUntil(TIMEOUT) { runCatching { compose.onNodeWithTag(Tags.CONVERSATIONS_ROOT).assertIsDisplayed() }.isSuccess }
        compose.runOnIdle {
            assertTrue("the old shell's ViewModels are cleared", probe.cleared)
            assertFalse(old in stores.keys)
            assertEquals(1, stores.keys.size)
        }
        // New back stacks: Settings is at its root.
        compose.onNodeWithTag(Tags.NAV_SETTINGS).performClick()
        compose.onNodeWithTag(Tags.SETTINGS_ROOT).assertIsDisplayed()
        compose.onNodeWithTag(Tags.YOUR_IDENTITY).assertDoesNotExist()
    }

    /**
     * Your identity is drawn as the Settings detail placeholder and as its
     * own entry; its ViewModel lives in the shell's store, so both are one
     * (P1d review R1-4).
     */
    @Test
    fun yourIdentityKeepsItsViewModelInTheShell() {
        fresh.host.ensureRuntime(staging = false)
        ready()
        compose.setContent { AppRoot(fresh.host) }
        openYourIdentity()
        compose.runOnIdle {
            // A factory that cannot make one: this finds the shell's, or fails.
            val none = object : ViewModelProvider.Factory {
                override fun <T : ViewModel> create(modelClass: Class<T>): T = error("not in the shell's store")
            }
            ViewModelProvider(stores.owner(stores.keys.single()).viewModelStore, none)[YourIdentityViewModel::class.java]
        }
    }

    private companion object {
        const val TIMEOUT = 30_000L
    }
}
