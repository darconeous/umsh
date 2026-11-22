package com.voria.umsh.features

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.platform.app.InstrumentationRegistry
import com.voria.umsh.R
import com.voria.umsh.app.CoreKind
import com.voria.umsh.app.FreshHostRule
import com.voria.umsh.app.HostState
import com.voria.umsh.app.ManageSpaceActivity
import com.voria.umsh.app.Tags
import com.voria.umsh.app.TestUmshApplication
import com.voria.umsh.services.preferences.OnboardingStep
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** Manage space (`manage-space.svg`, D8): works without a store, and ends at a first launch. */
class ManageSpaceTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<ManageSpaceActivity>()

    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val paths get() = (context.applicationContext as TestUmshApplication).paths!!

    /** A corrupt `app.sqlite` → Manage space → Start over, asked twice → a first launch. */
    @Test
    fun startOverFromAnUnopenableStoreIsAFirstLaunch() {
        val store = paths.store(CoreKind.Live).apply { parentFile!!.mkdirs() }
        store.writeBytes(ByteArray(8192) { (it * 31).toByte() })
        fresh.host.ensureRuntime(staging = false)
        runBlocking { withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.StoreUnavailable } } }

        compose.onNodeWithTag(Tags.MANAGE_SPACE_MESSAGES).assertIsDisplayed()
        compose.onNodeWithTag(Tags.MANAGE_SPACE_START_OVER).performClick()
        compose.onNode(hasText(context.getString(R.string.start_over_title))).assertIsDisplayed()
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        compose.onNode(hasText(context.getString(R.string.start_over_again_title))).assertIsDisplayed()
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()

        compose.waitUntil(TIMEOUT) { compose.activity.isFinishing || compose.activity.isDestroyed }
        assertEquals(HostState.NeedsFirstLaunch, fresh.host.state.value)
        assertFalse(store.exists())

        fresh.host.ensureRuntime(staging = false)
        val ready = runBlocking { withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } } as HostState.Ready
        assertEquals(OnboardingStep.Welcome, ready.runtime.onboarding.value)
    }

    /** With a running core: the identity row names it, and Erase identity mints nothing. */
    @Test
    fun eraseIdentityHereMakesNoNewOne() {
        fresh.host.ensureRuntime(staging = false)
        val before = runBlocking { withTimeout(TIMEOUT) { fresh.host.state.first { it is HostState.Ready } } } as HostState.Ready
        runBlocking { before.runtime.saveName("Juniper").await() }
        // The screen read its summary before the name; read it again.
        compose.activityRule.scenario.recreate()
        compose.waitUntil(TIMEOUT) { compose.onAllNodes(hasTestTag(Tags.MANAGE_SPACE_IDENTITY)).fetchSemanticsNodes().isNotEmpty() }
        compose.onNode(hasText("Juniper")).assertIsDisplayed()

        compose.onNodeWithTag(Tags.MANAGE_SPACE_ERASE).performClick()
        compose.onNodeWithTag(Tags.CONFIRM_ACTION).performClick()
        compose.waitUntil(TIMEOUT) { fresh.host.state.value == HostState.NeedsFirstLaunch }
        assertTrue(paths.identity.listFiles().isNullOrEmpty())
    }

    private companion object {
        const val TIMEOUT = 30_000L
    }
}
