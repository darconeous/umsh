package com.voria.umsh.app

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsFocused
import androidx.compose.ui.test.junit4.v2.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import com.voria.umsh.core.MobileAppLifecycle
import com.voria.umsh.services.preferences.OnboardingStep
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

class MainActivityTest {
    @get:Rule(order = 0) val fresh = FreshHostRule()

    @get:Rule(order = 1) val compose = createAndroidComposeRule<MainActivity>()

    /** A launch brings a live runtime up, over the test's own files. */
    @Test
    fun launchesTheRuntimeUnderTheTestApplication() = runBlocking<Unit> {
        compose.onNodeWithTag(Tags.APP_ROOT).assertIsDisplayed()
        val ready = withTimeout(30_000) { fresh.host.state.first { it is HostState.Ready } } as HostState.Ready
        assertEquals(CoreKind.Live, ready.runtime.kind)
        withTimeout(30_000) { ready.runtime.lifecycle.first { it is MobileAppLifecycle.Running } }
    }

    /** Compose restores no focus: open search takes it again in a recreated activity. */
    @Test
    fun searchKeepsFocusAcrossRecreation() {
        val ready = runBlocking { withTimeout(30_000) { fresh.host.state.first { it is HostState.Ready } } } as HostState.Ready
        runBlocking { ready.runtime.setOnboarding(OnboardingStep.Done).await() }
        compose.onNodeWithTag(Tags.CONVERSATIONS_SEARCH).performClick()
        compose.onNodeWithTag(Tags.SEARCH_FIELD).assertIsFocused()
        compose.activityRule.scenario.recreate()
        compose.onNodeWithTag(Tags.SEARCH_VIEW).assertIsDisplayed()
        compose.onNodeWithTag(Tags.SEARCH_FIELD).assertIsFocused()
    }
}
