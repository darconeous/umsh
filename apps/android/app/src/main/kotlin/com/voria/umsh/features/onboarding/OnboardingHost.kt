package com.voria.umsh.features.onboarding

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.lifecycle.viewmodel.navigation3.rememberViewModelStoreNavEntryDecorator
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberSaveableStateHolderNavEntryDecorator
import androidx.navigation3.ui.NavDisplay
import com.voria.umsh.app.LocalAppRuntime
import com.voria.umsh.app.Tags
import com.voria.umsh.designsystem.NoticeHost
import com.voria.umsh.services.preferences.OnboardingStep

/** The pages of first launch, in order. */
private enum class OnboardingPage { Welcome, ConnectRadio }

/**
 * First launch, in place of the shell (`onboarding.svg`): Welcome, then
 * Connect a radio over it. The stored step is the back stack, so a launch
 * resumes where the last one left off, and Back on Connect a radio returns
 * to Welcome with the predictive back preview. Set up later, or a radio
 * that comes up, finishes onboarding; the shell takes over from there.
 */
@Composable
fun OnboardingHost(step: OnboardingStep) {
    val runtime = LocalAppRuntime.current
    val pages = if (step == OnboardingStep.ConnectRadio) {
        listOf(OnboardingPage.Welcome, OnboardingPage.ConnectRadio)
    } else {
        listOf(OnboardingPage.Welcome)
    }
    NavDisplay(
        backStack = pages,
        onBack = { runtime.setOnboarding(OnboardingStep.Welcome) },
        // Each page's own ViewModels: leaving Connect a radio ends its search.
        entryDecorators = listOf(
            rememberSaveableStateHolderNavEntryDecorator(),
            rememberViewModelStoreNavEntryDecorator(),
        ),
        modifier = Modifier.testTag(Tags.ONBOARDING),
        entryProvider = entryProvider<OnboardingPage> {
            entry(OnboardingPage.Welcome) { NoticeHost { WelcomeScreen() } }
            entry(OnboardingPage.ConnectRadio) {
                val search = rememberRadioSearch(SEARCH_KEY)
                ConnectRadioScreen(
                    search,
                    onSetUpLater = { runtime.setOnboarding(OnboardingStep.Done) },
                    onConnected = { runtime.setOnboarding(OnboardingStep.Done) },
                )
            }
        },
    )
}

private const val SEARCH_KEY = "connect-a-radio"
