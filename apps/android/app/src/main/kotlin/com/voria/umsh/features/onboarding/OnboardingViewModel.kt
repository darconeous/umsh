package com.voria.umsh.features.onboarding

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.models.LocalIdentity
import com.voria.umsh.services.preferences.OnboardingStep
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** Why Continue stopped; the name stays typed. */
sealed interface WelcomeFailure {
    val error: Throwable

    /** The name was not stored. */
    data class NameNotSaved(override val error: Throwable) : WelcomeFailure

    /** The name was stored; recording that Welcome is done was not. */
    data class StepNotSaved(override val error: Throwable) : WelcomeFailure
}

/**
 * Welcome: the identity already minted, the name to save. Continue saves
 * the name, then moves onboarding on; the shell takes over from there.
 */
class OnboardingViewModel(private val runtime: AppRuntime) : ViewModel() {
    val identity: StateFlow<LocalIdentity> = runtime.identity

    private val _saving = MutableStateFlow(false)
    val saving: StateFlow<Boolean> = _saving.asStateFlow()

    private val _failure = MutableStateFlow<WelcomeFailure?>(null)

    /** Why Continue stopped; the name stays typed. */
    val failure: StateFlow<WelcomeFailure?> = _failure.asStateFlow()

    /**
     * Save [name] (trimmed; empty clears it), then finish Welcome. Phase 1
     * has no radio search, so Welcome goes straight to the shell (D6).
     */
    fun continueWith(name: String) {
        if (_saving.value) return
        _saving.value = true
        viewModelScope.launch {
            try {
                val saved = try {
                    runtime.saveName(name).await()
                    true
                } catch (error: CancellationException) {
                    throw error
                } catch (error: Exception) {
                    _failure.value = WelcomeFailure.NameNotSaved(error)
                    false
                }
                if (saved) {
                    try {
                        runtime.setOnboarding(OnboardingStep.Done).await()
                    } catch (error: CancellationException) {
                        throw error
                    } catch (error: Exception) {
                        _failure.value = WelcomeFailure.StepNotSaved(error)
                    }
                }
            } finally {
                _saving.value = false
            }
        }
    }

    fun dismissFailure() {
        _failure.value = null
    }
}
