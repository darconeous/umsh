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
 * the name, then moves onboarding on to Connect a radio, or, with a radio
 * already set up (an identity erased and made again keeps it), straight
 * to the shell.
 */
class OnboardingViewModel(
    private val runtime: AppRuntime,
    /** A radio is set up already; read as Continue moves on. */
    private val radioSetUp: suspend () -> Boolean = { false },
) : ViewModel() {
    val identity: StateFlow<LocalIdentity> = runtime.identity

    private val _saving = MutableStateFlow(false)
    val saving: StateFlow<Boolean> = _saving.asStateFlow()

    private val _failure = MutableStateFlow<WelcomeFailure?>(null)

    /** Why Continue stopped; the name stays typed. */
    val failure: StateFlow<WelcomeFailure?> = _failure.asStateFlow()

    /** Save [name] (trimmed; empty clears it), then finish Welcome. */
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
                        val next = if (radioSetUp()) OnboardingStep.Done else OnboardingStep.ConnectRadio
                        runtime.setOnboarding(next).await()
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
