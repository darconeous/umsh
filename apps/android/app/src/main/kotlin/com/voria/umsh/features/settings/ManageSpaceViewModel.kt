package com.voria.umsh.features.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppCoreHost
import com.voria.umsh.app.EraseMode
import com.voria.umsh.app.EraseOutcome
import com.voria.umsh.app.StorageSummary
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** Manage space: what is stored, and the two erasures (D8). */
class ManageSpaceViewModel(private val host: AppCoreHost) : ViewModel() {
    private val _summary = MutableStateFlow<StorageSummary?>(null)

    /** Null while it is read. */
    val summary: StateFlow<StorageSummary?> = _summary.asStateFlow()

    private val _erasing = MutableStateFlow(false)
    val erasing: StateFlow<Boolean> = _erasing.asStateFlow()

    private val _failure = MutableStateFlow<EraseOutcome?>(null)

    /** An erase that failed ([EraseOutcome.Failed]) or did not finish ([EraseOutcome.Incomplete]). */
    val failure: StateFlow<EraseOutcome?> = _failure.asStateFlow()

    private val _done = MutableStateFlow(false)

    /** Erased: the screen closes back to the system page. */
    val done: StateFlow<Boolean> = _done.asStateFlow()

    /** Read the figures again: each time the screen is shown, since the app may have changed them. */
    fun refresh() {
        if (_erasing.value) return
        viewModelScope.launch { _summary.value = host.storageSummary() }
    }

    /**
     * [EraseMode.IdentityOnly] keeps messages and peers and, unlike the
     * app's own Erase identity, makes no new identity: the next launch
     * starts at Welcome. [EraseMode.Everything] is Start over.
     */
    fun erase(mode: EraseMode) {
        if (_erasing.value) return
        _erasing.value = true
        viewModelScope.launch {
            when (val outcome = host.erase(mode, thenMint = false, announce = false).await()) {
                EraseOutcome.Done -> _done.value = true
                // Shown, and the screen stays: what is left is in its figures,
                // and Start over is still there.
                is EraseOutcome.Failed, is EraseOutcome.Incomplete, EraseOutcome.Refused -> {
                    if (outcome !is EraseOutcome.Refused) _failure.value = outcome
                    _erasing.value = false
                    _summary.value = host.storageSummary()
                }
            }
        }
    }

    fun dismissFailure() {
        _failure.value = null
    }
}
