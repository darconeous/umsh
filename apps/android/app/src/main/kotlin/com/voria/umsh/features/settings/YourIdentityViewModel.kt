package com.voria.umsh.features.settings

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.voria.umsh.app.AppCoreHost
import com.voria.umsh.app.AppRuntime
import com.voria.umsh.app.CoreKind
import com.voria.umsh.app.EraseMode
import com.voria.umsh.core.MobileAppPolicyRecord
import com.voria.umsh.models.LocalIdentity
import com.voria.umsh.services.location.LocationGrant
import com.voria.umsh.services.location.SharedPrecision
import kotlin.coroutines.cancellation.CancellationException
import com.voria.umsh.services.mobilecore.AppLog
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/** The dialog or sheet Your identity has open; one at a time. */
sealed interface IdentityDialog {
    data class EditName(val text: String, val saving: Boolean = false) : IdentityDialog

    data object Qr : IdentityDialog

    data class Schedule(val kind: ScheduleKind) : IdentityDialog

    data object Precision : IdentityDialog

    data object ConfirmErase : IdentityDialog
}

/** A failure that won't fix itself, shown as the failure dialog. */
sealed interface IdentityFailure {
    val error: Throwable

    data class NameNotSaved(override val error: Throwable) : IdentityFailure

    data class NotAdvertised(override val error: Throwable) : IdentityFailure
}

/**
 * Your identity (`identity.svg`). One per shell, in the shell's store: the
 * page is drawn both as the Settings detail placeholder and as its own
 * entry, and both read this one (P1d review R1-4).
 */
class YourIdentityViewModel(private val runtime: AppRuntime, private val host: AppCoreHost) : ViewModel() {
    val identity: StateFlow<LocalIdentity> = runtime.identity

    /** The stored policy: the Announcements rows' values. Null until read. */
    val policy: StateFlow<MobileAppPolicyRecord?> =
        runtime.policy.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), null)

    private val advertising = MutableStateFlow(false)

    /** Advertise needs the radio attached as this phone's, and none already going out. */
    val canAdvertise: StateFlow<Boolean> = combine(runtime.radio, advertising) { radio, busy ->
        radio?.carriesThisPhone == true && !busy
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(STOP_TIMEOUT_MS), runtime.radio.value?.carriesThisPhone == true)

    /** What Android allows of this phone's location: Share location's states. */
    val locationGrant: StateFlow<LocationGrant> = runtime.locationGrant

    /** The precisions on offer, and the approximate clamp. */
    val precisions: SharedPrecision = runtime.sharedPrecision

    /** Staging never erases: its identity is the live one (D16). */
    val canErase: Boolean = runtime.kind == CoreKind.Live

    private val _dialog = MutableStateFlow<IdentityDialog?>(null)
    val dialog: StateFlow<IdentityDialog?> = _dialog.asStateFlow()

    private val _failure = MutableStateFlow<IdentityFailure?>(null)
    val failure: StateFlow<IdentityFailure?> = _failure.asStateFlow()

    // No replay: an answer that lands while the page is gone is dropped,
    // never shown the next time it opens.
    private val _advertised = MutableSharedFlow<Unit>(extraBufferCapacity = 1)

    /** Once per Advertise that went out while the page shows: the snackbar. */
    val advertised: Flow<Unit> = _advertised.asSharedFlow()

    private val _shareUri = MutableStateFlow<String?>(null)

    /** This phone's link while the QR sheet is open. */
    val shareUri: StateFlow<String?> = _shareUri.asStateFlow()

    private var shareRead: Job? = null

    fun open(dialog: IdentityDialog) {
        _dialog.value = dialog
        if (dialog == IdentityDialog.Qr) {
            // Never the last opening's link: the name it signed may have changed.
            shareRead?.cancel()
            _shareUri.value = null
            shareRead = viewModelScope.launch { _shareUri.value = link() }
        }
    }

    fun dismissDialog() {
        _dialog.value = null
    }

    fun editName(text: String) {
        _dialog.update { (it as? IdentityDialog.EditName)?.copy(text = text) ?: it }
    }

    /** Save the edited name; the dialog closes on success and stays, with the failure over it, otherwise. */
    fun saveName() {
        val editing = _dialog.value as? IdentityDialog.EditName ?: return
        if (editing.saving) return
        _dialog.value = editing.copy(saving = true)
        viewModelScope.launch {
            try {
                runtime.saveName(editing.text).await()
                _dialog.value = null
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                _dialog.update { (it as? IdentityDialog.EditName)?.copy(saving = false) ?: it }
                _failure.value = IdentityFailure.NameNotSaved(error)
            }
        }
    }

    fun advertise() {
        if (!advertising.compareAndSet(expect = false, update = true)) return
        viewModelScope.launch {
            try {
                runtime.advertise().await()
                _advertised.tryEmit(Unit)
            } catch (error: CancellationException) {
                throw error
            } catch (error: Exception) {
                _failure.value = IdentityFailure.NotAdvertised(error)
            } finally {
                advertising.value = false
            }
        }
    }

    fun setDiscoverable(discoverable: Boolean) {
        runtime.setPolicy { this.discoverable = discoverable }
    }

    fun setSchedule(kind: ScheduleKind, seconds: Int) {
        _dialog.value = null
        runtime.setPolicy {
            when (kind) {
                ScheduleKind.Beacon -> beaconIntervalSeconds = seconds
                ScheduleKind.Identity -> advertIntervalSeconds = seconds
            }
        }
    }

    /** The switch: the choice is written whatever the grant; asking follows it (§3.8). */
    fun setShareLocation(share: Boolean) {
        runtime.setPolicy { shareLocation = share }
    }

    fun setPrecision(precision: UByte) {
        _dialog.value = null
        runtime.setPolicy { locationPrecision = precision.toInt() }
    }

    /** A location dialog was answered: no ON_START follows one, so the grant is read now. */
    fun locationAnswered() {
        runtime.refreshLocationGrant()
    }

    /**
     * Erase this identity and make a new one: Welcome follows. Runs in the
     * host, which replaces this runtime (and this ViewModel with it); a
     * failure is the host's to show.
     */
    fun erase() {
        _dialog.value = null
        if (canErase) host.erase(EraseMode.IdentityOnly, thenMint = true)
    }

    fun dismissFailure() {
        _failure.value = null
    }

    /**
     * This phone's `umsh:` link: with signed identity details when the core
     * can sign them, else the bare address's. Null only if even that
     * cannot be made, which is logged; the sheet's buttons stay disabled.
     */
    suspend fun link(): String? = try {
        runtime.shareUri().await()
    } catch (error: CancellationException) {
        throw error
    } catch (error: Exception) {
        AppLog.e(TAG, "no link: ${error.javaClass.simpleName}")
        null
    }

    private companion object {
        const val STOP_TIMEOUT_MS = 5_000L
        const val TAG = "umsh.identity"
    }
}
