package com.voria.umsh.services.mobilecore

import androidx.annotation.StringRes
import com.voria.umsh.R
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileAppStartFailure
import com.voria.umsh.core.MobileStoreException
import com.voria.umsh.core.SecretVaultException
import com.voria.umsh.core.ulcpStatusName
import com.voria.umsh.services.identity.IdentityVaultException

/** A reason phrase: a string resource and its arguments. */
data class ReasonText(@param:StringRes val id: Int, val args: List<Any> = emptyList())

/**
 * What the core's failures say to the person holding the phone.
 *
 * The core sends codes and never display text; these are the only words
 * for them, and an exception's `message` is never shown. Each `when` is
 * exhaustive with no `else`, so a variant added to the bindings fails the
 * build here until it has words.
 */
object CoreErrors {
    /** What a failed command says, whatever it threw. */
    fun reason(error: Throwable): ReasonText = when (error) {
        is MobileAppException -> reason(error)
        is MobileStoreException -> reason(error)
        is SecretVaultException -> reason(error)
        is IdentityVaultException -> reason(error)
        else -> ReasonText(R.string.reason_unknown)
    }

    fun reason(error: MobileAppException): ReasonText = when (error) {
        is MobileAppException.Store -> ReasonText(R.string.reason_store)
        is MobileAppException.InvalidInput -> ReasonText(R.string.reason_invalid_input)
        is MobileAppException.InvalidRequest,
        is MobileAppException.OperationReused,
        -> ReasonText(R.string.reason_invalid_request)
        is MobileAppException.NotFound -> ReasonText(R.string.reason_not_found)
        is MobileAppException.ChannelTableFull -> ReasonText(R.string.reason_channel_table_full)
        is MobileAppException.NoOwner,
        is MobileAppException.NotRunning,
        -> ReasonText(R.string.reason_not_running)
        is MobileAppException.Busy -> ReasonText(R.string.reason_busy)
        is MobileAppException.Stopped -> ReasonText(R.string.reason_stopped)
        is MobileAppException.StartFailed -> reason(error.reason)
        is MobileAppException.Vault -> reason(error.error)
        is MobileAppException.CountersNotRemoved -> ReasonText(R.string.reason_counters_not_removed)
        is MobileAppException.NoRadio -> ReasonText(R.string.reason_no_radio)
        is MobileAppException.NotThisPhone -> ReasonText(R.string.reason_not_this_phone)
        is MobileAppException.NoAnswer -> ReasonText(R.string.reason_no_answer)
        is MobileAppException.Unreachable -> ReasonText(R.string.reason_unreachable)
        is MobileAppException.Refused -> ReasonText(R.string.reason_refused, listOf(ulcpStatusName(error.status)))
        is MobileAppException.Unreadable -> ReasonText(R.string.reason_unreadable)
        is MobileAppException.Cancelled -> ReasonText(R.string.reason_cancelled)
        is MobileAppException.SendFailed -> ReasonText(R.string.reason_send_failed)
        is MobileAppException.DfuUnsupported -> ReasonText(R.string.reason_dfu_unsupported)
        is MobileAppException.DfuRefused ->
            ReasonText(R.string.reason_dfu_refused, listOf(ulcpStatusName(error.status)))
        is MobileAppException.DfuUnconfirmed -> ReasonText(R.string.reason_dfu_unconfirmed)
        is MobileAppException.EmergencyNotCertified -> ReasonText(R.string.reason_emergency_not_certified)
        is MobileAppException.MessageNotQueued -> ReasonText(
            if (error.recorded) R.string.reason_message_not_queued else R.string.reason_message_not_recorded,
        )
    }

    fun reason(failure: MobileAppStartFailure): ReasonText = when (failure) {
        MobileAppStartFailure.HOST_KEY -> ReasonText(R.string.reason_start_host_key)
        MobileAppStartFailure.SESSION -> ReasonText(R.string.reason_start_session)
        MobileAppStartFailure.STORE -> ReasonText(R.string.reason_start_store)
    }

    fun reason(error: MobileStoreException): ReasonText = when (error) {
        is MobileStoreException.OpenFailed,
        is MobileStoreException.UnsupportedSchema,
        is MobileStoreException.RecordNotFound,
        is MobileStoreException.InvalidArgument,
        is MobileStoreException.Failed,
        -> ReasonText(R.string.reason_store)
    }

    fun reason(error: SecretVaultException): ReasonText = when (error) {
        is SecretVaultException.Unavailable -> ReasonText(R.string.reason_vault_unavailable)
        is SecretVaultException.Failed -> ReasonText(R.string.reason_vault_failed)
    }

    fun reason(error: IdentityVaultException): ReasonText = when (error) {
        is IdentityVaultException.Unavailable -> ReasonText(R.string.reason_identity_unavailable)
        is IdentityVaultException.Lost -> ReasonText(R.string.reason_identity_lost)
    }
}
