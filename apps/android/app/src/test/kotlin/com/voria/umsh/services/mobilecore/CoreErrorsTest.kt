package com.voria.umsh.services.mobilecore

import com.voria.umsh.R
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileAppStartFailure
import com.voria.umsh.core.MobileException
import com.voria.umsh.core.MobileRadioException
import com.voria.umsh.core.MobileStoreException
import com.voria.umsh.core.SecretVaultException
import com.voria.umsh.services.identity.IdentityVaultException
import com.voria.umsh.services.radio.StatusWords
import com.voria.umsh.services.radio.UlcpStatusText
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class CoreErrorsTest {
    @Test
    fun everyAppFailureHasWords() {
        val failures = listOf(
            MobileAppException.Store(MobileStoreException.Failed(11, "")),
            MobileAppException.InvalidInput(MobileException.InvalidAddressLength()),
            MobileAppException.InvalidRequest(),
            MobileAppException.NotFound(),
            MobileAppException.ChannelTableFull(),
            MobileAppException.NoOwner(),
            MobileAppException.Busy(),
            MobileAppException.Stopped(),
            MobileAppException.NotRunning(),
            MobileAppException.StartFailed(MobileAppStartFailure.SESSION),
            MobileAppException.Vault(SecretVaultException.Unavailable()),
            MobileAppException.CountersNotRemoved(),
            MobileAppException.NoRadio(),
            MobileAppException.NotThisPhone(),
            MobileAppException.NoAnswer(),
            MobileAppException.Unreachable(),
            MobileAppException.Unreadable(),
            MobileAppException.Cancelled(),
            MobileAppException.SendFailed(),
            MobileAppException.DfuUnsupported(),
            MobileAppException.DfuRefused(2u),
            MobileAppException.DfuUnconfirmed(),
            MobileAppException.EmergencyNotCertified(),
            MobileAppException.MessageNotQueued(true),
            MobileAppException.MessageNotQueued(false),
        )
        for (failure in failures) {
            assertNotEquals(failure.javaClass.simpleName, 0, CoreErrors.reason(failure).id)
            assertNotEquals(failure.javaClass.simpleName, R.string.reason_unknown, CoreErrors.reason(failure).id)
        }
    }

    @Test
    fun nestedFailuresSpeakForThemselves() {
        assertEquals(
            ReasonText(R.string.reason_start_session),
            CoreErrors.reason(MobileAppException.StartFailed(MobileAppStartFailure.SESSION)),
        )
        assertEquals(
            ReasonText(R.string.reason_vault_failed),
            CoreErrors.reason(MobileAppException.Vault(SecretVaultException.Failed())),
        )
        assertEquals(
            ReasonText(R.string.reason_message_not_recorded),
            CoreErrors.reason(MobileAppException.MessageNotQueued(false)),
        )
    }

    /** A refusal says its status in the app's words, by code; never the core's debug name ("Status::BUSY"). */
    @Test
    fun aRefusalWordsItsStatusByCode() {
        val reason = CoreErrors.reason(MobileAppException.DfuRefused(12u))
        assertEquals(R.string.reason_dfu_refused, reason.id)
        assertEquals(listOf(StatusWords(R.string.banner_reason_radio_busy, 12)), reason.args)
        val rejected = CoreErrors.reason(MobileRadioException.OperationRejected("release host identity", 1u, "Status::FAILURE"))
        assertEquals(listOf(StatusWords(R.string.ulcp_status_failure, 1)), rejected.args)
        assertEquals(StatusWords(R.string.ulcp_status_code, 42), UlcpStatusText.of(42u))
    }

    @Test
    fun anythingElseIsThisPhonesFault() {
        assertEquals(ReasonText(R.string.reason_unknown), CoreErrors.reason(IllegalStateException()))
        assertEquals(
            ReasonText(R.string.reason_identity_lost),
            CoreErrors.reason(IdentityVaultException.Lost("AEADBadTagException")),
        )
    }
}
