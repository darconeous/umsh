package com.voria.umsh.services.mobilecore

import com.voria.umsh.R
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileAppStartFailure
import com.voria.umsh.core.MobileException
import com.voria.umsh.core.MobileStoreException
import com.voria.umsh.core.SecretVaultException
import com.voria.umsh.core.ulcpStatusName
import com.voria.umsh.services.identity.IdentityVaultException
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
            MobileAppException.Refused(2u),
            MobileAppException.Unreadable(),
            MobileAppException.Cancelled(),
            MobileAppException.OperationReused(),
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

    @Test
    fun aRefusalNamesItsStatusVerbatim() {
        val reason = CoreErrors.reason(MobileAppException.Refused(2u))
        assertEquals(R.string.reason_refused, reason.id)
        assertEquals(listOf(ulcpStatusName(2u)), reason.args)
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
