package com.voria.umsh.app

import com.voria.umsh.R
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileAppResent
import com.voria.umsh.models.ResendMode
import com.voria.umsh.services.mobilecore.CoreErrors
import com.voria.umsh.services.mobilecore.RecordMapping
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Each answer of a chat command, sorted as the thread words it. */
class SendOutcomeTest {
    @Test
    fun aResendSaysHowItWent() {
        assertEquals(ResendMode.InPlace, RecordMapping.resendMode(MobileAppResent.IN_PLACE))
        assertEquals(ResendMode.AsNew, RecordMapping.resendMode(MobileAppResent.AS_NEW))
    }

    @Test
    fun aMessageKeptEitherWayIsKept() {
        assertEquals(SendOutcome.Kept(recorded = true), SendOutcome.of(MobileAppException.MessageNotQueued(true)))
        assertEquals(SendOutcome.Kept(recorded = false), SendOutcome.of(MobileAppException.MessageNotQueued(false)))
    }

    @Test
    fun everyOtherErrorIsARefusalWithItsOwnWords() {
        val refusals = listOf(
            MobileAppException.EmergencyNotCertified() to R.string.reason_emergency_not_certified,
            MobileAppException.NoRadio() to R.string.reason_no_radio,
            MobileAppException.NotThisPhone() to R.string.reason_not_this_phone,
            MobileAppException.InvalidRequest() to R.string.reason_invalid_request,
            MobileAppException.NotFound() to R.string.reason_not_found,
            MobileAppException.NotRunning() to R.string.reason_not_running,
            MobileAppException.SendFailed() to R.string.reason_send_failed,
        )
        for ((error, words) in refusals) {
            val outcome = SendOutcome.of(error)
            assertTrue(outcome is SendOutcome.Refused)
            assertEquals(words, CoreErrors.reason((outcome as SendOutcome.Refused).error).id)
        }
    }

    @Test
    fun onlyTheEmergencyRefusalAsksForTheWarning() {
        assertTrue((SendOutcome.of(MobileAppException.EmergencyNotCertified()) as SendOutcome.Refused).needsEmergencyAgreement)
        assertFalse((SendOutcome.of(MobileAppException.NoRadio()) as SendOutcome.Refused).needsEmergencyAgreement)
        assertTrue(ResendOutcome.Refused(MobileAppException.EmergencyNotCertified()).needsEmergencyAgreement)
    }
}
