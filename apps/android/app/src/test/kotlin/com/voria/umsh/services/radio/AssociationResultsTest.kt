package com.voria.umsh.services.radio

import com.voria.umsh.services.radio.AssociationResults.Ending
import org.junit.Assert.assertEquals
import org.junit.Test

/** How Android's association dialog ended, read from its result (§7.1 step 2). */
class AssociationResultsTest {
    @Test
    fun allowedWithADeviceIsMade() {
        assertEquals(Ending.Made, AssociationResults.classify(RESULT_OK, hasDevice = true))
    }

    /** The pairing window closed under the dialog: allowed, but nothing to associate. */
    @Test
    fun allowedWithNoDeviceIsNoDevice() {
        assertEquals(Ending.NoDevice, AssociationResults.classify(RESULT_OK, hasDevice = false))
    }

    @Test
    fun dontAllowIsDeclined() {
        assertEquals(Ending.Declined, AssociationResults.classify(RESULT_CANCELED, hasDevice = false))
        assertEquals(Ending.Declined, AssociationResults.classify(AssociationResults.RESULT_USER_REJECTED, hasDevice = false))
        assertEquals(Ending.Declined, AssociationResults.classify(RESULT_CANCELED, hasDevice = false, failureReason = "user_rejected"))
    }

    /** API 35+ says so by code; 33–34 only in the callback's words, alongside a plain cancel. */
    @Test
    fun aLapsedSearchIsNoDevice() {
        assertEquals(Ending.NoDevice, AssociationResults.classify(AssociationResults.RESULT_DISCOVERY_TIMEOUT, hasDevice = false))
        assertEquals(Ending.NoDevice, AssociationResults.classify(RESULT_CANCELED, hasDevice = false, failureReason = "discovery_timeout"))
    }

    @Test
    fun androidsOwnErrorsFail() {
        assertEquals(Ending.Failed, AssociationResults.classify(AssociationResults.RESULT_INTERNAL_ERROR, hasDevice = false))
        assertEquals(Ending.Failed, AssociationResults.classify(AssociationResults.RESULT_SECURITY_ERROR, hasDevice = false))
    }

    /** No dialog was ever shown: the search found nothing, or Android refused. */
    @Test
    fun aFailureBeforeTheDialog() {
        assertEquals(Association.NoDevice, AssociationResults.beforeDialog(null))
        assertEquals(Association.NoDevice, AssociationResults.beforeDialog("Timed out"))
        assertEquals(Association.Declined, AssociationResults.beforeDialog("canceled"))
        assertEquals(Association.Failed, AssociationResults.beforeDialog("internal_error"))
    }

    private companion object {
        const val RESULT_OK = -1
        const val RESULT_CANCELED = 0
    }
}
