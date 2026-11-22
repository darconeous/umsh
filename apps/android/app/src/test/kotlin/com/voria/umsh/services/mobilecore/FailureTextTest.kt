package com.voria.umsh.services.mobilecore

import com.voria.umsh.R
import com.voria.umsh.core.MobileAppException
import com.voria.umsh.core.MobileStoreException
import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FailureTextTest {
    /** `onboarding.svg` board 3: a full disk reads "Android reported: the disk is full." */
    @Test
    fun aStorageFailureNamesWhatAndroidReported() {
        assertEquals(
            FailureReason.Android(ReasonText(R.string.android_reason_full)),
            FailureText.reason(MobileAppException.Store(MobileStoreException.Failed(13, "database or disk is full"))),
        )
        // An extended code reads as its primary.
        assertEquals(ReasonText(R.string.android_reason_io), FailureText.sqlite(10 or (3 shl 8)))
        assertEquals(ReasonText(R.string.android_reason_damaged), FailureText.sqlite(26))
        assertEquals(
            FailureReason.Android(ReasonText(R.string.android_reason_cant_open)),
            FailureText.reason(MobileStoreException.OpenFailed(14)),
        )
        assertEquals(ReasonText(R.string.android_reason_code, listOf("SQLITE_PROTOCOL")), FailureText.sqlite(15))
        assertEquals(FailureReason.Android(ReasonText(R.string.android_reason_io)), FailureText.reason(IOException("x")))
    }

    /** Anything else is the core's own sentence. */
    @Test
    fun otherFailuresUseTheReasonSentence() {
        assertEquals(
            FailureReason.Sentence(ReasonText(R.string.reason_no_radio)),
            FailureText.reason(MobileAppException.NoRadio()),
        )
        assertEquals(
            FailureReason.Sentence(ReasonText(R.string.reason_store)),
            FailureText.reason(MobileAppException.Store(MobileStoreException.UnsupportedSchema(40))),
        )
    }

    @Test
    fun detailsCarryTheCauses() {
        val details = FailureText.details(IllegalStateException("outer", IOException("inner")))
        assertTrue(details, details.startsWith("java.lang.IllegalStateException: outer\ncaused by java.io.IOException: inner"))
    }
}
