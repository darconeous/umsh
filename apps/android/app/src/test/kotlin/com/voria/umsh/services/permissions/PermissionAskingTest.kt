package com.voria.umsh.services.permissions

import com.voria.umsh.designsystem.RadioBannerAction
import com.voria.umsh.designsystem.action
import com.voria.umsh.services.radio.RadioBanner
import com.voria.umsh.services.radio.RadioBanner.Reading
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The banner's actions, and whether Allow asks or opens the app's settings. */
class PermissionAskingTest {
    @Test
    fun asksUntilAndroidStopsShowingItsDialog() {
        assertEquals(PermissionRequest.AlreadyGranted, PermissionAsking.decide(granted = true, blocked = true, showRationale = false))
        // Never asked, or only dismissed.
        assertEquals(PermissionRequest.Ask, PermissionAsking.decide(granted = false, blocked = false, showRationale = false))
        // Refused once: Android still shows its dialog.
        assertEquals(PermissionRequest.Ask, PermissionAsking.decide(granted = false, blocked = false, showRationale = true))
        assertEquals(PermissionRequest.Ask, PermissionAsking.decide(granted = false, blocked = true, showRationale = true))
        // Refused again, or "don't ask again": only the settings page can grant it.
        assertEquals(PermissionRequest.OpenSettings, PermissionAsking.decide(granted = false, blocked = true, showRationale = false))
    }

    @Test
    fun blockedOnlyWhenTheResultSaysSo() {
        // First refusal: a rationale to show, still asked.
        assertFalse(PermissionAsking.blockedAfterRefusal(dialogShown = true, rationaleBefore = false, rationaleAfter = true))
        // Dismissed with Back or a tap outside: nothing changes, still asked.
        assertFalse(PermissionAsking.blockedAfterRefusal(dialogShown = true, rationaleBefore = false, rationaleAfter = false))
        // Dismissed after one refusal: the rationale stays.
        assertFalse(PermissionAsking.blockedAfterRefusal(dialogShown = true, rationaleBefore = true, rationaleAfter = true))
        // Second refusal: the rationale is gone.
        assertTrue(PermissionAsking.blockedAfterRefusal(dialogShown = true, rationaleBefore = true, rationaleAfter = false))
        // Answered at once with nothing shown (after Start over, say): already blocked.
        assertTrue(PermissionAsking.blockedAfterRefusal(dialogShown = false, rationaleBefore = false, rationaleAfter = false))
    }

    @Test
    fun eachBannerHasItsAction() {
        val reading = Reading("T1000-E", 78, 1_000L)
        assertEquals(RadioBannerAction.ChooseRadio, RadioBanner.NoRadio.action())
        assertEquals(RadioBannerAction.Details, RadioBanner.Disconnected(reading).action())
        assertEquals(RadioBannerAction.Details, RadioBanner.Failed(reading).action())
        assertEquals(
            RadioBannerAction.Details,
            RadioBanner.TransmissionRejected(RadioBanner.RejectReason.DutyCycle, reading).action(),
        )
        assertEquals(RadioBannerAction.TurnOn, RadioBanner.BluetoothOff(reading).action())
        assertEquals(RadioBannerAction.Allow, RadioBanner.NearbyDenied.action())
    }
}
