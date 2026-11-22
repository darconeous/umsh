package com.voria.umsh.services.format

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The real ICU text for en-US, with the 24-hour setting both ways: the
 * skeletons [AndroidTimeFormatting] asks for and the hour cycle it picks.
 * Newer ICU puts a narrow no-break space before AM/PM; the comparison reads
 * every space as a plain one, so the test holds across API levels.
 */
@RunWith(AndroidJUnit4::class)
class AndroidTimeFormattingTest {
    private val zone = ZoneId.of("America/Los_Angeles")
    private val twelve = AndroidTimeFormatting(Locale.US, zone, use24Hour = false)
    private val twentyFour = AndroidTimeFormatting(Locale.US, zone, use24Hour = true)
    private val morning = at(2026, 10, 28, 9, 5)
    private val evening = at(2026, 10, 28, 18, 12)

    private fun at(y: Int, mo: Int, d: Int, h: Int, mi: Int): Instant =
        LocalDateTime.of(y, mo, d, h, mi).atZone(zone).toInstant()

    private fun plain(text: String) = text.replace(' ', ' ').replace(' ', ' ')

    @Test
    fun timeOfDayFollowsTheHourCycle() {
        assertEquals("9:05 AM", plain(twelve.timeOfDay(morning)))
        assertEquals("6:12 PM", plain(twelve.timeOfDay(evening)))
        assertEquals("09:05", plain(twentyFour.timeOfDay(morning)))
        assertEquals("18:12", plain(twentyFour.timeOfDay(evening)))
    }

    @Test
    fun datesInTheFormattersZone() {
        assertEquals("Wed", twelve.weekday(morning))
        assertEquals("Oct 28", twelve.monthDay(morning))
        assertEquals("Oct 28, 2026", twelve.monthDayYear(morning))
        // 23:30 UTC on the 28th is still the 28th in Los Angeles.
        assertEquals("Oct 28", twelve.monthDay(Instant.parse("2026-10-28T23:30:00Z")))
    }

    @Test
    fun datesWithATimeFollowTheHourCycle() {
        assertEquals("Oct 28, 6:12 PM", plain(twelve.monthDayTime(evening)))
        assertEquals("Oct 28, 18:12", plain(twentyFour.monthDayTime(evening)))
        assertEquals("Oct 28, 2026, 6:12 PM", plain(twelve.monthDayYearTime(evening)))
        assertEquals("Oct 28, 2026, 18:12", plain(twentyFour.monthDayYearTime(evening)))
    }

    @Test
    fun agesUseTheShortStyle() {
        assertEquals("1 min. ago", twelve.ago(1, AgeUnit.Minutes))
        assertEquals("12 min. ago", twelve.ago(12, AgeUnit.Minutes))
        assertEquals("20 hr. ago", twentyFour.ago(20, AgeUnit.Hours))
        assertEquals("3 days ago", twelve.ago(3, AgeUnit.Days))
    }
}
