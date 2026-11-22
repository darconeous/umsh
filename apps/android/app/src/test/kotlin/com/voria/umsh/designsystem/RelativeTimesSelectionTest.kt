package com.voria.umsh.designsystem

import com.voria.umsh.services.format.AgeUnit
import com.voria.umsh.services.format.TimeFormatting
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * A stand-in [TimeFormatting] for the JVM: fixed `java.time` patterns, not
 * ICU's. Its text is not what the app shows; it only makes each piece
 * recognizable, so the tests can see which one was chosen.
 * `AndroidTimeFormattingTest` (instrumented) covers the real text.
 */
class JvmTimeFormatting(override val zone: ZoneId, use24Hour: Boolean) : TimeFormatting {
    private val time = if (use24Hour) "H:mm" else "h:mm a"
    private fun f(pattern: String, at: Instant) =
        DateTimeFormatter.ofPattern(pattern, Locale.US).withZone(zone).format(at)

    override fun timeOfDay(at: Instant) = f(time, at)
    override fun weekday(at: Instant) = f("EEE", at)
    override fun monthDay(at: Instant) = f("MMM d", at)
    override fun monthDayYear(at: Instant) = f("MMM d, y", at)
    override fun monthDayTime(at: Instant) = f("MMM d $time", at)
    override fun monthDayYearTime(at: Instant) = f("MMM d, y $time", at)
    override fun ago(count: Long, unit: AgeUnit) = "$count ${unit.name.lowercase()} ago"
    override fun agoSpoken(count: Long, unit: AgeUnit) = "$count ${unit.name.lowercase()} ago, spoken"
}

/** Which piece [RelativeTimes] picks for a time, by calendar day. */
class RelativeTimesSelectionTest {
    private val zone = ZoneId.of("America/Los_Angeles")
    private val now = at(2026, 11, 3, 10, 24) // a Tuesday
    private fun at(y: Int, mo: Int, d: Int, h: Int, mi: Int): Instant =
        LocalDateTime.of(y, mo, d, h, mi).atZone(zone).toInstant()

    private val twelve = JvmTimeFormatting(zone, use24Hour = false)
    private val twentyFour = JvmTimeFormatting(zone, use24Hour = true)

    /** Today: a time; yesterday; within the week: a weekday; this year: a month and day; else the year too. */
    @Test
    fun listTimes() {
        assertEquals(ListTime.Text("10:21"), RelativeTimes.listTime(at(2026, 11, 3, 10, 21), now, twentyFour))
        assertEquals(ListTime.Text("10:21 AM"), RelativeTimes.listTime(at(2026, 11, 3, 10, 21), now, twelve))
        assertEquals(ListTime.Text("0:05"), RelativeTimes.listTime(at(2026, 11, 3, 0, 5), now, twentyFour))
        assertEquals(ListTime.Yesterday, RelativeTimes.listTime(at(2026, 11, 2, 23, 59), now, twelve))
        assertEquals(ListTime.Text("Wed"), RelativeTimes.listTime(at(2026, 10, 28, 9, 0), now, twelve))
        assertEquals(ListTime.Text("Oct 27"), RelativeTimes.listTime(at(2026, 10, 27, 9, 0), now, twelve))
        assertEquals(ListTime.Text("Dec 30, 2025"), RelativeTimes.listTime(at(2025, 12, 30, 9, 0), now, twelve))
        // A time ahead of the clock (a skewed peer) still reads as a time.
        assertEquals(ListTime.Text("11:00 AM"), RelativeTimes.listTime(at(2026, 11, 3, 11, 0), now, twelve))
    }

    /** Today and Yesterday carry a time; older lines a month and day with a time, and the year if it differs. */
    @Test
    fun dateLines() {
        assertEquals(DateLine.Today("9:40 AM"), RelativeTimes.dateLine(at(2026, 11, 3, 9, 40), now, twelve))
        assertEquals(DateLine.Today("9:40"), RelativeTimes.dateLine(at(2026, 11, 3, 9, 40), now, twentyFour))
        assertEquals(DateLine.Yesterday("6:12 PM"), RelativeTimes.dateLine(at(2026, 11, 2, 18, 12), now, twelve))
        assertEquals(DateLine.Text("Oct 28 9:00"), RelativeTimes.dateLine(at(2026, 10, 28, 9, 0), now, twentyFour))
        assertEquals(DateLine.Text("Dec 30, 2025 9:00 AM"), RelativeTimes.dateLine(at(2025, 12, 30, 9, 0), now, twelve))
    }

    @Test
    fun agesUseWholeUnitsAndNeverSeconds() {
        assertEquals(Age.JustNow, RelativeTimes.age(now.minusSeconds(59), now))
        assertEquals(Age.Ago(1, AgeUnit.Minutes), RelativeTimes.age(now.minusSeconds(60), now))
        assertEquals(Age.Ago(12, AgeUnit.Minutes), RelativeTimes.age(now.minusSeconds(12 * 60 + 59), now))
        assertEquals(Age.Ago(2, AgeUnit.Hours), RelativeTimes.age(now.minusSeconds(2 * 3600 + 1), now))
        assertEquals(Age.Ago(3, AgeUnit.Days), RelativeTimes.age(now.minusSeconds(3 * 86_400), now))
        assertEquals(Age.JustNow, RelativeTimes.age(now.plusSeconds(30), now))
    }
}
