package com.voria.umsh.services.format

import java.time.Instant
import java.time.ZoneId

/**
 * Locale-correct date and time pieces. The app's implementation is ICU's
 * ([AndroidTimeFormatting], tested on a device); JVM tests use a stand-in,
 * so the rules that choose between the pieces
 * ([com.voria.umsh.designsystem.RelativeTimes]) test without one. The
 * examples are en-US.
 */
interface TimeFormatting {
    val zone: ZoneId

    /** A time of day, following the 24-hour setting: "09:40" or "9:40 AM". */
    fun timeOfDay(at: Instant): String

    /** An abbreviated weekday: "Mon". */
    fun weekday(at: Instant): String

    /** A month and day: "Oct 28". */
    fun monthDay(at: Instant): String

    /** A month, day and year: "Oct 28, 2025". */
    fun monthDayYear(at: Instant): String

    /** A month and day with a time: "Oct 28, 9:00 AM". */
    fun monthDayTime(at: Instant): String

    /** A month, day and year with a time. */
    fun monthDayYearTime(at: Instant): String

    /** An age in whole units: "12 min. ago". */
    fun ago(count: Long, unit: AgeUnit): String

    /** The same age in full words, for TalkBack: "12 minutes ago". */
    fun agoSpoken(count: Long, unit: AgeUnit): String
}

enum class AgeUnit { Minutes, Hours, Days }

/**
 * When a hold ends: its time today, else its date and time, so a 12-hour
 * or day-long hold is never read as ending today.
 */
fun TimeFormatting.holdEnd(until: Instant, now: Instant): String =
    if (until.atZone(zone).toLocalDate() == now.atZone(zone).toLocalDate()) timeOfDay(until) else monthDayTime(until)
