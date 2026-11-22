package com.voria.umsh.services.format

import android.icu.text.DisplayContext
import android.icu.text.RelativeDateTimeFormatter
import android.icu.text.SimpleDateFormat
import android.icu.util.TimeZone
import android.icu.util.ULocale
import android.text.format.DateFormat
import java.time.Instant
import java.time.ZoneId
import java.util.Date
import java.util.Locale

/**
 * [TimeFormatting] through ICU: best patterns for the locale from skeletons,
 * the hour cycle from the phone's 24-hour setting, and ICU's relative
 * formatter for ages. Build a new one when the locale, zone or 24-hour
 * setting changes; it holds no other state. ICU's formatters are not
 * thread-safe: use one from a single thread (the UI's).
 */
class AndroidTimeFormatting(
    private val locale: Locale,
    override val zone: ZoneId,
    use24Hour: Boolean,
) : TimeFormatting {
    private val time = if (use24Hour) "Hm" else "hm"

    // Built on first use: an age needs only the relative formatter.
    private val timeOfDay by lazy { formatter(time) }
    private val weekday by lazy { formatter("EEE") }
    private val monthDay by lazy { formatter("MMMd") }
    private val monthDayYear by lazy { formatter("yMMMd") }
    private val monthDayTime by lazy { formatter("MMMd$time") }
    private val monthDayYearTime by lazy { formatter("yMMMd$time") }
    private val relative by lazy { relativeFormatter(RelativeDateTimeFormatter.Style.SHORT) }
    private val relativeSpoken by lazy { relativeFormatter(RelativeDateTimeFormatter.Style.LONG) }

    private fun relativeFormatter(style: RelativeDateTimeFormatter.Style) = RelativeDateTimeFormatter.getInstance(
        ULocale.forLocale(locale),
        null,
        style,
        DisplayContext.CAPITALIZATION_NONE,
    )

    private fun formatter(skeleton: String) =
        SimpleDateFormat(DateFormat.getBestDateTimePattern(locale, skeleton), locale).apply {
            timeZone = TimeZone.getTimeZone(zone.id)
        }

    private fun SimpleDateFormat.of(at: Instant): String = format(Date.from(at))

    override fun timeOfDay(at: Instant) = timeOfDay.of(at)
    override fun weekday(at: Instant) = weekday.of(at)
    override fun monthDay(at: Instant) = monthDay.of(at)
    override fun monthDayYear(at: Instant) = monthDayYear.of(at)
    override fun monthDayTime(at: Instant) = monthDayTime.of(at)
    override fun monthDayYearTime(at: Instant) = monthDayYearTime.of(at)

    override fun ago(count: Long, unit: AgeUnit): String = relative.of(count, unit)

    override fun agoSpoken(count: Long, unit: AgeUnit): String = relativeSpoken.of(count, unit)

    private fun RelativeDateTimeFormatter.of(count: Long, unit: AgeUnit): String = format(
        count.toDouble(),
        RelativeDateTimeFormatter.Direction.LAST,
        when (unit) {
            AgeUnit.Minutes -> RelativeDateTimeFormatter.RelativeUnit.MINUTES
            AgeUnit.Hours -> RelativeDateTimeFormatter.RelativeUnit.HOURS
            AgeUnit.Days -> RelativeDateTimeFormatter.RelativeUnit.DAYS
        },
    )
}
