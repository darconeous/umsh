package com.voria.umsh.designsystem

import android.icu.text.MeasureFormat
import android.icu.text.NumberFormat
import android.icu.util.Measure
import android.icu.util.MeasureUnit
import android.icu.util.ULocale
import java.util.Locale

/**
 * Measures in the reader's units and digits (§3.11), through ICU's
 * `MeasureFormat`, so no unit word is written into a string resource.
 */
object MeasurePresentation {
    /** A round trip or an elapsed wait, to a tenth of a second: "1.4 s". Negative reads as none. */
    fun seconds(milliseconds: Long, locale: Locale): String {
        val uLocale = ULocale.forLocale(locale)
        val number = NumberFormat.getNumberInstance(uLocale).apply {
            minimumFractionDigits = 1
            maximumFractionDigits = 1
        }
        return MeasureFormat.getInstance(uLocale, MeasureFormat.FormatWidth.SHORT, number)
            .format(Measure(milliseconds.coerceAtLeast(0) / 1_000.0, MeasureUnit.SECOND))
    }

    /**
     * A wait still to run, in whole seconds rounded up, so the last second
     * reads "1 sec", never "0 sec": "32 sec". [spoken] spells the unit out
     * for TalkBack.
     */
    fun wholeSecondsLeft(milliseconds: Long, locale: Locale, spoken: Boolean = false): String {
        val uLocale = ULocale.forLocale(locale)
        val seconds = (milliseconds.coerceAtLeast(0) + 999) / 1_000
        val width = if (spoken) MeasureFormat.FormatWidth.WIDE else MeasureFormat.FormatWidth.SHORT
        return MeasureFormat.getInstance(uLocale, width, NumberFormat.getIntegerInstance(uLocale))
            .format(Measure(seconds, MeasureUnit.SECOND))
    }

    /**
     * A length of time in the largest whole unit it fills, spelled out:
     * "30 minutes", "1 hour", "12 hours", "1 day" (a manual path's hold).
     */
    fun span(milliseconds: Long, locale: Locale): String {
        val uLocale = ULocale.forLocale(locale)
        val (count, unit) = when {
            milliseconds > 0 && milliseconds % DAY_MS == 0L -> milliseconds / DAY_MS to MeasureUnit.DAY
            milliseconds > 0 && milliseconds % HOUR_MS == 0L -> milliseconds / HOUR_MS to MeasureUnit.HOUR
            else -> (milliseconds.coerceAtLeast(0) / MINUTE_MS) to MeasureUnit.MINUTE
        }
        return MeasureFormat.getInstance(uLocale, MeasureFormat.FormatWidth.WIDE, NumberFormat.getIntegerInstance(uLocale))
            .format(Measure(count, unit))
    }

    private const val MINUTE_MS = 60_000L
    private const val HOUR_MS = 60 * MINUTE_MS
    private const val DAY_MS = 24 * HOUR_MS

    /** The same, spelled out for TalkBack: "1.4 seconds". */
    fun secondsSpoken(milliseconds: Long, locale: Locale): String {
        val uLocale = ULocale.forLocale(locale)
        val number = NumberFormat.getNumberInstance(uLocale).apply {
            minimumFractionDigits = 1
            maximumFractionDigits = 1
        }
        return MeasureFormat.getInstance(uLocale, MeasureFormat.FormatWidth.WIDE, number)
            .format(Measure(milliseconds.coerceAtLeast(0) / 1_000.0, MeasureUnit.SECOND))
    }
}
