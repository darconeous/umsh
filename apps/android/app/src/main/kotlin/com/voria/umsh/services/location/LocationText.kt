package com.voria.umsh.services.location

import android.icu.text.MeasureFormat
import android.icu.text.NumberFormat
import android.icu.util.Measure
import android.icu.util.MeasureUnit
import android.icu.util.ULocale
import java.util.Locale

/** A location cell's width, as the user reads it. */
object LocationText {
    /**
     * The bare measurement in whichever unit keeps it readable, with one
     * decimal below 10: "2,505 km", "9.8 km", "611 m", "2.4 m", "15 cm".
     */
    fun cellSize(meters: Double, locale: Locale = Locale.getDefault()): String {
        val (value, unit) = when {
            meters >= 1_000 -> meters / 1_000 to MeasureUnit.KILOMETER
            meters >= 1 -> meters to MeasureUnit.METER
            else -> meters * 100 to MeasureUnit.CENTIMETER
        }
        val digits = if (value < 10) 1 else 0
        val uLocale = ULocale.forLocale(locale)
        val number = NumberFormat.getInstance(uLocale).apply {
            minimumFractionDigits = digits
            maximumFractionDigits = digits
        }
        return MeasureFormat.getInstance(uLocale, MeasureFormat.FormatWidth.SHORT, number).format(Measure(value, unit))
    }
}
