package com.voria.umsh.designsystem

import android.icu.text.NumberFormat
import android.icu.util.ULocale
import android.content.res.Resources
import com.voria.umsh.R
import java.util.Locale

/**
 * Radio readings in words (Part E 4): strength in dBm, signal-to-noise in
 * dB with one decimal, through the locale's number format, and the two
 * together as one format string: "−97 dBm · SNR 6.5 dB".
 */
object SignalPresentation {
    /** Strength and signal-to-noise, whichever is known; null when neither is. */
    fun readingText(resources: Resources, rssiDbm: Int?, snrCentibels: Int?, locale: Locale): String? =
        reading(resources, rssiDbm, snrCentibels?.let { it / 10.0 }, locale)

    /**
     * The same for a Peer Repeaters listing, whose signal-to-noise comes in
     * quarter-decibel steps rather than a ping's centibels.
     */
    fun readingTextQuarterDb(resources: Resources, rssiDbm: Int?, snrQuarterDb: Int?, locale: Locale): String? =
        reading(resources, rssiDbm, snrQuarterDb?.let { it / 4.0 }, locale)

    private fun reading(resources: Resources, rssiDbm: Int?, snrDecibels: Double?, locale: Locale): String? {
        val strength = rssiDbm?.let { resources.getString(R.string.signal_dbm, integer(it, locale)) }
        val noise = snrDecibels?.let { resources.getString(R.string.signal_snr, decibels(it, locale)) }
        return when {
            strength != null && noise != null -> resources.getString(R.string.signal_reading, strength, noise)
            else -> strength ?: noise
        }
    }

    /**
     * The reading as zero to four bars (iOS `SignalPresentation.bars`).
     * Signal-to-noise decides when it is known: at LoRa's spreading factors
     * a link decodes below the noise floor, so strength alone says little.
     */
    fun bars(rssiDbm: Int?, snrCentibels: Int?): Int? {
        if (snrCentibels != null) {
            val snr = snrCentibels / 10.0
            return when {
                snr >= 10 -> 4
                snr >= 5 -> 3
                snr >= 0 -> 2
                snr >= -7.5 -> 1
                else -> 0
            }
        }
        val rssi = rssiDbm ?: return null
        return when {
            rssi >= -90 -> 4
            rssi >= -100 -> 3
            rssi >= -110 -> 2
            rssi >= -120 -> 1
            else -> 0
        }
    }

    private fun integer(value: Int, locale: Locale): String =
        NumberFormat.getIntegerInstance(ULocale.forLocale(locale)).format(value.toLong())

    private fun decibels(decibels: Double, locale: Locale): String =
        NumberFormat.getNumberInstance(ULocale.forLocale(locale)).apply {
            minimumFractionDigits = 1
            maximumFractionDigits = 1
        }.format(decibels)
}
