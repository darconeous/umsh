package com.voria.umsh.features.peers

import android.icu.text.MeasureFormat
import android.icu.text.NumberFormat
import android.icu.util.LocaleData
import android.icu.util.Measure
import android.icu.util.MeasureUnit
import android.icu.util.ULocale
import androidx.annotation.StringRes
import com.voria.umsh.R
import com.voria.umsh.models.PeerSummary
import com.voria.umsh.services.location.PhoneFix
import java.util.Locale
import kotlin.math.atan2
import kotlin.math.cos
import kotlin.math.roundToInt
import kotlin.math.sin
import kotlin.math.sqrt

/** A point to measure from, and how wide the cell it is somewhere in is; null for an exact one. */
data class Reference(val latitude: Double, val longitude: Double, val cellMeters: Double?)

/**
 * How far a node is and which way (`peer-page.svg` 1's Distance), honest
 * about both cells' size: closer than the cells allow to say reads as an
 * upper bound. Pure, as iOS `PeerDistance`; the text is [text]'s.
 */
data class PeerDistance(
    /** Between the two cells' centers, or the bound when [isUpperBound]. */
    val meters: Double,
    val isUpperBound: Boolean,
    /** Clockwise from north, 0 to 360. */
    val bearingDegrees: Double,
) {
    companion object {
        /** The mean Earth radius, in meters, as the core measures. */
        private const val EARTH_RADIUS_METERS = 6_371_008.8

        /**
         * From the phone's fix when location is already granted (never
         * asked for here), else from the companion radio's advertised
         * position; null when the node, or both references, have none.
         */
        fun of(peer: PeerSummary, phone: PhoneFix?, radio: PeerSummary?, cellMeters: (Int) -> Double?): PeerDistance? {
            val node = peer.advertised ?: return null
            val latitude = node.latitude ?: return null
            val longitude = node.longitude ?: return null
            val reference = phone?.let {
                // Accuracy is a radius; a cell is a width.
                Reference(it.latitudeDegrees, it.longitudeDegrees, it.accuracyMeters?.let { radius -> radius * 2 })
            } ?: radio?.takeIf { it.address != peer.address }?.advertised?.let { own ->
                val ownLatitude = own.latitude ?: return@let null
                val ownLongitude = own.longitude ?: return@let null
                Reference(ownLatitude, ownLongitude, own.locationPrecision?.let(cellMeters))
            } ?: return null
            return between(reference, latitude, longitude, node.locationPrecision?.let(cellMeters))
        }

        fun between(reference: Reference, latitude: Double, longitude: Double, otherCellMeters: Double?): PeerDistance {
            val center = meters(reference.latitude, reference.longitude, latitude, longitude)
            val slack = (reference.cellMeters ?: 0.0) / 2 + (otherCellMeters ?: 0.0) / 2
            return PeerDistance(
                meters = if (center < slack) center + slack else center,
                isUpperBound = center < slack,
                bearingDegrees = bearing(reference.latitude, reference.longitude, latitude, longitude),
            )
        }

        /** Great-circle distance (haversine). */
        fun meters(fromLatitude: Double, fromLongitude: Double, toLatitude: Double, toLongitude: Double): Double {
            val phi1 = Math.toRadians(fromLatitude)
            val phi2 = Math.toRadians(toLatitude)
            val dPhi = phi2 - phi1
            val dLambda = Math.toRadians(toLongitude - fromLongitude)
            val a = sin(dPhi / 2) * sin(dPhi / 2) + cos(phi1) * cos(phi2) * sin(dLambda / 2) * sin(dLambda / 2)
            return 2 * EARTH_RADIUS_METERS * atan2(sqrt(a), sqrt(1 - a))
        }

        /** Initial bearing, clockwise from true north. */
        fun bearing(fromLatitude: Double, fromLongitude: Double, toLatitude: Double, toLongitude: Double): Double {
            val phi1 = Math.toRadians(fromLatitude)
            val phi2 = Math.toRadians(toLatitude)
            val dLambda = Math.toRadians(toLongitude - fromLongitude)
            val y = sin(dLambda) * cos(phi2)
            val x = cos(phi1) * sin(phi2) - sin(phi1) * cos(phi2) * cos(dLambda)
            return (Math.toDegrees(atan2(y, x)) + 360) % 360
        }

        /** The eight compass points, read by TalkBack after the distance. */
        @StringRes
        fun compassPoint(degrees: Double): Int {
            val point = (((degrees % 360) + 360) % 360 / 45).roundToInt() % 8
            return COMPASS[point]
        }

        private val COMPASS = listOf(
            R.string.compass_north,
            R.string.compass_northeast,
            R.string.compass_east,
            R.string.compass_southeast,
            R.string.compass_south,
            R.string.compass_southwest,
            R.string.compass_west,
            R.string.compass_northwest,
        )

        /**
         * A distance between nodes in the locale's road unit, never meters
         * or feet (a short one would read as an altitude): "0.3 mi", "4.2 km",
         * "60 mi". Tenths below five, whole units from there.
         */
        fun text(meters: Double, locale: Locale = Locale.getDefault()): String {
            val uLocale = ULocale.forLocale(locale)
            val miles = LocaleData.getMeasurementSystem(uLocale) != LocaleData.MeasurementSystem.SI
            val value = if (miles) meters / METERS_PER_MILE else meters / 1_000
            val digits = if (value < 5) 1 else 0
            val number = NumberFormat.getInstance(uLocale).apply {
                minimumFractionDigits = digits
                maximumFractionDigits = digits
            }
            return MeasureFormat.getInstance(uLocale, MeasureFormat.FormatWidth.SHORT, number)
                .format(Measure(value, if (miles) MeasureUnit.MILE else MeasureUnit.KILOMETER))
        }

        private const val METERS_PER_MILE = 1_609.344
    }
}
