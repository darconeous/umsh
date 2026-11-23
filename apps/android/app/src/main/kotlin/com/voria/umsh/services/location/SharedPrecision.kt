package com.voria.umsh.services.location

import com.voria.umsh.core.MobileAppPolicyRecord
import com.voria.umsh.core.mobileLimits
import com.voria.umsh.core.ulcpLocationCellMeters

/** What Android lets UMSH read of this phone's location. */
enum class LocationGrant { None, Approximate, Precise }

/** One precision the encoding allows, and the width of the cell it discloses. */
data class PrecisionSize(val precision: UByte, val meters: Double)

/**
 * The precision the core shares this phone's position at (§3.8).
 *
 * The user's choice is kept as made. While Android grants only approximate
 * location, the core is given at most [approximateCeiling]: the core does
 * not coarsen a reading by its accuracy, so an approximate fix, off by
 * kilometers, would otherwise go out labeled as a much smaller cell.
 * Granting precise later restores the choice, since it was never changed.
 */
class SharedPrecision(cellMeters: (UByte) -> Double?, precisions: IntRange) {
    /** Every precision the core sizes, coarsest first. */
    val sizes: List<PrecisionSize> = precisions.mapNotNull { value ->
        val precision = value.toUByte()
        cellMeters(precision)?.let { PrecisionSize(precision, it) }
    }

    /**
     * The finest precision an approximate fix is good for: its cell is at
     * least as wide as the grid Android snaps approximate fixes to.
     */
    val approximateCeiling: UByte =
        sizes.lastOrNull { it.meters >= APPROXIMATE_GRID_METERS }?.precision ?: sizes.first().precision

    fun cellMeters(precision: UByte): Double? = sizes.firstOrNull { it.precision == precision }?.meters

    /** Whether [precision] can be shared under [grant]: all of them, except finer ones under approximate. */
    fun allows(precision: UByte, grant: LocationGrant): Boolean =
        grant != LocationGrant.Approximate || precision <= approximateCeiling

    /** The precision the core is given for the user's [chosen] one; null while not sharing. */
    fun effective(chosen: UByte?, grant: LocationGrant): UByte? = chosen?.let {
        if (allows(it, grant)) it else approximateCeiling
    }

    /** The stored [policy] as the core gets it. */
    fun effective(policy: MobileAppPolicyRecord, grant: LocationGrant): MobileAppPolicyRecord {
        val precision = effective(policy.locationPrecision, grant)
        return if (precision == policy.locationPrecision) policy else policy.copy(locationPrecision = precision)
    }

    companion object {
        /**
         * Android snaps an approximate fix to a grid about 2 km across
         * before handing it over (accurate to about 3 km²).
         */
        const val APPROXIMATE_GRID_METERS = 2_000.0

        /** The sizes the core knows. */
        val core: SharedPrecision by lazy {
            val limits = mobileLimits()
            SharedPrecision(::ulcpLocationCellMeters, limits.minLocationPrecision.toInt()..limits.maxLocationPrecision.toInt())
        }
    }
}
