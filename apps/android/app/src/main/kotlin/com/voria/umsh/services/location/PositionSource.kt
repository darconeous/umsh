package com.voria.umsh.services.location

import kotlinx.coroutines.withTimeoutOrNull

/**
 * One reading of this phone's position, for a moment that notes where the
 * phone is but has no business asking: where a manual path was set, and
 * whether the phone has moved since. Read only under a grant already given;
 * never a prompt. A seam, so the JVM tests hand in fixes of their own.
 */
fun interface PositionSource {
    /** A fix, or null: no grant, location off, or none in [WAIT_MS]. */
    suspend fun readOnceIfGranted(): PhoneFix?

    companion object {
        /** How long a reading waits for its fix, as iOS's one-shot reader. */
        const val WAIT_MS = 20_000L

        /** Never a position: tests that never need one. */
        val None = PositionSource { null }

        /** One fix from [location], when what Android allows already lets it have one. */
        fun of(location: PhoneLocationSource) = PositionSource {
            location.refresh()
            val grant = location.grant.value
            if (grant == LocationGrant.None) {
                null
            } else {
                withTimeoutOrNull(WAIT_MS) { location.currentFix(grant) }
            }
        }
    }
}
