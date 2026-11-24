package com.voria.umsh.models

/** One repeater a peer reported as its neighbor. */
data class RepeaterNeighbor(
    val hint: Octets,
    /** The core's rendering, else the bytes as uppercase hex. */
    val hintText: String,
    val name: String?,
    val rssiDbm: Int?,
    val snrQuarterDb: Int?,
    val lastHeardMinutes: Int?,
    val latitude: Double?,
    val longitude: Double?,
    val locationPrecision: Int?,
    val regionCodes: List<Octets>,
    val reportedAtMs: Long,
    /** The peer the core matched the hint to, when it matched one. */
    val peerAddress: String?,
) {
    /**
     * Whether the repeater's last-heard figure is a measurement rather than
     * the saturated "long ago" (65535 minutes, about 45 days).
     */
    val lastHeardIsMeasured: Boolean get() = lastHeardMinutes != null && lastHeardMinutes < LAST_HEARD_SATURATED

    /** When the repeater last heard it, on this phone's clock; null with no figure or only the saturated one. */
    val lastHeardAtMs: Long? get() = lastHeardMinutes?.takeIf { lastHeardIsMeasured }?.let { reportedAtMs - it * MINUTE_MS }

    /**
     * Whether the repeater last heard it more than [ageMs] before [nowMs]:
     * the saturated figure is older than any age; no figure is unknown, not old.
     */
    fun heardLongerAgoThan(ageMs: Long, nowMs: Long): Boolean {
        if (lastHeardMinutes == null) return false
        val at = lastHeardAtMs ?: return true
        return nowMs - at > ageMs
    }

    val hasPosition: Boolean get() = latitude != null && longitude != null

    companion object {
        /** The wire's "long ago": the last-heard minutes saturate here. */
        const val LAST_HEARD_SATURATED = 0xFFFF

        /** Not heard for this long, a neighbor is a memory rather than a presence (iOS `NeighborRow.staleAge`). */
        const val STALE_AGE_MS = 6 * 60 * 60 * 1000L

        private const val MINUTE_MS = 60_000L
    }
}

/** What one repeater said about its neighborhood. */
data class NeighborReport(val reporter: PeerSummary, val neighbor: RepeaterNeighbor)

/** What one repeater has said about its neighbors, as far as this phone asked. */
data class RepeaterListing(
    /** In the order the repeater listed them. */
    val entries: List<RepeaterNeighbor>,
    /** How many it holds in all, when it said. */
    val total: Long?,
    /** Where the next page starts; null once the pages in hand are the whole listing. */
    val nextCursor: Octets?,
    /** When the latest page was answered. */
    val asOfMs: Long,
) {
    val isComplete: Boolean get() = nextCursor == null
}
