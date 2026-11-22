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
)

/** What one router said about its neighborhood. */
data class NeighborReport(val reporter: PeerSummary, val neighbor: RepeaterNeighbor)

/** A peer's cached repeater listing. */
data class RepeaterListing(
    val entries: List<RepeaterNeighbor>,
    val total: Long?,
    val nextCursor: Octets?,
    val asOfMs: Long,
)
