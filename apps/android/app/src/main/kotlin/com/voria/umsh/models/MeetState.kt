package com.voria.umsh.models

/** A device listed on Nearby: its kind and its color for this visit, nothing of whose it is. */
data class MeetDevice(
    /** Its place on Nearby, stable while it stays listed; what an ask names. */
    val id: Long,
    /** Its model id (`platforms.json`, `boards.json`); 0 when unspecified. */
    val model: Int,
    /** `0xRRGGBB`. */
    val colorRgb: Int,
    /** 0 (far) to 3 (close), once known. */
    val nearness: Int?,
)

/** Why an exchange ended without contacts crossing. */
enum class MeetEnd { NotNow, Busy, Different, Left, TimedOut, Failed }

/** Where Add peer's exchange stands. */
sealed interface MeetExchange {
    data object Closed : MeetExchange

    data object Opening : MeetExchange

    /** Listed on Nearby, nothing in progress. */
    data object Idle : MeetExchange

    /** This phone asked [device]; waiting for an answer. */
    data class Asking(val device: MeetDevice) : MeetExchange

    /** [device] asked this phone; waiting for its holder. */
    data class Asked(val device: MeetDevice) : MeetExchange

    /** This phone agreed; waiting for [device]. */
    data class Accepted(val device: MeetDevice) : MeetExchange

    /** Both show [code]; [sent] once this phone's holder pressed Same. */
    data class Comparing(val device: MeetDevice, val code: Int, val sent: Boolean) : MeetExchange

    data class Ended(val reason: MeetEnd) : MeetExchange

    /** Contacts crossed; the core has stored [peerAddress] (unsaved). */
    data class Exchanged(val peerAddress: String, val signed: Boolean) : MeetExchange

    /**
     * Past Nearby: this phone asked or agreed, the codes are up, or it ended
     * there. What the exchange page shows, and what backing out leaves.
     */
    val isUnderWay: Boolean get() = this is Asking || this is Accepted || this is Comparing || this is Ended
}

/** What Add peer shows of the exchange. */
data class MeetState(
    /** This phone's color for this visit, once its session is up. */
    val ownColorRgb: Int?,
    /** The devices heard, oldest first. */
    val devices: List<MeetDevice>,
    /** The device the exchange is with, or was until it ended. */
    val device: MeetDevice?,
    val exchange: MeetExchange,
)
