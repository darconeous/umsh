package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.core.MobileRadioProblem
import com.voria.umsh.core.MobileRadioStateRecord
import com.voria.umsh.core.UlcpChargeState
import com.voria.umsh.core.UlcpHostOwnership
import com.voria.umsh.core.radioCarriesThisPhone

/**
 * The companion radio as the screens draw it, built from the core's record.
 * Holds no byte arrays, so equal states compare equal.
 */
data class RadioSnapshot(
    val phase: MobileRadioPhase,
    /** The radio's own name once it reports one, the transport's until then. */
    val name: String?,
    val linkId: String?,
    val host: UlcpHostOwnership,
    val batteryPercent: Int?,
    val batteryMillivolts: Int?,
    val charge: UlcpChargeState?,
    /** When the battery reading arrived. */
    val batteryReadAtMs: Long?,
    val problem: MobileRadioProblem?,
    /** The radio carries this phone's traffic: the one thing that lets Send fire. */
    val carriesThisPhone: Boolean,
    /**
     * The radio measures its own power state (`CAP_BATTERY`), as far as this
     * session has learned. False on a radio that never will, so its power
     * position is left empty rather than shown as unavailable.
     */
    val reportsBattery: Boolean = false,
    /**
     * The battery fields are a reading from an earlier link of this radio
     * (the core's `batteryCached`): drawn dimmed, with their age, never as
     * live. Its charge state is not carried: it says nothing about now.
     */
    val batteryCached: Boolean = false,
) {
    companion object {
        /** Null when there is no radio: none set up, or the one there was let go. */
        fun from(record: MobileRadioStateRecord?): RadioSnapshot? {
            if (record == null || (record.phase == MobileRadioPhase.IDLE && record.linkId == null)) return null
            return RadioSnapshot(
                phase = record.phase,
                name = record.name,
                linkId = record.linkId,
                host = record.host,
                batteryPercent = record.battery?.percentage?.toInt(),
                batteryMillivolts = record.battery?.voltageMv?.toInt(),
                charge = record.battery?.chargeState?.takeUnless { record.batteryCached },
                batteryReadAtMs = record.batteryReadAtMs?.toLong(),
                problem = record.problem,
                carriesThisPhone = radioCarriesThisPhone(record),
                reportsBattery = record.provisioning?.supportsBattery ?: (record.battery != null),
                batteryCached = record.batteryCached,
            )
        }
    }
}
