package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.core.MobileRadioProblem
import com.voria.umsh.core.MobileRadioStateRecord
import com.voria.umsh.core.SavedSnapshotRecord
import com.voria.umsh.core.UlcpChargeState
import com.voria.umsh.core.UlcpHostOwnership
import com.voria.umsh.core.UlcpSyncRecord
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
    /** The radio's own device key, as uppercase hex; null before it is read, or on a radio with none. */
    val deviceKeyHex: String? = null,
    /** What the radio reported once synchronized; null until then, and once the link goes. */
    val provisioning: RadioProvisioning? = null,
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
                deviceKeyHex = record.deviceKey?.let(::hex),
                provisioning = record.provisioning?.let(RadioProvisioning::from),
            )
        }
    }
}

private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02X".format(it.toInt() and 0xFF) }

/**
 * The radio's synchronized state as Radio Detail shows it: plain values,
 * each null when the radio lacks the capability or did not report it.
 */
data class RadioProvisioning(
    /** `PROP_DEV_MODEL`: the hardware, in the radio's own words. */
    val deviceModel: String?,
    val frequencyKhz: Long,
    val transmitPowerDbm: Int,
    val bandwidthHz: Long?,
    val spreadingFactor: Int?,
    val codingRateDenominator: Int?,
    /** Fractions of the hour, out of 65535; a limit of 65535 is no limit. */
    val dutyCycleNow: Int?,
    val dutyCycleLimit: Int?,
    val saved: SavedSnapshotRecord?,
    /** The radio filters and holds traffic for this phone (offline assistance). */
    val hasHostFiltering: Boolean,
    val filterCount: Long?,
    val hostChannelCount: Long?,
    val hostPeerCount: Long?,
    val queuedFrames: Int?,
    val droppedFrames: Long?,
    val autoAck: Boolean?,
    val supportsDeviceIdentity: Boolean,
    /** `CAP_REBOOT`: the radio restarts on request. */
    val supportsReboot: Boolean,
) {
    companion object {
        fun from(record: UlcpSyncRecord) = RadioProvisioning(
            deviceModel = record.deviceModel?.takeIf { it.isNotBlank() },
            frequencyKhz = record.frequencyKhz.toLong(),
            transmitPowerDbm = record.transmitPowerDbm.toInt(),
            bandwidthHz = record.bandwidthHz?.toLong(),
            spreadingFactor = record.spreadingFactor?.toInt(),
            codingRateDenominator = record.codingRateDenom?.toInt(),
            dutyCycleNow = record.dutyCycleNow?.toInt(),
            dutyCycleLimit = record.dutyCycleLimit?.toInt(),
            saved = record.saved,
            hasHostFiltering = record.hasHostFiltering,
            filterCount = record.filterCount?.toLong(),
            hostChannelCount = record.hostChannelCount?.toLong(),
            hostPeerCount = record.hostPeerCount?.toLong(),
            queuedFrames = record.queuedFrames?.toInt(),
            droppedFrames = record.droppedFrames?.toLong(),
            autoAck = record.autoAck,
            supportsDeviceIdentity = record.supportsDeviceIdentity,
            supportsReboot = record.supportsReboot,
        )
    }
}
