package com.voria.umsh.features.radio

import androidx.annotation.StringRes
import com.voria.umsh.R
import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.core.MobileRadioProblem
import com.voria.umsh.core.RadioPresetRecord
import com.voria.umsh.core.SavedSnapshotRecord
import com.voria.umsh.core.UlcpChargeState
import com.voria.umsh.services.radio.RadioControlState
import com.voria.umsh.services.radio.RadioProvisioning
import com.voria.umsh.services.radio.BoardCatalog
import com.voria.umsh.services.radio.RadioSnapshot

/**
 * What Radio Detail shows (`radio-detail.svg` 1–4), from the radio's
 * snapshot. Pure: the words are resources, picked where it is drawn, so the
 * JVM tests cover every state.
 */
data class RadioDetailModel(
    /** The radio's own name, else its advertised one; null before either. */
    val name: String?,
    /** The board's name from the board list, else the hardware in the radio's words; null when unknown. */
    val model: String?,
    /** The model identifier the radio was recorded with (`boards.json`), for its photo; null when unknown. */
    val modelId: Int? = null,
    val status: Status,
    val battery: Battery?,
    /** Why the connection failed; only in [Status.Failed]. */
    val reason: MobileRadioProblem?,
    val primary: Primary,
    /** The radio's device key as "3F2A9C41…E07B"; null without one. */
    val radioId: String?,
    val mesh: Mesh?,
    val offline: Offline?,
    /** The radio has a mesh identity of its own to show. */
    val showsIdentity: Boolean,
    /**
     * Maintenance (Restart radio…, Factory reset radio…) is offered: the
     * radio is attached and restarts on request. A radio that cannot restart
     * refuses a factory reset too, and one out of reach can take neither.
     */
    val offersMaintenance: Boolean,
) {
    enum class Status(@param:StringRes val label: Int) {
        Connected(R.string.radio_state_connected),
        Connecting(R.string.radio_state_connecting),
        Reconnecting(R.string.radio_state_reconnecting),
        Waiting(R.string.radio_state_waiting),
        Disconnected(R.string.radio_state_disconnected),
        Failed(R.string.radio_state_failed),
    }

    /** The first button; Forget is always beside it. */
    enum class Primary { Disconnect, StopWaiting, Reconnect, Connect }

    sealed interface Battery {
        /** A live reading. [charge] null: the radio said nothing about charging. */
        data class Live(val percent: Int, val charge: Charge?) : Battery

        /** Live, with no level: what the charger is doing. */
        data class ExternalOnly(val charging: Boolean) : Battery

        /** The last reading from an earlier link, with when it was taken. */
        data class Last(val percent: Int, val readAtMs: Long?) : Battery
    }

    enum class Charge { Discharging, Charging, ExternalPower }

    /** Mesh radio: the profile, the transmit budget, and whether the settings survive a restart. */
    data class Mesh(
        val frequencyKhz: Long,
        val bandwidthHz: Long?,
        val spreadingFactor: Int?,
        val codingRateDenominator: Int?,
        val transmitPowerDbm: Int,
        /** Fractions of the hour out of 65535, or null when unreported. */
        val dutyCycleNow: Int?,
        /** As [dutyCycleNow]; [NO_LIMIT] is no limit. */
        val dutyCycleLimit: Int?,
        val saved: SavedSnapshotRecord?,
    )

    /** Offline assistance: what the radio holds for this phone. Each row null when unreported. */
    data class Offline(
        val receiveFilters: Long?,
        val channelKeys: Long?,
        val peerKeys: Long?,
        val queuedFrames: Int?,
        val droppedFrames: Long?,
        val delegatedAcks: Boolean?,
    )

    companion object {
        /** A duty-cycle limit of the whole hour: the radio has none. */
        const val NO_LIMIT = 0xFFFF

        private const val ID_HEAD = 8
        private const val ID_TAIL = 4

        /** [board]: the bound radio's entry in the board list, by the model identifier recorded at pairing. */
        fun from(radio: RadioSnapshot, board: BoardCatalog.Board? = null): RadioDetailModel {
            val status = status(radio.phase)
            val provisioning = radio.provisioning
            return RadioDetailModel(
                name = radio.name,
                model = board?.name ?: provisioning?.deviceModel,
                modelId = board?.modelId,
                status = status,
                battery = battery(radio, live = status == Status.Connected && !radio.batteryCached),
                reason = radio.problem.takeIf { status == Status.Failed },
                primary = when (status) {
                    Status.Connected, Status.Connecting, Status.Reconnecting -> Primary.Disconnect
                    Status.Waiting -> Primary.StopWaiting
                    Status.Failed -> Primary.Reconnect
                    Status.Disconnected -> Primary.Connect
                },
                radioId = radio.deviceKeyHex?.let(::shortId),
                mesh = provisioning?.let(::mesh),
                offline = provisioning?.let(::offline),
                showsIdentity = radio.deviceKeyHex != null && provisioning?.supportsDeviceIdentity == true,
                offersMaintenance = status == Status.Connected && provisioning?.supportsReboot == true,
            )
        }

        fun status(phase: MobileRadioPhase): Status = when (RadioControlState.link(phase)) {
            RadioControlState.Link.Connected -> Status.Connected
            RadioControlState.Link.Connecting -> Status.Connecting
            RadioControlState.Link.Reconnecting -> Status.Reconnecting
            RadioControlState.Link.Waiting -> Status.Waiting
            RadioControlState.Link.Failed -> Status.Failed
            RadioControlState.Link.Disconnected,
            RadioControlState.Link.None,
            RadioControlState.Link.Unknown,
            -> Status.Disconnected
        }

        /** "3F2A9C41…E07B": the head and tail of the key, enough to tell radios apart. */
        fun shortId(hex: String): String =
            if (hex.length <= ID_HEAD + ID_TAIL) hex else "${hex.take(ID_HEAD)}…${hex.takeLast(ID_TAIL)}"

        private fun battery(radio: RadioSnapshot, live: Boolean): Battery? {
            val percent = radio.batteryPercent
            if (!live) return percent?.let { Battery.Last(it, radio.batteryReadAtMs) }
            val charge = when (radio.charge) {
                UlcpChargeState.DISCHARGING -> Charge.Discharging
                UlcpChargeState.CHARGING -> Charge.Charging
                UlcpChargeState.CHARGED, UlcpChargeState.NOT_CHARGING -> Charge.ExternalPower
                null -> null
            }
            return when {
                percent != null -> Battery.Live(percent, charge)
                charge == Charge.Charging -> Battery.ExternalOnly(charging = true)
                charge == Charge.ExternalPower -> Battery.ExternalOnly(charging = false)
                else -> null
            }
        }

        private fun mesh(provisioning: RadioProvisioning) = Mesh(
            frequencyKhz = provisioning.frequencyKhz,
            bandwidthHz = provisioning.bandwidthHz,
            spreadingFactor = provisioning.spreadingFactor,
            codingRateDenominator = provisioning.codingRateDenominator,
            transmitPowerDbm = provisioning.transmitPowerDbm,
            dutyCycleNow = provisioning.dutyCycleNow,
            dutyCycleLimit = provisioning.dutyCycleLimit,
            saved = provisioning.saved,
        )

        /** Only a radio that filters for this phone assists it offline. */
        private fun offline(provisioning: RadioProvisioning): Offline? {
            if (!provisioning.hasHostFiltering) return null
            return Offline(
                receiveFilters = provisioning.filterCount,
                channelKeys = provisioning.hostChannelCount,
                peerKeys = provisioning.hostPeerCount,
                queuedFrames = provisioning.queuedFrames,
                droppedFrames = provisioning.droppedFrames,
                delegatedAcks = provisioning.autoAck,
            )
        }
    }
}

/** The vetted profile the radio's settings match, by its id; null when they match none. */
fun List<RadioPresetRecord>.presetId(mesh: RadioDetailModel.Mesh): String? = firstOrNull { preset ->
    preset.frequencyKhz.toLong() == mesh.frequencyKhz &&
        preset.bandwidthHz.toLong() == mesh.bandwidthHz &&
        preset.spreadingFactor.toInt() == mesh.spreadingFactor &&
        preset.codingRateDenom.toInt() == mesh.codingRateDenominator
}?.id

/** The headline for a vetted profile, by its stable id; null for one this app has no words for. */
@StringRes
fun presetLabel(id: String): Int? = when (id) {
    "umsh-us-ca" -> R.string.radio_preset_umsh_us_ca
    "meshcore-us-ca" -> R.string.radio_preset_meshcore_us_ca
    "meshcore-au" -> R.string.radio_preset_meshcore_au
    "meshcore-au-narrow" -> R.string.radio_preset_meshcore_au_narrow
    "meshcore-au-mid" -> R.string.radio_preset_meshcore_au_mid
    "meshcore-au-sa-wa" -> R.string.radio_preset_meshcore_au_sa_wa
    "meshcore-au-qld" -> R.string.radio_preset_meshcore_au_qld
    "meshcore-br" -> R.string.radio_preset_meshcore_br
    "meshcore-cr" -> R.string.radio_preset_meshcore_cr
    "meshcore-eu-narrow" -> R.string.radio_preset_meshcore_eu_narrow
    "meshcore-cz-narrow" -> R.string.radio_preset_meshcore_cz_narrow
    "meshcore-eu-433-long-range" -> R.string.radio_preset_meshcore_eu_433_long_range
    "meshcore-eu-433-narrow" -> R.string.radio_preset_meshcore_eu_433_narrow
    "meshcore-hu" -> R.string.radio_preset_meshcore_hu
    "meshcore-nl" -> R.string.radio_preset_meshcore_nl
    "meshcore-nz-narrow" -> R.string.radio_preset_meshcore_nz_narrow
    "meshcore-nz-gisborne" -> R.string.radio_preset_meshcore_nz_gisborne
    "meshcore-pt-433" -> R.string.radio_preset_meshcore_pt_433
    "meshcore-pt-868" -> R.string.radio_preset_meshcore_pt_868
    "meshcore-sk" -> R.string.radio_preset_meshcore_sk
    "meshcore-ch" -> R.string.radio_preset_meshcore_ch
    "meshcore-vn-narrow" -> R.string.radio_preset_meshcore_vn_narrow
    else -> null
}
