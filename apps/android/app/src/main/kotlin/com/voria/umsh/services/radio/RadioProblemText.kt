package com.voria.umsh.services.radio

import android.content.res.Resources
import androidx.annotation.StringRes
import com.voria.umsh.R
import com.voria.umsh.core.MobileRadioProblem

/**
 * The radio's problem banner (`radio-control.svg` boards 2 and 3), chosen
 * from the radio's state. Pure; the words are resources, picked where it
 * is drawn. Null when there is nothing to say: a radio connected and well,
 * or one on its way up, which the radio control already shows.
 */
sealed interface RadioBanner {
    val tone: Tone

    enum class Tone { Warning, Error }

    /** What the detail line can say about the radio: its name and last reading. */
    data class Reading(val name: String?, val percent: Int?, val readAtMs: Long?)

    data object NoRadio : RadioBanner {
        override val tone get() = Tone.Warning
    }

    data class Disconnected(val reading: Reading) : RadioBanner {
        override val tone get() = Tone.Warning
    }

    data class BluetoothOff(val reading: Reading) : RadioBanner {
        override val tone get() = Tone.Warning
    }

    data object NearbyDenied : RadioBanner {
        override val tone get() = Tone.Warning
    }

    data class Failed(val reading: Reading) : RadioBanner {
        override val tone get() = Tone.Error
    }

    /** The radio refused to transmit; [reading]'s percent is live. */
    data class TransmissionRejected(val reason: RejectReason, val reading: Reading) : RadioBanner {
        override val tone get() = Tone.Error
    }

    /** Why the radio refused a transmission, from its status code (`umsh-ulcp` `Status`). */
    sealed interface RejectReason {
        data object DutyCycle : RejectReason
        data object ChannelBusy : RejectReason
        data object RadioBusy : RejectReason
        data object QueueFull : RejectReason

        /** Any other status; worded by its code ([UlcpStatusText]). */
        data class Status(val code: UInt) : RejectReason

        companion object {
            fun of(statusCode: UInt): RejectReason = when (statusCode) {
                UlcpStatusText.DUTY_LIMIT -> DutyCycle
                UlcpStatusText.CCA_FAILURE -> ChannelBusy
                UlcpStatusText.BUSY -> RadioBusy
                UlcpStatusText.NOMEM -> QueueFull
                else -> Status(statusCode)
            }
        }
    }

    companion object {
        /**
         * The banner for [radio]. [bluetoothOff] and [nearbyDenied] are the
         * phone's own state, which a Bluetooth radio link reports (Phase 2);
         * both need a radio set up to matter. [known] false: the radio has
         * not been read yet, and nothing is said until it has.
         */
        fun from(
            radio: RadioSnapshot?,
            bluetoothOff: Boolean = false,
            nearbyDenied: Boolean = false,
            known: Boolean = true,
        ): RadioBanner? {
            if (!known) return null
            if (radio == null) return NoRadio
            // This line's battery is live: a kept reading is not said here.
            fun live(radio: RadioSnapshot) =
                Reading(radio.name, radio.batteryPercent.takeUnless { radio.batteryCached }, radio.batteryReadAtMs)
            if (nearbyDenied) return NearbyDenied
            val last = Reading(radio.name, radio.batteryPercent, radio.batteryReadAtMs)
            if (bluetoothOff) return BluetoothOff(last)
            return when (RadioControlState.link(radio.phase)) {
                RadioControlState.Link.Failed -> Failed(last)
                RadioControlState.Link.Waiting,
                RadioControlState.Link.Disconnected,
                -> Disconnected(last)
                RadioControlState.Link.Connected -> when (val problem = radio.problem) {
                    is MobileRadioProblem.TransmissionRejected ->
                        TransmissionRejected(RejectReason.of(problem.statusCode), live(radio))
                    is MobileRadioProblem.RadioBusy -> TransmissionRejected(RejectReason.RadioBusy, live(radio))
                    else -> null
                }
                RadioControlState.Link.Connecting,
                RadioControlState.Link.Reconnecting,
                RadioControlState.Link.None,
                RadioControlState.Link.Unknown,
                -> null
            }
        }
    }
}

/**
 * What a radio problem says: a string resource, and what fills its
 * placeholders. An argument may itself be words ([StatusWords]), resolved
 * where the whole is ([resolvedArgs]).
 */
data class ProblemWords(val text: Int, val args: List<Any> = emptyList())

/** A status's words: a string resource, given the status's code for the one that shows it. */
data class StatusWords(@param:StringRes val text: Int, val code: Long)

/** [args] with any [StatusWords] among them put into words. */
fun resolvedArgs(resources: Resources, args: List<Any>): Array<Any> =
    args.map { if (it is StatusWords) resources.getString(it.text, it.code) else it }.toTypedArray()

/**
 * What a ULCP status code means, in this app's words (`umsh-ulcp`
 * `Status`). The core also names each status, but by its Rust debug form
 * (`Status::FAILURE`), which is a log label and never display text.
 */
object UlcpStatusText {
    const val FAILURE = 1u
    const val UNIMPLEMENTED = 2u
    const val INVALID_ARGUMENT = 3u
    const val INVALID_STATE = 4u
    const val INVALID_COMMAND = 5u
    const val INTERNAL_ERROR = 7u
    const val PARSE_ERROR = 9u
    const val IN_PROGRESS = 10u
    const val NOMEM = 11u
    const val BUSY = 12u
    const val PROP_NOT_FOUND = 13u
    const val CCA_FAILURE = 18u
    const val ALREADY = 19u
    const val ITEM_NOT_FOUND = 20u
    const val NOT_PERMITTED = 22u
    const val CHANNEL_NOT_FOUND = 23u
    const val NO_ACK = 27u
    const val DUTY_LIMIT = 32u

    fun of(code: UInt): StatusWords = StatusWords(text(code), code.toLong())

    @StringRes
    fun text(code: UInt): Int = when (code) {
        FAILURE -> R.string.ulcp_status_failure
        UNIMPLEMENTED -> R.string.ulcp_status_unimplemented
        INVALID_ARGUMENT -> R.string.ulcp_status_invalid_argument
        INVALID_STATE -> R.string.ulcp_status_invalid_state
        INVALID_COMMAND -> R.string.ulcp_status_invalid_command
        INTERNAL_ERROR -> R.string.ulcp_status_internal_error
        PARSE_ERROR -> R.string.ulcp_status_parse_error
        IN_PROGRESS -> R.string.ulcp_status_in_progress
        NOMEM -> R.string.banner_reason_queue_full
        BUSY -> R.string.banner_reason_radio_busy
        PROP_NOT_FOUND -> R.string.ulcp_status_prop_not_found
        CCA_FAILURE -> R.string.banner_reason_channel_busy
        ALREADY -> R.string.ulcp_status_already
        ITEM_NOT_FOUND -> R.string.ulcp_status_item_not_found
        NOT_PERMITTED -> R.string.ulcp_status_not_permitted
        CHANNEL_NOT_FOUND -> R.string.ulcp_status_channel_not_found
        NO_ACK -> R.string.ulcp_status_no_ack
        DUTY_LIMIT -> R.string.banner_reason_duty_cycle
        else -> R.string.ulcp_status_code
    }
}

/**
 * The reason line for a radio problem (Radio Detail's, and a failure
 * dialog's). Every case is a resource; a system error is never shown in the
 * system's own words, which are not this app's and are often not words.
 */
object RadioProblemWords {
    fun of(problem: MobileRadioProblem): ProblemWords = when (problem) {
        MobileRadioProblem.Disconnected -> ProblemWords(R.string.radio_problem_disconnected)
        MobileRadioProblem.InvalidFrame -> ProblemWords(R.string.radio_problem_invalid_frame)
        MobileRadioProblem.UnusableValue -> ProblemWords(R.string.radio_problem_unusable_value)
        MobileRadioProblem.SessionStartFailed -> ProblemWords(R.string.radio_problem_session_start_failed)
        MobileRadioProblem.SynchronizationStalled -> ProblemWords(R.string.radio_problem_synchronization_stalled)
        MobileRadioProblem.ClaimFailed -> ProblemWords(R.string.radio_problem_claim_failed)
        // The operation is a diagnostic label, shown as it is; the status is worded here.
        is MobileRadioProblem.OperationRejected -> ProblemWords(
            R.string.radio_problem_operation_rejected,
            listOf(problem.operation, UlcpStatusText.of(problem.statusCode), problem.statusCode.toLong()),
        )
        MobileRadioProblem.UnrecognizedAnswer -> ProblemWords(R.string.radio_problem_unrecognized_answer)
        MobileRadioProblem.RadioBusy -> ProblemWords(R.string.radio_problem_radio_busy)
        is MobileRadioProblem.TransmissionRejected ->
            ProblemWords(R.string.radio_problem_transmission_rejected, listOf(UlcpStatusText.of(problem.statusCode)))
        MobileRadioProblem.TransmissionUnreported -> ProblemWords(R.string.radio_problem_transmission_unreported)
        MobileRadioProblem.TransmissionUnsendable -> ProblemWords(R.string.radio_problem_transmission_unsendable)
        MobileRadioProblem.AutoEnableFailed -> ProblemWords(R.string.radio_problem_auto_enable_failed)
        is MobileRadioProblem.Transport ->
            ProblemWords(RadioTransportProblem.of(problem)?.let(::text) ?: R.string.radio_problem_connection_failed)
    }

    fun text(problem: RadioTransportProblem): Int = when (problem) {
        RadioTransportProblem.UnsendableFrame -> R.string.radio_problem_unsendable_frame
        RadioTransportProblem.LinkLost -> R.string.radio_problem_link_lost
        RadioTransportProblem.WriteUnacknowledged -> R.string.radio_problem_write_unacknowledged
        RadioTransportProblem.AttachmentIncomplete -> R.string.radio_problem_attachment_incomplete
        RadioTransportProblem.ServiceMissing -> R.string.radio_problem_service_missing
        RadioTransportProblem.ServiceIncompatible -> R.string.radio_problem_service_incompatible
        RadioTransportProblem.AttachmentRefused -> R.string.radio_problem_attachment_refused
        RadioTransportProblem.EndpointUnwritable -> R.string.radio_problem_endpoint_unwritable
        RadioTransportProblem.WriteModeUnsupported -> R.string.radio_problem_write_mode_unsupported
        RadioTransportProblem.NoRadioFound -> R.string.radio_problem_no_radio_found
        RadioTransportProblem.NoSavedRadio -> R.string.radio_problem_no_saved_radio
        RadioTransportProblem.SavedRadioUnknown -> R.string.radio_problem_saved_radio_unknown
        RadioTransportProblem.RemovalFailed -> R.string.radio_problem_removal_failed
        RadioTransportProblem.BluetoothUnauthorized -> R.string.radio_problem_bluetooth_unauthorized
        RadioTransportProblem.BluetoothUnsupported -> R.string.radio_problem_bluetooth_unsupported
        RadioTransportProblem.BluetoothOff -> R.string.radio_problem_bluetooth_off
        RadioTransportProblem.BluetoothResetting -> R.string.radio_problem_bluetooth_resetting
        RadioTransportProblem.BluetoothStarting -> R.string.radio_problem_bluetooth_starting
        RadioTransportProblem.BluetoothUnavailable -> R.string.radio_problem_bluetooth_unavailable
        RadioTransportProblem.BridgeUnreachable -> R.string.radio_problem_bridge_unreachable
        RadioTransportProblem.BridgeWaiting -> R.string.radio_problem_bridge_waiting
        RadioTransportProblem.BridgeFailed -> R.string.radio_problem_bridge_failed
        RadioTransportProblem.BridgeClosed -> R.string.radio_problem_bridge_closed
        RadioTransportProblem.LocalRadioStopped -> R.string.radio_problem_local_radio_stopped
        RadioTransportProblem.LocalRadioNotRunning -> R.string.radio_problem_local_radio_not_running
        RadioTransportProblem.LocalRadioClosed -> R.string.radio_problem_local_radio_closed
        RadioTransportProblem.LocalRadioInUse -> R.string.radio_problem_local_radio_in_use
        RadioTransportProblem.LocalRadioUnavailable -> R.string.radio_problem_local_radio_unavailable
        RadioTransportProblem.AccessRemoved -> R.string.radio_problem_access_removed
        RadioTransportProblem.ConnectionIncomplete -> R.string.radio_problem_connection_incomplete
        // iOS's accessory setup has nothing that happens here.
        RadioTransportProblem.ConnectionFailed,
        RadioTransportProblem.AccessoriesLoading,
        RadioTransportProblem.AccessorySetupOpen,
        RadioTransportProblem.AccessorySetupUnfinished,
        RadioTransportProblem.AccessoryNeeded,
        RadioTransportProblem.AccessoriesUnavailable,
        -> R.string.radio_problem_connection_failed
    }
}
