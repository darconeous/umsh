package com.voria.umsh.services.radio

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

        /** A status this app has no words for; [name] is the radio's diagnostic label. */
        data class Status(val name: String) : RejectReason

        companion object {
            private const val STATUS_NOMEM = 11u
            private const val STATUS_BUSY = 12u
            private const val STATUS_CCA_FAILURE = 18u
            private const val STATUS_DUTY_LIMIT = 32u

            fun of(statusCode: UInt, statusName: String): RejectReason = when (statusCode) {
                STATUS_DUTY_LIMIT -> DutyCycle
                STATUS_CCA_FAILURE -> ChannelBusy
                STATUS_BUSY -> RadioBusy
                STATUS_NOMEM -> QueueFull
                else -> Status(statusName)
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
                RadioControlState.Link.Disconnected -> Disconnected(last)
                RadioControlState.Link.Connected -> when (val problem = radio.problem) {
                    is MobileRadioProblem.TransmissionRejected ->
                        TransmissionRejected(RejectReason.of(problem.statusCode, problem.statusName), live(radio))
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
