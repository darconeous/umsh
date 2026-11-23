package com.voria.umsh.services.radio

import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.core.UlcpChargeState

/**
 * What the radio control draws (`radio-control.svg` board 1): a link glyph,
 * then a power glyph. Pure, so the JVM tests cover every state.
 */
data class RadioControlState(
    val link: Link,
    /** Null: no power position at all (a radio that measures no power state, or no radio). */
    val power: Power?,
    /** The power glyph is a reading kept from before the link went: drawn dimmed, never as live. */
    val cached: Boolean,
    /** The radio's name for TalkBack; null with no radio, or before it reports one. */
    val name: String?,
    /** When a cached reading was taken, for TalkBack's age. */
    val readAtMs: Long?,
) {
    enum class Link {
        /** Not read yet: the runtime has not had the core's status. Says nothing. */
        Unknown,

        /** No radio set up. */
        None,
        Connected,

        /** Coming up for the first time: connecting, pairing, synchronizing. */
        Connecting,

        /** Coming back after it was lost. */
        Reconnecting,

        /** A saved radio is out of reach, and the transport waits for it to appear. */
        Waiting,
        Disconnected,
        Failed,
    }

    sealed interface Power {
        /** Battery bars for [percent], with [extra] beside them. */
        data class Level(val percent: Int, val extra: Extra?) : Power {
            /** Material's battery glyphs: 0–6 bars, then full. */
            val bars: Int get() = batteryBars(percent)
        }

        /** No level, but the radio reports what its charger is doing. */
        data class ExternalOnly(val charging: Boolean) : Power

        /** The radio measures its battery and has no reading yet. */
        data object Unknown : Power
    }

    enum class Extra {
        /** Taking charge. */
        Charging,

        /** On external power, not charging: charged, or the charger idle. */
        ExternalPower,
    }

    companion object {
        /** Bars out of six, and seven for full: 78% → 5, 12% → 1, 0% → 0, 95% and up → full. */
        fun batteryBars(percent: Int): Int = when {
            percent >= FULL_PERCENT -> FULL_BARS
            percent <= 0 -> 0
            else -> ((percent * 6 + 99) / 100).coerceIn(1, 6)
        }

        const val FULL_BARS = 7
        private const val FULL_PERCENT = 95

        /** [known] false: the radio has not been read yet, so a null [radio] is not "none". */
        fun from(radio: RadioSnapshot?, known: Boolean = true): RadioControlState {
            if (!known) return RadioControlState(Link.Unknown, null, cached = false, name = null, readAtMs = null)
            if (radio == null) return RadioControlState(Link.None, null, cached = false, name = null, readAtMs = null)
            val link = link(radio.phase)
            val live = link == Link.Connected && !radio.batteryCached
            val power = power(radio, live)
            return RadioControlState(
                link = link,
                power = power,
                cached = !live && power != null,
                name = radio.name,
                readAtMs = radio.batteryReadAtMs,
            )
        }

        fun link(phase: MobileRadioPhase): Link = when (phase) {
            MobileRadioPhase.ATTACHED -> Link.Connected
            MobileRadioPhase.RECONNECTING -> Link.Reconnecting
            MobileRadioPhase.SCANNING,
            MobileRadioPhase.CONNECTING,
            MobileRadioPhase.PAIRING,
            MobileRadioPhase.ATTACHING,
            MobileRadioPhase.SYNCHRONIZING,
            MobileRadioPhase.AWAITING_HOST,
            MobileRadioPhase.PROVISIONING,
            MobileRadioPhase.CONFIGURING,
            -> Link.Connecting
            MobileRadioPhase.IDLE,
            MobileRadioPhase.UNAVAILABLE,
            MobileRadioPhase.DISCOVERED,
            MobileRadioPhase.DISCONNECTING,
            -> Link.Disconnected
            MobileRadioPhase.WAITING_FOR_RADIO -> Link.Waiting
            MobileRadioPhase.FAILED -> Link.Failed
        }

        /**
         * Live, the radio's reading; otherwise the last one it gave, if any.
         * A charge state is not kept as a cached reading: what a charger was
         * doing before the link went says nothing about now.
         */
        private fun power(radio: RadioSnapshot, live: Boolean): Power? {
            val percent = radio.batteryPercent
            if (!live) return percent?.let { Power.Level(it, extra = null) }
            val extra = when (radio.charge) {
                UlcpChargeState.CHARGING -> Extra.Charging
                UlcpChargeState.CHARGED, UlcpChargeState.NOT_CHARGING -> Extra.ExternalPower
                UlcpChargeState.DISCHARGING, null -> null
            }
            return when {
                percent != null -> Power.Level(percent, extra)
                extra != null -> Power.ExternalOnly(charging = extra == Extra.Charging)
                radio.reportsBattery -> Power.Unknown
                else -> null
            }
        }
    }
}
