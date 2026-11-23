package com.voria.umsh.services.background

import com.voria.umsh.core.MobileRadioTransportPhase
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind

/**
 * What a wanted Bluetooth radio does once the reconnect window has passed
 * without it (§7.2, D7).
 */
enum class ReconnectStrategy {
    /**
     * The link is closed and the service stops; Android's companion
     * presence wakes the app when the radio advertises again.
     */
    Presence,

    /** The service stays, showing Waiting, with a background connect armed for as long as the radio is wanted. */
    Waiting,

    ;

    companion object {
        /**
         * The strategy [radio] gets: [preferred] (the Developer switch;
         * Presence otherwise), unless presence cannot reach it: no
         * companion-device support on this phone, no association for the
         * radio, or not a Bluetooth radio.
         */
        fun effective(preferred: ReconnectStrategy, presenceAvailable: Boolean, radio: BoundRadio?): ReconnectStrategy =
            if (preferred == Presence && presenceAvailable && radio?.kind == RadioKind.Ble && radio.associationId != null) {
                Presence
            } else {
                Waiting
            }
    }
}

/**
 * Where a wanted Bluetooth radio's link stands while it is not attached,
 * and how long it is sought before the strategy takes over (§7.2). Pure:
 * the connection asks it and acts; [now] is a monotonic clock in
 * milliseconds.
 *
 * Seeking starts with a window ([windowMs], D5): Reconnecting after an
 * attachment went, Connecting otherwise. Losses and failures inside the
 * window keep it running; an attachment ends it. Once it passes, the
 * strategy decides: Waiting keeps the link armed ([Seeking.Waiting]),
 * Presence closes it ([Seeking.Parked]) until something wakes it.
 */
class ReconnectPolicy(
    private val now: () -> Long,
    private val windowMs: Long = WINDOW_MS,
) {
    enum class Seeking {
        /** Not seeking: attached, deliberately down, resting after a fault, or Bluetooth off. */
        None,

        /** Coming up, not after a loss: at a start, a wake, or the user's Connect. */
        Connecting,

        /** Coming back after the attachment went. */
        Reconnecting,

        /** Past the window, Waiting strategy: the link stays armed. */
        Waiting,

        /** Past the window, Presence strategy: the link is closed until a wake. */
        Parked,
    }

    var seeking: Seeking = Seeking.None
        private set

    /** When the running window ends; null when none runs. */
    var windowEndsAt: Long? = null
        private set

    /** Inside a window: [Seeking.Connecting] or [Seeking.Reconnecting]. */
    val inWindow: Boolean get() = seeking == Seeking.Connecting || seeking == Seeking.Reconnecting

    /**
     * Start seeking, unless already seeking. [lost]: the attachment just
     * went. [fresh]: the user asked, or something woke a parked or waiting
     * radio; a new window starts whatever was running. Returns the new
     * window's end when one starts, for the connection to schedule its
     * check; null when the running window goes on.
     */
    fun begin(lost: Boolean, fresh: Boolean = false): Long? {
        val idle = seeking == Seeking.None || seeking == Seeking.Parked
        if (!fresh && !idle) return null
        seeking = if (lost) Seeking.Reconnecting else Seeking.Connecting
        return (now() + windowMs).also { windowEndsAt = it }
    }

    /** Attached, or no longer seeking for any reason: no window runs. */
    fun stop() {
        seeking = Seeking.None
        windowEndsAt = null
    }

    /** Whether the running window has passed. */
    fun windowPassed(): Boolean = inWindow && windowEndsAt?.let { now() >= it } == true

    /**
     * The window has passed: [strategy] takes over. Returns the new state
     * ([Seeking.Waiting] or [Seeking.Parked]); nothing changes outside a
     * window, and the state is returned as it is.
     */
    fun windowEnded(strategy: ReconnectStrategy): Seeking {
        if (!windowPassed()) return seeking
        windowEndsAt = null
        seeking = when (strategy) {
            ReconnectStrategy.Presence -> Seeking.Parked
            ReconnectStrategy.Waiting -> Seeking.Waiting
        }
        return seeking
    }

    /**
     * The strategy changed: a radio past the window takes it, as
     * [windowEnded] would have given it. Returns the new state; nothing
     * changes inside a window, or when not seeking.
     */
    fun strategyChanged(strategy: ReconnectStrategy): Seeking {
        if (seeking != Seeking.Waiting && seeking != Seeking.Parked) return seeking
        seeking = when (strategy) {
            ReconnectStrategy.Presence -> Seeking.Parked
            ReconnectStrategy.Waiting -> Seeking.Waiting
        }
        return seeking
    }

    /**
     * The transport phase to report while the link is connecting (not yet
     * connected) in the current state.
     */
    fun connectingPhase(): MobileRadioTransportPhase = when (seeking) {
        Seeking.Reconnecting -> MobileRadioTransportPhase.RECONNECTING
        Seeking.Waiting, Seeking.Parked -> MobileRadioTransportPhase.WAITING_FOR_RADIO
        Seeking.Connecting, Seeking.None -> MobileRadioTransportPhase.CONNECTING
    }

    companion object {
        /** D5: two minutes; G-12 tunes it. */
        const val WINDOW_MS = 2 * 60 * 1000L
    }
}
