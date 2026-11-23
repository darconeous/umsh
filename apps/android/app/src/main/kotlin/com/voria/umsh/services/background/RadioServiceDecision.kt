package com.voria.umsh.services.background

import com.voria.umsh.core.MobileRadioPhase
import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioControlState
import com.voria.umsh.services.radio.RadioKind
import com.voria.umsh.services.radio.RadioSnapshot

/**
 * Whether the radio's foreground service should run, and what its
 * notification says. Pure, so the JVM tests cover every case.
 */
sealed interface RadioServiceDecision {
    /** Not settled yet (a core starting, a radio not read): neither start nor stop. */
    data object Pending : RadioServiceDecision

    data object Stop : RadioServiceDecision

    data class Run(val link: Link, val kind: RadioKind, val radio: RadioSnapshot) : RadioServiceDecision

    /** The notification's states (`notifications.svg` 3). */
    enum class Link { Connecting, Connected, Reconnecting, Waiting }

    companion object {
        /**
         * [live]: the live core runs (never staging), or null while one is
         * still coming up. [connected]: the host holds the bound radio's
         * connection. The service runs while a remembered radio, wanted
         * (`autoConnect`), is coming up, attached, or coming back within
         * the reconnect window; past the window only under the Waiting
         * [strategy], which keeps it through Bluetooth off too (§7.2).
         */
        fun of(
            live: Boolean?,
            connected: Boolean,
            bound: BoundRadio?,
            radio: RadioSnapshot?,
            radioKnown: Boolean,
            strategy: ReconnectStrategy = ReconnectStrategy.Presence,
        ): RadioServiceDecision {
            if (live == null) return Pending
            if (!live || !connected || bound == null || !bound.autoConnect) return Stop
            if (!radioKnown) return Pending
            radio ?: return Stop
            val waiting = strategy == ReconnectStrategy.Waiting && bound.kind == RadioKind.Ble
            val link = when (RadioControlState.link(radio.phase)) {
                RadioControlState.Link.Connected -> Link.Connected
                RadioControlState.Link.Connecting -> Link.Connecting
                RadioControlState.Link.Reconnecting -> Link.Reconnecting
                // Presence wakes the app when the radio is back; until then nothing is held.
                RadioControlState.Link.Waiting -> if (waiting) Link.Waiting else return Stop
                // Bluetooth off or not permitted: the Waiting strategy holds on,
                // and its receiver seeks the radio when Bluetooth is back.
                RadioControlState.Link.Disconnected ->
                    if (waiting && radio.phase == MobileRadioPhase.UNAVAILABLE) Link.Waiting else return Stop
                RadioControlState.Link.Failed,
                RadioControlState.Link.None,
                RadioControlState.Link.Unknown,
                -> return Stop
            }
            return Run(link, bound.kind, radio)
        }
    }
}
