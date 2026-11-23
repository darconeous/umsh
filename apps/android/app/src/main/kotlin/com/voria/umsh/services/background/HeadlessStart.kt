package com.voria.umsh.services.background

import com.voria.umsh.services.radio.BoundRadio
import com.voria.umsh.services.radio.RadioKind

/**
 * What a start from the background ([RadioServiceController.startForPresence],
 * [RadioServiceController.startForUpdate]) does.
 */
enum class HeadlessStart {
    /** No radio is wanted, it is still being added, or presence saw another one. */
    NotWanted,

    /** The user stopped the app and has not opened it since ([UserStop]). */
    StoppedByUser,

    /** Bluetooth is off: presence holds the appearance until it is on. */
    HoldForBluetooth,

    /** Nothing now: an update with Bluetooth off is left to presence, and a running service needs no start. */
    Skip,

    /** Start the service. */
    Start,
    ;

    companion object {
        /**
         * The rule, in order, for [trigger] and the [bound] radio (null when
         * none is bound, or presence saw another). [stopped] is read only
         * for a wanted radio.
         */
        suspend fun of(
            trigger: Trigger,
            bound: BoundRadio?,
            stopped: suspend () -> Boolean,
            bluetoothOn: () -> Boolean,
            serviceRunning: Boolean,
        ): HeadlessStart {
            if (bound == null || !bound.autoConnect || bound.pending != null) return NotWanted
            if (stopped()) return StoppedByUser
            val bluetoothOff = bound.kind == RadioKind.Ble && !bluetoothOn()
            return when (trigger) {
                Trigger.Presence -> if (bluetoothOff) HoldForBluetooth else Start
                Trigger.Update -> if (serviceRunning || bluetoothOff) Skip else Start
            }
        }
    }

    /** What wakes the app in the background. */
    enum class Trigger { Presence, Update }
}
